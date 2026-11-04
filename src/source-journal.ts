import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "./claims.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { parseLockfileInventory, type LockfileInventory } from "./inventory.js";
import type { FindingInput } from "./model.js";
import { osvFindingInputs, parseOsvRecord, type OsvSnapshot } from "./osv.js";
import { SourceAttention, timestamp } from "./source-http.js";

export interface StoredLockfiles {
  lockfiles: RepositoryLockfiles;
  inventory: LockfileInventory;
}

export interface StoredOsvScan {
  lockfileSnapshotId: string;
  observedAt: string;
  osv: OsvSnapshot;
}

interface SourceRow {
  snapshot_id: string;
  source_kind: "lockfiles" | "osv";
  repo: string;
  source_sha: string;
  bundle: StoredLockfiles | StoredOsvScan;
}

function snapshotId(kind: SourceRow["source_kind"], bundle: SourceRow["bundle"]): string {
  const content = canonicalJson(bundle);
  if (Buffer.byteLength(content) > 16 * 1024 * 1024) throw new SourceAttention("source_storage_capacity");
  return sha256(canonicalJson(["source-snapshot-v1", kind, bundle]));
}

function validateOsv(osv: OsvSnapshot, source: StoredLockfiles, observedAt: string): FindingInput[] {
  timestamp(osv.queriedAt, "invalid_query_time");
  if (!Array.isArray(osv.observations) || osv.observations.length > 2_000
    || !Array.isArray(osv.records) || osv.records.length > 2_000) throw new SourceAttention("invalid_osv_snapshot");
  const expected = source.inventory.dependencies.map(({ ecosystem, package: name, version }) => canonicalJson({ ecosystem, package: name, version })).sort();
  const actual = osv.observations.map(row => canonicalJson(row.dependency)).sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new SourceAttention("osv_inventory_coverage_mismatch");
  const records = new Set<string>();
  for (const record of osv.records) {
    if (records.has(record.id)) throw new SourceAttention("duplicate_osv_record");
    records.add(record.id);
    if (canonicalJson(parseOsvRecord(record.raw, record.id)) !== canonicalJson(record)) {
      throw new SourceAttention("osv_raw_record_mismatch");
    }
    if (Date.parse(record.modified!) > Date.parse(osv.queriedAt)
      || (record.withdrawn !== null && Date.parse(record.withdrawn) > Date.parse(osv.queriedAt))) {
      throw new SourceAttention("future_osv_record");
    }
  }
  for (const row of osv.observations) {
    if (!Array.isArray(row.advisoryIds) || new Set(row.advisoryIds).size !== row.advisoryIds.length) {
      throw new SourceAttention("invalid_osv_observation");
    }
  }
  const inputs = osvFindingInputs(osv, { repo: source.lockfiles.repo, artifactDigest: source.lockfiles.artifactDigest, observedAt });
  for (const input of inputs) Object.assign(input.provenance.toolVersions, source.inventory.toolVersions);
  return inputs;
}

/** Immutable raw evidence before decisions. Explicit refs, never a mutable latest-head cache. */
export class SourceJournal {
  private readonly table: string;
  constructor(private readonly db: PluginDatabaseClient, private readonly now = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Source journal namespace does not match the packaged migration");
    this.table = `"${db.namespace}".source_snapshots`;
  }

  private async insert(companyId: string, kind: SourceRow["source_kind"], repo: string, sourceSha: string, bundle: SourceRow["bundle"]): Promise<string> {
    const id = snapshotId(kind, bundle);
    await this.db.execute(
      `INSERT INTO ${this.table} (company_id, snapshot_id, source_kind, repo, source_sha, bundle)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (company_id, snapshot_id) DO NOTHING`,
      [companyId, id, kind, repo, sourceSha, canonicalJson(bundle)],
    );
    const stored = await this.read(companyId, id, kind);
    if (!stored || stored.repo !== repo || stored.source_sha !== sourceSha
      || canonicalJson(stored.bundle) !== canonicalJson(bundle)) throw new SourceAttention("source_persistence_mismatch");
    return id;
  }

  private async read(companyId: string, id: string, kind: SourceRow["source_kind"]): Promise<SourceRow | null> {
    if (!/^[a-f0-9]{64}$/u.test(id)) throw new SourceAttention("invalid_source_snapshot_id");
    const rows = await this.db.query<SourceRow>(
      `SELECT snapshot_id, source_kind, repo, source_sha, bundle FROM ${this.table}
       WHERE company_id = $1 AND snapshot_id = $2 AND source_kind = $3`, [companyId, id, kind],
    );
    const row = rows[0];
    if (!row) return null;
    if (row.snapshot_id !== id || row.source_kind !== kind || snapshotId(kind, row.bundle) !== id) {
      throw new SourceAttention("stored_source_hash_mismatch");
    }
    return row;
  }

  async recordLockfiles(companyId: string, lockfiles: RepositoryLockfiles): Promise<string> {
    const copy = structuredClone(lockfiles);
    const inventory = parseLockfileInventory(copy);
    return this.insert(companyId, "lockfiles", copy.repo, copy.sourceSha, { lockfiles: copy, inventory });
  }

  async readLockfiles(companyId: string, id: string): Promise<StoredLockfiles | null> {
    const row = await this.read(companyId, id, "lockfiles");
    if (!row) return null;
    const bundle = row.bundle as StoredLockfiles;
    if (bundle.lockfiles.repo !== row.repo || bundle.lockfiles.sourceSha !== row.source_sha
      || canonicalJson(parseLockfileInventory(bundle.lockfiles)) !== canonicalJson(bundle.inventory)) {
      throw new SourceAttention("stored_inventory_mismatch");
    }
    return bundle;
  }

  async recordOsv(companyId: string, lockfileSnapshotId: string, osv: OsvSnapshot): Promise<{ snapshotId: string; inputs: FindingInput[]; inventory: LockfileInventory }> {
    const bundle: StoredOsvScan = { lockfileSnapshotId, observedAt: this.now().toISOString(), osv: structuredClone(osv) };
    snapshotId("osv", bundle);
    const source = await this.readLockfiles(companyId, lockfileSnapshotId);
    if (!source) throw new SourceAttention("missing_lockfile_snapshot");
    const inputs = validateOsv(bundle.osv, source, bundle.observedAt);
    const id = await this.insert(companyId, "osv", source.lockfiles.repo, source.lockfiles.sourceSha, bundle);
    // The caller cannot journal/publish any returned normalized input before raw evidence is durable.
    return { snapshotId: id, inputs, inventory: source.inventory };
  }

  async readOsv(companyId: string, id: string): Promise<{ scan: StoredOsvScan; inputs: FindingInput[]; inventory: LockfileInventory } | null> {
    const row = await this.read(companyId, id, "osv");
    if (!row) return null;
    const scan = row.bundle as StoredOsvScan;
    const source = await this.readLockfiles(companyId, scan.lockfileSnapshotId);
    if (!source || source.lockfiles.repo !== row.repo || source.lockfiles.sourceSha !== row.source_sha) {
      throw new SourceAttention("missing_lockfile_snapshot");
    }
    return { scan, inputs: validateOsv(scan.osv, source, scan.observedAt), inventory: source.inventory };
  }
}
