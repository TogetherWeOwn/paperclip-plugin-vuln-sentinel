import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { FindingInput } from "./model.js";
import { SourceAttention } from "./source-http.js";
import { enrichThreatInputs, validateThreatSnapshot, type ThreatSnapshot } from "./threat-feeds.js";

function snapshotId(bundle: ThreatSnapshot): string {
  const content = canonicalJson(bundle);
  if (Buffer.byteLength(content) > 16 * 1024 * 1024) throw new SourceAttention("threat_storage_capacity");
  return sha256(canonicalJson(["threat-snapshot-v1", bundle]));
}

/** Global feed snapshots remain immutable and company scoped, never a mutable latest feed. */
export class ThreatJournal {
  private readonly table: string;
  constructor(private readonly db: PluginDatabaseClient) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Threat journal namespace does not match the packaged migration");
    this.table = `"${db.namespace}".threat_snapshots`;
  }

  async record(companyId: string, snapshot: ThreatSnapshot): Promise<string> {
    const bundle = structuredClone(snapshot);
    const id = snapshotId(bundle);
    validateThreatSnapshot(bundle);
    await this.db.execute(
      `INSERT INTO ${this.table} (company_id, snapshot_id, bundle) VALUES ($1, $2, $3)
       ON CONFLICT (company_id, snapshot_id) DO NOTHING`, [companyId, id, canonicalJson(bundle)],
    );
    const stored = await this.read(companyId, id);
    if (!stored || canonicalJson(stored) !== canonicalJson(bundle)) throw new SourceAttention("threat_persistence_mismatch");
    return id;
  }

  async read(companyId: string, id: string): Promise<ThreatSnapshot | null> {
    if (!/^[a-f0-9]{64}$/u.test(id)) throw new SourceAttention("invalid_threat_snapshot_id");
    const rows = await this.db.query<{ snapshot_id: string; bundle: ThreatSnapshot }>(
      `SELECT snapshot_id, bundle FROM ${this.table} WHERE company_id = $1 AND snapshot_id = $2`, [companyId, id],
    );
    const row = rows[0];
    if (!row) return null;
    if (row.snapshot_id !== id || snapshotId(row.bundle) !== id) throw new SourceAttention("stored_threat_hash_mismatch");
    validateThreatSnapshot(row.bundle);
    return row.bundle;
  }

  async enrich(companyId: string, id: string, inputs: FindingInput[]): Promise<FindingInput[]> {
    const snapshot = await this.read(companyId, id);
    if (!snapshot) throw new SourceAttention("missing_threat_snapshot");
    return enrichThreatInputs(inputs, snapshot).map(result => {
      result.provenance.threatSnapshotId = id;
      return result;
    });
  }
}
