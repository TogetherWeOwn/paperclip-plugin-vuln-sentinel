import { createHash } from "node:crypto";
import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { SourceJournal } from "./source-journal.js";
import { testDatabase } from "./test/database.js";
import { sourceLockfiles, sourceOsv } from "./test/sources.js";
import type { OsvSnapshot } from "./osv.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let journal: SourceJournal;
const now = () => new Date("2026-11-04T04:31:00Z");
function rehash(snapshot: OsvSnapshot): OsvSnapshot {
  const { snapshotSha256: _, ...body } = snapshot;
  return { ...body, snapshotSha256: sha256(canonicalJson(body)) };
}

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_snapshots`);
  journal = new SourceJournal(db, now);
});
afterAll(async () => { await postgres.close(); });

describe("immutable source journal", () => {
  it("persists raw lockfiles/inventory and OSV before returning normalized decisions", async () => {
    const lockfiles = sourceLockfiles();
    const lockfileId = await journal.recordLockfiles("company", lockfiles);
    const stored = (await journal.readLockfiles("company", lockfileId))!;
    expect(stored.lockfiles).toEqual(lockfiles);
    expect(stored.inventory.dependencies).toHaveLength(1);
    const recorded = await journal.recordOsv("company", lockfileId, sourceOsv());
    expect(recorded.inputs).toHaveLength(1);
    expect(recorded.inputs[0]!.provenance).toMatchObject({
      artifactDigest: lockfiles.artifactDigest, artifactKind: "lockfile", toolVersions: { "vuln-sentinel-inventory": "0.1.6", semver: "7.7.4" },
    });
    const saved = (await journal.readOsv("company", recorded.snapshotId))!;
    expect(saved.scan.osv).toEqual(sourceOsv());
    expect(saved.inputs).toEqual(recorded.inputs);
    expect(await journal.readLockfiles("other-company", lockfileId)).toBeNull();
    expect(await journal.readOsv("other-company", recorded.snapshotId)).toBeNull();
    expect(await journal.readOsv("company", lockfileId)).toBeNull();
  });

  it("retains complete build-version query identity through concurrent OSV replay", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    file.content = file.content.replaceAll("1.2.3", "1.2.3+build.01");
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
    const id = await journal.recordLockfiles("company", lockfiles);
    const osv = sourceOsv();
    // An otherwise equal base version is not exact inventory query coverage.
    await expect(journal.recordOsv("company", id, osv)).rejects.toThrow("osv_inventory_coverage_mismatch");
    osv.observations[0]!.dependency.version = "1.2.3+build.01";
    const scans = await Promise.all(Array.from({ length: 5 }, () => journal.recordOsv("company", id, rehash(osv))));
    expect(new Set(scans.map(row => row.snapshotId)).size).toBe(1);
    const stored = (await journal.readOsv("company", scans[0]!.snapshotId))!;
    expect(stored.inputs).toEqual(scans[0]!.inputs);
    expect(stored.inputs[0]!.version).toBe("1.2.3+build.01");
    expect(stored.inventory.dependencies[0]!.version).toBe("1.2.3+build.01");
    expect(stored.inputs[0]!.compatibleFixVerified).toBe(false);
    expect(stored.inputs[0]!.fixedVersion).toBeNull();
    expect(stored.inventory.coverage.runtimeCompleteness).toBe("not_proven");
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
  });

  it("replays malformed npm declarations as retained attention rather than accepting fabricated query coverage", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    const content = JSON.parse(file.content);
    content.packages[""].dependencies = { lib: null };
    file.content = JSON.stringify(content);
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toEqual(["invalid_npm_dependency_reference"]);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.toolVersions["vuln-sentinel-inventory"]).toBe("0.1.6");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
  });

  it("rejects lossy lockfile strings before attempting any journal write", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    file.content = file.content.replace('{', '{"note":"\ud800",');
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
    const before = structuredClone(lockfiles);
    let writes = 0;
    const guarded = new SourceJournal({ ...db, execute: async () => { writes++; throw new Error("unexpected write"); } }, now);
    await expect(guarded.recordLockfiles("company", lockfiles)).rejects.toThrow("invalid_inventory_utf8");
    expect(writes).toBe(0);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(0);
  });

  it.each(["0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5"])("holds historical parser %s drift without rewriting evidence and appends a distinct current inventory", async parser => {
    const lockfiles = sourceLockfiles();
    const id = await journal.recordLockfiles("company", lockfiles);
    const legacy = structuredClone((await journal.readLockfiles("company", id))!);
    legacy.inventory.toolVersions = { ...legacy.inventory.toolVersions, "vuln-sentinel-inventory": parser };
    const { inventorySha256: _, ...payload } = legacy.inventory;
    legacy.inventory.inventorySha256 = sha256(canonicalJson(payload));
    const legacyId = sha256(canonicalJson(["source-snapshot-v1", "lockfiles", legacy]));
    await postgres.query(`INSERT INTO ${DATABASE_NAMESPACE}.source_snapshots
      (company_id, snapshot_id, source_kind, repo, source_sha, bundle) VALUES ($1, $2, 'lockfiles', $3, $4, $5)`,
    ["company", legacyId, lockfiles.repo, lockfiles.sourceSha, canonicalJson(legacy)]);
    await expect(journal.readLockfiles("company", legacyId)).rejects.toThrow("stored_inventory_mismatch");
    await expect(journal.recordOsv("company", legacyId, sourceOsv())).rejects.toThrow("stored_inventory_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(id);
    expect(id).not.toBe(legacyId);
    const retained = await postgres.query<{ bundle: unknown }>(`SELECT bundle FROM ${DATABASE_NAMESPACE}.source_snapshots WHERE snapshot_id = $1`, [legacyId]);
    expect(retained.rows[0]!.bundle).toEqual(legacy);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
  });

  it("retains npm lookalike-location attention through concurrent immutable replay", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    file.content = file.content.replace('"node_modules/lib"', '"not_node_modules/lib"');
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await journal.readLockfiles("company", ids[0]!))!;
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.files[0]!.issues).toContain("local_or_workspace_package");
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.coverage.fullDependencyClosure).toBe("not_proven");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
  });

  it("retains Cargo reference gaps through concurrent immutable replay without policy or routing writes", async () => {
    const lockfiles = sourceLockfiles();
    const content = `version = 4\n[[package]]\nname = "lib"\nversion = "1.2.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"a".repeat(64)}"\ndependencies = ["absent"]\n`;
    lockfiles.files = [{ path: "Cargo.lock", content, sha256: sha256(content), etag: null,
      blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }];
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["Cargo.lock", sha256(content)]]))}`;
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await journal.readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(lockfiles);
    expect(stored.inventory.files[0]!.issues).toContain("missing_cargo_dependency_entry");
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.dependencies).toEqual([{
      ecosystem: "crates.io", package: "lib", version: "1.2.3", scope: "unknown", direct: null,
      locations: [{ path: "Cargo.lock", locator: "package[0]" }],
    }]);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
  });

  it("retains aggregate reference-capacity attention through concurrent replay without policy writes", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    const root = JSON.parse(file.content);
    const refs = Object.fromEntries(Array.from({ length: 5_001 }, (_, index) => [`lib${index}`, "*"]));
    root.packages[""].dependencies = refs;
    root.packages[""].optionalDependencies = refs;
    file.content = JSON.stringify(root);
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 3 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await journal.readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toContain("inventory_entry_capacity");
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(lockfiles).toEqual(before);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
  });

  it("concurrent replay inserts one immutable record of each kind", async () => {
    const ids = await Promise.all(Array.from({ length: 10 }, () => journal.recordLockfiles("company", sourceLockfiles())));
    expect(new Set(ids).size).toBe(1);
    const scans = await Promise.all(ids.map(id => journal.recordOsv("company", id, sourceOsv())));
    expect(new Set(scans.map(scan => scan.snapshotId)).size).toBe(1);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
  });

  it("retains older source snapshots without a mutable head/cache race", async () => {
    const oldId = await journal.recordLockfiles("company", sourceLockfiles());
    const newer = sourceLockfiles();
    newer.sourceSha = "b".repeat(40);
    const newId = await journal.recordLockfiles("company", newer);
    await journal.recordLockfiles("company", sourceLockfiles());
    expect(newId).not.toBe(oldId);
    expect((await journal.readLockfiles("company", newId))!.lockfiles.sourceSha).toBe(newer.sourceSha);
    expect((await journal.readLockfiles("company", oldId))!.lockfiles.sourceSha).toBe("a".repeat(40));
  });

  it("records attention coverage without inventing scope or publishing/closing issues", async () => {
    const lockfiles = sourceLockfiles();
    lockfiles.files[0]!.path = "unsupported.lock";
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["unsupported.lock", lockfiles.files[0]!.sha256]]))}`;
    const id = await journal.recordLockfiles("company", lockfiles);
    const source = (await journal.readLockfiles("company", id))!;
    expect(source.inventory.coverage.configuredPathsParsed).toBe(false);
    const empty = rehash({ ...sourceOsv(), observations: [], records: [] });
    const result = await journal.recordOsv("company", id, empty);
    expect(result.inputs).toEqual([]);
    expect((await journal.readOsv("company", result.snapshotId))!.scan.lockfileSnapshotId).toBe(id);
    // No rescan receipt or routing/decision/publication write occurred.
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.delivery_routing`)).rows).toEqual([]);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.decision_records`)).rows).toEqual([]);
  });

  it.each(["missing", "extra", "duplicate", "changed"])("holds %s OSV inventory coverage", async mode => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const osv = sourceOsv();
    if (mode === "missing") osv.observations = [];
    if (mode === "extra" || mode === "duplicate") osv.observations.push(structuredClone(osv.observations[0]!));
    if (mode === "extra" || mode === "changed") osv.observations.at(-1)!.dependency.version = "2.0.0";
    await expect(journal.recordOsv("company", id, rehash(osv))).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
  });

  it("rejects raw/derived record divergence even with a recomputed snapshot hash", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const osv = sourceOsv();
    osv.records[0]!.affected = [];
    await expect(journal.recordOsv("company", id, rehash(osv))).rejects.toThrow("osv_raw_record_mismatch");
  });

  it("rejects duplicate advisory records and IDs", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const osv = sourceOsv();
    osv.records.push(structuredClone(osv.records[0]!));
    await expect(journal.recordOsv("company", id, rehash(osv))).rejects.toThrow("duplicate_osv_record");
    osv.records.pop();
    osv.observations[0]!.advisoryIds.push(osv.observations[0]!.advisoryIds[0]!);
    await expect(journal.recordOsv("company", id, rehash(osv))).rejects.toThrow("invalid_osv_observation");
  });

  it("rejects a query after the trusted observation clock", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    await expect(new SourceJournal(db, () => new Date("2026-11-03T00:00:00Z")).recordOsv("company", id, sourceOsv())).rejects.toThrow("observation_before_query");
  });

  it("rejects missing/cross-company lockfile snapshots and invalid source ids", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    await expect(journal.recordOsv("other-company", id, sourceOsv())).rejects.toThrow("missing_lockfile_snapshot");
    await expect(journal.recordOsv("company", "f".repeat(64), sourceOsv())).rejects.toThrow("missing_lockfile_snapshot");
    await expect(journal.readLockfiles("company", "main")).rejects.toThrow("invalid_source_snapshot_id");
  });

  it("holds corrupted stored raw evidence, not an apparently good cache hit", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET bundle = '{}' WHERE snapshot_id = $1`, [id]);
    await expect(journal.readLockfiles("company", id)).rejects.toThrow("stored_source_hash_mismatch");
  });

  it("does not return normalized inputs on a failed storage write; replay is safe", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const broken = new SourceJournal({ ...db, execute: async () => { throw new Error("write interrupted"); } }, now);
    await expect(broken.recordOsv("company", id, sourceOsv())).rejects.toThrow("write interrupted");
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    expect((await journal.recordOsv("company", id, sourceOsv())).inputs).toHaveLength(1);
  });

  it("repairs an ambiguous committed insert by replay without duplicate history", async () => {
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const faulty = new SourceJournal({ ...db, execute: async (sql, params) => {
      await db.execute(sql, params);
      throw new Error("response lost");
    } }, now);
    await expect(faulty.recordOsv("company", id, sourceOsv())).rejects.toThrow("response lost");
    await journal.recordOsv("company", id, sourceOsv());
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
  });

  it("rejects mismatched namespaces", () => {
    expect(() => new SourceJournal({ ...db, namespace: "other" })).toThrow("namespace");
  });
});
