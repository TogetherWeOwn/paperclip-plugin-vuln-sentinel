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
      artifactDigest: lockfiles.artifactDigest, artifactKind: "lockfile", toolVersions: { "vuln-sentinel-inventory": "0.1.13", semver: "7.7.4" },
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
    expect(stored.inventory.toolVersions["vuln-sentinel-inventory"]).toBe("0.1.13");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
  });

  it("retains malformed npm peer declarations through concurrent replay without invented coverage or policy writes", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    const content = JSON.parse(file.content);
    content.packages["node_modules/lib"].peerDependencies = { absent: null };
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
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
  });

  it("retains malformed pnpm package peers through concurrent replay without fabricated coverage or policy writes", async () => {
    const lockfiles = sourceLockfiles();
    const content = JSON.stringify({ lockfileVersion: "9.0", importers: { ".": {} },
      packages: { "lib@1.2.3": { resolution: { integrity: "sha512-abc=" }, peerDependencies: { absent: null } } },
      snapshots: { "lib@1.2.3": {} } });
    lockfiles.files = [{ path: "pnpm-lock.yaml", content, sha256: sha256(content), etag: null,
      blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }];
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["pnpm-lock.yaml", sha256(content)]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toEqual(["invalid_pnpm_specifier"]);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
  });

  it.each(["packages", "snapshots"])("retains unsupported pnpm %s locators through concurrent replay without fabricated coverage or policy writes", async owner => {
    const lockfiles = sourceLockfiles();
    const key = "lib@1.2.3(peer@1.0.0))";
    const content = JSON.stringify({ lockfileVersion: "9.0", importers: { ".": {} },
      packages: { [owner === "packages" ? key : "lib@1.2.3"]: { resolution: { integrity: "sha512-abc=" } } },
      snapshots: { [key]: {} } });
    lockfiles.files = [{ path: "pnpm-lock.yaml", content, sha256: sha256(content), etag: null,
      blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }];
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["pnpm-lock.yaml", sha256(content)]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toEqual(["unsupported_pnpm_package_key"]);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.toolVersions["vuln-sentinel-inventory"]).toBe("0.1.13");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
  });

  it("retains malformed pnpm importer declarations through concurrent immutable replay", async () => {
    const lockfiles = sourceLockfiles();
    const content = JSON.stringify({ lockfileVersion: "9.0",
      importers: { ".": { dependencies: { lib: { specifier: null, version: "1.2.3" } } } },
      packages: { "lib@1.2.3": { resolution: { integrity: "sha512-abc=" } } },
      snapshots: { "lib@1.2.3": {} },
    });
    lockfiles.files = [{ path: "pnpm-lock.yaml", content, sha256: sha256(content), etag: null,
      blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }];
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["pnpm-lock.yaml", sha256(content)]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toEqual(["invalid_pnpm_specifier"]);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.coverage.fullDependencyClosure).toBe("not_proven");
    expect(stored.inventory.toolVersions["vuln-sentinel-inventory"]).toBe("0.1.13");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
  });

  it("retains unsupported pnpm importer paths through concurrent replay without policy writes", async () => {
    const lockfiles = sourceLockfiles();
    const content = JSON.stringify({ lockfileVersion: "9.0", importers: { ".": {}, "../external": {} },
      packages: { "lib@1.2.3": { resolution: { integrity: "sha512-abc=" } } }, snapshots: { "lib@1.2.3": {} } });
    lockfiles.files = [{ path: "pnpm-lock.yaml", content, sha256: sha256(content), etag: null,
      blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }];
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["pnpm-lock.yaml", sha256(content)]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toEqual(["invalid_pnpm_importer_path"]);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
  });

  it("retains YAML key-coercion ambiguity through concurrent replay without decision or routing writes", async () => {
    const lockfiles = sourceLockfiles();
    const content = `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      true: {specifier: 1.0.0, version: 1.0.0}\n      'true': {specifier: 2.0.0, version: 2.0.0}\npackages:\n  true@2.0.0:\n    resolution: {integrity: sha512-abc=}\nsnapshots:\n  true@2.0.0: {}\n`;
    lockfiles.files = [{ path: "pnpm-lock.yaml", content, sha256: sha256(content), etag: null,
      blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }];
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["pnpm-lock.yaml", sha256(content)]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.files[0]!.issues).toEqual(["unsupported_pnpm_yaml_key"]);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.toolVersions["vuln-sentinel-inventory"]).toBe("0.1.13");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
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

  it.each(["0.1.0", "0.1.1", "0.1.2", "0.1.3", "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.1.10", "0.1.11", "0.1.12"])("holds historical parser %s drift without rewriting evidence and appends a distinct current inventory", async parser => {
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

  it("retains malformed enclosing npm locators through concurrent replay without fabricated coverage or policy writes", async () => {
    const lockfiles = sourceLockfiles();
    const file = lockfiles.files[0]!;
    file.content = file.content.replace('"node_modules/lib"', '"node_modules/parent/extra/node_modules/lib"');
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
    const before = structuredClone(lockfiles);
    const ids = await Promise.all(Array.from({ length: 5 }, () => journal.recordLockfiles("company", lockfiles)));
    expect(new Set(ids).size).toBe(1);
    const stored = (await new SourceJournal(db, now).readLockfiles("company", ids[0]!))!;
    expect(stored.lockfiles).toEqual(before);
    expect(stored.inventory.dependencies).toEqual([]);
    expect(stored.inventory.files[0]!.issues).toEqual(["invalid_npm_locator"]);
    expect(stored.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(stored.inventory.coverage.fullDependencyClosure).toBe("not_proven");
    expect(stored.inventory.toolVersions["vuln-sentinel-inventory"]).toBe("0.1.13");
    await expect(journal.recordOsv("company", ids[0]!, sourceOsv())).rejects.toThrow("osv_inventory_coverage_mismatch");
    expect(await journal.recordLockfiles("company", lockfiles)).toBe(ids[0]);
    expect(lockfiles).toEqual(before);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    for (const table of ["delivery_routing", "decision_records"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
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

  describe("exact inventory query coverage", () => {
    function fixture() {
      const lockfiles = sourceLockfiles();
      const npm = JSON.parse(lockfiles.files[0]!.content);
      npm.packages["node_modules/parent/node_modules/lib"] = structuredClone(npm.packages["node_modules/lib"]);
      npm.packages["node_modules/other/node_modules/lib"] = {
        version: "2.0.0", resolved: "https://registry.npmjs.org/lib/-/lib-2.0.0.tgz",
      };
      const cargo = `version = 4\n[[package]]\nname = "lib"\nversion = "1.2.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"a".repeat(64)}"\n`;
      const files: Array<[string, string]> = [
        ["package-lock.json", JSON.stringify(npm)],
        ["tools/package-lock.json", sourceLockfiles().files[0]!.content],
        ["Cargo.lock", cargo],
      ];
      lockfiles.files = files.map(([path, content]) => ({ path, content, sha256: sha256(content), etag: null,
        blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex"),
      }));
      lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([...lockfiles.files]
        .sort((a, b) => a.path.localeCompare(b.path)).map(file => [file.path, file.sha256])))}`;
      const osv = sourceOsv();
      osv.observations.push(
        { dependency: { ecosystem: "npm", package: "lib", version: "2.0.0" }, advisoryIds: [] },
        { dependency: { ecosystem: "crates.io", package: "lib", version: "1.2.3" }, advisoryIds: [] },
      );
      return { lockfiles, osv: rehash(osv) };
    }

    it.each([false, true])("queries each exact tuple once, retaining all installation locations (reversed=%s)", async reversed => {
      const { lockfiles, osv } = fixture();
      if (reversed) { lockfiles.files.reverse(); osv.observations.reverse(); }
      const before = structuredClone({ lockfiles, osv });
      const id = await journal.recordLockfiles("company", lockfiles);
      const scans = await Promise.all(Array.from({ length: 5 }, () => journal.recordOsv("company", id, rehash(osv))));
      expect(new Set(scans.map(scan => scan.snapshotId)).size).toBe(1);
      const stored = (await new SourceJournal(db, now).readOsv("company", scans[0]!.snapshotId))!;
      expect(stored.inventory.dependencies).toHaveLength(3);
      expect(stored.inventory.dependencies.find(dep => dep.ecosystem === "npm" && dep.version === "1.2.3")!.locations).toEqual([
        { path: "package-lock.json", locator: "node_modules/lib" },
        { path: "package-lock.json", locator: "node_modules/parent/node_modules/lib" },
        { path: "tools/package-lock.json", locator: "node_modules/lib" },
      ]);
      expect(stored.scan.osv.observations).toEqual(osv.observations);
      expect(stored.inputs).toEqual(scans[0]!.inputs);
      expect(stored.inputs).toHaveLength(1);
      expect(stored.inputs[0]).toMatchObject({ ecosystem: "npm", package: "lib", version: "1.2.3",
        scope: "unknown", fixedVersion: null, compatibleFixVerified: false,
        provenance: { artifactDigest: lockfiles.artifactDigest, source: { snapshotSha256: rehash(osv).snapshotSha256 },
          toolVersions: stored.inventory.toolVersions },
      });
      expect(stored.inventory.coverage).toMatchObject({ configuredPathsParsed: true,
        fullDependencyClosure: "not_proven", runtimeCompleteness: "not_proven" });
      expect({ lockfiles, osv }).toEqual(before);
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
      for (const table of ["decision_records", "delivery_routing"]) {
        expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
      }
    });

    const mutations: Array<[string, (osv: OsvSnapshot) => void]> = [
      ["omitted empty-result tuple", osv => { osv.observations.pop(); }],
      ["extra tuple", osv => { osv.observations.push({ dependency: { ecosystem: "npm", package: "other", version: "1.2.3" }, advisoryIds: [] }); }],
      ["duplicate replacing another tuple", osv => { osv.observations[2] = structuredClone(osv.observations[1]!); }],
      ["per-location repeated query", osv => { osv.observations.push(structuredClone(osv.observations[0]!)); }],
      ["changed ecosystem", osv => { osv.observations[2]!.dependency.ecosystem = "npm"; }],
      ["changed name", osv => { osv.observations[2]!.dependency.package = "Lib"; }],
      ["changed version", osv => { osv.observations[1]!.dependency.version = "2.0.1"; }],
      ["equal-precedence build identity", osv => { osv.observations[1]!.dependency.version = "2.0.0+build.1"; }],
    ];
    it.each(mutations)("rejects %s before persisting OSV evidence", async (_, mutate) => {
      const { lockfiles, osv } = fixture();
      const id = await journal.recordLockfiles("company", lockfiles);
      mutate(osv);
      const changed = rehash(osv);
      const before = structuredClone(changed);
      await expect(journal.recordOsv("company", id, changed)).rejects.toThrow("osv_inventory_coverage_mismatch");
      expect(changed).toEqual(before);
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(1);
    });

    it.each(mutations)("revalidates %s on read even when both snapshot hashes were recomputed", async (_, mutate) => {
      const { lockfiles, osv } = fixture();
      const id = await journal.recordLockfiles("company", lockfiles);
      const recorded = await journal.recordOsv("company", id, osv);
      const scan = (await journal.readOsv("company", recorded.snapshotId))!.scan;
      mutate(scan.osv);
      scan.osv = rehash(scan.osv);
      const changedId = sha256(canonicalJson(["source-snapshot-v1", "osv", scan]));
      await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET snapshot_id = $1, bundle = $2 WHERE snapshot_id = $3`,
        [changedId, canonicalJson(scan), recorded.snapshotId]);
      await expect(new SourceJournal(db, now).readOsv("company", changedId)).rejects.toThrow("osv_inventory_coverage_mismatch");
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
      for (const table of ["decision_records", "delivery_routing"]) {
        expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
      }
    });

    it("preserves distinct empty-result query times without inventing decisions or resolution", async () => {
      const { lockfiles, osv } = fixture();
      const id = await journal.recordLockfiles("company", lockfiles);
      osv.records = [];
      osv.observations.forEach(row => { row.advisoryIds = []; });
      const first = await journal.recordOsv("company", id, rehash(osv));
      osv.queriedAt = "2026-11-04T04:30:30Z";
      const second = await journal.recordOsv("company", id, rehash(osv));
      expect(second.snapshotId).not.toBe(first.snapshotId);
      for (const result of [first, second]) {
        expect(result.inputs).toEqual([]);
        const stored = (await journal.readOsv("company", result.snapshotId))!;
        expect(stored.scan.osv.observations).toHaveLength(3);
        expect(stored.inventory.coverage.runtimeCompleteness).toBe("not_proven");
      }
      expect((await journal.readOsv("company", first.snapshotId))!.scan.osv.queriedAt).toBe("2026-11-04T04:30:00Z");
      expect((await journal.readOsv("company", second.snapshotId))!.scan.osv.queriedAt).toBe(osv.queriedAt);
      for (const table of ["decision_records", "delivery_routing", "finding_records"]) {
        expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
      }
    });
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
