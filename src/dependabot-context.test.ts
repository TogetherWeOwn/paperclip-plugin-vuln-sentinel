import { createHash } from "node:crypto";
import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { DependabotContext } from "./dependabot-context.js";
import { DependabotJournal } from "./dependabot-journal.js";
import { DependabotSource, type DependabotSnapshot } from "./dependabot.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore } from "./source-polls.js";
import { testDatabase } from "./test/database.js";
import { dependabotAlert } from "./test/dependabot.js";
import { sourceLockfiles } from "./test/sources.js";

const base = Date.now() - 10_000;
const DAY = 86_400_000;
let postgres: PGlite;
let db: PluginDatabaseClient;
let clock: number;
const now = () => new Date(clock);
let polls: SourcePollStore;
let sources: SourceJournal;
let journal: DependabotJournal;
let context: DependabotContext;
type Alert = ReturnType<typeof dependabotAlert>;

function alert(number = 1): Alert {
  const value = dependabotAlert(number);
  value.dependency.package.name = "lib";
  value.security_vulnerability.package.name = "lib";
  value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
  return value;
}
function rehash(lockfiles: RepositoryLockfiles) {
  for (const file of lockfiles.files) {
    file.sha256 = sha256(file.content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
  }
  lockfiles.artifactDigest = `sha256:${sha256(canonicalJson(lockfiles.files.map(file => [file.path, file.sha256]).sort()))}`;
  return lockfiles;
}
async function ready(lockfiles = sourceLockfiles(), companyId = "company") {
  const source = { repo: lockfiles.repo, paths: lockfiles.files.map(file => file.path).sort() };
  const poll = await polls.begin(companyId, source);
  const id = await sources.recordLockfiles(companyId, lockfiles);
  await polls.complete(poll, id);
  return polls.current(companyId, source);
}
async function snapshot(alerts: Alert[] = [alert()], org = "example"): Promise<DependabotSnapshot> {
  const read = await new DependabotSource(async () => new Response(JSON.stringify(alerts)), "fixture-token", now).read(org);
  if (read.status !== "available") throw new Error("fixture unavailable");
  return read.snapshot;
}
async function retain(alerts: Alert[] = [alert()]) { return journal.record("company", await snapshot(alerts)); }

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots,
    ${DATABASE_NAMESPACE}.dependabot_snapshots`);
  clock = base;
  polls = new SourcePollStore(db, now);
  sources = new SourceJournal(db, now);
  journal = new DependabotJournal(db);
  context = new DependabotContext(db, now);
});
afterAll(async () => { await postgres.close(); });

describe("exact-inventory retained Dependabot context", () => {
  it("binds only retained current company/repo/path/package/version/location evidence", async () => {
    const selected = await ready();
    const id = await retain();
    const before = structuredClone(selected);
    const result = await context.bind(selected, id);
    expect(selected).toEqual(before);
    expect(result).toMatchObject({ version: 1, status: "attention", companyId: "company", repo: "example/project",
      sourceSha: selected.stored.lockfiles.sourceSha, artifactDigest: selected.stored.lockfiles.artifactDigest,
      lockfileSnapshotId: selected.snapshotId, dependabotSnapshotId: id,
      sourceSelection: { pollRevision: selected.pollRevision, token: selected.token },
      observedAt: now().toISOString(), otherRepositoryAlerts: 0,
      alerts: [{ status: "matched_observation", attention: [],
        file: { path: "package-lock.json", sha256: selected.stored.lockfiles.files[0]!.sha256 },
        tuples: [{ dependency: { ecosystem: "npm", package: "lib", version: "1.2.3" },
          locators: ["node_modules/lib"], rangeMatch: "matches" }] }] });
    expect(result.alerts[0]!.alert).toMatchObject({ updatedAt: "2026-11-03T00:00:00Z",
      scope: "development", relationship: "transitive", firstPatchedVersion: "2.0.0",
      advisory: { updatedAt: "2026-11-02T00:00:00Z" } });
    expect(result.attention).toEqual(expect.arrayContaining(["dependabot_scope_not_applied",
      "dependabot_alias_closure_not_proven", "dependabot_compatible_fix_not_proven"]));
    const { contextSha256, ...content } = result;
    expect(contextSha256).toBe(sha256(canonicalJson(["dependabot-repository-context-v1", content])));
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.decision_records`)).rows).toEqual([]);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.delivery_routing`)).rows).toEqual([]);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.card_claims`)).rows).toEqual([]);
  });

  it("replays deterministically after reconstruction without restamping the observation", async () => {
    const selected = await ready();
    const id = await retain();
    const result = await context.bind(selected, id);
    clock += 1000;
    expect(await new DependabotContext(db, now).bind(selected, id)).toEqual(result);
    expect(await Promise.all(Array.from({ length: 6 }, () => context.bind(selected, id))))
      .toEqual(Array.from({ length: 6 }, () => result));
  });

  it("retains every candidate installed version and only exact-path locations", async () => {
    const lockfiles = sourceLockfiles();
    const raw = JSON.parse(lockfiles.files[0]!.content);
    raw.packages["node_modules/other/node_modules/lib"] = { version: "1.2.3", resolved: "https://registry.npmjs.org/lib/-/lib-1.2.3.tgz" };
    raw.packages["node_modules/another/node_modules/lib"] = { version: "3.0.0", resolved: "https://registry.npmjs.org/lib/-/lib-3.0.0.tgz" };
    lockfiles.files[0]!.content = JSON.stringify(raw);
    lockfiles.files.push({ ...lockfiles.files[0]!, path: "nested/package-lock.json" });
    const selected = await ready(rehash(lockfiles));
    const result = await context.bind(selected, await retain());
    expect(result.alerts[0]!.status).toBe("matched_observation");
    expect(result.alerts[0]!.tuples).toEqual([
      { dependency: { ecosystem: "npm", package: "lib", version: "1.2.3" },
        locators: ["node_modules/lib", "node_modules/other/node_modules/lib"], rangeMatch: "matches" },
      { dependency: { ecosystem: "npm", package: "lib", version: "3.0.0" },
        locators: ["node_modules/another/node_modules/lib"], rangeMatch: "does_not_match" },
    ]);
    expect(result.alerts[0]!.file!.path).toBe("package-lock.json");
  });

  it.each(["package.json", "nested/package-lock.json", "PACKAGE-LOCK.JSON"])("does not guess manifest/workspace mapping for %s", async path => {
    const selected = await ready();
    const value = alert(); value.dependency.manifest_path = path;
    const result = await context.bind(selected, await retain([value]));
    expect(result.alerts[0]).toMatchObject({ status: "attention", file: null, tuples: [],
      attention: ["dependabot_manifest_not_in_selected_inventory"] });
  });

  it("does not borrow the same package from another lockfile", async () => {
    const lockfiles = sourceLockfiles();
    lockfiles.files.push({ ...lockfiles.files[0]!, path: "nested/package-lock.json" });
    const raw = JSON.parse(lockfiles.files[0]!.content); raw.packages = { "": {} };
    lockfiles.files[0]!.content = JSON.stringify(raw);
    const result = await context.bind(await ready(rehash(lockfiles)), await retain());
    expect(result.alerts[0]).toMatchObject({ status: "attention", tuples: [],
      attention: ["dependabot_package_not_in_manifest_inventory"] });
  });

  it("retains parse attention rather than treating a partial inventory as bound", async () => {
    const lockfiles = sourceLockfiles();
    const raw = JSON.parse(lockfiles.files[0]!.content);
    raw.packages[""].dependencies.missing = "1.0.0";
    lockfiles.files[0]!.content = JSON.stringify(raw);
    const result = await context.bind(await ready(rehash(lockfiles)), await retain());
    expect(result.alerts[0]).toMatchObject({ status: "attention", tuples: [], attention: ["dependabot_inventory_file_attention"] });
    expect(result.attention).toContain("inventory_parse_attention");
  });

  it.each(["fixed", "dismissed", "auto_dismissed"])("retains %s as attention, never remediation or absence", async state => {
    const value = alert(); value.state = state;
    const result = await context.bind(await ready(), await retain([value]));
    expect(result.alerts[0]).toMatchObject({ status: "attention", attention: ["dependabot_alert_not_open"],
      tuples: [{ rangeMatch: "matches" }] });
  });

  it("does not turn advisory withdrawal into an artifact negative decision", async () => {
    const value = alert() as unknown as Record<string, any>;
    value.security_advisory.withdrawn_at = "2026-11-03T00:00:00Z";
    const result = await context.bind(await ready(), await retain([value as Alert]));
    expect(result.alerts[0]!.attention).toContain("dependabot_advisory_withdrawn");
  });

  it.each(["scope", "relationship"])("preserves missing %s as null without inferring policy", async field => {
    const value = alert() as unknown as Record<string, any>;
    delete value.dependency[field];
    const result = await context.bind(await ready(), await retain([value as Alert]));
    expect(result.alerts[0]!.alert[field as "scope" | "relationship"]).toBeNull();
    expect(result.attention).toContain("dependabot_scope_not_applied");
  });

  it.each(["< 2.0.0", ">= 1.0.0, < 2.0.0", ">=1.2.3", "= 1.2.3", "1.2.3"])("accepts narrow stable npm comparator context %s", async range => {
    const value = alert();
    value.security_vulnerability.vulnerable_version_range = range;
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await context.bind(await ready(), await retain([value]));
    expect(result.alerts[0]!.tuples[0]!.rangeMatch).toBe("matches");
  });

  it.each(["^1.0.0", "~1.2.0", "*", ">=1.0.0 || <2.0.0", "< 2.0", "< 02.0.0", "< 2.0.0-beta.1", "< 2.0.0+build", "< 2.0.0,", "< 2.0.0 >= 1.0.0"])("holds unsupported range grammar %s", async range => {
    const value = alert();
    value.security_vulnerability.vulnerable_version_range = range;
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await context.bind(await ready(), await retain([value]));
    expect(result.alerts[0]).toMatchObject({ status: "attention", tuples: [{ rangeMatch: "unknown" }] });
    expect(result.alerts[0]!.attention).toContain("dependabot_range_context_unknown");
  });

  it.each(["1.2.3-beta.1", "1.2.3+build"])("does not extrapolate stable comparator semantics to %s", async version => {
    const lockfiles = sourceLockfiles();
    const raw = JSON.parse(lockfiles.files[0]!.content);
    raw.packages["node_modules/lib"] = { version, resolved: `https://registry.npmjs.org/lib/-/lib-${version}.tgz` };
    lockfiles.files[0]!.content = JSON.stringify(raw);
    const result = await context.bind(await ready(rehash(lockfiles)), await retain());
    if (version.includes("+")) {
      // The inventory parser already holds build-metadata versions; no tuple leaks through.
      expect(result.alerts[0]!.attention).toContain("dependabot_inventory_file_attention");
      expect(result.alerts[0]!.tuples).toEqual([]);
    } else expect(result.alerts[0]!.tuples[0]!.rangeMatch).toBe("unknown");
    expect(result.alerts[0]!.status).toBe("attention");
  });

  it("keeps other ecosystems unknown rather than borrowing npm range or identity semantics", async () => {
    const lockfiles = sourceLockfiles();
    lockfiles.files[0]!.path = "Cargo.lock";
    lockfiles.files[0]!.content = `version = 4\n[[package]]\nname = "lib"\nversion = "1.2.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"a".repeat(64)}"\n`;
    const value = alert(); value.dependency.manifest_path = "Cargo.lock";
    value.dependency.package.ecosystem = "rust";
    value.security_vulnerability.package.ecosystem = "rust";
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await context.bind(await ready(rehash(lockfiles)), await retain([value]));
    expect(result.alerts[0]!.status).toBe("attention");
    expect(result.alerts[0]!.tuples).toEqual([]);
    expect(result.alerts[0]!.attention).toContain("dependabot_context_ecosystem_unsupported");
  });

  it("a nonmatching range remains attention, not a negative applicability proof", async () => {
    const value = alert();
    value.security_vulnerability.vulnerable_version_range = ">= 2.0.0";
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await context.bind(await ready(), await retain([value]));
    expect(result.alerts[0]).toMatchObject({ status: "attention", attention: ["dependabot_no_installed_version_match"],
      tuples: [{ rangeMatch: "does_not_match" }] });
  });

  it.each([false, true])("empty/unrelated observations never prove repository coverage; unrelated=%s", async unrelated => {
    const alerts = unrelated ? [Object.assign(alert(), { repository: { full_name: "example/elsewhere" } })] : [];
    const result = await context.bind(await ready(), await retain(alerts));
    expect(result.alerts).toEqual([]);
    expect(result.otherRepositoryAlerts).toBe(alerts.length);
    expect(result.attention).toEqual(expect.arrayContaining(["dependabot_no_repository_observations",
      "dependabot_repository_visibility_not_proven", "dependabot_snapshot_consistency_not_proven"]));
  });

  it("sorts by alert identity and isolates other repository observations", async () => {
    const foreign = alert(3); foreign.repository.full_name = "example/elsewhere";
    const result = await context.bind(await ready(), await retain([alert(2), foreign, alert(1)]));
    expect(result.alerts.map(row => row.alert.number)).toEqual([1, 2]);
    expect(result.otherRepositoryAlerts).toBe(1);
  });

  it.each([false, true])("rejects old snapshots against a newer same-content poll even when empty=%s", async empty => {
    const first = await ready();
    const id = await retain(empty ? [] : [alert()]);
    clock += 1000;
    const selected = await ready();
    expect(selected.snapshotId).toBe(first.snapshotId);
    await expect(context.bind(selected, id)).rejects.toThrow("stale_or_unbound_dependabot_context");
    expect((await context.bind(selected, await retain())).sourceSelection.token).toBe(selected.token);
  });

  it.each(["missing", "other-company", "corrupt", "tampered-selection", "other-org"])("holds %s evidence before returning context", async failure => {
    let selected = await ready();
    let id = await retain();
    if (failure === "missing") id = "0".repeat(64);
    if (failure === "other-company") selected = await ready(sourceLockfiles(), "other-company");
    if (failure === "corrupt") await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.dependabot_snapshots SET bundle = '{}' WHERE snapshot_id = $1`, [id]);
    if (failure === "tampered-selection") selected.stored.inventory.dependencies[0]!.version = "9.9.9";
    if (failure === "other-org") id = await journal.record("company", await snapshot([], "elsewhere"));
    await expect(context.bind(selected, id)).rejects.toThrow();
  });

  it.each([false, true])("rejects future snapshot evidence even when empty=%s", async empty => {
    const selected = await ready();
    clock += 1000;
    const id = await retain(empty ? [] : [alert()]);
    clock -= 1000;
    await expect(context.bind(selected, id)).rejects.toThrow("stale_or_unbound_dependabot_context");
  });

  it("bounds derived alert/tuple expansion without returning a truncated context", async () => {
    const lockfiles = sourceLockfiles();
    const raw = JSON.parse(lockfiles.files[0]!.content);
    for (let index = 0; index < 600; index++) {
      raw.packages[`node_modules/parent-${index}/node_modules/lib`] = {
        version: `1.${index}.0`, resolved: `https://registry.npmjs.org/lib/-/lib-1.${index}.0.tgz`,
      };
    }
    lockfiles.files[0]!.content = JSON.stringify(raw);
    const selected = await ready(rehash(lockfiles));
    const id = await retain(Array.from({ length: 100 }, (_, index) => alert(index + 1)));
    await expect(context.bind(selected, id)).rejects.toThrow("dependabot_context_capacity");
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.card_claims`)).rows).toEqual([]);
  });

  it("rechecks source supersession after retained observation readback", async () => {
    const selected = await ready();
    const id = await retain();
    let changed = false;
    const racing = new DependabotContext({ ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const rows = await db.query<T>(sql, params);
      if (sql.includes("dependabot_snapshots") && !changed) { changed = true; await polls.begin("company", selected.source); }
      return rows;
    } }, now);
    await expect(racing.bind(selected, id)).rejects.toThrow("current_source_pending");
  });

  it("rechecks freshness after suspended storage reads", async () => {
    clock = base - DAY + 1000;
    const selected = await ready();
    const id = await retain();
    const stale = new DependabotContext({ ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const rows = await db.query<T>(sql, params);
      if (sql.includes("dependabot_snapshots")) clock = base + 2000;
      return rows;
    } }, now);
    await expect(stale.bind(selected, id)).rejects.toThrow();
  });
});
