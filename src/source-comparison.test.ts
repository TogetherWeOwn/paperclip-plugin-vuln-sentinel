import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { DependabotJournal } from "./dependabot-journal.js";
import { DependabotSource } from "./dependabot.js";
import { canonicalJson, sha256 } from "./identity.js";
import { parseOsvRecord, type OsvSnapshot } from "./osv.js";
import { SourceComparison } from "./source-comparison.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore } from "./source-polls.js";
import { testDatabase } from "./test/database.js";
import { dependabotAlert } from "./test/dependabot.js";
import { sourceLockfiles, sourceOsv } from "./test/sources.js";

const base = Date.now() - 10_000;
const DAY = 86_400_000;
let postgres: PGlite;
let db: PluginDatabaseClient;
let clock: number;
const now = () => new Date(clock);
let polls: SourcePollStore;
let sources: SourceJournal;
const ghsa = "GHSA-2345-6789-cfgh";
type RawAlert = ReturnType<typeof dependabotAlert>;
type Alert = Omit<RawAlert, "security_advisory"> & {
  security_advisory: Omit<RawAlert["security_advisory"], "withdrawn_at"> & { withdrawn_at: string | null };
};

function alert(): Alert {
  const value = dependabotAlert();
  value.dependency.package.name = "lib";
  value.security_vulnerability.package.name = "lib";
  value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
  return value;
}
function scan(ids = [ghsa]): OsvSnapshot {
  const original = sourceOsv().records[0]!;
  const records = ids.map(id => parseOsvRecord({ ...original.raw, id, database_specific: { severity: "HIGH" } }, id));
  return rehash({ ...sourceOsv(), queriedAt: now().toISOString(), records,
    observations: [{ dependency: { ecosystem: "npm", package: "lib", version: "1.2.3" }, advisoryIds: ids }] });
}
function rehash(snapshot: OsvSnapshot): OsvSnapshot {
  const { snapshotSha256: _, ...content } = snapshot;
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}
async function setup(alerts = [alert()], snapshot = scan()) {
  const lockfiles = sourceLockfiles();
  const source = { repo: lockfiles.repo, paths: lockfiles.files.map(file => file.path) };
  const poll = await polls.begin("company", source);
  const lockId = await sources.recordLockfiles("company", lockfiles);
  await polls.complete(poll, lockId);
  const selected = await polls.current("company", source);
  const response = await new DependabotSource(async () => new Response(JSON.stringify(alerts)), "fixture", now).read("example");
  if (response.status !== "available") throw new Error("fixture unavailable");
  const dependabotId = await new DependabotJournal(db).record("company", response.snapshot);
  const osvId = (await sources.recordOsv("company", lockId, snapshot)).snapshotId;
  return { selected, dependabotId, osvId };
}
async function compare(fixture: Awaited<ReturnType<typeof setup>>, client = db) {
  return new SourceComparison(client, now).read(fixture.selected, fixture.dependabotId, fixture.osvId);
}

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots,
    ${DATABASE_NAMESPACE}.dependabot_snapshots`);
  clock = base;
  polls = new SourcePollStore(db, now);
  sources = new SourceJournal(db, now);
});
afterAll(async () => { await postgres.close(); });

describe("retained source comparison without policy mutation", () => {
  it("reports exact tuple/shared identity correspondence but never agreement as policy authority", async () => {
    const fixture = await setup();
    const result = await compare(fixture);
    expect(result).toMatchObject({ status: "attention", policySource: "osv_unchanged", osvSnapshotId: fixture.osvId,
      tuples: [{ alertNumber: 1, path: "package-lock.json", tuple: { dependency: { package: "lib", version: "1.2.3" },
        locators: ["node_modules/lib"], rangeMatch: "matches" }, attention: [],
        matches: [{ sharedIds: [ghsa], observation: { advisoryId: ghsa, versionStatus: "affected", severity: "high" } }] }],
      unmatchedOsv: [] });
    expect(result.context.alerts[0]!.alert.scope).toBe("development");
    expect(result.attention).toEqual(expect.arrayContaining(["dependabot_scope_not_applied", "source_comparison_not_policy_reconciliation",
      "dependabot_source_switch_not_enabled", "native_publication_disabled", "enabled_pilot_not_run"]));
    const { comparisonSha256, ...content } = result;
    expect(comparisonSha256).toBe(sha256(canonicalJson(["source-comparison-v1", content])));
  });

  it("uses query calls only, with no source, decision, routing, claim or pin mutation", async () => {
    const fixture = await setup();
    const execute = vi.fn(async () => { throw new Error("writes forbidden"); });
    const result = await compare(fixture, { ...db, query: db.query.bind(db), execute });
    expect(result.status).toBe("attention");
    expect(execute).not.toHaveBeenCalled();
    for (const table of ["decision_records", "delivery_routing", "card_claims"]) {
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows).toEqual([]);
    }
    expect(await polls.current("company", fixture.selected.source)).toEqual(fixture.selected);
  });

  it("replays after reconstruction and concurrently without restamping or changing caller values", async () => {
    const fixture = await setup(); const before = structuredClone(fixture);
    const result = await compare(fixture);
    clock += 1_000;
    expect(await Promise.all(Array.from({ length: 4 }, () => compare(fixture)))).toEqual(Array.from({ length: 4 }, () => result));
    expect(fixture).toEqual(before);
  });

  it("matches through an observed CVE alias without retagging the OSV identity", async () => {
    const fixture = await setup([alert()], scan(["CVE-2026-12345"]));
    const result = await compare(fixture);
    expect(result.tuples[0]!.matches[0]).toMatchObject({ sharedIds: ["CVE-2026-12345"],
      observation: { advisoryId: "CVE-2026-12345" } });
  });

  it("keeps multiple OSV groups separate when a Dependabot record bridges them", async () => {
    const result = await compare(await setup([alert()], scan([ghsa, "CVE-2026-12345"])));
    expect(result.tuples[0]!.matches).toHaveLength(2);
    expect(result.tuples[0]!.attention).toContain("dependabot_alias_bridge_ambiguous");
    expect(result.unmatchedOsv).toEqual([]);
  });

  it("retains both unmatched sides rather than joining merely by package or severity", async () => {
    const result = await compare(await setup([alert()], scan(["GHSA-unrelated"])));
    expect(result.tuples[0]!.matches).toEqual([]);
    expect(result.tuples[0]!.attention).toContain("dependabot_tuple_without_shared_osv_observation");
    expect(result.unmatchedOsv).toHaveLength(1);
  });

  it.each(["package.json", "nested/package-lock.json"]) ("does not guess manifest association for %s", async path => {
    const value = alert(); value.dependency.manifest_path = path;
    const result = await compare(await setup([value]));
    expect(result.tuples).toEqual([]);
    expect(result.unmatchedOsv).toHaveLength(1);
    expect(result.context.alerts[0]!.attention).toContain("dependabot_manifest_not_in_selected_inventory");
  });

  it.each(["fixed", "dismissed", "auto_dismissed"]) ("keeps %s observations as attention, never resolution", async state => {
    const value = alert(); value.state = state;
    const result = await compare(await setup([value]));
    expect(result.tuples[0]!.attention).toContain("dependabot_alert_not_open");
    expect(result.policySource).toBe("osv_unchanged");
  });

  it("retains range disagreement without dropping the affected OSV observation", async () => {
    const value = alert(); value.security_vulnerability.vulnerable_version_range = ">= 2.0.0";
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await compare(await setup([value]));
    expect(result.tuples[0]!.attention).toContain("source_range_disagreement");
    expect(result.tuples[0]!.matches[0]!.observation.versionStatus).toBe("affected");
  });

  it("retains unsupported comparator context as unknown, never disagreement-as-exclusion", async () => {
    const value = alert(); value.security_vulnerability.vulnerable_version_range = "^1.0.0";
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await compare(await setup([value]));
    expect(result.tuples[0]!.attention).toContain("source_range_comparison_unknown");
    expect(result.tuples[0]!.attention).not.toContain("source_range_disagreement");
  });

  it("reports severity disagreement without changing OSV severity or trusting scope/fix hints", async () => {
    const value = alert(); value.security_vulnerability.severity = "critical"; value.security_advisory.severity = "critical";
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await compare(await setup([value]));
    expect(result.tuples[0]!.attention).toContain("source_severity_disagreement");
    expect(result.tuples[0]!.matches[0]!.observation.severity).toBe("high");
  });

  it("keeps empty comparisons attention and never removes existing membership", async () => {
    const empty = scan([]);
    const result = await compare(await setup([], empty));
    expect(result).toMatchObject({ status: "attention", tuples: [], unmatchedOsv: [] });
    expect(result.context.attention).toContain("dependabot_no_repository_observations");
  });

  it("reports withdrawal disagreement without accepting it as current absence", async () => {
    const value = alert();
    value.security_advisory.withdrawn_at = "2026-11-03T00:00:00Z";
    const result = await compare(await setup([value]));
    expect(result.tuples[0]!.attention).toContain("source_withdrawal_disagreement");
    expect(result.tuples[0]!.attention).toContain("dependabot_advisory_withdrawn");
    expect(result.tuples[0]!.matches[0]!.observation.versionStatus).toBe("affected");
  });

  it("keeps unavailable OSV alias evidence and explicit coverage attention", async () => {
    const snapshot = scan();
    snapshot.records = [parseOsvRecord({ ...snapshot.records[0]!.raw, aliases: ["CVE-2026-12345"] }, ghsa)];
    snapshot.unavailableIds = ["CVE-2026-12345"];
    const result = await compare(await setup([alert()], rehash(snapshot)));
    expect(result.attention).toContain("osv_alias_coverage_incomplete");
    expect(result.tuples[0]!.matches[0]!.sharedIds).toEqual(["CVE-2026-12345", ghsa]);
    expect(result.tuples[0]!.matches[0]!.observation.revisions).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "CVE-2026-12345", modified: null, withdrawn: null }),
    ]));
  });

  it("does not join a shared advisory ID for another installed package", async () => {
    const value = alert(); value.dependency.package.name = "other";
    value.security_vulnerability.package.name = "other";
    value.security_advisory.vulnerabilities = [structuredClone(value.security_vulnerability)];
    const result = await compare(await setup([value]));
    expect(result.tuples).toEqual([]);
    expect(result.unmatchedOsv).toHaveLength(1);
  });

  it("does not join a shared advisory for a different installed version", async () => {
    const fixture = await setup();
    // A raw observation of a different version cannot enter this path via its parent journal.
    const snapshot = scan(); snapshot.observations[0]!.dependency.version = "2.0.0";
    await expect(sources.recordOsv("company", fixture.selected.snapshotId, rehash(snapshot)))
      .rejects.toThrow("osv_inventory_coverage_mismatch");
  });

  it("rejects equal bytes from a different immutable source parent", async () => {
    const fixture = await setup();
    const lockfiles = sourceLockfiles(); lockfiles.sourceSha = "b".repeat(40);
    const id = await sources.recordLockfiles("company", lockfiles);
    fixture.osvId = (await sources.recordOsv("company", id, scan())).snapshotId;
    await expect(compare(fixture)).rejects.toThrow("osv_source_binding_mismatch");
  });

  it("holds derived expansion at capacity instead of returning a truncated comparison", async () => {
    const snapshot = scan();
    const aliases = Array.from({ length: 1_000 }, (_, i) => `ALIAS-${i}`);
    snapshot.records = [parseOsvRecord({ ...snapshot.records[0]!.raw, aliases }, ghsa)];
    snapshot.unavailableIds = aliases;
    const alerts = Array.from({ length: 100 }, (_, i) => ({ ...alert(), number: i + 1 }));
    await expect(compare(await setup(alerts, rehash(snapshot)))).rejects.toThrow("source_comparison_capacity");
  });

  it("rejects a missing/cross-company OSV reference", async () => {
    const fixture = await setup();
    await postgres.exec(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET company_id = 'other' WHERE source_kind = 'osv'`);
    await expect(compare(fixture)).rejects.toThrow("missing_osv_snapshot");
  });

  it("rejects corrupt retained OSV evidence", async () => {
    const fixture = await setup();
    await postgres.exec(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET bundle = '{}' WHERE source_kind = 'osv'`);
    await expect(compare(fixture)).rejects.toThrow("stored_source_hash_mismatch");
  });

  it("rejects an old query even when its immutable lockfile parent is selected again", async () => {
    const fixture = await setup(); clock += 1_000;
    const poll = await polls.begin("company", fixture.selected.source);
    await polls.complete(poll, fixture.selected.snapshotId);
    fixture.selected = await polls.current("company", fixture.selected.source);
    // Re-observe alerts after the new selection; the earlier OSV query is still ineligible.
    const response = await new DependabotSource(async () => new Response(JSON.stringify([alert()])), "fixture", now).read("example");
    if (response.status !== "available") throw new Error("fixture");
    fixture.dependabotId = await new DependabotJournal(db).record("company", response.snapshot);
    await expect(compare(fixture)).rejects.toThrow("stale_or_unbound_osv_scan");
  });

  it("rejects supersession while retained OSV is read, including an empty comparison", async () => {
    const fixture = await setup([], scan([]));
    const client = { ...db, query: async <T>(sql: string, params: unknown[]) => {
      const rows = await db.query<T>(sql, params);
      if (params.includes("osv")) await polls.begin("company", fixture.selected.source);
      return rows;
    } };
    await expect(compare(fixture, client)).rejects.toThrow("current_source_pending");
  });

  it("rechecks freshness after the final asynchronous validation", async () => {
    const fixture = await setup([], scan([]));
    let readOsv = false;
    const client = { ...db, query: async <T>(sql: string, params: unknown[]) => {
      const rows = await db.query<T>(sql, params);
      if (params.includes("osv")) readOsv = true;
      else if (readOsv && sql.includes("source_polls")) clock += DAY + 1;
      return rows;
    } };
    await expect(compare(fixture, client)).rejects.toThrow("current_source_stale");
  });

  it("propagates storage failure with no successful partial comparison", async () => {
    const fixture = await setup();
    const client = { ...db, query: async <T>(sql: string, params: unknown[]): Promise<T[]> => {
      if (params.includes("osv")) throw new Error("fixture unavailable");
      return db.query<T>(sql, params);
    } };
    await expect(compare(fixture, client)).rejects.toThrow("fixture unavailable");
  });
});
