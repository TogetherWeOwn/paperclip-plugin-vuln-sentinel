import { createHash } from "node:crypto";
import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { DecisionJournal } from "./journal.js";
import { decide } from "./matcher.js";
import { parseOsvRecord, type OsvSnapshot } from "./osv.js";
import { ContainerPublication } from "./publication.js";
import { FakeIssues } from "./test/issues.js";
import { DeliveryRouting } from "./routing.js";
import { SourceDecisions } from "./source-decisions.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { parseKev, ThreatFeeds } from "./threat-feeds.js";
import { ThreatJournal } from "./threat-journal.js";
import { testDatabase } from "./test/database.js";
import { sourceLockfiles, sourceOsv } from "./test/sources.js";
import { epssModel, epssResponse } from "./test/threats.js";

const DAY = 86_400_000;
const base = Date.now() - 10_000;
const configured = { repo: "example/project", paths: ["package-lock.json"] };
let postgres: PGlite;
let db: PluginDatabaseClient;
let clock: number;
const now = () => new Date(clock);
let sources: SourceJournal;
let polls: SourcePollStore;
let threats: ThreatJournal;
let matcher: SourceDecisions;
let routing: DeliveryRouting;

function snapshot(empty = false, unavailable = false): OsvSnapshot {
  const value = sourceOsv();
  value.queriedAt = now().toISOString();
  value.records[0] = parseOsvRecord({ ...value.records[0]!.raw, aliases: unavailable ? ["CVE-2026-12345"] : [] }, "GHSA-fixture");
  if (unavailable) value.unavailableIds = ["CVE-2026-12345"];
  if (empty) { value.records = []; value.observations[0]!.advisoryIds = []; }
  return rehash(value);
}
function rehash(value: OsvSnapshot): OsvSnapshot {
  const { snapshotSha256: _, ...content } = value;
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}
async function ready(companyId = "company", sourceSha = "a".repeat(40)) {
  const poll = await polls.begin(companyId, configured);
  const id = await sources.recordLockfiles(companyId, { ...sourceLockfiles(), sourceSha });
  await polls.complete(poll, id);
  return polls.current(companyId, configured);
}
async function feed(at = clock, requested = ["CVE-2026-12345"]) {
  const time = new Date(at).toISOString();
  const date = time.slice(0, 10);
  const feeds = new ThreatFeeds(async () => new Response(JSON.stringify(epssResponse(
    requested.map(cve => ({ cve, epss: "0.04", percentile: "0.99", date })),
  ))), () => new Date(at));
  return threats.record("company", {
    kev: parseKev({ catalogVersion: date, dateReleased: time, count: 1,
      vulnerabilities: [{ cveID: "CVE-2026-12345", dateAdded: date }] }, time),
    epss: await feeds.epss(requested, date, epssModel),
  });
}
async function evidence(empty = false, unavailable = false) {
  const selected = await ready();
  const scan = await sources.recordOsv("company", selected.snapshotId, snapshot(empty, unavailable));
  const threatId = await feed();
  return { selected, scanId: scan.snapshotId, threatId };
}
async function multipleVersions(versions = ["1.2.3", "3.0.0"], unavailable = false, allOutside = false) {
  const poll = await polls.begin("company", configured);
  const lockfiles = sourceLockfiles();
  const file = lockfiles.files[0]!;
  const raw = JSON.parse(file.content);
  delete raw.packages["node_modules/lib"];
  versions.forEach((version, index) => {
    raw.packages[`node_modules/other-${index}/node_modules/lib`] = {
      version, resolved: `https://registry.npmjs.org/lib/-/lib-${version}.tgz`,
    };
  });
  file.content = JSON.stringify(raw);
  file.sha256 = sha256(file.content);
  file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(file.content)}\0`).update(file.content).digest("hex");
  lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
  const id = await sources.recordLockfiles("company", lockfiles);
  await polls.complete(poll, id);
  const selected = await polls.current("company", configured);
  const osv = snapshot(false, unavailable);
  if (allOutside) osv.records[0] = parseOsvRecord({ ...osv.records[0]!.raw, affected: [{
    package: { name: "lib", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
  }] }, "GHSA-fixture");
  osv.observations = versions.map(version => ({ dependency: { ecosystem: "npm", package: "lib", version }, advisoryIds: ["GHSA-fixture"] }));
  const scan = await sources.recordOsv("company", id, rehash(osv));
  return { selected, scanId: scan.snapshotId, threatId: await feed() };
}
async function records(table: string) {
  return (await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows;
}
const observe = (e: { selected: CurrentSource; scanId: string; threatId: string }) => matcher.observe(e.selected, e.scanId, e.threatId);

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots,
    ${DATABASE_NAMESPACE}.threat_snapshots, ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records,
    ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.card_claims`);
  clock = base;
  sources = new SourceJournal(db, now);
  polls = new SourcePollStore(db, now);
  threats = new ThreatJournal(db);
  matcher = new SourceDecisions(db, now);
  routing = new DeliveryRouting(db, now);
});
afterAll(async () => { await postgres.close(); });

describe("retained source decision orchestration", () => {
  it("derives deterministic fenced decisions from retained raw parents, preserving ids and conservative scope", async () => {
    const e = await evidence(false, true);
    const before = structuredClone(e);
    const result = await observe(e);
    expect(e).toEqual(before);
    expect(result).toMatchObject({ status: "attention", lockfileSnapshotId: e.selected.snapshotId,
      osvSnapshotId: e.scanId, threatSnapshotId: e.threatId,
      counters: { dependencies: 1, observations: 1, decisions: 1, routingAttention: 0 } });
    expect(result.attention).toEqual(["repository_discovery_not_proven", "full_dependency_closure_not_proven",
      "runtime_completeness_not_proven", "osv_alias_coverage_incomplete", "severity_not_observed"]);
    const member = (await routing.snapshot("company", configured.repo)).members[0]!;
    const stored = (await new DecisionJournal(db).latest("company", member.currentOriginId))!;
    expect(stored.input_bundle.provenance).toMatchObject({ osvSnapshotId: e.scanId, threatSnapshotId: e.threatId,
      sourceSelection: { snapshotId: e.selected.snapshotId, token: e.selected.token, pollRevision: e.selected.pollRevision } });
    expect(stored.input_bundle.scope).toBe("unknown");
    expect(stored.input_bundle.compatibleFixVerified).toBe(false);
    expect(stored.decision_bundle.priority).toBe(0);
    expect(decide(stored.input_bundle)).toEqual(stored.decision_bundle);
    expect(await records("card_claims")).toEqual([]);
  });

  it("journals vector-derived severity, attention and scorer provenance before replay-safe local routing", async () => {
    const selected = await ready();
    const osv = snapshot();
    osv.records[0] = parseOsvRecord({ ...osv.records[0]!.raw, database_specific: {}, severity: [
      { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" },
      { type: "CVSS_V4", score: "CVSS:4.0/..." },
    ] }, "GHSA-fixture");
    const scan = await sources.recordOsv("company", selected.snapshotId, rehash(osv));
    const e = { selected, scanId: scan.snapshotId, threatId: await feed() };
    const result = await observe(e);
    expect(result.attention).toContain("cvss_v4_not_scored");
    const member = (await routing.snapshot("company", configured.repo)).members[0]!;
    const stored = (await new DecisionJournal(db).latest("company", member.currentOriginId))!;
    expect(stored.input_bundle.severity).toBe("high");
    expect(stored.input_bundle.cvss4Base).toBeNull();
    expect(stored.input_bundle.provenance).toMatchObject({ osvSnapshotId: scan.snapshotId,
      severityAttention: ["cvss_v4_not_scored"], toolVersions: { "vuln-sentinel-osv-severity": "1.0.0" } });
    expect(stored.decision_bundle.priority).toBe(2);
    expect(decide(stored.input_bundle)).toEqual(stored.decision_bundle);
    await Promise.all([observe(e), observe(e)]);
    expect(await records("decision_records")).toHaveLength(1);
    expect(await records("card_claims")).toHaveLength(0);
  });

  it.each([
    { events: [{ introduced: "0" }, { fixed: "v1.0.0" }], status: "unknown" },
    { events: [{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "1.1.0" }, { last_affected: "1.1.1" }], status: "unknown" },
    { events: [{ introduced: "0" }, { limit: "1.0.0" }, { limit: "*" }], status: "affected" },
  ])("retains corrected range evidence and evaluator version across concurrent replay: %j", async ({ events, status }) => {
    const selected = await ready();
    const osv = snapshot();
    osv.records[0] = parseOsvRecord({ ...osv.records[0]!.raw, affected: [{
      package: { name: "lib", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events }],
    }] }, "GHSA-fixture");
    const before = structuredClone(osv.records[0]);
    const scan = await sources.recordOsv("company", selected.snapshotId, rehash(osv));
    const e = { selected, scanId: scan.snapshotId, threatId: await feed() };
    await Promise.all([observe(e), observe(e)]);
    const state = await routing.snapshot("company", configured.repo);
    expect(state.members).toHaveLength(1);
    expect(state.containers).toHaveLength(1);
    const stored = (await new DecisionJournal(db).latest("company", state.members[0]!.currentOriginId))!;
    expect(stored.input_bundle).toMatchObject({ versionEvidence: { status, complete: status !== "unknown" },
      fixedVersion: null, scope: "unknown", compatibleFixVerified: false,
      provenance: { osvSnapshotId: scan.snapshotId, toolVersions: { "vuln-sentinel-osv-ranges": "1.1.0" } } });
    expect(stored.decision_bundle.applicability).toBe("unknown");
    expect(decide(stored.input_bundle)).toEqual(stored.decision_bundle);
    expect(osv.records[0]).toEqual(before);
    await observe(e);
    expect(await records("decision_records")).toHaveLength(1);
    expect(await records("card_claims")).toEqual([]);
    expect(await routing.snapshot("company", configured.repo)).toEqual(state);
  });

  it("sequential and concurrent replay preserve one decision, member and original container", async () => {
    const e = await evidence();
    await observe(e);
    const before = await routing.snapshot("company", configured.repo);
    clock += 1000;
    await Promise.all(Array.from({ length: 6 }, () => observe(e)));
    expect(await routing.snapshot("company", configured.repo)).toEqual(before);
    expect(await records("decision_records")).toHaveLength(1);
    expect(before.members).toHaveLength(1);
    expect(before.containers).toHaveLength(1);
  });

  it("same bytes in a later poll need a newly bound scan; replay never re-stamps old evidence", async () => {
    const e = await evidence();
    await observe(e);
    clock += 1000;
    const selected = await ready();
    expect(selected.snapshotId).toBe(e.selected.snapshotId);
    await expect(matcher.observe(selected, e.scanId, e.threatId)).rejects.toThrow("stale_or_unbound_osv_scan");
    const scan = await sources.recordOsv("company", selected.snapshotId, snapshot());
    await matcher.observe(selected, scan.snapshotId, e.threatId);
    const state = await routing.snapshot("company", configured.repo);
    expect(state.members).toHaveLength(1);
    expect(state.containers).toHaveLength(1);
    expect(state.members[0]!.sourceSelection!.token).toBe(selected.token);
    expect(await records("decision_records")).toHaveLength(2);
  });

  it("empty scans retain coverage attention and never resolve or remove a prior membership", async () => {
    const e = await evidence();
    await observe(e);
    const before = await routing.snapshot("company", configured.repo);
    const empty = await sources.recordOsv("company", e.selected.snapshotId, snapshot(true));
    const result = await matcher.observe(e.selected, empty.snapshotId, e.threatId);
    expect(result.status).toBe("attention");
    expect(result.counters.decisions).toBe(0);
    expect(result.results).toEqual([]);
    expect(await routing.snapshot("company", configured.repo)).toEqual(before);
  });

  it.each(["osv", "threat", "company", "parent", "corruption"])("rejects %s binding failure before decision writes", async failure => {
    const e = await evidence();
    if (failure === "osv") e.scanId = "0".repeat(64);
    if (failure === "threat") e.threatId = "0".repeat(64);
    if (failure === "company") e.selected = await ready("other-company");
    if (failure === "parent") e.selected = await ready("company", "b".repeat(40));
    if (failure === "corruption") await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET bundle = '{}' WHERE snapshot_id = $1`, [e.scanId]);
    await expect(observe(e)).rejects.toThrow();
    expect(await records("decision_records")).toEqual([]);
    expect((await routing.snapshot("company", configured.repo)).members).toEqual([]);
  });

  it.each([false, true])("rejects feeds that were fresh at observation but stale now, even empty=%s", async empty => {
    clock = base - 23 * 3600000;
    const e = await evidence(empty);
    e.threatId = await feed(clock - 26 * 3600000);
    clock = base;
    await expect(observe(e)).rejects.toThrow("stale_or_future_threat_snapshot");
    expect(await records("decision_records")).toEqual([]);
  });

  it.each([false, true])("rejects future feeds even empty=%s", async empty => {
    const e = await evidence(empty);
    e.threatId = await feed(clock + 1000);
    await expect(observe(e)).rejects.toThrow("stale_or_future_threat_snapshot");
    expect(await records("decision_records")).toEqual([]);
  });

  it.each(["before_poll", "future_query", "future_observation", "observation_before_query"])("rejects scan time %s before local projection", async failure => {
    const e = await evidence();
    const osv = snapshot();
    if (failure === "before_poll") osv.queriedAt = new Date(clock - 1000).toISOString();
    if (failure === "future_query" || failure === "observation_before_query") osv.queriedAt = new Date(clock + 1000).toISOString();
    const journal = new SourceJournal(db, () => new Date(clock + (failure === "future_observation" || failure === "future_query" ? 2000 : 0)));
    if (failure === "observation_before_query") {
      await expect(journal.recordOsv("company", e.selected.snapshotId, rehash(osv))).rejects.toThrow("observation_before_query");
    } else {
      e.scanId = (await journal.recordOsv("company", e.selected.snapshotId, rehash(osv))).snapshotId;
      await expect(observe(e)).rejects.toThrow("stale_or_unbound_osv_scan");
    }
    expect(await records("decision_records")).toEqual([]);
  });

  it("prevalidates all alias coverage before writing an earlier valid finding", async () => {
    const e = await evidence();
    const osv = snapshot();
    const record = parseOsvRecord({ ...osv.records[0]!.raw, id: "GHSA-second", aliases: ["CVE-2026-99999"] }, "GHSA-second");
    osv.records.push(record);
    osv.unavailableIds.push("CVE-2026-99999");
    osv.observations[0]!.advisoryIds.push(record.id);
    e.scanId = (await sources.recordOsv("company", e.selected.snapshotId, rehash(osv))).snapshotId;
    await expect(observe(e)).rejects.toThrow("epss_alias_coverage_mismatch");
    expect(await records("decision_records")).toEqual([]);
  });

  it.each([false, true])("aggregates colliding installed versions into one complete action, urgent=%s", async urgent => {
    const e = await multipleVersions(["3.0.0", "1.2.3"], urgent);
    const result = await observe(e);
    expect(result.counters).toMatchObject({ dependencies: 2, observations: 2, decisions: 1, routingAttention: 0 });
    const state = await routing.snapshot("company", configured.repo);
    expect(state.members).toHaveLength(1);
    expect(state.containers).toHaveLength(1);
    const member = state.members[0]!;
    const stored = (await new DecisionJournal(db).latest("company", member.currentOriginId))!;
    expect(stored.input_bundle).toMatchObject({ aggregationVersion: 1, versions: [
      { version: "1.2.3", versionEvidence: { status: "affected" } },
      { version: "3.0.0", versionEvidence: { status: urgent ? "unknown" : "outside" } },
    ], provenance: { osvSnapshotId: e.scanId, threatSnapshotId: e.threatId,
      sourceSelection: { token: e.selected.token, snapshotId: e.selected.snapshotId } } });
    expect(stored.decision_bundle).toMatchObject({ applicability: urgent ? "affected" : "unknown", proposedVex: null,
      versionDecisions: [{ version: "1.2.3", applicability: urgent ? "affected" : "unknown" },
        { version: "3.0.0", applicability: urgent ? "affected" : "dropped" }] });
    expect(stored.input_bundle).not.toHaveProperty("version");
    expect(decide(stored.input_bundle)).toEqual(stored.decision_bundle);
    expect(member.applicability).toBe(urgent ? "affected" : "unknown");
    const issues = new FakeIssues();
    expect(await new ContainerPublication(db, issues).publish("company", configured.repo, member.deliveryOrigin!, "triage", true))
      .toMatchObject({ status: "attention", reason: expect.stringContaining("source-fenced host-effect") });
    expect(issues.lookups).toEqual([]);
    expect(issues.creates).toEqual([]);
    expect(await records("card_claims")).toEqual([]);
  });

  it("multi-version sequential/concurrent replay retains one full decision and original container", async () => {
    const e = await multipleVersions();
    await observe(e);
    const before = await routing.snapshot("company", configured.repo);
    clock += 1000;
    await Promise.all(Array.from({ length: 6 }, () => observe(e)));
    expect(await routing.snapshot("company", configured.repo)).toEqual(before);
    expect(await records("decision_records")).toHaveLength(1);
    expect(await records("finding_records")).toHaveLength(1);
  });

  it("all-version exclusion retains history without delivery or resolution", async () => {
    const e = await multipleVersions();
    await observe(e);
    const before = await routing.snapshot("company", configured.repo);
    clock += 1;
    const next = await multipleVersions(undefined, false, true);
    await observe(next);
    const state = await routing.snapshot("company", configured.repo);
    expect(state.members).toHaveLength(1);
    expect(state.members[0]).toMatchObject({ applicability: "dropped", state: "unresolved", deliveryOrigin: before.members[0]!.deliveryOrigin });
    expect(state.containers).toHaveLength(1);
    expect(await records("decision_records")).toHaveLength(2);
    expect(await records("card_claims")).toEqual([]);
  });

  it.each(["head", "route"])("multi-version source supersession before %s write cannot apply old membership", async phase => {
    const e = await multipleVersions();
    let raced = false;
    const database: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (!raced && (phase === "head" ? sql.includes(".finding_records") : sql.startsWith("UPDATE") && sql.includes(".delivery_routing"))) {
        raced = true; await polls.begin("company", configured);
      }
      return db.execute(sql, params);
    } };
    await expect(new SourceDecisions(database, now).observe(e.selected, e.scanId, e.threatId))
      .rejects.toThrow(/source_fence_rejected|current_source_pending/u);
    expect(await records("decision_records")).toHaveLength(1);
    expect((await routing.snapshot("company", configured.repo)).members).toEqual([]);
    expect(await records("card_claims")).toEqual([]);
  });

  it("multi-version lost routing response replays the full action without tuple/head duplication", async () => {
    const e = await multipleVersions();
    let failed = false;
    const database: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (!failed && sql.startsWith("UPDATE") && sql.includes(".delivery_routing")) { failed = true; throw new Error("lost response"); }
      return result;
    } };
    await expect(new SourceDecisions(database, now).observe(e.selected, e.scanId, e.threatId)).rejects.toThrow("lost response");
    await observe(e);
    expect(await records("decision_records")).toHaveLength(1);
    expect((await routing.snapshot("company", configured.repo)).members).toHaveLength(1);
  });

  it.each([false, true])("rechecks the source after final preflight, including empty=%s", async empty => {
    const e = await evidence(empty);
    let reads = 0;
    const database: PluginDatabaseClient = { ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const result = await db.query<T>(sql, params);
      if (sql.includes(".source_polls") && ++reads === 5) await polls.begin("company", configured);
      return result;
    } };
    await expect(new SourceDecisions(database, now).observe(e.selected, e.scanId, e.threatId)).rejects.toThrow(/source_poll_superseded|current_source_pending/u);
    expect(await records("card_claims")).toEqual([]);
  });

  it("retains positive findings while surfacing incomplete configured-path parsing", async () => {
    const poll = await polls.begin("company", { ...configured, paths: ["package-lock.json", "unknown.lock"] });
    const lockfiles = sourceLockfiles();
    lockfiles.files.push({ ...lockfiles.files[0]!, path: "unknown.lock" });
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson(lockfiles.files.map(file => [file.path, file.sha256]).sort()))}`;
    const id = await sources.recordLockfiles("company", lockfiles);
    await polls.complete(poll, id);
    const selected = await polls.current("company", poll.source);
    const scan = await sources.recordOsv("company", id, snapshot());
    const result = await matcher.observe(selected, scan.snapshotId, await feed());
    expect(result.attention).toContain("inventory_parse_attention");
    expect(result.inventory.coverage.configuredPathsParsed).toBe(false);
    expect(result.counters.decisions).toBe(1);
    expect((await routing.snapshot("company", configured.repo)).members).toHaveLength(1);
  });

  describe("partial retained inventory", () => {
    const cases = [
      { format: "npm", path: "tools/package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: {
        "": {},
        "node_modules/lost": { version: "1.0.0", resolved: "https://registry.npmjs.org/lost/-/lost-1.0.0.tgz" },
        "node_modules/broken": { version: "v1.0.0", resolved: "https://registry.npmjs.org/broken/-/broken-1.0.0.tgz" },
      } }) },
      { format: "pnpm", path: "tools/pnpm-lock.yaml", content: `lockfileVersion: '9.0'
importers: {'.': {}}
packages:
  lost@1.0.0: {resolution: {integrity: sha512-YQ==}}
  broken@v1.0.0: {resolution: {integrity: sha512-YQ==}}
snapshots: {lost@1.0.0: {}, broken@v1.0.0: {}}
` },
      { format: "cargo", path: "tools/Cargo.lock", content: `version = 4
[[package]]
name = "lost"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "${"a".repeat(64)}"
[[package]]
name = "broken"
version = "v1.0.0"
` },
      { format: "unsupported", path: "tools/unknown.lock", content: sourceLockfiles().files[0]!.content },
    ];

    function lockfiles(files: Array<{ path: string; content: string }>) {
      const value = sourceLockfiles();
      value.files = files.map(({ path, content }) => ({ path, content, sha256: sha256(content), etag: null,
        blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex"),
      }));
      value.artifactDigest = `sha256:${sha256(canonicalJson([...value.files]
        .sort((a, b) => a.path.localeCompare(b.path)).map(file => [file.path, file.sha256])))}`;
      return value;
    }

    async function retain(files: ReturnType<typeof lockfiles>, osv: OsvSnapshot) {
      const configuredSource = { repo: configured.repo, paths: files.files.map(file => file.path) };
      const poll = await polls.begin("company", configuredSource);
      const id = await sources.recordLockfiles("company", files);
      await polls.complete(poll, id);
      const selected = await polls.current("company", configuredSource);
      const scan = await sources.recordOsv("company", id, rehash(osv));
      return { selected, scanId: scan.snapshotId, threatId: await feed() };
    }

    it.each(cases.flatMap(fixture => [false, true].map(empty => ({ ...fixture, empty }))))(
      "keeps omitted prior members unresolved and independent positives replayable: $format, empty=$empty",
      async ({ format, path, content, empty }) => {
        const complete = sourceLockfiles();
        const raw = JSON.parse(complete.files[0]!.content);
        raw.packages["node_modules/lost"] = { version: "1.0.0", resolved: "https://registry.npmjs.org/lost/-/lost-1.0.0.tgz" };
        const firstOsv = snapshot();
        const lost = parseOsvRecord({ ...firstOsv.records[0]!.raw, id: "GHSA-lost", affected: [{
          package: { name: "lost", ecosystem: "npm" }, versions: ["1.0.0"],
        }] }, "GHSA-lost");
        firstOsv.records.push(lost);
        firstOsv.observations.push({ dependency: { ecosystem: "npm", package: "lost", version: "1.0.0" }, advisoryIds: [lost.id] });
        const first = await retain(lockfiles([{ path: "package-lock.json", content: JSON.stringify(raw) }]), firstOsv);
        await observe(first);
        const before = await routing.snapshot("company", configured.repo);
        expect(before.members).toHaveLength(2);
        const omitted = before.members.find(member => member.package === "lost")!;
        expect(omitted).toBeDefined();
        clock += 1;

        const partial = lockfiles([complete.files[0]!, { path, content }]);
        const e = await retain(partial, snapshot(empty));
        const retainedBefore = await sources.readOsv("company", e.scanId);
        const results = await Promise.all(Array.from({ length: 4 }, () => observe(e)));
        for (const result of results) {
          expect(result).toMatchObject({ status: "attention", lockfileSnapshotId: e.selected.snapshotId,
            osvSnapshotId: e.scanId, threatSnapshotId: e.threatId,
            counters: { dependencies: 1, observations: 1, decisions: empty ? 0 : 1, routingAttention: 0 },
            inventory: { coverage: { configuredPathsParsed: false, repositoryDiscovery: "not_proven",
              fullDependencyClosure: "not_proven", runtimeCompleteness: "not_proven" } } });
          expect(result.attention).toContain("inventory_parse_attention");
          expect(result.inventory.files.find(file => file.path === path)).toMatchObject({ format, status: "attention", entries: 0 });
          expect(result.inventory.dependencies).toEqual([expect.objectContaining({ package: "lib", version: "1.2.3", scope: "unknown", direct: null })]);
        }
        const state = await routing.snapshot("company", configured.repo);
        expect(state.members).toHaveLength(2);
        expect(state.members.find(member => member.package === "lost")).toEqual(omitted);
        expect(state.members.every(member => member.state === "unresolved")).toBe(true);
        expect(state.rescanHolds).toBeUndefined();
        if (empty) expect(state).toEqual(before);
        else {
          const member = state.members.find(member => member.package === "lib")!;
          const stored = (await new DecisionJournal(db).latest("company", member.currentOriginId))!;
          expect(stored.input_bundle).toMatchObject({ scope: "unknown", fixedVersion: null, compatibleFixVerified: false,
            provenance: { artifactDigest: partial.artifactDigest, osvSnapshotId: e.scanId, threatSnapshotId: e.threatId,
              sourceSelection: { token: e.selected.token, snapshotId: e.selected.snapshotId },
              toolVersions: retainedBefore!.inventory.toolVersions } });
          expect(stored.decision_bundle.applicability).toBe("unknown");
          expect(stored.decision_bundle.proposedVex).toBeNull();
          expect(decide(stored.input_bundle)).toEqual(stored.decision_bundle);
        }
        await observe(e);
        expect(await routing.snapshot("company", configured.repo)).toEqual(state);
        expect(await records("decision_records")).toHaveLength(empty ? 2 : 3);
        expect(await records("finding_records")).toHaveLength(2);
        expect(await records("card_claims")).toEqual([]);
        expect(await sources.readOsv("company", e.scanId)).toEqual(retainedBefore);
        expect((await sources.readLockfiles("company", e.selected.snapshotId))!.lockfiles).toEqual(partial);
      },
    );

    it.each(cases)("keeps an all-attention $format source empty without certifying absence", async ({ path, content }) => {
      const initial = await evidence();
      await observe(initial);
      const before = await routing.snapshot("company", configured.repo);
      clock += 1;
      const empty = snapshot(true);
      empty.observations = [];
      const e = await retain(lockfiles([{ path, content }]), empty);
      const result = await observe(e);
      expect(result).toMatchObject({ status: "attention", results: [], counters: { dependencies: 0, observations: 0, decisions: 0, routingAttention: 0 } });
      expect(result.attention).toContain("inventory_parse_attention");
      expect(result.inventory.files[0]).toMatchObject({ status: "attention", entries: 0 });
      expect(await routing.snapshot("company", configured.repo)).toEqual(before);
      expect(await records("decision_records")).toHaveLength(1);
      expect(await records("card_claims")).toEqual([]);
    });

    it.each(cases)("binds changed unparsed $format bytes into distinct raw and decision provenance", async ({ path, content }) => {
      const root = sourceLockfiles().files[0]!;
      const first = await retain(lockfiles([root, { path, content }]), snapshot());
      await observe(first);
      const firstRaw = await sources.readOsv("company", first.scanId);
      clock += 1;
      const second = await retain(lockfiles([root, { path, content: `${content}\n` }]), snapshot());
      await observe(second);
      expect(second.selected.snapshotId).not.toBe(first.selected.snapshotId);
      expect(second.scanId).not.toBe(first.scanId);
      const secondRaw = (await sources.readOsv("company", second.scanId))!;
      expect(secondRaw.inventory.dependencies).toEqual(firstRaw!.inventory.dependencies);
      expect(secondRaw.inventory.artifactDigest).not.toBe(firstRaw!.inventory.artifactDigest);
      expect(secondRaw.inventory.inventorySha256).not.toBe(firstRaw!.inventory.inventorySha256);
      expect(await sources.readOsv("company", first.scanId)).toEqual(firstRaw);
      const state = await routing.snapshot("company", configured.repo);
      expect(state.members).toHaveLength(1);
      expect(state.containers).toHaveLength(1);
      const stored = (await new DecisionJournal(db).latest("company", state.members[0]!.currentOriginId))!;
      expect(stored.input_bundle.provenance).toMatchObject({ artifactDigest: secondRaw.inventory.artifactDigest,
        osvSnapshotId: second.scanId, sourceSelection: { snapshotId: second.selected.snapshotId } });
      expect(await records("decision_records")).toHaveLength(2);
      expect(await records("card_claims")).toEqual([]);
    });
  });

  it.each([false, true])("supersession during retained feed read prevents writes, even empty=%s", async empty => {
    const e = await evidence(empty);
    let raced = false;
    const database: PluginDatabaseClient = { ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const result = await db.query<T>(sql, params);
      if (!raced && sql.includes(".threat_snapshots")) { raced = true; await polls.begin("company", configured); }
      return result;
    } };
    await expect(new SourceDecisions(database, now).observe(e.selected, e.scanId, e.threatId)).rejects.toThrow("current_source_pending");
    expect(await records("decision_records")).toEqual([]);
  });

  it("supersession after a committed route cannot report a completed current batch", async () => {
    const e = await evidence();
    let raced = false;
    const database: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (!raced && sql.startsWith("UPDATE") && sql.includes(".delivery_routing")) {
        raced = true; await polls.begin("company", configured);
      }
      return result;
    } };
    await expect(new SourceDecisions(database, now).observe(e.selected, e.scanId, e.threatId)).rejects.toThrow("current_source_pending");
    expect(await records("decision_records")).toHaveLength(1);
    expect((await routing.snapshot("company", configured.repo)).members).toHaveLength(1);
    expect(await records("card_claims")).toEqual([]);
  });

  it("repairs lost routing responses by retained-reference replay without duplicate history", async () => {
    const e = await evidence();
    let failed = false;
    const database: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (!failed && sql.startsWith("UPDATE") && sql.includes(".delivery_routing")) { failed = true; throw new Error("lost response"); }
      return result;
    } };
    await expect(new SourceDecisions(database, now).observe(e.selected, e.scanId, e.threatId)).rejects.toThrow("lost response");
    await observe(e);
    expect(await records("decision_records")).toHaveLength(1);
    expect((await routing.snapshot("company", configured.repo)).members).toHaveLength(1);
  });
});
