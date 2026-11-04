import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { DecisionJournal } from "./journal.js";
import { decide } from "./matcher.js";
import { RepositoryScan, type RepositoryScanOptions } from "./repository-scan.js";
import { DeliveryRouting } from "./routing.js";
import { SourceJournal } from "./source-journal.js";
import type { SourceFetch } from "./source-http.js";
import { SourcePollStore } from "./source-polls.js";
import { testDatabase } from "./test/database.js";
import { sourceLockfiles, sourceOsv } from "./test/sources.js";
import { epssModel, epssResponse, rawKev } from "./test/threats.js";

const base = Date.now() - 10_000;
let postgres: PGlite;
let db: PluginDatabaseClient;
let clock: number;
const now = () => new Date(clock);
const configured = { repo: "example/project", paths: ["package-lock.json"] };
let polls: SourcePollStore;
let sources: SourceJournal;
let options: RepositoryScanOptions;
let requests: string[];
let empty: boolean;
let fail: string | null;
let beforeResponse: (url: string) => Promise<void>;

const fetch: SourceFetch = async (url, init) => {
  requests.push(url);
  expect(new Headers(init.headers).has("authorization")).toBe(false);
  expect(init.redirect).toBe("error");
  await beforeResponse(url);
  clock += 10;
  if (fail && url.includes(fail)) return new Response(null, { status: 503 });
  if (url.endsWith("/querybatch")) {
    const input = JSON.parse(init.body as string);
    return new Response(JSON.stringify({ results: input.queries.map(() => empty ? {} : { vulns: [
      { id: "GHSA-fixture", modified: sourceOsv().records[0]!.modified },
    ] }) }));
  }
  if (url.endsWith("/vulns/GHSA-fixture")) return new Response(JSON.stringify({
    ...sourceOsv().records[0]!.raw, aliases: ["CVE-2026-12345", "CVE-2026-56789"],
  }));
  if (url.includes("/vulns/CVE-")) return new Response(null, { status: 404 });
  if (url.includes("www.cisa.gov/")) return new Response(JSON.stringify(rawKev()));
  if (url.includes("api.first.org/")) {
    const query = new URL(url);
    expect(query.searchParams.get("date")).toBe(options.epssDate);
    return new Response(JSON.stringify(epssResponse(query.searchParams.get("cve")!.split(",").map(cve => ({
      cve, epss: "0.05", percentile: "0.99", date: options.epssDate,
    })))));
  }
  throw new Error(`Unexpected fixture request ${url}`);
};

async function ready(companyId = "company") {
  const poll = await polls.begin(companyId, configured);
  const id = await sources.recordLockfiles(companyId, sourceLockfiles());
  await polls.complete(poll, id);
  return polls.current(companyId, configured);
}
async function count(table: string) {
  return (await postgres.query<Record<string, unknown>>(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows;
}

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots,
    ${DATABASE_NAMESPACE}.threat_snapshots, ${DATABASE_NAMESPACE}.dependabot_snapshots,
    ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records,
    ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.card_claims`);
  clock = base;
  polls = new SourcePollStore(db, now);
  sources = new SourceJournal(db, now);
  options = { epssDate: now().toISOString().slice(0, 10), epssModel: structuredClone(epssModel) };
  requests = []; empty = false; fail = null; beforeResponse = async () => undefined;
});
afterAll(async () => { await postgres.close(); });

describe("explicit repository scan to fenced local report projections", () => {
  it("retains source/feed evidence before deriving deterministic all-alias decisions", async () => {
    const selected = await ready();
    const original = structuredClone({ selected, options });
    const result = await new RepositoryScan(db, fetch, now).run(selected, options);
    expect({ selected, options }).toEqual(original);
    expect(result).toMatchObject({ status: "attention", startedAt: new Date(base).toISOString(),
      decisions: { status: "attention", lockfileSnapshotId: selected.snapshotId,
        counters: { dependencies: 1, observations: 1, decisions: 1, routingAttention: 0 } } });
    expect(result.attention).toEqual(expect.arrayContaining(["native_publication_disabled", "enabled_pilot_not_run",
      "osv_alias_coverage_incomplete", "dependabot_source_switch_not_enabled"]));
    const retained = (await sources.readOsv("company", result.decisions.osvSnapshotId))!;
    expect(Date.parse(retained.scan.observedAt)).toBeGreaterThan(Date.parse(retained.scan.osv.queriedAt));
    expect(retained.scan.osv.unavailableIds).toEqual(["CVE-2026-12345", "CVE-2026-56789"]);
    const feed = (await count("threat_snapshots"))[0]!.bundle as Record<string, any>;
    expect(feed.epss.requestedCves).toEqual(["CVE-2026-12345", "CVE-2026-56789"]);
    expect(Date.parse(retained.scan.observedAt)).toBeGreaterThanOrEqual(Date.parse(feed.epss.queriedAt));
    const state = await new DeliveryRouting(db, now).snapshot("company", configured.repo);
    const stored = (await new DecisionJournal(db).latest("company", state.members[0]!.currentOriginId))!;
    expect(stored.decision_bundle.priority).toBe(0);
    expect(stored.input_bundle.provenance).toMatchObject({ osvSnapshotId: result.decisions.osvSnapshotId,
      threatSnapshotId: result.decisions.threatSnapshotId, sourceSelection: { token: selected.token } });
    expect(decide(stored.input_bundle)).toEqual(stored.decision_bundle);
    expect(await count("card_claims")).toEqual([]);
    expect(requests.some(url => url.includes("github.com"))).toBe(false);
  });

  it("sequential/concurrent library scans retain one member/container without native claims", async () => {
    const selected = await ready();
    const first = await new RepositoryScan(db, fetch, now).run(selected, options);
    const before = await new DeliveryRouting(db, now).snapshot("company", configured.repo);
    const results = await Promise.all(Array.from({ length: 5 }, () => new RepositoryScan(db, fetch, now).run(selected, options)));
    expect(results.every(result => result.status === "attention")).toBe(true);
    const after = await new DeliveryRouting(db, now).snapshot("company", configured.repo);
    expect(after.members).toHaveLength(1);
    expect(after.containers).toHaveLength(1);
    expect(after.members[0]!.deliveryOrigin).toBe(before.members[0]!.deliveryOrigin);
    expect(first.attention).toContain("enabled_pilot_not_run");
    expect(await count("card_claims")).toEqual([]);
  });

  it("an empty later scan retains coverage attention and never resolves existing membership", async () => {
    const selected = await ready();
    await new RepositoryScan(db, fetch, now).run(selected, options);
    const before = await new DeliveryRouting(db, now).snapshot("company", configured.repo);
    empty = true;
    const result = await new RepositoryScan(db, fetch, now).run(selected, options);
    expect(result.decisions.results).toEqual([]);
    expect(result.decisions.counters.decisions).toBe(0);
    expect(result.status).toBe("attention");
    expect(await new DeliveryRouting(db, now).snapshot("company", configured.repo)).toEqual(before);
  });

  it.each(["querybatch", "vulns/GHSA-fixture", "cisa.gov", "api.first.org"])("holds %s provider failures without decisions", async provider => {
    const selected = await ready();
    fail = provider;
    await expect(new RepositoryScan(db, fetch, now).run(selected, options)).rejects.toThrow();
    expect(await count("decision_records")).toEqual([]);
    expect(await count("card_claims")).toEqual([]);
  });

  it.each(["source_snapshots", "threat_snapshots"])("holds lost %s persistence responses and replays safely", async table => {
    const selected = await ready();
    const lost = { ...db, execute: async (sql: string, params?: unknown[]) => {
      const result = await db.execute(sql, params);
      if (sql.includes(table)) throw new Error("response lost");
      return result;
    } };
    await expect(new RepositoryScan(lost, fetch, now).run(selected, options)).rejects.toThrow("response lost");
    expect(await count("decision_records")).toEqual([]);
    await new RepositoryScan(db, fetch, now).run(selected, options);
    expect((await new DeliveryRouting(db, now).snapshot("company", configured.repo)).members).toHaveLength(1);
    expect(await count("card_claims")).toEqual([]);
  });

  it.each(["querybatch", "cisa.gov", "api.first.org"])("rejects source invalidation during %s without local projections", async provider => {
    const selected = await ready();
    beforeResponse = async url => { if (url.includes(provider)) await polls.begin("company", configured); };
    await expect(new RepositoryScan(db, fetch, now).run(selected, options)).rejects.toThrow("current_source_pending");
    expect(await count("decision_records")).toEqual([]);
  });

  it.each(["stale", "pending", "forged"])("does not read providers for a %s selection", async failure => {
    const selected = await ready();
    if (failure === "stale") clock += 86_400_001;
    if (failure === "pending") await polls.begin("company", configured);
    if (failure === "forged") selected.stored.inventory.dependencies[0]!.package = "other";
    await expect(new RepositoryScan(db, fetch, now).run(selected, options)).rejects.toThrow();
    expect(requests).toEqual([]);
  });

  it.each([600_001, -1000])("holds scan clock/deadline drift of %s ms after a read", async drift => {
    const selected = await ready();
    beforeResponse = async () => { clock += drift; };
    await expect(new RepositoryScan(db, fetch, now).run(selected, options)).rejects.toThrow("repository_scan_deadline");
    expect(await count("decision_records")).toEqual([]);
  });

  it("does not substitute guessed EPSS model mapping or stale score dates", async () => {
    const selected = await ready();
    options.epssModel.effectiveUntil = "2026-01-01";
    await expect(new RepositoryScan(db, fetch, now).run(selected, options)).rejects.toThrow("epss_model_not_bound_to_date");
    expect(await count("decision_records")).toEqual([]);
    options.epssModel = structuredClone(epssModel);
    options.epssDate = "2026-10-01";
    await expect(new RepositoryScan(db, fetch, now).run(selected, options)).rejects.toThrow("stale_or_future_epss_date");
    expect(await count("decision_records")).toEqual([]);
  });
});
