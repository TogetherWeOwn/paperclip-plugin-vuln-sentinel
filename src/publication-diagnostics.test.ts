import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE, FINDING_ORIGIN_KIND, WEEKLY_ORIGIN_KIND } from "./claims.js";
import { PublicationDiagnostics } from "./publication-diagnostics.js";
import { testDatabase } from "./test/database.js";

const now = () => new Date("2026-11-04T10:00:00.000Z");
const origin = (value: number) => value.toString(16).padStart(64, "0");
const container = (value: number, originKind = FINDING_ORIGIN_KIND as string) => ({ originId: origin(value), originKind });
const schema = `"${DATABASE_NAMESPACE}"`;
let postgres: Awaited<ReturnType<typeof testDatabase>>["postgres"];
let db: PluginDatabaseClient;
let sequence = 0;
beforeAll(async () => { ({ postgres, db } = await testDatabase()); });
afterAll(async () => { await postgres.close(); });

async function seed(options: { sourcePin?: unknown; routingPin?: string | null; containers?: unknown[]; history?: unknown; company?: string } = {}) {
  const company = options.company ?? `diagnostics-${++sequence}`;
  const repo = "owner/repo";
  await db.execute(`INSERT INTO ${schema}.source_polls (company_id, repo, revision, bundle, effect_barrier, effect_history)
    VALUES ($1, $2, 3, $3, $4, $5)`, [company, repo, JSON.stringify({ version: 1, cacheSnapshotId: null, attempt: null }),
    options.sourcePin === undefined ? null : JSON.stringify(options.sourcePin), JSON.stringify(options.history ?? [])]);
  await db.execute(`INSERT INTO ${schema}.delivery_routing (company_id, repo, revision, bundle, effect_token)
    VALUES ($1, $2, 4, $3, $4)`, [company, repo,
    JSON.stringify({ version: 1, members: [], containers: options.containers ?? [], attention: [] }), options.routingPin ?? null]);
  return { company, repo };
}

async function claim(company: string, id: number, state: string, kind = FINDING_ORIGIN_KIND as string) {
  await db.execute(`INSERT INTO ${schema}.card_claims
    (company_id, origin_id, origin_kind, state, claim_token, claimed_at, attempt_count, last_error, recovery_audit)
    VALUES ($1, $2, $3, $4, 'private-token', '2026-11-04T09:00:00Z', 1, 'private-error', $5)`,
  [company, origin(id), kind, state, JSON.stringify([{ private: "callback-proof-not-authority" }])]);
}

function fake(source: unknown[] = [], routing: unknown[] = [], claims: unknown[] = []) {
  const query = vi.fn(async (sql: string) => sql.includes("source_polls") ? source : sql.includes("delivery_routing") ? routing : claims);
  return { namespace: DATABASE_NAMESPACE, query: query as PluginDatabaseClient["query"] };
}
const sourceRow = { revision: 3, pinned: false, history_bytes: 2, history_is_array: true };
const routingRow = { revision: 4, pinned: false, bundle_bytes: 200, bundle: { version: 1, containers: [container(1)] } };
const claimRow = { origin_id: origin(1), origin_kind: FINDING_ORIGIN_KIND, state: "linked", attempt_count: 1, claimed_at: "2026-11-04T09:00:00Z" };

function held(result: Awaited<ReturnType<PublicationDiagnostics["read"]>>) {
  expect(result.status).toBe("attention");
  expect(result.publication).toEqual({ enabled: false, ownershipMap: "publication-ownership-map/v1", admissibility: "not_admissible", supportedMethods: [] });
  expect(result.attention).toEqual(expect.arrayContaining(["native_publication_disabled", "worker_state_not_authority", "diagnostics_not_atomic", "claims_not_repository_exhaustive", "enabled_pilot_not_run"]));
}

describe("read-only publication diagnostics", () => {
  it("missing rows cannot certify a clean publication or an enabled pilot", async () => {
    const result = await new PublicationDiagnostics(db, now).read("missing", "Owner/Repo");
    held(result);
    expect(result.repo).toBe("owner/repo");
    expect(result.source.status).toBe("missing");
    expect(result.source.pinned).toBeNull();
    expect(result.routing.status).toBe("missing");
    expect(result.claims.counts).toBeNull();
    expect(result.attention).toContain("source_diagnostics_missing");
  });

  it.each([[false, false], [true, false], [false, true], [true, true]])("observes pins %s/%s without releasing either or changing a claim", async (sourcePin, routingPin) => {
    const { company, repo } = await seed({ sourcePin: sourcePin ? { private: "worker-proof" } : undefined,
      routingPin: routingPin ? "private-route-token" : null, containers: [container(1)] });
    await claim(company, 1, "indeterminate");
    const execute = vi.fn(db.execute);
    const port = { ...db, execute };
    const diagnostic = new PublicationDiagnostics(port, now);
    const before = await db.query(`SELECT * FROM ${schema}.card_claims WHERE company_id = $1`, [company]);
    for (let replay = 0; replay < 2; replay++) {
      const result = await diagnostic.read(company, repo);
      held(result);
      expect(result.source.pinned).toBe(sourcePin);
      expect(result.routing.pinned).toBe(routingPin);
      expect(result.claims.counts?.indeterminate).toBe(1);
      expect(result.attention).toContain("mapped_claim_uncertainty");
      expect(JSON.stringify(result)).not.toMatch(/private-|worker-proof|callback-proof/u);
    }
    expect(execute).not.toHaveBeenCalled();
    expect(await db.query(`SELECT * FROM ${schema}.card_claims WHERE company_id = $1`, [company])).toEqual(before);
    expect((await db.query<{ pinned: boolean }>(`SELECT effect_barrier IS NOT NULL AS pinned FROM ${schema}.source_polls WHERE company_id = $1`, [company]))[0]?.pinned).toBe(sourcePin);
    expect((await db.query<{ pinned: boolean }>(`SELECT effect_token IS NOT NULL AS pinned FROM ${schema}.delivery_routing WHERE company_id = $1`, [company]))[0]?.pinned).toBe(routingPin);
  });

  it("counts each mapped claim state, but not orphan, other-company or other-repository claims", async () => {
    const states = ["reserved", "creating", "linked", "refreshing", "indeterminate", "quarantined"];
    const { company, repo } = await seed({ containers: [...states.map((_, i) => container(i + 1)), container(7, WEEKLY_ORIGIN_KIND)] });
    for (let i = 0; i < states.length; i++) await claim(company, i + 1, states[i]!);
    await claim(company, 8, "creating"); // No repository column: orphan coverage is deliberately not claimed.
    await claim("another-company", 1, "creating");
    await db.execute(`INSERT INTO ${schema}.delivery_routing (company_id, repo, bundle) VALUES ($1, 'owner/other', $2)`,
      [company, JSON.stringify({ version: 1, containers: [container(8)] })]);
    const result = await new PublicationDiagnostics(db, now).read(company, repo);
    held(result);
    expect(result.source).toMatchObject({ status: "observed", revision: 3, pinned: false, historyIsArray: true });
    expect(result.routing).toMatchObject({ status: "observed", revision: 4, containers: 7 });
    expect(result.claims).toEqual({ status: "observed", coverage: "routing_containers_only", counts: Object.fromEntries(states.map(state => [state, 1])),
      missing: 1, attempts: 6, oldestClaimedAt: "2026-11-04T09:00:00.000000Z" });
  });

  it("an empty mapped set is zero observed claims, never exhaustive repository or settlement evidence", async () => {
    const { company, repo } = await seed();
    await claim(company, 1, "indeterminate");
    const result = await new PublicationDiagnostics(db, now).read(company, repo);
    held(result);
    expect(result.claims).toMatchObject({ status: "observed", missing: 0, attempts: 0, oldestClaimedAt: null });
    expect(Object.values(result.claims.counts!).every(value => value === 0)).toBe(true);
  });

  it("linked claims and worker-written history cannot clear inadmissibility", async () => {
    const { company, repo } = await seed({ containers: [container(1)], history: [{ proof: "CLOSED-and-settled" }] });
    await claim(company, 1, "linked");
    const result = await new PublicationDiagnostics(db, now).read(company, repo);
    held(result);
    expect(result.claims.counts?.linked).toBe(1);
    expect(result.attention).toContain("mapped_claims_require_independent_verification");
    expect(JSON.stringify(result)).not.toContain("CLOSED-and-settled");
  });

  it.each([{}, "not-array", ["x".repeat(1048576)]])("surfaces malformed or full history without returning its contents", async history => {
    const { company, repo } = await seed({ history });
    const result = await new PublicationDiagnostics(db, now).read(company, repo);
    held(result);
    expect(result.source.pinned).toBe(false);
    expect(result.attention).toContain(Array.isArray(history) ? "source_history_capacity" : "source_history_invalid");
    expect(JSON.stringify(result).length).toBeLessThan(3000);
  });

  it("bounds corrupt routing data in SQL and does not query claims from partial evidence", async () => {
    const { company, repo } = await seed({ containers: [container(1)] });
    await db.execute(`UPDATE ${schema}.delivery_routing SET bundle = $2 WHERE company_id = $1`,
      [company, JSON.stringify({ version: 1, containers: [container(1)], padding: "x".repeat(1048576) })]);
    const result = await new PublicationDiagnostics(db, now).read(company, repo);
    held(result);
    expect(result.routing).toMatchObject({ status: "invalid", containers: null, pinned: false });
    expect(result.attention).toContain("routing_diagnostics_capacity");
    expect(result.claims.counts).toBeNull();
  });

  it.each([null, [], { version: 2, containers: [] }, { version: 1, containers: null },
    { version: 1, containers: [container(1), container(1)] }, { version: 1, containers: [{ originId: "bad", originKind: FINDING_ORIGIN_KIND }] },
    { version: 1, containers: [container(1, "unsupported")] }, { version: 1, containers: Array.from({ length: 2001 }, (_, i) => container(i)) },
  ])("holds invalid container metadata without a claim query", async bundle => {
    const port = fake([sourceRow], [{ ...routingRow, pinned: true, bundle }]);
    const result = await new PublicationDiagnostics(port, now).read("company", "owner/repo");
    held(result);
    expect(result.routing.status).toBe("invalid");
    expect(result.routing.pinned).toBe(true);
    expect(result.claims.counts).toBeNull();
    expect(vi.mocked(port.query)).toHaveBeenCalledTimes(2);
  });

  it.each([{ state: "future-state" }, { attempt_count: -1 }, { attempt_count: "1" }, { origin_id: origin(2) },
    { origin_kind: WEEKLY_ORIGIN_KIND }, { claimed_at: "bad" }, { claimed_at: "2026-11-05T09:00:00Z" },
  ])("does not return partial counts for malformed or mismatched claim %j", async patch => {
    const result = await new PublicationDiagnostics(fake([sourceRow], [routingRow], [{ ...claimRow, ...patch }]), now).read("company", "owner/repo");
    held(result);
    expect(result.claims.status).toBe("unavailable");
    expect(result.claims.counts).toBeNull();
    expect(result.attention).toContain("claim_diagnostics_unavailable");
  });

  it("holds duplicate claims and overlarge attempt totals", async () => {
    const duplicate = await new PublicationDiagnostics(fake([sourceRow], [routingRow], [claimRow, claimRow]), now).read("company", "owner/repo");
    expect(duplicate.claims.status).toBe("unavailable");
    const overflow = await new PublicationDiagnostics(fake([sourceRow], [{ ...routingRow, bundle: { version: 1, containers: [container(1), container(2)] } }],
      [{ ...claimRow, attempt_count: Number.MAX_SAFE_INTEGER }, { ...claimRow, origin_id: origin(2) }]), now).read("company", "owner/repo");
    expect(overflow.claims.counts).toBeNull();
  });

  it.each(["source_polls", "delivery_routing", "card_claims"])("sanitizes %s read failures without retry or writes", async table => {
    const port = fake([sourceRow], [routingRow], [claimRow]);
    const query = port.query.bind(port);
    port.query = vi.fn(async (sql: string, params?: unknown[]) => {
      if (sql.includes(table)) throw new Error("secret-token provider error");
      return query(sql, params);
    }) as PluginDatabaseClient["query"];
    const result = await new PublicationDiagnostics(port, now).read("company", "owner/repo");
    held(result);
    expect(JSON.stringify(result)).not.toMatch(/secret-token|provider error/u);
    const key = table === "source_polls" ? "source" : table === "delivery_routing" ? "routing" : "claims";
    expect(result[key].status).toBe("unavailable");
    expect(vi.mocked(port.query).mock.calls.filter(([sql]) => sql.includes(table))).toHaveLength(1);
  });

  it.each([{ revision: -1 }, { pinned: null }, { history_bytes: "2" }, { history_is_array: null }])("holds invalid source summary %j", async patch => {
    const result = await new PublicationDiagnostics(fake([{ ...sourceRow, ...patch }]), now).read("company", "owner/repo");
    expect(result.source.status).toBe("unavailable");
    expect(result.source.pinned).toBeNull();
  });

  it("binds every query to the requested company and only mapped origins", async () => {
    const port = fake([sourceRow], [routingRow]);
    await new PublicationDiagnostics(port, now).read("company", "Owner/Repo");
    expect(vi.mocked(port.query).mock.calls.map(([, params]) => params)).toEqual([
      ["company", "owner/repo"], ["company", "owner/repo"], ["company", [origin(1)]],
    ]);
  });

  it("rejects invalid namespace and scope before reading", async () => {
    const port = fake();
    expect(() => new PublicationDiagnostics({ ...port, namespace: "wrong" })).toThrow(/namespace/u);
    await expect(new PublicationDiagnostics(port, now).read("", "owner/repo")).rejects.toThrow();
    await expect(new PublicationDiagnostics(port, now).read("company", "owner/repo;SELECT")).rejects.toThrow();
    expect(port.query).not.toHaveBeenCalled();
  });
});
