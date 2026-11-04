import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DATABASE_NAMESPACE, ClaimStore, publicationHash, type RecoveryProof } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { FindingInput } from "./model.js";
import { ContainerPublication } from "./publication.js";
import { DeliveryRouting } from "./routing.js";
import { SourceEffects, type SourceEffectBarrier } from "./source-effects.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { SourcePublicationStore } from "./source-publication.js";
import { testDatabase } from "./test/database.js";
import { finding } from "./test/fixtures.js";
import { deferred, FakeIssues, summary } from "./test/issues.js";
import { sourceLockfiles } from "./test/sources.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let polls: SourcePollStore;
let routing: DeliveryRouting;
let issues: FakeIssues;
let publisher: ContainerPublication;
let store: SourcePublicationStore;
const company = "company-a";
const configured = { repo: "example/project", paths: ["package-lock.json"] };
async function ready() {
  const poll = await polls.begin(company, configured);
  const id = await new SourceJournal(db).recordLockfiles(company, sourceLockfiles());
  await polls.complete(poll, id);
  return polls.current(company, configured);
}
function input(selected: CurrentSource, patch: Partial<FindingInput> = {}): FindingInput {
  const value = finding({ repo: configured.repo, ...patch });
  value.provenance.artifactKind = "lockfile";
  value.provenance.observedAt = new Date().toISOString();
  value.provenance.artifactDigest = selected.stored.lockfiles.artifactDigest;
  value.versionEvidence.artifactDigest = value.provenance.artifactDigest;
  return value;
}
async function route(selected: CurrentSource, patch: Partial<FindingInput> = {}) {
  return (await routing.observeCurrent(selected, input(selected, patch))).container!.originId;
}
const publish = (selected: CurrentSource, origin: string, due = false) => publisher.publishCurrent(selected, origin, "triage", "fixture-execution", due);
const proof = (barrier: SourceEffectBarrier): RecoveryProof => ({
  previousClaimToken: barrier.token, terminalExecutionReceipt: "fixture-terminal",
  settledHostEffectsReceipt: "fixture-settled", auditRef: "fixture-only-not-authentication",
});
async function held() { return new SourceEffects(db).read(company, configured.repo); }
async function routingToken() {
  return (await postgres.query<{ effect_token: string | null }>(
    `SELECT effect_token FROM ${DATABASE_NAMESPACE}.delivery_routing WHERE company_id = $1 AND repo = $2`,
    [company, configured.repo],
  )).rows[0]!.effect_token;
}
function intercept(match: (sql: string) => boolean, effect: () => Promise<unknown>): PluginDatabaseClient {
  let raced = false;
  return { ...db, execute: async (sql, params) => {
    if (!raced && match(sql)) { raced = true; await effect(); }
    return db.execute(sql, params);
  } };
}

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots,
    ${DATABASE_NAMESPACE}.finding_records, ${DATABASE_NAMESPACE}.decision_records,
    ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.card_claims`);
  polls = new SourcePollStore(db);
  routing = new DeliveryRouting(db);
  issues = new FakeIssues();
  publisher = new ContainerPublication(db, issues);
  store = new SourcePublicationStore(db);
});
afterEach(() => { vi.useRealTimers(); });
afterAll(async () => { await postgres.close(); });

describe("source-pinned publication library (fake issue transport only)", () => {
  it("binds all weekly members, source, origin/revision and exact rendered payload; both pins survive success", async () => {
    const selected = await ready();
    const origin = await route(selected, { scope: "development" });
    await route(selected, { scope: "development", package: "another-package" });
    const snapshot = await routing.snapshot(company, configured.repo);
    expect((await publish(selected, origin)).result.status).toBe("deferred");
    expect(await held()).toBeNull();
    const { result, barrier } = await publish(selected, origin, true);
    expect(result.status).toBe("created");
    expect(barrier).toMatchObject({ originId: origin, publicationRevision: 2, routingSha256: sha256(canonicalJson(snapshot)) });
    const payload = issues.creates[0]!;
    expect(payload).not.toHaveProperty("assigneeAgentId");
    expect(payload).not.toHaveProperty("assigneeUserId");
    expect(payload.description).toContain("another-package");
    for (const member of snapshot.members) expect(payload.description).toContain(member.decisionId);
    expect(barrier!.contentSha256).toBe(publicationHash({ companyId: company, title: payload.title, originId: origin, projectId: "triage",
      description: payload.description!, priority: payload.priority!, advisoryModified: null, reopenUnresolved: true }));
    expect((await new ClaimStore(db).read({ companyId: company, originId: origin }))!.published_sha256).toBe(barrier!.contentSha256);
    expect(await held()).toEqual(barrier);
    expect(await routingToken()).toBe(barrier!.token);
    await expect(polls.begin(company, configured)).rejects.toThrow("source_effect_pending");
    await expect(route(selected, { package: "blocked-package" })).rejects.toThrow("source_publication_pending");
  });

  it("settles independently and replays without duplicate creates or updates", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const first = await publish(selected, origin);
    expect(first.result.status).toBe("created");
    expect(await store.settle(first.barrier!, async value => proof(value))).toBe(true);
    expect(await held()).toBeNull();
    expect(await routingToken()).toBeNull();
    const replay = await publish(selected, origin);
    expect(replay.result.status).toBe("reused");
    expect(issues.creates).toHaveLength(1);
    expect(issues.updates).toHaveLength(0);
    expect(await store.settle(replay.barrier!, async value => proof(value))).toBe(true);
    await polls.begin(company, configured);
  });

  it("concurrent workers reserve one dispatch, with no takeover after a result", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const outcomes = await Promise.allSettled(Array.from({ length: 8 }, () => publish(selected, origin)));
    expect(outcomes.filter(value => value.status === "fulfilled")).toHaveLength(1);
    expect(issues.creates).toHaveLength(1);
    await expect(publish(selected, origin)).rejects.toThrow("source_effect_reservation_rejected");
  });

  it("retains source holds on the legacy path, with no issue lookups", async () => {
    const selected = await ready();
    const origin = await route(selected);
    expect((await publisher.publish(company, configured.repo, origin, "triage")).status).toBe("attention");
    expect(issues.lookups).toEqual([]);
    expect(issues.creates).toEqual([]);
  });

  it.each(["member", "evidence", "missing_record", "mixed_selection"])("rejects %s mismatch before reservation or host lookup", async kind => {
    const selected = await ready();
    const origin = await route(selected, { scope: "development" });
    if (kind === "mixed_selection") {
      const newer = await ready();
      await route(newer, { scope: "development", package: "second-package" });
      await expect(publish(newer, origin, true)).rejects.toThrow("source_publication_member_mismatch");
    } else if (kind === "member") {
      await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.delivery_routing
        SET bundle = jsonb_set(bundle, '{members,0,sourceSelection,token}', '"00000000-0000-0000-0000-000000000000"')`);
      await expect(publish(selected, origin, true)).rejects.toThrow("source_publication_member_mismatch");
    } else {
      if (kind === "missing_record") await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.decision_records`);
      else await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.decision_records
        SET decision_bundle = jsonb_set(decision_bundle, '{provenance,sourceSelection,token}', '"00000000-0000-0000-0000-000000000000"')`);
      await expect(publish(selected, origin, true)).rejects.toThrow(kind === "evidence" ? "source_publication_evidence_mismatch" : "evidence missing");
    }
    expect(await held()).toBeNull();
    expect(issues.lookups).toEqual([]);
  });

  it("rejects a source superseded after rendering and before reservation", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const raced = intercept(sql => sql.includes("SET effect_barrier = $3"), async () => { await ready(); });
    await expect(new ContainerPublication(raced, issues).publishCurrent(selected, origin, "triage", "fixture-execution"))
      .rejects.toThrow("source_effect_reservation_rejected");
    expect(issues.lookups).toEqual([]);
    expect(await held()).toBeNull();
  });

  it("a same-source routing change before the exact snapshot pin holds without dispatch", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const raced = intercept(sql => sql.includes("SET effect_token = $3"), async () => { await route(selected, { package: "racing-package" }); });
    await expect(new ContainerPublication(raced, issues).publishCurrent(selected, origin, "triage", "fixture-execution"))
      .rejects.toThrow("source_publication_routing_mismatch");
    expect(issues.lookups).toEqual([]);
    const barrier = (await held())!;
    expect(barrier).not.toBeNull();
    expect(await routingToken()).toBeNull();
    // No routing pin was acquired; the source pin still requires trusted settlement.
    expect(await store.settle(barrier, async value => proof(value))).toBe(false);
    expect(await held()).toBeNull();
  });

  it("a routing pin winning just before a mutation CAS rejects that stale write", async () => {
    const selected = await ready();
    const origin = await route(selected);
    let barrier: SourceEffectBarrier | null = null;
    const raced = intercept(sql => sql.includes("SET bundle = $4"), async () => { barrier = (await publish(selected, origin)).barrier; });
    await expect(new DeliveryRouting(raced).observeCurrent(selected, input(selected, { package: "racing-package" })))
      .rejects.toThrow("source_publication_pending");
    expect((await routing.snapshot(company, configured.repo)).members).toHaveLength(1);
    expect(await routingToken()).toBe(barrier!.token);
  });

  it.each([false, true])("routing pin write response lost (committed=%s) grants ownership only by exact readback", async committed => {
    const selected = await ready();
    const origin = await route(selected);
    const lost: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (!sql.includes("SET effect_token = $3")) return db.execute(sql, params);
      if (committed) await db.execute(sql, params);
      throw new Error("fixture-lost-response");
    } };
    const operation = new ContainerPublication(lost, issues).publishCurrent(selected, origin, "triage", "fixture-execution");
    if (committed) expect((await operation).result.status).toBe("created");
    else await expect(operation).rejects.toThrow("source_publication_routing_mismatch");
    expect(issues.creates).toHaveLength(committed ? 1 : 0);
    expect(await held()).not.toBeNull();
  });

  it("lost routing ownership readback keeps both pins and grants no dispatch", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const lost: PluginDatabaseClient = { ...db, query: async (sql, params) => {
      if (sql.startsWith("SELECT bundle, effect_token")) throw new Error("fixture-lost-read");
      return db.query(sql, params);
    } };
    await expect(new ContainerPublication(lost, issues).publishCurrent(selected, origin, "triage", "fixture-execution"))
      .rejects.toThrow("fixture-lost-read");
    expect(issues.lookups).toEqual([]);
    expect(await routingToken()).toBe((await held())!.token);
  });

  it("unknown create outcomes remain pinned and cannot be retried even with an empty issue lookup", async () => {
    const selected = await ready();
    const origin = await route(selected);
    issues.onCreate = async () => { throw new Error("fixture-response-lost"); };
    const result = await publish(selected, origin);
    expect(result.result.status).toBe("delivery_unknown");
    await expect(store.settle(result.barrier!, async () => null)).rejects.toThrow("source_effect_settlement_unproven");
    await expect(publish(selected, origin)).rejects.toThrow("source_effect_reservation_rejected");
    expect(issues.creates).toHaveLength(1);
    expect(await held()).toEqual(result.barrier);
  });

  it("blocks rescan mutations, including unfenced rescan paths, while publication is pinned", async () => {
    const selected = await ready();
    const origin = await route(selected);
    await publish(selected, origin);
    await expect(routing.applyRescan(company, configured.repo, {} as never)).rejects.toThrow("source_publication_pending");
  });

  it("late pre-send validation cannot dispatch after the delivery deadline returned", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const pause = deferred<void>();
    const entered = deferred<void>();
    let reads = 0;
    const delayed: PluginDatabaseClient = { ...db, query: async (sql, params) => {
      if (sql.startsWith("SELECT bundle, effect_token") && ++reads === 3) {
        entered.resolve();
        await pause.promise;
      }
      return db.query(sql, params);
    } };
    vi.useFakeTimers();
    const operation = new ContainerPublication(delayed, issues, 100000).publishCurrent(selected, origin, "triage", "fixture-execution");
    await entered.promise;
    await vi.advanceTimersByTimeAsync(100001);
    const result = await operation;
    expect(result.result.status).toBe("delivery_unknown");
    pause.resolve();
    await vi.advanceTimersByTimeAsync(0);
    expect(issues.creates).toEqual([]);
    expect(await held()).toEqual(result.barrier);
  });

  it("a submitted create may commit after timeout; its source and routing pins are not released", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const response = deferred<ReturnType<typeof summary>>();
    const entered = deferred<void>();
    issues.onCreate = async () => { entered.resolve(); return response.promise; };
    vi.useFakeTimers();
    const operation = new ContainerPublication(db, issues, 100000).publishCurrent(selected, origin, "triage", "fixture-execution");
    await entered.promise;
    await vi.advanceTimersByTimeAsync(100001);
    const result = await operation;
    expect(result.result.status).toBe("delivery_unknown");
    response.resolve(summary("late-issue", { companyId: company, originId: origin }));
    await vi.advanceTimersByTimeAsync(0);
    expect(issues.creates).toHaveLength(1);
    expect(await held()).toEqual(result.barrier);
    expect(await routingToken()).toBe(result.barrier!.token);
    await expect(publish(selected, origin)).rejects.toThrow();
  });

  it("refreshes/reopens the original issue and retains pins on an uncertain refresh", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const first = await publish(selected, origin);
    await store.settle(first.barrier!, async value => proof(value));
    issues.rows.get(first.result.status === "created" ? first.result.issueId! : "missing")!.status = "done";
    const second = await publish(selected, origin);
    expect(second.result.status).toBe("reopened");
    expect(issues.creates).toHaveLength(1);
    expect(issues.updates).toHaveLength(1);
    await store.settle(second.barrier!, async value => proof(value));
    issues.rows.values().next().value!.status = "done";
    issues.onUpdate = async () => { throw new Error("fixture-uncertain-refresh"); };
    const third = await publish(selected, origin);
    expect(third.result.status).toBe("delivery_unknown");
    expect(await held()).toEqual(third.barrier);
    await expect(store.settle(third.barrier!, async () => null)).rejects.toThrow();
  });

  it("lost settlement responses can clear the old routing pin on replay, never a newer pin", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const first = await publish(selected, origin);
    const lost: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (sql.includes("SET effect_barrier = NULL")) throw new Error("fixture-lost-settlement");
      return result;
    } };
    await expect(new SourcePublicationStore(lost).settle(first.barrier!, async value => proof(value))).rejects.toThrow("fixture-lost-settlement");
    expect(await held()).toBeNull();
    expect(await routingToken()).toBe(first.barrier!.token);
    // The retained audit is the only authority to repair the partial cleanup.
    expect(await store.settle(first.barrier!, async () => null)).toBe(true);
    const second = await publish(selected, origin);
    expect(await store.settle(first.barrier!, async () => null)).toBe(false);
    expect(await held()).toEqual(second.barrier);
    expect(await routingToken()).toBe(second.barrier!.token);
  });

  it("revalidates the routing pin before create, not just before issue lookup", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const list = issues.list.bind(issues);
    issues.list = async query => {
      const result = await list(query);
      await postgres.exec(`UPDATE ${DATABASE_NAMESPACE}.delivery_routing SET effect_token = 'fixture-corruption'`);
      return result;
    };
    expect((await publish(selected, origin)).result.status).toBe("delivery_unknown");
    expect(issues.lookups).toHaveLength(1);
    expect(issues.creates).toEqual([]);
    expect(await held()).not.toBeNull();
  });

  it("rechecks source freshness synchronously after delayed asynchronous pin validation", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const result = await publish(selected, origin);
    let time = Date.now();
    const delayed: PluginDatabaseClient = { ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const rows = await db.query<T>(sql, params);
      if (sql.startsWith("SELECT bundle, effect_token")) time += 2 * 86400000;
      return rows;
    } };
    await expect(new SourcePublicationStore(delayed, () => new Date(time)).assertDispatch(selected, result.barrier!))
      .rejects.toThrow("source_publication_expired");
    expect(await held()).toEqual(result.barrier);
  });

  it("a deadline closes dispatch even while uncertainty recording delays the return", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const guard = deferred<void>();
    const guardEntered = deferred<void>();
    const audit = deferred<void>();
    const auditEntered = deferred<void>();
    let reads = 0;
    const delayed: PluginDatabaseClient = { ...db,
      query: async (sql, params) => {
        if (sql.startsWith("SELECT bundle, effect_token") && ++reads === 3) {
          guardEntered.resolve();
          await guard.promise;
        }
        return db.query(sql, params);
      },
      execute: async (sql, params) => {
        if (sql.includes("card_claims") && params?.includes("indeterminate")) {
          auditEntered.resolve();
          await audit.promise;
        }
        return db.execute(sql, params);
      },
    };
    vi.useFakeTimers();
    const operation = new ContainerPublication(delayed, issues, 100000).publishCurrent(selected, origin, "triage", "fixture-execution");
    await guardEntered.promise;
    await vi.advanceTimersByTimeAsync(100001);
    await auditEntered.promise;
    guard.resolve();
    await vi.advanceTimersByTimeAsync(0);
    expect(issues.creates).toEqual([]);
    audit.resolve();
    expect((await operation).result.status).toBe("delivery_unknown");
    expect(await routingToken()).toBe((await held())!.token);
  });

  it("settlement cannot clear a forged routing/content binding or token", async () => {
    const selected = await ready();
    const origin = await route(selected);
    const { barrier } = await publish(selected, origin);
    const verify = vi.fn(async (value: SourceEffectBarrier) => proof(value));
    expect(await store.settle({ ...barrier!, contentSha256: "d".repeat(64) }, verify)).toBe(false);
    expect(await store.settle({ ...barrier!, routingSha256: "e".repeat(64) }, verify)).toBe(false);
    expect(verify).not.toHaveBeenCalled();
    expect(await held()).toEqual(barrier);
    expect(await routingToken()).toBe(barrier!.token);
  });
});
