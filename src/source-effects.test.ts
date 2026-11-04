import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DATABASE_NAMESPACE, type RecoveryProof } from "./claims.js";
import { canonicalJson } from "./identity.js";
import { SourceEffects, type SourceEffectBarrier, type SourceEffectIntent } from "./source-effects.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore } from "./source-polls.js";
import { testDatabase } from "./test/database.js";
import { sourceLockfiles } from "./test/sources.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let polls: SourcePollStore;
let effects: SourceEffects;
const configured = { repo: "example/project", paths: ["package-lock.json"] };
const intent: SourceEffectIntent = {
  executionId: "fixture-execution", originId: "b".repeat(64), publicationRevision: 1, contentSha256: "c".repeat(64),
};
async function ready(company = "company", repo = configured.repo) {
  const source = { ...configured, repo };
  const poll = await polls.begin(company, source);
  const id = await new SourceJournal(db).recordLockfiles(company, { ...sourceLockfiles(), repo });
  await polls.complete(poll, id);
  return polls.current(company, source);
}
const proof = (barrier: SourceEffectBarrier): RecoveryProof => ({
  previousClaimToken: barrier.token, terminalExecutionReceipt: "fixture-terminal",
  settledHostEffectsReceipt: "fixture-settled", auditRef: "fixture-only-not-authentication",
});
async function history() {
  return (await postgres.query<{ effect_history: unknown[] }>(
    `SELECT effect_history FROM ${DATABASE_NAMESPACE}.source_polls WHERE company_id = 'company' AND repo = 'example/project'`,
  )).rows[0]!.effect_history;
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
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots`);
  polls = new SourcePollStore(db);
  effects = new SourceEffects(db);
});
afterAll(async () => { await postgres.close(); });

describe("durable source effect barrier primitive (no native publication)", () => {
  it("reserves the exact ready selection and blocks every poll mutation, including same-token failure", async () => {
    const selected = await ready();
    const barrier = await effects.reserve(selected, intent);
    expect(barrier.selection).toEqual({ pollRevision: selected.pollRevision, token: selected.token, snapshotId: selected.snapshotId });
    expect(await effects.read("company", configured.repo)).toEqual(barrier);
    await expect(polls.begin("company", configured)).rejects.toThrow("source_effect_pending");
    await expect(polls.fail(selected, "fixture_failure")).rejects.toThrow("source_effect_pending");
    await polls.assertCurrent(selected);
    expect(await history()).toEqual([]);
  });

  it("concurrent reservations have one owner, without lease expiry or stealing", async () => {
    const selected = await ready();
    const attempts = await Promise.allSettled(Array.from({ length: 8 }, () => effects.reserve(selected, intent)));
    expect(attempts.filter(item => item.status === "fulfilled")).toHaveLength(1);
    expect(attempts.filter(item => item.status === "rejected")).toHaveLength(7);
    const future = new SourcePollStore(db, () => new Date(Date.now() + 365 * 86400000));
    await expect(future.begin("company", configured)).rejects.toThrow("source_effect_pending");
  });

  it.each(["pending", "ready", "failed"])("a newer %s poll winning just before reservation rejects the old selection", async state => {
    const selected = await ready();
    const raced = intercept(sql => sql.includes("SET effect_barrier = $3"), async () => {
      if (state === "ready") await ready();
      else {
        const poll = await polls.begin("company", configured);
        if (state === "failed") await polls.fail(poll, "fixture_failure");
      }
    });
    await expect(new SourceEffects(raced).reserve(selected, intent)).rejects.toThrow("source_effect_reservation_rejected");
    expect(await effects.read("company", configured.repo)).toBeNull();
  });

  it("a reservation winning between a poll's read and CAS prevents that stale poll write", async () => {
    const selected = await ready();
    let barrier: SourceEffectBarrier | undefined;
    const raced = intercept(sql => sql.startsWith("UPDATE") && sql.includes("SET bundle = $4"), async () => {
      barrier = await effects.reserve(selected, intent);
    });
    await expect(new SourcePollStore(raced).begin("company", configured)).rejects.toThrow("source_effect_pending");
    expect(await effects.read("company", configured.repo)).toEqual(barrier);
    await polls.assertCurrent(selected);
  });

  it.each([-2 * 86400000, 86400000])("database time rejects a stale/future reservation despite caller clock offset %s", async offset => {
    const clock = () => new Date(Date.now() + offset);
    polls = new SourcePollStore(db, clock);
    const selected = await ready();
    await polls.assertCurrent(selected);
    await expect(new SourceEffects(db, clock).reserve(selected, intent)).rejects.toThrow("source_effect_reservation_rejected");
    expect(await effects.read("company", configured.repo)).toBeNull();
  });

  it("an uncommitted failed reservation grants no ownership and does not pin the source", async () => {
    const selected = await ready();
    const failed: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (sql.includes("SET effect_barrier = $3")) throw new Error("not committed");
      return db.execute(sql, params);
    } };
    await expect(new SourceEffects(failed).reserve(selected, intent)).rejects.toThrow("source_effect_reservation_rejected");
    expect(await effects.read("company", configured.repo)).toBeNull();
    await polls.begin("company", configured);
  });

  it("recovers an exact committed reservation after its write response is lost", async () => {
    const selected = await ready();
    const lost: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (sql.includes("SET effect_barrier = $3")) throw new Error("lost response");
      return result;
    } };
    const barrier = await new SourceEffects(lost).reserve(selected, intent);
    expect(await effects.read("company", configured.repo)).toEqual(barrier);
  });

  it("an unconfirmed reservation remains durable and blocks replay after restart", async () => {
    const selected = await ready();
    const lost: PluginDatabaseClient = { ...db, query: async (sql, params) => {
      if (sql.startsWith("SELECT effect_barrier")) throw new Error("lost read");
      return db.query(sql, params);
    } };
    await expect(new SourceEffects(lost).reserve(selected, intent)).rejects.toThrow("lost read");
    expect(await effects.read("company", configured.repo)).not.toBeNull();
    await expect(effects.reserve(selected, intent)).rejects.toThrow("source_effect_reservation_rejected");
    await expect(polls.begin("company", configured)).rejects.toThrow("source_effect_pending");
  });

  it("keeps other companies and repositories independent", async () => {
    const selected = await ready();
    await effects.reserve(selected, intent);
    for (const other of [await ready("other-company"), await ready("company", "example/other")]) {
      await effects.reserve(other, intent);
    }
    expect(await effects.read("other-company", configured.repo)).not.toBeNull();
    expect(await effects.read("company", "example/other")).not.toBeNull();
  });

  it.each(["null", "token", "terminal", "host", "audit", "throw"])("holds the barrier on %s settlement proof", async kind => {
    const selected = await ready();
    const barrier = await effects.reserve(selected, intent);
    await expect(effects.release(barrier, async () => {
      if (kind === "throw") throw new Error("fixture-verifier-unavailable");
      if (kind === "null") return null;
      const value = proof(barrier);
      if (kind === "token") value.previousClaimToken = "wrong";
      if (kind === "terminal") value.terminalExecutionReceipt = "";
      if (kind === "host") value.settledHostEffectsReceipt = " ";
      if (kind === "audit") value.auditRef = "";
      return value;
    })).rejects.toThrow();
    expect(await effects.read("company", configured.repo)).toEqual(barrier);
    expect(await history()).toEqual([]);
    await expect(polls.begin("company", configured)).rejects.toThrow("source_effect_pending");
  });

  it("atomically retains a bound settlement audit and releases only that barrier", async () => {
    const selected = await ready();
    const barrier = await effects.reserve(selected, intent);
    expect(await effects.release(barrier, async value => proof(value))).toBe(true);
    expect(await effects.read("company", configured.repo)).toBeNull();
    expect(await history()).toEqual([{ barrier, proof: proof(barrier), releasedAt: expect.any(String) }]);
    const next = await ready();
    expect(next.pollRevision).toBeGreaterThan(selected.pollRevision);
    const nextBarrier = await effects.reserve(next, intent);
    const verify = vi.fn(async () => proof(barrier));
    expect(await effects.release(barrier, verify)).toBe(false);
    expect(verify).not.toHaveBeenCalled();
    expect(await effects.read("company", configured.repo)).toEqual(nextBarrier);
  });

  it("rejects a forged intent or selection at release without calling the verifier", async () => {
    const barrier = await effects.reserve(await ready(), intent);
    const verify = vi.fn(async () => proof(barrier));
    for (const changed of [{ ...barrier, publicationRevision: 2 }, { ...barrier, executionId: "other" },
      { ...barrier, selection: { ...barrier.selection, pollRevision: barrier.selection.pollRevision + 1 } }]) {
      expect(await effects.release(changed, verify)).toBe(false);
    }
    expect(verify).not.toHaveBeenCalled();
    expect(await effects.read("company", configured.repo)).toEqual(barrier);
  });

  it("lost settlement responses do not release a subsequent owner's barrier", async () => {
    const selected = await ready();
    const barrier = await effects.reserve(selected, intent);
    const lost: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (sql.includes("SET effect_barrier = NULL")) throw new Error("lost response");
      return result;
    } };
    await expect(new SourceEffects(lost).release(barrier, async value => proof(value))).rejects.toThrow("lost response");
    expect(await history()).toHaveLength(1);
    const next = await effects.reserve(await ready(), intent);
    expect(await effects.release(barrier, async () => proof(barrier))).toBe(false);
    expect(await effects.read("company", configured.repo)).toEqual(next);
  });

  it("two concurrent settlement attempts append exactly one audit", async () => {
    const barrier = await effects.reserve(await ready(), intent);
    const results = await Promise.all(Array.from({ length: 8 }, () => effects.release(barrier, async value => proof(value))));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await history()).toHaveLength(1);
  });

  it.each(["capacity", "malformed"])("holds on %s audit history rather than dropping receipts", async kind => {
    const barrier = await effects.reserve(await ready(), intent);
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_polls SET effect_history = $1`,
      [kind === "capacity" ? JSON.stringify(["x".repeat(1048576)]) : '{}']);
    expect(await effects.release(barrier, async value => proof(value))).toBe(false);
    expect(await effects.read("company", configured.repo)).toEqual(barrier);
  });

  it.each([0, -1, 1.5, 2147483647])("rejects invalid publication revision %s without reserving", async revision => {
    await expect(effects.reserve(await ready(), { ...intent, publicationRevision: revision })).rejects.toThrow("invalid_source_effect_barrier");
    expect(await effects.read("company", configured.repo)).toBeNull();
  });

  it("fails closed to malformed/badly bound durable barriers", async () => {
    const barrier = await effects.reserve(await ready(), intent);
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_polls SET effect_barrier = $1`,
      [canonicalJson({ ...barrier, repo: "example/other" })]);
    await expect(effects.read("company", configured.repo)).rejects.toThrow("source_effect_binding_mismatch");
    await expect(polls.begin("company", configured)).rejects.toThrow("source_effect_pending");
  });
});
