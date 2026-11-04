import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { DependabotJournal } from "./dependabot-journal.js";
import { DependabotSource, validateDependabotSnapshot, type DependabotSnapshot } from "./dependabot.js";
import { testDatabase } from "./test/database.js";
import { dependabotAlert, dependabotTime } from "./test/dependabot.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let journal: DependabotJournal;
let snapshot: DependabotSnapshot;
beforeAll(async () => {
  ({ postgres, db } = await testDatabase());
  const read = await new DependabotSource(async () => new Response(JSON.stringify([dependabotAlert()])), "fixture-token", () => new Date(dependabotTime)).read("example");
  if (read.status !== "available") throw new Error("fixture unavailable");
  snapshot = read.snapshot;
}, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.dependabot_snapshots`);
  journal = new DependabotJournal(db);
});
afterAll(async () => { await postgres.close(); });

describe("immutable company-scoped Dependabot evidence", () => {
  it("retains raw pages and source revisions before exposing replayable observations", async () => {
    const id = await journal.record("company", snapshot);
    expect(await journal.read("company", id)).toEqual(snapshot);
    expect(validateDependabotSnapshot((await journal.read("company", id))!)[0]!.updatedAt).toBe("2026-11-03T00:00:00Z");
    expect(await journal.read("other-company", id)).toBeNull();
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.card_claims`)).rows).toHaveLength(0);
  });

  it("sequential/concurrent replay persists one bundle without a latest-source pointer", async () => {
    const ids = await Promise.all(Array.from({ length: 10 }, () => journal.record("company", snapshot)));
    expect(new Set(ids).size).toBe(1);
    expect(await journal.record("company", snapshot)).toBe(ids[0]);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.dependabot_snapshots`)).rows).toHaveLength(1);
  });

  it("holds failed/ambiguous writes and safely replays retained evidence", async () => {
    const failed = new DependabotJournal({ ...db, execute: async () => { throw new Error("write failed"); } });
    await expect(failed.record("company", snapshot)).rejects.toThrow("write failed");
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.dependabot_snapshots`)).rows).toHaveLength(0);
    const lost = new DependabotJournal({ ...db, execute: async (sql, params) => { await db.execute(sql, params); throw new Error("response lost"); } });
    await expect(lost.record("company", snapshot)).rejects.toThrow("response lost");
    const id = await journal.record("company", snapshot);
    expect(await journal.read("company", id)).toEqual(snapshot);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.dependabot_snapshots`)).rows).toHaveLength(1);
  });

  it("requires matching persistence/readback before returning an evidence reference", async () => {
    const absent = new DependabotJournal({ ...db, execute: async () => ({ rowCount: 0 }) });
    await expect(absent.record("company", snapshot)).rejects.toThrow("dependabot_persistence_mismatch");
    const lost = new DependabotJournal({ ...db, query: async () => { throw new Error("read failed"); } });
    await expect(lost.record("company", snapshot)).rejects.toThrow("read failed");
  });

  it("rejects raw/derived hash drift, malformed references and namespace mismatches", async () => {
    const id = await journal.record("company", snapshot);
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.dependabot_snapshots SET bundle = jsonb_set(bundle, '{snapshotSha256}', '"corrupt"') WHERE snapshot_id = $1`, [id]);
    await expect(journal.read("company", id)).rejects.toThrow("dependabot_snapshot_mismatch");
    await expect(journal.read("company", "latest")).rejects.toThrow("invalid_dependabot_snapshot_id");
    expect(() => new DependabotJournal({ ...db, namespace: "other" })).toThrow("namespace");
  });

  it("does not let caller mutation alter the snapshot while a write is suspended", async () => {
    const input = structuredClone(snapshot);
    const mutate = new DependabotJournal({ ...db, execute: async (sql, params) => {
      input.pages[0]!.alerts = [];
      return db.execute(sql, params);
    } });
    const id = await mutate.record("company", input);
    expect(await journal.read("company", id)).toEqual(snapshot);
  });
});
