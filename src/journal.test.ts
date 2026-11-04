import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { decide } from "./matcher.js";
import { DecisionJournal } from "./journal.js";
import { finding, closure } from "./test/fixtures.js";
import { testDatabase } from "./test/database.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let journal: DecisionJournal;

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records`);
  journal = new DecisionJournal(db);
});
afterAll(async () => { await postgres.close(); });

describe("durable input/provenance journal", () => {
  it("stores inputs and decisions before a delivery effect; stored input reproduces the entire decision", async () => {
    const input = finding({ functions: closure() });
    const { decisionId, decision } = await journal.record("company", input);
    const saved = await journal.read("company", decision.identity.originId, decisionId);
    expect(saved!.input_bundle).toEqual(input);
    expect(saved!.decision_bundle).toEqual(decision);
    expect(decide(saved!.input_bundle)).toEqual(saved!.decision_bundle);
    expect(saved!.decision_bundle).toMatchObject({ matchedRule: 5, applicability: "not_affected" });
    expect((await journal.latest("company", decision.identity.originId))!.decision_id).toBe(decisionId);
    expect(await journal.read("other-company", decision.identity.originId, decisionId)).toBeNull();
  });

  it("concurrent identical replays append one revision and one stable finding", async () => {
    const input = finding();
    const outcomes = await Promise.all(Array.from({ length: 10 }, () => journal.record("company", input)));
    expect(new Set(outcomes.map(item => item.decisionId)).size).toBe(1);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.decision_records`)).rows).toHaveLength(1);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.finding_records`)).rows).toHaveLength(1);
  });

  it("new EPSS/catalog/artifact evidence gets an immutable revision without changing finding identity", async () => {
    const input = finding();
    const first = await journal.record("company", input);
    input.provenance.observedAt = "2026-11-05T04:30:00Z";
    input.provenance.epss!.date = "2026-11-05";
    input.provenance.epss!.probability = 0.05;
    input.provenance.kev!.catalogVersion = "2026.11.05";
    const second = await journal.record("company", input);
    expect(second.decisionId).not.toBe(first.decisionId);
    expect(second.decision.identity).toEqual(first.decision.identity);
    expect((await journal.latest("company", first.decision.identity.originId))!.decision_id).toBe(second.decisionId);
    expect((await journal.read("company", first.decision.identity.originId, first.decisionId))!.decision_bundle.priority).toBe(2);
    expect(second.decision.priority).toBe(1);
    await journal.record("company", finding());
    expect((await journal.latest("company", first.decision.identity.originId))!.decision_id).toBe(second.decisionId);
  });

  it("same-time conflicting observations select a deterministic head independent of writer order", async () => {
    const a = finding();
    const b = finding();
    b.provenance.epss!.probability = 0.9;
    const outcomes = await Promise.all([journal.record("company", a), journal.record("company", b)]);
    const expected = outcomes.map(item => item.decisionId).sort().at(-1);
    const originId = outcomes[0]!.decision.identity.originId;
    expect((await journal.latest("company", originId))!.decision_id).toBe(expected);
    await journal.record("company", b);
    await journal.record("company", a);
    expect((await journal.latest("company", originId))!.decision_id).toBe(expected);
  });

  it("a crash after history insertion but before head update is repaired by replay", async () => {
    const faulty: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (sql.includes(".finding_records")) throw new Error("Head write interrupted");
      return db.execute(sql, params);
    } };
    const input = finding();
    await expect(new DecisionJournal(faulty).record("company", input)).rejects.toThrow("interrupted");
    expect(await journal.latest("company", decide(input).identity.originId)).toBeNull();
    const { decisionId, decision } = await journal.record("company", input);
    expect((await journal.latest("company", decision.identity.originId))!.decision_id).toBe(decisionId);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.decision_records`)).rows).toHaveLength(1);
  });

  it("unknown and drop decisions retain their full evidence too", async () => {
    const input = finding();
    input.provenance.observedAt = "invalid";
    const unknown = await journal.record("company", input);
    expect((await journal.read("company", unknown.decision.identity.originId, unknown.decisionId))!.decision_bundle.applicability).toBe("unknown");
    input.provenance.observedAt = "2026-11-04T04:30:00Z";
    input.versionEvidence.status = "outside";
    const dropped = await journal.record("company", input);
    expect((await journal.read("company", dropped.decision.identity.originId, dropped.decisionId))!.decision_bundle.applicability).toBe("dropped");
    expect((await journal.latest("company", dropped.decision.identity.originId))!.decision_id).toBe(dropped.decisionId);
  });
});
