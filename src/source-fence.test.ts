import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson } from "./identity.js";
import { DecisionJournal } from "./journal.js";
import type { FindingInput } from "./model.js";
import { DeliveryRouting } from "./routing.js";
import { ContainerPublication } from "./publication.js";
import { FakeIssues } from "./test/issues.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { testDatabase } from "./test/database.js";
import { finding } from "./test/fixtures.js";
import { sourceLockfiles } from "./test/sources.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let polls: SourcePollStore;
let sources: SourceJournal;
let journal: DecisionJournal;
let routing: DeliveryRouting;
const configured = { repo: "example/project", paths: ["package-lock.json"] };
async function ready(sourceSha = "a".repeat(40)) {
  const poll = await polls.begin("company", configured);
  const id = await sources.recordLockfiles("company", { ...sourceLockfiles(), sourceSha });
  await polls.complete(poll, id);
  return polls.current("company", configured);
}
function input(selected: CurrentSource): FindingInput {
  const value = finding({ repo: configured.repo });
  value.provenance.artifactKind = "lockfile";
  value.provenance.artifactDigest = selected.stored.lockfiles.artifactDigest;
  value.versionEvidence.artifactDigest = value.provenance.artifactDigest;
  return value;
}
async function rows(table: string) {
  return (await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.${table}`)).rows;
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
    ${DATABASE_NAMESPACE}.finding_records, ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.delivery_routing`);
  polls = new SourcePollStore(db);
  sources = new SourceJournal(db);
  journal = new DecisionJournal(db);
  routing = new DeliveryRouting(db);
});
afterAll(async () => { await postgres.close(); });

describe("source-fenced decision and routing projections", () => {
  it("persists a reproducible source selection before routing, without changing caller inputs or producing host effects", async () => {
    const selected = await ready();
    const value = input(selected);
    const result = await routing.observeCurrent(selected, value);
    expect(result.status).toBe("recorded");
    const member = (await routing.snapshot("company", configured.repo)).members[0]!;
    expect(member.sourceSelection).toEqual({ pollRevision: selected.pollRevision, token: selected.token, snapshotId: selected.snapshotId });
    const stored = (await journal.latest("company", member.currentOriginId))!;
    expect(stored.input_bundle.provenance.sourceSelection).toEqual(member.sourceSelection);
    expect(stored.decision_bundle.provenance).toEqual(stored.input_bundle.provenance);
    expect(stored.decision_bundle.applicability).toBe("unknown");
    expect(value.provenance.sourceSelection).toBeUndefined();
    expect(selected.stored.inventory.coverage.runtimeCompleteness).toBe("not_proven");
    expect(await rows("card_claims")).toEqual([]);
  });

  it("same-poll observations retain deterministic head ordering and concurrent replay creates one membership", async () => {
    const selected = await ready();
    const a = input(selected);
    const b = input(selected);
    b.provenance.epss!.probability = 0.9;
    const records = await Promise.all([journal.recordCurrent(selected, a), journal.recordCurrent(selected, b)]);
    const expected = records.map(record => record.decisionId).sort().at(-1);
    await Promise.all(Array.from({ length: 8 }, () => routing.observeCurrent(selected, a)));
    const snapshot = await routing.snapshot("company", configured.repo);
    expect(snapshot.members).toHaveLength(1);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.members[0]!.decisionId).toBe(expected);
    expect((await journal.latest("company", snapshot.members[0]!.findingId))!.decision_id).toBe(expected);
    expect(await rows("decision_records")).toHaveLength(2);
  });

  it("a later poll wins over a future observation timestamp and lexically higher old commit", async () => {
    const old = await ready("f".repeat(40));
    const a = input(old);
    a.provenance.observedAt = "2099-01-01T00:00:00Z";
    await routing.observeCurrent(old, a);
    const next = await ready("0".repeat(40));
    const b = input(next);
    b.provenance.epss!.probability = 0.9;
    await routing.observeCurrent(next, b);
    const snapshot = await routing.snapshot("company", configured.repo);
    const member = snapshot.members[0]!;
    expect(member.sourceSelection!.token).toBe(next.token);
    expect(member.observedAt).toBe(b.provenance.observedAt);
    expect(member.priority).toBe(1);
    expect((await journal.latest("company", member.currentOriginId))!.decision_id).toBe(member.decisionId);
    expect(snapshot.containers).toHaveLength(1);
    await expect(routing.observeCurrent(old, a)).rejects.toThrow("source_poll_superseded");
  });

  it("a new poll of identical bytes still advances the current decision without duplicate routing", async () => {
    const old = await ready();
    await routing.observeCurrent(old, input(old));
    const before = await routing.snapshot("company", configured.repo);
    const next = await ready();
    expect(next.snapshotId).toBe(old.snapshotId);
    await routing.observeCurrent(next, input(next));
    const after = await routing.snapshot("company", configured.repo);
    expect(after.members).toHaveLength(1);
    expect(after.members[0]!.findingId).toBe(before.members[0]!.findingId);
    expect(after.members[0]!.deliveryOrigin).toBe(before.members[0]!.deliveryOrigin);
    expect(after.members[0]!.sourceSelection!.pollRevision).toBe(next.pollRevision);
  });

  it.each(["pending", "failed", "ready", "same-bytes"])("supersession just before the head write (%s) retains only immutable history", async state => {
    const selected = await ready();
    const database = intercept(sql => sql.includes(".finding_records"), async () => {
      if (state === "ready" || state === "same-bytes") await ready(state === "ready" ? "b".repeat(40) : "a".repeat(40));
      else {
        const poll = await polls.begin("company", configured);
        if (state === "failed") await polls.fail(poll, "fixture_failure");
      }
    });
    await expect(new DeliveryRouting(database).observeCurrent(selected, input(selected))).rejects.toThrow("source_fence_rejected");
    expect(await rows("decision_records")).toHaveLength(1);
    expect(await rows("finding_records")).toEqual([]);
    expect((await routing.snapshot("company", configured.repo)).members).toEqual([]);
  });

  it("same-token failure after source validation fences the head atomically", async () => {
    const selected = await ready();
    const database = intercept(sql => sql.includes(".finding_records"), () => polls.fail(selected, "fixture_failure"));
    await expect(new DecisionJournal(database).recordCurrent(selected, input(selected))).rejects.toThrow("source_fence_rejected");
    expect(await rows("finding_records")).toEqual([]);
    expect(await rows("decision_records")).toHaveLength(1);
  });

  it.each(["pending", "failed", "ready"])("a poll racing after the head but before routing (%s) cannot apply an old membership", async state => {
    const selected = await ready();
    const database = intercept(sql => sql.startsWith("UPDATE") && sql.includes(".delivery_routing"), async () => {
      if (state === "ready") await ready("b".repeat(40));
      else {
        const poll = await polls.begin("company", configured);
        if (state === "failed") await polls.fail(poll, "fixture_failure");
      }
    });
    await expect(new DeliveryRouting(database).observeCurrent(selected, input(selected))).rejects.toThrow(/current_source_|source_poll_superseded/u);
    expect(await rows("finding_records")).toHaveLength(1);
    expect((await routing.snapshot("company", configured.repo)).members).toEqual([]);
    const next = await ready("0".repeat(40));
    await routing.observeCurrent(next, input(next));
    expect((await routing.snapshot("company", configured.repo)).members[0]!.sourceSelection!.token).toBe(next.token);
  });

  it("stale routing cannot change a newer member even if the old decision was already journaled", async () => {
    const selected = await ready();
    const old = input(selected);
    old.provenance.observedAt = "2099-01-01T00:00:00Z";
    const database = intercept(sql => sql.startsWith("UPDATE") && sql.includes(".delivery_routing"), async () => {
      const next = await ready("b".repeat(40));
      await routing.observeCurrent(next, input(next));
    });
    await expect(new DeliveryRouting(database).observeCurrent(selected, old)).rejects.toThrow("source_poll_superseded");
    const snapshot = await routing.snapshot("company", configured.repo);
    expect(snapshot.members).toHaveLength(1);
    expect(snapshot.members[0]!.observedAt).not.toBe(old.provenance.observedAt);
    expect(snapshot.containers[0]!.revision).toBe(1);
  });

  it("CAS retries retain independent same-source membership rather than losing the competing write", async () => {
    const selected = await ready();
    const other = input(selected);
    other.advisoryId = "GHSA-other";
    other.aliases = [{ ...other.aliases[0]!, id: "GHSA-other", aliases: [] }];
    other.versionEvidence.advisoryId = other.advisoryId;
    const database = intercept(sql => sql.startsWith("UPDATE") && sql.includes(".delivery_routing"), () => routing.observeCurrent(selected, other));
    await new DeliveryRouting(database).observeCurrent(selected, input(selected));
    const snapshot = await routing.snapshot("company", configured.repo);
    expect(snapshot.members).toHaveLength(2);
    expect(new Set(snapshot.members.map(member => member.findingId)).size).toBe(2);
    expect(snapshot.members.every(member => member.sourceSelection!.token === selected.token)).toBe(true);
  });

  it.each(["finding_records", "delivery_routing"])("replays a committed %s write after a lost response without duplicate evidence or membership", async table => {
    const selected = await ready();
    let failed = false;
    const database: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (!failed && sql.includes(`.${table}`) && sql.startsWith(table === "delivery_routing" ? "UPDATE" : "INSERT")) {
        failed = true;
        throw new Error("lost response");
      }
      return result;
    } };
    await expect(new DeliveryRouting(database).observeCurrent(selected, input(selected))).rejects.toThrow("lost response");
    await routing.observeCurrent(selected, input(selected));
    const before = await routing.snapshot("company", configured.repo);
    await routing.observeCurrent(selected, input(selected));
    expect(await routing.snapshot("company", configured.repo)).toEqual(before);
    expect(before.members).toHaveLength(1);
    expect(await rows("decision_records")).toHaveLength(1);
  });

  it.each(["repo", "artifact", "kind", "company", "revision", "bytes", "config"])("rejects changed %s binding before recording a decision", async field => {
    const selected = await ready();
    const value = input(selected);
    if (field === "repo") value.repo = "other/project";
    if (field === "artifact") value.provenance.artifactDigest = "sha256:wrong";
    if (field === "kind") value.provenance.artifactKind = "worker_bundle";
    if (field === "company") selected.companyId = "other";
    if (field === "revision") selected.pollRevision++;
    if (field === "bytes") selected.stored.lockfiles.files[0]!.content += " ";
    if (field === "config") selected.source.paths = ["Cargo.lock"];
    await expect(routing.observeCurrent(selected, value)).rejects.toThrow();
    expect(await rows("decision_records")).toEqual([]);
  });

  it("unfenced APIs cannot impersonate source provenance or replace a fenced finding head", async () => {
    const selected = await ready();
    await routing.observeCurrent(selected, input(selected));
    const before = await routing.snapshot("company", configured.repo);
    const member = before.members[0]!;
    const latest = (await journal.latest("company", member.currentOriginId))!;
    await expect(journal.record("company", latest.input_bundle)).rejects.toThrow("source_selection_requires_fenced_write");
    const unbound = input(selected);
    unbound.provenance.observedAt = "2099-01-01T00:00:00Z";
    await journal.record("company", unbound);
    expect((await journal.latest("company", member.currentOriginId))!.decision_id).toBe(latest.decision_id);
    await expect(routing.observe("company", unbound)).rejects.toThrow("source_selection_requires_fenced_write");
    unbound.aliases = [{ ...unbound.aliases[0]!, id: "GHSA-other", aliases: [] }];
    unbound.advisoryId = "GHSA-other";
    await expect(routing.observe("company", unbound)).rejects.toThrow("source_selection_requires_fenced_write");
    expect(await routing.snapshot("company", configured.repo)).toEqual(before);
  });

  it("a source superseded during a routing no-op read is not returned as current replay success", async () => {
    const selected = await ready();
    await routing.observeCurrent(selected, input(selected));
    let raced = false;
    const database: PluginDatabaseClient = { ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const result = await db.query<T>(sql, params);
      if (!raced && sql.includes(".delivery_routing")) { raced = true; await polls.begin("company", configured); }
      return result;
    } };
    await expect(new DeliveryRouting(database).observeCurrent(selected, input(selected))).rejects.toThrow("current_source_pending");
  });

  it("the database statement clock also rejects an expired selection even if the application clock is old", async () => {
    const oldNow = () => new Date(Date.now() - 2 * 86400000);
    const oldPolls = new SourcePollStore(db, oldNow);
    const poll = await oldPolls.begin("company", configured);
    const id = await sources.recordLockfiles("company", sourceLockfiles());
    await oldPolls.complete(poll, id);
    const selected = await oldPolls.current("company", configured);
    await expect(new DecisionJournal(db, oldNow).recordCurrent(selected, input(selected))).rejects.toThrow("source_fence_rejected");
    expect(await rows("decision_records")).toHaveLength(1);
    expect(await rows("finding_records")).toEqual([]);
  });

  it.each([false, true])("holds source-selected publication without any issue effect, including a missing member source reference (%s)", async omitMemberRef => {
    const selected = await ready();
    const result = await routing.observeCurrent(selected, input(selected));
    if (omitMemberRef) {
      const snapshot = await routing.snapshot("company", configured.repo);
      delete snapshot.members[0]!.sourceSelection;
      await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.delivery_routing SET bundle = $1`, [canonicalJson(snapshot)]);
    }
    const issues = new FakeIssues();
    const publication = new ContainerPublication(db, issues);
    await expect(publication.publish("company", configured.repo, result.container!.originId, "triage", true))
      .resolves.toMatchObject({ status: "attention", reason: expect.stringContaining("source-fenced host-effect protocol") });
    expect(issues.lookups).toEqual([]);
    expect(issues.creates).toEqual([]);
    expect(issues.updates).toEqual([]);
    expect(await rows("card_claims")).toEqual([]);
  });

  it("embeds source locking and exact company/repo/revision/ready-state comparison in both mutating statements", async () => {
    const selected = await ready();
    const statements: string[] = [];
    const database: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (sql.includes("FOR UPDATE")) statements.push(sql);
      return db.execute(sql, params);
    } };
    await new DeliveryRouting(database).observeCurrent(selected, input(selected));
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain(".finding_records");
    expect(statements[1]).toContain(".delivery_routing");
    for (const sql of statements) {
      expect(sql).toContain(".source_polls");
      expect(sql).toContain("AND bundle =");
      expect(sql).toContain("statement_timestamp()");
    }
    const stored = (await journal.latest("company", (await routing.snapshot("company", configured.repo)).members[0]!.findingId))!;
    expect(canonicalJson(stored.input_bundle.provenance.sourceSelection)).toContain(selected.token);
  });
});
