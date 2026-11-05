import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { decide } from "./matcher.js";
import { parseOsvRecord } from "./osv.js";
import { DeliveryRouting } from "./routing.js";
import { SourceJournal } from "./source-journal.js";
import { ThreatJournal } from "./threat-journal.js";
import type { ThreatSnapshot } from "./threat-feeds.js";
import { testDatabase } from "./test/database.js";
import { finding } from "./test/fixtures.js";
import { sourceLockfiles, sourceOsv } from "./test/sources.js";
import { feedTime, threatSnapshot } from "./test/threats.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let journal: ThreatJournal;
const now = () => new Date(feedTime);
beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.threat_snapshots, ${DATABASE_NAMESPACE}.source_snapshots, ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.decision_records`);
  journal = new ThreatJournal(db);
});
afterAll(async () => { await postgres.close(); });

const input = () => {
  const value = finding(); value.provenance.observedAt = feedTime; return value;
};

function rehashFeeds(snapshot: ThreatSnapshot): void {
  for (const feed of [snapshot.kev, snapshot.epss]) {
    const { snapshotSha256: _, ...content } = feed;
    feed.snapshotSha256 = sha256(canonicalJson(content));
  }
}

const inconsistentFeeds: Array<{ name: string; change: (snapshot: ThreatSnapshot) => void; reason: string }> = [
  { name: "omitted KEV alias", change: value => { value.kev.cves = []; }, reason: "kev_snapshot_mismatch" },
  { name: "KEV catalog revision", change: value => { value.kev.catalogVersion = "different"; }, reason: "kev_snapshot_mismatch" },
  { name: "KEV release time", change: value => { value.kev.releasedAt = "2026-11-03T11:00:00Z"; }, reason: "kev_snapshot_mismatch" },
  { name: "lowered EPSS score", change: value => { value.epss.scores[0]!.probability = 0; }, reason: "epss_snapshot_mismatch" },
  { name: "omitted EPSS score", change: value => { value.epss.scores = []; }, reason: "epss_snapshot_mismatch" },
  { name: "EPSS score date", change: value => { value.epss.date = "2026-11-02"; }, reason: "epss_date_mismatch" },
  { name: "changed raw EPSS score", change: value => {
    (value.epss.responses[0]!.data as Array<Record<string, unknown>>)[0]!.epss = "0.9";
  }, reason: "epss_snapshot_mismatch" },
  { name: "extra EPSS query alias", change: value => { value.epss.requestedCves.push("CVE-2026-99999"); }, reason: "epss_snapshot_mismatch" },
];

describe("immutable company-scoped threat journal", () => {
  it.each(inconsistentFeeds)("rejects rehashed $name disagreement before persistence", async ({ change, reason }) => {
    const snapshot = await threatSnapshot();
    change(snapshot);
    rehashFeeds(snapshot);
    await expect(journal.record("company", snapshot)).rejects.toThrow(reason);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.threat_snapshots`)).rows).toEqual([]);
  });

  it.each(inconsistentFeeds)("rejects stored rehashed $name disagreement before enrichment", async ({ change, reason }) => {
    const snapshot = await threatSnapshot();
    const original = await journal.record("company", snapshot);
    change(snapshot);
    rehashFeeds(snapshot);
    const id = sha256(canonicalJson(["threat-snapshot-v1", snapshot]));
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.threat_snapshots SET snapshot_id = $1, bundle = $2 WHERE snapshot_id = $3`,
      [id, canonicalJson(snapshot), original]);
    await expect(journal.read("company", id)).rejects.toThrow(reason);
    await expect(journal.enrich("company", id, [input()])).rejects.toThrow(reason);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.decision_records`)).rows).toEqual([]);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.delivery_routing`)).rows).toEqual([]);
  });

  it.each(["model-reference", "percentile", "catalog-metadata", "query-time"])(
    "retains distinct %s provenance even when decision semantics stay equal", async change => {
      const snapshot = await threatSnapshot();
      const original = structuredClone(snapshot);
      const first = await journal.record("company", snapshot);
      const [before] = await journal.enrich("company", first, [input()]);
      if (change === "model-reference") snapshot.epss.model.reference = "https://example.invalid/revised-model-evidence";
      if (change === "percentile") (snapshot.epss.responses[0]!.data as Array<Record<string, unknown>>)[0]!.percentile = "0.5";
      if (change === "catalog-metadata") snapshot.kev.raw.title = "Corrected fixture catalog title";
      if (change === "query-time") snapshot.epss.queriedAt = "2026-11-04T04:29:59.000Z";
      rehashFeeds(snapshot);
      const ids = await Promise.all(Array.from({ length: 4 }, () => journal.record("company", snapshot)));
      const second = ids[0]!;
      expect(new Set(ids).size).toBe(1);
      expect(second).not.toBe(first);
      expect(await journal.record("company", snapshot)).toBe(second);
      const [after] = await journal.enrich("company", second, [input()]);
      const oldDecision = decide(before!);
      const newDecision = decide(after!);
      expect(newDecision.inputSha256).not.toBe(oldDecision.inputSha256);
      expect(newDecision).toMatchObject({ identity: oldDecision.identity, priority: oldDecision.priority,
        matchedRule: oldDecision.matchedRule, applicability: oldDecision.applicability,
        proposedVex: oldDecision.proposedVex, proposedRemediation: oldDecision.proposedRemediation });
      expect(after!.provenance.threatSnapshotId).toBe(second);
      expect(after!.provenance.kev!.snapshotSha256).toBe(snapshot.kev.snapshotSha256);
      expect(after!.provenance.epss!.snapshotSha256).toBe(snapshot.epss.snapshotSha256);
      expect(await journal.read("company", first)).toEqual(original);
      expect(await journal.read("company", second)).toEqual(snapshot);
      expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.threat_snapshots`)).rows).toHaveLength(2);
    },
  );

  it("persists raw feed/model/query coverage before returning enriched inputs", async () => {
    const snapshot = await threatSnapshot();
    const id = await journal.record("company", snapshot);
    expect(await journal.read("company", id)).toEqual(snapshot);
    const [value] = await journal.enrich("company", id, [input()]);
    expect(value!.provenance.threatSnapshotId).toBe(id);
    expect(decide(value!).priority).toBe(0);
    expect(await journal.enrich("company", id, [input()])).toEqual([value]);
    expect(await journal.read("other-company", id)).toBeNull();
    await expect(journal.enrich("other-company", id, [input()])).rejects.toThrow("missing_threat_snapshot");
  });

  it("concurrent and sequential replay retain one immutable raw bundle", async () => {
    const snapshot = await threatSnapshot();
    const ids = await Promise.all(Array.from({ length: 10 }, () => journal.record("company", snapshot)));
    expect(new Set(ids).size).toBe(1);
    await journal.record("company", snapshot);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.threat_snapshots`)).rows).toHaveLength(1);
  });

  it("requires durable feeds without suppressing raw old snapshots or mutating them", async () => {
    const snapshot = await threatSnapshot();
    const first = await journal.record("company", snapshot);
    const newer = structuredClone(snapshot);
    newer.epss.model.reference = "https://example.invalid/model-evidence-correction";
    // Rebuild the derived hash after changing trusted model evidence.
    const { snapshotSha256: _, ...content } = newer.epss;
    newer.epss.snapshotSha256 = sha256(canonicalJson(content));
    const second = await journal.record("company", newer);
    expect(first).not.toBe(second);
    expect(await journal.read("company", first)).toEqual(snapshot);
  });

  it("rejects failed/ambiguous storage effects and safely replays committed evidence", async () => {
    const snapshot = await threatSnapshot();
    const interrupted = new ThreatJournal({ ...db, execute: async () => { throw new Error("write failed"); } });
    await expect(interrupted.record("company", snapshot)).rejects.toThrow("write failed");
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.threat_snapshots`)).rows).toHaveLength(0);
    const ambiguous = new ThreatJournal({ ...db, execute: async (sql, params) => {
      await db.execute(sql, params); throw new Error("response lost");
    } });
    await expect(ambiguous.record("company", snapshot)).rejects.toThrow("response lost");
    const id = await journal.record("company", snapshot);
    expect(await journal.read("company", id)).toEqual(snapshot);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.threat_snapshots`)).rows).toHaveLength(1);
  });

  it("holds stored corruption, malformed ids, namespaces and derived/raw divergence", async () => {
    const snapshot = await threatSnapshot();
    const id = await journal.record("company", snapshot);
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.threat_snapshots SET bundle = '{}' WHERE snapshot_id = $1`, [id]);
    await expect(journal.read("company", id)).rejects.toThrow("stored_threat_hash_mismatch");
    await expect(journal.read("company", "latest")).rejects.toThrow("invalid_threat_snapshot_id");
    expect(() => new ThreatJournal({ ...db, namespace: "other" })).toThrow("namespace");
    snapshot.epss.scores[0]!.probability = 0;
    await expect(journal.record("company", snapshot)).rejects.toThrow("epss_snapshot_mismatch");
  });

  it("replays lockfile→OSV→raw feeds→rules→routing without duplicate membership", async () => {
    const sources = new SourceJournal(db, now);
    const lockfile = await sources.recordLockfiles("company", sourceLockfiles());
    const osv = sourceOsv();
    const raw = { ...osv.records[0]!.raw, aliases: ["CVE-2026-12345"] };
    osv.records[0] = parseOsvRecord(raw, "GHSA-fixture");
    osv.unavailableIds = ["CVE-2026-12345"];
    const { snapshotSha256: _, ...content } = osv;
    osv.snapshotSha256 = sha256(canonicalJson(content));
    const scan = await sources.recordOsv("company", lockfile, osv);
    const threatId = await journal.record("company", await threatSnapshot());
    const routing = new DeliveryRouting(db, now);
    for (let run = 0; run < 2; run++) {
      const stored = (await sources.readOsv("company", scan.snapshotId))!;
      const values = await journal.enrich("company", threatId, stored.inputs);
      for (const value of values) await routing.observe("company", value);
    }
    const result = await routing.snapshot("company", "example/project");
    expect(result.members).toHaveLength(1);
    expect(result.containers).toHaveLength(1);
    expect(result.members[0]!.priority).toBe(0);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.card_claims`)).rows).toHaveLength(0);
  });
});
