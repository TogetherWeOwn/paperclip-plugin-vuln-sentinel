import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE, FINDING_ORIGIN_KIND } from "./claims.js";
import { findingIdentity } from "./identity.js";
import { DeliveryRouting, WEEKLY_ORIGIN_KIND, utcWeekStart, weeklyOrigin } from "./routing.js";
import { DecisionJournal } from "./journal.js";
import { finding } from "./test/fixtures.js";
import { testDatabase } from "./test/database.js";
import type { FindingInput } from "./model.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let routing: DeliveryRouting;
let now: string;
const company = "company-a";
const repo = "example/service";
const weekly = (patch: Partial<FindingInput> = {}) => finding({ scope: "development", ...patch });
const at = (input: FindingInput, value: string): FindingInput => ({
  ...input, provenance: { ...input.provenance, observedAt: value },
});
const urgent = (input: FindingInput, observedAt: string): FindingInput => at({
  ...input, provenance: { ...input.provenance, kev: { catalogVersion: "fixture-new", aliases: [input.advisoryId] } },
}, observedAt);

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records`);
  now = "2026-11-04T05:00:00Z";
  routing = new DeliveryRouting(db, () => new Date(now));
});
afterAll(async () => { await postgres.close(); });

describe("versioned weekly identity", () => {
  it.each([
    ["2026-11-08T23:59:59.999Z", "2026-11-02T00:00:00.000Z"],
    ["2026-11-09T00:00:00Z", "2026-11-09T00:00:00.000Z"],
    ["2026-11-09T01:00:00+02:00", "2026-11-02T00:00:00.000Z"],
    ["2027-01-01T01:00:00Z", "2026-12-28T00:00:00.000Z"],
  ])("buckets %s on UTC Monday", (time, expected) => expect(utcWeekStart(time)).toBe(expected));

  it("uses a company/repo/week domain distinct from member identity", () => {
    const week = utcWeekStart(now);
    const origin = weeklyOrigin(company, repo, week);
    expect(origin).not.toBe(findingIdentity(weekly()).originId);
    expect(origin).toMatch(/^[a-f0-9]{64}$/);
    expect(origin).not.toBe(weeklyOrigin("other", repo, week));
    expect(origin).not.toBe(weeklyOrigin(company, "example/other", week));
    expect(origin).not.toBe(weeklyOrigin(company, repo, "2026-11-09T00:00:00.000Z"));
    expect(() => weeklyOrigin(company, "Example/Service", week)).toThrow();
    expect(() => weeklyOrigin(company, repo, now)).toThrow();
    expect(() => utcWeekStart("invalid")).toThrow();
  });
});

describe("durable routing before any issue effect", () => {
  it("puts two distinct findings into one repo-week with two member mappings", async () => {
    const first = await routing.observe(company, weekly());
    const second = await routing.observe(company, weekly({ package: "other-package" }));
    const snapshot = await routing.snapshot(company, repo);
    expect(first.container!.originId).toBe(second.container!.originId);
    expect(snapshot.members).toHaveLength(2);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.containers[0]).toMatchObject({ originKind: WEEKLY_ORIGIN_KIND, urgent: false, publishRequested: false });
    expect(snapshot.containers[0]!.memberIds).toHaveLength(2);
    const journal = new DecisionJournal(db);
    for (const member of snapshot.members) {
      expect(await journal.read(company, member.currentOriginId, member.decisionId)).not.toBeNull();
    }
  });

  it("serializes identical concurrent workers and callbacks with one membership", async () => {
    await Promise.all(Array.from({ length: 20 }, () => new DeliveryRouting(db, () => new Date(now)).observe(company, weekly())));
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members).toHaveLength(1);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.containers[0]!.memberIds).toHaveLength(1);
    expect((await routing.observe(company, weekly())).status).toBe("reused");
    expect(await routing.snapshot(company, repo)).toEqual(snapshot);
  });

  it("does not lose distinct concurrent members or container revisions", async () => {
    await Promise.all(Array.from({ length: 12 }, (_, i) => routing.observe(company, weekly({ package: `package-${i}` }))));
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members).toHaveLength(12);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.containers[0]!.memberIds).toHaveLength(12);
    expect(snapshot.containers[0]!.revision).toBe(12);
  });

  it("keeps company and repository boundaries distinct", async () => {
    const a = await routing.observe(company, weekly());
    const b = await routing.observe("company-b", weekly());
    const c = await routing.observe(company, weekly({ repo: "example/other" }));
    expect(new Set([a, b, c].map(result => result.container!.originId)).size).toBe(3);
    expect((await routing.snapshot(company, repo)).members).toHaveLength(1);
    expect(() => new DeliveryRouting({ ...db, namespace: "public" })).toThrow("namespace");
  });

  it("retains original bucket and SLA across rollover; only new identities enter the new week", async () => {
    now = "2026-11-08T23:59:59Z";
    const old = await routing.observe(company, at(weekly(), now));
    const original = (await routing.snapshot(company, repo)).members[0]!;
    now = "2026-11-09T00:00:01Z";
    expect((await routing.observe(company, at(weekly(), now))).container!.originId).toBe(old.container!.originId);
    const fresh = await routing.observe(company, at(weekly({ package: "new-package" }), now));
    expect(fresh.container!.originId).not.toBe(old.container!.originId);
    const retained = (await routing.snapshot(company, repo)).members[0]!;
    expect(retained.originalWeek).toBe("2026-11-02T00:00:00.000Z");
    expect(retained.firstObservedAt).toBe(original.firstObservedAt);
    expect(retained.deadlineAt).toBe(original.deadlineAt);
  });

  it("does not migrate an existing per-finding delivery when it later becomes weekly", async () => {
    const first = await routing.observe(company, finding());
    const later = await routing.observe(company, at(weekly(), "2026-11-05T00:00:00Z"));
    expect(first.container!.originKind).toBe(FINDING_ORIGIN_KIND);
    expect(later.container!.originId).toBe(first.container!.originId);
    expect(later.container!.originKind).toBe(FINDING_ORIGIN_KIND);
    expect((await routing.snapshot(company, repo)).containers).toHaveLength(1);
  });

  it("initial P0 requests immediate per-finding publication, without a weekly member", async () => {
    const result = await routing.observe(company, urgent(weekly(), now));
    expect(result.container).toMatchObject({ originKind: FINDING_ORIGIN_KIND, urgent: true, publishRequested: true, priority: 0, weekStart: null });
    expect(result.container!.originId).toBe(result.findingId);
    expect((await routing.snapshot(company, repo)).members[0]!.originalWeek).toBeNull();
  });

  it("promotes the original weekly container immediately, even across rollover; never splits", async () => {
    const first = await routing.observe(company, weekly());
    await routing.observe(company, weekly({ package: "unrelated" }));
    now = "2026-11-10T00:00:00Z";
    const result = await routing.observe(company, urgent(weekly(), now));
    expect(result.container).toMatchObject({ originId: first.container!.originId, originKind: WEEKLY_ORIGIN_KIND,
      urgent: true, publishRequested: true, priority: 0, weekStart: "2026-11-02T00:00:00.000Z" });
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.members).toHaveLength(2);
    expect(snapshot.members[1]!.priority).toBe(3);
    expect(Date.parse(result.container!.deadlineAt)).toBeLessThanOrEqual(Date.parse(snapshot.members[0]!.firstObservedAt) + 86400000);
  });

  it("concurrent refresh and P0 escalation cannot split or roll back the newer decision", async () => {
    const first = await routing.observe(company, weekly());
    await Promise.all([
      routing.observe(company, at(weekly(), "2026-11-05T00:00:00Z")),
      routing.observe(company, urgent(weekly(), "2026-11-06T00:00:00Z")),
    ]);
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.containers[0]).toMatchObject({ originId: first.container!.originId, priority: 0, publishRequested: true });
    expect(snapshot.members[0]!.priority).toBe(0);
    expect(snapshot.containers[0]!.memberIds).toHaveLength(1);
  });

  it("retains urgent delivery and the original deadline on later de-escalation", async () => {
    await routing.observe(company, weekly());
    const p0 = await routing.observe(company, urgent(weekly(), "2026-11-05T00:00:00Z"));
    now = "2026-11-11T00:00:00Z";
    const later = await routing.observe(company, at(weekly(), now));
    expect(later.container).toMatchObject({ originId: p0.container!.originId, urgent: true,
      publishRequested: true, priority: 0, deadlineAt: p0.container!.deadlineAt });
  });

  it("alias-minimum changes retain redirects, delivery origin and original bucket", async () => {
    const first = await routing.observe(company, weekly());
    now = "2026-11-10T00:00:00Z";
    const changed = at(weekly(), now);
    changed.aliases[0]!.aliases.push("AAA-new-minimum");
    const nextId = findingIdentity(changed).originId;
    const result = await routing.observe(company, changed);
    expect(result.findingId).toBe(first.findingId);
    expect(result.container!.originId).toBe(first.container!.originId);
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members).toHaveLength(1);
    expect(snapshot.members[0]!.identityKeys).toEqual([first.findingId, nextId]);
    expect(snapshot.members[0]!.originalWeek).toBe("2026-11-02T00:00:00.000Z");
    await routing.observe(company, weekly());
    expect((await routing.snapshot(company, repo)).members[0]!.currentOriginId).toBe(nextId);
  });

  it("an alias bridge between existing independent records requires attention, not silent merge", async () => {
    const a = weekly();
    const b = weekly({ advisoryId: "GHSA-independent", aliases: [{ id: "GHSA-independent", aliases: [], upstream: [], modified: "2026-11-01T00:00:00Z", withdrawn: null }] });
    await routing.observe(company, a);
    await routing.observe(company, b);
    const bridge = at(weekly(), "2026-11-05T00:00:00Z");
    bridge.aliases[0]!.aliases.push("GHSA-independent");
    expect((await routing.observe(company, bridge)).status).toBe("attention");
    expect((await routing.observe(company, bridge)).status).toBe("attention");
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members).toHaveLength(2);
    expect(snapshot.attention).toHaveLength(1);
    expect(snapshot.containers[0]!.memberIds).toHaveLength(2);
  });

  it("changed fix requires evidence, then atomically retains lineage without false remediation", async () => {
    const original = await routing.observe(company, weekly({ fixedVersion: "1.1.0" }));
    now = "2026-11-10T00:00:00Z";
    const changed = at(weekly({ fixedVersion: "1.2.0" }), now);
    expect((await routing.observe(company, changed)).status).toBe("attention");
    expect((await routing.snapshot(company, repo)).members).toHaveLength(1);
    const successor = await routing.observe(company, changed, {
      kind: "replacement", predecessorId: original.findingId!, evidenceRef: "verified-same-remediation-action",
    });
    expect(successor.findingId).not.toBe(original.findingId);
    expect(successor.container!.originId).not.toBe(original.container!.originId);
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members[0]).toMatchObject({ state: "superseded", successorIds: [successor.findingId] });
    expect(snapshot.members[1]).toMatchObject({ state: "unresolved", predecessorId: original.findingId,
      originalWeek: "2026-11-09T00:00:00.000Z", relationshipEvidenceRef: "verified-same-remediation-action" });
    expect(snapshot.containers[0]!.memberIds).toEqual([original.findingId]);
  });

  it("concurrent evidenced replacements grant only one active replacement action", async () => {
    const original = await routing.observe(company, weekly({ fixedVersion: "1.1.0" }));
    const relationship = { kind: "replacement" as const, predecessorId: original.findingId!, evidenceRef: "same-action-proof" };
    await Promise.all([
      routing.observe(company, at(weekly({ fixedVersion: "1.2.0" }), "2026-11-05T00:00:00Z"), relationship),
      routing.observe(company, at(weekly({ fixedVersion: "1.3.0" }), "2026-11-06T00:00:00Z"), relationship),
    ]);
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members.filter(item => item.state === "unresolved")).toHaveLength(1);
    expect(snapshot.members.filter(item => item.state === "superseded")).toHaveLength(1);
    expect(snapshot.attention).toHaveLength(1);
  });

  it("does not infer that independent remediation units replace each other", async () => {
    await routing.observe(company, weekly({ fixedVersion: "1.1.0" }));
    await routing.observe(company, weekly({ fixedVersion: "2.1.0" }), { kind: "independent", evidenceRef: "two-supported-release-lines" });
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.members).toHaveLength(2);
    expect(snapshot.members.every(item => item.state === "unresolved")).toBe(true);
  });

  it("cannot silently reactivate a superseded action from a newer observation", async () => {
    const original = await routing.observe(company, weekly({ fixedVersion: "1.1.0" }));
    await routing.observe(company, at(weekly({ fixedVersion: "1.2.0" }), "2026-11-05T00:00:00Z"), {
      kind: "replacement", predecessorId: original.findingId!, evidenceRef: "same-action-proof",
    });
    expect((await routing.observe(company, at(weekly({ fixedVersion: "1.1.0" }), "2026-11-06T00:00:00Z"))).status).toBe("attention");
    expect((await routing.snapshot(company, repo)).members[0]!.state).toBe("superseded");
  });

  it("negative proposals and same/new artifact observations never certify remediation", async () => {
    const first = await routing.observe(company, weekly());
    const outside = at(weekly(), "2026-11-05T00:00:00Z");
    outside.versionEvidence.status = "outside";
    const negative = await routing.observe(company, outside);
    expect(negative.container!.originId).toBe(first.container!.originId);
    outside.provenance.artifactDigest = "sha256:new-artifact";
    outside.versionEvidence.artifactDigest = "sha256:new-artifact";
    outside.provenance.observedAt = "2026-11-06T00:00:00Z";
    await routing.observe(company, outside);
    const member = (await routing.snapshot(company, repo)).members[0]!;
    expect(member).toMatchObject({ state: "unresolved", applicability: "dropped", deliveryOrigin: first.container!.originId });
  });

  it("initial negative has no delivery; first later eligibility gets that later week's bucket", async () => {
    const outside = weekly();
    outside.versionEvidence.status = "outside";
    expect((await routing.observe(company, outside)).container).toBeNull();
    now = "2026-11-10T00:00:00Z";
    const result = await routing.observe(company, at(weekly(), now));
    expect(result.container!.weekStart).toBe("2026-11-09T00:00:00.000Z");
    expect((await routing.snapshot(company, repo)).members).toHaveLength(1);
  });

  it("repairs a crash after journal persistence without duplicate membership", async () => {
    let fail = true;
    const faulty: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (fail && sql.includes("delivery_routing") && sql.startsWith("UPDATE")) { fail = false; throw new Error("Transport failure"); }
      return db.execute(sql, params);
    } };
    await expect(new DeliveryRouting(faulty, () => new Date(now)).observe(company, weekly())).rejects.toThrow("Transport failure");
    expect(await new DecisionJournal(db).latest(company, findingIdentity(weekly()).originId)).not.toBeNull();
    await routing.observe(company, weekly());
    await routing.observe(company, weekly());
    expect((await routing.snapshot(company, repo)).members).toHaveLength(1);
  });

  it("bounds CAS contention and leaves the full decision available for later replay", async () => {
    let attempts = 0;
    const contended: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (sql.includes("delivery_routing") && sql.startsWith("UPDATE")) { attempts++; return { rowCount: 0 }; }
      return db.execute(sql, params);
    } };
    await expect(new DeliveryRouting(contended, () => new Date(now)).observe(company, weekly())).rejects.toThrow("contention budget");
    expect(attempts).toBe(32);
    expect((await routing.snapshot(company, repo)).members).toHaveLength(0);
    expect(await new DecisionJournal(db).latest(company, findingIdentity(weekly()).originId)).not.toBeNull();
    expect((await routing.observe(company, weekly())).status).toBe("recorded");
  });

  it("oversized routing input remains journaled without a partial delivery assignment", async () => {
    const oversized = weekly();
    oversized.aliases[0]!.aliases.push(`GHSA-${"x".repeat(1048576)}`);
    await expect(routing.observe(company, oversized)).rejects.toThrow("capacity exceeded");
    expect((await routing.snapshot(company, repo)).members).toHaveLength(0);
    expect(await new DecisionJournal(db).latest(company, findingIdentity(oversized).originId)).not.toBeNull();
  });

  it("a lost routing commit response replays the committed mapping rather than multiplying members", async () => {
    let fail = true;
    const faulty: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (fail && sql.includes("delivery_routing") && sql.startsWith("UPDATE")) { fail = false; throw new Error("Response lost"); }
      return result;
    } };
    await expect(new DeliveryRouting(faulty, () => new Date(now)).observe(company, weekly())).rejects.toThrow("Response lost");
    expect((await routing.observe(company, weekly())).status).toBe("reused");
    expect((await routing.snapshot(company, repo)).containers[0]!.memberIds).toHaveLength(1);
  });
});
