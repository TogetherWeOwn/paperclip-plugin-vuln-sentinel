import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE, ClaimStore, CardDelivery, FINDING_ORIGIN_KIND, WEEKLY_ORIGIN_KIND } from "./claims.js";
import { ContainerPublication } from "./publication.js";
import { DeliveryRouting } from "./routing.js";
import type { FindingInput } from "./model.js";
import { finding } from "./test/fixtures.js";
import { testDatabase } from "./test/database.js";
import { deferred, FakeIssues, summary } from "./test/issues.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let routing: DeliveryRouting;
let issues: FakeIssues;
let publisher: ContainerPublication;
let now: string;
const company = "company-a";
const repo = "example/service";
const project = "triage";
const weekly = (patch: Partial<FindingInput> = {}) => finding({ scope: "development", ...patch });
const revised = (input: FindingInput, urgent = false): FindingInput => ({
  ...input,
  aliases: input.aliases.map(alias => ({ ...alias, modified: now })),
  provenance: {
    ...input.provenance, observedAt: now,
    ...(urgent ? { kev: { catalogVersion: "new-catalog", aliases: [input.advisoryId] } } : {}),
  },
});
const publish = (originId: string, due = false) => publisher.publish(company, repo, originId, project, due);

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records, ${DATABASE_NAMESPACE}.card_claims`);
  now = "2026-11-04T05:00:00Z";
  routing = new DeliveryRouting(db, () => new Date(now));
  issues = new FakeIssues();
  publisher = new ContainerPublication(db, issues);
});
afterAll(async () => { await postgres.close(); });

describe("explicit unassigned report-only publication", () => {
  it("publishes two weekly members as one native issue with full member evidence", async () => {
    const first = await routing.observe(company, weekly());
    await routing.observe(company, weekly({ package: "other-package" }));
    const origin = first.container!.originId;
    expect((await publish(origin)).status).toBe("deferred");
    expect(issues.creates).toHaveLength(0);
    expect((await publish(origin, true)).status).toBe("created");
    expect(issues.creates).toHaveLength(1);
    const payload = issues.creates[0]!;
    expect(payload).toMatchObject({ originId: origin, originKind: WEEKLY_ORIGIN_KIND, projectId: project, priority: "low" });
    expect(payload).not.toHaveProperty("assigneeAgentId");
    expect(payload).not.toHaveProperty("assigneeUserId");
    expect(payload.description).toContain("Container closure is not remediation");
    expect(payload.description).toContain("other-package");
    expect(payload.description).toContain("toolVersions");
    expect(payload.description).toContain("catalogVersion");
    expect(payload.description).toContain("snapshotSha256");
    expect(payload.description).toContain("proposedRemediation");
    const snapshot = await routing.snapshot(company, repo);
    for (const member of snapshot.members) expect(payload.description).toContain(member.findingId);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.members).toHaveLength(2);
    expect((await new ClaimStore(db).read({ companyId: company, originId: origin }))!.published_revision).toBe(2);
  });

  it("sequential and concurrent replay across worker instances creates no duplicate issues or memberships", async () => {
    const first = await routing.observe(company, weekly());
    const origin = first.container!.originId;
    await Promise.all(Array.from({ length: 12 }, async () => {
      await new DeliveryRouting(db, () => new Date(now)).observe(company, weekly());
      return new ContainerPublication(db, issues).publish(company, repo, origin, project, true);
    }));
    expect((await publish(origin)).status).toBe("reused");
    expect(issues.creates).toHaveLength(1);
    expect(issues.updates).toHaveLength(0);
    expect((await routing.snapshot(company, repo)).members).toHaveLength(1);
  });

  it("keeps native company, repo, and UTC-week issue origins distinct", async () => {
    const a = await routing.observe(company, weekly());
    const b = await routing.observe("company-b", weekly());
    const c = await routing.observe(company, weekly({ repo: "example/other" }));
    now = "2026-11-09T00:00:00Z";
    const d = await routing.observe(company, revised(weekly({ package: "next-week" })));
    await publish(a.container!.originId, true);
    await publisher.publish("company-b", repo, b.container!.originId, project, true);
    await publisher.publish(company, "example/other", c.container!.originId, project, true);
    await publish(d.container!.originId, true);
    expect(issues.creates).toHaveLength(4);
    expect(new Set(issues.creates.map(payload => payload.originId)).size).toBe(4);
  });

  it("rollover plus modified advisory refreshes and reopens the original old batch only", async () => {
    now = "2026-11-08T23:59:59Z";
    const first = await routing.observe(company, revised(weekly()));
    const origin = first.container!.originId;
    await publish(origin, true);
    issues.rows.get("issue-1")!.status = "done";
    now = "2026-11-09T00:00:01Z";
    const result = await routing.observe(company, revised(weekly()));
    expect(result.container!.originId).toBe(origin);
    expect((await publish(origin)).status).toBe("reopened");
    expect((await publish(origin)).status).toBe("reused");
    expect(issues.creates).toHaveLength(1);
    expect(issues.updates).toHaveLength(1);
    expect(issues.rows.get("issue-1")!.originId).toBe(origin);
    expect(issues.bodies.get("issue-1")).toContain("2026-11-02");
    expect((await routing.snapshot(company, repo)).members[0]!.state).toBe("unresolved");
  });

  it.each(["before-publication", "after-publication", "after-closure", "across-rollover"])("weekly to P0 %s promotes the same original batch with no urgent split", async phase => {
    const first = await routing.observe(company, weekly());
    const other = await routing.observe(company, weekly({ package: "unrelated" }));
    const origin = first.container!.originId;
    if (phase !== "before-publication") await publish(origin, true);
    if (phase === "after-closure") issues.rows.get("issue-1")!.status = "done";
    now = phase === "across-rollover" ? "2026-11-10T00:00:00Z" : "2026-11-05T00:00:00Z";
    await routing.observe(company, revised(weekly(), true));
    const result = await publish(origin);
    expect(result.status).toBe(phase === "before-publication" ? "created" : phase === "after-closure" ? "reopened" : "updated");
    expect(issues.creates).toHaveLength(1);
    expect(issues.creates[0]!.originKind).toBe(WEEKLY_ORIGIN_KIND);
    expect(issues.rows.get("issue-1")).toMatchObject({ originId: origin, status: "todo" });
    const latestPayload = issues.updates.at(-1)?.[1] ?? issues.creates[0]!;
    expect(latestPayload.priority).toBe("critical");
    expect(issues.bodies.get("issue-1")).toContain("URGENT container");
    expect(issues.bodies.get("issue-1")).toContain(`Finding ${first.findingId} — P0`);
    expect(issues.bodies.get("issue-1")).toContain(`Finding ${other.findingId} — P3`);
    const snapshot = await routing.snapshot(company, repo);
    expect(snapshot.containers).toHaveLength(1);
    expect(snapshot.members.filter(member => member.deliveryOrigin === origin)).toHaveLength(2);
  });

  it("initial P0 bypasses weekly timing and uses the guarded per-finding origin", async () => {
    const first = await routing.observe(company, revised(weekly(), true));
    expect((await publish(first.container!.originId)).status).toBe("created");
    expect(issues.creates[0]).toMatchObject({ originKind: FINDING_ORIGIN_KIND, originId: first.findingId, priority: "critical" });
    expect((await routing.snapshot(company, repo)).members[0]!.originalWeek).toBeNull();
  });

  it("external closure with unresolved members is reopened, never bulk-resolved", async () => {
    const first = await routing.observe(company, weekly());
    const origin = first.container!.originId;
    await publish(origin, true);
    const before = await routing.snapshot(company, repo);
    issues.rows.get("issue-1")!.status = "done";
    expect((await publish(origin)).status).toBe("reopened");
    expect((await publish(origin)).status).toBe("reused");
    expect(await routing.snapshot(company, repo)).toEqual(before);
    expect(issues.creates).toHaveLength(1);
    expect(issues.updates).toHaveLength(1);
  });

  it("alias-minimum changes retain the original native origin and replacement lineage is visible, never fixed", async () => {
    const original = await routing.observe(company, weekly({ fixedVersion: "1.1.0" }));
    const origin = original.container!.originId;
    await publish(origin, true);
    now = "2026-11-05T00:00:00Z";
    const alias = revised(weekly({ fixedVersion: "1.1.0" }));
    alias.aliases[0]!.aliases.push("AAA-new-minimum");
    await routing.observe(company, alias);
    expect((await publish(origin)).status).toBe("updated");
    expect(issues.creates).toHaveLength(1);
    expect(issues.bodies.get("issue-1")).toContain("AAA-new-minimum");
    now = "2026-11-10T00:00:00Z";
    const next = await routing.observe(company, revised(weekly({ fixedVersion: "1.2.0" })), {
      kind: "replacement", predecessorId: original.findingId!, evidenceRef: "same-action-proof",
    });
    await publish(origin);
    await publish(next.container!.originId, true);
    expect(issues.creates).toHaveLength(2);
    expect(issues.bodies.get("issue-1")).toContain("superseded");
    expect(issues.bodies.get("issue-1")).toContain(next.findingId!);
    expect((await routing.snapshot(company, repo)).members[0]!.state).toBe("superseded");
  });

  it("concurrent publication and escalation eventually refresh the original batch without an urgent copy", async () => {
    const first = await routing.observe(company, weekly());
    const origin = first.container!.originId;
    const started = deferred<void>();
    const finish = deferred<void>();
    issues.onCreate = async () => {
      started.resolve();
      await finish.promise;
      const row = summary("batch", { originId: origin, originKind: WEEKLY_ORIGIN_KIND });
      issues.rows.set(row.id, row);
      return row;
    };
    const low = publish(origin, true);
    await started.promise;
    now = "2026-11-05T00:00:00Z";
    await routing.observe(company, revised(weekly(), true));
    expect((await publish(origin)).status).toBe("pending");
    finish.resolve();
    expect((await low).status).toBe("created");
    expect((await publish(origin)).status).toBe("updated");
    expect(issues.creates).toHaveLength(1);
    expect(issues.updates.at(-1)![1].priority).toBe("critical");
    expect((await routing.snapshot(company, repo)).containers).toHaveLength(1);
  });

  it("a late weekly create after timeout and thirty minutes remains fenced with no second issue", async () => {
    const first = await routing.observe(company, weekly());
    const origin = first.container!.originId;
    const started = deferred<void>();
    const finish = deferred<void>();
    issues.onCreate = async () => {
      started.resolve();
      await finish.promise;
      const row = summary("late-batch", { originId: origin, originKind: WEEKLY_ORIGIN_KIND });
      issues.rows.set(row.id, row);
      return row;
    };
    publisher = new ContainerPublication(db, issues, 150);
    const call = publish(origin, true);
    await started.promise;
    expect((await call).status).toBe("delivery_unknown");
    await postgres.exec(`UPDATE ${DATABASE_NAMESPACE}.card_claims SET claimed_at = now() - interval '31 minutes'`);
    now = "2026-11-10T00:00:00Z";
    await routing.observe(company, revised(weekly(), true));
    expect((await publish(origin)).status).toBe("delivery_unknown");
    finish.resolve();
    await Promise.resolve();
    const payload = issues.creates[0]!;
    const delivery = new CardDelivery(new ClaimStore(db), issues);
    await delivery.reconcile({
      companyId: company, projectId: project, originId: origin, originKind: WEEKLY_ORIGIN_KIND,
      title: payload.title, description: payload.description!, priority: payload.priority!,
      advisoryModified: null, publicationRevision: 1, reopenUnresolved: true,
    });
    expect((await publish(origin)).status).toBe("updated");
    expect(issues.creates).toHaveLength(1);
    expect(issues.rows.size).toBe(1);
  });

  it("missing original links and missing journal evidence never generate fallback issues", async () => {
    expect((await publish("a".repeat(64), true)).status).toBe("attention");
    const first = await routing.observe(company, weekly());
    await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.decision_records`);
    await expect(publish(first.container!.originId, true)).rejects.toThrow("evidence missing");
    expect(issues.creates).toHaveLength(0);
  });

  it("multiple existing weekly issues, including closed ones, quarantine without deleting or adding issues", async () => {
    const first = await routing.observe(company, weekly());
    const origin = first.container!.originId;
    issues.rows.set("one", summary("one", { originId: origin, originKind: WEEKLY_ORIGIN_KIND }));
    issues.rows.set("two", summary("two", { originId: origin, originKind: WEEKLY_ORIGIN_KIND, status: "done" }));
    expect((await publish(origin, true)).status).toBe("quarantined");
    expect(issues.creates).toHaveLength(0);
    expect(issues.rows.size).toBe(2);
    expect(issues.updates).toHaveLength(0);
    expect(issues.lookups[0]!.status).toBeUndefined();
  });

  it("missing linked weekly issues are never automatically replaced", async () => {
    const first = await routing.observe(company, weekly());
    const origin = first.container!.originId;
    await publish(origin, true);
    issues.rows.clear();
    expect((await publish(origin)).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(1);
  });

  it("a malformed durable mapping is surfaced rather than creating a fallback or urgent split", async () => {
    const first = await routing.observe(company, weekly());
    const snapshot = await routing.snapshot(company, repo);
    snapshot.members[0]!.originalWeek = "2026-11-09T00:00:00.000Z";
    await db.execute(`UPDATE "${DATABASE_NAMESPACE}".delivery_routing SET bundle = $3 WHERE company_id = $1 AND repo = $2`,
      [company, repo, JSON.stringify(snapshot)]);
    await expect(publish(first.container!.originId, true)).rejects.toThrow("Malformed container membership");
    expect(issues.creates).toHaveLength(0);
  });

  it("oversized issue evidence is not silently truncated or emitted", async () => {
    const large = weekly();
    large.provenance.toolVersions.padding = "x".repeat(131072);
    const first = await routing.observe(company, large);
    await expect(publish(first.container!.originId, true)).rejects.toThrow("capacity exceeded");
    expect(issues.creates).toHaveLength(0);
  });
});
