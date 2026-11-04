import type { PGlite } from "@electric-sql/pglite";
import { testDatabase } from "./test/database.js";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { CardDelivery, ClaimStore, DATABASE_NAMESPACE, FINDING_ORIGIN_KIND } from "./claims.js";
import type { DeliveryInput, IssuePort } from "./claims.js";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

type Summary = Awaited<ReturnType<IssuePort["create"]>>;
const input = (patch: Partial<DeliveryInput> = {}): DeliveryInput => ({
  companyId: "company-a", projectId: "triage", originId: "a".repeat(64),
  title: "Report-only finding", description: "Evidence bundle", priority: "high",
  advisoryModified: "2026-11-01T00:00:00Z", ...patch,
});
const summary = (id: string, patch: Partial<Summary> = {}): Summary => ({
  id, companyId: "company-a", originId: "a".repeat(64), originKind: FINDING_ORIGIN_KIND, status: "todo", ...patch,
});

class FakeIssues implements IssuePort {
  rows = new Map<string, Summary>();
  creates: Parameters<IssuePort["create"]>[0][] = [];
  updates: Parameters<IssuePort["update"]>[] = [];
  lookups: Parameters<IssuePort["list"]>[0][] = [];
  onCreate: (() => Promise<Summary>) | null = null;
  onUpdate: (() => Promise<void>) | null = null;

  async list(query: Parameters<IssuePort["list"]>[0]): Promise<Summary[]> {
    this.lookups.push(query);
    return structuredClone([...this.rows.values()].filter(row => row.companyId === query.companyId
      && row.originKind === query.originKind && row.originId === query.originId).slice(0, query.limit));
  }
  async create(payload: Parameters<IssuePort["create"]>[0]): Promise<Summary> {
    this.creates.push(payload);
    if (this.onCreate) return this.onCreate();
    const issue = summary(`issue-${this.creates.length}`, {
      companyId: payload.companyId, originId: payload.originId!, originKind: payload.originKind!,
    });
    this.rows.set(issue.id, issue);
    return structuredClone(issue);
  }
  async update(...args: Parameters<IssuePort["update"]>): Promise<Summary> {
    this.updates.push(args);
    if (this.onUpdate) await this.onUpdate();
    const [id, patch] = args;
    const issue = this.rows.get(id)!;
    if (patch.status) issue.status = patch.status;
    return structuredClone(issue);
  }
}

let postgres: PGlite;
let db: PluginDatabaseClient;
let store: ClaimStore;
let issues: FakeIssues;
let delivery: CardDelivery;

beforeAll(async () => {
  ({ postgres, db } = await testDatabase());
}, 30000);

beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.card_claims`);
  store = new ClaimStore(db);
  issues = new FakeIssues();
  delivery = new CardDelivery(store, issues);
});
afterAll(async () => { await postgres.close(); });

async function ageClaim() {
  await postgres.exec(`UPDATE ${DATABASE_NAMESPACE}.card_claims SET claimed_at = now() - interval '31 minutes'`);
}

describe("atomic namespace SQL and report-only delivery", () => {
  it("replays sequentially across worker instances with zero duplicates and no assignee", async () => {
    expect((await delivery.ensure(input())).status).toBe("created");
    expect((await new CardDelivery(new ClaimStore(db), issues).ensure(input())).status).toBe("reused");
    expect(issues.creates).toHaveLength(1);
    expect(issues.creates[0]).not.toHaveProperty("assigneeAgentId");
    expect(issues.creates[0]).not.toHaveProperty("assigneeUserId");
    expect(issues.lookups[0]).toEqual({ companyId: "company-a", originKind: FINDING_ORIGIN_KIND, originId: "a".repeat(64), limit: 2 });
    expect(await store.read(input())).toMatchObject({ state: "linked", issue_id: "issue-1", attempt_count: 1 });
  });

  it("serializes concurrent jobs and API callbacks through the actual PostgreSQL primary key", async () => {
    const results = await Promise.all(Array.from({ length: 20 }, () => new CardDelivery(new ClaimStore(db), issues).ensure(input())));
    expect(results.filter(result => result.status === "created")).toHaveLength(1);
    expect(issues.creates).toHaveLength(1);
    expect(issues.rows.size).toBe(1);
    expect((await delivery.ensure(input())).status).toBe("reused");
  });

  it("isolates companies and rejects a different namespace", async () => {
    await delivery.ensure(input());
    await delivery.ensure(input({ companyId: "company-b" }));
    expect(issues.creates).toHaveLength(2);
    expect(() => new ClaimStore({ ...db, namespace: "public" })).toThrow("namespace");
  });

  it("looks up closed issues before an initial create and reopens the existing issue", async () => {
    issues.rows.set("existing", summary("existing", { status: "done" }));
    expect((await delivery.ensure(input())).status).toBe("reopened");
    expect(issues.creates).toHaveLength(0);
    expect(issues.rows.get("existing")!.status).toBe("todo");
    expect(issues.lookups.every(query => query.status === undefined)).toBe(true);
  });

  it("reopens a changed advisory once; same or old or unavailable revisions do not reopen", async () => {
    await delivery.ensure(input());
    issues.rows.get("issue-1")!.status = "done";
    expect((await delivery.ensure(input())).status).toBe("reused");
    expect((await delivery.ensure(input({ advisoryModified: "2026-11-03T00:00:00Z" }))).status).toBe("reopened");
    issues.rows.get("issue-1")!.status = "done";
    for (const advisoryModified of ["2026-11-03T00:00:00Z", "2026-11-02T00:00:00Z", null, "invalid"]) {
      expect((await delivery.ensure(input({ advisoryModified }))).status).toBe("reused");
    }
    expect(issues.updates).toHaveLength(1);
    expect(issues.creates).toHaveLength(1);
  });

  it("serializes concurrent newer-revision refreshes and does not regress to an old revision", async () => {
    await delivery.ensure(input());
    issues.rows.get("issue-1")!.status = "done";
    const changed = input({ advisoryModified: "2026-11-03T00:00:00Z" });
    await Promise.all(Array.from({ length: 10 }, () => delivery.ensure(changed)));
    expect(issues.updates).toHaveLength(1);
    expect((await store.read(input()))!.advisory_modified).toBe(changed.advisoryModified);
  });

  it("a changed remediation origin creates a separate guarded record, leaving the old one intact", async () => {
    await delivery.ensure(input());
    await delivery.ensure(input({ originId: "b".repeat(64) }));
    expect(issues.creates).toHaveLength(2);
    expect((await store.read(input()))!.state).toBe("linked");
  });

  it("a lost acquisition response is resolved only by reading the exact durable token", async () => {
    const faulty: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (sql.startsWith("INSERT")) throw new Error("Response lost");
      return result;
    } };
    expect((await new CardDelivery(new ClaimStore(faulty), issues).ensure(input())).status).toBe("created");
    expect(issues.creates).toHaveLength(1);
    const unavailable: PluginDatabaseClient = { ...db, execute: async () => { throw new Error("No response"); } };
    expect((await new CardDelivery(new ClaimStore(unavailable), issues).ensure(input({ originId: "c".repeat(64) }))).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(1);
  });

  it("create committed but response lost remains fenced and can safely relink", async () => {
    issues.onCreate = async () => {
      issues.rows.set("late", summary("late"));
      throw new Error("Response lost after commit");
    };
    expect((await delivery.ensure(input())).status).toBe("delivery_unknown");
    expect((await store.read(input()))!.state).toBe("indeterminate");
    expect((await delivery.ensure(input())).status).toBe("delivery_unknown");
    expect(["updated", "reused"]).toContain((await delivery.reconcile(input())).status);
    expect((await store.read(input()))!.issue_id).toBe("late");
    expect(issues.creates).toHaveLength(1);
  });

  it.each(["before", "after"])("link response failure %s commit never grants another create", async mode => {
    let failed = false;
    const faulty: PluginDatabaseClient = { ...db, execute: async (sql, params = []) => {
      if (!failed && sql.startsWith("UPDATE") && params[3] === "creating" && params[4] === "linked") {
        failed = true;
        if (mode === "after") await db.execute(sql, params);
        throw new Error("Link response lost");
      }
      return db.execute(sql, params);
    } };
    expect((await new CardDelivery(new ClaimStore(faulty), issues).ensure(input())).status).toBe("delivery_unknown");
    await delivery.ensure(input());
    await delivery.reconcile(input());
    expect(issues.creates).toHaveLength(1);
    expect((await store.read(input()))!.issue_id).toBe("issue-1");
  });

  it("same-job overlap after 30 minutes does not steal a live holder", async () => {
    const started = deferred<void>();
    const finish = deferred<Summary>();
    issues.onCreate = async () => { started.resolve(); return finish.promise; };
    const first = delivery.ensure(input());
    await started.promise;
    await ageClaim();
    expect(await new CardDelivery(new ClaimStore(db), issues).ensure(input())).toMatchObject({ status: "pending", needsReconciliation: true });
    expect((await delivery.reconcile(input())).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(1);
    issues.rows.set("late", summary("late"));
    finish.resolve(summary("late"));
    expect((await first).status).toBe("created");
  });

  it("a timed-out create completing late cannot cause a second create, even after 30 minutes", async () => {
    const started = deferred<void>();
    const finish = deferred<void>();
    issues.onCreate = async () => {
      started.resolve();
      await finish.promise;
      issues.rows.set("late", summary("late"));
      return summary("late");
    };
    const first = new CardDelivery(store, issues, 150).ensure(input());
    await started.promise;
    expect((await first).status).toBe("delivery_unknown");
    await ageClaim();
    await new CardDelivery(new ClaimStore(db), issues).ensure(input());
    expect((await delivery.reconcile(input())).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(1);
    finish.resolve();
    // The host effect settles after the caller has already abandoned the attempt.
    await Promise.resolve();
    await delivery.reconcile(input());
    expect(issues.rows.size).toBe(1);
    expect(issues.creates).toHaveLength(1);
    expect((await store.read(input()))!.issue_id).toBe("late");
  });

  it("an abandoned reserved claim survives a worker restart without automatic recovery", async () => {
    await store.acquire(input(), "dead-worker");
    await ageClaim();
    expect((await new CardDelivery(new ClaimStore(db), issues).ensure(input())).status).toBe("pending");
    expect((await delivery.reconcile(input())).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(0);
  });

  it("an empty lookup or worker-terminal receipt alone does not prove settled host effects", async () => {
    await store.acquire(input(), "old-attempt");
    await store.change(input(), "old-attempt", "reserved", { state: "indeterminate" });
    const result = await delivery.reconcile(input(), async () => ({
      previousClaimToken: "old-attempt", terminalExecutionReceipt: "worker stopped",
      settledHostEffectsReceipt: "", auditRef: "operator-audit",
    }));
    expect(result.status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(0);
  });

  it("independently verified terminal execution AND settled host effects grant one audited recovery", async () => {
    await store.acquire(input(), "old-attempt");
    await store.change(input(), "old-attempt", "reserved", { state: "indeterminate" });
    const proof = {
      previousClaimToken: "old-attempt", terminalExecutionReceipt: "execution-receipt",
      settledHostEffectsReceipt: "host-effect-receipt", auditRef: "operator-audit",
    };
    expect((await delivery.reconcile(input(), async () => proof)).status).toBe("created");
    expect((await store.read(input()))!.recovery_audit).toEqual([proof]);
    expect((await delivery.ensure(input())).status).toBe("reused");
    expect(issues.creates).toHaveLength(1);
  });

  it("concurrent proven-safe recovery still grants only one create attempt", async () => {
    await store.acquire(input(), "old-attempt");
    await store.change(input(), "old-attempt", "reserved", { state: "indeterminate" });
    const proof = {
      previousClaimToken: "old-attempt", terminalExecutionReceipt: "execution-receipt",
      settledHostEffectsReceipt: "host-effect-receipt", auditRef: "operator-audit",
    };
    await Promise.all(Array.from({ length: 10 }, () => delivery.reconcile(input(), async () => proof)));
    expect(issues.creates).toHaveLength(1);
    expect((await store.read(input()))!.recovery_audit).toHaveLength(1);
  });

  it("a reconciliation lookup failure reports unknown instead of rejecting or creating", async () => {
    await delivery.ensure(input());
    const faulty: IssuePort = { ...issues, create: issues.create.bind(issues), update: issues.update.bind(issues),
      list: async () => { throw new Error("Host read unavailable"); },
    };
    expect((await new CardDelivery(store, faulty).reconcile(input())).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(1);
  });

  it("a missing linked issue remains unknown, never recreated even with recovery receipts", async () => {
    await delivery.ensure(input());
    issues.rows.clear();
    expect(await delivery.ensure(input())).toMatchObject({ status: "delivery_unknown", needsReconciliation: true });
    expect((await delivery.reconcile(input())).status).toBe("delivery_unknown");
    expect(issues.creates).toHaveLength(1);
  });

  it("multiple existing origins, including closed issues, quarantine without create or deletion", async () => {
    issues.rows.set("one", summary("one"));
    issues.rows.set("two", summary("two", { status: "done" }));
    expect((await delivery.ensure(input())).status).toBe("quarantined");
    expect((await delivery.ensure(input())).status).toBe("quarantined");
    expect(issues.creates).toHaveLength(0);
    expect(issues.rows.size).toBe(2);
    expect((await store.read(input()))!.state).toBe("quarantined");
  });

  it("a failed refresh remains fenced without issuing another card", async () => {
    await delivery.ensure(input());
    issues.rows.get("issue-1")!.status = "done";
    issues.onUpdate = async () => { throw new Error("Uncertain update"); };
    const changed = input({ advisoryModified: "2026-11-03T00:00:00Z" });
    expect((await delivery.ensure(changed)).status).toBe("delivery_unknown");
    expect((await delivery.ensure(changed)).status).toBe("delivery_unknown");
    expect((await store.read(input()))!.state).toBe("indeterminate");
    expect(issues.updates).toHaveLength(1);
    expect(issues.creates).toHaveLength(1);
  });

  it("token-fenced SQL refuses a late old-owner link", async () => {
    await store.acquire(input(), "new-owner");
    expect(await store.change(input(), "old-owner", "reserved", { state: "linked", issue_id: "wrong" })).toBe(false);
    expect((await store.read(input()))!.issue_id).toBeNull();
  });
});
