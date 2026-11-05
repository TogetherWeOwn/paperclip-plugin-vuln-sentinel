import { FINDING_ORIGIN_KIND } from "../claims.js";
import type { IssuePort } from "../claims.js";

export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

export type Summary = Awaited<ReturnType<IssuePort["create"]>>;
export const summary = (id: string, patch: Partial<Summary> = {}): Summary => ({
  id, companyId: "company-a", originId: "a".repeat(64), originKind: FINDING_ORIGIN_KIND, status: "todo", ...patch,
});

export class FakeIssues implements IssuePort {
  rows = new Map<string, Summary>();
  bodies = new Map<string, string>();
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
    this.bodies.set(issue.id, payload.description ?? "");
    return structuredClone(issue);
  }
  async update(...args: Parameters<IssuePort["update"]>): Promise<Summary> {
    this.updates.push(args);
    if (this.onUpdate) await this.onUpdate();
    const [id, patch] = args;
    const issue = this.rows.get(id)!;
    if (patch.status) issue.status = patch.status;
    if (patch.description !== undefined) this.bodies.set(id, patch.description ?? "");
    return structuredClone(issue);
  }
}
