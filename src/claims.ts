import { randomUUID } from "node:crypto";
import type { Issue, PluginDatabaseClient, PluginIssuesClient } from "@paperclipai/plugin-sdk";
import { canonicalJson, sha256 } from "./identity.js";

export const DATABASE_NAMESPACE = "plugin_togetherweown_vuln_sentinel_4497ac2b8e";
export const FINDING_ORIGIN_KIND = "plugin:togetherweown.vuln-sentinel:finding" as const;
export const WEEKLY_ORIGIN_KIND = "plugin:togetherweown.vuln-sentinel:weekly:v1" as const;
type OriginKind = typeof FINDING_ORIGIN_KIND | typeof WEEKLY_ORIGIN_KIND;
type IssueSummary = Pick<Issue, "id" | "companyId" | "originId" | "originKind" | "status">;
export interface IssuePort {
  list(input: Parameters<PluginIssuesClient["list"]>[0]): Promise<IssueSummary[]>;
  create(input: Parameters<PluginIssuesClient["create"]>[0]): Promise<IssueSummary>;
  update(id: string, patch: Parameters<PluginIssuesClient["update"]>[1], companyId: string): Promise<IssueSummary>;
}

export interface DeliveryInput {
  companyId: string;
  originId: string;
  projectId: string;
  title: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  advisoryModified: string | null;
  originKind?: OriginKind;
  publicationRevision?: number;
  reopenUnresolved?: boolean;
}

type ClaimState = "reserved" | "creating" | "linked" | "refreshing" | "indeterminate" | "quarantined";
export interface RecoveryProof {
  previousClaimToken: string;
  terminalExecutionReceipt: string;
  settledHostEffectsReceipt: string;
  auditRef: string;
}

export interface Claim {
  company_id: string;
  origin_id: string;
  origin_kind: OriginKind;
  published_revision: number | null;
  published_sha256: string | null;
  state: ClaimState;
  claim_token: string;
  claimed_at: string;
  issue_id: string | null;
  advisory_modified: string | null;
  attempt_count: number;
  last_error: string | null;
  recovery_audit: RecoveryProof[] | null;
}

export interface DeliveryResult {
  status: "created" | "reused" | "updated" | "reopened" | "pending" | "delivery_unknown" | "quarantined";
  issueId: string | null;
  claimToken: string | null;
  needsReconciliation: boolean;
  reason: string;
}

export class ClaimStore {
  private readonly table: string;
  constructor(private readonly db: PluginDatabaseClient) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Claim namespace does not match the packaged migration");
    this.table = `"${db.namespace}".card_claims`;
  }

  async acquire(input: DeliveryInput, token: string): Promise<boolean> {
    const result = await this.db.execute(
      `INSERT INTO ${this.table} (company_id, origin_id, state, claim_token, origin_kind)
       VALUES ($1, $2, 'reserved', $3, $4) ON CONFLICT (company_id, origin_id) DO NOTHING`,
      [input.companyId, input.originId, token, input.originKind ?? FINDING_ORIGIN_KIND],
    );
    return result.rowCount === 1;
  }

  async read(input: Pick<DeliveryInput, "companyId" | "originId">): Promise<Claim | null> {
    const rows = await this.db.query<Claim>(
      `SELECT * FROM ${this.table} WHERE company_id = $1 AND origin_id = $2`,
      [input.companyId, input.originId],
    );
    return rows[0] ?? null;
  }

  async change(
    input: DeliveryInput, token: string, from: ClaimState,
    patch: Partial<Pick<Claim, "state" | "claim_token" | "issue_id" | "advisory_modified"
      | "attempt_count" | "last_error" | "recovery_audit" | "published_revision" | "published_sha256">>,
  ): Promise<boolean> {
    const entries = Object.entries(patch);
    const fields = new Set(["state", "claim_token", "issue_id", "advisory_modified", "attempt_count", "last_error", "recovery_audit",
      "published_revision", "published_sha256"]);
    if (!entries.length || entries.some(([field]) => !fields.has(field))) throw new Error("Invalid claim patch");
    const assignments = entries.map(([field], i) => `${field} = $${i + 5}`).join(", ");
    const values = entries.map(([field, value]) => field === "recovery_audit" ? JSON.stringify(value) : value);
    const result = await this.db.execute(
      `UPDATE ${this.table} SET ${assignments}
       WHERE company_id = $1 AND origin_id = $2 AND claim_token = $3 AND state = $4`,
      [input.companyId, input.originId, token, from, ...values],
    );
    return result.rowCount === 1;
  }
}

const timestamp = (value: string | null) => value === null ? NaN : Date.parse(value);
const originKind = (input: DeliveryInput) => input.originKind ?? FINDING_ORIGIN_KIND;
const publication = (input: DeliveryInput) => ({
  published_revision: input.publicationRevision ?? null,
  published_sha256: input.publicationRevision === undefined ? null : sha256(canonicalJson({
    projectId: input.projectId, title: input.title, description: input.description, priority: input.priority,
    reopenUnresolved: input.reopenUnresolved ?? false,
  })),
});
function validate(input: DeliveryInput): void {
  if (!/^[a-f0-9]{64}$/.test(input.originId)) throw new Error("Expected a delivery origin hash");
  if (![FINDING_ORIGIN_KIND, WEEKLY_ORIGIN_KIND].includes(originKind(input))) throw new Error("Unknown delivery origin kind");
  if (input.publicationRevision !== undefined && (!Number.isInteger(input.publicationRevision)
    || input.publicationRevision <= 0 || input.publicationRevision > 2147483646)) throw new Error("Invalid publication revision");
  if (originKind(input) === WEEKLY_ORIGIN_KIND && input.publicationRevision === undefined) {
    throw new Error("Weekly delivery requires a monotonic publication revision");
  }
}

/** No polling, create retry, lease expiry, or automatic stale ownership transfer. */
export class CardDelivery {
  constructor(
    private readonly claims: ClaimStore,
    private readonly issues: IssuePort,
    private readonly deadlineMs = 240_000,
  ) {}

  private result(status: DeliveryResult["status"], claim: Claim | null, reason: string): DeliveryResult {
    return {
      status, issueId: claim?.issue_id ?? null, claimToken: claim?.claim_token ?? null, reason,
      needsReconciliation: status === "delivery_unknown" || status === "quarantined"
        || (claim !== null && status === "pending" && Date.now() - Date.parse(claim.claimed_at) >= 30 * 60000),
    };
  }

  private budget() {
    const until = Date.now() + this.deadlineMs;
    return async <T>(operation: () => Promise<T>): Promise<T> => {
      const remaining = until - Date.now();
      if (remaining <= 0) throw new Error("Delivery deadline");
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          operation(),
          new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Delivery deadline")), remaining); }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
  }

  private async lookup(input: DeliveryInput, call: ReturnType<CardDelivery["budget"]>): Promise<IssueSummary[]> {
    const issues = await call(() => this.issues.list({
      companyId: input.companyId, originKind: originKind(input), originId: input.originId, limit: 2,
    }));
    if (issues.some(issue => issue.companyId !== input.companyId || issue.originId !== input.originId
      || issue.originKind !== originKind(input))) throw new Error("Inconsistent origin lookup");
    return issues;
  }

  private async unknown(input: DeliveryInput, claim: Claim | null, phase: string): Promise<DeliveryResult> {
    if (claim) {
      try {
        const current = await this.claims.read(input);
        if (current?.claim_token === claim.claim_token && current.state !== "linked" && current.state !== "quarantined") {
          await this.claims.change(input, current.claim_token, current.state, { state: "indeterminate", last_error: phase });
        }
      } catch { /* The durable row still fences every later caller, even when this write is lost. */ }
    }
    return this.result("delivery_unknown", claim, `${phase}; reconcile execution and settled host effects before retry`);
  }

  async ensure(input: DeliveryInput): Promise<DeliveryResult> {
    validate(input);
    const token = randomUUID();
    const call = this.budget();
    let claim: Claim | null = null;
    try {
      // A lost insert response must be resolved by reading our exact durable token.
      try { await call(() => this.claims.acquire(input, token)); } catch { /* read ownership below */ }
      claim = await call(() => this.claims.read(input));
      if (!claim) return this.result("delivery_unknown", null, "Claim ownership could not be established");
      if (claim.origin_kind !== originKind(input)) return this.result("delivery_unknown", claim, "Claim origin kind mismatch; no effect permitted");
      if (claim.state === "linked") return await this.refresh(input, claim, call);
      if (claim.state === "quarantined") return this.result("quarantined", claim, "Existing origin collision");
      if (claim.claim_token !== token || claim.state !== "reserved") {
        return this.result(claim.state === "indeterminate" ? "delivery_unknown" : "pending", claim,
          "Prior attempt fenced; age never grants another create attempt");
      }
      return await this.owned(input, claim, call);
    } catch {
      return this.unknown(input, claim, "Uncertain delivery operation");
    }
  }

  private async owned(input: DeliveryInput, claim: Claim, call: ReturnType<CardDelivery["budget"]>): Promise<DeliveryResult> {
    const existing = await this.lookup(input, call);
    if (existing.length > 1) return await this.quarantine(input, claim);
    if (existing.length === 1) {
      if (!await call(() => this.claims.change(input, claim.claim_token, "reserved", {
        state: "linked", issue_id: existing[0]!.id,
      }))) return this.unknown(input, claim, "Existing issue link not confirmed");
      return await this.refresh(input, { ...claim, state: "linked", issue_id: existing[0]!.id }, call);
    }
    if (!await call(() => this.claims.change(input, claim.claim_token, "reserved", {
      state: "creating", attempt_count: claim.attempt_count + 1,
    }))) return this.unknown(input, claim, "Creating transition not confirmed");
    claim = { ...claim, state: "creating" };
    const current = await call(() => this.claims.read(input));
    if (current?.claim_token !== claim.claim_token || current.state !== "creating") {
      return this.unknown(input, claim, "Creating ownership changed");
    }
    // The SDK has no idempotency key. Exactly one call; a timeout cannot cancel a host commit.
    const issue = await call(() => this.issues.create({
      companyId: input.companyId, projectId: input.projectId, title: input.title,
      description: input.description, priority: input.priority, status: "todo",
      originKind: originKind(input), originId: input.originId,
    }));
    if (!issue.id || issue.companyId !== input.companyId || issue.originId !== input.originId
      || issue.originKind !== originKind(input)) return this.unknown(input, claim, "Create response inconsistent");
    if (!await call(() => this.claims.change(input, claim.claim_token, "creating", {
      state: "linked", issue_id: issue.id, advisory_modified: input.advisoryModified, ...publication(input),
    }))) return this.unknown(input, claim, "Create succeeded but link not confirmed");
    return this.result("created", { ...claim, issue_id: issue.id }, "Created unassigned report-only finding");
  }

  private async quarantine(input: DeliveryInput, claim: Claim): Promise<DeliveryResult> {
    await this.claims.change(input, claim.claim_token, claim.state, {
      state: "quarantined", last_error: "Multiple issues share the exact origin; no automatic deletion",
    });
    return this.result("quarantined", claim, "Multiple issues share the exact origin; operator reconciliation required");
  }

  private async refresh(input: DeliveryInput, claim: Claim, call: ReturnType<CardDelivery["budget"]>): Promise<DeliveryResult> {
    const existing = await this.lookup(input, call);
    if (existing.length > 1) return await this.quarantine(input, claim);
    const issue = existing[0];
    if (!issue || issue.id !== claim.issue_id) return this.result("delivery_unknown", claim, "Linked issue missing or inconsistent; never recreate");
    const closed = issue.status === "done" || issue.status === "cancelled";
    if (input.publicationRevision !== undefined) {
      if (claim.published_revision !== null && input.publicationRevision < claim.published_revision) {
        return this.result("reused", claim, "Older container revision cannot overwrite or reopen the current publication");
      }
      if (input.publicationRevision === claim.published_revision) {
        if (publication(input).published_sha256 !== claim.published_sha256) {
          return this.result("delivery_unknown", claim, "Conflicting content for the same container revision");
        }
        if (!closed || !input.reopenUnresolved) return this.result("reused", claim, "Unchanged container revision");
        // External closure is not member remediation. Reopen the same container only.
      }
    } else {
      if (claim.published_revision !== null) return this.result("delivery_unknown", claim, "Versioned publication requires a container revision");
      const modified = timestamp(input.advisoryModified);
      if (!Number.isFinite(modified) || modified <= timestamp(claim.advisory_modified)
        || input.advisoryModified === claim.advisory_modified) return this.result("reused", claim, "Unchanged, old, or unavailable advisory revision");
    }
    const token = randomUUID();
    if (!await call(() => this.claims.change(input, claim.claim_token, "linked", { state: "refreshing", claim_token: token }))) {
      return this.result("pending", claim, "Another caller is refreshing the linked issue");
    }
    claim = { ...claim, state: "refreshing", claim_token: token };
    try {
      const updated = await call(() => this.issues.update(issue.id, {
        title: input.title, description: input.description, priority: input.priority,
        ...(closed ? { status: "todo" as const } : {}),
      }, input.companyId));
      if (updated.id !== issue.id || updated.companyId !== input.companyId
        || updated.originKind !== originKind(input) || updated.originId !== input.originId
        || (closed && updated.status !== "todo")) {
        return this.unknown(input, claim, "Issue refresh response inconsistent");
      }
      if (!await call(() => this.claims.change(input, token, "refreshing", {
        state: "linked", advisory_modified: input.advisoryModified, ...publication(input),
      }))) return this.unknown(input, claim, "Refresh link not confirmed");
      return this.result(closed ? "reopened" : "updated", claim,
        input.publicationRevision === undefined ? "Refreshed existing issue for a newer advisory revision"
          : "Published container revision; external closure never certifies member remediation");
    } catch {
      return this.unknown(input, claim, "Issue refresh uncertain");
    }
  }

  /** Lookup may relink a definitive issue; an empty lookup alone never permits creation. */
  async reconcile(
    input: DeliveryInput,
    verifySettled?: (claim: Claim) => Promise<RecoveryProof | null>,
  ): Promise<DeliveryResult> {
    validate(input);
    const call = this.budget();
    let claim: Claim | null = null;
    try {
      claim = await call(() => this.claims.read(input));
      if (!claim) return this.result("delivery_unknown", null, "No durable claim to reconcile");
      if (claim.origin_kind !== originKind(input)) return this.result("delivery_unknown", claim, "Claim origin kind mismatch; no effect permitted");
      if (claim.state === "linked") return await this.refresh(input, claim, call);
      if (claim.state === "quarantined") return this.result("quarantined", claim, "Collision requires operator reconciliation");
      const existing = await this.lookup(input, call);
      if (existing.length > 1) return await this.quarantine(input, claim);
      if (existing.length === 1) {
        const issueId = existing[0]!.id;
        let recovery = {};
        if (claim.issue_id) {
          if (claim.issue_id !== issueId) return this.result("delivery_unknown", claim, "Linked issue mismatch; never replace");
          // A visible issue proves a create committed, not that an update has settled.
          const proof = verifySettled ? await call(() => verifySettled(claim!)) : null;
          if (!proof || proof.previousClaimToken !== claim.claim_token || !proof.terminalExecutionReceipt
            || !proof.settledHostEffectsReceipt || !proof.auditRef) {
            return this.result("delivery_unknown", claim, "In-flight refresh requires terminal execution AND settled host effects");
          }
          recovery = { recovery_audit: [...(claim.recovery_audit ?? []), proof] };
        }
        const token = randomUUID();
        if (!await call(() => this.claims.change(input, claim!.claim_token, claim!.state, {
          state: "linked", issue_id: issueId, claim_token: token, ...recovery,
        }))) return this.unknown(input, claim, "Reconciliation link not confirmed");
        return await this.refresh(input, { ...claim, state: "linked", issue_id: issueId, claim_token: token }, call);
      }
      if (claim.issue_id) return this.result("delivery_unknown", claim, "Missing linked issue; no replacement is permitted");
      // The verifier must independently establish both receipts. No runtime endpoint exposes this yet.
      const proof = verifySettled ? await call(() => verifySettled(claim!)) : null;
      if (!proof || proof.previousClaimToken !== claim.claim_token || !proof.terminalExecutionReceipt
        || !proof.settledHostEffectsReceipt || !proof.auditRef) {
        return this.result("delivery_unknown", claim, "No proof of terminal execution AND settled host effects");
      }
      const token = randomUUID();
      if (!await call(() => this.claims.change(input, claim!.claim_token, claim!.state, {
        state: "reserved", claim_token: token, last_error: null,
        recovery_audit: [...(claim!.recovery_audit ?? []), proof],
      }))) return this.unknown(input, claim, "Recovery ownership not confirmed");
      claim = { ...claim, state: "reserved", claim_token: token };
      return await this.owned(input, claim, call);
    } catch {
      return this.unknown(input, claim, "Reconciliation uncertain");
    }
  }
}
