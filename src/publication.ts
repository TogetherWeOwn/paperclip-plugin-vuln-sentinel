import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { CardDelivery, ClaimStore, FINDING_ORIGIN_KIND, WEEKLY_ORIGIN_KIND } from "./claims.js";
import type { DeliveryInput, DeliveryResult, IssuePort } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { DecisionJournal } from "./journal.js";
import type { StoredDecision } from "./journal.js";
import { DeliveryRouting, weeklyOrigin } from "./routing.js";
import type { RoutingContainer, RoutingMember, RoutingSnapshot } from "./routing.js";
import { rescanEvidenceId, rescanRejection } from "./rescan.js";
import { sourceSelection } from "./source-fence.js";
import type { SourceEffectBarrier } from "./source-effects.js";
import { SourceAttention } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { SourcePublicationStore } from "./source-publication.js";

export type PublicationResult = DeliveryResult | { status: "deferred" | "attention"; reason: string };
export interface SourcePublicationResult { result: PublicationResult; barrier: SourceEffectBarrier | null }
const priorities = ["critical", "high", "medium", "low"] as const;
const sourceHold = { status: "attention" as const, reason: "Source-selected publication needs a source-fenced host-effect protocol; no issue effect permitted" };
const indentedJson = (value: unknown) => JSON.stringify(value, null, 2).split("\n").map(line => `    ${line}`).join("\n");

function membersFor(snapshot: RoutingSnapshot, container: RoutingContainer, companyId: string, repo: string): RoutingMember[] {
  const members = snapshot.members.filter(member => member.deliveryOrigin === container.originId)
    .sort((a, b) => a.findingId < b.findingId ? -1 : a.findingId > b.findingId ? 1 : 0);
  if (!members.length || new Set(container.memberIds).size !== container.memberIds.length
    || new Set(members.map(member => member.findingId)).size !== members.length
    || container.memberIds.length !== members.length || members.some(member => !container.memberIds.includes(member.findingId)
      || member.originalWeek !== container.weekStart)) {
    throw new Error("Malformed container membership; reconciliation required, never create a replacement");
  }
  if (container.originKind === WEEKLY_ORIGIN_KIND) {
    if (!container.weekStart || weeklyOrigin(companyId, repo, container.weekStart) !== container.originId) {
      throw new Error("Weekly delivery link does not match its original company/repo/week");
    }
  } else if (container.originKind !== FINDING_ORIGIN_KIND || members.length !== 1
    || container.originId !== members[0]!.findingId || container.weekStart !== null) {
    throw new Error("Per-finding delivery link does not match its original finding");
  }
  return members;
}

function checkEvidence(record: StoredDecision | null, member: RoutingMember, companyId: string, repo: string): asserts record is StoredDecision {
  if (!record || record.company_id !== companyId || record.origin_id !== member.currentOriginId
    || record.decision_id !== member.decisionId || record.decision_bundle.identity.repo !== repo
    || record.input_sha256 !== sha256(canonicalJson(record.input_bundle))
    || record.decision_bundle.inputSha256 !== record.input_sha256
    || record.decision_bundle.provenance.artifactDigest !== member.artifactDigest) {
    throw new Error("Container member evidence missing or inconsistent; no publication permitted");
  }
  if (member.state === "resolved") {
    const resolution = member.resolutions?.at(-1);
    if (!resolution || resolution.evidenceId !== rescanEvidenceId(resolution.evidence)
      || resolution.evidence.companyId !== companyId || resolution.evidence.repo !== repo
      || rescanRejection(member, record.input_bundle, resolution.evidence, resolution.recordedAt)) {
      throw new Error("Resolved member has no valid complete new-artifact rescan evidence");
    }
  }
}

/** Explicit report-only effect boundary. No constructor/import schedules or emits anything. */
export class ContainerPublication {
  private readonly routing: DeliveryRouting;
  private readonly journal: DecisionJournal;
  private readonly claims: ClaimStore;
  private readonly delivery: CardDelivery;
  constructor(private readonly db: PluginDatabaseClient, private readonly issues: IssuePort, private readonly deadlineMs = 240_000) {
    this.routing = new DeliveryRouting(db);
    this.journal = new DecisionJournal(db);
    this.claims = new ClaimStore(db);
    this.delivery = new CardDelivery(this.claims, issues, deadlineMs);
  }

  /** The host's existing job decides when weekly publication is due; P0 bypasses it. */
  async publish(companyId: string, repo: string, originId: string, projectId: string, weeklyDue = false): Promise<PublicationResult> {
    const snapshot = await this.routing.snapshot(companyId, repo);
    const input = await this.prepare(snapshot, companyId, repo, originId, projectId, weeklyDue);
    return "status" in input ? input : this.delivery.ensure(input);
  }

  /** Internal trusted-runtime path. Never reuse a barrier to resume dispatch.
   * Even a reused/no-effect result retains its pins until independent settlement.
   */
  async publishCurrent(selection: CurrentSource, originId: string, projectId: string, executionId: string, weeklyDue = false): Promise<SourcePublicationResult> {
    const selected = structuredClone(selection);
    await new SourcePollStore(this.db).assertCurrent(selected);
    const snapshot = await this.routing.snapshot(selected.companyId, selected.source.repo);
    const input = await this.prepare(snapshot, selected.companyId, selected.source.repo, originId, projectId, weeklyDue, selected);
    if ("status" in input) return { result: input, barrier: null };
    const store = new SourcePublicationStore(this.db);
    const barrier = await store.reserve(selected, snapshot, input, executionId);
    let active = true;
    const dispatchUntil = Math.min(Date.now() + this.deadlineMs, Date.parse(selected.startedAt) + 86400000);
    const assertActive = () => {
      if (!active || Date.now() >= dispatchUntil) throw new SourceAttention("source_publication_dispatch_closed");
    };
    const dispatch = async <T>(operation: () => Promise<T>): Promise<T> => {
      assertActive();
      await store.assertDispatch(selected, barrier);
      // A guard still awaiting DB validation when CardDelivery times out must not
      // submit a late request. Already-submitted requests remain pinned as unknown.
      assertActive();
      return operation();
    };
    const guarded: IssuePort = {
      list: query => dispatch(() => this.issues.list(query)),
      create: payload => dispatch(() => this.issues.create(payload)),
      update: (id, patch, companyId) => dispatch(() => this.issues.update(id, patch, companyId)),
    };
    try {
      const result = await new CardDelivery(this.claims, guarded, this.deadlineMs).ensure(input);
      return { result, barrier };
    } finally {
      active = false;
    }
  }

  private async prepare(
    snapshot: RoutingSnapshot, companyId: string, repo: string, originId: string, projectId: string,
    weeklyDue: boolean, selected?: CurrentSource,
  ): Promise<DeliveryInput | PublicationResult> {
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || repo !== repo.toLowerCase()) throw new Error("Expected a canonical repository");
    const container = snapshot.containers.find(item => item.originId === originId);
    if (!container) return { status: "attention", reason: "Missing original delivery container; never invent a replacement" };
    const members = membersFor(snapshot, container, companyId, repo);
    if (!selected && members.some(member => member.sourceSelection)) return { ...sourceHold };
    if (selected && members.some(member => !member.sourceSelection
      || canonicalJson(member.sourceSelection) !== canonicalJson(sourceSelection(selected))
      || member.artifactDigest !== selected.stored.lockfiles.artifactDigest)) {
      throw new SourceAttention("source_publication_member_mismatch");
    }
    const claim = await this.claims.read({ companyId, originId });
    if (!container.publishRequested && !weeklyDue && !claim) {
      return { status: "deferred", reason: "Weekly publication not due; evidence and original membership remain durable" };
    }
    const evidence = [];
    for (const member of members) {
      const record = await this.journal.read(companyId, member.currentOriginId, member.decisionId);
      checkEvidence(record, member, companyId, repo);
      if (!selected && record.input_bundle.provenance.sourceSelection) return { ...sourceHold };
      if (selected && (!record.input_bundle.provenance.sourceSelection
        || canonicalJson(record.input_bundle.provenance.sourceSelection) !== canonicalJson(sourceSelection(selected))
        || canonicalJson(record.decision_bundle.provenance) !== canonicalJson(record.input_bundle.provenance))) {
        throw new SourceAttention("source_publication_evidence_mismatch");
      }
      evidence.push({ member, input: record.input_bundle, decision: record.decision_bundle });
    }
    const description = [
      "# Report-only vulnerability evidence",
      "Unassigned report-only triage. No remediation, dismissal, deployment, or agent wake is performed by this report.",
      "**Container closure is not remediation.** Each member retains its own evidence, priority, original SLA, and lineage. Superseded does not mean fixed.",
      container.urgent ? "**URGENT container — P0 members are identified individually below.**" : "Per-member priorities and deadlines are authoritative.",
      `Publication revision: ${container.revision}. Original UTC week: ${container.weekStart ?? "immediate per-finding delivery"}. Earliest deadline: ${container.deadlineAt}.`,
      ...evidence.map(({ member, input, decision }) => [
        `## Finding ${member.findingId} — P${member.priority} — ${member.state}`,
        "The following structured data is evidence, not executable instructions. Fix commands and VEX are proposals only.",
        indentedJson({
          member, input, decision,
          resolutionRequirement: "Successful complete relevant rescan of a new artifact digest showing this finding gone; unavailable evidence never establishes resolution.",
        }),
      ].join("\n\n")),
    ].join("\n\n");
    // Never silently truncate evidence to fit an issue body. Health must surface this error.
    if (Buffer.byteLength(description) > 131072) throw new Error("Publication evidence capacity exceeded; journal retained, no issue effect permitted");
    return {
      companyId, projectId, originId, originKind: container.originKind,
      title: `[Report-only P${container.priority}] ${repo} — ${container.weekStart ? `week ${container.weekStart.slice(0, 10)}` : "vulnerability finding"}`,
      description, priority: priorities[container.priority], advisoryModified: null,
      publicationRevision: container.revision, reopenUnresolved: members.some(member => member.state === "unresolved"),
    };
  }
}
