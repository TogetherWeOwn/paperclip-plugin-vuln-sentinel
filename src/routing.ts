import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE, FINDING_ORIGIN_KIND, WEEKLY_ORIGIN_KIND } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { DecisionJournal } from "./journal.js";
import type { Decision, FindingInput, Priority, SourceSelection } from "./model.js";
import { sourceFence, sourceSelection } from "./source-fence.js";
import { SourceAttention } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { rescanEvidenceId, rescanRejection } from "./rescan.js";
import type { RescanEvidence, ResolutionRecord } from "./rescan.js";

export { WEEKLY_ORIGIN_KIND } from "./claims.js";
const DAY = 86400000;

export interface RoutingMember {
  findingId: string;
  identityKeys: string[];
  aliases: string[];
  ecosystem: FindingInput["ecosystem"];
  package: string;
  remediationUnit: string;
  currentOriginId: string;
  decisionId: string;
  sourceSelection?: SourceSelection;
  observedAt: string | null;
  firstObservedAt: string;
  artifactDigest: string;
  advisoryModified: string | null;
  applicability: Decision["applicability"];
  priority: Priority;
  deadlineAt: string;
  state: "unresolved" | "superseded" | "resolved";
  // Optional for existing version-1 rows; history is retained after reopening.
  resolutions?: ResolutionRecord[];
  deliveryOrigin: string | null;
  weeklyEligibleAt: string | null;
  originalWeek: string | null;
  predecessorId: string | null;
  successorIds: string[];
  relationshipEvidenceRef: string | null;
}

export interface RoutingContainer {
  originId: string;
  originKind: typeof FINDING_ORIGIN_KIND | typeof WEEKLY_ORIGIN_KIND;
  weekStart: string | null;
  memberIds: string[];
  revision: number;
  priority: Priority;
  deadlineAt: string;
  urgent: boolean;
  publishRequested: boolean;
}

export interface RoutingSnapshot {
  version: 1;
  members: RoutingMember[];
  containers: RoutingContainer[];
  attention: Array<{ decisionId: string; originId: string; reason: string }>;
  rescanHolds?: Array<ResolutionRecord & { reason: string }>;
}

export type RemediationRelationship =
  | { kind: "replacement"; predecessorId: string; evidenceRef: string }
  | { kind: "independent"; evidenceRef: string };

export interface RoutingResult {
  status: "recorded" | "reused" | "attention";
  findingId: string | null;
  container: RoutingContainer | null;
  reason: string;
}

interface Row { revision: number; bundle: RoutingSnapshot }

export function utcWeekStart(value: string): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new Error("Expected a valid weekly observation timestamp");
  const date = new Date(time);
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() - (date.getUTCDay() + 6) % 7);
  return date.toISOString();
}

export function weeklyOrigin(companyId: string, canonicalRepo: string, weekStart: string): string {
  if (!companyId || canonicalRepo !== canonicalRepo.toLowerCase()
    || !/^[\w.-]+\/[\w.-]+$/.test(canonicalRepo) || utcWeekStart(weekStart) !== weekStart) {
    throw new Error("Expected a company, canonical repository and UTC Monday bucket");
  }
  // An explicit versioned domain and JSON tuple prevent member or delimiter collisions.
  return sha256(canonicalJson([WEEKLY_ORIGIN_KIND, companyId, canonicalRepo, weekStart]));
}

const empty = (): RoutingSnapshot => ({ version: 1, members: [], containers: [], attention: [] });
const intersects = (a: string[], b: string[]) => a.some(value => b.includes(value));
const earlier = (a: string, b: string) => Date.parse(a) <= Date.parse(b) ? a : b;
const validTime = (value: string) => /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value));
const newer = (observedAt: string | null, decisionId: string, member: RoutingMember, selection?: SourceSelection) => {
  if (selection?.pollRevision !== member.sourceSelection?.pollRevision) {
    return (selection?.pollRevision ?? -1) > (member.sourceSelection?.pollRevision ?? -1);
  }
  const next = observedAt === null ? -Infinity : Date.parse(observedAt);
  const prior = member.observedAt === null ? -Infinity : Date.parse(member.observedAt);
  return next > prior || (next === prior && decisionId > member.decisionId);
};

function outcome(snapshot: RoutingSnapshot, member: RoutingMember | null, status: RoutingResult["status"], reason: string): RoutingResult {
  return {
    status, findingId: member?.findingId ?? null,
    container: snapshot.containers.find(item => item.originId === member?.deliveryOrigin) ?? null,
    reason,
  };
}

function attention(snapshot: RoutingSnapshot, decision: Decision, decisionId: string, reason: string): RoutingResult {
  if (!snapshot.attention.some(item => item.decisionId === decisionId && item.reason === reason)) {
    snapshot.attention.push({ decisionId, originId: decision.identity.originId, reason });
  }
  return outcome(snapshot, null, "attention", reason);
}

function touch(snapshot: RoutingSnapshot, member: RoutingMember): void {
  const container = snapshot.containers.find(item => item.originId === member.deliveryOrigin);
  if (!container) return;
  container.revision++;
  // Never extend an earlier container deadline, including on de-escalation/supersession.
  container.deadlineAt = earlier(container.deadlineAt, member.deadlineAt);
  container.priority = Math.min(container.priority, member.priority) as Priority;
  if (member.state === "unresolved" && member.priority === 0) {
    container.urgent = true;
    container.publishRequested = true;
  }
}

function route(
  snapshot: RoutingSnapshot, companyId: string, input: FindingInput, decision: Decision,
  decisionId: string, persistedAt: string, relationship?: RemediationRelationship,
): RoutingResult {
  const identity = decision.identity;
  const observedAt = validTime(input.provenance.observedAt) ? input.provenance.observedAt : null;
  const exact = snapshot.members.find(item => item.identityKeys.includes(identity.originId));
  const sameUnit = snapshot.members.filter(item => item.remediationUnit === identity.remediationUnit
    && intersects(item.aliases, identity.aliases));
  if (sameUnit.length > 1 || (exact && sameUnit.some(item => item !== exact))) {
    return attention(snapshot, decision, decisionId, "Alias closure joins multiple existing findings; reconciliation required");
  }
  let member = exact ?? sameUnit[0];
  if (member) {
    if (member.state === "superseded" && newer(observedAt, decisionId, member, input.provenance.sourceSelection)) {
      return attention(snapshot, decision, decisionId, "Superseded action observed again; reconcile lineage rather than silently reactivate");
    }
    // Retain old keys as redirects. Never retag the original native issue or move buckets.
    const priorIdentity = canonicalJson([member.identityKeys, member.aliases]);
    if (!member.identityKeys.includes(identity.originId)) member.identityKeys.push(identity.originId);
    member.aliases = [...new Set([...member.aliases, ...identity.aliases])].sort();
    const resolution = member.resolutions?.at(-1);
    if (member.state === "resolved" && (!resolution
      || member.aliases.some(alias => !resolution.evidence.aliases.includes(alias)))) {
      member.state = "unresolved";
      touch(snapshot, member);
    }
    if (!newer(observedAt, decisionId, member, input.provenance.sourceSelection)) {
      if (priorIdentity !== canonicalJson([member.identityKeys, member.aliases])) touch(snapshot, member);
      return outcome(snapshot, member, "reused", "Same or older decision; original membership retained");
    }
    // A new finding observation may contradict the rescan, even if it arrived late.
    // Only identical/older replay above is inert; do not infer ordering from scan completion.
    if (member.state === "resolved") member.state = "unresolved";
  } else {
    const related = snapshot.members.filter(item => item.ecosystem === input.ecosystem
      && item.package === input.package && intersects(item.aliases, identity.aliases));
    const predecessor = relationship?.kind === "replacement"
      ? related.find(item => item.identityKeys.includes(relationship.predecessorId)) : undefined;
    if (related.length && (!relationship?.evidenceRef.trim()
      || (relationship.kind === "replacement" && (!predecessor || predecessor.state !== "unresolved"
        || !newer(observedAt, decisionId, predecessor, input.provenance.sourceSelection))))) {
      return attention(snapshot, decision, decisionId, "Changed remediation target needs evidenced replacement or independent-action reconciliation");
    }
    if (relationship?.kind === "replacement" && !predecessor) {
      return attention(snapshot, decision, decisionId, "Replacement predecessor does not match package and advisory lineage");
    }
    const firstObservedAt = observedAt === null ? persistedAt : earlier(observedAt, persistedAt);
    member = {
      findingId: identity.originId, identityKeys: [identity.originId], aliases: identity.aliases,
      ecosystem: input.ecosystem, package: input.package, remediationUnit: identity.remediationUnit,
      currentOriginId: identity.originId, decisionId, observedAt, firstObservedAt,
      artifactDigest: input.provenance.artifactDigest, advisoryModified: decision.advisoryModified,
      applicability: decision.applicability, priority: decision.priority,
      deadlineAt: new Date(Date.parse(firstObservedAt) + decision.slaDays * DAY).toISOString(),
      state: "unresolved", deliveryOrigin: null, weeklyEligibleAt: null, originalWeek: null,
      predecessorId: predecessor?.findingId ?? null, successorIds: [],
      relationshipEvidenceRef: relationship?.evidenceRef ?? null,
    };
    snapshot.members.push(member);
    if (predecessor) {
      predecessor.state = "superseded";
      predecessor.successorIds.push(member.findingId);
      touch(snapshot, predecessor);
    }
  }
  member.currentOriginId = identity.originId;
  member.decisionId = decisionId;
  if (input.provenance.sourceSelection) member.sourceSelection = input.provenance.sourceSelection;
  member.observedAt = observedAt;
  member.artifactDigest = input.provenance.artifactDigest;
  member.advisoryModified = decision.advisoryModified;
  member.applicability = decision.applicability;
  member.priority = decision.priority;
  member.deadlineAt = earlier(member.deadlineAt,
    new Date(Date.parse(member.firstObservedAt) + decision.slaDays * DAY).toISOString());
  // Negative applicability remains a proposal, never a remediation state or closure.
  if (member.state === "unresolved" && !member.deliveryOrigin && decision.delivery !== "none") {
    const weekly = decision.delivery === "weekly";
    const weekStart = weekly ? utcWeekStart(persistedAt) : null;
    const originId = weekStart ? weeklyOrigin(companyId, identity.repo, weekStart) : member.findingId;
    let container = snapshot.containers.find(item => item.originId === originId);
    if (!container) {
      container = {
        originId, originKind: weekly ? WEEKLY_ORIGIN_KIND : FINDING_ORIGIN_KIND,
        weekStart, memberIds: [], revision: 0, priority: member.priority, deadlineAt: member.deadlineAt,
        urgent: false, publishRequested: !weekly,
      };
      snapshot.containers.push(container);
    }
    container.memberIds.push(member.findingId);
    member.deliveryOrigin = originId;
    member.weeklyEligibleAt = weekly ? persistedAt : null;
    member.originalWeek = weekStart;
  }
  touch(snapshot, member);
  return outcome(snapshot, member, "recorded", "Decision persisted; delivery membership is durable, no host effect performed");
}

/** Bounded pilot routing aggregate. CAS covers membership, redirects and lineage together. */
export class DeliveryRouting {
  private readonly table: string;
  private readonly journal: DecisionJournal;
  constructor(private readonly db: PluginDatabaseClient, private readonly clock: () => Date = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Routing namespace does not match the packaged migration");
    this.table = `"${db.namespace}".delivery_routing`;
    this.journal = new DecisionJournal(db, clock);
  }

  async snapshot(companyId: string, repo: string): Promise<RoutingSnapshot> {
    const rows = await this.db.query<Row>(
      `SELECT revision, bundle FROM ${this.table} WHERE company_id = $1 AND repo = $2`, [companyId, repo],
    );
    return rows[0]?.bundle ?? empty();
  }

  async observe(companyId: string, input: FindingInput, relationship?: RemediationRelationship): Promise<RoutingResult> {
    // Decisions survive a routing crash, and replay repairs the routing projection.
    const recorded = await this.journal.record(companyId, input);
    const latest = await this.journal.latest(companyId, recorded.decision.identity.originId);
    if (!latest) throw new Error("Decision history not readable; no delivery routing permitted");
    if (latest.input_bundle.provenance.sourceSelection) throw new SourceAttention("source_selection_requires_fenced_write");
    const persistedAt = this.clock().toISOString();
    const repo = latest.decision_bundle.identity.repo;
    return this.update(companyId, repo, snapshot => {
      if (snapshot.members.some(member => member.sourceSelection)) throw new SourceAttention("source_selection_requires_fenced_write");
      return route(snapshot, companyId, latest.input_bundle, latest.decision_bundle, latest.decision_id, persistedAt, relationship);
    });
  }

  /** Current lockfile decisions and routing are independently source-fenced; replay repairs a gap between them. */
  async observeCurrent(selection: CurrentSource, input: FindingInput, relationship?: RemediationRelationship): Promise<RoutingResult> {
    const selected = structuredClone(selection);
    const recorded = await this.journal.recordCurrent(selected, input);
    const latest = await this.journal.latest(selected.companyId, recorded.decision.identity.originId);
    if (!latest || canonicalJson(latest.input_bundle.provenance.sourceSelection) !== canonicalJson(sourceSelection(selected))) {
      throw new SourceAttention("current_decision_source_mismatch");
    }
    const persistedAt = this.clock().toISOString();
    return this.update(selected.companyId, selected.source.repo, snapshot => route(snapshot, selected.companyId,
      latest.input_bundle, latest.decision_bundle, latest.decision_id, persistedAt, relationship), selected);
  }

  /** Record member resolution only; this report-only API never closes a native issue. */
  async applyRescan(companyId: string, repo: string, receipt: RescanEvidence): Promise<RoutingResult> {
    const evidence = structuredClone(receipt);
    const evidenceId = rescanEvidenceId(evidence);
    const recordedAt = this.clock().toISOString();
    return this.update(companyId, repo, async snapshot => {
      const member = snapshot.members.find(item => item.findingId === evidence.findingId);
      // A replay after reopening must not reactivate a historical resolution.
      if (member?.resolutions?.some(item => item.evidenceId === evidenceId)) {
        return outcome(snapshot, member, "reused", "Rescan already recorded; current member state retained");
      }
      let reason: string | null = null;
      if (evidence.companyId !== companyId || evidence.repo !== repo) {
        reason = "Rescan company or repository binding does not match";
      } else if (!member || member.state !== "unresolved") {
        reason = "Rescan needs a current unresolved member; supersession is not remediation";
      } else {
        const record = await this.journal.read(companyId, member.currentOriginId, member.decisionId);
        if (!record || record.company_id !== companyId || record.origin_id !== member.currentOriginId
          || record.decision_id !== member.decisionId || record.decision_bundle.identity.repo !== repo
          || record.input_sha256 !== sha256(canonicalJson(record.input_bundle))
          || record.decision_bundle.inputSha256 !== record.input_sha256
          || record.input_bundle.provenance.artifactDigest !== member.artifactDigest) {
          reason = "Current member decision evidence is missing or inconsistent";
        } else {
          reason = rescanRejection(member, record.input_bundle, evidence, recordedAt);
        }
      }
      if (reason) {
        snapshot.rescanHolds ??= [];
        if (!snapshot.rescanHolds.some(item => item.evidenceId === evidenceId)) {
          snapshot.rescanHolds.push({ evidenceId, evidence, recordedAt, reason });
        }
        return outcome(snapshot, member ?? null, "attention", reason);
      }
      if (!member) throw new Error("Missing validated rescan member");
      member.resolutions ??= [];
      member.resolutions.push({ evidenceId, evidence, recordedAt });
      member.state = "resolved";
      touch(snapshot, member);
      return outcome(snapshot, member, "recorded", "Complete new-artifact rescan resolved only this member; no host closure performed");
    });
  }

  private async update(
    companyId: string, repo: string, reduce: (snapshot: RoutingSnapshot) => RoutingResult | Promise<RoutingResult>,
    selected?: CurrentSource,
  ): Promise<RoutingResult> {
    if (!companyId || !/^[\w.-]+\/[\w.-]+$/.test(repo) || repo !== repo.toLowerCase()) {
      throw new Error("Expected a company and canonical repository");
    }
    await this.db.execute(
      `INSERT INTO ${this.table} (company_id, repo, bundle) VALUES ($1, $2, $3)
       ON CONFLICT (company_id, repo) DO NOTHING`, [companyId, repo, canonicalJson(empty())],
    );
    for (let attempt = 0; attempt < 32; attempt++) {
      const rows = await this.db.query<Row>(
        `SELECT revision, bundle FROM ${this.table} WHERE company_id = $1 AND repo = $2`, [companyId, repo],
      );
      const row = rows[0];
      if (!row || row.revision >= 2147483646) throw new Error("Routing revision unavailable; operator attention required");
      const snapshot = structuredClone(row.bundle);
      const result = await reduce(snapshot);
      const bundle = canonicalJson(snapshot);
      if (bundle === canonicalJson(row.bundle)) {
        if (selected) await new SourcePollStore(this.db, this.clock).assertCurrent(selected);
        return result;
      }
      if (snapshot.members.length > 2000 || Buffer.byteLength(bundle) > 1048576) {
        throw new Error("Pilot routing capacity exceeded; evidence retained, no delivery effect permitted");
      }
      const fence = selected ? sourceFence(selected, 5) : null;
      const updated = await this.db.execute(
        `UPDATE ${this.table} SET bundle = $4, revision = revision + 1
         WHERE company_id = $1 AND repo = $2 AND revision = $3${fence ? ` AND ${fence.sql}` : ""}`,
        [companyId, repo, row.revision, bundle, ...(fence?.params ?? [])],
      );
      if (updated.rowCount === 1) return result;
      if (selected) await new SourcePollStore(this.db, this.clock).assertCurrent(selected);
    }
    throw new Error("Routing contention budget exhausted; replay journal without issuing host effects");
  }
}
