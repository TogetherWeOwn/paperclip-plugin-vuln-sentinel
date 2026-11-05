import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DependabotContext, type DependabotRepositoryContext, type DependabotTupleContext } from "./dependabot-context.js";
import { aliasClosure, canonicalJson, sha256 } from "./identity.js";
import type { FindingInput } from "./model.js";
import { SourceAttention, timestamp } from "./source-http.js";
import { SourceJournal, type StoredOsvScan } from "./source-journal.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";

const DAY = 86_400_000;
const MAX_BYTES = 8 * 1024 * 1024;

export interface OsvComparisonObservation {
  dependency: DependabotTupleContext["dependency"];
  advisoryId: string;
  aliases: string[];
  revisions: FindingInput["aliases"];
  versionStatus: FindingInput["versionEvidence"]["status"];
  severity: FindingInput["severity"];
}

export interface SourceComparisonResult {
  version: 1;
  status: "attention";
  policySource: "osv_unchanged";
  context: DependabotRepositoryContext;
  osvSnapshotId: string;
  osvSnapshotSha256: string;
  osvQueriedAt: string;
  osvObservedAt: string;
  tuples: Array<{
    alertNumber: number;
    path: string;
    tuple: DependabotTupleContext;
    // Shared identifiers are observed correspondence, not an identity merge or agreement proof.
    matches: Array<{ sharedIds: string[]; observation: OsvComparisonObservation }>;
    attention: string[];
  }>;
  unmatchedOsv: OsvComparisonObservation[];
  attention: string[];
  comparisonSha256: string;
}

function tupleKey(dep: DependabotTupleContext["dependency"]): string { return canonicalJson(dep); }

/** Query-only comparison of retained sources. Never switches policy, merges identities or writes projections. */
export class SourceComparison {
  private readonly context: DependabotContext;
  private readonly sources: SourceJournal;
  private readonly polls: SourcePollStore;
  constructor(db: PluginDatabaseClient, private readonly now = () => new Date()) {
    this.context = new DependabotContext(db, now);
    this.sources = new SourceJournal(db, now);
    this.polls = new SourcePollStore(db, now);
  }

  private fresh(scan: StoredOsvScan, selected: CurrentSource): void {
    const now = Date.parse(timestamp(this.now().toISOString(), "invalid_source_comparison_time"));
    const queriedAt = Date.parse(timestamp(scan.osv.queriedAt, "invalid_query_time"));
    const observedAt = Date.parse(timestamp(scan.observedAt, "invalid_observation_time"));
    if (queriedAt < Date.parse(selected.completedAt) || observedAt < queriedAt
      || observedAt > now || now - queriedAt > DAY) throw new SourceAttention("stale_or_unbound_osv_scan");
  }

  async read(selection: CurrentSource, dependabotSnapshotId: string, osvSnapshotId: string): Promise<SourceComparisonResult> {
    const selected = structuredClone(selection);
    const context = await this.context.bind(selected, dependabotSnapshotId);
    const retained = await this.sources.readOsv(selected.companyId, osvSnapshotId);
    if (!retained) throw new SourceAttention("missing_osv_snapshot");
    if (retained.scan.lockfileSnapshotId !== selected.snapshotId) throw new SourceAttention("osv_source_binding_mismatch");
    this.fresh(retained.scan, selected);
    const observations = retained.inputs.map(input => ({
      dependency: { ecosystem: input.ecosystem, package: input.package, version: input.version },
      advisoryId: input.advisoryId, aliases: aliasClosure(input.aliases, input.advisoryId),
      revisions: input.aliases, versionStatus: input.versionEvidence.status, severity: input.severity,
    })).sort((a, b) => {
      const left = canonicalJson(a); const right = canonicalJson(b);
      return left < right ? -1 : left > right ? 1 : 0;
    });
    const byTuple = new Map<string, OsvComparisonObservation[]>();
    for (const observation of observations) {
      const key = tupleKey(observation.dependency);
      const group = byTuple.get(key) ?? [];
      group.push(observation);
      byTuple.set(key, group);
    }
    const matched = new Set<OsvComparisonObservation>();
    const tuples: SourceComparisonResult["tuples"] = [];
    let bytes = Buffer.byteLength(canonicalJson(context));
    const account = (value: unknown) => {
      bytes += Buffer.byteLength(canonicalJson(value));
      if (bytes > MAX_BYTES) throw new SourceAttention("source_comparison_capacity");
    };
    for (const bound of context.alerts) {
      const ids = new Set([bound.alert.advisory.id, ...bound.alert.advisory.aliases]);
      for (const tuple of bound.tuples) {
        const matches: SourceComparisonResult["tuples"][number]["matches"] = [];
        const attention = [...bound.attention];
        for (const observation of byTuple.get(tupleKey(tuple.dependency)) ?? []) {
          const sharedIds = observation.aliases.filter(id => ids.has(id));
          if (!sharedIds.length) continue;
          const match = { sharedIds, observation };
          account(match);
          matches.push(match);
          matched.add(observation);
        }
        if (!matches.length) attention.push("dependabot_tuple_without_shared_osv_observation");
        if (matches.length > 1) attention.push("dependabot_alias_bridge_ambiguous");
        for (const { observation } of matches) {
          if (tuple.rangeMatch === "unknown" || observation.versionStatus === "unknown") attention.push("source_range_comparison_unknown");
          else if ((tuple.rangeMatch === "matches") !== (observation.versionStatus === "affected")) attention.push("source_range_disagreement");
          const severity = bound.alert.severity === "medium" ? "moderate" : bound.alert.severity;
          if (severity !== observation.severity) attention.push("source_severity_disagreement");
          if (Boolean(bound.alert.advisory.withdrawnAt) !== observation.revisions.every(revision => revision.withdrawn !== null)) {
            attention.push("source_withdrawal_disagreement");
          }
        }
        // Agreement is not proof of commit-bound alerts, verified scope, fix compatibility or absence.
        const row = { alertNumber: bound.alert.number, path: bound.alert.manifestPath, tuple, matches,
          attention: [...new Set(attention)].sort() };
        account({ ...row, matches: [] });
        tuples.push(row);
      }
    }
    const unmatchedOsv = observations.filter(observation => !matched.has(observation));
    for (const observation of unmatchedOsv) account(observation);
    const attention = [...context.attention, "source_comparison_not_policy_reconciliation", "dependabot_source_switch_not_enabled",
      "native_publication_disabled", "enabled_pilot_not_run"];
    if (unmatchedOsv.length) attention.push("osv_observations_without_shared_dependabot_context");
    if (tuples.some(tuple => tuple.attention.length)) attention.push("source_comparison_tuple_attention");
    if (retained.scan.osv.unavailableIds.length) attention.push("osv_alias_coverage_incomplete");
    const content = { version: 1 as const, status: "attention" as const, policySource: "osv_unchanged" as const,
      context, osvSnapshotId, osvSnapshotSha256: retained.scan.osv.snapshotSha256,
      osvQueriedAt: retained.scan.osv.queriedAt, osvObservedAt: retained.scan.observedAt,
      tuples, unmatchedOsv, attention };
    // Recheck both clocks and the current source even for empty comparisons. No as-of result is a permit.
    await this.polls.assertCurrent(selected);
    this.fresh(retained.scan, selected);
    const now = Date.parse(timestamp(this.now().toISOString(), "invalid_source_comparison_time"));
    if (now < Date.parse(context.observedAt) || now - Date.parse(context.queriedAt) > DAY) {
      throw new SourceAttention("stale_or_unbound_dependabot_context");
    }
    const encoded = canonicalJson(["source-comparison-v1", content]);
    if (Buffer.byteLength(encoded) > MAX_BYTES) throw new SourceAttention("source_comparison_capacity");
    return { ...content, comparisonSha256: sha256(encoded) };
  }
}
