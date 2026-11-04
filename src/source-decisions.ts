import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { findingIdentity } from "./identity.js";
import type { LockfileInventory } from "./inventory.js";
import { DeliveryRouting, type RoutingResult } from "./routing.js";
import { SourceJournal, type StoredOsvScan } from "./source-journal.js";
import { SourceAttention, timestamp } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { assertThreatFreshness, enrichThreatInputs, type ThreatSnapshot } from "./threat-feeds.js";
import { ThreatJournal } from "./threat-journal.js";

const DAY = 86_400_000;

export interface SourceDecisionResult {
  // Coverage gaps are not a successful complete scan, even when there are no inputs.
  status: "attention";
  lockfileSnapshotId: string;
  osvSnapshotId: string;
  threatSnapshotId: string;
  inventory: LockfileInventory;
  attention: string[];
  counters: { dependencies: number; observations: number; decisions: number; routingAttention: number };
  results: RoutingResult[];
}

/** Retained evidence to local projections only; no HTTP, publication or resolution. */
export class SourceDecisions {
  private readonly sources: SourceJournal;
  private readonly threats: ThreatJournal;
  private readonly polls: SourcePollStore;
  private readonly routing: DeliveryRouting;
  constructor(db: PluginDatabaseClient, private readonly now = () => new Date()) {
    this.sources = new SourceJournal(db, now);
    this.threats = new ThreatJournal(db);
    this.polls = new SourcePollStore(db, now);
    this.routing = new DeliveryRouting(db, now);
  }

  private fresh(scan: StoredOsvScan, selected: CurrentSource, threat: ThreatSnapshot): void {
    const now = this.now().toISOString();
    const queriedAt = timestamp(scan.osv.queriedAt, "invalid_query_time");
    const observedAt = timestamp(scan.observedAt, "invalid_observation_time");
    if (Date.parse(queriedAt) < Date.parse(selected.completedAt)
      || Date.parse(observedAt) < Date.parse(queriedAt)
      || Date.parse(observedAt) > Date.parse(now)
      || Date.parse(now) - Date.parse(queriedAt) > DAY) {
      throw new SourceAttention("stale_or_unbound_osv_scan");
    }
    // Historical replay is deterministic, but old feeds cannot become current merely
    // because they were fresh at an old observation. Validate even an empty OSV scan.
    assertThreatFreshness(threat, observedAt);
    assertThreatFreshness(threat, now);
  }

  async observe(selection: CurrentSource, osvSnapshotId: string, threatSnapshotId: string): Promise<SourceDecisionResult> {
    const selected = structuredClone(selection);
    await this.polls.assertCurrent(selected);
    const retained = await this.sources.readOsv(selected.companyId, osvSnapshotId);
    if (!retained) throw new SourceAttention("missing_osv_snapshot");
    if (retained.scan.lockfileSnapshotId !== selected.snapshotId) throw new SourceAttention("osv_source_binding_mismatch");
    const threat = await this.threats.read(selected.companyId, threatSnapshotId);
    if (!threat) throw new SourceAttention("missing_threat_snapshot");
    this.fresh(retained.scan, selected, threat);
    // Normalize and check the entire batch's raw/alias/feed coverage before writes.
    // No caller-supplied scope, range, fix or absence assertion enters this path.
    const inputs = enrichThreatInputs(retained.inputs, threat);
    const origins = new Set<string>();
    for (const input of inputs) {
      const origin = findingIdentity(input).originId;
      // Identity is remediation-based, not version-based. Until an explicit
      // all-version reducer exists, hash ordering must not let an outside tuple
      // replace affected evidence for another installed version of that action.
      if (origins.has(origin)) throw new SourceAttention("multiple_versions_require_aggregation");
      origins.add(origin);
      input.provenance.osvSnapshotId = osvSnapshotId;
      input.provenance.threatSnapshotId = threatSnapshotId;
    }
    await this.polls.assertCurrent(selected);
    const results: RoutingResult[] = [];
    for (const input of inputs) {
      this.fresh(retained.scan, selected, threat);
      results.push(await this.routing.observeCurrent(selected, input));
    }
    // Including no-op/empty batches: never report current success after invalidation.
    await this.polls.assertCurrent(selected);
    this.fresh(retained.scan, selected, threat);
    const inventory = retained.inventory;
    const attention = ["repository_discovery_not_proven", "full_dependency_closure_not_proven", "runtime_completeness_not_proven"];
    if (!inventory.coverage.configuredPathsParsed) attention.push("inventory_parse_attention");
    if (retained.scan.osv.unavailableIds.length) attention.push("osv_alias_coverage_incomplete");
    if (results.some(result => result.status === "attention")) attention.push("routing_attention");
    return {
      status: "attention", lockfileSnapshotId: selected.snapshotId, osvSnapshotId, threatSnapshotId,
      inventory, attention,
      counters: { dependencies: inventory.dependencies.length, observations: retained.scan.osv.observations.length,
        decisions: inputs.length, routingAttention: results.filter(result => result.status === "attention").length },
      results,
    };
  }
}
