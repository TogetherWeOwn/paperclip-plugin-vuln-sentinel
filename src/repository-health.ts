import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { normalizeRepositorySources, type RepositorySource } from "./github-lockfiles.js";
import type { LockfileInventory } from "./inventory.js";
import { PublicationDiagnostics, type PublicationDiagnosticResult } from "./publication-diagnostics.js";
import { SourceAttention, text, timestamp } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";

export interface RepositoryHealthResult {
  status: "attention";
  companyId: string;
  repo: string;
  observedAt: string;
  completedAt: string;
  mode: "library_only";
  pilot: { startedAt: null; successfulScans: null };
  source: {
    status: "observed" | "unavailable";
    reason: string | null;
    summary: {
      pollRevision: number;
      snapshotId: string;
      startedAt: string;
      completedAt: string;
      ageMs: number;
      discoveryBound: boolean;
      inventory: {
        dependencies: number;
        files: number;
        parsedFiles: number;
        attentionFiles: number;
        issues: number;
        coverage: LockfileInventory["coverage"];
      };
    } | null;
  };
  diagnostics: PublicationDiagnosticResult;
  attention: string[];
}

// Never return raw errors or arbitrary SourceAttention codes from a database adapter.
const SOURCE_REASONS = new Set(["missing_current_source", "current_source_pending", "current_source_attention",
  "current_source_stale", "source_configuration_changed", "source_poll_superseded"]);
const reason = (error: unknown) => error instanceof SourceAttention && SOURCE_REASONS.has(error.code)
  ? error.code : "source_health_unavailable";

/** Read-only as-of observations, never a runtime health endpoint or enablement gate. */
export class RepositoryHealth {
  private readonly polls: SourcePollStore;
  private readonly diagnostics: PublicationDiagnostics;
  constructor(db: PluginDatabaseClient, private readonly now = () => new Date()) {
    this.polls = new SourcePollStore(db, now);
    this.diagnostics = new PublicationDiagnostics(db, now);
  }

  async read(companyId: string, configured: RepositorySource): Promise<RepositoryHealthResult> {
    text(companyId, "invalid_company", 256);
    const source = normalizeRepositorySources([configured])[0]!;
    const observedAt = timestamp(this.now().toISOString(), "invalid_repository_health_time");
    let selected: CurrentSource | null = null;
    let sourceReason: string | null = null;
    try { selected = await this.polls.current(companyId, source); }
    catch (error) { sourceReason = reason(error); }
    // Diagnostic failures retain their independent unavailable/invalid states.
    const diagnostics = await this.diagnostics.read(companyId, source.repo);
    if (selected) {
      try { await this.polls.assertCurrent(selected); }
      catch (error) { selected = null; sourceReason = reason(error); }
    }
    const completedAt = timestamp(this.now().toISOString(), "invalid_repository_health_time");
    if (Date.parse(completedAt) < Date.parse(observedAt)) throw new SourceAttention("repository_health_clock_regressed");
    // A last asynchronous read may cross the freshness boundary; no stale summary survives.
    if (selected && (Date.parse(completedAt) - Date.parse(selected.startedAt) > 86_400_000
      || Date.parse(completedAt) < Date.parse(selected.completedAt))) {
      selected = null;
      sourceReason = "current_source_stale";
    }
    const inventory = selected?.stored.inventory;
    const attention = [...diagnostics.attention, "health_library_only", "source_health_not_atomic",
      "repository_coverage_not_proven", "full_dependency_closure_not_proven", "runtime_completeness_not_proven",
      "advisory_feed_health_not_observed", "enabled_scan_counters_not_observed"];
    if (sourceReason) attention.push(sourceReason);
    if (inventory && !inventory.coverage.configuredPathsParsed) attention.push("inventory_parse_attention");
    return {
      status: "attention", companyId, repo: source.repo, observedAt, completedAt, mode: "library_only",
      pilot: { startedAt: null, successfulScans: null },
      source: { status: selected ? "observed" : "unavailable", reason: sourceReason,
        summary: selected && inventory ? {
          pollRevision: selected.pollRevision, snapshotId: selected.snapshotId,
          startedAt: selected.startedAt, completedAt: selected.completedAt,
          ageMs: Date.parse(completedAt) - Date.parse(selected.startedAt),
          discoveryBound: selected.stored.discoverySnapshotId !== undefined,
          inventory: { dependencies: inventory.dependencies.length, files: inventory.files.length,
            parsedFiles: inventory.files.filter(file => file.status === "parsed").length,
            attentionFiles: inventory.files.filter(file => file.status === "attention").length,
            issues: inventory.files.reduce((count, file) => count + file.issues.length, 0),
            coverage: structuredClone(inventory.coverage) },
        } : null },
      diagnostics, attention: [...new Set(attention)].sort(),
    };
  }
}
