import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { satisfies, valid } from "semver";
import { DependabotJournal } from "./dependabot-journal.js";
import { validateDependabotSnapshot, type DependabotAlert, type DependabotSnapshot } from "./dependabot.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { InventoryDependency } from "./inventory.js";
import { SourceAttention, timestamp } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";

const DAY = 86_400_000;
const VERSION = "0.1.0";

type RangeMatch = "matches" | "does_not_match" | "unknown";

export interface DependabotTupleContext {
  dependency: Pick<InventoryDependency, "ecosystem" | "package" | "version">;
  // Exact installed locations in this file, not all locations in the repository.
  locators: string[];
  rangeMatch: RangeMatch;
}

export interface DependabotAlertContext {
  alert: DependabotAlert;
  status: "matched_observation" | "attention";
  attention: string[];
  file: { path: string; sha256: string; blobSha: string } | null;
  tuples: DependabotTupleContext[];
}

export interface DependabotRepositoryContext {
  version: 1;
  status: "attention";
  companyId: string;
  repo: string;
  sourceSha: string;
  artifactDigest: string;
  lockfileSnapshotId: string;
  sourceSelection: { pollRevision: number; token: string; startedAt: string; completedAt: string };
  dependabotSnapshotId: string;
  dependabotSnapshotSha256: string;
  queriedAt: string;
  observedAt: string;
  alerts: DependabotAlertContext[];
  otherRepositoryAlerts: number;
  attention: string[];
  toolVersions: Record<string, string>;
  contextSha256: string;
}

/** A deliberately narrow GitHub comparator subset. Never a negative applicability proof. */
function rangeMatch(version: string, range: string): RangeMatch {
  // GitHub ranges are not OSV ranges, nor are npm comparators portable to other ecosystems.
  // Prereleases/build metadata and unsupported grammar remain unknown, not exclusions.
  if (!/^\d+\.\d+\.\d+$/u.test(version) || valid(version) !== version) return "unknown";
  const parts = range.split(",").map(part => part.trim());
  if (!parts.length || parts.length > 8) return "unknown";
  for (const part of parts) {
    const match = /^(?:<=|>=|<|>|=)?\s*(\d+\.\d+\.\d+)$/u.exec(part);
    if (!match || valid(match[1]) !== match[1]) return "unknown";
  }
  return satisfies(version, parts.join(" ")) ? "matches" : "does_not_match";
}

function bindAlert(alert: DependabotAlert, selected: CurrentSource): DependabotAlertContext {
  const attention: string[] = [];
  const file = selected.stored.lockfiles.files.find(file => file.path === alert.manifestPath);
  const parsed = selected.stored.inventory.files.find(file => file.path === alert.manifestPath);
  if (!file) attention.push("dependabot_manifest_not_in_selected_inventory");
  else if (parsed?.status !== "parsed") attention.push("dependabot_inventory_file_attention");
  if (alert.state !== "open") attention.push("dependabot_alert_not_open");
  if (alert.advisory.withdrawnAt !== null) attention.push("dependabot_advisory_withdrawn");
  // Only the installed npm identity and the comparator subset above are supported here.
  // Other ecosystems retain their raw reported context without borrowing npm semantics.
  if (alert.package.ecosystem !== "npm") attention.push("dependabot_context_ecosystem_unsupported");
  const candidates = file && parsed?.status === "parsed" ? selected.stored.inventory.dependencies.filter(dep =>
    dep.ecosystem === alert.package.ecosystem && dep.package === alert.package.name
      && dep.locations.some(location => location.path === alert.manifestPath)) : [];
  if (file && parsed?.status === "parsed" && !candidates.length) attention.push("dependabot_package_not_in_manifest_inventory");
  const tuples = candidates.map(dep => ({
    dependency: { ecosystem: dep.ecosystem, package: dep.package, version: dep.version },
    locators: dep.locations.filter(location => location.path === alert.manifestPath).map(location => location.locator).sort(),
    rangeMatch: alert.package.ecosystem === "npm" ? rangeMatch(dep.version, alert.vulnerableVersionRange) : "unknown" as RangeMatch,
  })).sort((a, b) => {
    const left = canonicalJson(a.dependency);
    const right = canonicalJson(b.dependency);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  if (tuples.some(tuple => tuple.rangeMatch === "unknown")) attention.push("dependabot_range_context_unknown");
  if (tuples.length && !tuples.some(tuple => tuple.rangeMatch === "matches")) attention.push("dependabot_no_installed_version_match");
  return { alert, status: attention.length ? "attention" : "matched_observation", attention,
    file: file ? { path: file.path, sha256: file.sha256, blobSha: file.blobSha } : null, tuples };
}

/** Retained observations joined to exact current inventory, not source switching or a policy input. */
export class DependabotContext {
  private readonly journal: DependabotJournal;
  private readonly polls: SourcePollStore;
  constructor(db: PluginDatabaseClient, private readonly now = () => new Date()) {
    this.journal = new DependabotJournal(db);
    this.polls = new SourcePollStore(db, now);
  }

  private fresh(snapshot: DependabotSnapshot, selected: CurrentSource): void {
    const now = Date.parse(timestamp(this.now().toISOString(), "invalid_dependabot_context_time"));
    if (snapshot.organization !== selected.source.repo.split("/")[0]) throw new SourceAttention("dependabot_context_organization_mismatch");
    if (Date.parse(snapshot.queriedAt) < Date.parse(selected.completedAt)
      || Date.parse(snapshot.completedAt) > now || now - Date.parse(snapshot.queriedAt) > DAY) {
      throw new SourceAttention("stale_or_unbound_dependabot_context");
    }
  }

  async bind(selection: CurrentSource, dependabotSnapshotId: string): Promise<DependabotRepositoryContext> {
    const selected = structuredClone(selection);
    await this.polls.assertCurrent(selected);
    const snapshot = await this.journal.read(selected.companyId, dependabotSnapshotId);
    if (!snapshot) throw new SourceAttention("missing_dependabot_snapshot");
    this.fresh(snapshot, selected);
    const observations = validateDependabotSnapshot(snapshot);
    const alerts: DependabotAlertContext[] = [];
    let bytes = 0;
    for (const alert of observations.filter(alert => alert.repo === selected.source.repo).sort((a, b) => a.number - b.number)) {
      const bound = bindAlert(alert, selected);
      bytes += Buffer.byteLength(canonicalJson(bound));
      if (bytes > 8 * 1024 * 1024) throw new SourceAttention("dependabot_context_capacity");
      alerts.push(bound);
    }
    const attention = ["dependabot_repository_visibility_not_proven", "dependabot_snapshot_consistency_not_proven",
      "dependabot_alias_closure_not_proven", "dependabot_scope_not_applied", "dependabot_compatible_fix_not_proven",
      "full_dependency_closure_not_proven", "runtime_completeness_not_proven"];
    if (!selected.stored.inventory.coverage.configuredPathsParsed) attention.push("inventory_parse_attention");
    if (!alerts.length) attention.push("dependabot_no_repository_observations");
    if (alerts.some(alert => alert.status === "attention")) attention.push("dependabot_alert_context_attention");
    const content = {
      version: 1 as const, status: "attention" as const, companyId: selected.companyId, repo: selected.source.repo,
      sourceSha: selected.stored.lockfiles.sourceSha, artifactDigest: selected.stored.lockfiles.artifactDigest,
      lockfileSnapshotId: selected.snapshotId,
      sourceSelection: { pollRevision: selected.pollRevision, token: selected.token,
        startedAt: selected.startedAt, completedAt: selected.completedAt },
      dependabotSnapshotId, dependabotSnapshotSha256: snapshot.snapshotSha256,
      queriedAt: snapshot.queriedAt, observedAt: snapshot.completedAt, alerts,
      otherRepositoryAlerts: observations.length - alerts.length, attention,
      toolVersions: { ...selected.stored.inventory.toolVersions, "vuln-sentinel-dependabot-context": VERSION },
    };
    // A superseded/expired invocation, including an empty result, returns no current context.
    // These checks are as-of only, not a lasting permission to write or publish.
    await this.polls.assertCurrent(selected);
    this.fresh(snapshot, selected);
    const encoded = canonicalJson(["dependabot-repository-context-v1", content]);
    if (Buffer.byteLength(encoded) > 8 * 1024 * 1024) throw new SourceAttention("dependabot_context_capacity");
    return { ...content, contextSha256: sha256(encoded) };
  }
}
