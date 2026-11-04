import semver from "semver";
import { aliasClosure, canonicalJson } from "./identity.js";
import { validateOsvSnapshot, type OsvDependency, type OsvRecord, type OsvSnapshot } from "./osv.js";
import { OSV_RANGES_VERSION, osvVersionStatus, type OsvAffected, type VersionStatus } from "./ranges.js";
import { SourceAttention } from "./source-http.js";

export const OSV_FIXES_VERSION = "1.0.0";

export interface OsvFixCandidate {
  version: string;
  reportedBy: string[];
  status: "outside_reported_ranges" | "still_affected" | "unknown";
  sources: Array<{ id: string; status: VersionStatus }>;
}

export interface OsvFixObservation {
  version: typeof OSV_FIXES_VERSION;
  rangeEvaluatorVersion: typeof OSV_RANGES_VERSION;
  status: "attention";
  dependency: OsvDependency;
  source: { queriedAt: string; snapshotSha256: string };
  groups: Array<{
    aliasGroup: string;
    aliases: string[];
    records: Array<{ id: string; modified: string | null; rawSha256: string; withdrawn: string | null }>;
    candidates: OsvFixCandidate[];
    attention: string[];
  }>;
  compatibleFixVerified: false;
  attention: string[];
}

// Stable canonical npm versions only. Prerelease/build and other ecosystem
// compatibility must not be guessed from npm's permissive version parser.
function stableVersion(value: string): boolean {
  return semver.valid(value) === value && semver.prerelease(value) === null;
}

/** Offline reported boundaries, never a compatible fix or an input to rule 6. */
export function observeOsvFixes(snapshot: OsvSnapshot, dependency: OsvDependency): OsvFixObservation {
  validateOsvSnapshot(snapshot);
  const observation = snapshot.observations.find(row => canonicalJson(row.dependency) === canonicalJson(dependency));
  if (!observation) throw new SourceAttention("fix_dependency_not_queried");
  const byId = new Map(snapshot.records.map(row => [row.id, row]));
  const graph = [...snapshot.records, ...snapshot.unavailableIds.map(id => ({
    id, aliases: [], upstream: [], modified: null, withdrawn: null,
  }))];
  const closures = new Map<string, string[]>();
  const covered = new Set<string>();
  for (const id of observation.advisoryIds) {
    if (covered.has(id)) continue;
    const closure = aliasClosure(graph, id);
    for (const linked of closure) covered.add(linked);
    closures.set(closure[0]!, closure);
  }
  const supported = dependency.ecosystem === "npm" && stableVersion(dependency.version);
  let work = 0;
  const spend = (amount: number) => {
    work += amount;
    if (work > 100_000) throw new SourceAttention("fix_observation_capacity");
  };
  const matching = (record: OsvRecord) => record.affected.filter(row => row.package?.ecosystem === dependency.ecosystem
    && row.package.name === dependency.package);
  const evaluate = (rows: OsvAffected[], version: string) => {
    spend(1 + rows.reduce((sum, row) => sum + 1 + (row.versions?.length ?? 0)
      + (row.ranges ?? []).reduce((sum, range) => sum + 1 + range.events.length, 0), 0));
    return osvVersionStatus(rows, dependency.ecosystem, dependency.package, version);
  };
  const groups: OsvFixObservation["groups"] = [];
  for (const [aliasGroup, aliases] of [...closures].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
    const records = aliases.flatMap(id => byId.has(id) ? [byId.get(id)!] : []);
    const active = records.filter(row => row.withdrawn === null);
    const unavailable = aliases.filter(id => !byId.has(id));
    const attention = new Set<string>();
    if (!supported) attention.add("unsupported_fix_version_context");
    if (unavailable.length) attention.add("unavailable_alias_fix_context");
    if (!active.length) attention.add("no_active_reported_fix_source");
    const reported = new Map<string, Set<string>>();
    if (supported) for (const record of active) {
      for (const affected of matching(record)) {
        for (const range of affected.ranges ?? []) {
          const rows = [{ package: affected.package!, ranges: [range] }];
          const installed = evaluate(rows, dependency.version);
          if (installed === "unknown") attention.add("unusable_fix_range");
          if (installed !== "affected") continue;
          for (const event of range.events) {
            if (event.fixed === undefined) continue;
            const fixed = event.fixed;
            if (!stableVersion(fixed)) {
              attention.add("unsupported_fixed_version");
              continue;
            }
            if (!semver.gt(fixed, dependency.version)) continue;
            // A fixed event must actually close this supported affected range.
            if (evaluate(rows, fixed) !== "outside") continue;
            if (!reported.has(fixed)) reported.set(fixed, new Set());
            reported.get(fixed)!.add(record.id);
            if (reported.size > 100) throw new SourceAttention("fix_candidate_capacity");
          }
        }
      }
    }
    const candidates = [...reported].sort(([a], [b]) => semver.compare(a, b)).map(([version, ids]) => {
      const sources = [
        ...active.map(row => ({ id: row.id, status: evaluate(matching(row), version) })),
        ...unavailable.map(id => ({ id, status: "unknown" as const })),
      ].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
      const status: OsvFixCandidate["status"] = sources.some(row => row.status === "affected") ? "still_affected"
        : sources.length && sources.every(row => row.status === "outside") ? "outside_reported_ranges" : "unknown";
      if (status !== "outside_reported_ranges") attention.add("candidate_not_excluded_by_all_active_sources");
      return { version, reportedBy: [...ids].sort(), status, sources };
    });
    if (!candidates.length) attention.add("no_supported_fixed_boundary_observed");
    groups.push({
      aliasGroup, aliases, candidates,
      records: records.map(({ id, modified, rawSha256, withdrawn }) => ({ id, modified, rawSha256, withdrawn })),
      attention: [...attention].sort(),
    });
  }
  const result: OsvFixObservation = {
    version: OSV_FIXES_VERSION, rangeEvaluatorVersion: OSV_RANGES_VERSION, status: "attention",
    dependency: structuredClone(observation.dependency),
    source: { queriedAt: snapshot.queriedAt, snapshotSha256: snapshot.snapshotSha256 }, groups,
    compatibleFixVerified: false,
    attention: ["manifest_compatibility_not_verified", "release_availability_not_verified", "reported_ranges_not_remediation"],
  };
  if (Buffer.byteLength(canonicalJson(result)) > 1024 * 1024) throw new SourceAttention("fix_observation_capacity");
  return result;
}
