import { aliasClosure, canonicalJson, sha256 } from "./identity.js";
import type { Advisory, Ecosystem, FindingInput } from "./model.js";
import { osvVersionStatus, type OsvAffected } from "./ranges.js";
import { object, SourceAttention, sourceBudget, text, timestamp, type SourceFetch } from "./source-http.js";

const BASE = "https://api.osv.dev/v1";
const VERSION = "0.2.0";
const ECOSYSTEMS: Ecosystem[] = ["npm", "crates.io", "Go", "PyPI"];
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u;

export interface OsvDependency {
  ecosystem: Ecosystem;
  package: string;
  version: string;
}

export interface OsvRecord extends Advisory {
  affected: OsvAffected[];
  severity: FindingInput["severity"];
  rawSha256: string;
  raw: Record<string, unknown>;
}

export interface OsvSnapshot {
  queriedAt: string;
  snapshotSha256: string;
  observations: Array<{ dependency: OsvDependency; advisoryIds: string[] }>;
  records: OsvRecord[];
  /** Referenced IDs returning 404, not proof of withdrawal or range exclusion. */
  unavailableIds: string[];
}

function id(value: unknown): string {
  const result = text(value, "invalid_advisory_id", 200);
  if (!ID.test(result)) throw new SourceAttention("invalid_advisory_id");
  return result;
}

function array(value: unknown, code: string, max = 10_000): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw new SourceAttention(code);
  return value;
}

function ids(value: unknown): string[] {
  return [...new Set(array(value === undefined ? [] : value, "invalid_aliases").map(id))].sort();
}

function dependency(value: OsvDependency): OsvDependency {
  if (!ECOSYSTEMS.includes(value.ecosystem)) throw new SourceAttention("unsupported_ecosystem");
  const name = text(value.package, "invalid_package", 512);
  const version = text(value.version, "invalid_version", 256);
  if (/[|\s]/u.test(name) || /[|\s]/u.test(version)) throw new SourceAttention("ambiguous_package");
  return { ecosystem: value.ecosystem, package: name, version };
}

function affected(value: unknown): OsvAffected {
  const row = object(value, "invalid_affected");
  const pkg = object(row.package, "missing_affected_package");
  const result: OsvAffected = {
    package: { name: text(pkg.name, "invalid_affected_name", 512), ecosystem: text(pkg.ecosystem, "invalid_affected_ecosystem", 100) },
  };
  if (row.versions !== undefined) {
    result.versions = array(row.versions, "invalid_versions", 100_000).map(v => text(v, "invalid_version", 256));
  }
  if (row.ranges !== undefined) {
    result.ranges = array(row.ranges, "invalid_ranges").map(value => {
      const range = object(value, "invalid_range");
      return {
        type: text(range.type, "invalid_range_type", 100),
        events: array(range.events, "invalid_range_events").map(value => {
          const event = object(value, "invalid_range_event");
          const entries = Object.entries(event);
          if (entries.length !== 1) throw new SourceAttention("invalid_range_event");
          const [key, raw] = entries[0]!;
          if (!["introduced", "fixed", "last_affected", "limit"].includes(key)) {
            throw new SourceAttention("invalid_range_event");
          }
          return { [key]: text(raw, "invalid_range_event", 256) };
        }),
      };
    });
  }
  return result;
}

export function parseOsvRecord(value: unknown, expectedId: string): OsvRecord {
  const row = object(value, "invalid_advisory");
  if (id(row.id) !== expectedId) throw new SourceAttention("advisory_id_mismatch");
  const modified = timestamp(row.modified, "missing_advisory_revision");
  const withdrawn = row.withdrawn === undefined ? null : timestamp(row.withdrawn, "invalid_withdrawal");
  const rawSeverity = row.database_specific === undefined ? undefined
    : object(row.database_specific, "invalid_database_specific").severity;
  const knownSeverity = typeof rawSeverity === "string" ? rawSeverity.toLowerCase() : "unknown";
  const severity = ["critical", "high", "moderate", "low"].includes(knownSeverity)
    ? knownSeverity as OsvRecord["severity"] : "unknown";
  return {
    id: expectedId, modified, withdrawn, aliases: ids(row.aliases), upstream: ids(row.upstream),
    affected: array(row.affected === undefined ? [] : row.affected, "invalid_affected").map(affected),
    severity, rawSha256: sha256(canonicalJson(value)), raw: structuredClone(row),
  };
}

/** Read-only API adapter. Nothing is scheduled, cached as safe, resolved or published here. */
export class OsvSource {
  constructor(private readonly fetch: SourceFetch, private readonly now = () => new Date()) {}

  async query(dependencies: OsvDependency[]): Promise<OsvSnapshot> {
    if (dependencies.length > 2_000) throw new SourceAttention("inventory_capacity");
    const unique = new Map<string, OsvDependency>();
    for (const value of dependencies) {
      const dep = dependency(value);
      unique.set(canonicalJson(dep), dep);
    }
    const deps = [...unique.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, dep]) => dep);
    const queriedAt = this.now().toISOString();
    const request = sourceBudget(this.fetch);
    const observations: OsvSnapshot["observations"] = [];
    const revisions = new Map<string, string>();
    let associations = 0;
    for (let offset = 0; offset < deps.length; offset += 100) {
      const chunk = deps.slice(offset, offset + 100);
      const seen = chunk.map(() => new Set<string>());
      const found = chunk.map(() => new Set<string>());
      let pending = chunk.map((dep, index) => ({ dep, index, token: null as string | null }));
      for (let page = 0; pending.length; page++) {
        if (page >= 20) throw new SourceAttention("pagination_capacity");
        const response = await request(`${BASE}/querybatch`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries: pending.map(({ dep, token }) => ({
            package: { name: dep.package, ecosystem: dep.ecosystem }, version: dep.version,
            ...(token === null ? {} : { page_token: token }),
          })) }),
        });
        if (response.status !== 200) throw new SourceAttention(`osv_batch_http_${response.status}`);
        const body = object(response.body, "invalid_batch");
        const results = array(body.results, "invalid_batch_results", 100);
        if (results.length !== pending.length) throw new SourceAttention("batch_length_mismatch");
        const next: typeof pending = [];
        results.forEach((value, index) => {
          const result = object(value, "invalid_batch_result");
          // Empty OSV results are {}, but an explicit error must not become no findings.
          if (result.error !== undefined) throw new SourceAttention("batch_query_error");
          if (Object.keys(result).some(key => !["vulns", "next_page_token"].includes(key))) {
            throw new SourceAttention("unrecognized_batch_result");
          }
          const query = pending[index]!;
          for (const value of array(result.vulns === undefined ? [] : result.vulns, "invalid_batch_vulns")) {
            const vuln = object(value, "invalid_batch_vuln");
            const advisoryId = id(vuln.id);
            const modified = timestamp(vuln.modified, "missing_batch_revision");
            const previous = revisions.get(advisoryId);
            if (previous && previous !== modified) throw new SourceAttention("advisory_changed_during_query");
            revisions.set(advisoryId, modified);
            if (!found[query.index]!.has(advisoryId) && ++associations > 2_000) {
              throw new SourceAttention("finding_capacity");
            }
            found[query.index]!.add(advisoryId);
          }
          if (result.next_page_token !== undefined && result.next_page_token !== "") {
            const token = text(result.next_page_token, "invalid_page_token", 4096);
            if (seen[query.index]!.has(token)) throw new SourceAttention("pagination_cycle");
            seen[query.index]!.add(token);
            next.push({ ...query, token });
          }
        });
        pending = next;
      }
      chunk.forEach((dep, index) => observations.push({ dependency: dep, advisoryIds: [...found[index]!].sort() }));
    }
    const records: OsvRecord[] = [];
    const unavailableIds: string[] = [];
    const pending = [...revisions.keys()].sort();
    const discovered = new Set(pending);
    let snapshotBytes = Buffer.byteLength(canonicalJson(observations));
    for (let index = 0; index < pending.length; index++) {
      const advisoryId = pending[index]!;
      const response = await request(`${BASE}/vulns/${encodeURIComponent(advisoryId)}`, { method: "GET" });
      if (response.status === 404 && !revisions.has(advisoryId)) {
        unavailableIds.push(advisoryId);
        continue;
      }
      if (response.status !== 200) throw new SourceAttention(`osv_detail_http_${response.status}`);
      const record = parseOsvRecord(response.body, advisoryId);
      if (revisions.has(advisoryId) && record.modified !== revisions.get(advisoryId)) {
        throw new SourceAttention("advisory_changed_during_query");
      }
      if (Date.parse(record.modified!) > Date.parse(queriedAt)
        || record.withdrawn !== null && Date.parse(record.withdrawn) > Date.parse(queriedAt)) {
        throw new SourceAttention("future_advisory_revision");
      }
      snapshotBytes += Buffer.byteLength(canonicalJson(record));
      if (snapshotBytes > 8 * 1024 * 1024) throw new SourceAttention("snapshot_capacity");
      records.push(record);
      for (const linked of [...record.aliases, ...record.upstream].sort()) {
        if (discovered.has(linked)) continue;
        discovered.add(linked);
        if (discovered.size > 2_000) throw new SourceAttention("alias_capacity");
        pending.push(linked);
      }
    }
    records.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    const snapshot = { queriedAt, observations, records, unavailableIds: unavailableIds.sort() };
    if (Buffer.byteLength(canonicalJson(snapshot)) > 8 * 1024 * 1024) throw new SourceAttention("snapshot_capacity");
    return { ...snapshot, snapshotSha256: sha256(canonicalJson(snapshot)) };
  }
}

/** Replay checks include the raw records and every discovered edge, not just a content hash. */
export function validateOsvSnapshot(snapshot: OsvSnapshot): void {
  timestamp(snapshot.queriedAt, "invalid_query_time");
  const { snapshotSha256, ...content } = snapshot;
  const serialized = canonicalJson(content);
  if (Buffer.byteLength(serialized) > 8 * 1024 * 1024) throw new SourceAttention("snapshot_capacity");
  if (sha256(serialized) !== snapshotSha256) throw new SourceAttention("snapshot_hash_mismatch");
  const records = array(snapshot.records, "invalid_osv_snapshot", 2_000) as OsvRecord[];
  const unavailable = ids(snapshot.unavailableIds);
  if (!Array.isArray(snapshot.unavailableIds) || unavailable.length !== snapshot.unavailableIds.length) {
    throw new SourceAttention("invalid_unavailable_ids");
  }
  const known = new Set(unavailable);
  for (const record of records) {
    if (known.has(record.id)) throw new SourceAttention("duplicate_osv_record");
    known.add(record.id);
    if (canonicalJson(parseOsvRecord(record.raw, record.id)) !== canonicalJson(record)) {
      throw new SourceAttention("osv_raw_record_mismatch");
    }
    if (Date.parse(record.modified!) > Date.parse(snapshot.queriedAt)
      || record.withdrawn !== null && Date.parse(record.withdrawn) > Date.parse(snapshot.queriedAt)) {
      throw new SourceAttention("future_osv_record");
    }
  }
  if (known.size > 2_000) throw new SourceAttention("alias_capacity");
  const referenced = new Set<string>();
  for (const record of records) {
    for (const linked of [...record.aliases, ...record.upstream]) {
      referenced.add(linked);
      if (!known.has(linked)) throw new SourceAttention("incomplete_alias_hydration");
    }
  }
  if (unavailable.some(value => !referenced.has(value))) throw new SourceAttention("unreferenced_unavailable_id");
  const seen = new Set<string>();
  const reachable = new Set<string>();
  let associations = 0;
  for (const row of array(snapshot.observations, "invalid_osv_snapshot", 2_000) as OsvSnapshot["observations"]) {
    const key = canonicalJson(dependency(row.dependency));
    if (seen.has(key)) throw new SourceAttention("duplicate_osv_observation");
    seen.add(key);
    if (!Array.isArray(row.advisoryIds) || ids(row.advisoryIds).length !== row.advisoryIds.length) {
      throw new SourceAttention("invalid_osv_observation");
    }
    associations += row.advisoryIds.length;
    if (associations > 2_000) throw new SourceAttention("finding_capacity");
    for (const root of row.advisoryIds) {
      if (!records.some(record => record.id === root)) throw new SourceAttention("missing_advisory_detail");
      if (!reachable.has(root)) for (const linked of aliasClosure(records, root)) reachable.add(linked);
    }
  }
  if ([...known].some(value => !reachable.has(value))) throw new SourceAttention("unreferenced_osv_record");
}

/** Conservative lockfile inputs only. An empty query result is not a rescan receipt. */
export function osvFindingInputs(
  snapshot: OsvSnapshot,
  context: { repo: string; artifactDigest: string; observedAt: string },
): FindingInput[] {
  if (!/^sha256:[a-f0-9]{64}$/u.test(context.artifactDigest)) throw new SourceAttention("invalid_artifact_digest");
  const observedAt = timestamp(context.observedAt, "invalid_observation_time");
  if (Date.parse(observedAt) < Date.parse(snapshot.queriedAt)) throw new SourceAttention("observation_before_query");
  validateOsvSnapshot(snapshot);
  const { snapshotSha256 } = snapshot;
  // Missing alias documents remain active unknown nodes. They can neither withdraw
  // another source nor help establish an all-sources range exclusion.
  const sources = [...snapshot.records, ...snapshot.unavailableIds.map(id => ({
    id, aliases: [], upstream: [], modified: null, withdrawn: null, affected: [], severity: "unknown" as const,
  }))];
  const graph = sources.map(({ id, aliases, upstream, modified, withdrawn }) => ({ id, aliases, upstream, modified, withdrawn }));
  const byId = new Map(snapshot.records.map(record => [record.id, record]));
  const closures = new Map<string, string[]>();
  return snapshot.observations.flatMap(({ dependency: dep, advisoryIds }) => {
    const groups = new Map<string, Set<string>>();
    for (const advisoryId of advisoryIds) {
      if (!byId.has(advisoryId)) throw new SourceAttention("missing_advisory_detail");
      let connected = closures.get(advisoryId);
      if (!connected) {
        connected = aliasClosure(graph, advisoryId);
        for (const linked of connected) closures.set(linked, connected);
      }
      groups.set(connected[0]!, new Set(connected));
    }
    return [...groups.values()].map(connected => {
      const records = sources.filter(row => connected.has(row.id))
        .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
      const active = records.filter(row => row.withdrawn === null);
      // Prefer a known active revision, but an unavailable alias prevents an
      // all-withdrawn group from taking rule 1.
      const record = active.find(row => row.modified !== null) ?? active[0] ?? records[0]!;
      const advisoryId = record.id;
      const statuses = active.map(row => osvVersionStatus(row.affected, dep.ecosystem, dep.package, dep.version));
      const status = statuses.includes("affected") ? "affected"
        : statuses.length && statuses.every(value => value === "outside") ? "outside" : "unknown";
      const severityOrder: FindingInput["severity"][] = ["critical", "high", "moderate", "low", "unknown"];
      const severity = severityOrder.find(value => active.some(row => row.severity === value)) ?? record.severity;
      return {
        repo: context.repo, ecosystem: dep.ecosystem, package: dep.package, version: dep.version,
        fixedVersion: null, compatibleFixVerified: false, direct: false,
        aliases: structuredClone(graph.filter(row => connected.has(row.id))),
        advisoryId, scope: "unknown", severity, cvss4Base: null,
        buildTargets: [], deployedTags: [], platform: null, go: null, functions: null,
        versionEvidence: {
          artifactDigest: context.artifactDigest, advisoryId, advisoryModified: record.modified,
          tool: "vuln-sentinel-osv", complete: status !== "unknown", status,
        },
        provenance: {
          observedAt, artifactDigest: context.artifactDigest, artifactKind: "lockfile",
          source: { kind: "osv", queriedAt: snapshot.queriedAt, snapshotSha256 },
          epss: null, kev: null, toolVersions: { "vuln-sentinel-osv": VERSION },
        },
      } satisfies FindingInput;
    });
  });
}
