import { aliasClosure, canonicalJson, sha256 } from "./identity.js";
import type { FindingInput } from "./model.js";
import { object, SourceAttention, sourceBudget, text, timestamp, type SourceFetch } from "./source-http.js";

const KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS = "https://api.first.org/data/v1/epss";
const CVE = /^CVE-\d{4}-\d{4,}$/u;
const VERSION = "0.1.0";
const DAY = 86_400_000;

export interface KevSnapshot {
  fetchedAt: string;
  catalogVersion: string;
  releasedAt: string;
  cves: string[];
  raw: Record<string, unknown>;
  snapshotSha256: string;
}

/** Trusted configuration, not the EPSS API envelope's protocol version. */
export interface EpssModel {
  version: string;
  effectiveFrom: string;
  effectiveUntil: string;
  reference: string;
}

export interface EpssSnapshot {
  queriedAt: string;
  date: string;
  model: EpssModel;
  requestedCves: string[];
  scores: Array<{ cve: string; probability: number | null }>;
  responses: Record<string, unknown>[];
  snapshotSha256: string;
}

export interface ThreatSnapshot {
  kev: KevSnapshot;
  epss: EpssSnapshot;
}

function date(value: unknown, code: string): string {
  const result = text(value, code, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(result)) throw new SourceAttention(code);
  timestamp(`${result}T00:00:00Z`, code);
  return result;
}

function cve(value: unknown): string {
  const result = text(value, "invalid_cve", 64);
  if (!CVE.test(result)) throw new SourceAttention("invalid_cve");
  return result;
}

function cves(values: string[]): string[] {
  if (!Array.isArray(values) || values.length > 2_000) throw new SourceAttention("epss_capacity");
  return [...new Set(values.map(cve))].sort();
}

function probability(value: unknown): number {
  if (typeof value !== "string" && typeof value !== "number"
    || !/^(?:0(?:\.\d+)?|1(?:\.0+)?)$/u.test(String(value))) throw new SourceAttention("invalid_probability");
  const result = Number(value);
  if (!Number.isFinite(result) || result < 0 || result > 1) throw new SourceAttention("invalid_probability");
  return result;
}

function model(value: EpssModel, requestedDate: string): EpssModel {
  const result = {
    version: text(value.version, "invalid_epss_model", 100),
    effectiveFrom: date(value.effectiveFrom, "invalid_model_dates"),
    effectiveUntil: date(value.effectiveUntil, "invalid_model_dates"),
    reference: text(value.reference, "missing_model_reference", 2048),
  };
  if (result.effectiveFrom >= result.effectiveUntil || requestedDate < result.effectiveFrom
    || requestedDate >= result.effectiveUntil) throw new SourceAttention("epss_model_not_bound_to_date");
  return result;
}

export function parseKev(raw: unknown, fetchedAt: string): KevSnapshot {
  timestamp(fetchedAt, "invalid_feed_time");
  const row = object(raw, "invalid_kev");
  const catalogVersion = text(row.catalogVersion, "invalid_kev_version", 100);
  const releasedAt = timestamp(row.dateReleased, "invalid_kev_release");
  if (Date.parse(releasedAt) > Date.parse(fetchedAt)) throw new SourceAttention("future_kev_release");
  if (!Array.isArray(row.vulnerabilities) || row.vulnerabilities.length === 0 || row.vulnerabilities.length > 20_000
    || row.count !== row.vulnerabilities.length) throw new SourceAttention("kev_count_mismatch");
  const identifiers = row.vulnerabilities.map(value => {
    const item = object(value, "invalid_kev_entry");
    const added = date(item.dateAdded, "invalid_kev_date_added");
    if (added > releasedAt.slice(0, 10)) throw new SourceAttention("future_kev_entry");
    return cve(item.cveID);
  });
  if (new Set(identifiers).size !== identifiers.length) throw new SourceAttention("duplicate_kev_entry");
  const content = { fetchedAt, catalogVersion, releasedAt, cves: identifiers.sort(), raw: structuredClone(row) };
  if (Buffer.byteLength(canonicalJson(content)) > 8 * 1024 * 1024) throw new SourceAttention("kev_snapshot_capacity");
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}

function parseEpssResponse(raw: unknown, requested: string[], requestedDate: string): Record<string, unknown> {
  const row = object(raw, "invalid_epss");
  if (row.status !== "OK" || row["status-code"] !== 200 || row.version !== "1.0") {
    throw new SourceAttention("epss_api_status_or_version");
  }
  if (!Array.isArray(row.data) || !Number.isSafeInteger(row.total) || row.total !== row.data.length
    || row.data.length > requested.length || row.offset !== 0 || row.limit !== 100) {
    throw new SourceAttention("epss_coverage_mismatch");
  }
  const seen = new Set<string>();
  for (const value of row.data) {
    const item = object(value, "invalid_epss_entry");
    const identifier = cve(item.cve);
    if (!requested.includes(identifier) || seen.has(identifier)) throw new SourceAttention("epss_cve_mismatch");
    seen.add(identifier);
    if (date(item.date, "invalid_epss_date") !== requestedDate) throw new SourceAttention("epss_date_mismatch");
    probability(item.epss);
    probability(item.percentile);
  }
  return structuredClone(row);
}

function epssSnapshot(
  queriedAt: string, requested: string[], requestedDate: string, selectedModel: EpssModel, raw: unknown[],
): EpssSnapshot {
  timestamp(queriedAt, "invalid_feed_time");
  date(requestedDate, "invalid_epss_date");
  if (requestedDate > queriedAt.slice(0, 10)) throw new SourceAttention("future_epss_date");
  const pinnedModel = model(selectedModel, requestedDate);
  const expectedChunks = Math.ceil(requested.length / 100);
  if (raw.length !== expectedChunks) throw new SourceAttention("epss_coverage_mismatch");
  const responses = raw.map((value, index) => parseEpssResponse(value, requested.slice(index * 100, index * 100 + 100), requestedDate));
  const available = new Map<string, number>();
  for (const response of responses) {
    for (const value of response.data as Record<string, unknown>[]) available.set(cve(value.cve), probability(value.epss));
  }
  const content = {
    queriedAt, date: requestedDate, model: pinnedModel, requestedCves: requested,
    scores: requested.map(cve => ({ cve, probability: available.get(cve) ?? null })), responses,
  };
  if (Buffer.byteLength(canonicalJson(content)) > 8 * 1024 * 1024) throw new SourceAttention("epss_snapshot_capacity");
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}

export function validateThreatSnapshot(snapshot: ThreatSnapshot): void {
  if (Buffer.byteLength(canonicalJson(snapshot)) > 16 * 1024 * 1024) throw new SourceAttention("threat_storage_capacity");
  if (canonicalJson(parseKev(snapshot.kev.raw, snapshot.kev.fetchedAt)) !== canonicalJson(snapshot.kev)) {
    throw new SourceAttention("kev_snapshot_mismatch");
  }
  const epss = snapshot.epss;
  if (canonicalJson(epssSnapshot(epss.queriedAt, cves(epss.requestedCves), epss.date, epss.model, epss.responses)) !== canonicalJson(epss)) {
    throw new SourceAttention("epss_snapshot_mismatch");
  }
}

/** Fixed read-only providers; no scheduling, credentials, retries or publication. */
export class ThreatFeeds {
  constructor(private readonly fetch: SourceFetch, private readonly now = () => new Date()) {}

  async kev(): Promise<KevSnapshot> {
    const fetchedAt = this.now().toISOString();
    const response = await sourceBudget(this.fetch)(KEV, { method: "GET" });
    if (response.status !== 200) throw new SourceAttention(`kev_http_${response.status}`);
    return parseKev(response.body, fetchedAt);
  }

  async epss(identifiers: string[], requestedDate: string, selectedModel: EpssModel): Promise<EpssSnapshot> {
    const requested = cves(identifiers);
    const queriedAt = this.now().toISOString();
    // Validate all configuration before contacting a provider.
    epssSnapshot(queriedAt, [], requestedDate, selectedModel, []);
    const request = sourceBudget(this.fetch);
    const responses: unknown[] = [];
    let retainedBytes = 0;
    for (let index = 0; index < requested.length; index += 100) {
      const query = new URLSearchParams({ cve: requested.slice(index, index + 100).join(","), date: requestedDate, limit: "100", offset: "0" });
      const response = await request(`${EPSS}?${query}`, { method: "GET" });
      if (response.status !== 200) throw new SourceAttention(`epss_http_${response.status}`);
      const parsed = parseEpssResponse(response.body, requested.slice(index, index + 100), requestedDate);
      retainedBytes += Buffer.byteLength(canonicalJson(parsed));
      if (retainedBytes > 8 * 1024 * 1024) throw new SourceAttention("epss_snapshot_capacity");
      responses.push(parsed);
    }
    return epssSnapshot(queriedAt, requested, requestedDate, selectedModel, responses);
  }
}

/** Conservative immutable enrichment. The runtime must retain these snapshots first. */
export function enrichThreats(input: FindingInput, snapshot: ThreatSnapshot): FindingInput {
  return enrichThreatInputs([input], snapshot)[0]!;
}

export function enrichThreatInputs(inputs: FindingInput[], snapshot: ThreatSnapshot): FindingInput[] {
  if (inputs.length > 2_000) throw new SourceAttention("finding_capacity");
  validateThreatSnapshot(snapshot);
  return inputs.map(input => enrichValidated(input, snapshot));
}

function enrichValidated(input: FindingInput, snapshot: ThreatSnapshot): FindingInput {
  const observedAt = timestamp(input.provenance.observedAt, "invalid_observation_time");
  for (const fetchedAt of [snapshot.kev.fetchedAt, snapshot.epss.queriedAt]) {
    const age = Date.parse(observedAt) - Date.parse(fetchedAt);
    if (age < 0 || age > 2 * DAY) throw new SourceAttention("stale_or_future_threat_snapshot");
  }
  const scoreAge = Date.parse(observedAt) - Date.parse(`${snapshot.epss.date}T00:00:00Z`);
  if (scoreAge < 0 || scoreAge > 3 * DAY) throw new SourceAttention("stale_or_future_epss_date");
  const aliases = aliasClosure(input.aliases, input.advisoryId);
  const requested = aliases.filter(value => CVE.test(value));
  if (requested.some(value => !snapshot.epss.requestedCves.includes(value))) throw new SourceAttention("epss_alias_coverage_mismatch");
  const scores = snapshot.epss.scores.filter(row => requested.includes(row.cve));
  const known = scores.flatMap(row => row.probability === null ? [] : [row.probability]);
  const result = structuredClone(input);
  result.provenance.kev = {
    catalogVersion: snapshot.kev.catalogVersion, aliases: aliases.filter(value => snapshot.kev.cves.includes(value)),
    snapshotSha256: snapshot.kev.snapshotSha256,
  };
  result.provenance.epss = {
    date: snapshot.epss.date, modelVersion: snapshot.epss.model.version,
    probability: known.length ? Math.max(...known) : null, snapshotSha256: snapshot.epss.snapshotSha256,
  };
  result.provenance.toolVersions["vuln-sentinel-threat-feeds"] = VERSION;
  return result;
}
