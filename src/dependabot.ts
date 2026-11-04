import { repository } from "./github-repository.js";
import { canonicalJson, sha256 } from "./identity.js";
import { object, SourceAttention, sourceBudget, text, timestamp, type SourceFetch } from "./source-http.js";

const BASE = "https://api.github.com";
const MAX_PAGES = 20;
const MAX_BYTES = 8 * 1024 * 1024;
const STATES = ["open", "fixed", "dismissed", "auto_dismissed"] as const;

export interface DependabotAlert {
  repo: string;
  number: number;
  state: typeof STATES[number];
  createdAt: string;
  updatedAt: string;
  package: { ecosystem: string; name: string };
  manifestPath: string;
  scope: "development" | "runtime" | null;
  relationship: "direct" | "transitive" | "unknown" | "inconclusive" | null;
  // Neither an installed version nor a proven semver-compatible remediation.
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
  severity: "low" | "medium" | "high" | "critical";
  advisory: { id: string; aliases: string[]; updatedAt: string; withdrawnAt: string | null };
}

export interface DependabotSnapshot {
  version: 1;
  organization: string;
  queriedAt: string;
  completedAt: string;
  pages: Array<{ url: string; link: string | null; alerts: unknown[] }>;
  snapshotSha256: string;
}

export type DependabotRead = { status: "unavailable"; reason: "credential_not_supplied" | "http_403" | "http_404" }
  | { status: "available"; snapshot: DependabotSnapshot; alerts: DependabotAlert[] };

function organization(value: unknown): string {
  const org = text(value, "invalid_dependabot_organization", 39).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(org) || org.includes("--")) {
    throw new SourceAttention("invalid_dependabot_organization");
  }
  return org;
}

function initialUrl(org: string): string {
  // No state/scope/severity filter: dismissed/fixed records are evidence too, not absence proof.
  return `${BASE}/orgs/${org}/dependabot/alerts?sort=created&direction=asc&per_page=100`;
}

function nextUrl(link: string | null, org: string): string | null {
  if (link === null) return null;
  text(link, "invalid_dependabot_pagination", 16_384);
  const relations = new Set<string>();
  let next: string | null = null;
  for (const part of link.split(/,\s*(?=<)/u)) {
    const match = /^<([^<>]+)>;\s*rel="(next|prev|first|last)"$/u.exec(part);
    if (!match || relations.has(match[2]!)) throw new SourceAttention("invalid_dependabot_pagination");
    relations.add(match[2]!);
    if (match[2] !== "next") continue;
    let url: URL;
    try { url = new URL(match[1]!); } catch { throw new SourceAttention("invalid_dependabot_pagination"); }
    if (url.origin !== BASE || url.username || url.password || url.hash
      || url.pathname !== `/orgs/${org}/dependabot/alerts`
      || url.searchParams.get("sort") !== "created" || url.searchParams.get("direction") !== "asc"
      || url.searchParams.get("per_page") !== "100" || !url.searchParams.get("after")
      || [...url.searchParams.keys()].sort().join(",") !== "after,direction,per_page,sort") {
      throw new SourceAttention("unbound_dependabot_pagination");
    }
    text(url.searchParams.get("after"), "invalid_dependabot_cursor", 4096);
    next = url.href;
  }
  return next;
}

function time(value: unknown, completedAt: string): string {
  const result = timestamp(value, "invalid_dependabot_time");
  if (Date.parse(result) > Date.parse(completedAt)) throw new SourceAttention("future_dependabot_revision");
  return result;
}

function severity(value: unknown): DependabotAlert["severity"] {
  if (!["low", "medium", "high", "critical"].includes(value as string)) {
    throw new SourceAttention("invalid_dependabot_severity");
  }
  return value as DependabotAlert["severity"];
}

function pkg(value: unknown): DependabotAlert["package"] {
  const row = object(value, "invalid_dependabot_package");
  return { ecosystem: text(row.ecosystem, "invalid_dependabot_ecosystem", 100),
    name: text(row.name, "invalid_dependabot_package_name", 512) };
}

function alert(value: unknown, org: string, completedAt: string): DependabotAlert {
  const row = object(value, "invalid_dependabot_alert");
  const repo = repository(text(object(row.repository, "missing_dependabot_repository").full_name, "invalid_dependabot_repository"));
  if (repo.split("/")[0] !== org) throw new SourceAttention("dependabot_organization_mismatch");
  if (!Number.isSafeInteger(row.number) || (row.number as number) < 1 || !STATES.includes(row.state as typeof STATES[number])) {
    throw new SourceAttention("invalid_dependabot_alert_identity");
  }
  const createdAt = time(row.created_at, completedAt);
  const updatedAt = time(row.updated_at, completedAt);
  if (Date.parse(updatedAt) < Date.parse(createdAt)) throw new SourceAttention("invalid_dependabot_time_order");
  const dependency = object(row.dependency, "invalid_dependabot_dependency");
  const selected = object(row.security_vulnerability, "invalid_dependabot_vulnerability");
  const advisory = object(row.security_advisory, "invalid_dependabot_advisory");
  const dependencyPackage = pkg(dependency.package);
  if (canonicalJson(dependencyPackage) !== canonicalJson(pkg(selected.package))) {
    throw new SourceAttention("dependabot_package_mismatch");
  }
  const manifestPath = text(dependency.manifest_path, "invalid_dependabot_manifest", 512);
  if (manifestPath.startsWith("/") || manifestPath.includes("\\")
    || manifestPath.split("/").some(part => !part || part === "." || part === "..")) {
    throw new SourceAttention("invalid_dependabot_manifest");
  }
  const scope = dependency.scope === undefined ? null : dependency.scope;
  const relationship = dependency.relationship === undefined ? null : dependency.relationship;
  if (!["development", "runtime", null].includes(scope as string | null)
    || !["direct", "transitive", "unknown", "inconclusive", null].includes(relationship as string | null)) {
    throw new SourceAttention("invalid_dependabot_dependency_context");
  }
  const id = text(advisory.ghsa_id, "invalid_dependabot_ghsa", 19);
  if (!/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/u.test(id)) {
    throw new SourceAttention("invalid_dependabot_ghsa");
  }
  const aliases = new Set([id]);
  if (advisory.cve_id !== null) {
    const cve = text(advisory.cve_id, "invalid_dependabot_cve", 32);
    if (!/^CVE-\d{4}-\d{4,}$/u.test(cve)) throw new SourceAttention("invalid_dependabot_cve");
    aliases.add(cve);
  }
  if (!Array.isArray(advisory.identifiers) || advisory.identifiers.length > 100) {
    throw new SourceAttention("invalid_dependabot_identifiers");
  }
  for (const value of advisory.identifiers) {
    const identifier = object(value, "invalid_dependabot_identifier");
    const name = text(identifier.value, "invalid_dependabot_identifier", 200);
    if ((identifier.type === "GHSA" && name === id) || (identifier.type === "CVE" && /^CVE-\d{4}-\d{4,}$/u.test(name))) {
      aliases.add(name);
    } else throw new SourceAttention("invalid_dependabot_identifier");
  }
  const advisoryUpdated = time(advisory.updated_at, completedAt);
  const published = time(advisory.published_at, completedAt);
  if (Date.parse(advisoryUpdated) < Date.parse(published)) throw new SourceAttention("invalid_dependabot_time_order");
  const withdrawnAt = advisory.withdrawn_at === null ? null : time(advisory.withdrawn_at, completedAt);
  const firstPatchedVersion = selected.first_patched_version === null ? null
    : text(object(selected.first_patched_version, "invalid_dependabot_patch").identifier, "invalid_dependabot_patch", 256);
  severity(advisory.severity);
  const selectedSeverity = severity(selected.severity);
  if (!Array.isArray(advisory.vulnerabilities) || advisory.vulnerabilities.length > 10_000
    || !advisory.vulnerabilities.some(value => canonicalJson(value) === canonicalJson(selected))) {
    throw new SourceAttention("dependabot_advisory_vulnerability_mismatch");
  }
  return { repo, number: row.number as number, state: row.state as DependabotAlert["state"], createdAt, updatedAt,
    package: dependencyPackage, manifestPath, scope: scope as DependabotAlert["scope"],
    relationship: relationship as DependabotAlert["relationship"],
    vulnerableVersionRange: text(selected.vulnerable_version_range, "invalid_dependabot_range", 4096),
    firstPatchedVersion, severity: selectedSeverity,
    advisory: { id, aliases: [...aliases].sort(), updatedAt: advisoryUpdated, withdrawnAt } };
}

/** Revalidate retained pages and their exact cursor chain before exposing any observations. */
export function validateDependabotSnapshot(snapshot: DependabotSnapshot): DependabotAlert[] {
  if (snapshot.version !== 1 || organization(snapshot.organization) !== snapshot.organization) {
    throw new SourceAttention("invalid_dependabot_snapshot");
  }
  const queriedAt = timestamp(snapshot.queriedAt, "invalid_dependabot_query_time");
  const completedAt = timestamp(snapshot.completedAt, "invalid_dependabot_completion_time");
  if (Date.parse(completedAt) < Date.parse(queriedAt) || Date.parse(completedAt) - Date.parse(queriedAt) > 240_000) {
    throw new SourceAttention("invalid_dependabot_query_interval");
  }
  const { snapshotSha256, ...content } = snapshot;
  if (Buffer.byteLength(canonicalJson(snapshot)) > MAX_BYTES) throw new SourceAttention("dependabot_snapshot_capacity");
  if (snapshotSha256 !== sha256(canonicalJson(content))) throw new SourceAttention("dependabot_snapshot_mismatch");
  if (!Array.isArray(snapshot.pages) || !snapshot.pages.length || snapshot.pages.length > MAX_PAGES) {
    throw new SourceAttention("dependabot_page_capacity");
  }
  let expected: string | null = initialUrl(snapshot.organization);
  const urls = new Set<string>();
  const identities = new Set<string>();
  const alerts: DependabotAlert[] = [];
  for (const page of snapshot.pages) {
    if (!expected || page.url !== expected || urls.has(page.url)) throw new SourceAttention("dependabot_page_chain_mismatch");
    urls.add(page.url);
    if (!Array.isArray(page.alerts) || page.alerts.length > 100) throw new SourceAttention("invalid_dependabot_page");
    expected = nextUrl(page.link, snapshot.organization);
    if (expected && !page.alerts.length) throw new SourceAttention("empty_dependabot_page_with_cursor");
    for (const raw of page.alerts) {
      const parsed = alert(raw, snapshot.organization, completedAt);
      const identity = canonicalJson([parsed.repo, parsed.number]);
      if (identities.has(identity)) throw new SourceAttention("duplicate_dependabot_alert");
      identities.add(identity);
      alerts.push(parsed);
    }
  }
  if (expected) throw new SourceAttention("incomplete_dependabot_pagination");
  return alerts;
}

/** Read-only observations, not repository coverage, artifact binding or a source-switch permit. */
export class DependabotSource {
  constructor(private readonly fetch: SourceFetch, private readonly token: string, private readonly now = () => new Date()) {}

  async read(org: string): Promise<DependabotRead> {
    const selected = organization(org);
    if (!this.token) return { status: "unavailable", reason: "credential_not_supplied" };
    const queriedAt = this.now().toISOString();
    const request = sourceBudget(this.fetch);
    const pages: DependabotSnapshot["pages"] = [];
    const seen = new Set<string>();
    let url: string | null = initialUrl(selected);
    let bytes = 0;
    while (url !== null) {
      if (pages.length >= MAX_PAGES) throw new SourceAttention("dependabot_page_capacity");
      if (seen.has(url)) throw new SourceAttention("dependabot_pagination_cycle");
      seen.add(url);
      const response = await request(url, { method: "GET", headers: {
        Accept: "application/vnd.github+json", Authorization: `Bearer ${this.token}`,
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Paperclip-vuln-sentinel/0.1.0",
      } });
      if (response.rateLimited) throw new SourceAttention("dependabot_rate_limited");
      // Forbidden/not-found do not prove a missing grant. OSV can continue independently;
      // the runtime must surface the reason, never replace this with an empty alert set.
      if (!pages.length && (response.status === 403 || response.status === 404)) {
        return { status: "unavailable", reason: response.status === 403 ? "http_403" : "http_404" };
      }
      if (response.status !== 200) throw new SourceAttention(`dependabot_http_${response.status}`);
      if (!Array.isArray(response.body) || response.body.length > 100) throw new SourceAttention("invalid_dependabot_page");
      const page = { url, link: response.link, alerts: response.body as unknown[] };
      bytes += Buffer.byteLength(canonicalJson(page));
      if (bytes > MAX_BYTES) throw new SourceAttention("dependabot_snapshot_capacity");
      pages.push(page);
      url = nextUrl(response.link, selected);
      if (url && !page.alerts.length) throw new SourceAttention("empty_dependabot_page_with_cursor");
    }
    const content = { version: 1 as const, organization: selected, queriedAt, completedAt: this.now().toISOString(), pages };
    const snapshot = { ...content, snapshotSha256: sha256(canonicalJson(content)) };
    return { status: "available", snapshot, alerts: validateDependabotSnapshot(snapshot) };
  }
}
