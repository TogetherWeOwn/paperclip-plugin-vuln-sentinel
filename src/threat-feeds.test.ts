import { describe, expect, it, vi } from "vitest";
import { decide } from "./matcher.js";
import { canonicalJson, sha256 } from "./identity.js";
import { enrichThreats, enrichThreatInputs, parseKev, ThreatFeeds, validateThreatSnapshot } from "./threat-feeds.js";
import type { SourceFetch } from "./source-http.js";
import { finding } from "./test/fixtures.js";
import { epssModel, epssResponse, epssScore, feedTime, rawKev, scoreDate, threatSnapshot } from "./test/threats.js";

const now = () => new Date(feedTime);
const input = () => {
  const result = finding();
  result.provenance.observedAt = feedTime;
  return result;
};
function transport(data: unknown) {
  return vi.fn<SourceFetch>(async () => data instanceof Response ? data : new Response(JSON.stringify(data)));
}

describe("read-only KEV ingestion", () => {
  it("retains a complete count-checked raw catalog at the fixed provider without credentials", async () => {
    const fetch = transport(rawKev());
    const result = await new ThreatFeeds(fetch, now).kev();
    expect(result.cves).toEqual(["CVE-2026-12345"]);
    expect(result.raw).toEqual(rawKev());
    expect(fetch.mock.calls[0]![0]).toBe("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    expect(fetch.mock.calls[0]![1]).toMatchObject({ method: "GET", redirect: "error" });
    expect(fetch.mock.calls[0]![1].headers).toBeUndefined();
    const { snapshotSha256, ...content } = result;
    expect(snapshotSha256).toBe(sha256(canonicalJson(content)));
  });

  it.each([
    { count: 2 }, { vulnerabilities: [] }, { vulnerabilities: null }, { catalogVersion: "" },
    { dateReleased: "2030-01-01T00:00:00Z" }, { dateReleased: "yesterday" },
    { count: 2, vulnerabilities: [rawKev().vulnerabilities[0], rawKev().vulnerabilities[0]] },
    { vulnerabilities: [{ cveID: "CVE-2026-12345", dateAdded: "2026-02-30" }] },
    { vulnerabilities: [{ cveID: "CVE-2026-12345", dateAdded: "2026-11-04" }] },
    { vulnerabilities: [{ cveID: "GHSA-not-cve", dateAdded: scoreDate }] },
  ])("rejects partial or malformed catalogs %#", change => {
    expect(() => parseKev({ ...rawKev(), ...change }, feedTime)).toThrow("Source requires attention");
  });

  it.each([304, 403, 429, 500])("HTTP %s does not establish an empty KEV set", async status => {
    const fetch = transport(new Response(null, { status }));
    await expect(new ThreatFeeds(fetch, now).kev()).rejects.toThrow(`kev_http_${status}`);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("date-pinned EPSS ingestion", () => {
  it("pins CVEs/date and preserves probability separately from percentile and API version", async () => {
    const fetch = transport(epssResponse([epssScore()]));
    const result = await new ThreatFeeds(fetch, now).epss(["CVE-2026-12345", "CVE-2026-12345"], scoreDate, epssModel);
    const url = new URL(fetch.mock.calls[0]![0]);
    expect(url.origin + url.pathname).toBe("https://api.first.org/data/v1/epss");
    expect(Object.fromEntries(url.searchParams)).toEqual({ cve: "CVE-2026-12345", date: scoreDate, limit: "100", offset: "0" });
    expect(fetch.mock.calls[0]![1].headers).toBeUndefined();
    expect(result.scores).toEqual([{ cve: "CVE-2026-12345", probability: 0.04 }]);
    expect(result.model).toEqual(epssModel);
    expect(result.model.version).not.toBe(result.responses[0]!.version);
  });

  it("batches at 100 identifiers and retains explicit missing scores, not zeroes", async () => {
    const identifiers = Array.from({ length: 101 }, (_, n) => `CVE-2026-${n + 10000}`);
    const fetch = transport(epssResponse());
    const result = await new ThreatFeeds(fetch, now).epss(identifiers, scoreDate, epssModel);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(result.requestedCves).toHaveLength(101);
    expect(result.scores.every(row => row.probability === null)).toBe(true);
    expect(new URL(fetch.mock.calls[0]![0]).searchParams.get("cve")!.split(",")).toHaveLength(100);
  });

  it("makes no request when there are no CVE aliases", async () => {
    const fetch = transport(null);
    const result = await new ThreatFeeds(fetch, now).epss([], scoreDate, epssModel);
    expect(fetch).not.toHaveBeenCalled();
    expect(result.scores).toEqual([]);
    expect(result.responses).toEqual([]);
  });

  it.each([
    { status: "ERROR" }, { "status-code": 500 }, { version: "2.0" }, { total: 2 },
    { offset: 100 }, { limit: 1 }, { data: null }, { data: [epssScore("CVE-2026-99999")] },
    { total: 2, data: [epssScore(), epssScore()] }, { data: [{ ...epssScore(), date: "2026-11-02" }] },
    { data: [{ ...epssScore(), epss: "4.0" }] }, { data: [{ ...epssScore(), epss: "NaN" }] },
    { data: [{ ...epssScore(), epss: "-0.1" }] }, { data: [{ ...epssScore(), epss: null }] },
    { data: [{ ...epssScore(), percentile: "1.1" }] },
  ])("rejects partial, shifted or malformed responses %#", async change => {
    const fetch = transport({ ...epssResponse([epssScore()]), ...change });
    await expect(new ThreatFeeds(fetch, now).epss(["CVE-2026-12345"], scoreDate, epssModel)).rejects.toThrow("Source requires attention");
  });

  it.each([403, 404, 429, 500])("never treats HTTP %s as missing EPSS", async status => {
    const fetch = transport(new Response(null, { status }));
    await expect(new ThreatFeeds(fetch, now).epss(["CVE-2026-12345"], scoreDate, epssModel)).rejects.toThrow(`epss_http_${status}`);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    { date: "2026-11-05", model: epssModel }, { date: "2026-02-30", model: epssModel },
    { date: scoreDate, model: { ...epssModel, version: "" } },
    { date: scoreDate, model: { ...epssModel, reference: "" } },
    { date: scoreDate, model: { ...epssModel, effectiveFrom: "2026-11-04" } },
    { date: scoreDate, model: { ...epssModel, effectiveUntil: scoreDate } },
  ])("requires a model assertion bound to the date before fetching %#", async value => {
    const fetch = transport(null);
    await expect(new ThreatFeeds(fetch, now).epss(["CVE-2026-12345"], value.date, value.model)).rejects.toThrow("Source requires attention");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds retained response bytes across batches instead of dropping raw evidence", async () => {
    const identifiers = Array.from({ length: 301 }, (_, n) => `CVE-2026-${n + 10000}`);
    const fetch = transport({ ...epssResponse(), extra: "x".repeat(3 * 1024 * 1024) });
    await expect(new ThreatFeeds(fetch, now).epss(identifiers, scoreDate, epssModel)).rejects.toThrow("epss_snapshot_capacity");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("bounds and validates requested identifiers before fetching", async () => {
    const fetch = transport(null);
    const source = new ThreatFeeds(fetch, now);
    await expect(source.epss(["GHSA-example"], scoreDate, epssModel)).rejects.toThrow("invalid_cve");
    await expect(source.epss(Array.from({ length: 2001 }, () => "CVE-2026-12345"), scoreDate, epssModel)).rejects.toThrow("epss_capacity");
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("all-alias immutable threat enrichment", () => {
  it("KEV through a CVE alias promotes P0 regardless of scope, without mutating input", async () => {
    const original = input();
    original.scope = "development";
    const result = enrichThreats(original, await threatSnapshot());
    expect(result.provenance.kev).toMatchObject({ aliases: ["CVE-2026-12345"], catalogVersion: "2026.11.03" });
    expect(result.provenance.kev!.snapshotSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(decide(result).priority).toBe(0);
    expect(decide(result).matchedRule).toBe(2);
    expect(original.provenance.kev).not.toEqual(result.provenance.kev);
    expect(original.provenance).not.toHaveProperty("threatSnapshotId");
  });

  it.each([["0.039", "0.999", 3], ["0.04", "0.1", 1], ["0.9", "0.999", 1]])("uses EPSS %s, not percentile %s", async (score, percentile, priority) => {
    const result = await threatSnapshot();
    result.kev = parseKev({ ...rawKev(), vulnerabilities: [{ cveID: "CVE-2026-99999", dateAdded: scoreDate }] }, feedTime);
    result.epss = await new ThreatFeeds(transport(epssResponse([epssScore("CVE-2026-12345", score as string, percentile as string)])), now)
      .epss(["CVE-2026-12345"], scoreDate, epssModel);
    const value = input(); value.severity = "low";
    expect(decide(enrichThreats(value, result)).priority).toBe(priority);
  });

  it("selects the maximum probability across the complete alias closure", async () => {
    const feeds = await threatSnapshot();
    feeds.epss = await new ThreatFeeds(transport(epssResponse([epssScore(), epssScore("CVE-2026-99999", "0.5")])), now)
      .epss(["CVE-2026-12345", "CVE-2026-99999"], scoreDate, epssModel);
    const value = input();
    value.aliases.push({ id: "CVE-2026-12345", aliases: [], upstream: ["CVE-2026-99999"], modified: null, withdrawn: null });
    expect(enrichThreats(value, feeds).provenance.epss!.probability).toBe(0.5);
  });

  it("keeps missing EPSS null for severity fallback and retains tool/feed hashes", async () => {
    const feeds = await threatSnapshot();
    feeds.epss = await new ThreatFeeds(transport(epssResponse()), now).epss(["CVE-2026-12345"], scoreDate, epssModel);
    const result = enrichThreats(input(), feeds);
    expect(result.provenance.epss).toMatchObject({ date: scoreDate, modelVersion: epssModel.version, probability: null });
    expect(result.provenance.epss!.snapshotSha256).toBe(feeds.epss.snapshotSha256);
    expect(result.provenance.toolVersions["vuln-sentinel-threat-feeds"]).toBe("0.1.0");
  });

  it("requires every newly learned CVE to have been queried", async () => {
    const value = input();
    value.aliases[0]!.upstream = ["CVE-2026-99999"];
    const feeds = await threatSnapshot();
    expect(() => enrichThreats(value, feeds)).toThrow("epss_alias_coverage_mismatch");
  });

  it.each(["2026-11-04T04:29:59Z", "2026-11-07T00:00:00Z"])("holds future/stale snapshots at observation %s", async observedAt => {
    const value = input(); value.provenance.observedAt = observedAt;
    const feeds = await threatSnapshot();
    expect(() => enrichThreats(value, feeds)).toThrow("stale_or_future_threat_snapshot");
  });

  it("holds a stale EPSS date even when it was fetched just now", async () => {
    const feeds = await threatSnapshot();
    feeds.epss = await new ThreatFeeds(transport(epssResponse()), now).epss(["CVE-2026-12345"], "2026-10-31", epssModel);
    expect(() => enrichThreats(input(), feeds)).toThrow("stale_or_future_epss_date");
  });

  it("handles bounded batches without mutating inputs and rejects capacity overflow", async () => {
    const feeds = await threatSnapshot();
    const values = [input(), input()];
    expect(enrichThreatInputs(values, feeds)).toEqual(values.map(value => enrichThreats(value, feeds)));
    expect(() => enrichThreatInputs(Array.from({ length: 2_001 }, input), feeds)).toThrow("finding_capacity");
  });

  it("does not guess scopes, compatible fixes or runtime absence", async () => {
    const value = input(); value.scope = "unknown"; value.fixedVersion = null; value.functions = null;
    const result = enrichThreats(value, await threatSnapshot());
    expect(result.scope).toBe("unknown");
    expect(result.fixedVersion).toBeNull();
    expect(result.functions).toBeNull();
    expect(result.provenance.artifactDigest).toBe(value.provenance.artifactDigest);
  });

  it.each(["kev", "epss"])("rejects derived %s tampering despite recalculated content hashes", async kind => {
    const feeds = await threatSnapshot();
    if (kind === "kev") feeds.kev.cves = [];
    else feeds.epss.scores[0]!.probability = 0;
    const snapshot = kind === "kev" ? feeds.kev : feeds.epss;
    const { snapshotSha256: _, ...content } = snapshot;
    snapshot.snapshotSha256 = sha256(canonicalJson(content));
    expect(() => validateThreatSnapshot(feeds)).toThrow(`${kind}_snapshot_mismatch`);
  });
});
