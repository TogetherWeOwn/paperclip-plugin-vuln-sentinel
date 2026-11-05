import { describe, expect, it, vi } from "vitest";
import { DependabotSource, validateDependabotSnapshot, type DependabotSnapshot } from "./dependabot.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { SourceFetch } from "./source-http.js";
import { dependabotAlert, dependabotTime } from "./test/dependabot.js";

const now = () => new Date(dependabotTime);
const firstUrl = "https://api.github.com/orgs/example/dependabot/alerts?sort=created&direction=asc&per_page=100";
const next = (cursor = "cursor") => `${firstUrl}&after=${cursor}`;
const link = (url = next()) => `<${url}>; rel="next"`;
const json = (value: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(value), { headers });

async function snapshot(raw: unknown[] = [dependabotAlert()]): Promise<DependabotSnapshot> {
  const read = await new DependabotSource(async () => json(raw), "fixture-token", now).read("Example");
  if (read.status !== "available") throw new Error("fixture unavailable");
  return read.snapshot;
}
function rehash(value: DependabotSnapshot) {
  const { snapshotSha256: _, ...content } = value;
  value.snapshotSha256 = sha256(canonicalJson(content));
  return value;
}

describe("read-only organization Dependabot alerts", () => {
  it("makes one unfiltered org read, retaining raw evidence and exact alert/advisory revisions", async () => {
    const raw = dependabotAlert();
    const fetch = vi.fn<SourceFetch>(async () => json([raw]));
    const result = await new DependabotSource(fetch, "fixture-token", now).read("Example");
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe(firstUrl);
    expect(init.method).toBe("GET");
    expect(init.redirect).toBe("error");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer fixture-token");
    expect(new Headers(init.headers).get("X-GitHub-Api-Version")).toBe("2022-11-28");
    expect(result.status).toBe("available");
    if (result.status !== "available") throw new Error("unavailable");
    expect(result.alerts).toEqual([{
      repo: "example/project", number: 1, state: "open", createdAt: raw.created_at, updatedAt: raw.updated_at,
      package: raw.dependency.package, manifestPath: "package-lock.json", scope: "development", relationship: "transitive",
      vulnerableVersionRange: "< 2.0.0", firstPatchedVersion: "2.0.0", severity: "high",
      advisory: { id: raw.security_advisory.ghsa_id, aliases: ["CVE-2026-12345", raw.security_advisory.ghsa_id],
        updatedAt: raw.security_advisory.updated_at, withdrawnAt: null },
    }]);
    expect(result.snapshot.pages[0]!.alerts).toEqual([raw]);
    expect(validateDependabotSnapshot(result.snapshot)).toEqual(result.alerts);
    expect(result.alerts[0]).not.toHaveProperty("version");
    expect(result.alerts[0]).not.toHaveProperty("artifactDigest");
  });

  it("follows only the bound next cursor and retains dismissed/fixed/auto-dismissed records", async () => {
    const rows = ["open", "dismissed", "fixed", "auto_dismissed"].map((state, i) => ({ ...dependabotAlert(i + 1), state }));
    const fetch = vi.fn<SourceFetch>(async url => url === firstUrl
      ? json(rows.slice(0, 2), { link: link() }) : json(rows.slice(2), { link: `<${firstUrl}>; rel="prev"` }));
    const result = await new DependabotSource(fetch, "fixture-token", now).read("example");
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([firstUrl, next()]);
    if (result.status !== "available") throw new Error("unavailable");
    expect(result.alerts.map(row => row.state)).toEqual(["open", "dismissed", "fixed", "auto_dismissed"]);
    expect(result.snapshot.pages).toHaveLength(2);
  });

  it("does not translate an empty traversal into repository/artifact coverage or a safe finding", async () => {
    const result = await new DependabotSource(async () => json([]), "fixture-token", now).read("example");
    expect(result.status).toBe("available");
    if (result.status !== "available") throw new Error("unavailable");
    expect(result.alerts).toEqual([]);
    expect(result).not.toHaveProperty("coverage");
    expect(result).not.toHaveProperty("sourceSelection");
    expect(result).not.toHaveProperty("resolved");
  });

  it("avoids HTTP without a credential and reports unavailable separately from empty alerts", async () => {
    const fetch = vi.fn<SourceFetch>();
    expect(await new DependabotSource(fetch, "", now).read("example")).toEqual({ status: "unavailable", reason: "credential_not_supplied" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([403, 404])("records initial %s as unavailable, not proof of grant absence or empty coverage", async status => {
    const fetch = vi.fn<SourceFetch>(async () => new Response(null, { status }));
    expect(await new DependabotSource(fetch, "fixture-token", now).read("example"))
      .toEqual({ status: "unavailable", reason: `http_${status}` });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([
    [403, { "x-ratelimit-remaining": "0" }], [403, { "retry-after": "60" }], [429, {}],
  ] as Array<[number, Record<string, string>]>) ("holds rate-limited %s instead of permission fallback", async (status, headers) => {
    const fetch = vi.fn<SourceFetch>(async () => new Response(null, { status, headers }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("dependabot_rate_limited");
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([401, 304, 422, 500])("holds HTTP %s with no retries", async status => {
    const fetch = vi.fn<SourceFetch>(async () => new Response(null, { status }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow(`dependabot_http_${status}`);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each([403, 404, 500])("never returns a partial alert set after page failure %s", async status => {
    const fetch = vi.fn<SourceFetch>(async url => url === firstUrl ? json([dependabotAlert()], { link: link() }) : new Response(null, { status }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow(`dependabot_http_${status}`);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it.each([
    "https://evil.invalid/alerts?after=x", next().replace("/orgs/example/", "/orgs/other/"),
    next().replace("direction=asc", "direction=desc"), `${next()}&state=open`, `${next()}&after=other`,
    `${next()}#fragment`, next().replace("api.github.com", "user@api.github.com"), firstUrl,
  ])("rejects an unbound next URL before sending credentials: %s", async url => {
    const fetch = vi.fn<SourceFetch>(async () => json([dependabotAlert()], { link: link(url) }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("unbound_dependabot_pagination");
    expect(fetch).toHaveBeenCalledOnce();
  });

  it.each(["broken", `${link()}, ${link()}`, "<https://api.github.com>; rel=next", "<https://api.github.com>; rel=\"unknown\""])
    ("holds malformed or repeated link relations: %s", async header => {
      await expect(new DependabotSource(async () => json([dependabotAlert()], { link: header }), "fixture-token", now).read("example"))
        .rejects.toThrow("invalid_dependabot_pagination");
    });

  it("detects cursor cycles before another request", async () => {
    let calls = 0;
    const fetch = vi.fn<SourceFetch>(async () => json([dependabotAlert(++calls)], { link: link() }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("dependabot_pagination_cycle");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("holds duplicate alerts across pages, including changed duplicates", async () => {
    const fetch: SourceFetch = async url => url === firstUrl ? json([dependabotAlert()], { link: link() })
      : json([{ ...dependabotAlert(), state: "dismissed" }]);
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("duplicate_dependabot_alert");
  });

  it("keeps alert numbers scoped to their repository", async () => {
    const raw = dependabotAlert(); raw.repository.full_name = "example/other";
    expect(validateDependabotSnapshot(await snapshot([dependabotAlert(), raw]))).toHaveLength(2);
  });

  it.each([{}, { error: "unavailable" }, Array.from({ length: 101 }, () => dependabotAlert())])("holds invalid page shape/capacity", async raw => {
    await expect(snapshot(raw as unknown[])).rejects.toThrow("invalid_dependabot_page");
  });

  it("holds empty pages with next cursors and page exhaustion", async () => {
    await expect(new DependabotSource(async () => json([], { link: link() }), "fixture-token", now).read("example"))
      .rejects.toThrow("empty_dependabot_page_with_cursor");
    let calls = 0;
    const fetch = vi.fn<SourceFetch>(async () => json([dependabotAlert(++calls)], { link: link(next(String(calls))) }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("dependabot_page_capacity");
    expect(fetch).toHaveBeenCalledTimes(20);
  });

  it.each([
    ["foreign repository", (r: any) => { r.repository.full_name = "other/project"; }, "dependabot_organization_mismatch"],
    ["bad number", (r: any) => { r.number = 0; }, "invalid_dependabot_alert_identity"],
    ["unknown state", (r: any) => { r.state = "safe"; }, "invalid_dependabot_alert_identity"],
    ["future revision", (r: any) => { r.updated_at = "2026-12-01T00:00:00Z"; }, "future_dependabot_revision"],
    ["backwards revision", (r: any) => { r.updated_at = "2026-10-01T00:00:00Z"; }, "invalid_dependabot_time_order"],
    ["wrong package", (r: any) => { r.security_vulnerability.package.name = "other"; }, "dependabot_package_mismatch"],
    ["unknown scope", (r: any) => { r.dependency.scope = "dev"; }, "invalid_dependabot_dependency_context"],
    ["unknown relationship", (r: any) => { r.dependency.relationship = "indirect"; }, "invalid_dependabot_dependency_context"],
    ["path traversal", (r: any) => { r.dependency.manifest_path = "../secret"; }, "invalid_dependabot_manifest"],
    ["absolute path", (r: any) => { r.dependency.manifest_path = "/package.json"; }, "invalid_dependabot_manifest"],
    ["bad GHSA", (r: any) => { r.security_advisory.ghsa_id = "GHSA-bad"; }, "invalid_dependabot_ghsa"],
    ["bad CVE", (r: any) => { r.security_advisory.cve_id = "MAL-fixture"; }, "invalid_dependabot_cve"],
    ["bad identifier", (r: any) => { r.security_advisory.identifiers[0].value = "GHSA-xxxx-xxxx-xxxx"; }, "invalid_dependabot_identifier"],
    ["unknown severity", (r: any) => { r.security_vulnerability.severity = "none"; }, "invalid_dependabot_severity"],
    ["unbound selected vulnerability", (r: any) => { r.security_advisory.vulnerabilities = []; }, "dependabot_advisory_vulnerability_mismatch"],
    ["bad patch", (r: any) => { r.security_vulnerability.first_patched_version = {}; }, "invalid_dependabot_patch"],
  ] as Array<[string, (row: any) => void, string]>) ("holds %s", async (_name, mutate, code) => {
    const raw = dependabotAlert(); mutate(raw);
    await expect(snapshot([raw])).rejects.toThrow(code);
  });

  it("retains null context/unfixed/withdrawn and sub-millisecond advisory revisions without inference", async () => {
    const raw: any = dependabotAlert();
    raw.dependency.scope = null; raw.dependency.relationship = null;
    raw.security_vulnerability.first_patched_version = null;
    raw.security_advisory.vulnerabilities = [structuredClone(raw.security_vulnerability)];
    raw.security_advisory.cve_id = null; raw.security_advisory.identifiers = [];
    raw.security_advisory.updated_at = "2026-11-03T00:00:00.123456Z";
    raw.security_advisory.withdrawn_at = "2026-11-03T00:00:00Z";
    const [value] = validateDependabotSnapshot(await snapshot([raw]));
    expect(value!.scope).toBeNull();
    expect(value!.relationship).toBeNull();
    expect(value!.firstPatchedVersion).toBeNull();
    expect(value!.advisory.updatedAt).toBe(raw.security_advisory.updated_at);
    expect(value!.advisory.withdrawnAt).toBe(raw.security_advisory.withdrawn_at);
  });

  it("preserves missing optional scope/relationship as unknown, never development or direct", async () => {
    const raw: any = dependabotAlert();
    delete raw.dependency.scope; delete raw.dependency.relationship;
    const [value] = validateDependabotSnapshot(await snapshot([raw]));
    expect(value!.scope).toBeNull();
    expect(value!.relationship).toBeNull();
  });

  it("revalidates raw hash, page-chain completeness and query interval on replay", async () => {
    const original = await snapshot();
    const changed = structuredClone(original); (changed.pages[0]!.alerts[0] as any).state = "fixed";
    expect(() => validateDependabotSnapshot(changed)).toThrow("dependabot_snapshot_mismatch");
    const incomplete = structuredClone(original); incomplete.pages[0]!.link = link();
    expect(() => validateDependabotSnapshot(rehash(incomplete))).toThrow("incomplete_dependabot_pagination");
    const unbound = structuredClone(original); unbound.pages[0]!.url = next();
    expect(() => validateDependabotSnapshot(rehash(unbound))).toThrow("dependabot_page_chain_mismatch");
    const expired = structuredClone(original); expired.completedAt = "2026-11-04T08:05:00Z";
    expect(() => validateDependabotSnapshot(rehash(expired))).toThrow("invalid_dependabot_query_interval");
  });

  it.each(["../example", "example/other", "https://evil.invalid", "example--org", "-example"])
    ("rejects invalid organization input before HTTP: %s", async org => {
      const fetch = vi.fn<SourceFetch>();
      await expect(new DependabotSource(fetch, "fixture-token", now).read(org)).rejects.toThrow("invalid_dependabot_organization");
      expect(fetch).not.toHaveBeenCalled();
    });

  it("bounds individual response bytes and aggregate retained raw evidence", async () => {
    const large = { ...dependabotAlert(), description: "x".repeat(4 * 1024 * 1024) };
    await expect(snapshot([large])).rejects.toThrow("response_too_large");
    let calls = 0;
    const fetch = vi.fn<SourceFetch>(async () => json([{ ...dependabotAlert(++calls), description: "x".repeat(3 * 1024 * 1024) }],
      { link: link(next(String(calls))) }));
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("dependabot_snapshot_capacity");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("holds invalid JSON rather than treating it as an empty response", async () => {
    await expect(new DependabotSource(async () => new Response("not-json"), "fixture-token", now).read("example"))
      .rejects.toThrow("invalid_json");
  });

  it("sanitizes transport failures without retrying or exposing credentials", async () => {
    const fetch = vi.fn<SourceFetch>(async () => { throw new Error("fixture-token and provider data"); });
    await expect(new DependabotSource(fetch, "fixture-token", now).read("example")).rejects.toThrow("Source requires attention: transport_failed");
    expect(fetch).toHaveBeenCalledOnce();
  });
});
