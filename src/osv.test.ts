import { describe, expect, it, vi } from "vitest";
import { decide } from "./matcher.js";
import { canonicalJson, sha256 } from "./identity.js";
import { OsvSource, osvFindingInputs, parseOsvRecord, type OsvDependency } from "./osv.js";
import { sourceBudget, sourceRequest, timestamp, type SourceFetch } from "./source-http.js";
import type { OsvRange } from "./ranges.js";

const modified = "2026-11-03T00:00:00.000Z";
const observedAt = "2026-11-04T04:00:00.000Z";
const dep: OsvDependency = { ecosystem: "npm", package: "example", version: "1.2.0" };
const context = { repo: "example/repo", artifactDigest: `sha256:${"a".repeat(64)}`, observedAt };
const now = () => new Date(observedAt);
const advisory = (id = "GHSA-example") => ({
  id, modified, aliases: [] as string[], database_specific: { severity: "HIGH" },
  affected: [{ package: { ecosystem: "npm", name: "example" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] as OsvRange["events"] }] }],
});
const json = (data: unknown) => new Response(JSON.stringify(data));
function transport(responses: Array<unknown | Response>) {
  return vi.fn<SourceFetch>(async () => {
    if (!responses.length) throw new Error("Unexpected request");
    const response = responses.shift();
    return response instanceof Response ? response : json(response);
  });
}
const batch = (id = "GHSA-example") => ({ results: [{ vulns: [{ id, modified }] }] });

async function snapshot(raw = advisory()) {
  return new OsvSource(transport([batch(raw.id), raw]), now).query([dep]);
}

describe("bounded OSV source ingestion", () => {
  it("hydrates revisions, retains hashes, and builds conservative matcher inputs", async () => {
    const result = await snapshot();
    const [input] = osvFindingInputs(result, context);
    expect(input!.versionEvidence.status).toBe("affected");
    expect(input!.scope).toBe("unknown");
    expect(input!.fixedVersion).toBeNull();
    expect(input!.compatibleFixVerified).toBe(false);
    expect(input!.functions).toBeNull();
    expect(input!.provenance.source).toEqual({ kind: "osv", queriedAt: observedAt, snapshotSha256: result.snapshotSha256 });
    expect(input!.provenance.artifactKind).toBe("lockfile");
    expect(result.records[0]!.rawSha256).toBe(sha256(canonicalJson(advisory())));
    expect(decide(input!).priority).toBe(2);
    expect(decide(input!).identity.aliases).toEqual(["GHSA-example"]);
  });

  it("makes no source calls for an empty inventory", async () => {
    const fetch = transport([]);
    const result = await new OsvSource(fetch, now).query([]);
    expect(fetch).not.toHaveBeenCalled();
    expect(osvFindingInputs(result, context)).toEqual([]);
    expect(result).not.toHaveProperty("complete");
  });

  it("deduplicates inventories and deterministically hashes identical observations", async () => {
    const fetch = transport([batch(), advisory()]);
    const first = await new OsvSource(fetch, now).query([dep, dep]);
    expect(JSON.parse(fetch.mock.calls[0]![1].body as string).queries).toHaveLength(1);
    expect(first).toEqual(await snapshot());
  });

  it("chunks requests and hydrates a shared advisory only once", async () => {
    const dependencies = Array.from({ length: 101 }, (_, n) => ({ ...dep, version: `1.2.${n}` }));
    const fetch = transport([
      { results: Array.from({ length: 100 }, () => ({ vulns: [{ id: "GHSA-example", modified }] })) },
      batch(), advisory(),
    ]);
    const result = await new OsvSource(fetch, now).query(dependencies);
    expect(result.observations).toHaveLength(101);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(result.records).toHaveLength(1);
  });

  it("keeps per-query pagination associated with the correct package", async () => {
    const fetch = transport([
      { results: [{ next_page_token: "token1", vulns: [{ id: "GHSA-example", modified }] }, {}] },
      { results: [{ vulns: [{ id: "MAL-example", modified }] }] }, advisory(), { ...advisory("MAL-example"), aliases: ["GHSA-example"] },
    ]);
    const result = await new OsvSource(fetch, now).query([dep, { ...dep, package: "z-other" }]);
    expect(result.observations[0]!.advisoryIds).toEqual(["GHSA-example", "MAL-example"]);
    expect(result.observations[1]!.advisoryIds).toEqual([]);
    const page = JSON.parse(fetch.mock.calls[1]![1].body as string).queries;
    expect(page).toEqual([{ package: { name: "example", ecosystem: "npm" }, version: "1.2.0", page_token: "token1" }]);
    // Connected records produce one grouped finding, elevated by MAL.
    expect(osvFindingInputs(result, context).map(input => decide(input).priority)).toEqual([0]);
  });

  it.each(["withdrawn", "outside", "unknown"])("does not let an alias's %s record erase an active affected source", async kind => {
    const first = {
      ...advisory("GHSA-a"), aliases: ["GHSA-b"], ...(kind === "withdrawn" ? { withdrawn: modified } : {}),
      affected: kind === "outside" ? [{ ...advisory().affected[0]!, versions: ["0.5.0"], ranges: [] }]
        : kind === "unknown" ? [] : advisory().affected,
    };
    const second = { ...advisory("GHSA-b"), database_specific: { severity: "CRITICAL" } };
    const fetch = transport([{ results: [{ vulns: [{ id: first.id, modified }, { id: second.id, modified }] }] }, first, second]);
    const result = await new OsvSource(fetch, now).query([dep]);
    const inputs = osvFindingInputs(result, context);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]!.versionEvidence.status).toBe("affected");
    expect(inputs[0]!.severity).toBe("critical");
    expect(decide(inputs[0]!).applicability).not.toBe("dropped");
    expect(decide(inputs[0]!).identity.aliases).toEqual(["GHSA-a", "GHSA-b"]);
  });

  it("requires every active alias source to prove outside before dropping a group", async () => {
    const first = { ...advisory("GHSA-a"), aliases: ["GHSA-b"], affected: [] };
    const second = { ...advisory("GHSA-b"), affected: [{ ...advisory().affected[0]!, ranges: [], versions: ["0.5.0"] }] };
    const fetch = transport([{ results: [{ vulns: [{ id: first.id, modified }, { id: second.id, modified }] }] }, first, second]);
    const inputs = osvFindingInputs(await new OsvSource(fetch, now).query([dep]), context);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]!.versionEvidence.status).toBe("unknown");
    expect(decide(inputs[0]!).applicability).toBe("unknown");
  });

  it("rejects pagination cycles", async () => {
    const fetch = transport([{ results: [{ next_page_token: "loop" }] }, { results: [{ next_page_token: "loop" }] }]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("pagination_cycle");
  });

  it("bounds pagination even with distinct tokens", async () => {
    const fetch = transport(Array.from({ length: 20 }, (_, n) => ({ results: [{ next_page_token: `token${n}` }] })));
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("pagination_capacity");
    expect(fetch).toHaveBeenCalledTimes(20);
  });

  it.each([403, 404, 429, 500])("never treats batch HTTP %s as no findings", async status => {
    const fetch = transport([new Response(null, { status })]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow(`osv_batch_http_${status}`);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([404, 429, 500])("holds missing/failed detail HTTP %s", async status => {
    await expect(new OsvSource(transport([batch(), new Response(null, { status })]), now).query([dep]))
      .rejects.toThrow(`osv_detail_http_${status}`);
  });

  it.each([
    [{}, "invalid_batch_results"],
    [{ results: [] }, "batch_length_mismatch"],
    [{ results: [null] }, "invalid_batch_result"],
    [{ results: [{ error: "failed" }] }, "batch_query_error"],
    [{ results: [{ vulns: "no" }] }, "invalid_batch_vulns"],
    [{ results: [{ vulns: null }] }, "invalid_batch_vulns"],
    [{ results: [{ status: "failed" }] }, "unrecognized_batch_result"],
    [{ results: [{ vulns: [{ id: "GHSA-x" }] }] }, "missing_batch_revision"],
    [{ results: [{ vulns: [{ id: "../path", modified }] }] }, "invalid_advisory_id"],
    [{ results: [{ vulns: [{ id: "GHSA-x", modified: "yesterday" }] }] }, "missing_batch_revision"],
    [{ results: [{ next_page_token: null }] }, "invalid_page_token"],
  ])("rejects malformed batches %#", async (body, error) => {
    await expect(new OsvSource(transport([body]), now).query([dep])).rejects.toThrow(error as string);
  });

  it("holds a feed that changes between batch and detail", async () => {
    await expect(snapshot({ ...advisory(), modified: "2026-11-03T01:00:00Z" })).rejects.toThrow("advisory_changed_during_query");
  });

  it("holds conflicting revisions across batch pages", async () => {
    const fetch = transport([
      { results: [{ vulns: [{ id: "GHSA-example", modified }], next_page_token: "next" }] },
      { results: [{ vulns: [{ id: "GHSA-example", modified: observedAt }] }] },
    ]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("advisory_changed_during_query");
  });

  it("rejects mismatched detail identity", async () => {
    await expect(new OsvSource(transport([batch(), advisory("GHSA-other")]), now).query([dep]))
      .rejects.toThrow("advisory_id_mismatch");
  });

  it.each(["modified", "withdrawn"])("holds future %s timestamps", async field => {
    const raw = { ...advisory(), [field]: "2030-01-01T00:00:00Z" };
    const fetch = transport([{ results: [{ vulns: [{ id: raw.id, modified: raw.modified }] }] }, raw]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("future_advisory_revision");
  });

  it.each([
    { aliases: [false] }, { aliases: null }, { upstream: "GHSA-other" }, { affected: {} }, { affected: null },
    { affected: [{ package: {} }] },
    { affected: [{ package: { name: "example", ecosystem: "npm" }, versions: [false] }] },
    { affected: [{ package: { name: "example", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0", fixed: "2.0.0" }] }] }] },
  ])("rejects malformed advisory data %#", async change => {
    await expect(snapshot({ ...advisory(), ...change } as ReturnType<typeof advisory>)).rejects.toThrow("Source requires attention");
  });

  it("can prove npm range exclusion only from supported validated data", async () => {
    const result = await snapshot();
    result.observations[0]!.dependency.version = "2.0.0";
    const { snapshotSha256: _, ...content } = result;
    result.snapshotSha256 = sha256(canonicalJson(content));
    expect(decide(osvFindingInputs(result, context)[0]!).applicability).toBe("dropped");
  });

  it.each([
    [{ introduced: "0" }, { fixed: "v1.0.0" }],
    [{ introduced: "0" }, { fixed: "1.0" }],
    [{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "1.1.0" }, { last_affected: "1.1.1" }],
  ])("malformed range evidence cannot reach rule 1 after raw-source replay: %j", async (...events) => {
    const raw = advisory();
    raw.affected[0]!.ranges[0]!.events = events;
    const result = await snapshot(raw);
    const before = structuredClone(result);
    const input = osvFindingInputs(result, context)[0]!;
    expect(input.versionEvidence).toMatchObject({ status: "unknown", complete: false });
    expect(input.provenance.toolVersions["vuln-sentinel-osv-ranges"]).toBe("1.1.0");
    expect(decide(input)).toMatchObject({ applicability: "unknown", matchedRule: 8 });
    expect(osvFindingInputs(result, context)).toEqual([input]);
    expect(result).toEqual(before);
  });

  it("replays range-wide limit constraints without inferring a fix or resolution", async () => {
    const raw = advisory();
    raw.affected[0]!.ranges[0]!.events = [{ introduced: "0" }, { limit: "*" }, { limit: "1.0.0" }];
    const input = osvFindingInputs(await snapshot(raw), context)[0]!;
    expect(input.versionEvidence.status).toBe("affected");
    expect(input.fixedVersion).toBeNull();
    expect(input.compatibleFixVerified).toBe(false);
    expect(input.scope).toBe("unknown");
    expect(decide(input).applicability).not.toBe("dropped");
  });

  it("keeps unsupported ecosystem ranges unknown and never invents runtime evidence", async () => {
    const raw = advisory();
    raw.affected[0]!.package.ecosystem = "crates.io";
    const result = await new OsvSource(transport([batch(), raw]), now).query([{ ...dep, ecosystem: "crates.io" }]);
    const input = osvFindingInputs(result, context)[0]!;
    expect(input.versionEvidence.status).toBe("unknown");
    expect(decide(input).applicability).toBe("unknown");
    expect(input.platform).toBeNull();
    expect(input.go).toBeNull();
  });

  it("does not infer outside from an advisory with no matching package", async () => {
    const raw = advisory();
    raw.affected[0]!.package.name = "other";
    expect(osvFindingInputs(await snapshot(raw), context)[0]!.versionEvidence.status).toBe("unknown");
  });

  it("retains validated withdrawal for rule 1", async () => {
    const raw = { ...advisory(), withdrawn: modified };
    const result = await snapshot(raw);
    expect(decide(osvFindingInputs(result, context)[0]!).applicability).toBe("dropped");
  });

  it.each([
    { ...dep, ecosystem: "unknown" }, { ...dep, package: "bad|name" },
    { ...dep, version: "" }, { ...dep, version: "1\n2" },
  ])("rejects invalid query inventory before contacting providers %#", async bad => {
    const fetch = transport([]);
    await expect(new OsvSource(fetch, now).query([bad as OsvDependency])).rejects.toThrow("Source requires attention");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds finding associations before fetching any advisory detail", async () => {
    const fetch = transport([{ results: [{ vulns: Array.from({ length: 2001 }, (_, n) => ({ id: `GHSA-${n}`, modified })) }] }]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("finding_capacity");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("bounds retained raw evidence instead of silently truncating a snapshot", async () => {
    const rows = Array.from({ length: 3 }, (_, n) => ({ ...advisory(`GHSA-${n}`), details: "x".repeat(3 * 1024 * 1024) }));
    const fetch = transport([{ results: [{ vulns: rows.map(({ id, modified }) => ({ id, modified })) }] }, ...rows]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("snapshot_capacity");
  });

  it("does not collapse distinct sub-millisecond advisory revisions", async () => {
    const first = "2026-11-03T00:00:00.123456Z";
    const second = "2026-11-03T00:00:00.123457Z";
    const fetch = transport([{ results: [{ vulns: [{ id: "GHSA-example", modified: first }] }] }, { ...advisory(), modified: second }]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("advisory_changed_during_query");
  });

  it("bounds inventory before contacting providers", async () => {
    const fetch = transport([]);
    await expect(new OsvSource(fetch, now).query(Array.from({ length: 2001 }, () => dep))).rejects.toThrow("inventory_capacity");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not accept a mutated snapshot or unbound artifact/time", async () => {
    const result = await snapshot();
    await expect(Promise.resolve().then(() => osvFindingInputs(result, { ...context, artifactDigest: "mutable-tag" })))
      .rejects.toThrow("invalid_artifact_digest");
    expect(() => osvFindingInputs(result, { ...context, observedAt: modified })).toThrow("observation_before_query");
    result.records[0]!.withdrawn = modified;
    expect(() => osvFindingInputs(result, context)).toThrow("snapshot_hash_mismatch");
  });

  it("retains unknown rather than guessing severity from a CVSS vector", () => {
    expect(parseOsvRecord({ ...advisory(), database_specific: {}, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N" }] }, "GHSA-example").severity)
      .toBe("unknown");
  });
});

describe("recursive OSV alias/upstream hydration", () => {
  it("walks transitive aliases and upstream with shared-node/cycle deduplication", async () => {
    const a = { ...advisory(), aliases: ["CVE-2026-1234"], upstream: ["RUSTSEC-example"] };
    const b = { ...advisory("CVE-2026-1234"), aliases: [a.id], upstream: ["GO-example"] };
    const c = { ...advisory("RUSTSEC-example"), aliases: [b.id], upstream: ["GO-example"] };
    const d = { ...advisory("GO-example"), aliases: [a.id], upstream: ["MAL-example"] };
    const fetch = transport([batch(), a, b, c, d, advisory("MAL-example")]);
    const result = await new OsvSource(fetch, now).query([dep]);
    expect(fetch.mock.calls.slice(1).map(([url]) => url.split("/").at(-1))).toEqual([a.id, b.id, c.id, d.id, "MAL-example"]);
    expect(result.unavailableIds).toEqual([]);
    expect(result.records).toHaveLength(5);
    const inputs = osvFindingInputs(result, context);
    expect(inputs).toHaveLength(1);
    expect(decide(inputs[0]!).priority).toBe(0);
    expect(decide(inputs[0]!).identity.aliasGroup).toBe("CVE-2026-1234");
    expect(result.observations[0]!.advisoryIds).toEqual([a.id]);
  });

  it.each(["outside", "withdrawn"])("an unavailable alias cannot certify %s", async kind => {
    const a = { ...advisory(), aliases: ["CVE-2026-1234"],
      ...(kind === "withdrawn" ? { withdrawn: modified } : { affected: [{ ...advisory().affected[0]!, ranges: [], versions: ["0.1.0"] }] }),
    };
    const fetch = transport([batch(), a, new Response(null, { status: 404 })]);
    const result = await new OsvSource(fetch, now).query([dep]);
    expect(result.unavailableIds).toEqual(["CVE-2026-1234"]);
    const input = osvFindingInputs(result, context)[0]!;
    expect(input.versionEvidence.status).toBe("unknown");
    expect(decide(input).applicability).toBe("unknown");
    expect(input.aliases.find(row => row.id === "CVE-2026-1234")!.modified).toBeNull();
  });

  it("retains an affected source despite a missing alias document", async () => {
    const result = await new OsvSource(transport([batch(), { ...advisory(), aliases: ["CVE-2026-1234"] }, new Response(null, { status: 404 })]), now).query([dep]);
    expect(osvFindingInputs(result, context)[0]!.versionEvidence.status).toBe("affected");
  });

  it("a hydrated active upstream prevents a withdrawn root from dropping the group", async () => {
    const result = await new OsvSource(transport([batch(), { ...advisory(), withdrawn: modified, upstream: ["MAL-example"] }, advisory("MAL-example")]), now).query([dep]);
    expect(decide(osvFindingInputs(result, context)[0]!).matchedRule).toBe(2);
  });

  it.each([403, 429, 500])("holds transitive HTTP %s instead of returning partial records", async status => {
    const fetch = transport([batch(), { ...advisory(), aliases: ["CVE-2026-1234"] }, new Response(null, { status })]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow(`osv_detail_http_${status}`);
  });

  it("rejects future revisions in transitively fetched records", async () => {
    const fetch = transport([batch(), { ...advisory(), upstream: ["GO-example"] }, { ...advisory("GO-example"), modified: "2030-01-01T00:00:00Z" }]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("future_advisory_revision");
  });

  it("bounds discovered identifiers before fetching their documents", async () => {
    const fetch = transport([batch(), { ...advisory(), aliases: Array.from({ length: 2_000 }, (_, n) => `CVE-2026-${n + 1000}`) }]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("alias_capacity");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("shares the original query deadline/request budget through recursive traversal", async () => {
    const rows = Array.from({ length: 127 }, (_, n) => ({ ...advisory(n === 0 ? "GHSA-example" : `GHSA-${n}`), upstream: [`GHSA-${n + 1}`] }));
    const fetch = transport([batch(), ...rows]);
    await expect(new OsvSource(fetch, now).query([dep])).rejects.toThrow("query_budget_exhausted");
    expect(fetch).toHaveBeenCalledTimes(128);
  });

  it.each(["omitted", "unreferenced", "root404", "duplicate"])("rejects rehashed %s hydration evidence", async kind => {
    const result = await snapshot();
    if (kind === "omitted") {
      const raw = { ...advisory(), aliases: ["CVE-2026-1234"] };
      result.records[0] = parseOsvRecord(raw, raw.id);
    }
    if (kind === "unreferenced") result.records.push(parseOsvRecord(advisory("GHSA-orphan"), "GHSA-orphan"));
    if (kind === "root404") { result.records = []; result.unavailableIds = ["GHSA-example"]; }
    if (kind === "duplicate") result.unavailableIds = ["GHSA-example"];
    const { snapshotSha256: _, ...content } = result;
    result.snapshotSha256 = sha256(canonicalJson(content));
    expect(() => osvFindingInputs(result, context)).toThrow("Source requires attention");
  });
});

describe("source HTTP containment", () => {
  it("preserves sub-millisecond revision changes and rejects impossible calendar dates", () => {
    const precise = "2026-11-03T00:00:00.123456Z";
    expect(timestamp(precise, "invalid_date")).toBe(precise);
    expect(() => timestamp("2026-02-30T00:00:00Z", "invalid_date")).toThrow("invalid_date");
    expect(() => timestamp("2026-11-03T24:00:00Z", "invalid_date")).toThrow("invalid_date");
  });

  it("bounds total calls independently of pagination and inventory size", async () => {
    const fetch = transport(Array.from({ length: 128 }, () => ({})));
    const request = sourceBudget(fetch);
    for (let n = 0; n < 128; n++) await request("https://api.osv.dev/v1/querybatch", {});
    expect(() => request("https://api.osv.dev/v1/querybatch", {})).toThrow("query_budget_exhausted");
    expect(fetch).toHaveBeenCalledTimes(128);
  });

  it("bounds the whole scan's elapsed time, not just individual requests", () => {
    vi.useFakeTimers();
    try {
      const fetch = transport([]);
      const request = sourceBudget(fetch);
      vi.advanceTimersByTime(240_000);
      expect(() => request("https://api.osv.dev", {})).toThrow("query_budget_exhausted");
      expect(fetch).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("uses a bounded deadline, refuses redirects, and never sends GitHub credentials to OSV", async () => {
    const fetch = transport([{}]);
    await sourceRequest(fetch, "https://api.osv.dev/v1/querybatch", { method: "POST" });
    expect(fetch.mock.calls[0]![1]).toMatchObject({ redirect: "error", method: "POST" });
    expect(fetch.mock.calls[0]![1].signal).toBeInstanceOf(AbortSignal);
    expect(fetch.mock.calls[0]![1].headers).toBeUndefined();
  });

  it("rejects malformed JSON and oversized streamed responses", async () => {
    await expect(sourceRequest(transport([new Response("{")]), "https://api.osv.dev", {})).rejects.toThrow("invalid_json");
    await expect(sourceRequest(transport([new Response("12345")]), "https://api.osv.dev", {}, 4)).rejects.toThrow("response_too_large");
  });

  it("does not expose credentials or provider text in transport errors", async () => {
    const fetch: SourceFetch = async () => { throw new Error("secret bearer token"); };
    await expect(sourceRequest(fetch, "https://api.osv.dev", {})).rejects.toThrow("transport_failed");
  });

  it("bounds a transport that ignores cancellation", async () => {
    vi.useFakeTimers();
    try {
      const fetch: SourceFetch = () => new Promise(() => undefined);
      const request = expect(sourceRequest(fetch, "https://api.osv.dev", {})).rejects.toThrow("request_timeout");
      await vi.advanceTimersByTimeAsync(30_000);
      await request;
    } finally {
      vi.useRealTimers();
    }
  });
});
