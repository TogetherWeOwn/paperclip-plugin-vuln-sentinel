import { describe, expect, it } from "vitest";
import { canonicalJson, sha256 } from "./identity.js";
import { observeOsvFixes, OSV_FIXES_VERSION } from "./osv-fixes.js";
import { osvFindingInputs, parseOsvRecord, type OsvDependency, type OsvSnapshot } from "./osv.js";
import { OSV_RANGES_VERSION, type OsvAffected, type OsvRange } from "./ranges.js";

const dep: OsvDependency = { ecosystem: "npm", package: "example", version: "1.0.0" };
const pkg = { ecosystem: dep.ecosystem, name: dep.package };
const modified = "2026-11-03T00:00:00.000Z";
const queriedAt = "2026-11-04T00:00:00.000Z";
const range = (events: OsvRange["events"], type = "SEMVER"): OsvRange => ({ type, events });
const closed = (fixed = "1.1.0") => range([{ introduced: "0" }, { fixed }]);
const affected = (ranges = [closed()]): OsvAffected => ({ package: pkg, ranges });
function raw(id = "GHSA-a", rows = [affected()], aliases: string[] = []) {
  return { id, modified, affected: rows, aliases };
}
function snapshot(raws: Record<string, unknown>[] = [raw()], unavailableIds: string[] = [], dependency = dep): OsvSnapshot {
  const content = {
    queriedAt, unavailableIds, records: raws.map(row => parseOsvRecord(row, row.id as string)),
    observations: [{ dependency, advisoryIds: [raws[0]!.id as string] }],
  };
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}
function rehash(value: OsvSnapshot): OsvSnapshot {
  const { snapshotSha256: _, ...content } = value;
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}
const first = (value = snapshot()) => observeOsvFixes(value, value.observations[0]!.dependency).groups[0]!;

describe("offline retained OSV fix observations", () => {
  it("binds a reported boundary to exact immutable source revisions, without verifying compatibility", () => {
    const source = snapshot();
    const result = observeOsvFixes(source, dep);
    expect(result).toMatchObject({
      version: OSV_FIXES_VERSION, rangeEvaluatorVersion: OSV_RANGES_VERSION, status: "attention", dependency: dep,
      compatibleFixVerified: false, source: { queriedAt, snapshotSha256: source.snapshotSha256 },
      attention: ["manifest_compatibility_not_verified", "release_availability_not_verified", "reported_ranges_not_remediation"],
    });
    expect(result.groups[0]).toEqual({
      aliasGroup: "GHSA-a", aliases: ["GHSA-a"], attention: [],
      records: [{ id: "GHSA-a", modified, withdrawn: null, rawSha256: source.records[0]!.rawSha256 }],
      candidates: [{ version: "1.1.0", reportedBy: ["GHSA-a"], status: "outside_reported_ranges",
        sources: [{ id: "GHSA-a", status: "outside" }] }],
    });
  });

  it("retains an alias disagreement and only marks the later boundary outside all reported ranges", () => {
    const result = first(snapshot([raw("GHSA-a", [affected()], ["GHSA-b"]), raw("GHSA-b", [affected([closed("1.2.0")])])]));
    expect(result.candidates.map(row => [row.version, row.status])).toEqual([
      ["1.1.0", "still_affected"], ["1.2.0", "outside_reported_ranges"],
    ]);
    expect(result.candidates[0]!.sources).toEqual([{ id: "GHSA-a", status: "outside" }, { id: "GHSA-b", status: "affected" }]);
    expect(result.attention).toContain("candidate_not_excluded_by_all_active_sources");
  });

  it.each(["unavailable", "unsupported", "missing"])('keeps %s alias evidence unknown', kind => {
    const other = kind === "unsupported" ? [affected([range([{ introduced: "0" }, { fixed: "1.1.0" }], "ECOSYSTEM")])]
      : [];
    const source = snapshot([raw("GHSA-a", [affected()], ["GHSA-b"]),
      ...(kind === "unavailable" ? [] : [raw("GHSA-b", other)])], kind === "unavailable" ? ["GHSA-b"] : []);
    expect(first(source).candidates[0]!.status).toBe("unknown");
    expect(first(source).candidates[0]!.sources).toContainEqual({ id: "GHSA-b", status: "unknown" });
  });

  it("does not let unknown aliases erase another alias's positive candidate conflict", () => {
    const source = snapshot([raw("GHSA-a", [affected()], ["GHSA-b", "GHSA-c"]),
      raw("GHSA-b", [affected([closed("1.2.0")])])], ["GHSA-c"]);
    expect(first(source).candidates[0]!.status).toBe("still_affected");
    expect(first(source).candidates[1]!.status).toBe("unknown");
  });

  it("ignores withdrawn boundary/conflict data but preserves its immutable revision", () => {
    const source = snapshot([raw("GHSA-a", [affected()], ["GHSA-b"]),
      { ...raw("GHSA-b", [affected([closed("2.0.0")])]), withdrawn: modified }]);
    const result = first(source);
    expect(result.candidates.map(row => row.version)).toEqual(["1.1.0"]);
    expect(result.candidates[0]!.status).toBe("outside_reported_ranges");
    expect(result.records[1]!.withdrawn).toBe(modified);
  });

  it("never turns an all-withdrawn group into a fixing version", () => {
    const result = first(snapshot([{ ...raw(), withdrawn: modified }]));
    expect(result.candidates).toEqual([]);
    expect(result.attention).toContain("no_active_reported_fix_source");
  });

  it("reads upstream closure and deduplicates shared fixed boundaries", () => {
    const source = snapshot([{ ...raw(), upstream: ["GHSA-b"] }, raw("GHSA-b")]);
    const result = first(source);
    expect(result.aliases).toEqual(["GHSA-a", "GHSA-b"]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.reportedBy).toEqual(["GHSA-a", "GHSA-b"]);
  });

  it("keeps disconnected finding groups separate, including a no-candidate group", () => {
    const source = snapshot([raw(), raw("GHSA-b", [])]);
    source.observations[0]!.advisoryIds.push("GHSA-b");
    const result = observeOsvFixes(rehash(source), dep);
    expect(result.groups.map(row => row.aliasGroup)).toEqual(["GHSA-a", "GHSA-b"]);
    expect(result.groups[1]!.candidates).toEqual([]);
  });

  it.each([
    [{ ...pkg, name: "other" }], [{ ...pkg, ecosystem: "PyPI" }],
  ])("does not borrow a boundary from an unrelated package %#", (other) => {
    const source = snapshot([raw("GHSA-a", [{ ...affected(), package: other }])]);
    expect(first(source).candidates).toEqual([]);
  });

  it("checks every matching affected row and explicit version, not only the reporting range", () => {
    const source = snapshot([raw("GHSA-a", [affected(), { package: pkg, versions: ["1.1.0"] }])]);
    expect(first(source).candidates[0]!.status).toBe("still_affected");
  });

  it("retains an unknown peer range in the same record", () => {
    const source = snapshot([raw("GHSA-a", [affected([closed(), range([{ introduced: "0" }], "GIT")])])]);
    expect(first(source).candidates[0]!.status).toBe("unknown");
  });

  it.each([
    [range([{ introduced: "0" }, { last_affected: "1.1.0" }])],
    [range([{ introduced: "0" }, { limit: "1.1.0" }])],
    [range([{ introduced: "0" }])],
    [range([{ introduced: "0" }, { fixed: "1.1.0" }], "ECOSYSTEM")],
    [range([{ fixed: "1.1.0" }])],
    [range([{ introduced: "0" }, { fixed: "1.1.0" }, { introduced: "1.2.0" }, { last_affected: "1.3.0" }])],
  ])("does not invent fixed boundaries from unsupported or non-fixing events %#", candidate => {
    expect(first(snapshot([raw("GHSA-a", [affected([candidate])])])).candidates).toEqual([]);
  });

  it("never guesses a fixed boundary from an enumeration", () => {
    expect(first(snapshot([raw("GHSA-a", [{ package: pkg, versions: ["1.0.0"] }])])).candidates).toEqual([]);
  });

  it("retains reintroductions and chooses no boundary that is still affected", () => {
    const events = [{ introduced: "0" }, { fixed: "1.1.0" }, { introduced: "1.1.0" }, { fixed: "1.2.0" }];
    expect(first(snapshot([raw("GHSA-a", [affected([range(events)])])])).candidates.map(row => row.version)).toEqual(["1.2.0"]);
  });

  it("does not claim a fixed version for a range that excludes the installed tuple", () => {
    expect(first(snapshot([raw("GHSA-a", [affected([closed("0.9.0")])])])).candidates).toEqual([]);
    expect(first(snapshot([raw("GHSA-a", [affected([range([{ introduced: "1.1.0" }, { fixed: "1.2.0" }])])])])).candidates).toEqual([]);
  });

  it.each(["v1.1.0", "1.1", "1.1.0-beta.1", "1.1.0+build"])('does not suggest unsupported boundary %s', fixed => {
    expect(first(snapshot([raw("GHSA-a", [affected([closed(fixed)])])])).candidates).toEqual([]);
  });

  it.each([
    { ...dep, ecosystem: "crates.io" as const }, { ...dep, ecosystem: "Go" as const }, { ...dep, ecosystem: "PyPI" as const },
    { ...dep, version: "v1.0.0" }, { ...dep, version: "1.0.0-beta.1" }, { ...dep, version: "1.0.0+build" },
  ])("withholds candidates in unsupported tuple context %#", dependency => {
    const result = first(snapshot([raw()], [], dependency));
    expect(result.candidates).toEqual([]);
    expect(result.attention).toContain("unsupported_fix_version_context");
  });

  it("sorts candidates by precedence rather than lexicographic order", () => {
    const result = first(snapshot([raw("GHSA-a", [affected([closed("1.10.0"), closed("1.2.0")])])]));
    expect(result.candidates.map(row => row.version)).toEqual(["1.2.0", "1.10.0"]);
    expect(result.candidates[0]!.status).toBe("still_affected");
  });

  it("returns empty observed groups as attention, never an absence or remediation receipt", () => {
    const source = snapshot();
    source.observations[0]!.advisoryIds = [];
    source.records = [];
    const result = observeOsvFixes(rehash(source), dep);
    expect(result.groups).toEqual([]);
    expect(result.status).toBe("attention");
    expect(result.compatibleFixVerified).toBe(false);
    expect(result).not.toHaveProperty("complete");
  });

  it("requires an exact queried tuple, including package case and installed version", () => {
    for (const dependency of [{ ...dep, version: "1.0.1" }, { ...dep, package: "Example" }, { ...dep, ecosystem: "Go" as const }]) {
      expect(() => observeOsvFixes(snapshot(), dependency)).toThrow("fix_dependency_not_queried");
    }
  });

  it("rejects corrupt raw/derived evidence and missing alias coverage even after rehashing", () => {
    const source = snapshot();
    source.records[0]!.affected = [];
    expect(() => first(rehash(source))).toThrow("osv_raw_record_mismatch");
    const missing = snapshot([raw("GHSA-a", [affected()], ["GHSA-b"])]);
    expect(() => first(missing)).toThrow("incomplete_alias_hydration");
    expect(() => first({ ...snapshot(), snapshotSha256: "0".repeat(64) })).toThrow("snapshot_hash_mismatch");
  });

  it("does not mutate snapshots, change matcher inputs, verify a fix or acquire any runtime port", async () => {
    const source = snapshot();
    const saved = structuredClone(source);
    const context = { repo: "example/repo", artifactDigest: `sha256:${"a".repeat(64)}`, observedAt: queriedAt };
    const inputs = osvFindingInputs(source, context);
    const results = await Promise.all(Array.from({ length: 8 }, async () => observeOsvFixes(source, dep)));
    expect(results.every(result => canonicalJson(result) === canonicalJson(results[0]))).toBe(true);
    results[0]!.groups[0]!.aliases.push("injected");
    expect(source).toEqual(saved);
    expect(osvFindingInputs(source, context)).toEqual(inputs);
    expect(inputs[0]).toMatchObject({ fixedVersion: null, compatibleFixVerified: false, scope: "unknown" });
  });

  it("is deterministic across alias/seed/record order without merging separate groups", () => {
    const source = snapshot([raw("GHSA-a", [affected()], ["GHSA-b"]), raw("GHSA-b")]);
    source.observations[0]!.advisoryIds.push("GHSA-b");
    const reordered = rehash({ ...source, records: [...source.records].reverse(), observations: [
      { dependency: dep, advisoryIds: ["GHSA-b", "GHSA-a"] },
    ] });
    expect(first(rehash(source))).toEqual(first(reordered));
    expect(first(reordered).candidates).toHaveLength(1);
  });

  it("does not suggest the installed version or a limit-excluded interval's boundary", () => {
    expect(first(snapshot([raw("GHSA-a", [affected([closed("1.0.0")])])])).candidates).toEqual([]);
    const limited = range([{ introduced: "0" }, { fixed: "2.0.0" }, { limit: "0.9.0" }]);
    expect(first(snapshot([raw("GHSA-a", [affected([limited])])])).candidates).toEqual([]);
  });

  it("bounds expanded report bytes without returning truncated alias-source results", () => {
    const ids = Array.from({ length: 100 }, (_, n) => `GHSA-${String(n).padStart(3, "0")}-${"a".repeat(190)}`);
    const raws = ids.map((id, n) => raw(id, [affected([closed(`1.${n + 1}.0`)])], n ? [] : ids.slice(1)));
    expect(() => first(snapshot(raws))).toThrow("fix_observation_capacity");
  });

  it("bounds unique candidates instead of truncating to a partial suggestion", () => {
    const rows = Array.from({ length: 101 }, (_, n) => affected([closed(`1.${n + 1}.0`)]));
    expect(() => first(snapshot([raw("GHSA-a", rows)]))).toThrow("fix_candidate_capacity");
  });

  it("bounds repeated evaluator work instead of accepting a partial all-source check", () => {
    const rows = Array.from({ length: 100 }, (_, n) => affected([closed(`1.${n + 1}.0`)]));
    const raws = Array.from({ length: 10 }, (_, n) => raw(`GHSA-${n}`, rows, n ? [] : Array.from({ length: 9 }, (_, n) => `GHSA-${n + 1}`)));
    expect(() => first(snapshot(raws))).toThrow("fix_observation_capacity");
  });
});
