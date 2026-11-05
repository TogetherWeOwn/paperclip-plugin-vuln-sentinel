import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { RepositoryDiscovery, RepositoryTreeEntry } from "./github-discovery.js";
import { canonicalJson, sha256 } from "./identity.js";
import { observeNpmManifest, NPM_MANIFEST_VERSION } from "./npm-manifest.js";
import { observeOsvFixes } from "./osv-fixes.js";
import { osvFindingInputs, parseOsvRecord, type OsvDependency } from "./osv.js";

const candidate: OsvDependency = { ecosystem: "npm", package: "example", version: "1.2.3" };
function discovery(content: string, path = "package.json"): RepositoryDiscovery {
  const bytes = Buffer.from(content);
  const entries: RepositoryTreeEntry[] = [];
  let prefix = "";
  for (const part of path.split("/").slice(0, -1)) {
    prefix += part;
    entries.push({ path: prefix, type: "tree", mode: "040000", sha: "a".repeat(40), size: null });
    prefix += "/";
  }
  entries.push({ path, type: "blob", mode: "100644", size: bytes.byteLength,
    sha: createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex") });
  return rehash({ version: 1, repo: "org/repo", sourceSha: "b".repeat(40), treeSha: "c".repeat(40),
    defaultBranch: "main", entries, sha256: "" });
}
function rehash(value: RepositoryDiscovery): RepositoryDiscovery {
  const { sha256: _, ...body } = value;
  return { ...body, sha256: sha256(canonicalJson(["repository-discovery-v1", body])) };
}
function observe(value: unknown, query: OsvDependency | undefined = candidate) {
  const content = JSON.stringify(value);
  return observeNpmManifest(discovery(content), "package.json", content, query);
}
function matches(specifier: string, version = "1.2.3") {
  return observe({ dependencies: { example: specifier } }, { ...candidate, version }).declarations[0]!;
}

describe("offline exact-tree npm manifest observations", () => {
  it("binds exact UTF-8 bytes/path/commit/tree and retains every declaration without scope or fix inference", () => {
    const content = JSON.stringify({ description: "雪", dependencies: { example: "^1.0.0", zebra: "~2.0.0" },
      devDependencies: { example: "1.2.3" }, optionalDependencies: { example: "~1.2.0" }, peerDependencies: { example: ">=2.0.0" } });
    const source = discovery(content, "packages/tool/package.json");
    const result = observeNpmManifest(source, "packages/tool/package.json", content, candidate);
    expect(result).toMatchObject({ version: NPM_MANIFEST_VERSION, status: "attention", scope: "unknown", direct: null,
      candidate, compatibleFixVerified: false,
      source: { repo: source.repo, sourceSha: source.sourceSha, treeSha: source.treeSha, discoverySha256: source.sha256,
        path: "packages/tool/package.json", blobSha: source.entries.at(-1)!.sha, sha256: sha256(content) } });
    expect(result.declarations.map(row => [row.section, row.package, row.candidateRangeMatch])).toEqual([
      ["dependencies", "example", "matches"], ["dependencies", "zebra", null], ["devDependencies", "example", "matches"],
      ["optionalDependencies", "example", "matches"], ["peerDependencies", "example", "does_not_match"],
    ]);
    const { observationSha256, ...body } = result;
    expect(observationSha256).toBe(sha256(canonicalJson(["npm-manifest-observation-v1", body])));
  });

  it.each([
    ["1.2.3", "1.2.3", "matches"], ["1.2.3", "1.2.4", "does_not_match"],
    ["^1.2.3", "1.9.0", "matches"], ["^1.2.3", "2.0.0", "does_not_match"],
    ["^0.2.3", "0.3.0", "does_not_match"], ["^0.0.3", "0.0.4", "does_not_match"],
    ["~1.2.3", "1.2.9", "matches"], ["~1.2.3", "1.3.0", "does_not_match"],
    [">=1.0.0 <2.0.0", "1.5.0", "matches"], [">=1.0.0 <2.0.0", "2.0.0", "does_not_match"],
    ["=1.2.3 || ^2.0.0", "2.4.0", "matches"], ["=1.2.3 || ^2.0.0", "1.2.4", "does_not_match"],
    [">1.2.3 <=1.2.4", "1.2.4", "matches"], [">=2.0.0 <1.0.0", "1.2.3", "does_not_match"],
  ])("observes supported declared range %s against %s as %s, never as compatibility", (specifier, version, expected) => {
    expect(matches(specifier!, version)).toMatchObject({ specifierKind: "stable_semver_subset", candidateRangeMatch: expected });
    expect(observe({ dependencies: { example: specifier } }).compatibleFixVerified).toBe(false);
  });

  it.each(["*", "", "latest", "next", "1", "1.2", "1.x", "1.2.x", "v1.2.3", "01.2.3", ">= 1.2.3",
    "1.2.3 - 2.0.0", "1.2.3-beta.1", "1.2.3+build", "npm:other@^1.0.0", "workspace:^", "file:../local", "link:../local",
    "git+https://example.test/pkg.git", "https://example.test/pkg.tgz", "github:org/repo", "^1.2.3 ||", "|| 1.2.3",
    "^9007199254740991.0.0", Array(9).fill("^1.2.3").join(" || "), Array(9).fill(">=1.2.3").join(" ")])(
    "retains unsupported specifier %s as unknown, not a mismatch", specifier => {
      const result = observe({ dependencies: { example: specifier } });
      expect(result.declarations[0]).toMatchObject({ specifier, specifierKind: "unsupported", candidateRangeMatch: "unknown" });
      expect(result.attention).toContain("unsupported_npm_manifest_specifier");
    });

  it("does not infer a version, installed direct relationship, or dev-only scope from declarations", () => {
    const content = JSON.stringify({ devDependencies: { example: "^1.0.0" } });
    const result = observeNpmManifest(discovery(content), "package.json", content);
    expect(result).toMatchObject({ candidate: null, direct: null, scope: "unknown", compatibleFixVerified: false });
    expect(result.declarations[0]!.candidateRangeMatch).toBeNull();
    expect(result.attention).toEqual(expect.arrayContaining(["manifest_scope_not_applied", "manifest_range_not_compatible_fix",
      "manifest_lockfile_association_not_verified", "manifest_workspace_association_not_verified"]));
  });

  it.each(["workspaces", "overrides", "resolutions", "pnpm", "peerDependenciesMeta", "bundledDependencies", "bundleDependencies"])(
    "holds unevaluated %s influences even when present with null", field => {
      const result = observe({ [field]: null, dependencies: { example: "^1.0.0" } });
      expect(result.attention).toContain(`npm_manifest_${field}_not_evaluated`);
      expect(result.compatibleFixVerified).toBe(false);
    });

  it("preserves conflicting optional/dependency/peer declarations without choosing npm override semantics", () => {
    const result = observe({ dependencies: { example: "^1.0.0" }, optionalDependencies: { example: "^2.0.0" },
      peerDependencies: { example: "npm:other@1.2.3" } });
    expect(result.declarations.map(row => row.candidateRangeMatch)).toEqual(["matches", "does_not_match", "unknown"]);
    expect(result.scope).toBe("unknown");
  });

  it("treats missing declarations as attention, not transitive/absent/safe evidence", () => {
    expect(observe({}).attention).toContain("candidate_not_declared_in_manifest");
    expect(observe({ dependencies: { other: "^1.0.0" } }).declarations[0]!.candidateRangeMatch).toBeNull();
  });

  it("accepts scoped names and sorts declarations deterministically", () => {
    expect(observe({ dependencies: { zebra: "1.0.0", "@scope/pkg": "^1.0.0", alpha: "1.0.0" } }).declarations.map(row => row.package))
      .toEqual(["@scope/pkg", "alpha", "zebra"]);
  });

  it.each(["1.2", "v1.2.3", "01.2.3", "1.2.3-beta.1", "1.2.3+build", " 1.2.3", "1.2.3 "])(
    "rejects unsupported candidate version %s rather than borrowing stable npm semantics", version => {
      expect(() => matches("^1.0.0", version)).toThrow("unsupported_npm_manifest_candidate");
    });
  it("rejects other ecosystems and invalid candidate package names", () => {
    expect(() => observe({}, { ...candidate, ecosystem: "crates.io" })).toThrow("unsupported_npm_manifest_candidate");
    expect(() => observe({}, { ...candidate, package: "../example" })).toThrow("unsupported_npm_manifest_candidate");
  });

  it.each([null, [], "text", 1])("rejects non-object manifest %j", value => {
    expect(() => observe(value)).toThrow("invalid_npm_manifest");
  });
  it.each([null, [], "text", 1])("rejects non-object dependency map %j", value => {
    expect(() => observe({ dependencies: value })).toThrow("invalid_npm_manifest_dependency_map");
  });
  it.each([null, 1, {}, [], true, "bad\nrange", "bad\u007frange", "a".repeat(257)])("rejects invalid declaration %j", value => {
    expect(() => observe({ dependencies: { example: value } })).toThrow("invalid_npm_manifest_declaration");
  });
  it.each(["../evil", "@scope", "@/pkg", "bad name", "A", "a".repeat(215)])("rejects invalid declaration name %s", pkg => {
    expect(() => observe({ dependencies: { [pkg]: "1.0.0" } })).toThrow("invalid_npm_manifest_declaration");
  });

  it.each([
    '{"dependencies":{"example":"1.0.0"},"dependencies":{"example":"2.0.0"}}',
    '{"dependencies":{"example":"1.0.0","example":"2.0.0"}}',
    '{"dependencies":{"example":"1.0.0","ex\\u0061mple":"2.0.0"}}',
    '{"unused":{"key":1,"key":2}}',
  ])("rejects duplicate JSON keys anywhere before reporting declarations", content => {
    expect(() => observeNpmManifest(discovery(content), "package.json", content)).toThrow("ambiguous_npm_manifest_json");
  });
  it.each(['{"dependencies":{},}', '{/* comment */"dependencies":{}}', '{"dependencies":{example:"1.0.0"}}', "---\ndependencies: {}"])(
    "rejects non-JSON syntax", content => {
      expect(() => observeNpmManifest(discovery(content), "package.json", content)).toThrow("invalid_npm_manifest_json");
    });

  it("rejects corrupt discovery and exact-byte mismatches", () => {
    const content = "{}"; const source = discovery(content);
    expect(() => observeNpmManifest({ ...source, sourceSha: "d".repeat(40) }, "package.json", content)).toThrow("discovery_hash_mismatch");
    expect(() => observeNpmManifest(source, "package.json", "{ }" )).toThrow("npm_manifest_discovered_blob_mismatch");
    source.entries[0]!.size = 1;
    expect(() => observeNpmManifest(rehash(source), "package.json", content)).toThrow("npm_manifest_discovered_blob_mismatch");
  });
  it("requires the exact tracked path, not a basename or another file with the same bytes", () => {
    const content = "{}";
    expect(() => observeNpmManifest(discovery(content, "other/package.json"), "package.json", content)).toThrow("npm_manifest_not_in_discovery");
    expect(() => observeNpmManifest(discovery(content), "package-lock.json", content)).toThrow("unsupported_npm_manifest_path");
    expect(() => observeNpmManifest(discovery(content), "../package.json", content)).toThrow("npm_manifest_not_in_discovery");
  });
  it.each(["120000", "160000", "040000"])("rejects symlink/submodule/tree mode %s", mode => {
    const source = discovery("{}");
    Object.assign(source.entries[0]!, { mode, type: mode === "160000" ? "commit" : mode === "040000" ? "tree" : "blob", size: null });
    expect(() => observeNpmManifest(rehash(source), "package.json", "{}")).toThrow("npm_manifest_not_in_discovery");
  });
  it("accepts null reported size and executable regular-file metadata without executing any scripts", () => {
    const content = JSON.stringify({ scripts: { install: "throw if executed" }, dependencies: { example: "^1.0.0" } });
    const source = discovery(content); Object.assign(source.entries[0]!, { mode: "100755", size: null });
    expect(observeNpmManifest(rehash(source), "package.json", content).declarations).toHaveLength(1);
  });
  it("rejects lossy UTF-8 surrogate encoding", () => {
    const content = '{"description":"\ud800"}';
    expect(() => observeNpmManifest(discovery(content), "package.json", content)).toThrow("invalid_npm_manifest_utf8");
  });

  it("fails rather than truncating at the raw byte bound", () => {
    const content = JSON.stringify({ unused: "a".repeat(2 * 1024 * 1024) });
    expect(() => observeNpmManifest(discovery(content), "package.json", content)).toThrow("npm_manifest_content_capacity");
  });
  it("counts declarations across all sections before permitting more than 10,000", () => {
    const dependencies = Object.fromEntries(Array.from({ length: 5001 }, (_, i) => [`pkg-${i}`, "1.0.0"]));
    expect(() => observe({ dependencies, devDependencies: dependencies })).toThrow("npm_manifest_declaration_capacity");
  });
  it("fails rather than truncating expanded observation data", () => {
    const dependencies = Object.fromEntries(Array.from({ length: 9000 }, (_, i) => [`pkg-${i}`, "1.0.0"]));
    expect(() => observe({ dependencies })).toThrow("npm_manifest_observation_capacity");
  });

  it("does not promote an outside-reported-range candidate plus matching manifest into a rule-6 fix", () => {
    const dependency = { ...candidate, version: "1.0.0" };
    const queriedAt = "2026-11-04T00:00:00.000Z";
    const body = { queriedAt, unavailableIds: [], observations: [{ dependency, advisoryIds: ["GHSA-a"] }],
      records: [parseOsvRecord({ id: "GHSA-a", modified: queriedAt, affected: [{
        package: { ecosystem: "npm", name: "example" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }],
      }] }, "GHSA-a")] };
    const snapshot = { ...body, snapshotSha256: sha256(canonicalJson(body)) };
    const context = { repo: "org/repo", artifactDigest: `sha256:${"a".repeat(64)}`, observedAt: queriedAt };
    const before = osvFindingInputs(snapshot, context);
    const boundary = observeOsvFixes(snapshot, dependency).groups[0]!.candidates[0]!;
    expect(boundary.status).toBe("outside_reported_ranges");
    const result = observe({ dependencies: { example: "^1.0.0" } }, { ...dependency, version: boundary.version });
    expect(result.declarations[0]!.candidateRangeMatch).toBe("matches");
    expect(result.compatibleFixVerified).toBe(false);
    expect(result.toolVersions).toEqual({ "vuln-sentinel-npm-manifest": "1.0.0", semver: "7.7.4", yaml: "2.9.1" });
    expect(osvFindingInputs(snapshot, context)).toEqual(before);
    expect(before[0]).toMatchObject({ fixedVersion: null, compatibleFixVerified: false, scope: "unknown" });
  });

  it("replays concurrently without mutating source or candidate; new source/bytes change provenance", async () => {
    const content = JSON.stringify({ dependencies: { example: "^1.0.0" } });
    const source = discovery(content); const before = structuredClone({ source, candidate });
    const results = await Promise.all(Array.from({ length: 4 }, async () => observeNpmManifest(source, "package.json", content, candidate)));
    expect(results.every(row => canonicalJson(row) === canonicalJson(results[0]))).toBe(true);
    expect({ source, candidate }).toEqual(before);
    const newer = rehash({ ...source, sourceSha: "e".repeat(40) });
    expect(observeNpmManifest(newer, "package.json", content, candidate).observationSha256).not.toBe(results[0]!.observationSha256);
    expect(observeNpmManifest(discovery(content + "\n"), "package.json", content + "\n", candidate).observationSha256)
      .not.toBe(results[0]!.observationSha256);
    results[0]!.candidate!.version = "9.0.0";
    expect(candidate.version).toBe("1.2.3");
  });
});
