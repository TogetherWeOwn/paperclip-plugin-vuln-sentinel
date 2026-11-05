import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { RepositoryDiscovery, RepositoryTreeEntry } from "./github-discovery.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { NPM_ROOT_CONTEXT_VERSION, observeNpmRootContext } from "./npm-root-context.js";
import { observeOsvFixes } from "./osv-fixes.js";
import { osvFindingInputs, parseOsvRecord, type OsvDependency } from "./osv.js";

const declarations = { dependencies: { example: "^1.0.0" } };
function installed(version = "1.2.3", name = "example") {
  return { version, resolved: `https://registry.npmjs.org/${name}/-/${name.split("/").at(-1)}-${version}.tgz` };
}
function blob(content: string) {
  const bytes = Buffer.from(content);
  return createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
}
function rehash(tree: RepositoryDiscovery) {
  const { sha256: _, ...body } = tree;
  tree.sha256 = sha256(canonicalJson(["repository-discovery-v1", body]));
}
function snapshot(files: Array<{ path: string; content: string }>): RepositoryLockfiles {
  const rows = files.map(row => ({ ...row, blobSha: blob(row.content), sha256: sha256(row.content), etag: null }));
  return { repo: "org/repo", sourceSha: "b".repeat(40), defaultBranch: "main", files: rows,
    artifactDigest: `sha256:${sha256(canonicalJson([...rows].sort((a, b) => a.path < b.path ? -1 : 1).map(row => [row.path, row.sha256])))}` };
}
function fixture(owner: unknown = declarations, manifest: unknown = owner, packages: Record<string, unknown> = {
  "node_modules/example": installed(), "node_modules/other/node_modules/example": installed("1.5.0"),
}, path = "package-lock.json", lockVersion = 3) {
  const content = JSON.stringify({ lockfileVersion: lockVersion, packages: { "": owner, ...packages } });
  const source = snapshot([{ path, content }]);
  const manifestPath = path.slice(0, path.lastIndexOf("/") + 1) + "package.json";
  const manifestContent = JSON.stringify(manifest);
  const tree = treeFor(source, [{ path: manifestPath, content: manifestContent }]);
  return { tree, source, path, manifestContent, manifestPath };
}
function treeFor(source: RepositoryLockfiles, extra: Array<{ path: string; content: string }>): RepositoryDiscovery {
  const entries = new Map<string, RepositoryTreeEntry>();
  for (const file of [...source.files, ...extra]) {
    const parts = file.path.split("/");
    for (let i = 1; i < parts.length; i++) {
      const path = parts.slice(0, i).join("/");
      entries.set(path, { path, type: "tree", mode: "040000", sha: "a".repeat(40), size: null });
    }
    entries.set(file.path, { path: file.path, type: "blob", mode: "100644", sha: blob(file.content), size: Buffer.byteLength(file.content) });
  }
  const tree: RepositoryDiscovery = { version: 1, repo: source.repo, sourceSha: source.sourceSha, defaultBranch: source.defaultBranch,
    treeSha: "c".repeat(40), entries: [...entries.values()].sort((a, b) => a.path < b.path ? -1 : 1), sha256: "" };
  rehash(tree);
  return tree;
}
function observe(f = fixture(), candidate?: OsvDependency) {
  return observeNpmRootContext(f.tree, f.source, f.path, f.manifestContent, candidate);
}
const candidate: OsvDependency = { ecosystem: "npm", package: "example", version: "1.2.3" };
function rawLockfile(content: string) {
  const f = fixture();
  f.source = snapshot([{ path: f.path, content }]);
  f.tree = treeFor(f.source, [{ path: f.manifestPath, content: f.manifestContent }]);
  return f;
}

describe("offline npm root declaration context", () => {
  it.each([2, 3])("binds retained npm v%i root declarations and every same-name version/location, not owner edges", version => {
    const f = fixture(declarations, declarations, undefined, "apps/web/package-lock.json", version);
    const result = observe(f);
    expect(result).toMatchObject({ version: NPM_ROOT_CONTEXT_VERSION, status: "attention", scope: "unknown", direct: null,
      compatibleFixVerified: false, source: { repo: f.tree.repo, sourceSha: f.tree.sourceSha, treeSha: f.tree.treeSha,
        discoverySha256: f.tree.sha256, artifactDigest: f.source.artifactDigest, lockfilePath: f.path,
        lockfileBlobSha: f.source.files[0]!.blobSha, lockfileSha256: f.source.files[0]!.sha256 } });
    expect(result.declarations).toEqual([{ section: "dependencies", package: "example", manifestSpecifier: "^1.0.0",
      lockfileSpecifier: "^1.0.0", comparison: "same_specifier", manifestCandidateRangeMatch: null, lockfileCandidateRangeMatch: null }]);
    expect(result.inventoryCandidates).toEqual([
      { ecosystem: "npm", package: "example", version: "1.2.3", rootLocatorReported: true,
        locations: [{ path: f.path, locator: "node_modules/example" }] },
      { ecosystem: "npm", package: "example", version: "1.5.0", rootLocatorReported: false,
        locations: [{ path: f.path, locator: "node_modules/other/node_modules/example" }] },
    ]);
    const { observationSha256, ...body } = result;
    expect(observationSha256).toBe(sha256(canonicalJson(["npm-root-context-observation-v1", body])));
  });

  it.each([
    ["1.2.3", "1.2.3", "matches"], ["1.2.3", "1.2.4", "does_not_match"],
    ["^1.2.3", "1.9.0", "matches"], ["^1.2.3", "2.0.0", "does_not_match"],
    ["^0.2.3", "0.3.0", "does_not_match"], ["^0.0.3", "0.0.4", "does_not_match"],
    ["~1.2.3", "1.2.9", "matches"], ["~1.2.3", "1.3.0", "does_not_match"],
    [">=1.0.0 <2.0.0", "1.5.0", "matches"], [">=1.0.0 <2.0.0", "2.0.0", "does_not_match"],
    ["=1.2.3 || ^2.0.0", "2.4.0", "matches"], ["=1.2.3 || ^2.0.0", "1.2.4", "does_not_match"],
    [">1.2.3 <=1.2.4", "1.2.4", "matches"], [">=2.0.0 <1.0.0", "1.2.3", "does_not_match"],
  ])("compares a candidate against both supported declarations %s at %s as %s", (specifier, version, expected) => {
    const f = fixture({ dependencies: { example: specifier } });
    const result = observe(f, { ...candidate, version: version! });
    expect(result.declarations[0]).toMatchObject({ manifestCandidateRangeMatch: expected, lockfileCandidateRangeMatch: expected });
    expect(result.manifest.candidate).toEqual({ ...candidate, version });
    expect(result).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
    expect(result.inventoryCandidates).toEqual(observe(f).inventoryCandidates);
    expect(result.toolVersions["vuln-sentinel-npm-root-context"]).toBe("1.1.0");
  });

  it.each(["*", "", "latest", "next", "1", "1.2", "1.x", "1.2.x", "v1.2.3", "01.2.3", ">= 1.2.3",
    "1.2.3 - 2.0.0", "1.2.3-beta.1", "1.2.3+build", "npm:other@^1.0.0", "workspace:^", "file:../local", "link:../local",
    "git+https://example.test/pkg.git", "https://example.test/pkg.tgz", "github:org/repo", "^1.2.3 ||", "|| 1.2.3",
    "^9007199254740991.0.0", Array(9).fill("^1.2.3").join(" || "), Array(9).fill(">=1.2.3").join(" ")])(
    "retains unsupported lockfile specifier %s as unknown, not exclusion", specifier => {
      const result = observe(fixture({ dependencies: { example: specifier } }, declarations), candidate);
      expect(result.declarations[0]).toMatchObject({ manifestCandidateRangeMatch: "matches", lockfileCandidateRangeMatch: "unknown" });
      expect(result.attention).toContain("unsupported_npm_root_specifier");
      expect(result.compatibleFixVerified).toBe(false);
    });

  it("keeps semantic agreement distinct from literal equality, and preserves cross-section conflicts", () => {
    const result = observe(fixture({ dependencies: { example: ">=1.0.0 <2.0.0" }, devDependencies: { example: "^2.0.0" },
      optionalDependencies: { example: "workspace:*" }, peerDependencies: { example: "^1.0.0" } },
    { dependencies: { example: "^1.0.0" }, devDependencies: { example: "^1.0.0" },
      optionalDependencies: { example: "^2.0.0" }, peerDependencies: { example: "*" } }), candidate);
    expect(result.declarations.map(row => [row.section, row.comparison, row.manifestCandidateRangeMatch, row.lockfileCandidateRangeMatch]))
      .toEqual([["dependencies", "different_specifier", "matches", "matches"], ["devDependencies", "different_specifier", "matches", "does_not_match"],
        ["optionalDependencies", "different_specifier", "does_not_match", "unknown"], ["peerDependencies", "different_specifier", "unknown", "matches"]]);
    expect(result.attention).toEqual(expect.arrayContaining(["npm_root_candidate_declaration_mismatch", "unsupported_npm_root_specifier",
      "unsupported_npm_manifest_specifier", "npm_root_declarations_disagree"]));
    expect(result.compatibleFixVerified).toBe(false);
  });

  it.each(["manifest_only", "lockfile_only", "neither", "other_package"])(
    "never invents a range comparison for missing or unqueried sides: %s", condition => {
      const manifest = condition === "lockfile_only" || condition === "neither" ? {} : declarations;
      const owner = condition === "manifest_only" || condition === "neither" ? {} : declarations;
      const result = observe(fixture(owner, manifest), condition === "other_package" ? { ...candidate, package: "other" } : candidate);
      expect(result.declarations.every(row => row.manifestCandidateRangeMatch === (condition === "manifest_only" ? "matches" : null))).toBe(true);
      expect(result.declarations.every(row => row.lockfileCandidateRangeMatch === (condition === "lockfile_only" ? "matches" : null))).toBe(true);
      if (condition !== "lockfile_only") expect(result.attention).toContain("candidate_not_declared_in_npm_root");
      if (condition !== "manifest_only") expect(result.attention).toContain("candidate_not_declared_in_manifest");
      expect(result.compatibleFixVerified).toBe(false);
    });

  it("leaves both comparison sides null without a candidate, including unsupported declarations", () => {
    const result = observe(fixture({ dependencies: { example: "workspace:*" } }));
    expect(result.manifest.candidate).toBeNull();
    expect(result.declarations[0]).toMatchObject({ manifestCandidateRangeMatch: null, lockfileCandidateRangeMatch: null });
    expect(result.attention).toContain("unsupported_npm_root_specifier");
  });

  it("does not equate an unsupported empty specifier with a missing side", () => {
    const result = observe(fixture({ dependencies: { example: "" } }, {}), candidate);
    expect(result.declarations[0]).toMatchObject({ manifestSpecifier: null, lockfileSpecifier: "", comparison: "lockfile_only",
      manifestCandidateRangeMatch: null, lockfileCandidateRangeMatch: "unknown" });
  });

  it("compares scoped names exactly without querying a same-version unrelated package", () => {
    const result = observe(fixture({ dependencies: { "@scope/example": "^1.0.0", example: "^2.0.0" } }),
      { ...candidate, package: "@scope/example" });
    expect(result.declarations.map(row => [row.package, row.manifestCandidateRangeMatch, row.lockfileCandidateRangeMatch]))
      .toEqual([["@scope/example", "matches", "matches"], ["example", null, null]]);
  });

  it.each(["1.2", "v1.2.3", "01.2.3", "1.2.3-beta.1", "1.2.3+build", " 1.2.3", "1.2.3 "])(
    "rejects unsupported candidate %s even when the manifest has no declarations", version => {
      expect(() => observe(fixture(declarations, {}), { ...candidate, version })).toThrow("unsupported_npm_manifest_candidate");
    });

  it("rejects another ecosystem and malformed candidate package before comparing locked declarations", () => {
    expect(() => observe(fixture(declarations, {}), { ...candidate, ecosystem: "crates.io" })).toThrow("unsupported_npm_manifest_candidate");
    expect(() => observe(fixture(declarations, {}), { ...candidate, package: "../example" })).toThrow("unsupported_npm_manifest_candidate");
  });

  it("never promotes matching manifest/root declarations plus an OSV boundary to a compatible fix", () => {
    const dependency = { ...candidate, version: "1.0.0" };
    const queriedAt = "2026-11-04T00:00:00.000Z";
    const body = { queriedAt, unavailableIds: [], observations: [{ dependency, advisoryIds: ["GHSA-a"] }],
      records: [parseOsvRecord({ id: "GHSA-a", modified: queriedAt, affected: [{
        package: { ecosystem: "npm", name: "example" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.2.3" }] }],
      }] }, "GHSA-a")] };
    const scan = { ...body, snapshotSha256: sha256(canonicalJson(body)) };
    const f = fixture();
    const context = { repo: f.source.repo, artifactDigest: f.source.artifactDigest, observedAt: queriedAt };
    const before = osvFindingInputs(scan, context);
    const boundary = observeOsvFixes(scan, dependency).groups[0]!.candidates[0]!;
    expect(boundary.status).toBe("outside_reported_ranges");
    const result = observe(f, { ...dependency, version: boundary.version });
    expect(result.declarations[0]).toMatchObject({ manifestCandidateRangeMatch: "matches", lockfileCandidateRangeMatch: "matches" });
    expect(result.inventoryCandidates).toHaveLength(2);
    expect(result).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
    expect(result.attention).toEqual(expect.arrayContaining(["npm_transitive_and_workspace_constraints_not_verified", "release_availability_not_verified"]));
    expect(osvFindingInputs(scan, context)).toEqual(before);
    expect(before[0]).toMatchObject({ fixedVersion: null, compatibleFixVerified: false });
  });

  it("replays candidate comparisons without mutating inputs or borrowing later candidate results", async () => {
    const f = fixture(); const before = structuredClone({ f, candidate });
    const results = await Promise.all(Array.from({ length: 4 }, async () => observe(f, candidate)));
    expect(results.every(result => canonicalJson(result) === canonicalJson(results[0]))).toBe(true);
    expect({ f, candidate }).toEqual(before);
    const other = observe(f, { ...candidate, version: "2.0.0" });
    expect(other.observationSha256).not.toBe(results[0]!.observationSha256);
    expect(other.declarations[0]!.lockfileCandidateRangeMatch).toBe("does_not_match");
    expect(other.inventoryCandidates).toEqual(results[0]!.inventoryCandidates);
    expect(observe(f).observationSha256).not.toBe(results[0]!.observationSha256);
    results[0]!.manifest.candidate!.version = "9.0.0";
    results[0]!.declarations[0]!.lockfileCandidateRangeMatch = "unknown";
    expect(observe(f, candidate)).toEqual(results[1]);
    expect(candidate.version).toBe("1.2.3");
  });

  it("preserves conflicting sections, both missing sides and literal specifier differences", () => {
    const result = observe(fixture({ dependencies: { example: "^1.0.0", locked: "1.0.0" },
      devDependencies: { example: "^2.0.0" }, optionalDependencies: { example: "npm:other@1.0.0" }, peerDependencies: { example: "*" } },
    { dependencies: { example: ">=1.0.0 <2.0.0", declared: "1.0.0" }, devDependencies: { example: "^2.0.0" },
      optionalDependencies: { example: "^3.0.0" }, peerDependencies: { example: "*" } }));
    expect(result.declarations.map(row => [row.section, row.package, row.comparison])).toEqual([
      ["dependencies", "declared", "manifest_only"], ["dependencies", "example", "different_specifier"],
      ["dependencies", "locked", "lockfile_only"], ["devDependencies", "example", "same_specifier"],
      ["optionalDependencies", "example", "different_specifier"], ["peerDependencies", "example", "same_specifier"],
    ]);
    expect(result.attention).toContain("npm_root_declarations_disagree");
    expect(result.manifest.declarations.at(-1)!.specifierKind).toBe("unsupported");
  });

  it("does not convert dev-only declarations or root locator presence into scope/directness/fix permission", () => {
    const result = observe(fixture({ devDependencies: { example: "^1.0.0" } }));
    expect(result).toMatchObject({ scope: "unknown", direct: null, compatibleFixVerified: false });
    expect(result.attention).toEqual(expect.arrayContaining(["npm_root_declaration_equality_not_owner_proof",
      "npm_name_candidates_not_dependency_edges", "npm_transitive_and_workspace_constraints_not_verified",
      "manifest_source_authenticity_and_freshness_not_verified", "npm_root_context_not_current_source_selection"]));
  });

  it("retains empty strings as unsupported reported specifiers, not missing declarations", () => {
    expect(observe(fixture({ dependencies: { example: "" } })).declarations[0]).toMatchObject({
      manifestSpecifier: "", lockfileSpecifier: "", comparison: "same_specifier" });
  });

  it.each(["npm:real@^1.0.0", "workspace:*", "file:../pkg", "https://example.test/pkg.tgz"]) (
    "does not resolve unsupported reference %s or borrow the alias target's inventory tuple", specifier => {
      const result = observe(fixture({ dependencies: { alias: specifier } }, undefined, { "node_modules/alias": { ...installed("1.2.3", "real"), name: "real" } }));
      expect(result.declarations[0]!.comparison).toBe("same_specifier");
      expect(result.inventoryCandidates).toEqual([]);
      expect(result.attention).toContain("declared_name_without_inventory_candidate");
    });

  it("never treats a same-name installed alias at a different locator as a root owner edge", () => {
    const result = observe(fixture(declarations, declarations, { "node_modules/alias": { ...installed(), name: "example" } }));
    expect(result.inventoryCandidates).toMatchObject([{ package: "example", rootLocatorReported: false }]);
  });

  it("retains all locations for one version and excludes unrelated names", () => {
    const result = observe(fixture(declarations, declarations, { "node_modules/example": installed(),
      "node_modules/parent/node_modules/example": installed(), "node_modules/other": installed("1.0.0", "other") }));
    expect(result.inventoryCandidates).toHaveLength(1);
    expect(result.inventoryCandidates[0]!.locations).toHaveLength(2);
  });

  it("does not import tuple candidates from a different lockfile in the same retained snapshot", () => {
    const f = fixture(declarations, declarations, {});
    f.source = snapshot([...f.source.files, { path: "other/package-lock.json", content: fixture().source.files[0]!.content }]);
    f.tree = treeFor(f.source, [{ path: f.manifestPath, content: f.manifestContent }]);
    expect(observe(f).inventoryCandidates).toEqual([]);
  });

  it("retains inventory partial-coverage reasons and workspace/override holds", () => {
    const f = fixture({ ...declarations, workspaces: ["packages/*"] }, { ...declarations, overrides: { example: "2.0.0" } },
      { "packages/local": { version: "1.0.0" }, "node_modules/local": { link: true, resolved: "packages/local" } });
    expect(observe(f).attention).toEqual(expect.arrayContaining(["npm_root_workspaces_not_evaluated",
      "npm_manifest_overrides_not_evaluated", "inventory:package-lock.json:local_or_workspace_package",
      "inventory:package-lock.json:missing_npm_dependency_entry"]));
  });

  it("does not infer absence from empty declarations or an empty candidate list", () => {
    const result = observe(fixture({}, {}, {}));
    expect(result.declarations).toEqual([]);
    expect(result.inventoryCandidates).toEqual([]);
    expect(result.attention).toContain("empty_root_declarations_not_absence");
    expect(result.status).toBe("attention");
  });

  it.each(["npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]) (
    "holds selection ambiguity with tracked sibling %s, even if it is not in the snapshot", sibling => {
      const f = fixture();
      f.tree = treeFor(f.source, [{ path: f.manifestPath, content: f.manifestContent }, { path: sibling, content: "{}" }]);
      expect(observe(f).attention).toContain("multiple_colocated_lockfiles_not_selected");
    });

  it("supports exact npm-shrinkwrap input without silently preferring package-lock", () => {
    expect(observe(fixture(declarations, declarations, undefined, "npm-shrinkwrap.json")).source.lockfilePath).toBe("npm-shrinkwrap.json");
  });

  it.each(["repo", "sourceSha", "defaultBranch"] as const)("rejects discovery/lockfile %s mismatch", key => {
    const f = fixture();
    f.source[key] = key === "sourceSha" ? "d".repeat(40) : "different";
    expect(() => observe(f)).toThrow("npm_root_source_mismatch");
  });

  it.each(["sha", "size", "mode", "type", "missing"])("rejects discovered lockfile %s mismatch", field => {
    const f = fixture();
    const entry = f.tree.entries.find(row => row.path === f.path)!;
    if (field === "sha") entry.sha = "e".repeat(40);
    if (field === "size") entry.size = entry.size! + 1;
    if (field === "mode") entry.mode = "120000";
    if (field === "type") { entry.type = "commit"; entry.mode = "160000"; entry.size = null; }
    if (field === "missing") f.tree.entries = f.tree.entries.filter(row => row.path !== f.path);
    rehash(f.tree);
    expect(() => observe(f)).toThrow("npm_root_discovered_lockfile_mismatch");
  });

  it.each(["content", "blobSha", "sha256", "artifactDigest"])("rejects retained lockfile %s mismatch", field => {
    const f = fixture();
    if (field === "artifactDigest") f.source.artifactDigest = `sha256:${"0".repeat(64)}`;
    else f.source.files[0]![field as "content" | "blobSha" | "sha256"] += "x";
    expect(() => observe(f)).toThrow(/inventory_(content|digest)_mismatch/u);
  });

  it("rejects changed or non-colocated manifest bytes", () => {
    const f = fixture();
    f.manifestContent += " ";
    expect(() => observe(f)).toThrow("npm_manifest_discovered_blob_mismatch");
    const nested = fixture(declarations, declarations, undefined, "nested/package-lock.json");
    nested.tree = treeFor(nested.source, [{ path: "package.json", content: nested.manifestContent }]);
    expect(() => observe(nested)).toThrow("npm_manifest_not_in_discovery");
  });

  it("rejects corrupt discovery and lossy UTF-8 bytes", () => {
    const f = fixture();
    f.tree.sha256 = "0".repeat(64);
    expect(() => observe(f)).toThrow("discovery_hash_mismatch");
    expect(() => observe(rawLockfile('{"lockfileVersion":3,"packages":{"":{}},"note":"' + "\ud800" + '"}')))
      .toThrow("invalid_inventory_utf8");
  });

  it.each([
    ['{"lockfileVersion":3,"packages":{"":{},"":{}}}', "ambiguous_npm_root_json"],
    ['{"lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.0.0","exampl\\u0065":"2.0.0"}}}}', "ambiguous_npm_root_json"],
    ['{"lockfileVersion":1,"packages":{"":{}}}', "unsupported_npm_root_lockfile_version"],
    ['{"lockfileVersion":3,"packages":{}}', "missing_npm_root_owner"],
    ['{"lockfileVersion":3,"packages":{"":null}}', "invalid_npm_root_owner"],
    ['{"lockfileVersion":3,"packages":[]}', "missing_npm_root_packages"],
    ['{"lockfileVersion":3,"packages":{"":{}}', "invalid_npm_root_json"],
  ])("rejects malformed/ambiguous root records %s", (content, code) => {
    expect(() => observe(rawLockfile(content!))).toThrow(code);
  });

  it.each([null, [], 1, "text"])("rejects malformed root declaration map %j", value => {
    expect(() => observe(fixture({ dependencies: value }, {}))).toThrow("invalid_npm_root_dependency_map");
  });
  it.each([null, {}, [], 1, "bad\nrange", "a".repeat(257)])("rejects malformed root specifier %j", value => {
    expect(() => observe(fixture({ dependencies: { example: value } }, {}))).toThrow("invalid_npm_root_declaration");
  });
  it.each(["A", "../example", "@scope", "a".repeat(215)])("rejects malformed root package %s", name => {
    expect(() => observe(fixture({ dependencies: { [name]: "^1.0.0" } }, {}))).toThrow("invalid_npm_root_declaration");
  });

  it("rejects absent/unsupported selected lockfile without guessing a source", () => {
    const f = fixture();
    f.path = "other/package-lock.json";
    expect(() => observe(f)).toThrow("unsupported_npm_root_lockfile");
    expect(() => observe(fixture({}, {}, {}, "yarn.lock"))).toThrow("unsupported_npm_root_lockfile");
  });

  it("binds every supplied lockfile to discovery, not only the selected file", () => {
    const f = fixture();
    f.source = snapshot([...f.source.files, { path: "other/package-lock.json", content: fixture().source.files[0]!.content }]);
    expect(() => observe(f)).toThrow("npm_root_discovered_lockfile_mismatch");
  });

  it("fails rather than truncating excessive combined declarations", () => {
    const root = Object.fromEntries(Array.from({ length: 5_001 }, (_, i) => [`lock${i}`, "1.0.0"]));
    const manifest = Object.fromEntries(Array.from({ length: 5_001 }, (_, i) => [`manifest${i}`, "1.0.0"]));
    expect(() => observe(fixture({ dependencies: root }, { dependencies: manifest }, {}))).toThrow("npm_root_declaration_capacity");
    expect(() => observe(fixture({ dependencies: { ...root, ...manifest } }, {}, {}))).toThrow("npm_root_declaration_capacity");
  });

  it("fails rather than truncating excessive expanded output", () => {
    const deps = Object.fromEntries(Array.from({ length: 2_100 }, (_, i) => [`pkg${i}`, "1".repeat(240)]));
    expect(() => observe(fixture({ dependencies: deps }, { dependencies: deps }, {}))).toThrow("npm_root_observation_capacity");
  });

  it("is deterministic across replay, preserves every input and returns independent values", async () => {
    const f = fixture();
    const before = structuredClone(f);
    const results = await Promise.all(Array.from({ length: 4 }, async () => observe(f)));
    expect(results.every(result => canonicalJson(result) === canonicalJson(results[0]))).toBe(true);
    expect(f).toEqual(before);
    results[0]!.inventoryCandidates[0]!.locations[0]!.locator = "changed";
    results[0]!.manifest.attention.length = 0;
    expect(observe(f)).toEqual(results[1]);
  });
});
