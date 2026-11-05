import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CARGO_LOCKFILE_CONTEXT_VERSION, observeCargoLockfileContext } from "./cargo-lockfile-context.js";
import { observeCargoManifest, type CargoManifestCandidate } from "./cargo-manifest.js";
import type { RepositoryDiscovery, RepositoryTreeEntry } from "./github-discovery.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { parseLockfileInventory } from "./inventory.js";

const registry = "registry+https://github.com/rust-lang/crates.io-index";
function crate(name = "example", version = "1.2.3", source: string | null = registry, checksum = "a".repeat(64)) {
  return `[[package]]\nname = ${JSON.stringify(name)}\nversion = ${JSON.stringify(version)}\n`
    + (source === null ? "" : `source = ${JSON.stringify(source)}\n`) + `checksum = ${JSON.stringify(checksum)}\n`;
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
function treeFor(source: RepositoryLockfiles, manifestPath: string, manifestContent: string): RepositoryDiscovery {
  const entries = new Map<string, RepositoryTreeEntry>();
  for (const file of [...source.files, { path: manifestPath, content: manifestContent }]) {
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
function fixture(manifestContent = '[dependencies]\nexample = "1.2.3"',
  content = `version = 4\n${crate()}${crate("example", "2.0.0")}${crate("other")}`,
  lockfilePath = "Cargo.lock", manifestPath = "Cargo.toml", extra: Array<{ path: string; content: string }> = []) {
  const source = snapshot([{ path: lockfilePath, content }, ...extra]);
  return { source, tree: treeFor(source, manifestPath, manifestContent), lockfilePath, manifestPath, manifestContent };
}
function observe(f = fixture(), candidate?: CargoManifestCandidate) {
  return observeCargoLockfileContext(f.tree, f.source, f.lockfilePath, f.manifestPath, f.manifestContent, candidate);
}
function compared(f = fixture()) {
  const result = observe(f);
  return result.declarations.map(row => row.inventoryComparisons.map(comparison => ({
    package: result.inventoryCandidates[comparison.inventoryCandidateIndex]!.package,
    version: result.inventoryCandidates[comparison.inventoryCandidateIndex]!.version,
    basis: comparison.nameBasis, match: comparison.declaredRequirementMatch,
  })));
}

describe("offline exact-tree Cargo manifest/lockfile context", () => {
  it.each([3, 4])("binds v%i lockfile and manifest identities and retains every name-matching version", version => {
    const f = fixture(undefined, `version = ${version}\n${crate()}${crate("example", "2.0.0")}${crate("other")}`);
    const result = observe(f);
    expect(result).toMatchObject({ version: CARGO_LOCKFILE_CONTEXT_VERSION, status: "attention", scope: "unknown", direct: null,
      compatibleFixVerified: false, source: { repo: f.source.repo, sourceSha: f.source.sourceSha, treeSha: f.tree.treeSha,
        discoverySha256: f.tree.sha256, artifactDigest: f.source.artifactDigest, inventorySha256: parseLockfileInventory(f.source).inventorySha256,
        lockfilePath: f.lockfilePath, lockfileBlobSha: f.source.files[0]!.blobSha, lockfileSha256: f.source.files[0]!.sha256 } });
    expect(result.manifest.source).toMatchObject({ path: f.manifestPath, sha256: sha256(f.manifestContent), blobSha: blob(f.manifestContent) });
    expect(result.inventoryCandidates).toEqual(["1.2.3", "2.0.0"].map((version, i) => ({ ecosystem: "crates.io", package: "example", version,
      locations: [{ path: f.lockfilePath, locator: `package[${i}]` }] })));
    expect(compared(f)).toEqual([[{ package: "example", version: "1.2.3", basis: ["declared_name"], match: "matches" },
      { package: "example", version: "2.0.0", basis: ["declared_name"], match: "does_not_match" }]]);
    const { observationSha256, ...body } = result;
    expect(observationSha256).toBe(sha256(canonicalJson(["cargo-lockfile-context-observation-v1", body])));
    expect(result.attention).toEqual(expect.arrayContaining(["cargo_multiple_inventory_name_comparisons_not_selected",
      "cargo_inventory_declared_requirement_mismatch", "manifest_lockfile_association_not_verified"]));
  });

  it.each([
    ["Cargo.lock", "crates/tool/Cargo.toml"], ["nested/Cargo.lock", "nested/Cargo.toml"],
    ["locks/Cargo.lock", "unrelated/Cargo.toml"],
  ])("requires explicit paths %s and %s without guessing workspace membership", (lockPath, manifestPath) => {
    const result = observe(fixture(undefined, undefined, lockPath, manifestPath));
    expect(result.manifest.source.path).toBe(manifestPath);
    expect(result.source.lockfilePath).toBe(lockPath);
    expect(result.attention).toContain("cargo_context_explicit_paths_not_workspace_proof");
    expect(result.direct).toBeNull();
  });
  it("preserves package/dev/build/workspace/target conflicts without selecting a requirement or scope", () => {
    const content = '[dependencies]\nexample = "1.2.3"\n[dev-dependencies]\nexample = "=2.0.0"\n'
      + '[build-dependencies]\nexample = { workspace = true }\n[workspace.dependencies]\nexample = "=3.0.0"\n'
      + '[target.\'cfg(unix)\'.dependencies]\nexample = "*"';
    const result = observe(fixture(content));
    expect(result.manifest.declarations.map(row => [row.owner, row.section, row.target])).toEqual([
      ["package", "dependencies", null], ["package", "dev-dependencies", null], ["package", "build-dependencies", null],
      ["workspace", "dependencies", null], ["target", "dependencies", "cfg(unix)"],
    ]);
    expect(result.declarations.map(row => row.manifestDeclarationIndex)).toEqual([0, 1, 2, 3, 4]);
    expect(result.declarations.map(row => row.inventoryComparisons.map(c => c.declaredRequirementMatch))).toEqual([
      ["matches", "does_not_match"], ["does_not_match", "matches"], ["unknown", "unknown"],
      ["does_not_match", "does_not_match"], ["unknown", "unknown"],
    ]);
    expect(result).toMatchObject({ scope: "unknown", direct: null, compatibleFixVerified: false });
  });
  it("keeps declared-name and package-hint comparisons separate, including both spellings when they conflict", () => {
    const result = compared(fixture('[dependencies]\nalias = { package = "example", version = "1.2.3" }',
      `version = 4\n${crate("alias")}${crate()}`));
    expect(result).toEqual([[{ package: "alias", version: "1.2.3", basis: ["declared_name"], match: "matches" },
      { package: "example", version: "1.2.3", basis: ["package_hint"], match: "matches" }]]);
  });
  it("does not double-count equal declaration and hint spellings", () => {
    const result = observe(fixture('[dependencies]\nexample = { package = "example", version = "1.2.3" }', `version = 4\n${crate()}`));
    expect(result.declarations[0]!.inventoryComparisons).toEqual([
      { inventoryCandidateIndex: 0, nameBasis: ["declared_name", "package_hint"], declaredRequirementMatch: "matches" },
    ]);
    expect(result.attention).toContain("cargo_package_hint_not_registry_identity");
  });
  it("does not merge multiple aliases pointing at the same reported package", () => {
    const result = observe(fixture('[dependencies]\na = { package = "example", version = "1.2.3" }\nb = { package = "example", version = "2.0.0" }'));
    expect(result.inventoryCandidates).toHaveLength(2);
    expect(result.declarations.map(row => row.inventoryComparisons.map(c => c.declaredRequirementMatch)))
      .toEqual([["matches", "does_not_match"], ["does_not_match", "matches"]]);
  });
  it.each(["EXAMPLE", "exam_ple", "exam-ple"]) ("does not normalize spelling %s", name => {
    const result = observe(fixture(`[dependencies]\n${name} = "1.2.3"`));
    expect(result.inventoryCandidates).toEqual([]);
    expect(result.declarations[0]!.inventoryComparisons).toEqual([]);
    expect(result.attention).toContain("cargo_declaration_without_inventory_name_comparison");
  });
  it.each(["__proto__", "constructor"]) ("retains prototype-shaped name %s as data", name => {
    expect(compared(fixture(`[dependencies]\n${name} = "1.2.3"`, `version = 4\n${crate(name)}`))[0]![0]!.package).toBe(name);
  });

  it.each([
    ["1.2.3", "1.9.0", "matches"], ["1.2.3", "2.0.0", "does_not_match"], ["^0.2.3", "0.3.0", "does_not_match"],
    ["~1.2.3", "1.3.0", "does_not_match"], [">=1.0.0, <2.0.0", "1.5.0", "matches"],
    ["=1.2.3", "1.2.4", "does_not_match"], ["*", "1.2.3", "unknown"], ["1", "1.2.3", "unknown"],
    ["1.2.3 || 2.0.0", "1.2.3", "unknown"], ["1.2.3", "1.2.3-beta.1", "unknown"],
    ["1.2.3", "1.2.3+build", "unknown"], ["=1.2.3+build", "1.2.3", "unknown"],
  ])("compares only supported stable Cargo requirement %s with %s as %s", (requirement, version, match) => {
    const f = fixture(`[dependencies]\nexample = ${JSON.stringify(requirement)}`, `version = 4\n${crate("example", version)}`);
    expect(compared(f)[0]![0]!.match).toBe(match);
    expect(observe(f).compatibleFixVerified).toBe(false);
  });
  it("retains distinct equal-precedence build identities and does not turn unsupported comparisons into exclusion", () => {
    const result = observe(fixture(undefined, `version = 4\n${crate()}${crate("example", "1.2.3+one")}${crate("example", "1.2.3+two")}`));
    expect(result.inventoryCandidates.map(row => row.version)).toEqual(["1.2.3", "1.2.3+one", "1.2.3+two"]);
    expect(result.declarations[0]!.inventoryComparisons.map(row => row.declaredRequirementMatch)).toEqual(["matches", "unknown", "unknown"]);
  });
  it("keeps an explicit future candidate independent of retained locked-version comparisons", () => {
    const f = fixture();
    const before = observe(f);
    const after = observe(f, { declaredName: "example", version: "1.9.0" });
    expect(after.manifest.declarations[0]!.candidateRangeMatch).toBe("matches");
    expect(after.inventoryCandidates).toEqual(before.inventoryCandidates);
    expect(after.declarations).toEqual(before.declarations);
    expect(after.source).toEqual(before.source);
    expect(after.observationSha256).not.toBe(before.observationSha256);
    expect(after.compatibleFixVerified).toBe(false);
  });
  it("does not apply a candidate's declared key to a package-hint spelling", () => {
    const result = observe(fixture('[dependencies]\nalias = { package = "example", version = "1.2.3" }'),
      { declaredName: "example", version: "1.9.0" });
    expect(result.manifest.declarations[0]!.candidateRangeMatch).toBeNull();
    expect(result.manifest.attention).toContain("candidate_not_declared_in_cargo_manifest");
  });
  it.each(["path", "git", "registry", "registry-index"]) ("preserves %s source hints even when spelling/range match", field => {
    const result = observe(fixture(`[dependencies]\nexample = { ${field} = "opaque", version = "1.2.3", optional = true }`));
    expect(result.declarations[0]!.inventoryComparisons[0]!.declaredRequirementMatch).toBe("matches");
    expect(result.attention).toContain("cargo_source_overrides_not_verified");
    expect(result.manifest.declarations[0]!.sourceHints).toEqual({ [field]: "opaque" });
    expect(result.compatibleFixVerified).toBe(false);
  });
  it.each([null, "git+https://example.test/repo#abcd", "registry+https://example.test/index"]) (
    "does not invent a registry comparison for unverified source %s", source => {
      const result = observe(fixture(undefined, `version = 4\n${crate("example", "1.2.3", source)}`));
      expect(result.inventoryCandidates).toEqual([]);
      expect(result.attention).toContain(`inventory:Cargo.lock:${source === null ? "local_or_workspace_package" : "unverified_cargo_registry_source"}`);
    });
  it("does not invent a candidate for missing checksum", () => {
    expect(observe(fixture(undefined, `version = 4\n${crate("example", "1.2.3", registry, "")}`)).inventoryCandidates).toEqual([]);
  });
  it("retains missing/ambiguous reference attention without treating reference lists as declaration-owner edges", () => {
    const f = fixture(undefined, `version = 4\n${crate("tool", "1.0.0", null)}dependencies = ["example", "missing"]\n${crate()}${crate("example", "2.0.0")}`);
    const result = observe(f);
    expect(result.inventoryCandidates).toHaveLength(2);
    expect(result.attention).toEqual(expect.arrayContaining(["inventory:Cargo.lock:ambiguous_cargo_dependency_reference",
      "inventory:Cargo.lock:missing_cargo_dependency_entry"]));
    expect(result.direct).toBeNull();
  });

  it.each(["", '[workspace]\nmembers = ["crates/*"]']) ("empty declarations are not absence", content => {
    const result = observe(fixture(content));
    expect(result.declarations).toEqual([]);
    expect(result.inventoryCandidates).toEqual([]);
    expect(result.attention).toContain("empty_cargo_declarations_not_absence");
  });
  it.each(["1979-05-27T07:32:00Z", "1979-05-27T07:32:00", "1979-05-27", "07:32:00"])(
    "rejects temporal declaration %s before returning partial lockfile comparisons", scalar => {
      const f = fixture(`[dependencies]\nexample = "1.2.3"\ninvalid = ${scalar}`);
      expect(() => observe(f)).toThrow("invalid_cargo_manifest_dependency");
    });
  it("keeps malformed selected-file attention and does not leak positives from another lockfile", () => {
    const result = observe(fixture(undefined, `version = 4\n${crate()}${crate()}`, "Cargo.lock", "Cargo.toml",
      [{ path: "other/Cargo.lock", content: `version = 4\n${crate("example", "1.9.0")}` }]));
    expect(result.inventoryCandidates).toEqual([]);
    expect(result.attention).toContain("inventory:Cargo.lock:duplicate_cargo_tuple");
  });
  it("keeps independent positives when another file is malformed, without borrowing its locations", () => {
    const result = observe(fixture(undefined, undefined, "Cargo.lock", "Cargo.toml", [
      { path: "other/Cargo.lock", content: "version = 2" },
      { path: "third/Cargo.lock", content: `version = 4\n${crate("example", "1.9.0")}` },
    ]));
    expect(result.inventoryCandidates.map(row => row.version)).toEqual(["1.2.3", "2.0.0"]);
    expect(result.inventoryCandidates.flatMap(row => row.locations).every(row => row.path === "Cargo.lock")).toBe(true);
    expect(result.attention).toContain("inventory:other/Cargo.lock:unsupported_cargo_lockfile_version");
  });
  it("marks other colocated locks without selecting or borrowing npm tuples", () => {
    const result = observe(fixture(undefined, undefined, "Cargo.lock", "Cargo.toml", [
      { path: "package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/example": {
        version: "1.9.0", resolved: "https://registry.npmjs.org/example/-/example.tgz",
      } } }) },
    ]));
    expect(result.inventoryCandidates.map(row => row.ecosystem)).toEqual(["crates.io", "crates.io"]);
    expect(result.attention).toContain("multiple_colocated_lockfiles_not_selected");
  });
  it.each(["repo", "sourceSha", "defaultBranch"] as const)("rejects mismatched %s", field => {
    const f = fixture();
    f.source[field] = field === "repo" ? "other/repo" : field === "sourceSha" ? "d".repeat(40) : "develop";
    expect(() => observe(f)).toThrow("cargo_context_source_mismatch");
  });
  it("rejects stale/corrupt tree and content identities", () => {
    const f = fixture();
    f.tree.entries[0]!.sha = "d".repeat(40);
    expect(() => observe(f)).toThrow("discovery_hash_mismatch");
    rehash(f.tree);
    expect(() => observe(f)).toThrow("cargo_context_discovered_lockfile_mismatch");
    const changed = fixture();
    changed.source.files[0]!.content += "\n";
    expect(() => observe(changed)).toThrow("inventory_content_mismatch");
    const digest = fixture();
    digest.source.artifactDigest = `sha256:${"0".repeat(64)}`;
    expect(() => observe(digest)).toThrow("inventory_digest_mismatch");
  });
  it.each(["120000", "160000", "040000"]) ("rejects non-regular lockfile mode %s", mode => {
    const f = fixture();
    const entry = f.tree.entries.find(row => row.path === f.lockfilePath)!;
    Object.assign(entry, { mode, type: mode === "160000" ? "commit" : mode === "040000" ? "tree" : "blob", size: null });
    rehash(f.tree);
    expect(() => observe(f)).toThrow("cargo_context_discovered_lockfile_mismatch");
  });
  it("requires every retained lockfile to be exact-tree bound, including unselected files", () => {
    const f = fixture(undefined, undefined, "Cargo.lock", "Cargo.toml", [{ path: "other/Cargo.lock", content: `version = 4\n${crate()}` }]);
    f.tree.entries = f.tree.entries.filter(row => row.path !== "other/Cargo.lock");
    rehash(f.tree);
    expect(() => observe(f)).toThrow("cargo_context_discovered_lockfile_mismatch");
  });
  it("rejects a mismatched reported lockfile size, accepts unknown size and executable metadata", () => {
    const f = fixture();
    const entry = f.tree.entries.find(row => row.path === f.lockfilePath)!;
    entry.size = 1;
    rehash(f.tree);
    expect(() => observe(f)).toThrow("cargo_context_discovered_lockfile_mismatch");
    entry.size = null;
    entry.mode = "100755";
    rehash(f.tree);
    expect(observe(f).inventoryCandidates).toHaveLength(2);
  });
  it("rejects absent/non-Cargo lockfile selection and wrong/unbound manifest selection", () => {
    const f = fixture();
    expect(() => observe({ ...f, lockfilePath: "other/Cargo.lock" })).toThrow("unsupported_cargo_context_lockfile");
    expect(() => observe({ ...f, manifestPath: "other/Cargo.toml" })).toThrow("cargo_manifest_not_in_discovery");
    expect(() => observe({ ...f, manifestPath: "package.json" })).toThrow("unsupported_cargo_manifest_path");
    expect(() => observe(fixture(undefined, '{"lockfileVersion":3,"packages":{"":{}}}', "package-lock.json")))
      .toThrow("unsupported_cargo_context_lockfile");
  });
  it("rejects lossy input, bad candidates and changed manifest bytes", () => {
    expect(() => observe(fixture(undefined, '#\ud800\nversion = 4\n' + crate()))).toThrow("invalid_inventory_utf8");
    expect(() => observe(fixture('#\ud800'))).toThrow("invalid_cargo_manifest_utf8");
    expect(() => observe(fixture(), { declaredName: "example", version: "1.2.3+build" })).toThrow("unsupported_cargo_manifest_candidate");
    expect(() => observe({ ...fixture(), manifestContent: '[dependencies]\nexample = "2.0.0"' }))
      .toThrow("cargo_manifest_discovered_blob_mismatch");
  });
  it("does not mutate retained inputs and returns isolated deterministic observations across concurrent replay", async () => {
    const f = fixture();
    const retained = structuredClone(f);
    const expected = observe(f);
    const results = await Promise.all(Array.from({ length: 8 }, async () => observe(f)));
    expect(results.every(result => canonicalJson(result) === canonicalJson(expected))).toBe(true);
    results[0]!.inventoryCandidates[0]!.locations[0]!.locator = "changed";
    results[0]!.declarations[0]!.inventoryComparisons[0]!.nameBasis.push("package_hint");
    expect(f).toEqual(retained);
    expect(observe(f)).toEqual(expected);
    expect(results[1]).toEqual(expected);
  });
  it("bounds aggregate name/range comparisons across all declaration owners without truncating", () => {
    const content = Array.from({ length: 1001 }, (_, i) => `[target.t${i}.dependencies]\nexample = "1.0.0"`).join("\n");
    const locked = `version = 4\n${Array.from({ length: 10 }, (_, i) => crate("example", `1.0.${i}`)).join("")}`;
    expect(() => observe(fixture(content, locked))).toThrow("cargo_context_comparison_capacity");
  });
  it("bounds the combined observation even when each individual input and manifest observation fits", () => {
    const content = `[dependencies]\n${Array.from({ length: 2600 }, (_, i) => `x${i} = "${"1".repeat(120)}"`).join("\n")}`;
    const f = fixture(content);
    expect(() => observeCargoManifest(f.tree, f.manifestPath, f.manifestContent)).not.toThrow();
    expect(() => observe(f)).toThrow("cargo_context_observation_capacity");
  });
  it("retains tool provenance and has no rule-6, normalized fix, resolution or publication fields", () => {
    const result = observe();
    expect(result.toolVersions).toMatchObject({ "vuln-sentinel-cargo-manifest": "1.1.1",
      "vuln-sentinel-cargo-lockfile-context": "1.0.0", "vuln-sentinel-inventory": "0.1.13", "smol-toml": "1.9.1", semver: "7.7.4" });
    for (const field of ["fixedVersion", "compatibleFix", "resolutionEligible", "publicationAllowed", "owner"]) expect(Object.hasOwn(result, field)).toBe(false);
    expect(result.attention).toEqual([...result.attention].sort());
  });
});
