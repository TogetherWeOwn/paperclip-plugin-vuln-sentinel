import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CARGO_MANIFEST_VERSION, observeCargoManifest } from "./cargo-manifest.js";
import type { RepositoryDiscovery, RepositoryTreeEntry } from "./github-discovery.js";
import { canonicalJson, sha256 } from "./identity.js";

function rehash(value: RepositoryDiscovery): RepositoryDiscovery {
  const { sha256: _, ...body } = value;
  return { ...body, sha256: sha256(canonicalJson(["repository-discovery-v1", body])) };
}
function discovery(content: string, path = "Cargo.toml"): RepositoryDiscovery {
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
function observe(content: string) { return observeCargoManifest(discovery(content), "Cargo.toml", content); }

const manifest = `
[package]
name = "tool"
version = "1.0.0"
description = "雪"
[dependencies]
zebra = "2"
alias = { package = "real-crate", version = "^1.0", optional = true, features = ["derive"] }
[dev-dependencies]
alias = "=3.0.0"
[build-dependencies]
alias = { workspace = true }
[workspace.dependencies]
alias = { version = "4", default-features = false }
[target.'cfg(unix)'.dependencies]
alias = { path = "../local", version = "5" }
[target.x86_64-pc-windows-msvc.build-dependencies]
alias = { git = "https://example.test/repo", rev = "abc" }
`;

describe("offline exact-tree Cargo declaration observations", () => {
  it("binds exact bytes/tree/commit and preserves owners, sections, rename hints and conflicts without resolving them", () => {
    const source = discovery(manifest, "crates/tool/Cargo.toml");
    const result = observeCargoManifest(source, "crates/tool/Cargo.toml", manifest);
    expect(result).toMatchObject({ version: CARGO_MANIFEST_VERSION, status: "attention", scope: "unknown", direct: null,
      compatibleFixVerified: false, source: { repo: source.repo, sourceSha: source.sourceSha, treeSha: source.treeSha,
        discoverySha256: source.sha256, path: "crates/tool/Cargo.toml", blobSha: source.entries.at(-1)!.sha, sha256: sha256(manifest) } });
    expect(result.declarations.map(row => [row.owner, row.target, row.section, row.declaredName, row.versionRequirement])).toEqual([
      ["package", null, "dependencies", "alias", "^1.0"], ["package", null, "dependencies", "zebra", "2"],
      ["package", null, "dev-dependencies", "alias", "=3.0.0"], ["package", null, "build-dependencies", "alias", null],
      ["workspace", null, "dependencies", "alias", "4"], ["target", "cfg(unix)", "dependencies", "alias", "5"],
      ["target", "x86_64-pc-windows-msvc", "build-dependencies", "alias", null],
    ]);
    expect(result.declarations[0]).toMatchObject({ packageHint: "real-crate", unevaluatedFields: ["features", "optional"] });
    expect(result.declarations[3]).toMatchObject({ workspaceInherited: true, packageHint: null, versionRequirement: null });
    expect(result.declarations[5]!.sourceHints).toEqual({ path: "../local" });
    expect(result.declarations[6]!.sourceHints).toEqual({ git: "https://example.test/repo", rev: "abc" });
    const { observationSha256, ...body } = result;
    expect(observationSha256).toBe(sha256(canonicalJson(["cargo-manifest-observation-v1", body])));
    expect(result.attention).toEqual(expect.arrayContaining(["cargo_workspace_inheritance_not_resolved", "cargo_target_selectors_not_evaluated",
      "cargo_source_overrides_not_verified", "cargo_requirements_not_fully_evaluated", "manifest_scope_not_applied"]));
  });

  it.each(["1", "1.2", "^1.2.3", "~1.0", "*", ">=1, <2", "=1.2.3+build", "1.2.3-beta.1", "nonsense"])(
    "retains requirement %s verbatim without applying npm semantics or fix promotion", requirement => {
      const result = observe(`[dependencies]\nexample = ${JSON.stringify(requirement)}`);
      expect(result.declarations[0]!.versionRequirement).toBe(requirement);
      expect(result).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
      expect(result.attention).toContain("cargo_requirements_not_fully_evaluated");
    });

  it("retains dotted declarations and prototype-shaped names as data", () => {
    const result = observe('[dependencies]\nconstructor.version = "1"\n__proto__ = "2"\nAlias_Crate = "3"');
    expect(result.declarations.map(row => row.declaredName)).toEqual(["Alias_Crate", "__proto__", "constructor"]);
  });
  it("does not merge inherited workspace constraints, source overrides or mutually conflicting hints", () => {
    const result = observe('[dependencies]\nx = { workspace = true, version = "1", git = "https://example.test/repo", path = "../x" }\n[workspace.dependencies]\nx = "2"');
    expect(result.declarations.map(row => row.versionRequirement)).toEqual(["1", "2"]);
    expect(result.declarations[0]).toMatchObject({ workspaceInherited: true, sourceHints: { git: "https://example.test/repo", path: "../x" } });
    expect(result.compatibleFixVerified).toBe(false);
  });
  it.each(["registry", "registry-index", "branch", "tag", "rev", "git", "path"])("retains %s only as an unverified hint", field => {
    const result = observe(`[dependencies]\nx = { ${field} = "opaque" }`);
    expect(result.declarations[0]!.sourceHints).toEqual({ [field]: "opaque" });
    expect(result.attention).toContain("cargo_source_overrides_not_verified");
  });
  it.each(["patch", "replace", "features", "profile", "cargo-features"])("marks %s influences unevaluated", field => {
    expect(observe(`${field} = {}\n[dependencies]\nx = "1"`).attention).toContain(`cargo_manifest_${field}_not_evaluated`);
  });
  it("marks unknown dependency fields and empty tables as unevaluated, never source or range proof", () => {
    const result = observe('[dependencies]\nx = { future-field = { nested = true }, optional = true }\ny = {}');
    expect(result.declarations[0]).toMatchObject({ versionRequirement: null, packageHint: null, unevaluatedFields: ["future-field", "optional"] });
    expect(result.attention).toContain("cargo_declaration_without_requirement_or_source");
  });
  it.each(["", "[package]\nname = 'tool'\nversion = '1.0.0'", "[workspace]\nmembers = ['crates/*']"])(
    "empty declarations do not prove absence or workspace membership", content => {
      const result = observe(content);
      expect(result.declarations).toEqual([]);
      expect(result.attention).toContain("empty_cargo_declarations_not_absence");
    });

  it.each(["null", "1", "true", "[]", '""', '"bad\\nrequirement"', JSON.stringify("x".repeat(257))])(
    "rejects malformed dependency requirement %s", value => {
      const code = value === "1" || value === "true" || value === "[]" ? "invalid_cargo_manifest_dependency" : value === "null"
        ? "invalid_cargo_manifest_toml" : "invalid_cargo_manifest_requirement";
      expect(() => observe(`[dependencies]\nx = ${value}`)).toThrow(code);
    });
  it.each(['version = 1', 'version = true', 'version = []', 'version = ""'])("rejects malformed table %s", fields => {
    expect(() => observe(`[dependencies]\nx = { ${fields} }`)).toThrow("invalid_cargo_manifest_requirement");
  });
  it.each(["false", '"true"', "1"])("does not interpret workspace=%s as inheritance", value => {
    expect(() => observe(`[dependencies]\nx = { workspace = ${value} }`)).toThrow("unsupported_cargo_manifest_workspace_flag");
  });
  it.each(["bad/name", "bad name", "", "a".repeat(65)])("rejects unsupported declared name %s", name => {
    expect(() => observe(`[dependencies]\n${JSON.stringify(name)} = "1"`)).toThrow("invalid_cargo_manifest_dependency_name");
    expect(() => observe(`[dependencies]\nx = { package = ${JSON.stringify(name)}, version = "1" }`)).toThrow("invalid_cargo_manifest_package_hint");
  });
  it.each(['git = 1', 'path = []', 'registry = ""', 'rev = "bad\\nref"'])("rejects malformed source hint %s", fields => {
    expect(() => observe(`[dependencies]\nx = { ${fields} }`)).toThrow("invalid_cargo_manifest_source_hint");
  });
  it.each(['[dependencies]\nx = "1"\nx = "2"', '[dependencies]\nx = "1"\n[dependencies]\ny = "2"', '[dependencies', 'dependencies = null'])(
    "rejects duplicate or invalid TOML before observations", content => {
      expect(() => observe(content)).toThrow("invalid_cargo_manifest_toml");
    });
  it.each(['dependencies = []', 'workspace = []', 'target = []', '[target]\nunix = []', '[target."cfg(unix)"]\ndependencies = 1'])(
    "rejects malformed owner/map %s", content => { expect(() => observe(content)).toThrow(/invalid_cargo_manifest_/u); });
  describe.each(["1979-05-27T07:32:00Z", "1979-05-27T07:32:00", "1979-05-27", "07:32:00"])("TOML temporal scalar %s is not a table", scalar => {
    it.each([
      ["dependencies = SCALAR", "invalid_cargo_manifest_dependency_map"],
      ["[dependencies]\nx = SCALAR", "invalid_cargo_manifest_dependency"],
      ["workspace = SCALAR", "invalid_cargo_manifest_workspace"],
      ["[workspace]\ndependencies = SCALAR", "invalid_cargo_manifest_dependency_map"],
      ["target = SCALAR", "invalid_cargo_manifest_targets"],
      ["[target]\nunix = SCALAR", "invalid_cargo_manifest_target_owner"],
      ["[target.unix]\ndependencies = SCALAR", "invalid_cargo_manifest_dependency_map"],
    ])("rejects %s without returning empty/partial declarations", (template, code) => {
      expect(() => observe(template.replace("SCALAR", scalar))).toThrow(code);
    });
  });
  it("keeps ordinary/inline tables and temporal metadata or requirement strings distinct", () => {
    const content = 'workspace = { dependencies = { shared = "1.2.3" } }\ntarget = { unix = { dependencies = { target_dep = "1.2.3" } } }\n'
      + '[package]\nreleased = 1979-05-27\n[dependencies]\nx = { version = "1.2.3" }\ny = "1979-05-27"';
    const result = observe(content);
    expect(result.declarations.map(row => row.declaredName)).toEqual(["x", "y", "shared", "target_dep"]);
    expect(result.declarations[1]).toMatchObject({ versionRequirement: "1979-05-27", requirementKind: "unsupported" });
    expect(result).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
  });
  it.each(["", "x".repeat(1025), "bad\nselector"])("rejects unsupported target key %s", target => {
    expect(() => observe(`[target.${JSON.stringify(target)}.dependencies]\nx = "1"`)).toThrow("invalid_cargo_manifest_target");
  });

  it("rejects exact-byte, size and discovery corruption", () => {
    const source = discovery(manifest);
    expect(() => observeCargoManifest(source, "Cargo.toml", manifest + "\n")).toThrow("cargo_manifest_discovered_blob_mismatch");
    source.entries[0]!.size = 1;
    expect(() => observeCargoManifest(rehash(source), "Cargo.toml", manifest)).toThrow("cargo_manifest_discovered_blob_mismatch");
    expect(() => observeCargoManifest({ ...source, sourceSha: "d".repeat(40) }, "Cargo.toml", manifest)).toThrow("discovery_hash_mismatch");
  });
  it("requires the exact tracked Cargo.toml path", () => {
    expect(() => observeCargoManifest(discovery(manifest, "other/Cargo.toml"), "Cargo.toml", manifest)).toThrow("cargo_manifest_not_in_discovery");
    expect(() => observeCargoManifest(discovery(manifest), "Cargo.lock", manifest)).toThrow("unsupported_cargo_manifest_path");
    expect(() => observeCargoManifest(discovery(manifest), "../Cargo.toml", manifest)).toThrow("cargo_manifest_not_in_discovery");
  });
  it.each(["120000", "160000", "040000"])("rejects non-regular file mode %s", mode => {
    const source = discovery(manifest);
    Object.assign(source.entries[0]!, { mode, type: mode === "160000" ? "commit" : mode === "040000" ? "tree" : "blob", size: null });
    expect(() => observeCargoManifest(rehash(source), "Cargo.toml", manifest)).toThrow("cargo_manifest_not_in_discovery");
  });
  it("accepts unknown size and executable file metadata without executing anything", () => {
    const source = discovery(manifest);
    Object.assign(source.entries[0]!, { mode: "100755", size: null });
    expect(observeCargoManifest(rehash(source), "Cargo.toml", manifest).declarations).toHaveLength(7);
  });
  it("rejects lossy surrogate encoding and over-limit content", () => {
    expect(() => observe('description = "\ud800"')).toThrow("invalid_cargo_manifest_utf8");
    const content = "#" + "x".repeat(2 * 1024 * 1024);
    expect(() => observe(content)).toThrow("cargo_manifest_content_capacity");
  });
  it("shares one declaration budget across package, workspace and target owners", () => {
    const rows = (prefix: string, count: number) => Array.from({ length: count }, (_, i) => `${prefix}${i} = "1"`).join("\n");
    const content = `[dependencies]\n${rows("a", 3500)}\n[workspace.dependencies]\n${rows("b", 3500)}\n[target.unix.build-dependencies]\n${rows("c", 3001)}`;
    expect(() => observe(content)).toThrow("cargo_manifest_declaration_capacity");
  });
  it("bounds empty target owners independently of the declaration count", () => {
    expect(() => observe(Array.from({ length: 10001 }, (_, i) => `[target.t${i}]`).join("\n"))).toThrow("cargo_manifest_target_capacity");
  });
  it("bounds output before returning a large partial observation", () => {
    const rows = Array.from({ length: 4500 }, (_, i) => `x${i} = { version = "${"1".repeat(256)}" }`).join("\n");
    expect(() => observe(`[dependencies]\n${rows}`)).toThrow("cargo_manifest_observation_capacity");
  });
  it.each(["dev_dependencies", "build_dependencies"])("holds legacy %s sections instead of silently normalizing them", section => {
    for (const prefix of ["", "target.unix."]) {
      const result = observe(`[${prefix}${section}]\nx = "1"`);
      expect(result.declarations).toEqual([]);
      expect(result.attention).toContain("cargo_legacy_dependency_sections_not_evaluated");
    }
  });
  it("retains multiple aliases for the same package without guessing identity or merging requirements", () => {
    const result = observe('[dependencies]\na = { package = "real", version = "1" }\nb = { package = "real", version = "2" }');
    expect(result.declarations.map(row => [row.declaredName, row.packageHint, row.versionRequirement])).toEqual([
      ["a", "real", "1"], ["b", "real", "2"],
    ]);
    expect(result.direct).toBeNull();
  });
  it("does not mutate discovery or share mutable observation objects across replay", () => {
    const source = discovery(manifest);
    const retained = structuredClone(source);
    const first = observeCargoManifest(source, "Cargo.toml", manifest);
    const expected = structuredClone(first);
    first.declarations[0]!.sourceHints.path = "changed";
    first.declarations[0]!.unevaluatedFields.push("changed");
    first.source.repo = "changed/repo";
    expect(source).toEqual(retained);
    expect(observeCargoManifest(source, "Cargo.toml", manifest)).toEqual(expected);
  });
  it("bounds source hints without interpreting or truncating the boundary", () => {
    const value = "x".repeat(1024);
    expect(observe(`[dependencies]\nx = { git = "${value}" }`).declarations[0]!.sourceHints.git).toBe(value);
    expect(() => observe(`[dependencies]\nx = { git = "${value}x" }`)).toThrow("invalid_cargo_manifest_source_hint");
  });
  it("sorts targets and declared names independently of TOML insertion order", () => {
    const one = observe('[target.z.dependencies]\nb = "2"\na = "1"\n[target.a.dependencies]\nx = "3"');
    const two = observe('[target.a.dependencies]\nx = "3"\n[target.z.dependencies]\na = "1"\nb = "2"');
    expect(one.declarations).toEqual(two.declarations);
    expect(one.observationSha256).not.toBe(two.observationSha256);
    expect(observe(manifest)).toEqual(observe(manifest));
  });
});

function compare(requirement: string, version: string) {
  const content = `[dependencies]\nx = ${JSON.stringify(requirement)}`;
  return observeCargoManifest(discovery(content), "Cargo.toml", content, { declaredName: "x", version });
}

describe("bounded Cargo stable candidate requirement observations", () => {
  it.each([
    ["1.2.3", "1.2.3", true], ["1.2.3", "1.9.9", true], ["1.2.3", "2.0.0", false],
    ["1.2.3", "1.2.2", false], ["^1.2.3", "1.9.9", true], ["^1.2.3", "2.0.0", false],
    ["0.2.3", "0.2.9", true], ["0.2.3", "0.3.0", false], ["^0.2.3", "0.2.2", false],
    ["0.0.3", "0.0.3", true], ["0.0.3", "0.0.4", false], ["^0.0.0", "0.0.0", true],
    ["^0.0.0", "0.0.1", false], ["~1.2.3", "1.2.9", true], ["~1.2.3", "1.3.0", false],
    ["~0.0.3", "0.0.4", true], ["~0.0.3", "0.1.0", false], ["=1.2.3", "1.2.3", true],
    ["=1.2.3", "1.2.4", false], [">=1.2.3", "2.0.0", true], [">=1.2.3", "1.2.2", false],
    [">1.2.3", "1.2.3", false], [">1.2.3", "1.2.4", true], ["<=1.2.3", "1.2.3", true],
    ["<=1.2.3", "1.2.4", false], ["<1.2.3", "1.2.3", false], ["<1.2.3", "1.2.2", true],
    [">=1.2.3, <1.5.0", "1.4.9", true], [">=1.2.3, <1.5.0", "1.5.0", false],
    ["1.2.3, <1.5.0", "1.4.9", true], ["1.2.3, <1.5.0", "1.5.0", false],
    [">=2.0.0, <1.0.0", "1.5.0", false], [" ^1.2.3 , >=1.3.0 ", "1.3.0", true],
  ] as const)("compares Cargo requirement %s against %s without fix proof", (requirement, version, matches) => {
    const result = compare(requirement, version);
    expect(result.candidate).toEqual({ declaredName: "x", version });
    expect(result.declarations[0]).toMatchObject({ versionRequirement: requirement, requirementKind: "stable_semver_subset",
      candidateRangeMatch: matches ? "matches" : "does_not_match" });
    expect(result).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
    expect(result.attention).toEqual(expect.arrayContaining(["manifest_range_not_compatible_fix", "release_availability_not_verified",
      "cargo_declared_names_not_registry_identity", "cargo_features_and_dependency_resolution_not_evaluated"]));
  });

  it.each(["1", "1.2", "0.0", "*", "1.*", "1.2.*", "1.2.x", "v1.2.3", "01.2.3", "1.02.3", "1.2.03",
    "1.2.3-beta.1", "1.2.3+build", "1.2.3 || 2.0.0", ">=1.2.3 <2.0.0", "1.2.3 - 2.0.0", "= 1.2.3",
    ",1.2.3", "1.2.3,", "1.2.3,,<2.0.0", "nonsense", "1.2.3 ", "9007199254740992.0.0"])(
    "withholds unsupported requirement %s instead of reporting exclusion", requirement => {
      const result = compare(requirement, "9.9.9");
      expect(result.declarations[0]).toMatchObject({ versionRequirement: requirement, requirementKind: "unsupported", candidateRangeMatch: "unknown" });
      expect(result.attention).toContain("unsupported_cargo_manifest_requirement");
      expect(result.compatibleFixVerified).toBe(false);
    });

  it("bounds conjunctions without truncating a conflicting ninth clause", () => {
    const clauses = Array(8).fill(">=1.0.0").join(",");
    expect(compare(clauses, "1.2.3").declarations[0]!.candidateRangeMatch).toBe("matches");
    expect(compare(`${clauses},<1.0.0`, "1.2.3").declarations[0]).toMatchObject({ requirementKind: "unsupported", candidateRangeMatch: "unknown" });
  });

  it("checks a stable boundary grid using independent full-triple interval expectations", () => {
    const cases = [
      ["1.2.3", [1, 2, 3], [2, 0, 0]], ["^0.2.3", [0, 2, 3], [0, 3, 0]],
      ["^0.0.3", [0, 0, 3], [0, 0, 4]], ["~0.0.3", [0, 0, 3], [0, 1, 0]],
      ["~1.2.3", [1, 2, 3], [1, 3, 0]], [">=0.2.3, <1.3.0", [0, 2, 3], [1, 3, 0]],
    ] as const;
    const order = (a: readonly number[], b: readonly number[]) => a[0]! - b[0]! || a[1]! - b[1]! || a[2]! - b[2]!;
    for (const [requirement, lower, upper] of cases) {
      for (const tuple of [[0, 0, 0], [0, 0, 2], [0, 0, 3], [0, 0, 4], [0, 1, 0], [0, 2, 2], [0, 2, 3],
        [0, 2, 4], [0, 3, 0], [1, 2, 2], [1, 2, 3], [1, 2, 4], [1, 3, 0], [1, 9, 9], [2, 0, 0]]) {
        const expected = order(tuple, lower) >= 0 && order(tuple, upper) < 0;
        expect(compare(requirement, tuple.join(".")).declarations[0]!.candidateRangeMatch,
          `${requirement}: ${tuple.join(".")}`).toBe(expected ? "matches" : "does_not_match");
      }
    }
  });

  it("preserves conflicting package/workspace/target requirements and unreported inheritance independently", () => {
    const content = '[dependencies]\nx = "1.2.3"\ny = "1.2.3"\n[dev-dependencies]\nx = "=2.0.0"\n[workspace.dependencies]\nx = "^2.0.0"\n[target.unix.dependencies]\nx = { workspace = true }';
    const result = observeCargoManifest(discovery(content), "Cargo.toml", content, { declaredName: "x", version: "1.5.0" });
    expect(result.declarations.map(row => row.candidateRangeMatch)).toEqual(["matches", null, "does_not_match", "does_not_match", "unknown"]);
    expect(result.declarations.at(-1)).toMatchObject({ requirementKind: "not_reported", versionRequirement: null, workspaceInherited: true });
    expect(result.attention).toContain("cargo_workspace_inheritance_not_resolved");
    expect(result.compatibleFixVerified).toBe(false);
  });

  it("selects only an explicit declaration key, never guesses a rename or registry identity", () => {
    const content = '[dependencies]\nalias = { package = "real", version = "1.2.3", git = "opaque" }';
    const tree = discovery(content);
    const missing = observeCargoManifest(tree, "Cargo.toml", content, { declaredName: "real", version: "1.5.0" });
    expect(missing.attention).toContain("candidate_not_declared_in_cargo_manifest");
    expect(missing.declarations[0]!.candidateRangeMatch).toBeNull();
    const selected = observeCargoManifest(tree, "Cargo.toml", content, { declaredName: "alias", version: "1.5.0" });
    expect(selected.declarations[0]).toMatchObject({ packageHint: "real", sourceHints: { git: "opaque" }, candidateRangeMatch: "matches" });
    expect(selected.attention).toContain("cargo_source_overrides_not_verified");
    expect(selected.compatibleFixVerified).toBe(false);
  });

  it.each([null, {}, { declaredName: "x" }, { declaredName: "bad/name", version: "1.2.3" },
    { declaredName: "x", version: "1" }, { declaredName: "x", version: "01.2.3" },
    { declaredName: "x", version: "1.2.3-beta.1" }, { declaredName: "x", version: "1.2.3+build" },
    { declaredName: "x", version: 123 }, { declaredName: "x", version: "1.2.3\n" }])(
    "rejects unsupported candidate %j rather than converting it to a negative", candidate => {
      const content = '[dependencies]\nx = "1.2.3"';
      expect(() => observeCargoManifest(discovery(content), "Cargo.toml", content,
        candidate as Parameters<typeof observeCargoManifest>[3])).toThrow("unsupported_cargo_manifest_candidate");
    });

  it("keeps unqueried and missing requirements distinct and candidate-specific hashes replayable", () => {
    const content = '[dependencies]\nx = { workspace = true }\ny = "1.2.3"';
    const tree = discovery(content);
    const plain = observeCargoManifest(tree, "Cargo.toml", content);
    expect(plain.candidate).toBeNull();
    expect(plain.declarations.map(row => row.candidateRangeMatch)).toEqual([null, null]);
    const candidate = { declaredName: "x", version: "1.5.0" };
    const selected = observeCargoManifest(tree, "Cargo.toml", content, candidate);
    expect(selected.declarations.map(row => row.candidateRangeMatch)).toEqual(["unknown", null]);
    expect(selected.observationSha256).not.toBe(plain.observationSha256);
    expect(selected.source).toEqual(plain.source);
    expect(selected.toolVersions).toMatchObject({ "vuln-sentinel-cargo-manifest": "1.1.1", semver: "7.7.4" });
    const expected = structuredClone(selected);
    candidate.version = "2.0.0";
    expect(selected).toEqual(expected);
    expect(observeCargoManifest(tree, "Cargo.toml", content, expected.candidate!)).toEqual(expected);
  });
});
