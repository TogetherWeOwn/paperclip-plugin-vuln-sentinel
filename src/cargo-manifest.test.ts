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
      "cargo_source_overrides_not_verified", "cargo_requirements_not_evaluated", "manifest_scope_not_applied"]));
  });

  it.each(["1", "1.2", "^1.2.3", "~1.0", "*", ">=1, <2", "=1.2.3+build", "1.2.3-beta.1", "nonsense"])(
    "retains requirement %s verbatim without applying npm semantics or fix promotion", requirement => {
      const result = observe(`[dependencies]\nexample = ${JSON.stringify(requirement)}`);
      expect(result.declarations[0]!.versionRequirement).toBe(requirement);
      expect(result).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
      expect(result.attention).toContain("cargo_requirements_not_evaluated");
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
