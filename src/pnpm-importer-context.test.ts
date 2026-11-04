import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { stringify } from "yaml";
import type { RepositoryDiscovery, RepositoryTreeEntry } from "./github-discovery.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { OsvDependency } from "./osv.js";
import { observePnpmImporterContext, PNPM_IMPORTER_CONTEXT_VERSION } from "./pnpm-importer-context.js";

const manifest = { dependencies: { example: "^1.0.0" } };
const importer = { dependencies: { example: { specifier: "^1.0.0", version: "1.2.3" } } };
const candidate: OsvDependency = { ecosystem: "npm", package: "example", version: "1.5.0" };
function blob(content: string) {
  const bytes = Buffer.from(content);
  return createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
}
function rehash(tree: RepositoryDiscovery) {
  const { sha256: _, ...body } = tree;
  tree.sha256 = sha256(canonicalJson(["repository-discovery-v1", body]));
}
function fixture(owner: unknown = importer, declared: unknown = manifest, selected = ".", path = "pnpm-lock.yaml", raw?: string) {
  const content = raw ?? stringify({ lockfileVersion: "9.0", importers: { [selected]: owner },
    packages: { "example@1.2.3": { resolution: { integrity: "sha512-YWJj" } },
      "example@1.8.0": { resolution: { integrity: "sha512-YWJj" } } },
    snapshots: { "example@1.2.3": {}, "example@1.8.0": {} } }, { aliasDuplicateObjects: false });
  const file = { path, content, blobSha: blob(content), sha256: sha256(content), etag: null };
  const source: RepositoryLockfiles = { repo: "org/repo", sourceSha: "b".repeat(40), defaultBranch: "main", files: [file],
    artifactDigest: `sha256:${sha256(canonicalJson([[path, file.sha256]]))}` };
  const manifestPath = path.slice(0, path.lastIndexOf("/") + 1) + (selected === "." ? "" : `${selected}/`) + "package.json";
  const manifestContent = typeof declared === "string" ? declared : JSON.stringify(declared);
  const entries = new Map<string, RepositoryTreeEntry>();
  for (const row of [file, { path: manifestPath, content: manifestContent }]) {
    const parts = row.path.split("/");
    for (let i = 1; i < parts.length; i++) {
      const p = parts.slice(0, i).join("/");
      entries.set(p, { path: p, type: "tree", mode: "040000", sha: "a".repeat(40), size: null });
    }
    entries.set(row.path, { path: row.path, type: "blob", mode: "100644", sha: blob(row.content), size: Buffer.byteLength(row.content) });
  }
  const tree: RepositoryDiscovery = { version: 1, repo: source.repo, sourceSha: source.sourceSha, defaultBranch: "main",
    treeSha: "c".repeat(40), entries: [...entries.values()].sort((a, b) => a.path < b.path ? -1 : 1), sha256: "" };
  rehash(tree);
  return { tree, source, path, selected, manifestPath, manifestContent };
}
function observe(f = fixture(), c?: OsvDependency) {
  return observePnpmImporterContext(f.tree, f.source, f.path, f.selected, f.manifestContent, c);
}

describe("offline pnpm importer declaration context", () => {
  it.each([[".", "pnpm-lock.yaml"], ["packages/web", "pnpm-lock.yaml"], [".", "apps/web/pnpm-lock.yaml"],
    ["packages/web", "apps/web/pnpm-lock.yaml"]])("binds exact importer %s beneath %s without owner inference", (selected, path) => {
    const f = fixture(importer, manifest, selected, path);
    const result = observe(f, candidate);
    expect(result).toMatchObject({ version: PNPM_IMPORTER_CONTEXT_VERSION, status: "attention", scope: "unknown", direct: null,
      compatibleFixVerified: false, source: { importer: selected, lockfilePath: path, lockfileBlobSha: f.source.files[0]!.blobSha,
        discoverySha256: f.tree.sha256 }, manifest: { source: { path: f.manifestPath } } });
    expect(result.declarations).toEqual([{ section: "dependencies", package: "example", manifestSpecifier: "^1.0.0",
      lockfileSpecifier: "^1.0.0", resolvedReference: "1.2.3", comparison: "same_specifier",
      manifestCandidateRangeMatch: "matches", lockfileCandidateRangeMatch: "matches" }]);
    expect(result.inventoryCandidates.map(row => row.version)).toEqual(["1.2.3", "1.8.0"]);
    const { observationSha256, ...body } = result;
    expect(observationSha256).toBe(sha256(canonicalJson(["pnpm-importer-context-observation-v1", body])));
  });

  it("preserves conflicting sections, peer-only manifest constraints and independent range results", () => {
    const result = observe(fixture({ dependencies: { example: { specifier: "^2.0.0", version: "1.2.3" } },
      devDependencies: { example: { specifier: ">=1.0.0 <2.0.0", version: "1.8.0" } },
      optionalDependencies: { other: { specifier: "workspace:*", version: "link:../other" } } },
    { dependencies: { example: "^1.0.0" }, devDependencies: { example: "^1.0.0" }, peerDependencies: { example: "^2.0.0" } }), candidate);
    expect(result.declarations.map(row => [row.section, row.comparison, row.manifestCandidateRangeMatch, row.lockfileCandidateRangeMatch]))
      .toEqual([["dependencies", "different_specifier", "matches", "does_not_match"],
        ["devDependencies", "different_specifier", "matches", "matches"], ["optionalDependencies", "lockfile_only", null, null],
        ["peerDependencies", "manifest_only", "does_not_match", null]]);
    expect(result.attention).toEqual(expect.arrayContaining(["pnpm_importer_declarations_disagree",
      "pnpm_importer_candidate_declaration_mismatch", "unsupported_pnpm_importer_specifier", "declared_name_without_inventory_candidate"]));
    expect(result.compatibleFixVerified).toBe(false);
  });

  it.each(["", "workspace:*", "npm:other@^1.0.0", "latest", "^1.0.0 ||", "1.x", "1.0.0-beta.1", "file:../local"])(
    "keeps unsupported importer specifier %s unknown", specifier => {
      const result = observe(fixture({ dependencies: { example: { specifier, version: "1.2.3" } } }), candidate);
      expect(result.declarations[0]).toMatchObject({ lockfileSpecifier: specifier, lockfileCandidateRangeMatch: "unknown",
        manifestCandidateRangeMatch: "matches" });
      expect(result.attention).toContain("unsupported_pnpm_importer_specifier");
    });

  it.each(["link:../local", "file:../local", "other@1.2.3", "1.2.3(peer@2.0.0)"])(
    "retains reference %s without using it to select one installed version or rewrite package identity", reference => {
      const result = observe(fixture({ dependencies: { example: { specifier: "^1.0.0", version: reference } } }), candidate);
      expect(result.declarations[0]!.resolvedReference).toBe(reference);
      expect(result.inventoryCandidates.map(row => [row.package, row.version])).toEqual([["example", "1.2.3"], ["example", "1.8.0"]]);
      expect(result).toMatchObject({ scope: "unknown", direct: null, compatibleFixVerified: false });
    });

  it("does not query an unrelated package or absent side and never equates an empty specifier with absence", () => {
    const f = fixture({ dependencies: { example: { specifier: "", version: "1.2.3" } } }, {});
    expect(observe(f, candidate).declarations[0]).toMatchObject({ comparison: "lockfile_only", manifestSpecifier: null,
      lockfileSpecifier: "", manifestCandidateRangeMatch: null, lockfileCandidateRangeMatch: "unknown" });
    expect(observe(f, { ...candidate, package: "other" }).declarations[0]!.lockfileCandidateRangeMatch).toBeNull();
    expect(observe(f).declarations[0]!.lockfileCandidateRangeMatch).toBeNull();
    expect(observe(fixture({}, {}), candidate).attention).toEqual(expect.arrayContaining([
      "empty_importer_declarations_not_absence", "candidate_not_declared_in_pnpm_importer", "candidate_not_declared_in_manifest"]));
  });

  it("compares scoped package names exactly", () => {
    const result = observe(fixture({ dependencies: { "@scope/example": { specifier: "^1.0.0", version: "1.2.3" },
      example: { specifier: "^2.0.0", version: "1.2.3" } } }, { dependencies: { "@scope/example": "^1.0.0", example: "^2.0.0" } }),
    { ...candidate, package: "@scope/example" });
    expect(result.declarations.map(row => [row.package, row.lockfileCandidateRangeMatch])).toEqual([["@scope/example", "matches"], ["example", null]]);
  });

  it.each(["", "..", "../web", "./web", "web/..", "web/./app", "/web", "web/", "web//app", "web\\app", "web\napp", "x".repeat(1025)])(
    "rejects unsupported importer locator %s", selected => {
      const f = fixture(); f.selected = selected;
      expect(() => observe(f)).toThrow("invalid_pnpm_importer_path");
    });

  it.each(["repo", "sourceSha", "defaultBranch"] as const)("rejects mismatched %s", field => {
    const f = fixture(); f.source[field] = field === "sourceSha" ? "d".repeat(40) : "other";
    expect(() => observe(f)).toThrow("pnpm_importer_source_mismatch");
  });

  it("requires exact selected importer rather than borrowing root or another workspace", () => {
    const f = fixture(importer, manifest, "packages/web", "pnpm-lock.yaml",
      stringify({ lockfileVersion: "9.0", importers: { ".": importer, "packages/other": structuredClone(importer) }, packages: {}, snapshots: {} }));
    expect(() => observe(f)).toThrow("missing_pnpm_importer");
  });

  it("requires exact manifest bytes at the selected reported path, not root bytes", () => {
    const f = fixture(importer, manifest, "packages/web");
    expect(() => observe({ ...f, manifestContent: JSON.stringify({ dependencies: { example: "^2.0.0" } }) })).toThrow("npm_manifest_discovered_blob_mismatch");
    f.tree.entries = f.tree.entries.filter(row => row.path !== f.manifestPath); rehash(f.tree);
    expect(() => observe(f)).toThrow("npm_manifest_not_in_discovery");
  });

  it.each(["sha", "mode", "size", "missing"])("rejects discovered lockfile mismatch %s", change => {
    const f = fixture(); const entry = f.tree.entries.find(row => row.path === f.path)!;
    if (change === "sha") entry.sha = "d".repeat(40);
    if (change === "mode") entry.mode = "120000";
    if (change === "size") entry.size = entry.size! + 1;
    if (change === "missing") f.tree.entries = f.tree.entries.filter(row => row.path !== f.path);
    rehash(f.tree);
    expect(() => observe(f)).toThrow("pnpm_importer_discovered_lockfile_mismatch");
  });

  it.each([
    "lockfileVersion: '9.0'\nimporters: {}\nimporters: {}\n",
    "lockfileVersion: '9.0'\nimporters: &owners\n  .: {}\npackages: *owners\n",
    "lockfileVersion: '9.0'\nimporters:\n  .:\n    <<: {}\n",
    "lockfileVersion: '9.0'\nimporters: !custom {}\n",
  ])("rejects ambiguous/expanded YAML rather than manufacturing context", raw => {
    expect(() => observe(fixture(importer, manifest, ".", "pnpm-lock.yaml", raw))).toThrow();
  });

  it.each([null, 1, {}, [], "bad\nvalue", "x".repeat(257)])("rejects malformed selected specifier %j", specifier => {
    expect(() => observe(fixture({ dependencies: { example: { specifier, version: "1.2.3" } } }))).toThrow("invalid_pnpm_specifier");
  });

  it.each([null, 1, {}, [], "bad\nvalue", "x".repeat(1025)])("rejects malformed selected resolved reference %j", version => {
    expect(() => observe(fixture({ dependencies: { example: { specifier: "^1.0.0", version } } }))).toThrow("invalid_pnpm_reference");
  });

  it("does not let malformed independent inventory provide partial candidates", () => {
    const f = fixture(importer, manifest, ".", "pnpm-lock.yaml", stringify({ lockfileVersion: "9.0", importers: { ".": importer,
      other: { dependencies: { other: { version: "1.2.3" } } } }, packages: { "example@1.2.3": { resolution: { integrity: "sha512-YWJj" } } },
    snapshots: { "example@1.2.3": {} } }));
    const result = observe(f, candidate);
    expect(result.declarations[0]!.comparison).toBe("same_specifier");
    expect(result.inventoryCandidates).toEqual([]);
    expect(result.attention).toContain("inventory:pnpm-lock.yaml:invalid_pnpm_specifier");
  });

  it.each(["1.2", "1.2.3+build", "1.2.3-beta.1"])("rejects unsupported candidate %s", version => {
    expect(() => observe(fixture(), { ...candidate, version })).toThrow("unsupported_npm_manifest_candidate");
  });

  it("rejects unsupported lockfile versions, formats, selected peer sections and malformed maps", () => {
    expect(() => observe(fixture(importer, manifest, ".", "pnpm-lock.yaml", stringify({ lockfileVersion: "6.0", importers: { ".": importer } }))))
      .toThrow("unsupported_pnpm_importer_lockfile_version");
    expect(() => observe(fixture(importer, manifest, ".", "package-lock.json"))).toThrow("unsupported_pnpm_importer_lockfile");
    expect(() => observe(fixture({ peerDependencies: {} }))).toThrow("unsupported_pnpm_importer_peer_section");
    expect(() => observe(fixture({ dependencies: [] }))).toThrow("invalid_pnpm_dependency_map");
  });

  it("bounds aggregate selected declarations before returning comparisons", () => {
    const dependencies = Object.fromEntries(Array.from({ length: 5001 }, (_, i) => [`pkg${i}`, { specifier: "^1.0.0", version: "1.2.3" }]));
    expect(() => observe(fixture({ dependencies, devDependencies: dependencies }, {}))).toThrow("pnpm_importer_declaration_capacity");
  });

  it("bounds the combined declaration union even when each input is individually within capacity", () => {
    const dependencies = Object.fromEntries(Array.from({ length: 5001 }, (_, i) => [`locked${i}`, { specifier: "^1.0.0", version: "1.2.3" }]));
    const declared = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`manifest${i}`, "^1.0.0"]));
    expect(() => observe(fixture({ dependencies }, { dependencies: declared }))).toThrow("pnpm_importer_declaration_capacity");
  });

  it("rejects expanded output above 1 MiB instead of truncating retained references", () => {
    const dependencies = Object.fromEntries(Array.from({ length: 1100 }, (_, i) => [`pkg${i}`, {
      specifier: "^1.0.0", version: "x".repeat(1024),
    }]));
    expect(() => observe(fixture({ dependencies }, {}))).toThrow("pnpm_importer_observation_capacity");
  });

  it("replays deterministically without mutating inputs or promoting a candidate to a verified fix", async () => {
    const f = fixture(); const before = structuredClone({ f, candidate });
    const results = await Promise.all(Array.from({ length: 4 }, () => Promise.resolve().then(() => observe(f, candidate))));
    expect(results.every(row => canonicalJson(row) === canonicalJson(results[0]))).toBe(true);
    expect({ f, candidate }).toEqual(before);
    expect(results[0]).toMatchObject({ status: "attention", scope: "unknown", direct: null, compatibleFixVerified: false });
    expect(results[0]!.attention).toEqual(expect.arrayContaining(["release_availability_not_verified",
      "pnpm_transitive_and_workspace_constraints_not_verified", "pnpm_importer_path_not_workspace_proof"]));
  });
});
