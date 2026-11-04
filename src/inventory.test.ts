import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalJson, sha256 } from "./identity.js";
import { parseLockfileInventory } from "./inventory.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";

function snapshot(files: Record<string, string>): RepositoryLockfiles {
  const blobs = Object.entries(files).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([path, content]) => ({
    path, content, sha256: sha256(content), etag: null,
    blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex"),
  }));
  return {
    repo: "example/project", sourceSha: "a".repeat(40), defaultBranch: "main", files: blobs,
    artifactDigest: `sha256:${sha256(canonicalJson(blobs.map(file => [file.path, file.sha256])))}`,
  };
}

function npmRow(name = "lib", version = "1.2.3") {
  return { version, resolved: `https://registry.npmjs.org/${name}/-/${name.split("/").at(-1)}-${version}.tgz`, integrity: "sha512-abc=" };
}

function npm(packages: Record<string, unknown>, lockfileVersion = 3) {
  return JSON.stringify({ lockfileVersion, packages: { "": {}, ...packages } });
}

function parseNpm(packages: Record<string, unknown>, lockfileVersion = 3) {
  return parseLockfileInventory(snapshot({ "package-lock.json": npm(packages, lockfileVersion) }));
}

const pnpm = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias:
        specifier: npm:lib@^1.2.3
        version: lib@1.2.3
      '@scope/lib':
        specifier: ^2.0.0
        version: 2.0.0(lib@1.2.3)
packages:
  lib@1.2.3:
    resolution: {integrity: sha512-abc=}
  '@scope/lib@2.0.0':
    resolution: {integrity: sha512-def=}
snapshots:
  lib@1.2.3: {}
  '@scope/lib@2.0.0(lib@1.2.3)':
    dependencies:
      lib: 1.2.3
`;

function cargoPackage(name = "lib", version = "1.2.3", source: string | null = "registry+https://github.com/rust-lang/crates.io-index") {
  return `[[package]]\nname = "${name}"\nversion = "${version}"\n${source === null ? "" : `source = "${source}"\n`}checksum = "${"a".repeat(64)}"\n`;
}

function parseFile(path: string, content: string) {
  return parseLockfileInventory(snapshot({ [path]: content }));
}

function expectAttention(path: string, content: string, code?: string) {
  const result = parseFile(path, content);
  expect(result.coverage.configuredPathsParsed).toBe(false);
  expect(result.files[0]!.status).toBe("attention");
  if (code) expect(result.files[0]!.issues).toContain(code);
  return result;
}

describe("lockfile inventory boundary", () => {
  it("binds parsed entries to immutable bytes, source SHA, paths and parser versions", () => {
    const input = snapshot({ "package-lock.json": npm({ "node_modules/lib": npmRow() }) });
    const result = parseLockfileInventory(input);
    expect(result.repo).toBe(input.repo);
    expect(result.sourceSha).toBe(input.sourceSha);
    expect(result.artifactDigest).toBe(input.artifactDigest);
    expect(result.dependencies).toEqual([{
      ecosystem: "npm", package: "lib", version: "1.2.3", scope: "unknown", direct: null,
      locations: [{ path: "package-lock.json", locator: "node_modules/lib" }],
    }]);
    expect(result.coverage).toEqual({
      configuredPathsParsed: true, repositoryDiscovery: "not_proven", fullDependencyClosure: "not_proven", runtimeCompleteness: "not_proven",
    });
    const { inventorySha256, ...payload } = result;
    expect(inventorySha256).toBe(sha256(canonicalJson(payload)));
    expect(result.toolVersions).toMatchObject({ yaml: "2.9.1", "smol-toml": "1.9.1" });
    expect(parseLockfileInventory(input)).toEqual(result);
  });

  it.each(["content", "sha256", "blobSha"] as const)("rejects tampered %s before parsing", field => {
    const input = snapshot({ "package-lock.json": npm({}) });
    input.files[0]![field] += "tampered";
    expect(() => parseLockfileInventory(input)).toThrow("inventory_content_mismatch");
  });

  it("rejects an unbound digest and invalid source revision", () => {
    const input = snapshot({ "package-lock.json": npm({}) });
    input.artifactDigest = `sha256:${"b".repeat(64)}`;
    expect(() => parseLockfileInventory(input)).toThrow("inventory_digest_mismatch");
    input.sourceSha = "main";
    expect(() => parseLockfileInventory(input)).toThrow("invalid_inventory_snapshot");
  });

  it("rejects duplicate, traversal and absent paths", () => {
    const input = snapshot({ "package-lock.json": npm({}) });
    input.files.push(input.files[0]!);
    expect(() => parseLockfileInventory(input)).toThrow("duplicate_inventory_path");
    expect(() => parseFile("../package-lock.json", npm({}))).toThrow("invalid_inventory_file");
    expect(() => parseLockfileInventory(snapshot({}))).toThrow("invalid_inventory_snapshot");
  });

  it("retains supported positives alongside an unsupported lockfile without certifying coverage", () => {
    const result = parseLockfileInventory(snapshot({
      "package-lock.json": npm({ "node_modules/lib": npmRow() }), "go.sum": "unknown",
    }));
    expect(result.dependencies).toHaveLength(1);
    expect(result.coverage.configuredPathsParsed).toBe(false);
    expect(result.files.find(file => file.path === "go.sum")!.issues).toEqual(["unsupported_lockfile_format"]);
  });

  it("deduplicates query tuples while retaining every installed occurrence and lockfile", () => {
    const content = npm({ "node_modules/lib": npmRow(), "node_modules/other/node_modules/lib": npmRow() });
    const result = parseLockfileInventory(snapshot({ "package-lock.json": content, "nested/npm-shrinkwrap.json": content }));
    expect(result.dependencies).toHaveLength(1);
    expect(result.dependencies[0]!.locations).toHaveLength(4);
  });

  it("does not mutate the caller snapshot", () => {
    const input = snapshot({ "package-lock.json": npm({ "node_modules/lib": npmRow() }) });
    const before = structuredClone(input);
    parseLockfileInventory(input);
    expect(input).toEqual(before);
  });

  it("fails on configured byte capacity, never truncates", () => {
    expect(() => parseFile("package-lock.json", " ".repeat(2 * 1024 * 1024 + 1))).toThrow("inventory_content_mismatch");
  });
});

describe("npm lockfile entries", () => {
  it("parses this repository's actual locked registry inventory offline", () => {
    const result = parseFile("package-lock.json", readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.length).toBeGreaterThan(20);
  });

  it("holds duplicate JSON keys rather than silently discarding a package", () => {
    const content = '{"lockfileVersion":3,"packages":{"":{},"":{}}}';
    expectAttention("package-lock.json", content, "ambiguous_npm_json");
  });

  it("throws at query capacity without returning a truncated inventory", () => {
    const packages = Object.fromEntries(Array.from({ length: 2_001 }, (_, index) => [`node_modules/lib${index}`, npmRow(`lib${index}`)]));
    expect(() => parseNpm(packages)).toThrow("inventory_query_capacity");
  });

  it.each([2, 3])("supports version %i, scoped names, aliases and nested multiple versions", lockfileVersion => {
    const result = parseNpm({
      "node_modules/@scope/lib": npmRow("@scope/lib"),
      "node_modules/alias": { ...npmRow("real"), name: "real" },
      "node_modules/lib": npmRow(), "node_modules/real/node_modules/lib": npmRow("lib", "2.0.0"),
    }, lockfileVersion);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.map(dep => `${dep.package}@${dep.version}`).sort()).toEqual(["@scope/lib@1.2.3", "lib@1.2.3", "lib@2.0.0", "real@1.2.3"]);
  });

  it("does not lower priority or infer scope from dev/optional/platform flags", () => {
    const result = parseNpm({ "node_modules/lib": { ...npmRow(), dev: true, optional: true, os: ["!linux"] } });
    expect(result.dependencies[0]!.scope).toBe("unknown");
    expect(result.dependencies[0]!.direct).toBeNull();
  });

  it.each(["git+https://example.com/lib", "file:lib", "https://mirror.invalid/lib.tgz", "https://registry.npmjs.org.evil/lib.tgz", "https://user:password@registry.npmjs.org/lib/-/lib.tgz", undefined])("holds unverified sources: %s", resolved => {
    const result = parseNpm({ "node_modules/lib": { ...npmRow(), resolved } });
    expect(result.dependencies).toEqual([]);
    expect(result.files[0]!.issues).toContain("unverified_npm_registry_source");
  });

  it("does not query a registry package under an unrelated alias identity", () => {
    const result = parseNpm({ "node_modules/alias": npmRow("real") });
    expect(result.dependencies).toEqual([]);
    expect(result.files[0]!.issues).toContain("npm_tarball_identity_mismatch");
  });

  it("retains registry entries but holds links/workspaces", () => {
    const result = parseNpm({ "node_modules/lib": npmRow(), "node_modules/local": { link: true, resolved: "packages/local" }, "packages/local": { version: "1.0.0" } });
    expect(result.dependencies).toHaveLength(1);
    expect(result.files[0]!.issues).toContain("local_or_workspace_package");
  });

  it("detects missing explicit dependency entries and accepts hoisted references", () => {
    const packages = { "node_modules/lib": npmRow(), "node_modules/other": { ...npmRow("other"), dependencies: { lib: "^1.0.0" } } };
    expect(parseNpm(packages).coverage.configuredPathsParsed).toBe(true);
    expect(parseNpm({ "": { dependencies: { absent: "^1.0.0" } }, ...packages }).files[0]!.issues).toContain("missing_npm_dependency_entry");
  });

  it.each([1, 4, "3"])("holds unsupported lockfile version %s", v => {
    expectAttention("package-lock.json", JSON.stringify({ lockfileVersion: v, packages: {} }), "unsupported_npm_lockfile_version");
  });

  it.each(["{", "null", "[]", '{"lockfileVersion":3}', '{"lockfileVersion":3,"packages":{}}'])("holds malformed/missing-root input: %s", content => {
    expect(expectAttention("package-lock.json", content).dependencies).toEqual([]);
  });

  it.each(["latest", "v1.0.0", "^1.0.0", "1.0", "1.0.0|other", "file:local"])("holds ambiguous version %s and discards that file's partial results", v => {
    const result = parseNpm({ "node_modules/lib": npmRow(), "node_modules/bad": npmRow("bad", v) });
    expect(result.dependencies).toEqual([]);
    expect(result.files[0]!.issues).toContain("unsupported_package_version");
  });
});

describe("pnpm v9 entries", () => {
  it("parses every registry tuple with scopes, aliases and peer suffixes", () => {
    const result = parseFile("pnpm-lock.yaml", pnpm);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.map(dep => `${dep.package}@${dep.version}`).sort()).toEqual(["@scope/lib@2.0.0", "lib@1.2.3"]);
  });

  it("accepts a genuinely empty importer without claiming repository completeness", () => {
    const result = parseFile("pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .: {}\n");
    expect(result.dependencies).toEqual([]);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.coverage.fullDependencyClosure).toBe("not_proven");
  });

  it.each([
    [pnpm.replace("version: lib@1.2.3", "version: lib@9.0.0"), "missing_pnpm_snapshot_reference"],
    [pnpm.replace("'@scope/lib@2.0.0':", "'@scope/lib@3.0.0':"), "missing_pnpm_package_entry"],
    [pnpm.replace("  lib@1.2.3: {}", "  lib@1.2.4: {}"), "missing_pnpm_snapshot_entry"],
    [pnpm.replace("version: lib@1.2.3", "version: link:../local"), "local_or_workspace_package"],
    [pnpm.replace("sha512-abc=", "sha1-abc="), "missing_pnpm_integrity"],
    [pnpm.replace("resolution: {integrity: sha512-abc=}", "resolution: {tarball: https://example.com/lib.tgz}"), "unverified_pnpm_registry_source"],
  ])("requires attention for incomplete source/reference: %s", (content, code) => {
    expectAttention("pnpm-lock.yaml", content, code);
  });

  it.each([
    "lockfileVersion: '8.0'\nimporters: {}", "lockfileVersion: '9.0'\nimporters: {}",
    "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\nimporters: {'.': {}}",
    "lockfileVersion: '9.0'\nimporters: &a {'.': *a}",
    "lockfileVersion: '9.0'\nimporters: !custom {'.': {}}", "[malformed",
    "lockfileVersion: '9.0'\nimporters: {'.': {}}\n<<: {packages: {}}",
    "lockfileVersion: '9.0'\nimporters: {'.': {}}\npackages: null",
  ])("rejects unsupported versions, duplicate keys, aliases, custom tags and malformed YAML", content => {
    expectAttention("pnpm-lock.yaml", content);
  });
});

describe("Cargo locked inventory is not native inventory", () => {
  it.each([3, 4])("retains every registry version in Cargo lock v%i", v => {
    const result = parseFile("Cargo.lock", `version = ${v}\n${cargoPackage()}${cargoPackage("lib", "2.0.0")}`);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.map(dep => dep.version)).toEqual(["1.2.3", "2.0.0"]);
    expect(result.dependencies.every(dep => dep.scope === "unknown")).toBe(true);
    expect(result.coverage.runtimeCompleteness).toBe("not_proven");
  });

  it.each([null, "git+https://example.com/lib#abc", "registry+https://custom.invalid/index"])("holds local/git/custom sources rather than inventing crates.io identity: %s", source => {
    const result = expectAttention("Cargo.lock", `version = 4\n${cargoPackage("lib", "1.2.3", source)}`);
    expect(result.dependencies).toEqual([]);
  });

  it.each([
    [`version = 4\n${cargoPackage()}${cargoPackage()}`, "duplicate_cargo_tuple"],
    [`version = 4\n${cargoPackage().replace("a".repeat(64), "invalid")}`, "missing_cargo_checksum"],
    [`version = 4\n${cargoPackage("lib", "^1.0.0")}`, "unsupported_package_version"],
    [`version = 2\n${cargoPackage()}`, "unsupported_cargo_lockfile_version"],
    ["version = 4\n[[package]]\nname = 'lib'", "unsupported_package_version"],
  ])("requires attention for malformed/unverified Cargo: %s", (content, code) => {
    expectAttention("Cargo.lock", content, code);
  });

  it("does not accept duplicate TOML keys", () => {
    expectAttention("Cargo.lock", `version = 4\nversion = 4\n${cargoPackage()}`, "malformed_lockfile");
  });
});
