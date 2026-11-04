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

  it.each(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "Cargo.lock", "go.sum"])(
    "rejects lossy UTF-8 in %s before format parsing, even with matching replacement-byte hashes", path => {
      for (const value of ["\ud800", "\udfff", "\ud800x", "x\udfff", "\udfff\ud800"]) {
        const input = snapshot({ [path]: value });
        const before = structuredClone(input);
        expect(() => parseLockfileInventory(input)).toThrow("invalid_inventory_utf8");
        expect(input).toEqual(before);
      }
    });

  it("rejects lossy metadata rather than claiming a successfully parsed npm inventory", () => {
    const content = npm({ "node_modules/lib": npmRow() }).replace('"lockfileVersion":3', '"note":"\ud800","lockfileVersion":3');
    expect(() => parseFile("package-lock.json", content)).toThrow("invalid_inventory_utf8");
  });

  it("rejects the entire snapshot when another file is not exact UTF-8", () => {
    const input = snapshot({ "package-lock.json": npm({ "node_modules/lib": npmRow() }), "nested/go.sum": "\ud800" });
    expect(() => parseLockfileInventory(input)).toThrow("invalid_inventory_utf8");
  });

  it.each(["雪", "😀", "�", "\\ud800", "\\udfff"])(
    "retains exact UTF-8 or escaped JSON text %s without normalization", value => {
      const content = npm({ "node_modules/lib": npmRow() }).replace('"lockfileVersion":3', `"note":"${value}","lockfileVersion":3`);
      const input = snapshot({ "package-lock.json": content });
      const result = parseLockfileInventory(input);
      expect(result.coverage.configuredPathsParsed).toBe(true);
      expect(result.dependencies[0]).toMatchObject({ package: "lib", version: "1.2.3", scope: "unknown", direct: null });
      expect(result.artifactDigest).toBe(input.artifactDigest);
      expect(input.files[0]!.content).toBe(content);
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

describe("pnpm importer path boundary", () => {
  const withImporter = (path: string) => pnpm.replace("  .:\n", `  ? ${JSON.stringify(path)}\n  :\n`);

  it.each(["", "..", "../web", "./web", "web/..", "web/./app", "/web", "web/", "web//app",
    "web\\app", "web\napp", "web\u0000app", "web\u007fapp", "x".repeat(1025)])(
    "holds unsupported importer path %j even when its dependency references resolve", path => {
      const result = expectAttention("pnpm-lock.yaml", withImporter(path), "invalid_pnpm_importer_path");
      expect(result.dependencies).toEqual([]);
    });

  it.each([".", "packages/web", "apps/.hidden/web", "packages/@scope/web", "x".repeat(1024)])(
    "retains supported importer path %s without workspace or scope inference", path => {
      const input = snapshot({ "pnpm-lock.yaml": withImporter(path) });
      const before = structuredClone(input);
      const result = parseLockfileInventory(input);
      expect(result.coverage.configuredPathsParsed).toBe(true);
      expect(result.coverage.fullDependencyClosure).toBe("not_proven");
      expect(result.dependencies).toHaveLength(2);
      expect(result.dependencies.every(dep => dep.scope === "unknown" && dep.direct === null)).toBe(true);
      expect(parseLockfileInventory(input)).toEqual(result);
      expect(input).toEqual(before);
    });

  it("checks an empty unselected importer and preserves only independent-file positives", () => {
    const malformed = pnpm.replace("importers:\n", 'importers:\n  "../external": {}\n');
    const input = snapshot({ "pnpm-lock.yaml": malformed, "nested/package-lock.json": npm({ "node_modules/lib": npmRow() }) });
    const before = structuredClone(input);
    const result = parseLockfileInventory(input);
    expect(result.files.find(row => row.path === "pnpm-lock.yaml")!.issues).toEqual(["invalid_pnpm_importer_path"]);
    expect(result.dependencies).toMatchObject([{ package: "lib", locations: [{ path: "nested/package-lock.json" }] }]);
    expect(result.coverage.configuredPathsParsed).toBe(false);
    expect(parseLockfileInventory(input)).toEqual(result);
    expect(input).toEqual(before);
  });
});

describe("pnpm YAML mapping identity", () => {
  it.each(["true", "false", "null", "~", "42", "0x2a", "1.5", ".nan", "[example]", "{example: value}", ""])(
    "holds non-string mapping key %j before JavaScript conversion", key => {
      const content = `${pnpm}\nmetadata:\n  ? ${key}\n  : value\n`;
      const result = expectAttention("pnpm-lock.yaml", content, "unsupported_pnpm_yaml_key");
      expect(result.dependencies).toEqual([]);
    });

  it.each(["dependencies", "devDependencies", "optionalDependencies"])(
    "does not collapse boolean and quoted string keys in %s", section => {
      const content = `lockfileVersion: '9.0'\nimporters:\n  .:\n    ${section}:\n      true: {specifier: 1.0.0, version: 1.0.0}\n      'true': {specifier: 2.0.0, version: 2.0.0}\npackages:\n  true@2.0.0:\n    resolution: {integrity: sha512-abc=}\nsnapshots:\n  true@2.0.0: {}\n`;
      const result = expectAttention("pnpm-lock.yaml", content, "unsupported_pnpm_yaml_key");
      expect(result.dependencies).toEqual([]);
    });

  it.each(["'true'", "'false'", "'null'", "'42'", "'1.5'"])("preserves quoted name %s exactly", key => {
    const name = key.slice(1, -1);
    const content = `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      ${key}: {specifier: 1.2.3, version: 1.2.3}\npackages:\n  ${name}@1.2.3:\n    resolution: {integrity: sha512-abc=}\nsnapshots:\n  ${name}@1.2.3: {}\n`;
    const result = parseFile("pnpm-lock.yaml", content);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies).toMatchObject([{ package: name, version: "1.2.3", scope: "unknown", direct: null }]);
  });

  it("discards only the ambiguous file, preserving independent inventory and exact raw bytes", () => {
    const content = `${pnpm}\nmetadata: {true: first, 'true': second}\n`;
    const input = snapshot({ "pnpm-lock.yaml": content, "nested/package-lock.json": npm({ "node_modules/lib": npmRow() }) });
    const before = structuredClone(input);
    const result = parseLockfileInventory(input);
    expect(result.files.find(row => row.path === "pnpm-lock.yaml")!.issues).toEqual(["unsupported_pnpm_yaml_key"]);
    expect(result.dependencies).toMatchObject([{ package: "lib", locations: [{ path: "nested/package-lock.json" }] }]);
    expect(result.coverage.configuredPathsParsed).toBe(false);
    expect(input).toEqual(before);
    expect(parseLockfileInventory(input)).toEqual(result);
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

  it.each([
    "not_node_modules/lib", "packages/not_node_modules/lib", "packages/custom_node_modules/@scope/lib",
    "node_modules-helper/not_node_modules/lib",
  ])("does not derive an installed registry identity from the substring in %s", locator => {
    const name = locator.includes("@scope/") ? "@scope/lib" : "lib";
    const result = parseNpm({ [locator]: npmRow(name) });
    expect(result.dependencies).toEqual([]);
    expect(result.files[0]!.issues).toContain("local_or_workspace_package");
    expect(result.coverage.configuredPathsParsed).toBe(false);
  });

  it.each([
    "node_modules/parent/not_node_modules/lib", "packages/app/node_modules/parent/not_node_modules/@scope/lib",
  ])("does not let a later substring hide the malformed installed suffix in %s", locator => {
    const result = parseNpm({ [locator]: npmRow(locator.includes("@scope/") ? "@scope/lib" : "lib") });
    expect(result.dependencies).toEqual([]);
    expect(result.files[0]!.issues).toContain("invalid_npm_name");
    expect(result.coverage.configuredPathsParsed).toBe(false);
  });

  it.each([
    "node_modules/lib", "node_modules/parent/node_modules/lib",
    "packages/not_node_modules/node_modules/lib", "packages/app/node_modules/@scope/lib",
  ])("retains exact node_modules path segments in %s without owner inference", locator => {
    const name = locator.includes("@scope/") ? "@scope/lib" : "lib";
    const result = parseNpm({ [locator]: npmRow(name) });
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies).toEqual([{
      ecosystem: "npm", package: name, version: "1.2.3", scope: "unknown", direct: null,
      locations: [{ path: "package-lock.json", locator }],
    }]);
  });

  it("retains independent valid positives while holding lookalike local paths", () => {
    const result = parseNpm({ "not_node_modules/lib": npmRow(), "node_modules/other": npmRow("other") });
    expect(result.dependencies.map(dep => dep.package)).toEqual(["other"]);
    expect(result.files[0]!.issues).toEqual(["local_or_workspace_package"]);
  });

  it("discards a malformed installed suffix without losing another file's positives", () => {
    const result = parseLockfileInventory(snapshot({
      "package-lock.json": npm({ "node_modules/good": npmRow("good"), "node_modules/parent/not_node_modules/lib": npmRow() }),
      "nested/package-lock.json": npm({ "node_modules/other": npmRow("other") }),
    }));
    expect(result.dependencies.map(dep => dep.package)).toEqual(["other"]);
    expect(result.coverage.configuredPathsParsed).toBe(false);
    expect(result.files.find(file => file.path === "package-lock.json")!.issues).toContain("invalid_npm_name");
  });

  describe.each([2, 3])("version %i complete npm installation locators", lockfileVersion => {
    it.each([
      "node_modules/parent/extra/node_modules/lib", "node_modules/@scope/parent/extra/node_modules/lib",
      "node_modules/parent/not_node_modules/other/node_modules/lib", "node_modules/node_modules/lib",
      "node_modules/@scope/node_modules/lib", "node_modules/PARENT/node_modules/lib",
      "packages/app/node_modules/parent/extra/node_modules/lib",
      "node_modules/parent\\other/node_modules/lib", "node_modules/parent\u0000/node_modules/lib",
      "packages/app\\other/node_modules/lib", "packages/app\nother/node_modules/lib",
    ])("holds malformed enclosing path %j even when the final name is valid", locator => {
      const result = parseNpm({ "node_modules/good": npmRow("good"), [locator]: npmRow() }, lockfileVersion);
      expect(result.coverage.configuredPathsParsed).toBe(false);
      expect(result.files[0]!.issues).toContain("invalid_npm_locator");
      expect(result.dependencies).toEqual([]);
    });

    it.each([
      "node_modules/parent/node_modules/lib", "node_modules/@scope/parent/node_modules/lib",
      "node_modules/parent/node_modules/@scope/lib",
      "node_modules/@first/parent/node_modules/@second/parent/node_modules/@scope/lib",
      "packages/custom_node_modules/app/node_modules/@scope/parent/node_modules/lib",
    ])("retains complete scoped and workspace-prefixed path %s without inferring owner edges", locator => {
      const name = locator.endsWith("/@scope/lib") ? "@scope/lib" : "lib";
      const input = snapshot({ "npm-shrinkwrap.json": npm({ [locator]: npmRow(name) }, lockfileVersion) });
      const before = structuredClone(input);
      const result = parseLockfileInventory(input);
      expect(result.coverage.configuredPathsParsed).toBe(true);
      expect(result.dependencies).toEqual([{
        ecosystem: "npm", package: name, version: "1.2.3", scope: "unknown", direct: null,
        locations: [{ path: "npm-shrinkwrap.json", locator }],
      }]);
      expect(result.coverage.fullDependencyClosure).toBe("not_proven");
      expect(result.coverage.runtimeCompleteness).toBe("not_proven");
      expect(input).toEqual(before);
      expect(parseLockfileInventory(input)).toEqual(result);
    });
  });

  it("preserves independent file positives when an enclosing npm installation path is malformed", () => {
    const input = snapshot({
      "npm-shrinkwrap.json": npm({ "node_modules/good": npmRow("good"), "node_modules/parent/extra/node_modules/lib": npmRow() }),
      "other/package-lock.json": npm({ "node_modules/other": npmRow("other") }),
    });
    const before = structuredClone(input);
    const result = parseLockfileInventory(input);
    expect(result.files.find(file => file.path === "npm-shrinkwrap.json")!.issues).toEqual(["invalid_npm_locator"]);
    expect(result.dependencies.map(dep => dep.package)).toEqual(["other"]);
    expect(result.coverage.configuredPathsParsed).toBe(false);
    expect(input).toEqual(before);
    expect(parseLockfileInventory(input)).toEqual(result);
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

  describe.each([2, 3])("version %i dependency declarations", lockfileVersion => {
    it.each(["dependencies", "devDependencies", "optionalDependencies"])("holds malformed %s values even when the installed target exists", kind => {
      for (const value of [null, true, 1, [], {}, "x".repeat(257), "^1.0.0\n", "\u0000", "\u007f"]) {
        for (const locator of ["", "node_modules/parent", "packages/local"]) {
          const input = snapshot({ "package-lock.json": npm({
            [locator]: { ...(locator.startsWith("node_modules/") ? npmRow("parent") : {}), [kind]: { lib: value } },
            "node_modules/lib": npmRow(),
          }, lockfileVersion) });
          const before = structuredClone(input);
          const result = parseLockfileInventory(input);
          expect(result.files[0]!.issues).toContain("invalid_npm_dependency_reference");
          expect(result.coverage.configuredPathsParsed).toBe(false);
          expect(result.dependencies).toEqual([]);
          expect(input).toEqual(before);
          expect(parseLockfileInventory(input)).toEqual(result);
        }
      }
    });

    it.each(["dependencies", "devDependencies", "optionalDependencies"])("retains valid %s strings without declaring range compatibility or ownership", kind => {
      for (const value of ["", "*", "^1.0.0", "latest", "npm:lib@^1.0.0", "workspace:*", "file:../lib", "git+https://example.com/lib.git", "x".repeat(256)]) {
        const result = parseNpm({ "": { [kind]: { lib: value } }, "node_modules/lib": npmRow() }, lockfileVersion);
        expect(result.coverage.configuredPathsParsed).toBe(true);
        expect(result.dependencies[0]).toMatchObject({ package: "lib", version: "1.2.3", scope: "unknown", direct: null });
        expect(result.coverage.fullDependencyClosure).toBe("not_proven");
        expect(result.coverage.runtimeCompleteness).toBe("not_proven");
      }
    });
  });

  it("discards malformed npm reference positives but preserves another file's inventory", () => {
    const result = parseLockfileInventory(snapshot({
      "npm-shrinkwrap.json": npm({ "node_modules/lib": { ...npmRow(), dependencies: { lib: false } } }),
      "other/package-lock.json": npm({ "node_modules/other": npmRow("other") }),
    }));
    expect(result.files.find(file => file.path === "npm-shrinkwrap.json")!.issues).toEqual(["invalid_npm_dependency_reference"]);
    expect(result.dependencies.map(dep => dep.package)).toEqual(["other"]);
    expect(result.coverage.configuredPathsParsed).toBe(false);
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

describe("canonical locked versions", () => {
  function locked(path: string, v: string) {
    if (path === "Cargo.lock") return `version = 4\n${cargoPackage("lib", v)}`;
    if (path === "pnpm-lock.yaml") return `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lib:\n        specifier: ^1.0.0\n        version: ${JSON.stringify(v)}\npackages:\n  ${JSON.stringify(`lib@${v}`)}:\n    resolution: {integrity: sha512-abc=}\nsnapshots:\n  ${JSON.stringify(`lib@${v}`)}: {}\n`;
    return npm({ "node_modules/lib": npmRow("lib", v), "node_modules/other": npmRow("other") });
  }

  describe.each(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "Cargo.lock"])("%s", path => {
    it.each(["1.2.3+vendor.1", "1.2.3+001", "1.2.3+Vendor-ABC.01", "1.2.3-beta.1+build.01"])("preserves canonical %s without dropping the file", v => {
      const result = parseFile(path, locked(path, v));
      expect(result.coverage.configuredPathsParsed).toBe(true);
      expect(result.dependencies.find(dep => dep.package === "lib")).toMatchObject({ version: v, scope: "unknown", direct: null });
      if (path.endsWith(".json")) expect(result.dependencies.find(dep => dep.package === "other")).toBeDefined();
      expect(result.coverage.fullDependencyClosure).toBe("not_proven");
      expect(result.coverage.runtimeCompleteness).toBe("not_proven");
      expect(parseFile(path, locked(path, v))).toEqual(result);
    });

    it.each(["v1.2.3+build", " 1.2.3+build", "1.2.3+build ", "01.2.3+build", "1.2.3-01+build", "1.2.3+", "1.2.3+a..b", "1.2.3+a+b", "1.2.3+a_b"])("holds noncanonical or invalid %s", v => {
      const result = expectAttention(path, locked(path, v), "unsupported_package_version");
      expect(result.dependencies).toEqual([]);
    });
  });

  it("keeps equal-precedence build identities and all their locations separate", () => {
    const result = parseNpm({
      "node_modules/lib": npmRow("lib", "1.2.3"),
      "node_modules/a/node_modules/lib": npmRow("lib", "1.2.3+one"),
      "node_modules/b/node_modules/lib": npmRow("lib", "1.2.3+two"),
      "node_modules/c/node_modules/lib": npmRow("lib", "1.2.3+one"),
    });
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.map(dep => dep.version).sort()).toEqual(["1.2.3", "1.2.3+one", "1.2.3+two"]);
    expect(result.dependencies.find(dep => dep.version === "1.2.3+one")!.locations.map(row => row.locator)).toEqual([
      "node_modules/a/node_modules/lib", "node_modules/c/node_modules/lib",
    ]);
  });
});

describe("aggregate JavaScript lockfile reference limits", () => {
  function fixture(format: "npm" | "pnpm", count: number, kind: string) {
    const owners = Array.from({ length: Math.ceil(count / 100) }, (_, index) => {
      const names = Array.from({ length: Math.min(100, count - index * 100) }, (_, dep) => [`lib${dep}`, format === "npm" ? "*" : { specifier: "npm:lib@1.2.3", version: "lib@1.2.3" }]);
      return [format === "npm" ? (index ? `node_modules/owner${index}` : "") : `workspace${index}`, { [kind]: Object.fromEntries(names) }] as const;
    });
    if (format === "npm") {
      const packages: Record<string, unknown> = Object.fromEntries(owners.map(([key, value]) => [key, { ...npmRow("owner"), name: "owner", ...value }]));
      for (let index = 0; index < 100; index++) packages[`node_modules/lib${index}`] = npmRow(`lib${index}`);
      return npm(packages);
    }
    return JSON.stringify({ lockfileVersion: "9.0", importers: Object.fromEntries(owners),
      packages: { "lib@1.2.3": { resolution: { integrity: "sha512-abc=" } } }, snapshots: { "lib@1.2.3": {} } });
  }

  describe.each(["npm", "pnpm"] as const)("%s", format => {
    const path = format === "npm" ? "package-lock.json" : "pnpm-lock.yaml";
    it.each(["dependencies", "devDependencies", "optionalDependencies"])("accepts exactly 10,000 aggregate %s without promoting coverage", kind => {
      const result = parseFile(path, fixture(format, 10_000, kind));
      expect(result.coverage.configuredPathsParsed).toBe(true);
      expect(result.dependencies.length).toBeGreaterThan(0);
      expect(result.dependencies.every(dep => dep.scope === "unknown" && dep.direct === null)).toBe(true);
      expect(result.coverage.fullDependencyClosure).toBe("not_proven");
    });
    it.each(["dependencies", "devDependencies", "optionalDependencies"])("holds 10,001 aggregate %s instead of returning partial positives", kind => {
      const content = fixture(format, 10_001, kind);
      const input = snapshot({ [path]: content, "other/Cargo.lock": `version = 4\n${cargoPackage()}` });
      const before = structuredClone(input);
      const result = parseLockfileInventory(input);
      expect(result.files.find(file => file.path === path)!.issues).toContain("inventory_entry_capacity");
      expect(result.coverage.configuredPathsParsed).toBe(false);
      expect(result.dependencies.map(dep => dep.ecosystem)).toEqual(["crates.io"]);
      expect(input).toEqual(before);
      expect(parseLockfileInventory(input)).toEqual(result);
    });
  });

  it("shares the npm budget across declaration sections and the root/package owners", () => {
    const root = JSON.parse(fixture("npm", 10_000, "dependencies"));
    root.packages["node_modules/lib0"].optionalDependencies = { lib1: "*" };
    expectAttention("package-lock.json", JSON.stringify(root), "inventory_entry_capacity");
  });

  it("shares the pnpm budget across importers and snapshots", () => {
    const root = JSON.parse(fixture("pnpm", 10_000, "dependencies"));
    root.snapshots["lib@1.2.3"].optionalDependencies = { lib: "1.2.3" };
    expectAttention("pnpm-lock.yaml", JSON.stringify(root), "inventory_entry_capacity");
  });
});

describe("pnpm v9 entries", () => {
  it("parses every registry tuple with scopes, aliases and peer suffixes", () => {
    const result = parseFile("pnpm-lock.yaml", pnpm);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.map(dep => `${dep.package}@${dep.version}`).sort()).toEqual(["@scope/lib@2.0.0", "lib@1.2.3"]);
  });

  function withReference(value: unknown, kind: string, owner = ".", importer = true) {
    return JSON.stringify({ lockfileVersion: "9.0",
      importers: { [owner]: importer ? { [kind]: { lib: value } } : {} },
      packages: { "lib@1.2.3": { resolution: { integrity: "sha512-abc=" } } },
      snapshots: { "lib@1.2.3": importer ? {} : { [kind]: { lib: value } } },
    });
  }

  it.each(["dependencies", "devDependencies", "optionalDependencies"])("holds malformed importer %s specifiers even when the resolved snapshot exists", kind => {
    for (const specifier of [undefined, null, true, 1, [], {}, "x".repeat(257), "^1.0.0\n", "\u0000", "\u007f"]) {
      for (const owner of [".", "packages/app"]) {
        const input = snapshot({ "pnpm-lock.yaml": withReference({ specifier, version: "1.2.3" }, kind, owner) });
        const before = structuredClone(input);
        const result = parseLockfileInventory(input);
        expect(result.files[0]!.issues).toContain("invalid_pnpm_specifier");
        expect(result.coverage.configuredPathsParsed).toBe(false);
        expect(result.dependencies).toEqual([]);
        expect(input).toEqual(before);
        expect(parseLockfileInventory(input)).toEqual(result);
      }
    }
  });

  it.each(["dependencies", "devDependencies", "optionalDependencies"])("retains bounded importer %s specifiers as shape only", kind => {
    for (const specifier of ["", "*", "^1.0.0", "latest", "npm:lib@^1.0.0", "workspace:*", "file:../lib", "git+https://example.com/lib.git", "雪", "x".repeat(256)]) {
      const result = parseFile("pnpm-lock.yaml", withReference({ specifier, version: "1.2.3" }, kind));
      expect(result.coverage.configuredPathsParsed).toBe(true);
      expect(result.dependencies[0]).toMatchObject({ package: "lib", version: "1.2.3", scope: "unknown", direct: null });
      expect(result.coverage.fullDependencyClosure).toBe("not_proven");
      expect(result.coverage.runtimeCompleteness).toBe("not_proven");
    }
  });

  it.each(["dependencies", "devDependencies", "optionalDependencies"])("validates importer %s declarations before holding local references", kind => {
    for (const version of ["link:../local", "file:../local"]) {
      const malformed = expectAttention("pnpm-lock.yaml", withReference({ specifier: false, version }, kind), "invalid_pnpm_specifier");
      expect(malformed.dependencies).toEqual([]);
      const local = expectAttention("pnpm-lock.yaml", withReference({ specifier: "workspace:*", version }, kind), "local_or_workspace_package");
      expect(local.dependencies[0]).toMatchObject({ package: "lib", scope: "unknown", direct: null });
    }
  });

  describe.each([true, false])("importer=%s resolved-reference shapes", importer => {
    it.each(["dependencies", "devDependencies", "optionalDependencies"])("rejects malformed %s references before local/snapshot lookup", kind => {
      for (const ref of [...(importer ? [undefined] : []), null, true, 1, [], {}, "x".repeat(1025), "1.2.3\n", "link:../local\u0000", "file:../local\u007f"]) {
        const value = importer ? { specifier: "*", version: ref } : ref;
        const result = expectAttention("pnpm-lock.yaml", withReference(value, kind, ".", importer), "invalid_pnpm_reference");
        expect(result.dependencies).toEqual([]);
      }
    });
  });

  it("checks the reference length boundary without changing peer-context identity", () => {
    for (const length of [1024, 1025]) {
      const ref = `1.2.3(${"x".repeat(length - 7)})`;
      expect(ref).toHaveLength(length);
      const content = JSON.parse(withReference({ specifier: "*", version: ref }, "dependencies"));
      content.snapshots = { [`lib@${ref}`]: {} };
      const result = parseFile("pnpm-lock.yaml", JSON.stringify(content));
      expect(result.coverage.configuredPathsParsed).toBe(length === 1024);
      if (length === 1024) expect(result.dependencies[0]).toMatchObject({ package: "lib", version: "1.2.3", scope: "unknown", direct: null });
      else expect(result.files[0]!.issues).toContain("invalid_pnpm_reference");
    }
  });

  it("discards malformed pnpm declaration positives but retains another file's inventory", () => {
    const result = parseLockfileInventory(snapshot({
      "pnpm-lock.yaml": withReference({ specifier: null, version: "1.2.3" }, "dependencies"),
      "other/package-lock.json": npm({ "node_modules/other": npmRow("other") }),
    }));
    expect(result.files.find(file => file.path === "pnpm-lock.yaml")!.issues).toEqual(["invalid_pnpm_specifier"]);
    expect(result.dependencies.map(dep => dep.package)).toEqual(["other"]);
    expect(result.coverage.configuredPathsParsed).toBe(false);
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

  it.each([3, 4])("checks supported reference forms in Cargo v%i without inferring scope or closure", v => {
    const content = `version = ${v}\n${cargoPackage("owner")}dependencies = ["lib", "other 2.0.0", "third 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]\n${cargoPackage()}${cargoPackage("other", "2.0.0")}${cargoPackage("third", "3.0.0")}`;
    const result = parseFile("Cargo.lock", content);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies).toHaveLength(4);
    expect(result.dependencies.every(dep => dep.scope === "unknown" && dep.direct === null)).toBe(true);
    expect(result.coverage.fullDependencyClosure).toBe("not_proven");
    expect(result.coverage.runtimeCompleteness).toBe("not_proven");
  });

  it.each(["absent", "lib 9.0.0", "lib 1.2.3 (registry+https://other.invalid/index)"])("holds missing Cargo reference %s while retaining known positives", reference => {
    const result = expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = [${JSON.stringify(reference)}]\n${cargoPackage()}`, "missing_cargo_dependency_entry");
    expect(result.dependencies.map(dep => dep.package).sort()).toEqual(["lib", "owner"]);
  });

  it.each(["lib", "lib 1.2.3"])("holds ambiguous Cargo reference %s without choosing one source or version", reference => {
    const extra = reference === "lib" ? cargoPackage("lib", "2.0.0") : cargoPackage("lib", "1.2.3", "registry+https://other.invalid/index");
    const result = expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = [${JSON.stringify(reference)}]\n${cargoPackage()}${extra}`, "ambiguous_cargo_dependency_reference");
    expect(result.dependencies.find(dep => dep.package === "lib")).toBeDefined();
  });

  it("resolves exact build-version references without collapsing equal-precedence versions", () => {
    const result = parseFile("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = ["lib 1.2.3+one", "lib 1.2.3+two"]\n${cargoPackage("lib", "1.2.3+one")}${cargoPackage("lib", "1.2.3+two")}`);
    expect(result.coverage.configuredPathsParsed).toBe(true);
    expect(result.dependencies.filter(dep => dep.package === "lib").map(dep => dep.version)).toEqual(["1.2.3+one", "1.2.3+two"]);
  });

  it.each(["lib ^1.2.3", "lib v1.2.3", "lib 1.2.3 trailing", "lib 1.2.3 ()", " lib", "lib ", "lib\\nother", "lib 1.2.3 (x(y))"])("holds unsupported Cargo reference %s", reference => {
    expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = [${JSON.stringify(reference)}]\n${cargoPackage()}`, "unsupported_cargo_dependency_reference");
  });

  it.each(["42", "{}", '"lib"', "[42]"])("holds malformed Cargo dependency list %s", dependencies => {
    expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = ${dependencies}\n${cargoPackage()}`, "invalid_cargo_dependencies");
  });

  it("holds duplicate references without dropping known package identities", () => {
    const result = expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = ["lib", "lib"]\n${cargoPackage()}`, "duplicate_cargo_dependency_reference");
    expect(result.dependencies).toHaveLength(2);
  });

  it("checks dependencies of local owners even though their registry identity remains unverified", () => {
    const result = expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner", "1.0.0", null)}dependencies = ["absent"]\n${cargoPackage()}`, "missing_cargo_dependency_entry");
    expect(result.files[0]!.issues).toContain("local_or_workspace_package");
    expect(result.dependencies.map(dep => dep.package)).toEqual(["lib"]);
  });

  it("bounds aggregate Cargo references instead of returning truncated parsed coverage", () => {
    const refs = JSON.stringify(Array.from({ length: 5001 }, () => "lib"));
    expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = ${refs}\n${cargoPackage("other")}dependencies = ${refs}\n${cargoPackage()}`, "inventory_entry_capacity");
  });

  it("source-qualified references disambiguate retained rows, not their registry authenticity", () => {
    const content = `version = 4\n${cargoPackage("owner")}dependencies = ["lib 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)"]\n${cargoPackage()}${cargoPackage("lib", "1.2.3", "registry+https://other.invalid/index")}`;
    const result = parseFile("Cargo.lock", content);
    expect(result.files[0]!.issues).toEqual(["unverified_cargo_registry_source"]);
    expect(result.dependencies).toHaveLength(2);
  });

  it("does not satisfy a missing Cargo reference from a separate lockfile", () => {
    const input = snapshot({ "Cargo.lock": `version = 4\n${cargoPackage("owner")}dependencies = ["lib"]\n`, "nested/Cargo.lock": `version = 4\n${cargoPackage()}` });
    const before = structuredClone(input);
    const result = parseLockfileInventory(input);
    expect(result.files.find(row => row.path === "Cargo.lock")!.issues).toContain("missing_cargo_dependency_entry");
    expect(result.files.find(row => row.path === "nested/Cargo.lock")!.status).toBe("parsed");
    expect(result.dependencies).toHaveLength(2);
    expect(input).toEqual(before);
    expect(parseLockfileInventory(input)).toEqual(result);
  });

  it.each(["lib 1.2.3+different", "lib 1.2.3"])("does not collapse build identity for absent reference %s", reference => {
    expectAttention("Cargo.lock", `version = 4\n${cargoPackage("owner")}dependencies = [${JSON.stringify(reference)}]\n${cargoPackage("lib", "1.2.3+one")}`, "missing_cargo_dependency_entry");
  });

  it.each(['source = 42', 'source = ""', 'source = "registry+bad source"'])("holds malformed Cargo source shape %s", source => {
    const content = cargoPackage().replace('source = "registry+https://github.com/rust-lang/crates.io-index"', source);
    expectAttention("Cargo.lock", `version = 4\n${content}`, "invalid_cargo_source");
  });

  it("holds oversized reference text without truncation or a missing-entry claim", () => {
    const content = `version = 4\n${cargoPackage()}dependencies = [${JSON.stringify("a".repeat(1537))}]\n`;
    const result = expectAttention("Cargo.lock", content, "unsupported_cargo_dependency_reference");
    expect(result.files[0]!.issues).not.toContain("missing_cargo_dependency_entry");
  });

  it("does not accept duplicate TOML keys", () => {
    expectAttention("Cargo.lock", `version = 4\nversion = 4\n${cargoPackage()}`, "malformed_lockfile");
  });
});
