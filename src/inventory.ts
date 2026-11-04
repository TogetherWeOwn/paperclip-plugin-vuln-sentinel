import { createHash } from "node:crypto";
import { parse } from "semver";
import { parse as parseToml } from "smol-toml";
import { parseDocument } from "yaml";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { OsvDependency } from "./osv.js";
import { validatePnpmImporterPath, validatePnpmMappingKeys } from "./pnpm-yaml.js";
import { object, SourceAttention } from "./source-http.js";

const MAX_ENTRIES = 10_000;
const NPM_NAME = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/u;
const CRATE_NAME = /^[A-Za-z0-9_-]+$/u;
export const INVENTORY_TOOLS = { "vuln-sentinel-inventory": "0.1.11", semver: "7.7.4", yaml: "2.9.1", "smol-toml": "1.9.1" };

export interface InventoryDependency extends OsvDependency {
  locations: Array<{ path: string; locator: string }>;
  // Lockfile presence and native absence do not prove runtime/development scope.
  scope: "unknown";
  direct: null;
}

export interface InventoryFile {
  path: string;
  format: "npm" | "pnpm" | "cargo" | "unsupported";
  status: "parsed" | "attention";
  entries: number;
  issues: string[];
}

export interface LockfileInventory {
  repo: string;
  sourceSha: string;
  artifactDigest: string;
  inventorySha256: string;
  dependencies: InventoryDependency[];
  files: InventoryFile[];
  coverage: {
    configuredPathsParsed: boolean;
    repositoryDiscovery: "not_proven";
    fullDependencyClosure: "not_proven";
    runtimeCompleteness: "not_proven";
  };
  toolVersions: Record<string, string>;
}

type Add = (dep: OsvDependency, locator: string) => void;

function entries(value: unknown, code: string): Array<[string, unknown]> {
  const rows = Object.entries(object(value, code));
  if (rows.length > MAX_ENTRIES) throw new SourceAttention("inventory_entry_capacity");
  return rows;
}

function version(value: unknown): string {
  if (typeof value !== "string" || value.length > 256) throw new SourceAttention("unsupported_package_version");
  const parsed = parse(value);
  // semver.valid strips build metadata; query/tuple identity must preserve the complete locked version.
  if (!parsed || value !== parsed.version + (parsed.build.length ? `+${parsed.build.join(".")}` : "")) {
    throw new SourceAttention("unsupported_package_version");
  }
  return value;
}

function npmName(value: unknown): string {
  if (typeof value !== "string" || value.length > 214 || !NPM_NAME.test(value)) {
    throw new SourceAttention("invalid_npm_name");
  }
  return value;
}

function registryTarball(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "registry.npmjs.org"
      && !url.username && !url.password && !url.port && !url.search && !url.hash;
  } catch { return false; }
}

function readNpm(content: string, add: Add, issues: Set<string>): number {
  const root = object(JSON.parse(content), "invalid_npm_lockfile");
  const document = parseDocument(content, { schema: "json", uniqueKeys: true, strict: true });
  if (document.errors.length || document.warnings.length) throw new SourceAttention("ambiguous_npm_json");
  if (root.lockfileVersion !== 2 && root.lockfileVersion !== 3) throw new SourceAttention("unsupported_npm_lockfile_version");
  const rows = entries(root.packages, "missing_npm_packages");
  const packages = new Map(rows.map(([key, row]) => [key, object(row, "invalid_npm_package")]));
  if (!packages.has("")) throw new SourceAttention("missing_npm_root");
  for (const [locator, row] of packages) {
    if (!locator) continue;
    if (locator.length > 1024 || /[\\\u0000-\u001f\u007f]/u.test(locator)
      || locator.split("/").some(part => !part || part === "." || part === "..")) {
      throw new SourceAttention("invalid_npm_locator");
    }
    const path = `/${locator}`;
    const marker = path.lastIndexOf("/node_modules/");
    if (row.link === true || marker < 0) {
      issues.add("local_or_workspace_package");
      continue;
    }
    const derived = path.slice(marker + "/node_modules/".length);
    const installedName = npmName(derived);
    // Validate every installed package segment, not just the final nested name.
    const parts = locator.split("/");
    for (let index = parts.indexOf("node_modules"); index < parts.length;) {
      if (parts[index++] !== "node_modules") throw new SourceAttention("invalid_npm_locator");
      const end = index + (parts[index]?.startsWith("@") ? 2 : 1);
      const name = parts.slice(index, end).join("/");
      if (name.length > 214 || !NPM_NAME.test(name)) throw new SourceAttention("invalid_npm_locator");
      index = end;
    }
    // npm aliases record the real registry package name in the installed row.
    const name = row.name === undefined ? installedName : npmName(row.name);
    if (!registryTarball(row.resolved)) {
      issues.add("unverified_npm_registry_source");
      continue;
    }
    const tarball = new URL(row.resolved as string);
    if (!tarball.pathname.startsWith(`/${name}/-/`)
      && !tarball.pathname.startsWith(`/${name.replace("/", "%2f")}/-/`)) {
      issues.add("npm_tarball_identity_mismatch");
      continue;
    }
    add({ ecosystem: "npm", package: name, version: version(row.version) }, locator);
  }
  // Detect an explicitly referenced but missing installed entry, not just table syntax.
  let referenceCount = 0;
  for (const [locator, row] of packages) {
    for (const kind of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      if (row[kind] === undefined) continue;
      const refs = entries(row[kind], "invalid_npm_dependency_map");
      referenceCount += refs.length;
      if (referenceCount > MAX_ENTRIES) throw new SourceAttention("inventory_entry_capacity");
      for (const [name, reference] of refs) {
        npmName(name);
        if (typeof reference !== "string" || reference.length > 256 || /[\u0000-\u001f\u007f]/u.test(reference)) {
          throw new SourceAttention("invalid_npm_dependency_reference");
        }
        // Peer constraints are declarations, not guaranteed installed targets (including optional peers).
        if (kind === "peerDependencies") continue;
        let parent = locator;
        let found = false;
        for (;;) {
          if (packages.has(`${parent ? `${parent}/` : ""}node_modules/${name}`)) { found = true; break; }
          const index = parent.lastIndexOf("/node_modules/");
          if (!parent) break;
          parent = index < 0 ? "" : parent.slice(0, index);
        }
        if (!found) issues.add("missing_npm_dependency_entry");
      }
    }
  }
  return rows.length - 1;
}

function pnpmKey(key: string): OsvDependency {
  const match = /^((?:@[^/]+\/)?[^@/]+)@([^()]+)(?:\([^\r\n]*\))?$/u.exec(key);
  if (!match) throw new SourceAttention("unsupported_pnpm_package_key");
  return { ecosystem: "npm", package: npmName(match[1]), version: version(match[2]) };
}

function readPnpm(content: string, add: Add, issues: Set<string>): number {
  const document = parseDocument(content, { schema: "core", uniqueKeys: true, customTags: [], strict: true });
  if (document.errors.length || document.warnings.length) throw new SourceAttention("invalid_pnpm_yaml");
  // No key coercion, alias expansion, merge keys or executable/custom YAML tags.
  validatePnpmMappingKeys(document);
  const root = object(document.toJS({ maxAliasCount: 0 }), "invalid_pnpm_lockfile");
  if (root.lockfileVersion !== "9.0" && root.lockfileVersion !== 9) throw new SourceAttention("unsupported_pnpm_lockfile_version");
  const packages = entries(root.packages === undefined ? {} : root.packages, "invalid_pnpm_packages");
  const keys = new Set(packages.map(([key]) => key));
  const tuples = new Set<string>();
  for (const [locator, value] of packages) {
    const dep = pnpmKey(locator);
    tuples.add(`${dep.package}@${dep.version}`);
    const row = object(value, "invalid_pnpm_package");
    const resolution = object(row.resolution, "missing_pnpm_resolution");
    if (resolution.tarball !== undefined || resolution.type !== undefined) {
      // Explicit source overrides may be a fork with unrelated registry identity.
      issues.add("unverified_pnpm_registry_source");
      continue;
    }
    if (typeof resolution.integrity !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(resolution.integrity)) {
      issues.add("missing_pnpm_integrity");
      continue;
    }
    add(dep, locator);
  }
  const snapshots = entries(root.snapshots === undefined ? {} : root.snapshots, "invalid_pnpm_snapshots");
  const snapshotKeys = new Set(snapshots.map(([key]) => key));
  let referenceCount = 0;
  const references = (value: unknown, importer: boolean) => {
    const row = object(value, "invalid_pnpm_dependency_owner");
    for (const kind of ["dependencies", "devDependencies", "optionalDependencies"]) {
      if (row[kind] === undefined) continue;
      const refs = entries(row[kind], "invalid_pnpm_dependency_map");
      referenceCount += refs.length;
      if (referenceCount > MAX_ENTRIES) throw new SourceAttention("inventory_entry_capacity");
      for (const [name, value] of refs) {
        npmName(name);
        let ref = value;
        if (importer) {
          const declaration = object(value, "invalid_pnpm_importer_dependency");
          if (typeof declaration.specifier !== "string" || declaration.specifier.length > 256
            || /[\u0000-\u001f\u007f]/u.test(declaration.specifier)) throw new SourceAttention("invalid_pnpm_specifier");
          ref = declaration.version;
        }
        if (typeof ref !== "string" || ref.length > 1024 || /[\u0000-\u001f\u007f]/u.test(ref)) {
          throw new SourceAttention("invalid_pnpm_reference");
        }
        if (ref.startsWith("link:") || ref.startsWith("file:")) { issues.add("local_or_workspace_package"); continue; }
        const key = `${name}@${ref}`;
        // Alias references may carry the real package name in the resolved value.
        const target = snapshotKeys.has(key) ? key : ref;
        if (!snapshotKeys.has(target)) issues.add("missing_pnpm_snapshot_reference");
      }
    }
  };
  const seen = new Set<string>();
  for (const [key, value] of snapshots) {
    const dep = pnpmKey(key);
    const tuple = `${dep.package}@${dep.version}`;
    if (!keys.has(key) && !keys.has(tuple)) issues.add("missing_pnpm_package_entry");
    seen.add(tuple);
    references(value, false);
  }
  for (const tuple of tuples) if (!seen.has(tuple)) issues.add("missing_pnpm_snapshot_entry");
  const importers = entries(root.importers, "missing_pnpm_importers");
  if (!importers.length) throw new SourceAttention("missing_pnpm_importers");
  for (const [path, value] of importers) {
    validatePnpmImporterPath(path);
    references(value, true);
  }
  return packages.length;
}

function readCargo(content: string, add: Add, issues: Set<string>): number {
  const root = object(parseToml(content), "invalid_cargo_lockfile");
  if (root.version !== 3 && root.version !== 4) throw new SourceAttention("unsupported_cargo_lockfile_version");
  if (!Array.isArray(root.package) || root.package.length > MAX_ENTRIES) throw new SourceAttention("invalid_cargo_packages");
  const seen = new Set<string>();
  const targets = new Map<string, number>();
  const references: string[][] = [];
  let referenceCount = 0;
  for (const [index, value] of root.package.entries()) {
    const row = object(value, "invalid_cargo_package");
    if (typeof row.name !== "string" || row.name.length > 64 || !CRATE_NAME.test(row.name)) throw new SourceAttention("invalid_crate_name");
    const v = version(row.version);
    const key = canonicalJson([row.name, v, row.source ?? null]);
    if (seen.has(key)) throw new SourceAttention("duplicate_cargo_tuple");
    seen.add(key);
    if (row.source !== undefined && (typeof row.source !== "string" || !row.source.length || row.source.length > 1024
      || /[\u0000- \u007f()]/u.test(row.source))) throw new SourceAttention("invalid_cargo_source");
    for (const reference of [row.name, `${row.name} ${v}`, ...(row.source === undefined ? [] : [`${row.name} ${v} (${row.source})`])]) {
      targets.set(reference, (targets.get(reference) ?? 0) + 1);
    }
    if (row.dependencies !== undefined) {
      if (!Array.isArray(row.dependencies) || row.dependencies.some(ref => typeof ref !== "string")) {
        throw new SourceAttention("invalid_cargo_dependencies");
      }
      referenceCount += row.dependencies.length;
      if (referenceCount > MAX_ENTRIES) throw new SourceAttention("inventory_entry_capacity");
      references.push(row.dependencies as string[]);
    }
    if (row.source !== "registry+https://github.com/rust-lang/crates.io-index") {
      issues.add(row.source === undefined ? "local_or_workspace_package" : "unverified_cargo_registry_source");
      continue;
    }
    if (typeof row.checksum !== "string" || !/^[a-f0-9]{64}$/u.test(row.checksum)) {
      issues.add("missing_cargo_checksum");
      continue;
    }
    add({ ecosystem: "crates.io", package: row.name, version: v }, `package[${index}]`);
  }
  // References describe only retained lockfile accounting, not installed owner/scope or full closure.
  for (const refs of references) {
    const unique = new Set<string>();
    for (const ref of refs) {
      if (unique.has(ref)) issues.add("duplicate_cargo_dependency_reference");
      unique.add(ref);
      const match = ref.length <= 1536 ? /^([A-Za-z0-9_-]{1,64})(?: ([^\s()]+)(?: \(([^\u0000- \u007f()]+)\))?)?$/u.exec(ref) : null;
      try {
        if (!match) throw new SourceAttention("unsupported_cargo_dependency_reference");
        if (match[2] !== undefined) version(match[2]);
      } catch {
        issues.add("unsupported_cargo_dependency_reference");
        continue;
      }
      const count = targets.get(ref) ?? 0;
      if (!count) issues.add("missing_cargo_dependency_entry");
      else if (count > 1) issues.add("ambiguous_cargo_dependency_reference");
    }
  }
  return root.package.length;
}

/** Enumerates configured lockfile entries, never certifies repository/runtime absence. */
export function parseLockfileInventory(snapshot: RepositoryLockfiles): LockfileInventory {
  if (!/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9_.-]{1,100}$/u.test(snapshot.repo)
    || snapshot.repo.endsWith("/.") || snapshot.repo.endsWith("/..")
    || !/^[a-f0-9]{40}$/u.test(snapshot.sourceSha) || !Array.isArray(snapshot.files)
    || !snapshot.files.length || snapshot.files.length > 10) throw new SourceAttention("invalid_inventory_snapshot");
  const sorted = [...snapshot.files].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (new Set(sorted.map(file => file.path)).size !== sorted.length) throw new SourceAttention("duplicate_inventory_path");
  let bytes = 0;
  for (const file of sorted) {
    if (typeof file.content !== "string" || !/^[A-Za-z0-9_./-]+$/u.test(file.path)
      || file.path.split("/").some(part => !part || part === "." || part === "..")) throw new SourceAttention("invalid_inventory_file");
    const content = Buffer.from(file.content);
    // Hash equality cannot detect lone surrogates silently replaced during UTF-8 encoding.
    if (content.toString("utf8") !== file.content) throw new SourceAttention("invalid_inventory_utf8");
    bytes += content.byteLength;
    const blob = createHash("sha1").update(`blob ${content.byteLength}\0`).update(content).digest("hex");
    if (content.byteLength > 2 * 1024 * 1024 || bytes > 8 * 1024 * 1024
      || sha256(file.content) !== file.sha256 || blob !== file.blobSha) throw new SourceAttention("inventory_content_mismatch");
  }
  const digest = `sha256:${sha256(canonicalJson(sorted.map(file => [file.path, file.sha256])))}`;
  if (digest !== snapshot.artifactDigest) throw new SourceAttention("inventory_digest_mismatch");
  const dependencies = new Map<string, InventoryDependency>();
  const files: InventoryFile[] = [];
  let totalEntries = 0;
  for (const file of sorted) {
    const basename = file.path.split("/").at(-1);
    const format = basename === "package-lock.json" || basename === "npm-shrinkwrap.json" ? "npm"
      : basename === "pnpm-lock.yaml" ? "pnpm" : basename === "Cargo.lock" ? "cargo" : "unsupported";
    const issues = new Set<string>();
    const pending: Array<{ dep: OsvDependency; locator: string }> = [];
    const add: Add = (dep, locator) => { pending.push({ dep, locator }); };
    let count = 0;
    try {
      if (format === "unsupported") throw new SourceAttention("unsupported_lockfile_format");
      count = format === "npm" ? readNpm(file.content, add, issues)
        : format === "pnpm" ? readPnpm(file.content, add, issues) : readCargo(file.content, add, issues);
    } catch (error) {
      // Discard a malformed file's partial parse, while retaining other files' positives.
      pending.length = 0;
      issues.add(error instanceof SourceAttention ? error.code : "malformed_lockfile");
    }
    totalEntries += count;
    if (totalEntries > MAX_ENTRIES) throw new SourceAttention("inventory_entry_capacity");
    for (const { dep, locator } of pending) {
      const key = canonicalJson(dep);
      const current = dependencies.get(key) ?? { ...dep, scope: "unknown", direct: null, locations: [] };
      current.locations.push({ path: file.path, locator });
      dependencies.set(key, current);
    }
    if (dependencies.size > 2_000) throw new SourceAttention("inventory_query_capacity");
    files.push({ path: file.path, format, status: issues.size ? "attention" : "parsed", entries: count, issues: [...issues].sort() });
  }
  const result = {
    repo: snapshot.repo, sourceSha: snapshot.sourceSha, artifactDigest: digest,
    dependencies: [...dependencies.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, dep]) => dep), files,
    coverage: {
      configuredPathsParsed: files.every(file => file.status === "parsed"),
      repositoryDiscovery: "not_proven" as const, fullDependencyClosure: "not_proven" as const, runtimeCompleteness: "not_proven" as const,
    },
    toolVersions: { ...INVENTORY_TOOLS },
  };
  return { ...result, inventorySha256: sha256(canonicalJson(result)) };
}
