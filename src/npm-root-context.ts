import { parseDocument } from "yaml";
import { discoveryCoverage, validateRepositoryDiscovery, type RepositoryDiscovery } from "./github-discovery.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { parseLockfileInventory, type InventoryDependency } from "./inventory.js";
import { npmDeclarationRange, observeNpmManifest, type NpmManifestObservation } from "./npm-manifest.js";
import type { OsvDependency } from "./osv.js";
import { object, SourceAttention } from "./source-http.js";

export const NPM_ROOT_CONTEXT_VERSION = "1.1.0";
const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const NAME = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/u;

type Section = typeof SECTIONS[number];

export interface NpmRootContextObservation {
  version: typeof NPM_ROOT_CONTEXT_VERSION;
  status: "attention";
  source: {
    repo: string; sourceSha: string; treeSha: string; discoverySha256: string;
    artifactDigest: string; inventorySha256: string;
    lockfilePath: string; lockfileBlobSha: string; lockfileSha256: string;
  };
  manifest: NpmManifestObservation;
  declarations: Array<{
    section: Section; package: string; manifestSpecifier: string | null; lockfileSpecifier: string | null;
    comparison: "same_specifier" | "different_specifier" | "manifest_only" | "lockfile_only";
    // Null means missing side, no candidate, or another package; unknown means unsupported syntax.
    manifestCandidateRangeMatch: NpmManifestObservation["declarations"][number]["candidateRangeMatch"];
    lockfileCandidateRangeMatch: NpmManifestObservation["declarations"][number]["candidateRangeMatch"];
  }>;
  // Same-name candidates only. Neither a locator nor a declaration comparison proves an owner edge.
  inventoryCandidates: Array<Pick<InventoryDependency, "ecosystem" | "package" | "version" | "locations"> & {
    rootLocatorReported: boolean;
  }>;
  scope: "unknown";
  direct: null;
  compatibleFixVerified: false;
  attention: string[];
  toolVersions: Record<string, string>;
  observationSha256: string;
}

function rootDeclarations(root: Record<string, unknown>): Array<{ section: Section; package: string; specifier: string }> {
  const result: Array<{ section: Section; package: string; specifier: string }> = [];
  for (const section of SECTIONS) {
    if (!Object.hasOwn(root, section)) continue;
    const rows = Object.entries(object(root[section], "invalid_npm_root_dependency_map"));
    if (rows.length + result.length > 10_000) throw new SourceAttention("npm_root_declaration_capacity");
    for (const [pkg, specifier] of rows) {
      if (pkg.length > 214 || !NAME.test(pkg) || typeof specifier !== "string" || specifier.length > 256
        || /[\u0000-\u001f\u007f]/u.test(specifier)) throw new SourceAttention("invalid_npm_root_declaration");
      result.push({ section, package: pkg, specifier });
    }
  }
  return result;
}

/** Exact retained bytes, root declaration comparisons and name-only candidates; not package resolution. */
export function observeNpmRootContext(
  discovery: RepositoryDiscovery, snapshot: RepositoryLockfiles, lockfilePath: string, manifestContent: string,
  candidate?: OsvDependency,
): NpmRootContextObservation {
  const tree = validateRepositoryDiscovery(discovery);
  if (tree.repo !== snapshot.repo || tree.sourceSha !== snapshot.sourceSha || tree.defaultBranch !== snapshot.defaultBranch) {
    throw new SourceAttention("npm_root_source_mismatch");
  }
  const inventory = parseLockfileInventory(snapshot);
  const entries = new Map(tree.entries.map(entry => [entry.path, entry]));
  for (const file of snapshot.files) {
    const entry = entries.get(file.path);
    if (Buffer.from(file.content).toString("utf8") !== file.content) throw new SourceAttention("invalid_npm_root_utf8");
    if (!entry || entry.type !== "blob" || !["100644", "100755"].includes(entry.mode)
      || entry.sha !== file.blobSha || (entry.size !== null && entry.size !== Buffer.byteLength(file.content))) {
      throw new SourceAttention("npm_root_discovered_lockfile_mismatch");
    }
  }
  const file = snapshot.files.find(row => row.path === lockfilePath);
  const fileInventory = inventory.files.find(row => row.path === lockfilePath);
  if (!file || fileInventory?.format !== "npm") throw new SourceAttention("unsupported_npm_root_lockfile");
  const directory = lockfilePath.slice(0, lockfilePath.lastIndexOf("/") + 1);
  const manifest = observeNpmManifest(tree, `${directory}package.json`, manifestContent, candidate);
  let root: Record<string, unknown>;
  try {
    root = object(JSON.parse(file.content), "invalid_npm_root_lockfile");
    const document = parseDocument(file.content, { schema: "json", uniqueKeys: true, strict: true });
    if (document.errors.length || document.warnings.length) throw new SourceAttention("ambiguous_npm_root_json");
  } catch (error) {
    if (error instanceof SourceAttention) throw error;
    throw new SourceAttention("invalid_npm_root_json");
  }
  if (root.lockfileVersion !== 2 && root.lockfileVersion !== 3) throw new SourceAttention("unsupported_npm_root_lockfile_version");
  const packages = object(root.packages, "missing_npm_root_packages");
  if (!Object.hasOwn(packages, "")) throw new SourceAttention("missing_npm_root_owner");
  const owner = object(packages[""], "invalid_npm_root_owner");
  const locked = rootDeclarations(owner);
  const attention = new Set([
    ...manifest.attention, "npm_root_declaration_equality_not_owner_proof", "npm_name_candidates_not_dependency_edges",
    "npm_transitive_and_workspace_constraints_not_verified", "npm_root_metadata_not_evaluated",
    "npm_root_context_not_current_source_selection",
  ]);
  for (const row of inventory.files) for (const issue of row.issues) attention.add(`inventory:${row.path}:${issue}`);
  const coverage = discoveryCoverage(tree);
  if ([...coverage.supportedLockfiles, ...coverage.unsupportedLockfiles].some(path => path !== lockfilePath
    && path.slice(0, path.lastIndexOf("/") + 1) === directory)) attention.add("multiple_colocated_lockfiles_not_selected");
  if (Object.hasOwn(owner, "workspaces")) attention.add("npm_root_workspaces_not_evaluated");
  if (manifest.candidate && !locked.some(row => row.package === manifest.candidate!.package)) {
    attention.add("candidate_not_declared_in_npm_root");
  }
  // Preserve each section independently; do not apply optional/peer/override precedence.
  const declarations: NpmRootContextObservation["declarations"] = [];
  for (const section of SECTIONS) {
    const declared = new Map(manifest.declarations.filter(row => row.section === section).map(row => [row.package, row]));
    const reported = new Map(locked.filter(row => row.section === section).map(row => [row.package, row.specifier]));
    for (const pkg of [...new Set([...declared.keys(), ...reported.keys()])].sort()) {
      const declaration = declared.get(pkg);
      const manifestSpecifier = declaration?.specifier ?? null;
      const lockfileSpecifier = reported.get(pkg) ?? null;
      const lockedRange = lockfileSpecifier === null ? null : npmDeclarationRange(lockfileSpecifier,
        manifest.candidate?.package === pkg ? manifest.candidate.version : undefined);
      if (lockedRange?.specifierKind === "unsupported") attention.add("unsupported_npm_root_specifier");
      declarations.push({ section, package: pkg, manifestSpecifier, lockfileSpecifier,
        comparison: manifestSpecifier === null ? "lockfile_only" : lockfileSpecifier === null ? "manifest_only"
          : manifestSpecifier === lockfileSpecifier ? "same_specifier" : "different_specifier",
        manifestCandidateRangeMatch: declaration?.candidateRangeMatch ?? null,
        lockfileCandidateRangeMatch: lockedRange?.candidateRangeMatch ?? null });
    }
  }
  if (declarations.length > 10_000) throw new SourceAttention("npm_root_declaration_capacity");
  if (declarations.some(row => row.manifestCandidateRangeMatch === "does_not_match" || row.lockfileCandidateRangeMatch === "does_not_match")) {
    attention.add("npm_root_candidate_declaration_mismatch");
  }
  if (!declarations.length) attention.add("empty_root_declarations_not_absence");
  if (declarations.some(row => row.comparison !== "same_specifier")) attention.add("npm_root_declarations_disagree");
  const names = new Set(declarations.map(row => row.package));
  const inventoryCandidates: NpmRootContextObservation["inventoryCandidates"] = [];
  let locations = 0;
  for (const dep of inventory.dependencies) {
    if (dep.ecosystem !== "npm" || !names.has(dep.package)) continue;
    const selected = dep.locations.filter(row => row.path === lockfilePath);
    if (!selected.length) continue;
    locations += selected.length;
    if (locations > 10_000) throw new SourceAttention("npm_root_location_capacity");
    inventoryCandidates.push({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version,
      locations: structuredClone(selected), rootLocatorReported: selected.some(row => row.locator === `node_modules/${dep.package}`) });
  }
  for (const pkg of names) if (!inventoryCandidates.some(row => row.package === pkg)) attention.add("declared_name_without_inventory_candidate");
  const result: Omit<NpmRootContextObservation, "observationSha256"> = {
    version: NPM_ROOT_CONTEXT_VERSION, status: "attention",
    source: { repo: tree.repo, sourceSha: tree.sourceSha, treeSha: tree.treeSha, discoverySha256: tree.sha256,
      artifactDigest: inventory.artifactDigest, inventorySha256: inventory.inventorySha256,
      lockfilePath, lockfileBlobSha: file.blobSha, lockfileSha256: file.sha256 },
    manifest, declarations, inventoryCandidates, scope: "unknown", direct: null, compatibleFixVerified: false,
    attention: [...attention].sort(), toolVersions: { ...inventory.toolVersions, ...manifest.toolVersions,
      "vuln-sentinel-npm-root-context": NPM_ROOT_CONTEXT_VERSION },
  };
  const encoded = canonicalJson(["npm-root-context-observation-v1", result]);
  if (Buffer.byteLength(encoded) > 1024 * 1024) throw new SourceAttention("npm_root_observation_capacity");
  return { ...result, observationSha256: sha256(encoded) };
}
