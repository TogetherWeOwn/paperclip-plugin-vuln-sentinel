import { isScalar, parseDocument, visit } from "yaml";
import { discoveryCoverage, validateRepositoryDiscovery, type RepositoryDiscovery } from "./github-discovery.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { parseLockfileInventory, type InventoryDependency } from "./inventory.js";
import { npmDeclarationRange, observeNpmManifest, type NpmManifestObservation } from "./npm-manifest.js";
import type { OsvDependency } from "./osv.js";
import { object, SourceAttention } from "./source-http.js";

export const PNPM_IMPORTER_CONTEXT_VERSION = "1.0.0";
const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const NAME = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/u;
type Section = typeof SECTIONS[number];

export interface PnpmImporterContextObservation {
  version: typeof PNPM_IMPORTER_CONTEXT_VERSION;
  status: "attention";
  source: {
    repo: string; sourceSha: string; treeSha: string; discoverySha256: string;
    artifactDigest: string; inventorySha256: string;
    lockfilePath: string; lockfileBlobSha: string; lockfileSha256: string; importer: string;
  };
  manifest: NpmManifestObservation;
  declarations: Array<{
    section: Section; package: string; manifestSpecifier: string | null; lockfileSpecifier: string | null;
    resolvedReference: string | null;
    comparison: "same_specifier" | "different_specifier" | "manifest_only" | "lockfile_only";
    manifestCandidateRangeMatch: NpmManifestObservation["declarations"][number]["candidateRangeMatch"];
    lockfileCandidateRangeMatch: NpmManifestObservation["declarations"][number]["candidateRangeMatch"];
  }>;
  // Same-name inventory observations only; resolved references are not authenticated owner edges.
  inventoryCandidates: Array<Pick<InventoryDependency, "ecosystem" | "package" | "version" | "locations">>;
  scope: "unknown";
  direct: null;
  compatibleFixVerified: false;
  attention: string[];
  toolVersions: Record<string, string>;
  observationSha256: string;
}

/** Exact importer-key/path observations, not workspace membership or installed dependency resolution. */
export function observePnpmImporterContext(
  discovery: RepositoryDiscovery, snapshot: RepositoryLockfiles, lockfilePath: string, importer: string,
  manifestContent: string, candidate?: OsvDependency,
): PnpmImporterContextObservation {
  if (typeof importer !== "string" || !importer.length || importer.length > 1024
    || /[\\\u0000-\u001f\u007f]/u.test(importer)
    || (importer !== "." && importer.split("/").some(part => !part || part === "." || part === ".."))) {
    throw new SourceAttention("invalid_pnpm_importer_path");
  }
  const tree = validateRepositoryDiscovery(discovery);
  if (tree.repo !== snapshot.repo || tree.sourceSha !== snapshot.sourceSha || tree.defaultBranch !== snapshot.defaultBranch) {
    throw new SourceAttention("pnpm_importer_source_mismatch");
  }
  const inventory = parseLockfileInventory(snapshot);
  const entries = new Map(tree.entries.map(entry => [entry.path, entry]));
  for (const file of snapshot.files) {
    const entry = entries.get(file.path);
    if (!entry || entry.type !== "blob" || !["100644", "100755"].includes(entry.mode)
      || entry.sha !== file.blobSha || (entry.size !== null && entry.size !== Buffer.byteLength(file.content))) {
      throw new SourceAttention("pnpm_importer_discovered_lockfile_mismatch");
    }
  }
  const file = snapshot.files.find(row => row.path === lockfilePath);
  const fileInventory = inventory.files.find(row => row.path === lockfilePath);
  if (!file || fileInventory?.format !== "pnpm") throw new SourceAttention("unsupported_pnpm_importer_lockfile");
  const directory = lockfilePath.slice(0, lockfilePath.lastIndexOf("/") + 1);
  const manifest = observeNpmManifest(tree, `${directory}${importer === "." ? "" : `${importer}/`}package.json`, manifestContent, candidate);
  let root: Record<string, unknown>;
  try {
    const document = parseDocument(file.content, { schema: "core", uniqueKeys: true, customTags: [], strict: true });
    if (document.errors.length || document.warnings.length) throw new SourceAttention("invalid_pnpm_importer_yaml");
    visit(document, { Pair: (_key, pair) => {
      if (isScalar(pair.key) && pair.key.value === "<<") throw new SourceAttention("unsupported_yaml_merge");
    } });
    root = object(document.toJS({ maxAliasCount: 0 }), "invalid_pnpm_importer_lockfile");
  } catch (error) {
    if (error instanceof SourceAttention) throw error;
    throw new SourceAttention("invalid_pnpm_importer_yaml");
  }
  if (root.lockfileVersion !== "9.0" && root.lockfileVersion !== 9) throw new SourceAttention("unsupported_pnpm_importer_lockfile_version");
  const importers = object(root.importers, "missing_pnpm_importers");
  if (!Object.hasOwn(importers, importer)) throw new SourceAttention("missing_pnpm_importer");
  const owner = object(importers[importer], "invalid_pnpm_importer");
  const locked: Array<{ section: Section; package: string; specifier: string; reference: string }> = [];
  for (const section of SECTIONS) {
    // Peer constraints live in the manifest; do not guess a missing importer peer section from snapshots.
    if (!Object.hasOwn(owner, section)) continue;
    if (section === "peerDependencies") throw new SourceAttention("unsupported_pnpm_importer_peer_section");
    const rows = Object.entries(object(owner[section], "invalid_pnpm_dependency_map"));
    if (rows.length + locked.length > 10_000) throw new SourceAttention("pnpm_importer_declaration_capacity");
    for (const [pkg, value] of rows) {
      const declaration = object(value, "invalid_pnpm_importer_dependency");
      if (pkg.length > 214 || !NAME.test(pkg) || typeof declaration.specifier !== "string" || declaration.specifier.length > 256
        || /[\u0000-\u001f\u007f]/u.test(declaration.specifier)) throw new SourceAttention("invalid_pnpm_specifier");
      if (typeof declaration.version !== "string" || declaration.version.length > 1024
        || /[\u0000-\u001f\u007f]/u.test(declaration.version)) throw new SourceAttention("invalid_pnpm_reference");
      locked.push({ section, package: pkg, specifier: declaration.specifier, reference: declaration.version });
    }
  }
  const attention = new Set([
    ...manifest.attention, "pnpm_importer_path_not_workspace_proof", "pnpm_importer_declaration_equality_not_owner_proof",
    "pnpm_name_candidates_not_dependency_edges", "pnpm_resolved_references_not_evaluated",
    "pnpm_transitive_and_workspace_constraints_not_verified", "pnpm_importer_context_not_current_source_selection",
    "pnpm_lockfile_metadata_not_evaluated",
  ]);
  for (const row of inventory.files) for (const issue of row.issues) attention.add(`inventory:${row.path}:${issue}`);
  const coverage = discoveryCoverage(tree);
  if ([...coverage.supportedLockfiles, ...coverage.unsupportedLockfiles].some(path => path !== lockfilePath
    && path.slice(0, path.lastIndexOf("/") + 1) === directory)) attention.add("multiple_colocated_lockfiles_not_selected");
  const declarations: PnpmImporterContextObservation["declarations"] = [];
  for (const section of SECTIONS) {
    const declared = new Map(manifest.declarations.filter(row => row.section === section).map(row => [row.package, row]));
    const reported = new Map(locked.filter(row => row.section === section).map(row => [row.package, row]));
    for (const pkg of [...new Set([...declared.keys(), ...reported.keys()])].sort()) {
      const declaration = declared.get(pkg);
      const report = reported.get(pkg);
      const manifestSpecifier = declaration?.specifier ?? null;
      const lockfileSpecifier = report?.specifier ?? null;
      const range = lockfileSpecifier === null ? null : npmDeclarationRange(lockfileSpecifier,
        manifest.candidate?.package === pkg ? manifest.candidate.version : undefined);
      if (range?.specifierKind === "unsupported") attention.add("unsupported_pnpm_importer_specifier");
      declarations.push({ section, package: pkg, manifestSpecifier, lockfileSpecifier, resolvedReference: report?.reference ?? null,
        comparison: manifestSpecifier === null ? "lockfile_only" : lockfileSpecifier === null ? "manifest_only"
          : manifestSpecifier === lockfileSpecifier ? "same_specifier" : "different_specifier",
        manifestCandidateRangeMatch: declaration?.candidateRangeMatch ?? null,
        lockfileCandidateRangeMatch: range?.candidateRangeMatch ?? null });
    }
  }
  if (declarations.length > 10_000) throw new SourceAttention("pnpm_importer_declaration_capacity");
  if (!declarations.length) attention.add("empty_importer_declarations_not_absence");
  if (declarations.some(row => row.comparison !== "same_specifier")) attention.add("pnpm_importer_declarations_disagree");
  if (declarations.some(row => row.manifestCandidateRangeMatch === "does_not_match" || row.lockfileCandidateRangeMatch === "does_not_match")) {
    attention.add("pnpm_importer_candidate_declaration_mismatch");
  }
  if (manifest.candidate && !locked.some(row => row.package === manifest.candidate!.package)) attention.add("candidate_not_declared_in_pnpm_importer");
  const names = new Set(declarations.map(row => row.package));
  const inventoryCandidates = inventory.dependencies.filter(dep => dep.ecosystem === "npm" && names.has(dep.package))
    .map(dep => ({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version,
      locations: dep.locations.filter(row => row.path === lockfilePath).map(row => ({ ...row })) })).filter(dep => dep.locations.length);
  const candidateNames = new Set(inventoryCandidates.map(row => row.package));
  for (const pkg of names) if (!candidateNames.has(pkg)) attention.add("declared_name_without_inventory_candidate");
  const result: Omit<PnpmImporterContextObservation, "observationSha256"> = {
    version: PNPM_IMPORTER_CONTEXT_VERSION, status: "attention",
    source: { repo: tree.repo, sourceSha: tree.sourceSha, treeSha: tree.treeSha, discoverySha256: tree.sha256,
      artifactDigest: inventory.artifactDigest, inventorySha256: inventory.inventorySha256,
      lockfilePath, lockfileBlobSha: file.blobSha, lockfileSha256: file.sha256, importer },
    manifest, declarations, inventoryCandidates, scope: "unknown", direct: null, compatibleFixVerified: false,
    attention: [...attention].sort(), toolVersions: { ...inventory.toolVersions, ...manifest.toolVersions,
      "vuln-sentinel-pnpm-importer-context": PNPM_IMPORTER_CONTEXT_VERSION },
  };
  const encoded = canonicalJson(["pnpm-importer-context-observation-v1", result]);
  if (Buffer.byteLength(encoded) > 1024 * 1024) throw new SourceAttention("pnpm_importer_observation_capacity");
  return { ...result, observationSha256: sha256(encoded) };
}
