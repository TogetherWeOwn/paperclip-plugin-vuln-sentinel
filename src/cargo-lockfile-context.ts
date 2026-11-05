import { cargoDeclarationRange, observeCargoManifest, type CargoManifestCandidate, type CargoManifestObservation } from "./cargo-manifest.js";
import { discoveryCoverage, validateRepositoryDiscovery, type RepositoryDiscovery } from "./github-discovery.js";
import type { RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { parseLockfileInventory, type InventoryDependency } from "./inventory.js";
import { SourceAttention } from "./source-http.js";

export const CARGO_LOCKFILE_CONTEXT_VERSION = "1.0.0";

type NameBasis = "declared_name" | "package_hint";

export interface CargoLockfileContextObservation {
  version: typeof CARGO_LOCKFILE_CONTEXT_VERSION;
  status: "attention";
  source: {
    repo: string; sourceSha: string; treeSha: string; discoverySha256: string;
    artifactDigest: string; inventorySha256: string;
    lockfilePath: string; lockfileBlobSha: string; lockfileSha256: string;
  };
  manifest: CargoManifestObservation;
  // Indexes refer only to rows in this observation, never Cargo resolver/owner edges.
  declarations: Array<{
    manifestDeclarationIndex: number;
    inventoryComparisons: Array<{
      inventoryCandidateIndex: number;
      nameBasis: NameBasis[];
      declaredRequirementMatch: "matches" | "does_not_match" | "unknown";
    }>;
  }>;
  inventoryCandidates: Array<Pick<InventoryDependency, "ecosystem" | "package" | "version" | "locations">>;
  scope: "unknown";
  direct: null;
  compatibleFixVerified: false;
  attention: string[];
  toolVersions: Record<string, string>;
  observationSha256: string;
}

/** Explicit same-tree inputs and spelling/range comparisons only, not workspace or installed-owner association. */
export function observeCargoLockfileContext(
  discovery: RepositoryDiscovery, snapshot: RepositoryLockfiles, lockfilePath: string,
  manifestPath: string, manifestContent: string, candidate?: CargoManifestCandidate,
): CargoLockfileContextObservation {
  const tree = validateRepositoryDiscovery(discovery);
  if (tree.repo !== snapshot.repo || tree.sourceSha !== snapshot.sourceSha || tree.defaultBranch !== snapshot.defaultBranch) {
    throw new SourceAttention("cargo_context_source_mismatch");
  }
  const inventory = parseLockfileInventory(snapshot);
  const entries = new Map(tree.entries.map(entry => [entry.path, entry]));
  for (const file of snapshot.files) {
    const entry = entries.get(file.path);
    if (!entry || entry.type !== "blob" || !["100644", "100755"].includes(entry.mode)
      || entry.sha !== file.blobSha || (entry.size !== null && entry.size !== Buffer.byteLength(file.content))) {
      throw new SourceAttention("cargo_context_discovered_lockfile_mismatch");
    }
  }
  const file = snapshot.files.find(row => row.path === lockfilePath);
  const fileInventory = inventory.files.find(row => row.path === lockfilePath);
  if (!file || fileInventory?.format !== "cargo") throw new SourceAttention("unsupported_cargo_context_lockfile");
  const manifest = observeCargoManifest(tree, manifestPath, manifestContent, candidate);
  const attention = new Set([
    ...manifest.attention, "cargo_context_explicit_paths_not_workspace_proof", "cargo_name_comparisons_not_dependency_edges",
    "cargo_declared_requirement_matches_not_resolution", "cargo_context_not_current_source_selection",
  ]);
  for (const row of inventory.files) for (const issue of row.issues) attention.add(`inventory:${row.path}:${issue}`);
  const directory = lockfilePath.slice(0, lockfilePath.lastIndexOf("/") + 1);
  const coverage = discoveryCoverage(tree);
  if ([...coverage.supportedLockfiles, ...coverage.unsupportedLockfiles].some(path => path !== lockfilePath
    && path.slice(0, path.lastIndexOf("/") + 1) === directory)) attention.add("multiple_colocated_lockfiles_not_selected");

  const names = new Set<string>();
  for (const declaration of manifest.declarations) {
    names.add(declaration.declaredName);
    if (declaration.packageHint !== null) names.add(declaration.packageHint);
  }
  const inventoryCandidates: CargoLockfileContextObservation["inventoryCandidates"] = [];
  const byName = new Map<string, number[]>();
  let locations = 0;
  for (const dep of inventory.dependencies) {
    if (dep.ecosystem !== "crates.io" || !names.has(dep.package)) continue;
    const selected = dep.locations.filter(row => row.path === lockfilePath);
    if (!selected.length) continue;
    locations += selected.length;
    if (locations > 10_000) throw new SourceAttention("cargo_context_location_capacity");
    const indexes = byName.get(dep.package) ?? [];
    indexes.push(inventoryCandidates.length);
    byName.set(dep.package, indexes);
    inventoryCandidates.push({ ecosystem: dep.ecosystem, package: dep.package, version: dep.version, locations: structuredClone(selected) });
  }
  let comparisons = 0;
  const declarations = manifest.declarations.map((declaration, manifestDeclarationIndex) => {
    const indexes = [...new Set([...(byName.get(declaration.declaredName) ?? []),
      ...(declaration.packageHint === null ? [] : byName.get(declaration.packageHint) ?? [])])].sort((a, b) => a - b);
    comparisons += indexes.length;
    if (comparisons > 10_000) throw new SourceAttention("cargo_context_comparison_capacity");
    if (!indexes.length) attention.add("cargo_declaration_without_inventory_name_comparison");
    if (indexes.length > 1) attention.add("cargo_multiple_inventory_name_comparisons_not_selected");
    if (declaration.packageHint !== null) attention.add("cargo_package_hint_not_registry_identity");
    return { manifestDeclarationIndex, inventoryComparisons: indexes.map(inventoryCandidateIndex => {
      const dep = inventoryCandidates[inventoryCandidateIndex]!;
      const nameBasis: NameBasis[] = [];
      if (dep.package === declaration.declaredName) nameBasis.push("declared_name");
      if (dep.package === declaration.packageHint) nameBasis.push("package_hint");
      const declaredRequirementMatch = cargoDeclarationRange(declaration.versionRequirement, dep.version).candidateRangeMatch!;
      if (declaredRequirementMatch === "does_not_match") attention.add("cargo_inventory_declared_requirement_mismatch");
      if (declaredRequirementMatch === "unknown") attention.add("cargo_inventory_declared_requirement_unknown");
      return { inventoryCandidateIndex, nameBasis, declaredRequirementMatch };
    }) };
  });
  const result: Omit<CargoLockfileContextObservation, "observationSha256"> = {
    version: CARGO_LOCKFILE_CONTEXT_VERSION, status: "attention",
    source: { repo: tree.repo, sourceSha: tree.sourceSha, treeSha: tree.treeSha, discoverySha256: tree.sha256,
      artifactDigest: inventory.artifactDigest, inventorySha256: inventory.inventorySha256,
      lockfilePath, lockfileBlobSha: file.blobSha, lockfileSha256: file.sha256 },
    manifest, declarations, inventoryCandidates, scope: "unknown", direct: null, compatibleFixVerified: false,
    attention: [...attention].sort(), toolVersions: { ...inventory.toolVersions, ...manifest.toolVersions,
      "vuln-sentinel-cargo-lockfile-context": CARGO_LOCKFILE_CONTEXT_VERSION },
  };
  const encoded = canonicalJson(["cargo-lockfile-context-observation-v1", result]);
  if (Buffer.byteLength(encoded) > 1024 * 1024) throw new SourceAttention("cargo_context_observation_capacity");
  return { ...result, observationSha256: sha256(encoded) };
}
