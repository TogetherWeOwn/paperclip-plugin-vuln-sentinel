import { createHash } from "node:crypto";
import { Range, satisfies, valid } from "semver";
import { parse as parseToml } from "smol-toml";
import { validateRepositoryDiscovery, type RepositoryDiscovery } from "./github-discovery.js";
import { canonicalJson, sha256 } from "./identity.js";
import { object, SourceAttention } from "./source-http.js";

export const CARGO_MANIFEST_VERSION = "1.1.0";
const SECTIONS = ["dependencies", "dev-dependencies", "build-dependencies"] as const;
const SOURCE_FIELDS = ["path", "git", "registry", "registry-index", "branch", "tag", "rev"] as const;
const NAME = /^[A-Za-z0-9_-]{1,64}$/u;

// This is a declared table key, not an authenticated crates.io package identity.
export interface CargoManifestCandidate { declaredName: string; version: string }

export interface CargoManifestObservation {
  version: typeof CARGO_MANIFEST_VERSION;
  status: "attention";
  source: {
    repo: string; sourceSha: string; treeSha: string; discoverySha256: string;
    path: string; blobSha: string; sha256: string;
  };
  candidate: CargoManifestCandidate | null;
  declarations: Array<{
    owner: "package" | "workspace" | "target";
    target: string | null;
    section: typeof SECTIONS[number];
    declaredName: string;
    // A rename hint is not an authenticated registry identity or installed-owner edge.
    packageHint: string | null;
    versionRequirement: string | null;
    requirementKind: "stable_semver_subset" | "unsupported" | "not_reported";
    // Null is unqueried; unknown is not an exclusion or an inherited requirement.
    candidateRangeMatch: "matches" | "does_not_match" | "unknown" | null;
    workspaceInherited: boolean;
    sourceHints: Partial<Record<typeof SOURCE_FIELDS[number], string>>;
    unevaluatedFields: string[];
  }>;
  scope: "unknown";
  direct: null;
  compatibleFixVerified: false;
  attention: string[];
  toolVersions: Record<string, string>;
  observationSha256: string;
}

function text(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= limit && !/[\u0000-\u001f\u007f]/u.test(value);
}

function stable(value: unknown): value is string {
  return typeof value === "string" && value.length <= 256 && /^\d+\.\d+\.\d+$/u.test(value) && valid(value) === value;
}

/** Cargo bare triples mean caret, unlike npm exact triples. Commas are conjunctions, never alternatives. */
function requirementRange(requirement: string | null): Range | null {
  if (requirement === null) return null;
  const clauses = requirement.split(",");
  if (clauses.length > 8) return null;
  const translated: string[] = [];
  for (const clause of clauses) {
    const match = /^ *(<=|>=|<|>|=|\^|~)?(\d+\.\d+\.\d+) *$/u.exec(clause);
    if (!match || !stable(match[2])) return null;
    translated.push(`${match[1] ?? "^"}${match[2]}`);
  }
  try { return new Range(translated.join(" ")); } catch { return null; }
}

/** Exact-tree declaration/range observations only; no Cargo resolver, target evaluation or fix proof. */
export function observeCargoManifest(
  discovery: RepositoryDiscovery, path: string, content: string, candidate?: CargoManifestCandidate,
): CargoManifestObservation {
  const snapshot = validateRepositoryDiscovery(discovery);
  if (typeof path !== "string" || path.slice(path.lastIndexOf("/") + 1) !== "Cargo.toml") {
    throw new SourceAttention("unsupported_cargo_manifest_path");
  }
  const entry = snapshot.entries.find(row => row.path === path);
  if (!entry || entry.type !== "blob" || !["100644", "100755"].includes(entry.mode)) {
    throw new SourceAttention("cargo_manifest_not_in_discovery");
  }
  if (typeof content !== "string" || Buffer.byteLength(content) > 2 * 1024 * 1024) {
    throw new SourceAttention("cargo_manifest_content_capacity");
  }
  const bytes = Buffer.from(content);
  if (bytes.toString("utf8") !== content) throw new SourceAttention("invalid_cargo_manifest_utf8");
  const blobSha = createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
  if (blobSha !== entry.sha || (entry.size !== null && entry.size !== bytes.byteLength)) {
    throw new SourceAttention("cargo_manifest_discovered_blob_mismatch");
  }
  let root: Record<string, unknown>;
  try { root = object(parseToml(content), "invalid_cargo_manifest"); }
  catch { throw new SourceAttention("invalid_cargo_manifest_toml"); }
  if (candidate !== undefined && (!candidate || typeof candidate.declaredName !== "string"
    || !NAME.test(candidate.declaredName) || !stable(candidate.version))) {
    throw new SourceAttention("unsupported_cargo_manifest_candidate");
  }
  const attention = new Set([
    "manifest_lockfile_association_not_verified", "manifest_workspace_association_not_verified",
    "manifest_scope_not_applied", "manifest_range_not_compatible_fix", "release_availability_not_verified",
    "manifest_source_authenticity_and_freshness_not_verified", "cargo_requirements_not_fully_evaluated",
    "cargo_features_and_dependency_resolution_not_evaluated", "cargo_declared_names_not_registry_identity",
  ]);
  for (const field of ["workspace", "patch", "replace", "features", "profile", "cargo-features"]) {
    if (Object.hasOwn(root, field)) attention.add(`cargo_manifest_${field}_not_evaluated`);
  }
  const declarations: CargoManifestObservation["declarations"] = [];
  const read = (owner: CargoManifestObservation["declarations"][number]["owner"], target: string | null,
    section: typeof SECTIONS[number], value: unknown) => {
    const rows = Object.entries(object(value, "invalid_cargo_manifest_dependency_map"));
    if (rows.length + declarations.length > 10_000) throw new SourceAttention("cargo_manifest_declaration_capacity");
    for (const [declaredName, value] of rows.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
      if (!NAME.test(declaredName)) throw new SourceAttention("invalid_cargo_manifest_dependency_name");
      let versionRequirement: string | null = null;
      let packageHint: string | null = null;
      let workspaceInherited = false;
      const sourceHints: CargoManifestObservation["declarations"][number]["sourceHints"] = {};
      let unevaluatedFields: string[] = [];
      if (typeof value === "string") {
        if (!text(value, 256)) throw new SourceAttention("invalid_cargo_manifest_requirement");
        versionRequirement = value;
      } else {
        const row = object(value, "invalid_cargo_manifest_dependency");
        if (Object.hasOwn(row, "version")) {
          if (!text(row.version, 256)) throw new SourceAttention("invalid_cargo_manifest_requirement");
          versionRequirement = row.version;
        }
        if (Object.hasOwn(row, "package")) {
          if (typeof row.package !== "string" || !NAME.test(row.package)) throw new SourceAttention("invalid_cargo_manifest_package_hint");
          packageHint = row.package;
        }
        if (Object.hasOwn(row, "workspace")) {
          if (row.workspace !== true) throw new SourceAttention("unsupported_cargo_manifest_workspace_flag");
          workspaceInherited = true;
          attention.add("cargo_workspace_inheritance_not_resolved");
        }
        for (const field of SOURCE_FIELDS) if (Object.hasOwn(row, field)) {
          if (!text(row[field], 1024)) throw new SourceAttention("invalid_cargo_manifest_source_hint");
          sourceHints[field] = row[field];
        }
        if (Object.keys(sourceHints).length) attention.add("cargo_source_overrides_not_verified");
        unevaluatedFields = Object.keys(row).filter(field => field !== "version" && field !== "package"
          && field !== "workspace" && !SOURCE_FIELDS.some(source => source === field)).sort();
        if (unevaluatedFields.length) attention.add("cargo_dependency_fields_not_evaluated");
        if (!versionRequirement && !workspaceInherited && !Object.keys(sourceHints).length) {
          attention.add("cargo_declaration_without_requirement_or_source");
        }
      }
      const range = requirementRange(versionRequirement);
      const requirementKind = versionRequirement === null ? "not_reported" : range ? "stable_semver_subset" : "unsupported";
      if (requirementKind === "unsupported") attention.add("unsupported_cargo_manifest_requirement");
      const candidateRangeMatch = candidate?.declaredName !== declaredName ? null : !range ? "unknown"
        : satisfies(candidate.version, range) ? "matches" : "does_not_match";
      declarations.push({ owner, target, section, declaredName, packageHint, versionRequirement,
        requirementKind, candidateRangeMatch, workspaceInherited, sourceHints, unevaluatedFields });
    }
  };
  const readSections = (owner: "package" | "target", target: string | null, row: Record<string, unknown>) => {
    for (const field of ["dev_dependencies", "build_dependencies"]) {
      if (Object.hasOwn(row, field)) attention.add("cargo_legacy_dependency_sections_not_evaluated");
    }
    for (const section of SECTIONS) if (Object.hasOwn(row, section)) read(owner, target, section, row[section]);
  };
  readSections("package", null, root);
  if (Object.hasOwn(root, "workspace")) {
    const workspace = object(root.workspace, "invalid_cargo_manifest_workspace");
    if (Object.hasOwn(workspace, "dependencies")) read("workspace", null, "dependencies", workspace.dependencies);
  }
  if (Object.hasOwn(root, "target")) {
    attention.add("cargo_target_selectors_not_evaluated");
    const targets = Object.entries(object(root.target, "invalid_cargo_manifest_targets"));
    if (targets.length > 10_000) throw new SourceAttention("cargo_manifest_target_capacity");
    for (const [target, value] of targets.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
      if (!text(target, 1024)) throw new SourceAttention("invalid_cargo_manifest_target");
      readSections("target", target, object(value, "invalid_cargo_manifest_target_owner"));
    }
  }
  if (!declarations.length) attention.add("empty_cargo_declarations_not_absence");
  if (candidate && !declarations.some(row => row.declaredName === candidate.declaredName)) {
    attention.add("candidate_not_declared_in_cargo_manifest");
  }
  const result: Omit<CargoManifestObservation, "observationSha256"> = {
    version: CARGO_MANIFEST_VERSION, status: "attention",
    source: { repo: snapshot.repo, sourceSha: snapshot.sourceSha, treeSha: snapshot.treeSha,
      discoverySha256: snapshot.sha256, path, blobSha, sha256: sha256(content) },
    candidate: candidate ? { declaredName: candidate.declaredName, version: candidate.version } : null,
    declarations, scope: "unknown", direct: null, compatibleFixVerified: false, attention: [...attention].sort(),
    toolVersions: { "vuln-sentinel-cargo-manifest": CARGO_MANIFEST_VERSION, "smol-toml": "1.9.1", semver: "7.7.4" },
  };
  const encoded = canonicalJson(["cargo-manifest-observation-v1", result]);
  if (Buffer.byteLength(encoded) > 1024 * 1024) throw new SourceAttention("cargo_manifest_observation_capacity");
  return { ...result, observationSha256: sha256(encoded) };
}
