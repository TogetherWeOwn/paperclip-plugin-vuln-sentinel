import { createHash } from "node:crypto";
import { Range, satisfies, valid } from "semver";
import { parseDocument } from "yaml";
import { validateRepositoryDiscovery, type RepositoryDiscovery } from "./github-discovery.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { OsvDependency } from "./osv.js";
import { object, SourceAttention } from "./source-http.js";

export const NPM_MANIFEST_VERSION = "1.0.0";
const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const NAME = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/u;

type RangeMatch = "matches" | "does_not_match" | "unknown";

export interface NpmManifestObservation {
  version: typeof NPM_MANIFEST_VERSION;
  status: "attention";
  source: {
    repo: string; sourceSha: string; treeSha: string; discoverySha256: string;
    path: string; blobSha: string; sha256: string;
  };
  candidate: OsvDependency | null;
  declarations: Array<{
    section: typeof SECTIONS[number]; package: string; specifier: string;
    specifierKind: "stable_semver_subset" | "unsupported";
    // Null means this row was not queried. Unknown is not a range exclusion.
    candidateRangeMatch: RangeMatch | null;
  }>;
  scope: "unknown";
  direct: null;
  compatibleFixVerified: false;
  attention: string[];
  toolVersions: Record<string, string>;
  observationSha256: string;
}

function name(value: string): boolean {
  return value.length <= 214 && NAME.test(value);
}

function stable(value: string): boolean {
  return value.length <= 256 && /^\d+\.\d+\.\d+$/u.test(value) && valid(value) === value;
}

/** Full stable-version exact/caret/tilde/comparator sets only, not npm spec resolution. */
function supportedRange(specifier: string): boolean {
  const sets = specifier.split("||");
  if (sets.length > 8) return false;
  for (const set of sets) {
    const tokens = set.trim().split(/\s+/u);
    if (tokens.length > 8) return false;
    for (const token of tokens) {
      const match = /^(?:<=|>=|<|>|=|\^|~)?(\d+\.\d+\.\d+)$/u.exec(token);
      if (!match || !stable(match[1]!)) return false;
    }
  }
  try { new Range(specifier); return true; } catch { return false; }
}

/** Offline declaration/range observations. Never binds installed tuples, scope or a rule-6 fix. */
export function observeNpmManifest(
  discovery: RepositoryDiscovery, path: string, content: string, candidate?: OsvDependency,
): NpmManifestObservation {
  const snapshot = validateRepositoryDiscovery(discovery);
  if (typeof path !== "string" || path.slice(path.lastIndexOf("/") + 1) !== "package.json") {
    throw new SourceAttention("unsupported_npm_manifest_path");
  }
  const entry = snapshot.entries.find(row => row.path === path);
  if (!entry || entry.type !== "blob" || !["100644", "100755"].includes(entry.mode)) {
    throw new SourceAttention("npm_manifest_not_in_discovery");
  }
  if (typeof content !== "string" || Buffer.byteLength(content) > 2 * 1024 * 1024) {
    throw new SourceAttention("npm_manifest_content_capacity");
  }
  const bytes = Buffer.from(content);
  // Reject lossy surrogate encoding; content identity must describe exact UTF-8 bytes.
  if (bytes.toString("utf8") !== content) throw new SourceAttention("invalid_npm_manifest_utf8");
  const blobSha = createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
  if (blobSha !== entry.sha || (entry.size !== null && entry.size !== bytes.byteLength)) {
    throw new SourceAttention("npm_manifest_discovered_blob_mismatch");
  }
  let root: Record<string, unknown>;
  try {
    root = object(JSON.parse(content), "invalid_npm_manifest");
    const document = parseDocument(content, { schema: "json", uniqueKeys: true, strict: true });
    if (document.errors.length || document.warnings.length) throw new SourceAttention("ambiguous_npm_manifest_json");
  } catch (error) {
    if (error instanceof SourceAttention) throw error;
    throw new SourceAttention("invalid_npm_manifest_json");
  }
  if (candidate && (candidate.ecosystem !== "npm" || typeof candidate.package !== "string" || !name(candidate.package)
    || typeof candidate.version !== "string" || !stable(candidate.version))) {
    throw new SourceAttention("unsupported_npm_manifest_candidate");
  }
  const attention = new Set([
    "manifest_lockfile_association_not_verified", "manifest_workspace_association_not_verified",
    "manifest_scope_not_applied", "manifest_range_not_compatible_fix", "release_availability_not_verified",
    "manifest_source_authenticity_and_freshness_not_verified",
  ]);
  for (const field of ["workspaces", "overrides", "resolutions", "pnpm", "peerDependenciesMeta", "bundledDependencies", "bundleDependencies"]) {
    if (Object.hasOwn(root, field)) attention.add(`npm_manifest_${field}_not_evaluated`);
  }
  const declarations: NpmManifestObservation["declarations"] = [];
  for (const section of SECTIONS) {
    if (!Object.hasOwn(root, section)) continue;
    const rows = Object.entries(object(root[section], "invalid_npm_manifest_dependency_map"));
    if (rows.length + declarations.length > 10_000) throw new SourceAttention("npm_manifest_declaration_capacity");
    for (const [pkg, value] of rows.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
      if (!name(pkg) || typeof value !== "string" || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) {
        throw new SourceAttention("invalid_npm_manifest_declaration");
      }
      const supported = supportedRange(value);
      if (!supported) attention.add("unsupported_npm_manifest_specifier");
      declarations.push({ section, package: pkg, specifier: value,
        specifierKind: supported ? "stable_semver_subset" : "unsupported",
        candidateRangeMatch: !candidate || candidate.package !== pkg ? null : !supported ? "unknown"
          : satisfies(candidate.version, value) ? "matches" : "does_not_match",
      });
    }
  }
  if (candidate && !declarations.some(row => row.package === candidate.package)) attention.add("candidate_not_declared_in_manifest");
  const result: Omit<NpmManifestObservation, "observationSha256"> = {
    version: NPM_MANIFEST_VERSION, status: "attention" as const,
    source: { repo: snapshot.repo, sourceSha: snapshot.sourceSha, treeSha: snapshot.treeSha,
      discoverySha256: snapshot.sha256, path, blobSha, sha256: sha256(content) },
    candidate: candidate ? structuredClone(candidate) : null, declarations,
    scope: "unknown" as const, direct: null, compatibleFixVerified: false as const, attention: [...attention].sort(),
    toolVersions: { "vuln-sentinel-npm-manifest": NPM_MANIFEST_VERSION, semver: "7.7.4", yaml: "2.9.1" },
  };
  const encoded = canonicalJson(["npm-manifest-observation-v1", result]);
  if (Buffer.byteLength(encoded) > 1024 * 1024) throw new SourceAttention("npm_manifest_observation_capacity");
  return { ...result, observationSha256: sha256(encoded) };
}
