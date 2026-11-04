import { repository } from "./github-repository.js";
import { canonicalJson, sha256 } from "./identity.js";
import { object, SourceAttention, sourceBudget, text, type SourceFetch } from "./source-http.js";

const BASE = "https://api.github.com";
const SHA = /^[a-f0-9]{40}$/u;
const MANIFESTS = new Set(["package.json", "Cargo.toml", "go.mod", "pyproject.toml", "Pipfile", "requirements.txt"]);
const SUPPORTED = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "Cargo.lock"]);
const UNSUPPORTED = new Set([
  "yarn.lock", "bun.lock", "bun.lockb", "deno.lock", "go.sum", "uv.lock", "poetry.lock", "Pipfile.lock",
  "requirements.txt", "composer.lock", "Gemfile.lock", "packages.lock.json",
]);

export interface RepositoryTreeEntry {
  path: string;
  mode: string;
  type: "blob" | "tree" | "commit";
  sha: string;
  size: number | null;
}

export interface RepositoryDiscovery {
  version: 1;
  repo: string;
  sourceSha: string;
  treeSha: string;
  defaultBranch: string;
  entries: RepositoryTreeEntry[];
  sha256: string;
}

export interface DiscoveryCoverage {
  manifests: string[];
  supportedLockfiles: string[];
  unsupportedLockfiles: string[];
  attention: Array<{ code: string; path: string | null }>;
  repositoryCoverage: "tracked_tree_only";
  dependencyClosure: "not_proven";
  runtimeCompleteness: "not_proven";
}

function entries(value: unknown): RepositoryTreeEntry[] {
  if (!Array.isArray(value) || value.length > 10_000) throw new SourceAttention("discovery_tree_capacity");
  const result = value.map(item => {
    const row = object(item, "invalid_tree_entry");
    const path = text(row.path, "invalid_tree_path", 512);
    if (path.startsWith("/") || path.split("/").some(part => !part || part === "." || part === "..")) {
      throw new SourceAttention("invalid_tree_path");
    }
    const type = row.type;
    const mode = row.mode;
    if (!((type === "blob" && ["100644", "100755", "120000"].includes(mode as string))
      || (type === "tree" && mode === "040000") || (type === "commit" && mode === "160000"))
      || typeof row.sha !== "string" || !SHA.test(row.sha)) throw new SourceAttention("invalid_tree_entry");
    const size = row.size ?? null;
    if (size !== null && (type !== "blob" || !Number.isSafeInteger(size) || (size as number) < 0)) {
      throw new SourceAttention("invalid_tree_size");
    }
    return { path, mode: mode as string, type, sha: row.sha, size: size as number | null } as RepositoryTreeEntry;
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const byPath = new Map(result.map(row => [row.path, row]));
  if (byPath.size !== result.length) throw new SourceAttention("duplicate_tree_path");
  for (const row of result) {
    const separator = row.path.lastIndexOf("/");
    if (separator !== -1 && byPath.get(row.path.slice(0, separator))?.type !== "tree") {
      throw new SourceAttention("missing_tree_parent");
    }
  }
  return result;
}

function hash(value: Omit<RepositoryDiscovery, "sha256">): string {
  return sha256(canonicalJson(["repository-discovery-v1", value]));
}

/** Validates retained typed evidence; a hash binds content, not a producer identity. */
export function validateRepositoryDiscovery(value: RepositoryDiscovery): RepositoryDiscovery {
  const copy = structuredClone(value);
  if (copy.version !== 1 || repository(copy.repo) !== copy.repo || !SHA.test(copy.sourceSha) || !SHA.test(copy.treeSha)) {
    throw new SourceAttention("invalid_discovery_snapshot");
  }
  text(copy.defaultBranch, "invalid_default_branch", 256);
  const normalized = entries(copy.entries);
  if (canonicalJson(normalized) !== canonicalJson(copy.entries)) throw new SourceAttention("invalid_discovery_entries");
  const { sha256: storedHash, ...bundle } = copy;
  if (hash(bundle) !== storedHash) throw new SourceAttention("discovery_hash_mismatch");
  return copy;
}

/** Known filenames only. Tracked-tree coverage is never dependency/runtime completeness. */
export function discoveryCoverage(value: RepositoryDiscovery): DiscoveryCoverage {
  const snapshot = validateRepositoryDiscovery(value);
  const result: DiscoveryCoverage = {
    manifests: [], supportedLockfiles: [], unsupportedLockfiles: [], attention: [],
    repositoryCoverage: "tracked_tree_only", dependencyClosure: "not_proven", runtimeCompleteness: "not_proven",
  };
  for (const entry of snapshot.entries) {
    if (entry.mode === "120000" || entry.type === "commit") {
      result.attention.push({ code: entry.type === "commit" ? "uninspected_submodule" : "uninspected_symlink", path: entry.path });
      continue;
    }
    if (entry.type !== "blob") continue;
    const name = entry.path.slice(entry.path.lastIndexOf("/") + 1);
    if (MANIFESTS.has(name)) result.manifests.push(entry.path);
    if (SUPPORTED.has(name)) {
      if (!/^[A-Za-z0-9_./-]+$/u.test(entry.path)) {
        result.attention.push({ code: "unsupported_lockfile_path", path: entry.path });
      } else {
        result.supportedLockfiles.push(entry.path);
      }
      if (entry.size !== null && entry.size > 2 * 1024 * 1024) {
        result.attention.push({ code: "lockfile_content_capacity", path: entry.path });
      }
    }
    if (UNSUPPORTED.has(name)) {
      result.unsupportedLockfiles.push(entry.path);
      result.attention.push({ code: "unsupported_lockfile_format", path: entry.path });
    }
  }
  const lockfiles = new Set([...result.supportedLockfiles, ...result.unsupportedLockfiles]);
  const candidates: Record<string, string[]> = {
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"],
    "Cargo.toml": ["Cargo.lock"], "go.mod": ["go.sum"],
    "pyproject.toml": ["uv.lock", "poetry.lock"], Pipfile: ["Pipfile.lock"], "requirements.txt": ["requirements.txt"],
  };
  for (const manifest of result.manifests) {
    const separator = manifest.lastIndexOf("/");
    const directory = manifest.slice(0, separator + 1);
    const name = manifest.slice(separator + 1);
    if (!candidates[name]!.some(candidate => lockfiles.has(directory + candidate))) {
      result.attention.push({ code: "manifest_lockfile_binding_unproven", path: manifest });
    }
  }
  if (!result.supportedLockfiles.length) result.attention.push({ code: "no_supported_lockfiles", path: null });
  if (result.supportedLockfiles.length > 10) result.attention.push({ code: "lockfile_path_capacity", path: null });
  return result;
}

/** One heads request, then complete recursive trees at immutable tree IDs. No file execution/content reads. */
export class GitHubRepositoryDiscovery {
  constructor(private readonly fetch: SourceFetch, private readonly token: string) {}

  async read(repositories: string[], previous: RepositoryDiscovery[] = []): Promise<RepositoryDiscovery[]> {
    if (!Array.isArray(repositories) || repositories.length > 50 || !Array.isArray(previous) || previous.length > 50) {
      throw new SourceAttention("repository_capacity");
    }
    const repos = repositories.map(repository);
    if (new Set(repos).size !== repos.length) throw new SourceAttention("duplicate_repository");
    const cache = new Map<string, RepositoryDiscovery>();
    for (const value of previous) {
      const snapshot = validateRepositoryDiscovery(value);
      if (cache.has(snapshot.repo)) throw new SourceAttention("duplicate_cached_discovery");
      cache.set(snapshot.repo, snapshot);
    }
    if (!repos.length) return [];
    const request = sourceBudget(this.fetch);
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json", "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Paperclip-vuln-sentinel/0.1.0",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const declarations: string[] = [];
    const selections: string[] = [];
    const variables: Record<string, string> = {};
    repos.forEach((repo, i) => {
      declarations.push(`$owner${i}: String!`, `$name${i}: String!`);
      const [owner, name] = repo.split("/");
      variables[`owner${i}`] = owner!;
      variables[`name${i}`] = name!;
      selections.push(`repo${i}: repository(owner: $owner${i}, name: $name${i}) { nameWithOwner defaultBranchRef { name target { ... on Commit { oid tree { oid } } } } }`);
    });
    const response = await request(`${BASE}/graphql`, {
      method: "POST", headers,
      body: JSON.stringify({ query: `query DiscoveryHeads(${declarations.join(", ")}) { ${selections.join(" ")} }`, variables }),
    });
    if (response.status !== 200) throw new SourceAttention(`github_heads_http_${response.status}`);
    const body = object(response.body, "invalid_heads_response");
    if (body.errors !== undefined && body.errors !== null
      && (!Array.isArray(body.errors) || body.errors.length)) throw new SourceAttention("github_graphql_errors");
    const data = object(body.data, "missing_heads_data");
    const heads = repos.map((repo, i) => {
      const row = object(data[`repo${i}`], "missing_repository_head");
      if (typeof row.nameWithOwner !== "string" || row.nameWithOwner.toLowerCase() !== repo) {
        throw new SourceAttention("repository_identity_mismatch");
      }
      const branch = object(row.defaultBranchRef, "missing_default_branch");
      const target = object(branch.target, "missing_head_target");
      const tree = object(target.tree, "missing_head_tree");
      if (typeof target.oid !== "string" || !SHA.test(target.oid) || typeof tree.oid !== "string" || !SHA.test(tree.oid)) {
        throw new SourceAttention("invalid_source_sha");
      }
      return { version: 1 as const, repo, sourceSha: target.oid, treeSha: tree.oid, defaultBranch: text(branch.name, "invalid_default_branch", 256) };
    });
    const result: RepositoryDiscovery[] = [];
    let totalBytes = 0;
    for (const head of heads) {
      const old = cache.get(head.repo);
      let rows: RepositoryTreeEntry[];
      if (old && old.sourceSha === head.sourceSha) {
        if (old.treeSha !== head.treeSha) throw new SourceAttention("discovery_commit_tree_mismatch");
        rows = old.entries;
      } else {
        const response = await request(`${BASE}/repos/${head.repo}/git/trees/${head.treeSha}?recursive=1`, { method: "GET", headers });
        if (response.status !== 200) throw new SourceAttention(`github_tree_http_${response.status}`);
        const tree = object(response.body, "invalid_tree_response");
        if (tree.sha !== head.treeSha || tree.truncated !== false) throw new SourceAttention("incomplete_repository_tree");
        rows = entries(tree.tree);
      }
      const bundle = { ...head, entries: rows };
      totalBytes += Buffer.byteLength(canonicalJson(bundle));
      if (totalBytes > 8 * 1024 * 1024) throw new SourceAttention("discovery_snapshot_capacity");
      result.push({ ...bundle, sha256: hash(bundle) });
    }
    return result;
  }
}
