import { createHash } from "node:crypto";
import { discoveryCoverage, validateRepositoryDiscovery, type RepositoryDiscovery } from "./github-discovery.js";
import { repository } from "./github-repository.js";
import { canonicalJson, sha256 } from "./identity.js";
import { object, SourceAttention, sourceBudget, text, type SourceFetch } from "./source-http.js";

const BASE = "https://api.github.com";
const SHA = /^[a-f0-9]{40}$/u;

export interface RepositorySource {
  repo: string;
  paths: string[];
}

export interface LockfileBlob {
  path: string;
  blobSha: string;
  content: string;
  sha256: string;
  etag: string | null;
}

export interface RepositoryLockfiles {
  repo: string;
  sourceSha: string;
  defaultBranch: string;
  artifactDigest: string;
  files: LockfileBlob[];
}

function path(value: string): string {
  text(value, "invalid_lockfile_path", 512);
  if (!/^[A-Za-z0-9_./-]+$/u.test(value)
    || value.split("/").some(part => !part || part === "." || part === "..")) {
    throw new SourceAttention("invalid_lockfile_path");
  }
  return value;
}

function gitBlob(content: string): string {
  const bytes = Buffer.from(content);
  return createHash("sha1").update(`blob ${bytes.byteLength}\0`).update(bytes).digest("hex");
}

function digest(files: LockfileBlob[]): string {
  return `sha256:${sha256(canonicalJson(files.map(file => [file.path, file.sha256])))}`;
}

function validateBlob(file: LockfileBlob): void {
  path(file.path);
  if (typeof file.content !== "string" || Buffer.byteLength(file.content) > 2 * 1024 * 1024
    || !SHA.test(file.blobSha) || gitBlob(file.content) !== file.blobSha || sha256(file.content) !== file.sha256) {
    throw new SourceAttention("invalid_cached_blob");
  }
  if (file.etag !== null) text(file.etag, "invalid_etag", 512);
}

export function normalizeRepositorySources(sources: RepositorySource[]): RepositorySource[] {
  if (!Array.isArray(sources) || sources.length > 50) throw new SourceAttention("repository_capacity");
  const normalized = sources.map(source => {
    if (!Array.isArray(source.paths) || !source.paths.length || source.paths.length > 10) {
      throw new SourceAttention("lockfile_path_capacity");
    }
    return { repo: repository(source.repo), paths: [...new Set(source.paths.map(path))].sort() };
  });
  if (new Set(normalized.map(source => source.repo)).size !== normalized.length) {
    throw new SourceAttention("duplicate_repository");
  }
  return normalized;
}

/** One default-head GraphQL call; content reads use immutable SHAs, never branch names. */
export class GitHubLockfiles {
  constructor(private readonly fetch: SourceFetch, private readonly token: string) {}

  async read(sources: RepositorySource[], previous: RepositoryLockfiles[] = []): Promise<RepositoryLockfiles[]> {
    return this.readSelected(sources, previous);
  }

  async readDiscovered(discoveries: RepositoryDiscovery[], previous: RepositoryLockfiles[] = []): Promise<RepositoryLockfiles[]> {
    if (!Array.isArray(discoveries) || discoveries.length > 50) throw new SourceAttention("repository_capacity");
    const selected = discoveries.map(validateRepositoryDiscovery);
    const sources = selected.map(snapshot => {
      const coverage = discoveryCoverage(snapshot);
      if (coverage.attention.length) throw new SourceAttention("discovery_coverage_attention");
      return { repo: snapshot.repo, paths: coverage.supportedLockfiles };
    });
    return this.readSelected(sources, previous, selected);
  }

  private async readSelected(sources: RepositorySource[], previous: RepositoryLockfiles[], discoveries?: RepositoryDiscovery[]): Promise<RepositoryLockfiles[]> {
    if (previous.length > 50) throw new SourceAttention("repository_capacity");
    const normalized = normalizeRepositorySources(sources);
    const cache = new Map<string, RepositoryLockfiles>();
    for (const entry of previous) {
      const repo = repository(entry.repo);
      if (repo !== entry.repo || cache.has(repo) || !SHA.test(entry.sourceSha)
        || !Array.isArray(entry.files) || entry.files.length > 10) throw new SourceAttention("invalid_cached_repository");
      entry.files.forEach(validateBlob);
      if (new Set(entry.files.map(file => file.path)).size !== entry.files.length
        || entry.artifactDigest !== digest(entry.files)) throw new SourceAttention("invalid_cached_repository");
      cache.set(repo, structuredClone(entry));
    }
    if (!normalized.length) return [];
    const request = sourceBudget(this.fetch);
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json", "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Paperclip-vuln-sentinel/0.1.0",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const heads = discoveries?.map(({ sourceSha, defaultBranch }) => ({ sourceSha, defaultBranch }))
      ?? await this.readHeads(normalized, request, headers);
    const snapshots: RepositoryLockfiles[] = [];
    let totalBytes = 0;
    for (const [index, source] of normalized.entries()) {
      const head = heads[index]!;
      const cached = cache.get(source.repo);
      const files: LockfileBlob[] = [];
      for (const filePath of source.paths) {
        const old = cached?.files.find(file => file.path === filePath);
        let file: LockfileBlob;
        if (old && cached!.sourceSha === head.sourceSha) {
          file = old;
        } else {
          const contentHeaders = { ...headers };
          if (old?.etag) contentHeaders["If-None-Match"] = old.etag;
          const url = `${BASE}/repos/${source.repo}/contents/${filePath.split("/").map(encodeURIComponent).join("/")}?ref=${head.sourceSha}`;
          const result = await request(url, { method: "GET", headers: contentHeaders });
          if (result.status === 304) {
            if (!old?.etag) throw new SourceAttention("unbound_not_modified");
            file = old;
          } else {
            if (result.status !== 200) throw new SourceAttention(`github_lockfile_http_${result.status}`);
            const row = object(result.body, "invalid_lockfile_response");
            if (row.type !== "file" || row.path !== filePath || row.encoding !== "base64"
              || typeof row.content !== "string" || !Number.isInteger(row.size) || (row.size as number) < 0
              || (row.size as number) > 2 * 1024 * 1024) throw new SourceAttention("incomplete_lockfile_content");
            const encoded = row.content.replace(/\n/gu, "");
            if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(encoded)) {
              throw new SourceAttention("invalid_lockfile_base64");
            }
            const bytes = Buffer.from(encoded, "base64");
            const content = bytes.toString("utf8");
            if (bytes.toString("base64") !== encoded || bytes.byteLength !== row.size || !Buffer.from(content).equals(bytes)) {
              throw new SourceAttention("lockfile_size_or_encoding_mismatch");
            }
            file = {
              path: filePath, content, sha256: sha256(content),
              blobSha: text(row.sha, "invalid_blob_sha", 40), etag: result.etag,
            };
            validateBlob(file);
          }
        }
        const discovered = discoveries?.[index]?.entries.find(entry => entry.path === filePath);
        if (discoveries && (!discovered || discovered.type !== "blob" || discovered.mode === "120000"
          || discovered.sha !== file.blobSha || (discovered.size !== null && discovered.size !== Buffer.byteLength(file.content)))) {
          throw new SourceAttention("discovered_blob_mismatch");
        }
        totalBytes += Buffer.byteLength(file.content);
        if (totalBytes > 8 * 1024 * 1024) throw new SourceAttention("lockfile_snapshot_capacity");
        files.push(file);
      }
      snapshots.push({ ...head, repo: source.repo, files, artifactDigest: digest(files) });
    }
    return snapshots;
  }

  private async readHeads(sources: RepositorySource[], request: ReturnType<typeof sourceBudget>, headers: Record<string, string>) {
    const declarations: string[] = [];
    const selections: string[] = [];
    const variables: Record<string, string> = {};
    sources.forEach((source, index) => {
      declarations.push(`$owner${index}: String!`, `$name${index}: String!`);
      const [owner, name] = source.repo.split("/");
      variables[`owner${index}`] = owner!;
      variables[`name${index}`] = name!;
      selections.push(`repo${index}: repository(owner: $owner${index}, name: $name${index}) { nameWithOwner defaultBranchRef { name target { ... on Commit { oid } } } }`);
    });
    const response = await request(`${BASE}/graphql`, {
      method: "POST", headers,
      body: JSON.stringify({ query: `query DefaultHeads(${declarations.join(", ")}) { ${selections.join(" ")} }`, variables }),
    });
    if (response.status !== 200) throw new SourceAttention(`github_heads_http_${response.status}`);
    const body = object(response.body, "invalid_heads_response");
    if (body.errors !== undefined && body.errors !== null
      && (!Array.isArray(body.errors) || body.errors.length)) throw new SourceAttention("github_graphql_errors");
    const data = object(body.data, "missing_heads_data");
    // Validate all heads before fetching any content; partial GraphQL data cannot certify coverage.
    return sources.map((source, index) => {
      const repo = object(data[`repo${index}`], "missing_repository_head");
      if (typeof repo.nameWithOwner !== "string" || repo.nameWithOwner.toLowerCase() !== source.repo) {
        throw new SourceAttention("repository_identity_mismatch");
      }
      const branch = object(repo.defaultBranchRef, "missing_default_branch");
      const target = object(branch.target, "missing_head_target");
      const sourceSha = text(target.oid, "invalid_source_sha", 40);
      if (!SHA.test(sourceSha)) throw new SourceAttention("invalid_source_sha");
      return { sourceSha, defaultBranch: text(branch.name, "invalid_default_branch", 256) };
    });
  }
}
