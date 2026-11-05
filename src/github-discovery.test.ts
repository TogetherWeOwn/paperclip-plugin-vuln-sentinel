import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { discoveryCoverage, GitHubRepositoryDiscovery, validateRepositoryDiscovery } from "./github-discovery.js";
import { GitHubLockfiles } from "./github-lockfiles.js";
import { parseLockfileInventory } from "./inventory.js";
import type { SourceFetch } from "./source-http.js";

const commit = "a".repeat(40);
const treeSha = "b".repeat(40);
const blobSha = "c".repeat(40);
const head = (repo = "Example/Repo", oid = commit, tree = treeSha) => ({
  nameWithOwner: repo, defaultBranchRef: { name: "main", target: { oid, tree: { oid: tree } } },
});
const heads = () => ({ data: { repo0: head() } });
const entry = (path = "package-lock.json", mode = "100644", type = "blob") => ({ path, mode, type, sha: blobSha });
const tree = (rows: unknown[] = [entry()]) => ({ sha: treeSha, truncated: false, tree: rows });
function transport(responses: unknown[]) {
  return vi.fn<SourceFetch>(async () => {
    if (!responses.length) throw new Error("Unexpected request");
    const value = responses.shift();
    return value instanceof Response ? value : new Response(JSON.stringify(value));
  });
}
const discovery = async (rows: unknown[] = [entry()]) => new GitHubRepositoryDiscovery(transport([heads(), tree(rows)]), "token").read(["example/repo"]);
const content = '{"lockfileVersion":3,"packages":{"":{"name":"fixture"},"node_modules/example":{"version":"1.0.0","resolved":"https://registry.npmjs.org/example/-/example-1.0.0.tgz"}}}';
const contentSha = createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex");
const contents = () => ({ type: "file", path: "package-lock.json", encoding: "base64", size: Buffer.byteLength(content), content: Buffer.from(content).toString("base64"), sha: contentSha });
const withContent = () => discovery([{ ...entry(), sha: contentSha, size: Buffer.byteLength(content) }]);

describe("immutable tracked-tree discovery", () => {
  it("reads all heads once and fetches each tree at its immutable ID", async () => {
    const fetch = transport([{ data: { repo0: head(), repo1: head("example/other") } }, tree(), tree()]);
    const result = await new GitHubRepositoryDiscovery(fetch, "token").read(["Example/Repo", "example/other"]);
    expect(result.map(row => row.repo)).toEqual(["example/repo", "example/other"]);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      "https://api.github.com/graphql", `https://api.github.com/repos/example/repo/git/trees/${treeSha}?recursive=1`,
      `https://api.github.com/repos/example/other/git/trees/${treeSha}?recursive=1`,
    ]);
    expect(fetch.mock.calls[1]![1]).toMatchObject({ redirect: "error", headers: { Authorization: "Bearer token" } });
    expect(result[0]).toMatchObject({ sourceSha: commit, treeSha, version: 1 });
    expect(result[0]!.sha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("discovers nested files, unsupported lockfiles and opaque tree entries without following links", async () => {
    const [value] = await discovery([
      entry("sub", "040000", "tree"), entry("sub/Cargo.lock"), entry("sub/Cargo.toml"), entry("package.json"),
      entry("pnpm-lock.yaml"), entry("yarn.lock"), entry("linked", "120000"), entry("vendor", "160000", "commit"),
    ]);
    expect(discoveryCoverage(value!)).toEqual({
      manifests: ["package.json", "sub/Cargo.toml"], supportedLockfiles: ["pnpm-lock.yaml", "sub/Cargo.lock"],
      unsupportedLockfiles: ["yarn.lock"], repositoryCoverage: "tracked_tree_only", dependencyClosure: "not_proven", runtimeCompleteness: "not_proven",
      attention: [
        { code: "uninspected_symlink", path: "linked" }, { code: "uninspected_submodule", path: "vendor" },
        { code: "unsupported_lockfile_format", path: "yarn.lock" },
      ],
    });
  });

  it("reuses validated trees only on unchanged commit and tree identities", async () => {
    const old = await discovery();
    const fetch = transport([heads()]);
    const values = await new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"], old);
    expect(values).toEqual(old);
    values[0]!.entries[0]!.path = "changed";
    expect(old[0]!.entries[0]!.path).toBe("package-lock.json");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("refetches a changed commit even when the tree ID is equal", async () => {
    const old = await discovery();
    const fetch = transport([{ data: { repo0: head("Example/Repo", "d".repeat(40)) } }, tree()]);
    const [value] = await new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"], old);
    expect(value!.sourceSha).toBe("d".repeat(40));
    expect(value!.sha256).not.toBe(old[0]!.sha256);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("rejects changed tree identity under an unchanged commit", async () => {
    const old = await discovery();
    const fetch = transport([{ data: { repo0: head("Example/Repo", commit, "d".repeat(40)) } }]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"], old)).rejects.toThrow("discovery_commit_tree_mismatch");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("validates every head before any tree read", async () => {
    const fetch = transport([{ data: { repo0: head(), repo1: null } }]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo", "example/other"])).rejects.toThrow("missing_repository_head");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    { data: { repo0: head("example/wrong") } }, { data: { repo0: head("example/repo", "main") } },
    { data: { repo0: head("example/repo", commit, "main") } }, { errors: [{ message: "partial" }], ...heads() },
    { data: { repo0: { nameWithOwner: "example/repo", defaultBranchRef: null } } },
  ])("holds invalid GraphQL evidence %#", async response => {
    const fetch = transport([response]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"])).rejects.toThrow("Source requires attention");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    { truncated: true }, { truncated: undefined }, { sha: "d".repeat(40) }, { tree: null },
    { tree: [entry(), entry()] }, { tree: [entry("sub/package-lock.json")] },
    { tree: [entry("sub"), entry("sub/package-lock.json")] }, { tree: [entry("../package-lock.json")] },
    { tree: [entry("/package-lock.json")] }, { tree: [entry("sub//package-lock.json")] },
    { tree: [entry("bad\npath")] }, { tree: [entry("package-lock.json", "160000", "blob")] },
    { tree: [{ ...entry(), sha: "invalid" }] }, { tree: [{ ...entry(), size: -1 }] },
    { tree: [{ ...entry(), size: 1.5 }] }, { tree: [{ ...entry("sub", "040000", "tree"), size: 0 }] },
  ])("refuses partial or malformed recursive trees %#", async change => {
    const fetch = transport([heads(), { ...tree(), ...change }]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"])).rejects.toThrow("Source requires attention");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it.each([304, 403, 404, 429, 500])("never reuses stale tree evidence after HTTP %s", async status => {
    const old = await discovery();
    const fetch = transport([{ data: { repo0: head("example/repo", "d".repeat(40)) } }, new Response(null, { status })]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"], old)).rejects.toThrow(`github_tree_http_${status}`);
  });

  it.each([[], [entry("package.json")], [entry("go.mod"), entry("go.sum")]].map(rows => ({ rows })))("never interprets missing supported inventory as complete %#", async ({ rows }) => {
    const [value] = await discovery(rows);
    expect(discoveryCoverage(value!).attention).toContainEqual({ code: "no_supported_lockfiles", path: null });
    expect(discoveryCoverage(value!).runtimeCompleteness).toBe("not_proven");
  });

  it("retains unsafe-for-content paths, oversize files and capacity as attention", async () => {
    const [value] = await discovery([
      entry("with space", "040000", "tree"), entry("with space/package-lock.json"),
      { ...entry("Cargo.lock"), size: 3 * 1024 * 1024 },
      ...Array.from({ length: 11 }, (_, i) => [entry(`p${i}`, "040000", "tree"), entry(`p${i}/pnpm-lock.yaml`)]).flat(),
    ]);
    const coverage = discoveryCoverage(value!);
    expect(coverage.attention).toEqual(expect.arrayContaining([
      { code: "unsupported_lockfile_path", path: "with space/package-lock.json" },
      { code: "lockfile_content_capacity", path: "Cargo.lock" }, { code: "lockfile_path_capacity", path: null },
    ]));
  });

  it("enforces tree capacity without truncating", async () => {
    const fetch = transport([heads(), tree(Array.from({ length: 10_001 }, (_, i) => entry(`p${i}`)))]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"])).rejects.toThrow("discovery_tree_capacity");
  });

  it("validates snapshot hashes and canonical entries before cache reuse", async () => {
    const old = await discovery();
    old[0]!.entries[0]!.sha = "d".repeat(40);
    const fetch = transport([]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(["example/repo"], old)).rejects.toThrow("discovery_hash_mismatch");
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([["https://example.test/repo"], ["example/repo", "Example/Repo"], Array<string>(51).fill("example/repo")].map(repos => ({ repos })))("validates repos before sending credentials %#", async ({ repos }) => {
    const fetch = transport([]);
    await expect(new GitHubRepositoryDiscovery(fetch, "token").read(repos)).rejects.toThrow("Source requires attention");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not contact a provider when no repositories are selected", async () => {
    const fetch = transport([]);
    expect(await new GitHubRepositoryDiscovery(fetch, "token").read([])).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("discovery-bound immutable content reads", () => {
  it("uses the discovered commit without another heads request and binds blob identity", async () => {
    const selected = await withContent();
    const fetch = transport([contents()]);
    const [snapshot] = await new GitHubLockfiles(fetch, "token").readDiscovered(selected);
    expect(snapshot!.sourceSha).toBe(commit);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([`https://api.github.com/repos/example/repo/contents/package-lock.json?ref=${commit}`]);
    expect(parseLockfileInventory(snapshot!).dependencies).toContainEqual(expect.objectContaining({ package: "example", version: "1.0.0" }));
    expect(validateRepositoryDiscovery(selected[0]!)).toEqual(selected[0]);
  });

  it("skips content requests for unchanged discovered commits", async () => {
    const selected = await withContent();
    const old = await new GitHubLockfiles(transport([contents()]), "token").readDiscovered(selected);
    const fetch = transport([]);
    expect(await new GitHubLockfiles(fetch, "token").readDiscovered(selected, old)).toEqual(old);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects content that passes its own hash but differs from the discovered blob", async () => {
    const selected = await discovery();
    await expect(new GitHubLockfiles(transport([contents()]), "token").readDiscovered(selected)).rejects.toThrow("discovered_blob_mismatch");
  });

  it.each([[entry("yarn.lock"), entry()], [entry("link", "120000"), entry()], [], [entry("vendor", "160000", "commit"), entry()]].map(rows => ({ rows })))("holds coverage attention before content reads %#", async ({ rows }) => {
    const selected = await discovery(rows);
    const fetch = transport([]);
    await expect(new GitHubLockfiles(fetch, "token").readDiscovered(selected)).rejects.toThrow("discovery_coverage_attention");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("does not hide an unbound Go manifest or assume a root lockfile covers a nested manifest", async () => {
    for (const rows of [
      [entry(), entry("go.mod")],
      [entry(), entry("sub", "040000", "tree"), entry("sub/package.json")],
    ]) {
      const selected = await discovery(rows);
      expect(discoveryCoverage(selected[0]!).attention).toContainEqual(expect.objectContaining({ code: "manifest_lockfile_binding_unproven" }));
      const fetch = transport([]);
      await expect(new GitHubLockfiles(fetch, "token").readDiscovered(selected)).rejects.toThrow("discovery_coverage_attention");
      expect(fetch).not.toHaveBeenCalled();
    }
  });

  it("rebinds ETag content only when the new discovered tree agrees on blob and size", async () => {
    const selected = await withContent();
    const old = await new GitHubLockfiles(transport([new Response(JSON.stringify(contents()), { headers: { etag: '"etag"' } })]), "token").readDiscovered(selected);
    const next = await new GitHubRepositoryDiscovery(transport([
      { data: { repo0: head("example/repo", "d".repeat(40)) } }, tree([{ ...entry(), sha: contentSha }]),
    ]), "token").read(["example/repo"], selected);
    const fetch = transport([new Response(null, { status: 304 })]);
    const [snapshot] = await new GitHubLockfiles(fetch, "token").readDiscovered(next, old);
    expect(snapshot!.sourceSha).toBe("d".repeat(40));
    expect(fetch.mock.calls[0]![1].headers).toMatchObject({ "If-None-Match": '"etag"' });
    const changed = await new GitHubRepositoryDiscovery(transport([
      { data: { repo0: head("example/repo", "e".repeat(40)) } }, tree(),
    ]), "token").read(["example/repo"], selected);
    await expect(new GitHubLockfiles(transport([new Response(null, { status: 304 })]), "token").readDiscovered(changed, old))
      .rejects.toThrow("discovered_blob_mismatch");
  });

  it("rejects duplicate discovery repos before content reads", async () => {
    const selected = await withContent();
    const fetch = transport([]);
    await expect(new GitHubLockfiles(fetch, "token").readDiscovered([...selected, ...selected])).rejects.toThrow("duplicate_repository");
    expect(fetch).not.toHaveBeenCalled();
  });
});
