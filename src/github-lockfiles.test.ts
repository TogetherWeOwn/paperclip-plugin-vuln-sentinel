import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { GitHubLockfiles } from "./github-lockfiles.js";
import type { SourceFetch } from "./source-http.js";

const sha = "a".repeat(40);
const nextSha = "b".repeat(40);
const source = { repo: "example/repo", paths: ["pnpm-lock.yaml"] };
const head = (oid = sha, repo = "Example/Repo") => ({ nameWithOwner: repo, defaultBranchRef: { name: "main", target: { oid } } });
const heads = (oid = sha) => ({ data: { repo0: head(oid) } });
const blob = (content = "lockfileVersion: '9.0'\n", path = "pnpm-lock.yaml") => ({
  type: "file", path, encoding: "base64", size: Buffer.byteLength(content),
  content: Buffer.from(content).toString("base64"),
  sha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex"),
});
const json = (value: unknown, etag?: string) => new Response(JSON.stringify(value), { headers: etag ? { etag } : {} });
function transport(responses: Array<unknown | Response>) {
  return vi.fn<SourceFetch>(async () => {
    if (!responses.length) throw new Error("Unexpected request");
    const response = responses.shift();
    return response instanceof Response ? response : json(response);
  });
}
const cached = async () => new GitHubLockfiles(transport([heads(), json(blob(), '"etag"')]), "token").read([source]);

describe("immutable GitHub lockfile snapshots", () => {
  it("gets every default SHA in one GraphQL call and binds content reads to SHAs", async () => {
    const fetch = transport([
      { data: { repo0: head(), repo1: head(sha, "example/other") } }, blob(), blob(),
    ]);
    const result = await new GitHubLockfiles(fetch, "token").read([source, { ...source, repo: "example/other" }]);
    expect(result).toHaveLength(2);
    expect(result[0]).toMatchObject({ repo: source.repo, sourceSha: sha, defaultBranch: "main" });
    expect(result[0]!.artifactDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(result[0]!.files[0]!.content).toContain("lockfileVersion");
    expect(fetch.mock.calls.filter(([url]) => url.endsWith("/graphql"))).toHaveLength(1);
    expect(JSON.parse(fetch.mock.calls[0]![1].body as string).variables)
      .toEqual({ owner0: "example", name0: "repo", owner1: "example", name1: "other" });
    expect(fetch.mock.calls[1]![0]).toBe(`https://api.github.com/repos/example/repo/contents/pnpm-lock.yaml?ref=${sha}`);
    expect(fetch.mock.calls[1]![1]).toMatchObject({ redirect: "error", headers: { Authorization: "Bearer token" } });
  });

  it("does no content reads on an unchanged SHA", async () => {
    const previous = await cached();
    const fetch = transport([heads()]);
    expect(await new GitHubLockfiles(fetch, "token").read([source], previous)).toEqual(previous);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("uses ETags on changed heads and rebinds 304 content to the new source SHA", async () => {
    const previous = await cached();
    const fetch = transport([heads(nextSha), new Response(null, { status: 304 })]);
    const [result] = await new GitHubLockfiles(fetch, "token").read([source], previous);
    expect(result!.sourceSha).toBe(nextSha);
    expect(result!.artifactDigest).toBe(previous[0]!.artifactDigest);
    expect(fetch.mock.calls[1]![1].headers).toMatchObject({ "If-None-Match": '"etag"' });
    expect(fetch.mock.calls[1]![0]).toContain(`ref=${nextSha}`);
    expect(previous[0]!.sourceSha).toBe(sha);
  });

  it("replaces changed content and ETag without mutating the previous snapshot", async () => {
    const previous = await cached();
    const fetch = transport([heads(nextSha), json(blob("changed\n"), '"new"')]);
    const [result] = await new GitHubLockfiles(fetch, "token").read([source], previous);
    expect(result!.files[0]!.etag).toBe('"new"');
    expect(result!.artifactDigest).not.toBe(previous[0]!.artifactDigest);
    expect(previous[0]!.files[0]!.etag).toBe('"etag"');
  });

  it("fetches newly configured paths even on unchanged SHAs", async () => {
    const previous = await cached();
    const fetch = transport([heads(), blob("{}", "package-lock.json")]);
    const [result] = await new GitHubLockfiles(fetch, "token").read([{ ...source, paths: [...source.paths, "package-lock.json"] }], previous);
    expect(result!.files.map(file => file.path)).toEqual(["package-lock.json", "pnpm-lock.yaml"]);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("never reuses an ETag from a different repository or path", async () => {
    const previous = await cached();
    const fetch = transport([{ data: { repo0: head(nextSha, "example/other") } }, blob()]);
    await new GitHubLockfiles(fetch, "token").read([{ ...source, repo: "example/other" }], previous);
    expect(fetch.mock.calls[1]![1].headers).not.toHaveProperty("If-None-Match");
  });

  it("rejects a 304 with no bound cached ETag", async () => {
    await expect(new GitHubLockfiles(transport([heads(), new Response(null, { status: 304 })]), "token").read([source]))
      .rejects.toThrow("unbound_not_modified");
  });

  it.each([403, 404, 429, 500])("never falls back to stale content on content HTTP %s", async status => {
    const previous = await cached();
    const fetch = transport([heads(nextSha), new Response(null, { status })]);
    await expect(new GitHubLockfiles(fetch, "token").read([source], previous)).rejects.toThrow(`github_lockfile_http_${status}`);
    expect(previous[0]!.sourceSha).toBe(sha);
  });

  it.each([
    { errors: [{ message: "permission denied" }], data: { repo0: head() } },
    { data: { repo0: null } },
    { data: { repo0: { ...head(), defaultBranchRef: null } } },
    { data: { repo0: head("mutable-main") } },
    { data: { repo0: head(sha, "example/other") } },
    {},
  ])("holds partial, mismatched or malformed default-head results %#", async body => {
    const fetch = transport([body]);
    await expect(new GitHubLockfiles(fetch, "token").read([source])).rejects.toThrow("Source requires attention");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("validates all repo heads before any content read", async () => {
    const fetch = transport([{ data: { repo0: head(), repo1: null } }]);
    await expect(new GitHubLockfiles(fetch, "token").read([source, { ...source, repo: "example/other" }]))
      .rejects.toThrow("missing_repository_head");
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    { type: "symlink" }, { path: "other.yaml" }, { encoding: "none" }, { size: 123 },
    { size: 3 * 1024 * 1024 }, { content: "invalid?" }, { sha: "0".repeat(40) },
    { content: "/w==", size: 1 },
  ])("rejects mismatched, truncated, unbound or non-UTF8 content %#", async change => {
    const fetch = transport([heads(), { ...blob(), ...change }]);
    await expect(new GitHubLockfiles(fetch, "token").read([source])).rejects.toThrow("Source requires attention");
  });

  it.each([
    { repo: "https://malicious.example/repo", paths: ["pnpm-lock.yaml"] },
    { repo: "example/repo", paths: ["../pnpm-lock.yaml"] },
    { repo: "example/repo", paths: ["/pnpm-lock.yaml"] },
    { repo: "example/repo", paths: ["a//pnpm-lock.yaml"] },
    { repo: "example/repo", paths: ["a?ref=main"] },
    { repo: "example/repo", paths: [] },
  ])("rejects unsafe config before sending credentials %#", async config => {
    const fetch = transport([]);
    await expect(new GitHubLockfiles(fetch, "token").read([config])).rejects.toThrow("Source requires attention");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects case-folded duplicate repositories", async () => {
    const fetch = transport([]);
    await expect(new GitHubLockfiles(fetch, "token").read([source, { ...source, repo: "Example/Repo" }]))
      .rejects.toThrow("duplicate_repository");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects corrupt cached content, hashes, ETags and duplicate paths before a network request", async () => {
    for (const mutate of [
      (entry: Awaited<ReturnType<typeof cached>>[number]) => { entry.files[0]!.content = "corrupt"; },
      (entry: Awaited<ReturnType<typeof cached>>[number]) => { entry.artifactDigest = "sha256:wrong"; },
      (entry: Awaited<ReturnType<typeof cached>>[number]) => { entry.files[0]!.etag = "bad\r\nheader"; },
      (entry: Awaited<ReturnType<typeof cached>>[number]) => { entry.files.push(entry.files[0]!); },
    ]) {
      const previous = await cached();
      mutate(previous[0]!);
      const fetch = transport([]);
      await expect(new GitHubLockfiles(fetch, "token").read([source], previous)).rejects.toThrow("Source requires attention");
      expect(fetch).not.toHaveBeenCalled();
    }
  });

  it("does not contact GitHub with no configured repositories", async () => {
    const fetch = transport([]);
    expect(await new GitHubLockfiles(fetch, "token").read([])).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});
