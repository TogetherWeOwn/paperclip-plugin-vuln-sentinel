import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { DiscoveredRepositorySourceSync } from "./discovered-source-sync.js";
import { GitHubRepositoryDiscovery, discoveryCoverage } from "./github-discovery.js";
import { GitHubLockfiles } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { DeliveryRouting } from "./routing.js";
import { SourceEffects } from "./source-effects.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore } from "./source-polls.js";
import type { SourceFetch } from "./source-http.js";
import { testDatabase } from "./test/database.js";
import { finding } from "./test/fixtures.js";
import { sourceLockfiles } from "./test/sources.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let polls: SourcePollStore;
let journal: SourceJournal;
const repo = "example/project";
const configured = { repo, paths: ["package-lock.json"] };
const commit = "a".repeat(40);
const treeSha = "b".repeat(40);
const nextCommit = "c".repeat(40);
const head = (name = repo, oid = commit) => ({ nameWithOwner: name, defaultBranchRef: { name: "main", target: { oid, tree: { oid: treeSha } } } });
const heads = (oid = commit) => ({ data: { repo0: head(repo, oid) } });
const file = () => sourceLockfiles().files[0]!;
const entry = () => ({ path: file().path, mode: "100644", type: "blob", sha: file().blobSha, size: Buffer.byteLength(file().content) });
const tree = (entries: unknown[] = [entry()]) => ({ sha: treeSha, truncated: false, tree: entries });
const blob = () => ({ type: "file", path: file().path, sha: file().blobSha, encoding: "base64", size: Buffer.byteLength(file().content), content: Buffer.from(file().content).toString("base64") });
function transport(responses: unknown[]) {
  return vi.fn<SourceFetch>(async () => {
    if (!responses.length) throw new Error("Unexpected request");
    const response = responses.shift();
    return response instanceof Response ? response : new Response(JSON.stringify(response), { headers: { etag: '"fixture"' } });
  });
}
function sync(fetch: SourceFetch, database = db) {
  return new DiscoveredRepositorySourceSync(new SourcePollStore(database), new SourceJournal(database),
    new GitHubRepositoryDiscovery(fetch, "fixture"), new GitHubLockfiles(fetch, "fixture"));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
async function discovery() {
  return (await new GitHubRepositoryDiscovery(transport([heads(), tree()]), "fixture").read([repo]))[0]!;
}
async function snapshots() {
  return (await postgres.query<{ snapshot_id: string; source_kind: string }>(`SELECT snapshot_id, source_kind FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows;
}

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_snapshots, ${DATABASE_NAMESPACE}.source_polls,
    ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records, ${DATABASE_NAMESPACE}.delivery_routing`);
  polls = new SourcePollStore(db);
  journal = new SourceJournal(db);
});
afterAll(async () => { await postgres.close(); });

describe("discovery-bound durable source synchronization", () => {
  it("retains exact discovery before content and selects the bound inventory with only one heads call", async () => {
    const replies = transport([heads(), tree(), blob()]);
    const fetch: SourceFetch = async (url, init) => {
      if (url.includes("/contents/")) {
        expect((await snapshots()).map(row => row.source_kind)).toEqual(["discovery"]);
        await expect(polls.current("company", configured)).rejects.toThrow("current_source_pending");
      }
      return replies(url, init);
    };
    const [selected] = await sync(fetch).read("company", ["Example/Project"]);
    expect(replies.mock.calls.map(([url]) => url)).toEqual([
      "https://api.github.com/graphql", `https://api.github.com/repos/${repo}/git/trees/${treeSha}?recursive=1`,
      `https://api.github.com/repos/${repo}/contents/package-lock.json?ref=${commit}`,
    ]);
    expect(selected!.stored.lockfiles).toEqual(sourceLockfiles());
    expect(selected!.stored.discoverySnapshotId).toMatch(/^[a-f0-9]{64}$/u);
    const retained = (await journal.readDiscovery("company", selected!.stored.discoverySnapshotId!))!;
    expect(discoveryCoverage(retained)).toMatchObject({ repositoryCoverage: "tracked_tree_only", dependencyClosure: "not_proven", runtimeCompleteness: "not_proven" });
    expect(selected!.stored.inventory.coverage.runtimeCompleteness).toBe("not_proven");
    await polls.assertCurrent(selected!);
    expect(await journal.readDiscovery("other", selected!.stored.discoverySnapshotId!)).toBeNull();
  });

  it("reuses durable unchanged discovery and content after reconstructing adapters, without fetching either again", async () => {
    const [first] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const fetch = transport([heads()]);
    const [second] = await sync(fetch).read("company", [repo]);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(second!.snapshotId).toBe(first!.snapshotId);
    expect(second!.token).not.toBe(first!.token);
    expect(second!.pollRevision).toBeGreaterThan(first!.pollRevision);
    expect(await snapshots()).toHaveLength(2);
  });

  it("fetches a changed head's tree and validates ETag bytes against that exact discovery", async () => {
    const [first] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const fetch = transport([heads(nextCommit), tree(), new Response(null, { status: 304 })]);
    const [second] = await sync(fetch).read("company", [repo]);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(fetch.mock.calls[2]![1]!.headers).toMatchObject({ "If-None-Match": '"fixture"' });
    expect(second!.stored.lockfiles.sourceSha).toBe(nextCommit);
    expect(second!.stored.lockfiles.artifactDigest).toBe(first!.stored.lockfiles.artifactDigest);
    expect(second!.stored.discoverySnapshotId).not.toBe(first!.stored.discoverySnapshotId);
    expect(second!.snapshotId).not.toBe(first!.snapshotId);
  });

  it("reserves before the first network request, so old ready evidence cannot be selected during discovery", async () => {
    const [old] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const fetch = transport([heads()]);
    const checked: SourceFetch = async (url, init) => {
      await expect(polls.assertCurrent(old!)).rejects.toThrow("source_configuration_changed");
      return fetch(url, init);
    };
    await sync(checked).read("company", [repo]);
  });

  it.each([
    [{ path: "yarn.lock", mode: "100644", type: "blob", sha: treeSha }, "unsupported_lockfile_format"],
    [{ path: "nested", mode: "120000", type: "blob", sha: treeSha }, "uninspected_symlink"],
    [{ path: "vendor", mode: "160000", type: "commit", sha: treeSha }, "uninspected_submodule"],
    [{ path: "Cargo.toml", mode: "100644", type: "blob", sha: treeSha }, "manifest_lockfile_binding_unproven"],
  ])("retains attention discovery without narrowing coverage or reading contents (%s)", async (extra, code) => {
    const fetch = transport([heads(), tree([entry(), extra])]);
    await expect(sync(fetch).read("company", [repo])).rejects.toThrow("discovery_coverage_attention");
    expect(fetch).toHaveBeenCalledTimes(2);
    const retained = await snapshots();
    expect(retained).toHaveLength(1);
    const evidence = (await journal.readDiscovery("company", retained[0]!.snapshot_id))!;
    expect(discoveryCoverage(evidence).attention).toContainEqual({ code, path: extra.path });
    await expect(polls.current("company", configured)).rejects.toThrow();
    const row = (await postgres.query<{ bundle: { attempt: { state: string } } }>(`SELECT bundle FROM ${DATABASE_NAMESPACE}.source_polls`)).rows[0]!;
    expect(row.bundle.attempt.state).toBe("attention");
  });

  it("holds all repositories before any content read if any discovered coverage requires attention", async () => {
    const fetch = transport([{ data: { repo0: head(), repo1: head("example/other") } }, tree(), tree([])]);
    await expect(sync(fetch).read("company", [repo, "example/other"])).rejects.toThrow("discovery_coverage_attention");
    expect(fetch).toHaveBeenCalledTimes(3);
    expect((await snapshots()).map(row => row.source_kind)).toEqual(["discovery", "discovery"]);
    const states = await postgres.query<{ state: string }>(`SELECT bundle->'attempt'->>'state' AS state FROM ${DATABASE_NAMESPACE}.source_polls`);
    expect(states.rows.map(row => row.state)).toEqual(["attention", "attention"]);
  });

  it("rejects completion with missing, wrong-company, wrong-commit or unbound discovery evidence", async () => {
    const evidence = await discovery();
    const discoveryId = await journal.recordDiscovery("company", evidence);
    expect(await journal.recordDiscovery("company", evidence)).toBe(discoveryId);
    const poll = await polls.beginDiscovery("company", repo);
    const bound = await polls.bindDiscovery(poll, discoveryId);
    expect(await polls.bindDiscovery(poll, discoveryId)).toEqual(bound);
    const unboundId = await journal.recordLockfiles("company", sourceLockfiles());
    await expect(polls.complete(bound, unboundId)).rejects.toThrow("source_discovery_binding_mismatch");
    await expect(journal.recordLockfiles("other", sourceLockfiles(), discoveryId)).rejects.toThrow("source_discovery_binding_mismatch");
    await expect(journal.recordLockfiles("company", { ...sourceLockfiles(), sourceSha: nextCommit }, discoveryId)).rejects.toThrow("source_discovery_binding_mismatch");
    await expect(journal.recordLockfiles("company", { ...sourceLockfiles(), defaultBranch: "other" }, discoveryId)).rejects.toThrow("source_discovery_binding_mismatch");
    await expect(polls.bindDiscovery({ ...poll, companyId: "other" }, discoveryId)).rejects.toThrow("source_discovery_binding_mismatch");
    const id = await journal.recordLockfiles("company", sourceLockfiles(), discoveryId);
    await polls.complete(bound, id);
    await polls.assertCurrent(await polls.current("company", configured));
  });

  it("revalidates retained discovery on read and rejects missing or corrupted linked evidence", async () => {
    const [selected] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const id = selected!.stored.discoverySnapshotId!;
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET bundle = jsonb_set(bundle, '{defaultBranch}', '"other"') WHERE snapshot_id = $1`, [id]);
    await expect(polls.current("company", configured)).rejects.toThrow("stored_source_hash_mismatch");
    await postgres.query(`DELETE FROM ${DATABASE_NAMESPACE}.source_snapshots WHERE snapshot_id = $1`, [id]);
    await expect(polls.current("company", configured)).rejects.toThrow("source_discovery_binding_mismatch");
  });

  it("does not complete an unbound discovery reservation, including with empty files", async () => {
    const poll = await polls.beginDiscovery("company", repo);
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    await expect(polls.complete(poll, id)).rejects.toThrow("lockfile_path_capacity");
    await expect(polls.current("company", { repo, paths: [] })).rejects.toThrow("lockfile_path_capacity");
    await polls.fail(poll, "discovery_failed");
    await expect(polls.bindDiscovery(poll, await journal.recordDiscovery("company", await discovery()))).rejects.toThrow("source_poll_settled");
  });

  it("a slow older discovery cannot rebind or replace a newer successful poll", async () => {
    const entered = deferred<void>();
    const release = deferred<Response>();
    const slow = vi.fn<SourceFetch>(async () => { entered.resolve(); return release.promise; });
    const older = sync(slow).read("company", [repo]);
    const rejected = expect(older).rejects.toThrow("source_poll_superseded");
    await entered.promise;
    const [newer] = await sync(transport([heads(nextCommit), tree(), blob()])).read("company", [repo]);
    // Supply the older tree using another response from the same delayed transport.
    slow.mockImplementationOnce(async () => new Response(JSON.stringify(tree())));
    release.resolve(new Response(JSON.stringify(heads())));
    await rejected;
    expect((await polls.current("company", configured)).token).toBe(newer!.token);
    expect(await snapshots()).toHaveLength(3); // both raw discoveries retained; only new files selected
  });

  it("a late older failure cannot overwrite a newer ready source", async () => {
    const entered = deferred<void>();
    const release = deferred<Response>();
    const older = sync(async () => { entered.resolve(); return release.promise; }).read("company", [repo]);
    const rejected = expect(older).rejects.toThrow("github_heads_http_403");
    await entered.promise;
    const [newer] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    release.resolve(new Response(null, { status: 403 }));
    await rejected;
    expect((await polls.current("company", configured)).token).toBe(newer!.token);
  });

  it("a publication pin prevents a discovery poll before any network request", async () => {
    const [selected] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    await new SourceEffects(db).reserve(selected!, { executionId: "fixture", originId: "d".repeat(64), publicationRevision: 1, contentSha256: "e".repeat(64) });
    const fetch = transport([]);
    await expect(sync(fetch).read("company", [repo])).rejects.toThrow("source_effect_pending");
    expect(fetch).not.toHaveBeenCalled();
    await polls.assertCurrent(selected!);
  });

  it("uses discovery-bound exact-bundle SQL fences for decisions/routing and barrier reservation", async () => {
    const [selected] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const input = finding({ repo });
    input.provenance.artifactKind = "lockfile";
    input.provenance.artifactDigest = selected!.stored.lockfiles.artifactDigest;
    input.versionEvidence.artifactDigest = input.provenance.artifactDigest;
    const routing = new DeliveryRouting(db);
    expect((await routing.observeCurrent(selected!, input)).status).toBe("recorded");
    expect((await routing.snapshot("company", repo)).members).toHaveLength(1);
    const barrier = await new SourceEffects(db).reserve(selected!, { executionId: "fixture", originId: "d".repeat(64), publicationRevision: 1, contentSha256: "e".repeat(64) });
    expect(barrier.selection.snapshotId).toBe(selected!.snapshotId);
  });

  it("persists attention after a lost completion response, never serving the old ready source", async () => {
    await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const faulty = { ...db, execute: async (sql: string, params?: unknown[]) => {
      const result = await db.execute(sql, params);
      if (sql.startsWith("UPDATE") && sql.includes("SET bundle = $4") && String(params?.[3]).includes('"state":"ready"')) throw new Error("lost response");
      return result;
    } } as PluginDatabaseClient;
    await expect(sync(transport([heads()]), faulty).read("company", [repo])).rejects.toThrow("discovered_repository_sync_failed");
    await expect(polls.current("company", configured)).rejects.toThrow("current_source_attention");
  });

  it("rejects a wrong discovered blob even when ETag cache bytes are valid", async () => {
    await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const fetch = transport([heads(nextCommit), tree([{ ...entry(), sha: "f".repeat(40) }]), new Response(null, { status: 304 })]);
    await expect(sync(fetch).read("company", [repo])).rejects.toThrow("discovered_blob_mismatch");
    await expect(polls.current("company", configured)).rejects.toThrow("current_source_attention");
  });

  it("rejects discovered metadata/bytes mismatch at the durable journal boundary", async () => {
    const evidence = await discovery();
    evidence.entries[0]!.size = 1;
    const { sha256: ignored, ...bundle } = evidence;
    evidence.sha256 = sha256(canonicalJson(["repository-discovery-v1", bundle]));
    const id = await journal.recordDiscovery("company", evidence);
    await expect(journal.recordLockfiles("company", sourceLockfiles(), id)).rejects.toThrow("discovered_blob_mismatch");
  });

  it("binds each repository to its own discovery despite reversed input order", async () => {
    const fetch = transport([{ data: { repo0: head("example/other", nextCommit), repo1: head() } }, tree(), tree(), blob(), blob()]);
    const selected = await sync(fetch).read("company", ["example/other", repo]);
    expect(selected.map(value => [value.source.repo, value.stored.lockfiles.sourceSha])).toEqual([["example/other", nextCommit], [repo, commit]]);
    for (const value of selected) {
      expect((await journal.readDiscovery("company", value.stored.discoverySnapshotId!))!.repo).toBe(value.source.repo);
      await polls.assertCurrent(value);
    }
    expect(fetch).toHaveBeenCalledTimes(5);
  });

  it("recovers exact discovery binding after its CAS committed but the response was lost", async () => {
    const poll = await polls.beginDiscovery("company", repo);
    const id = await journal.recordDiscovery("company", await discovery());
    const faulty = { ...db, execute: async (sql: string, params?: unknown[]) => {
      await db.execute(sql, params);
      throw new Error("lost response");
    } } as PluginDatabaseClient;
    await expect(new SourcePollStore(faulty).bindDiscovery(poll, id)).rejects.toThrow("lost response");
    const bound = await polls.bindDiscovery(poll, id);
    const lockfileId = await journal.recordLockfiles("company", sourceLockfiles(), id);
    await polls.complete(bound, lockfileId);
    expect((await polls.current("company", configured)).stored.discoverySnapshotId).toBe(id);
  });

  it("retains a polling fence if a lost binding response prevents the orchestrator's attention write", async () => {
    const faulty = { ...db, execute: async (sql: string, params?: unknown[]) => {
      const result = await db.execute(sql, params);
      if (sql.startsWith("UPDATE") && String(params?.[3]).includes('"discoverySnapshotId"')) throw new Error("lost binding response");
      return result;
    } } as PluginDatabaseClient;
    const fetch = transport([heads(), tree()]);
    await expect(sync(fetch, faulty).read("company", [repo])).rejects.toThrow("discovered_repository_sync_failed");
    expect(fetch).toHaveBeenCalledTimes(2);
    await expect(polls.current("company", configured)).rejects.toThrow("current_source_pending");
  });

  it("never reads content when discovery persistence fails or its durable outcome is unknown", async () => {
    const faulty = { ...db, execute: async (sql: string, params?: unknown[]) => {
      const result = await db.execute(sql, params);
      if (sql.includes("source_snapshots") && params?.[2] === "discovery") throw new Error("lost journal response");
      return result;
    } } as PluginDatabaseClient;
    const fetch = transport([heads(), tree()]);
    await expect(sync(fetch, faulty).read("company", [repo])).rejects.toThrow("discovered_repository_sync_failed");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect((await snapshots()).map(row => row.source_kind)).toEqual(["discovery"]);
    await expect(polls.current("company", configured)).rejects.toThrow();
  });

  it("fails closed on malformed/truncated trees without making a content request or using old readiness", async () => {
    const [old] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const fetch = transport([heads(nextCommit), { ...tree(), truncated: true }]);
    await expect(sync(fetch).read("company", [repo])).rejects.toThrow("incomplete_repository_tree");
    expect(fetch).toHaveBeenCalledTimes(2);
    await expect(polls.assertCurrent(old!)).rejects.toThrow();
  });

  it("a discovered file-set change cannot reuse only the old configured paths", async () => {
    const [old] = await sync(transport([heads(), tree(), blob()])).read("company", [repo]);
    const fetch = transport([heads(nextCommit), tree([entry(), { ...entry(), path: "npm-shrinkwrap.json" }]),
      { ...blob(), path: "npm-shrinkwrap.json" }, new Response(null, { status: 304 })]);
    const [selected] = await sync(fetch).read("company", [repo]);
    expect(selected!.source.paths).toEqual(["npm-shrinkwrap.json", "package-lock.json"]);
    expect(selected!.stored.lockfiles.files).toHaveLength(2);
    expect(selected!.snapshotId).not.toBe(old!.snapshotId);
    await expect(polls.current("company", configured)).rejects.toThrow("source_configuration_changed");
  });

  it("validates repository batches before touching state and allows an empty batch", async () => {
    const fetch = transport([]);
    await expect(sync(fetch).read("company", [repo, "Example/Project"])).rejects.toThrow("duplicate_repository");
    await expect(sync(fetch).read("company", ["../bad"])).rejects.toThrow();
    expect(await sync(fetch).read("company", [])).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
    expect(await snapshots()).toEqual([]);
  });
});
