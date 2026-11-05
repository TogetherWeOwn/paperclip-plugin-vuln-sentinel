import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { GitHubLockfiles, type RepositorySource } from "./github-lockfiles.js";
import { canonicalJson, sha256 } from "./identity.js";
import { SourceJournal } from "./source-journal.js";
import { RepositorySourceSync, SourcePollStore } from "./source-polls.js";
import type { SourceFetch } from "./source-http.js";
import { testDatabase } from "./test/database.js";
import { sourceLockfiles } from "./test/sources.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let polls: SourcePollStore;
let journal: SourceJournal;
let clock: Date;
const start = "2026-11-04T05:30:00Z";
const now = () => new Date(clock);
const source: RepositorySource = { repo: "example/project", paths: ["package-lock.json"] };
const nextSha = "b".repeat(40);
const json = (value: unknown, etag?: string) => new Response(JSON.stringify(value), { headers: etag ? { etag } : {} });
const head = (sha = "a".repeat(40), repo = source.repo) => ({ nameWithOwner: repo, defaultBranchRef: { name: "main", target: { oid: sha } } });
const heads = (sha?: string) => ({ data: { repo0: head(sha) } });
const blob = () => {
  const file = sourceLockfiles().files[0]!;
  return { type: "file", path: file.path, sha: file.blobSha, encoding: "base64", size: Buffer.byteLength(file.content), content: Buffer.from(file.content).toString("base64") };
};
function transport(responses: Array<unknown | Response>) {
  return vi.fn<SourceFetch>(async () => {
    if (!responses.length) throw new Error("Unexpected request");
    const value = responses.shift();
    return value instanceof Response ? value : json(value);
  });
}
function sync(fetch: SourceFetch, database = db) {
  return new RepositorySourceSync(new SourcePollStore(database, now), new SourceJournal(database, now), new GitHubLockfiles(fetch, "fixture-token"));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
async function ready() {
  const poll = await polls.begin("company", source);
  const id = await journal.recordLockfiles("company", sourceLockfiles());
  await polls.complete(poll, id);
  return polls.current("company", source);
}

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.source_polls, ${DATABASE_NAMESPACE}.source_snapshots`);
  clock = new Date(start);
  polls = new SourcePollStore(db, now);
  journal = new SourceJournal(db, now);
});
afterAll(async () => { await postgres.close(); });

describe("durable current-source fences", () => {
  it("selects retained raw bytes only after completion and isolates companies", async () => {
    await expect(polls.current("company", source)).rejects.toThrow("missing_current_source");
    const poll = await polls.begin("company", source);
    expect(await polls.cached(poll)).toBeNull();
    await expect(polls.current("company", source)).rejects.toThrow("current_source_pending");
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    await polls.complete(poll, id);
    const selected = await polls.current("company", source);
    expect(selected).toMatchObject({ ...poll, snapshotId: id, stored: { lockfiles: sourceLockfiles() } });
    expect(selected.stored.inventory.coverage.runtimeCompleteness).toBe("not_proven");
    await polls.assertCurrent(selected);
    await expect(polls.current("other", source)).rejects.toThrow("missing_current_source");
    await expect(polls.complete({ ...poll, companyId: "other" }, id)).rejects.toThrow("source_poll_snapshot_mismatch");
    await expect(polls.cached({ ...poll, companyId: "other" })).rejects.toThrow("source_poll_superseded");
  });

  it("a new attempt fences the prior ready selection but retains only cache material", async () => {
    const selected = await ready();
    const poll = await polls.begin("company", source);
    expect(await polls.cached(poll)).toEqual(selected.stored.lockfiles);
    await expect(polls.assertCurrent(selected)).rejects.toThrow("current_source_pending");
    await polls.fail(poll, "github_heads_http_403");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
    expect(await polls.cached(poll)).toEqual(selected.stored.lockfiles);
    await expect(polls.complete(poll, selected.snapshotId)).rejects.toThrow("source_poll_settled");
  });

  it("late success and late failure cannot replace a newer successful poll", async () => {
    const older = await polls.begin("company", source);
    const newer = await polls.begin("company", source);
    const oldId = await journal.recordLockfiles("company", sourceLockfiles());
    const newId = await journal.recordLockfiles("company", { ...sourceLockfiles(), sourceSha: nextSha });
    await polls.complete(newer, newId);
    await expect(polls.complete(older, oldId)).rejects.toThrow("source_poll_superseded");
    await expect(polls.fail(older, "transport_failed")).rejects.toThrow("source_poll_superseded");
    expect((await polls.current("company", source)).snapshotId).toBe(newId);
    expect((await journal.readLockfiles("company", oldId))!.lockfiles.sourceSha).toBe("a".repeat(40));
  });

  it("an older successful poll cannot undo a newer failed or pending poll", async () => {
    const older = await polls.begin("company", source);
    const newer = await polls.begin("company", source);
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    await expect(polls.complete(older, id)).rejects.toThrow("source_poll_superseded");
    await polls.fail(newer, "github_lockfile_http_404");
    await expect(polls.complete(older, id)).rejects.toThrow("source_poll_superseded");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
  });

  it("uses DB attempt ordering, not timestamp ties or commit ordering, including force-reset heads", async () => {
    await ready();
    const newer = await polls.begin("company", source);
    const newId = await journal.recordLockfiles("company", { ...sourceLockfiles(), sourceSha: "0".repeat(40) });
    await polls.complete(newer, newId);
    expect((await polls.current("company", source)).stored.lockfiles.sourceSha).toBe("0".repeat(40));
  });

  it("concurrent reservations have one eligible last-started token", async () => {
    const attempts = await Promise.all(Array.from({ length: 12 }, () => polls.begin("company", source)));
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const results = await Promise.allSettled(attempts.map(poll => polls.complete(poll, id)));
    expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
    expect(new Set(attempts.map(poll => poll.token)).size).toBe(12);
    expect((await polls.current("company", source)).snapshotId).toBe(id);
  });

  it("replays a committed completion after a lost response without changing its revision", async () => {
    const poll = await polls.begin("company", source);
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    const faulty = new SourcePollStore({ ...db, execute: async (sql, params) => {
      await db.execute(sql, params);
      throw new Error("lost response");
    } }, now);
    await expect(faulty.complete(poll, id)).rejects.toThrow("lost response");
    const before = await postgres.query(`SELECT revision FROM ${DATABASE_NAMESPACE}.source_polls`);
    await polls.complete(poll, id);
    expect(await postgres.query(`SELECT revision FROM ${DATABASE_NAMESPACE}.source_polls`)).toEqual(before);
    await polls.fail(poll, "repository_sync_failed");
    await polls.fail(poll, "repository_sync_failed");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
  });

  it("rejects changed or wrong repository/path configuration, but canonicalizes ordering and case", async () => {
    const selected = await ready();
    expect((await polls.current("company", { ...source, repo: "Example/Project", paths: [...source.paths, ...source.paths] })).snapshotId).toBe(selected.snapshotId);
    await expect(polls.current("company", { ...source, paths: ["Cargo.lock"] })).rejects.toThrow("source_configuration_changed");
    const changed = await polls.begin("company", { ...source, paths: ["Cargo.lock"] });
    await expect(polls.complete(changed, selected.snapshotId)).rejects.toThrow("source_poll_snapshot_mismatch");
    await expect(polls.current("company", source)).rejects.toThrow("source_configuration_changed");
    const other = await polls.begin("company", { ...source, repo: "example/other" });
    await expect(polls.complete(other, selected.snapshotId)).rejects.toThrow("source_poll_snapshot_mismatch");
  });

  it("retains configured-parser attention without claiming successful discovery or completeness", async () => {
    const configured = { ...source, paths: ["unknown.lock"] };
    const poll = await polls.begin("company", configured);
    const lockfiles = sourceLockfiles();
    lockfiles.files[0]!.path = "unknown.lock";
    lockfiles.artifactDigest = `sha256:${sha256(canonicalJson([["unknown.lock", lockfiles.files[0]!.sha256]]))}`;
    const id = await journal.recordLockfiles("company", lockfiles);
    await polls.complete(poll, id);
    const selected = await polls.current("company", configured);
    expect(selected.stored.inventory.coverage).toMatchObject({ configuredPathsParsed: false, repositoryDiscovery: "not_proven", fullDependencyClosure: "not_proven" });
    expect(selected.stored.inventory.files[0]!.issues).toContain("unsupported_lockfile_format");
  });

  it.each([0, -1, Infinity, 1.5, 86_400_001])("rejects invalid freshness bounds %s", async maxAge => {
    await expect(polls.current("company", source, maxAge)).rejects.toThrow("invalid_source_max_age");
  });

  it("ages from the poll start, not cache content or delayed completion time", async () => {
    const poll = await polls.begin("company", source);
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    clock = new Date(Date.parse(start) + 60_000);
    await polls.complete(poll, id);
    await expect(polls.current("company", source, 30_000)).rejects.toThrow("current_source_stale");
    const selected = await polls.current("company", source);
    clock = new Date(Date.parse(start) + 86_400_001);
    await expect(polls.assertCurrent(selected)).rejects.toThrow("current_source_stale");
    clock = new Date(Date.parse(start) + 30_000);
    await expect(polls.current("company", source)).rejects.toThrow("current_source_stale");
  });

  it("holds clock regression on completion and future poll starts on selection", async () => {
    const poll = await polls.begin("company", source);
    const id = await journal.recordLockfiles("company", sourceLockfiles());
    clock = new Date(Date.parse(start) - 1000);
    await expect(polls.complete(poll, id)).rejects.toThrow("source_poll_clock_regressed");
    await polls.fail(poll, "clock_failed");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
  });

  it("detects supersession during source readback", async () => {
    await ready();
    let raced = false;
    const racing = new SourcePollStore({ ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const result = await db.query<T>(sql, params);
      if (!raced && sql.includes("source_snapshots")) {
        raced = true;
        await polls.begin("company", source);
      }
      return result;
    } }, now);
    await expect(racing.current("company", source)).rejects.toThrow("source_poll_superseded");
  });

  it("rechecks freshness after raw evidence readback", async () => {
    await ready();
    const ticking = new SourcePollStore({ ...db, query: async <T>(sql: string, params?: unknown[]) => {
      const result = await db.query<T>(sql, params);
      if (sql.includes("source_snapshots")) clock = new Date(Date.parse(start) + 86_400_001);
      return result;
    } }, now);
    await expect(ticking.current("company", source)).rejects.toThrow("current_source_stale");
  });

  it("rejects a different completion ID for an already settled token", async () => {
    const selected = await ready();
    const other = await journal.recordLockfiles("company", { ...sourceLockfiles(), sourceSha: nextSha });
    await expect(polls.complete(selected, other)).rejects.toThrow("source_poll_settled");
    expect((await polls.current("company", source)).snapshotId).toBe(selected.snapshotId);
  });

  it("holds a missing retained snapshot without recreating or selecting old bytes", async () => {
    const selected = await ready();
    await postgres.query(`DELETE FROM ${DATABASE_NAMESPACE}.source_snapshots WHERE snapshot_id = $1`, [selected.snapshotId]);
    await expect(polls.current("company", source)).rejects.toThrow("source_poll_snapshot_mismatch");
    await expect(polls.cached(await polls.begin("company", source))).rejects.toThrow("source_cache_binding_mismatch");
  });

  it("rejects an older selection even when a newer poll selects the same immutable snapshot", async () => {
    const selected = await ready();
    const next = await polls.begin("company", source);
    await polls.complete(next, selected.snapshotId);
    await expect(polls.assertCurrent(selected)).rejects.toThrow("source_poll_superseded");
    expect((await polls.current("company", source)).snapshotId).toBe(selected.snapshotId);
  });

  it("fails closed on missing/corrupt source bytes instead of a cache hit", async () => {
    const selected = await ready();
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_snapshots SET bundle = '{}' WHERE snapshot_id = $1`, [selected.snapshotId]);
    await expect(polls.current("company", source)).rejects.toThrow("stored_source_hash_mismatch");
    await expect(polls.cached(await polls.begin("company", source))).rejects.toThrow("stored_source_hash_mismatch");
  });

  it.each([
    { version: 2, cacheSnapshotId: null, attempt: null },
    { version: 1, cacheSnapshotId: "bad", attempt: null },
    { version: 1, cacheSnapshotId: null, attempt: { state: "ready" } },
  ])("holds malformed stored pointer state %#", async bundle => {
    await polls.begin("company", source);
    await postgres.query(`UPDATE ${DATABASE_NAMESPACE}.source_polls SET bundle = $1`, [canonicalJson(bundle)]);
    await expect(polls.current("company", source)).rejects.toThrow("invalid_source_poll");
  });

  it("bounds CAS contention and rejects invalid namespaces and unsafe config", async () => {
    const contended = new SourcePollStore({ ...db, execute: async (sql, params) => sql.startsWith("UPDATE") ? { rowCount: 0 } : db.execute(sql, params) }, now);
    await expect(contended.begin("company", source)).rejects.toThrow("source_poll_contention");
    expect(() => new SourcePollStore({ ...db, namespace: "other" })).toThrow("namespace");
    await expect(polls.begin("company", { ...source, paths: ["../secret"] })).rejects.toThrow("invalid_lockfile_path");
    await expect(polls.fail(await polls.begin("company", source), "provider message with secret")).rejects.toThrow("invalid_source_attention_code");
  });
});

describe("explicit repository source synchronization", () => {
  it("uses one heads call per poll, retains raw evidence and reuses unchanged cached bytes", async () => {
    const fetch = transport([heads(), json(blob(), '"etag"'), heads(), heads(nextSha), new Response(null, { status: 304 })]);
    const reader = sync(fetch);
    const first = (await reader.read("company", [source]))[0]!;
    const second = (await reader.read("company", [source]))[0]!;
    expect(second.snapshotId).toBe(first.snapshotId);
    expect(second.token).not.toBe(first.token);
    const third = (await reader.read("company", [source]))[0]!;
    expect(third.stored.lockfiles.sourceSha).toBe(nextSha);
    expect(third.stored.lockfiles.artifactDigest).toBe(first.stored.lockfiles.artifactDigest);
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(fetch.mock.calls.filter(([url]) => url.endsWith("/graphql"))).toHaveLength(3);
    expect(fetch.mock.calls[4]![1].headers).toMatchObject({ "If-None-Match": '"etag"' });
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_snapshots`)).rows).toHaveLength(2);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.decision_records`)).rows).toEqual([]);
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.card_claims`)).rows).toEqual([]);
  });

  it.each([403, 404, 429, 500])("a failed HTTP %s poll cannot select the old source", async status => {
    await sync(transport([heads(), blob()])).read("company", [source]);
    await expect(sync(transport([heads(nextSha), new Response(null, { status })])).read("company", [source])).rejects.toThrow(`github_lockfile_http_${status}`);
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
    // The next poll may reuse verified cache bytes, but must obtain fresh heads first.
    const fetch = transport([heads()]);
    await sync(fetch).read("company", [source]);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("holds all configured repositories on partial GraphQL data without fetching content", async () => {
    const other = { ...source, repo: "example/other" };
    const fetch = transport([{ data: { repo0: head(), repo1: null } }]);
    await expect(sync(fetch).read("company", [source, other])).rejects.toThrow("missing_repository_head");
    expect(fetch).toHaveBeenCalledTimes(1);
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
    await expect(polls.current("company", other)).rejects.toThrow("current_source_attention");
  });

  it.each(["success", "failure"])("a late older HTTP %s cannot replace a newer source selection", async mode => {
    const entered = deferred<void>();
    const resume = deferred<Response>();
    const oldFetch = vi.fn<SourceFetch>(async url => {
      if (url.endsWith("/graphql")) return json(heads());
      entered.resolve();
      return resume.promise;
    });
    const older = sync(oldFetch).read("company", [source]).then(() => new Error("unexpected success"), error => error as Error);
    await entered.promise;
    const selected = (await sync(transport([heads(nextSha), blob()])).read("company", [source]))[0]!;
    resume.resolve(mode === "success" ? json(blob()) : new Response(null, { status: 500 }));
    expect((await older).message).toContain(mode === "success" ? "source_poll_superseded" : "github_lockfile_http_500");
    expect((await polls.current("company", source)).token).toBe(selected.token);
    expect((await polls.current("company", source)).stored.lockfiles.sourceSha).toBe(nextSha);
  });

  it("a late older success cannot hide a newer failed poll", async () => {
    const entered = deferred<void>();
    const resume = deferred<Response>();
    const older = sync(async url => {
      if (url.endsWith("/graphql")) return json(heads());
      entered.resolve();
      return resume.promise;
    }).read("company", [source]).then(() => new Error("unexpected success"), error => error as Error);
    await entered.promise;
    await expect(sync(transport([new Response(null, { status: 403 })])).read("company", [source])).rejects.toThrow("github_heads_http_403");
    resume.resolve(json(blob()));
    expect((await older).message).toContain("source_poll_superseded");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
  });

  it("never returns source selections on raw evidence persistence failure or leaks database errors", async () => {
    await ready();
    const database = { ...db, execute: async (sql: string, params?: unknown[]) => {
      if (sql.includes("source_snapshots")) throw new Error("sensitive storage details");
      return db.execute(sql, params);
    } };
    await expect(sync(transport([heads()]), database).read("company", [source])).rejects.toThrow("repository_sync_failed");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
  });

  it("an ambiguous ready write is held and the next fresh poll safely recovers", async () => {
    const database = { ...db, execute: async (sql: string, params?: unknown[]) => {
      const result = await db.execute(sql, params);
      if (sql.includes("source_polls") && sql.startsWith("UPDATE") && JSON.parse(params![3] as string).attempt.state === "ready") throw new Error("lost response");
      return result;
    } };
    await expect(sync(transport([heads(), blob()]), database).read("company", [source])).rejects.toThrow("repository_sync_failed");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_attention");
    expect((await sync(transport([heads()])).read("company", [source]))[0]!.stored.lockfiles.sourceSha).toBe("a".repeat(40));
  });

  it("a failed attention write leaves the durable pending fence rather than stale readiness", async () => {
    await ready();
    const database = { ...db, execute: async (sql: string, params?: unknown[]) => {
      if (sql.includes("source_polls") && sql.startsWith("UPDATE") && JSON.parse(params![3] as string).attempt.state === "attention") throw new Error("write unavailable");
      return db.execute(sql, params);
    } };
    await expect(sync(transport([new Response(null, { status: 500 })]), database).read("company", [source])).rejects.toThrow("github_heads_http_500");
    await expect(polls.current("company", source)).rejects.toThrow("current_source_pending");
  });

  it("does no HTTP or DB work for an empty configuration, and rejects invalid config before reservations", async () => {
    const fetch = transport([]);
    expect(await sync(fetch).read("company", [])).toEqual([]);
    await expect(sync(fetch).read("company", [source, { ...source, repo: "Example/Project" }])).rejects.toThrow("duplicate_repository");
    expect(fetch).not.toHaveBeenCalled();
    expect((await postgres.query(`SELECT * FROM ${DATABASE_NAMESPACE}.source_polls`)).rows).toEqual([]);
  });
});
