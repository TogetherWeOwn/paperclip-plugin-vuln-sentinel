import { createHash } from "node:crypto";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DATABASE_NAMESPACE, FINDING_ORIGIN_KIND } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { RepositoryHealth, type RepositoryHealthResult } from "./repository-health.js";
import { SourceAttention } from "./source-http.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore } from "./source-polls.js";
import { testDatabase } from "./test/database.js";
import { sourceLockfiles } from "./test/sources.js";

let postgres: Awaited<ReturnType<typeof testDatabase>>["postgres"];
let db: PluginDatabaseClient;
let clock: Date;
let polls: SourcePollStore;
const now = () => new Date(clock);
const source = { repo: "example/project", paths: ["package-lock.json"] };
const schema = `"${DATABASE_NAMESPACE}"`;
const company = "health-company";
const start = "2026-11-04T10:00:00.000Z";

beforeAll(async () => { ({ postgres, db } = await testDatabase()); });
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${schema}.source_polls, ${schema}.source_snapshots, ${schema}.delivery_routing, ${schema}.card_claims`);
  clock = new Date(start);
  polls = new SourcePollStore(db, now);
});
afterAll(async () => { await postgres.close(); });

async function ready(content?: string) {
  const snapshot = sourceLockfiles();
  if (content !== undefined) {
    const file = snapshot.files[0]!;
    file.content = content;
    file.sha256 = sha256(content);
    file.blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex");
    snapshot.artifactDigest = `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`;
  }
  const poll = await polls.begin(company, source);
  const id = await new SourceJournal(db, now).recordLockfiles(company, snapshot);
  await polls.complete(poll, id);
  return polls.current(company, source);
}

function held(result: RepositoryHealthResult) {
  expect(result.status).toBe("attention");
  expect(result.mode).toBe("library_only");
  expect(result.pilot).toEqual({ startedAt: null, successfulScans: null });
  expect(result.diagnostics.publication).toMatchObject({ enabled: false, admissibility: "not_admissible", supportedMethods: [] });
  expect(result.attention).toEqual(expect.arrayContaining(["health_library_only", "source_health_not_atomic",
    "repository_coverage_not_proven", "full_dependency_closure_not_proven", "runtime_completeness_not_proven",
    "advisory_feed_health_not_observed", "enabled_scan_counters_not_observed", "enabled_pilot_not_run"]));
}

function port(hook?: (sql: string) => Promise<void>) {
  const execute = vi.fn(db.execute);
  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    await hook?.(sql);
    return db.query(sql, params);
  }) as PluginDatabaseClient["query"];
  return { ...db, execute, query };
}

describe("disabled read-only repository health", () => {
  it("reports validated inventory counts, never enabled scan counters or completeness", async () => {
    const selected = await ready();
    clock = new Date(Date.parse(start) + 1000);
    const database = port();
    const result = await new RepositoryHealth(database, now).read(company, { ...source, repo: "Example/Project" });
    held(result);
    expect(result.repo).toBe(source.repo);
    expect(result.source).toEqual({ status: "observed", reason: null, summary: {
      pollRevision: selected.pollRevision, snapshotId: selected.snapshotId, startedAt: start, completedAt: start,
      ageMs: 1000, discoveryBound: false, inventory: {
        dependencies: 1, files: 1, parsedFiles: 1, attentionFiles: 0, issues: 0,
        coverage: { configuredPathsParsed: true, repositoryDiscovery: "not_proven", fullDependencyClosure: "not_proven", runtimeCompleteness: "not_proven" },
      },
    } });
    expect(database.execute).not.toHaveBeenCalled();
    expect(vi.mocked(database.query).mock.calls.every(([sql]) => sql.trimStart().startsWith("SELECT"))).toBe(true);
    const output = JSON.stringify(result);
    expect(output).not.toContain(selected.token);
    expect(output).not.toContain("node_modules");
    expect(output).not.toContain('"packages"');
  });

  it("does not invent zero successful scans from an empty valid inventory", async () => {
    await ready(JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }));
    const result = await new RepositoryHealth(db, now).read(company, source);
    held(result);
    expect(result.source.summary?.inventory).toMatchObject({ dependencies: 0, parsedFiles: 1 });
  });

  it("retains parse attention without exposing raw bytes or parser errors", async () => {
    await ready("private-invalid-content");
    const result = await new RepositoryHealth(db, now).read(company, source);
    held(result);
    expect(result.source.summary?.inventory).toMatchObject({ dependencies: 0, parsedFiles: 0, attentionFiles: 1, issues: 1 });
    expect(result.attention).toContain("inventory_parse_attention");
    expect(JSON.stringify(result)).not.toContain("private-invalid-content");
  });

  it("missing and cross-company selections never reuse another company's inventory", async () => {
    await ready();
    const result = await new RepositoryHealth(db, now).read("another-company", source);
    held(result);
    expect(result.source).toEqual({ status: "unavailable", reason: "missing_current_source", summary: null });
  });

  it.each(["polling", "discovering", "attention"])("preserves the hold for a %s attempt", async state => {
    await ready();
    const poll = state === "discovering" ? await polls.beginDiscovery(company, source.repo) : await polls.begin(company, source);
    if (state === "attention") await polls.fail(poll, "provider_private_failure");
    const result = await new RepositoryHealth(db, now).read(company, source);
    held(result);
    expect(result.source.summary).toBeNull();
    // A discovering attempt has no known paths, so cannot match configured ready paths.
    expect(result.source.reason).toBe(state === "discovering" ? "source_configuration_changed" : state === "attention" ? "current_source_attention" : "current_source_pending");
    expect(JSON.stringify(result)).not.toContain("provider_private_failure");
  });

  it.each([-1, 86_400_001])("withholds future/stale source age %s", async age => {
    await ready();
    clock = new Date(Date.parse(start) + age);
    const result = await new RepositoryHealth(db, now).read(company, source);
    held(result);
    expect(result.source).toEqual({ status: "unavailable", reason: "current_source_stale", summary: null });
  });

  it("holds a changed configured path set without replacing it", async () => {
    await ready();
    const result = await new RepositoryHealth(db, now).read(company, { ...source, paths: ["pnpm-lock.yaml"] });
    held(result);
    expect(result.source.reason).toBe("source_configuration_changed");
    expect(result.source.summary).toBeNull();
    expect((await polls.current(company, source)).source).toEqual(source);
  });

  it("discards an initially observed summary on supersession during diagnostics", async () => {
    await ready();
    let changed = false;
    const database = port(async sql => {
      if (!changed && sql.includes("delivery_routing")) { changed = true; await polls.begin(company, source); }
    });
    const result = await new RepositoryHealth(database, now).read(company, source);
    held(result);
    expect(result.source).toEqual({ status: "unavailable", reason: "current_source_pending", summary: null });
    expect(database.execute).not.toHaveBeenCalled();
  });

  it("does not mistake the same bytes selected by a new token for the original selection", async () => {
    const selected = await ready();
    let changed = false;
    const database = port(async sql => {
      if (!changed && sql.includes("delivery_routing")) {
        changed = true;
        const poll = await polls.begin(company, source);
        await polls.complete(poll, selected.snapshotId);
      }
    });
    const result = await new RepositoryHealth(database, now).read(company, source);
    held(result);
    expect(result.source.reason).toBe("source_poll_superseded");
    expect(result.source.summary).toBeNull();
  });

  it("withholds source evidence that expires while reading diagnostics", async () => {
    await ready();
    const database = port(async sql => { if (sql.includes("delivery_routing")) clock = new Date(Date.parse(start) + 86_400_001); });
    const result = await new RepositoryHealth(database, now).read(company, source);
    held(result);
    expect(result.source.reason).toBe("current_source_stale");
    expect(result.source.summary).toBeNull();
  });

  it("keeps both pins and claim uncertainty intact across repeated/concurrent reads", async () => {
    const selected = await ready();
    const id = "1".repeat(64);
    await db.execute(`UPDATE ${schema}.source_polls SET effect_barrier = $2 WHERE company_id = $1`, [company, JSON.stringify({ private: "source-token" })]);
    await db.execute(`INSERT INTO ${schema}.delivery_routing (company_id, repo, bundle, effect_token) VALUES ($1, $2, $3, 'private-routing-token')`,
      [company, source.repo, JSON.stringify({ version: 1, containers: [{ originId: id, originKind: FINDING_ORIGIN_KIND }] })]);
    await db.execute(`INSERT INTO ${schema}.card_claims (company_id, origin_id, origin_kind, state, claim_token, claimed_at)
      VALUES ($1, $2, $3, 'indeterminate', 'private-claim-token', $4)`, [company, id, FINDING_ORIGIN_KIND, start]);
    const before = await db.query(`SELECT * FROM ${schema}.source_polls WHERE company_id = $1`, [company]);
    const database = port();
    const health = new RepositoryHealth(database, now);
    const results = await Promise.all([health.read(company, source), health.read(company, source)]);
    expect(results[0]).toEqual(results[1]);
    for (const result of results) {
      held(result);
      expect(result.diagnostics.source.pinned).toBe(true);
      expect(result.diagnostics.routing.pinned).toBe(true);
      expect(result.diagnostics.claims.counts?.indeterminate).toBe(1);
      expect(result.attention).toContain("mapped_claim_uncertainty");
      expect(JSON.stringify(result)).not.toMatch(/private-|source-token/u);
      expect(JSON.stringify(result)).not.toContain(selected.token);
    }
    expect(database.execute).not.toHaveBeenCalled();
    expect(await db.query(`SELECT * FROM ${schema}.source_polls WHERE company_id = $1`, [company])).toEqual(before);
    expect((await db.query<{ effect_token: string }>(`SELECT effect_token FROM ${schema}.delivery_routing WHERE company_id = $1`, [company]))[0]?.effect_token).toBe("private-routing-token");
    expect((await db.query<{ state: string }>(`SELECT state FROM ${schema}.card_claims WHERE company_id = $1`, [company]))[0]?.state).toBe("indeterminate");
  });

  it.each([new Error("secret-provider-error"), new SourceAttention("secret_provider_error")])("sanitizes database failures, including arbitrary typed attention", async error => {
    const database = port();
    database.query = vi.fn(async () => { throw error; });
    const result = await new RepositoryHealth(database, now).read(company, source);
    held(result);
    expect(result.source.reason).toBe("source_health_unavailable");
    expect(result.source.summary).toBeNull();
    expect(JSON.stringify(result)).not.toMatch(/secret[-_]provider/u);
    expect(database.execute).not.toHaveBeenCalled();
  });

  it("withholds corrupt retained evidence instead of returning cached counts", async () => {
    const selected = await ready();
    await db.execute(`UPDATE ${schema}.source_snapshots SET bundle = '{}'::jsonb WHERE company_id = $1 AND snapshot_id = $2`, [company, selected.snapshotId]);
    const result = await new RepositoryHealth(db, now).read(company, source);
    held(result);
    expect(result.source).toEqual({ status: "unavailable", reason: "source_health_unavailable", summary: null });
  });

  it("preserves independent diagnostic failures without certifying overall health", async () => {
    await ready();
    const database = port(async sql => { if (sql.includes("delivery_routing")) throw new Error("private-failure"); });
    const result = await new RepositoryHealth(database, now).read(company, source);
    held(result);
    expect(result.source.status).toBe("observed");
    expect(result.diagnostics.routing.status).toBe("unavailable");
    expect(result.attention).toContain("routing_diagnostics_unavailable");
  });

  it("retains discovery binding without upgrading repository or runtime completeness", async () => {
    const snapshot = sourceLockfiles();
    const file = snapshot.files[0]!;
    const bundle = { version: 1 as const, repo: source.repo, sourceSha: snapshot.sourceSha,
      treeSha: "b".repeat(40), defaultBranch: "main", entries: [{ path: file.path, mode: "100644" as const,
        type: "blob" as const, sha: file.blobSha, size: Buffer.byteLength(file.content) }] };
    const journal = new SourceJournal(db, now);
    const discovery = await journal.recordDiscovery(company, { ...bundle,
      sha256: sha256(canonicalJson(["repository-discovery-v1", bundle])) });
    const poll = await polls.bindDiscovery(await polls.beginDiscovery(company, source.repo), discovery);
    const id = await journal.recordLockfiles(company, snapshot, discovery);
    await polls.complete(poll, id);
    const result = await new RepositoryHealth(db, now).read(company, source);
    held(result);
    expect(result.source.summary?.discoveryBound).toBe(true);
    expect(result.source.summary?.inventory.coverage.repositoryDiscovery).toBe("not_proven");
  });

  it("discards source counts when final validation loses storage access", async () => {
    await ready();
    let validating = false;
    const database = port(async sql => {
      if (sql.includes("delivery_routing")) validating = true;
      if (validating && sql.includes("source_snapshots")) throw new Error("private-storage-error");
    });
    const result = await new RepositoryHealth(database, now).read(company, source);
    held(result);
    expect(result.source).toEqual({ status: "unavailable", reason: "source_health_unavailable", summary: null });
    expect(JSON.stringify(result)).not.toContain("private-storage-error");
  });

  it("does not return a completed report when the invocation clock regresses", async () => {
    await ready();
    const database = port(async sql => { if (sql.includes("delivery_routing")) clock = new Date(Date.parse(start) - 1); });
    await expect(new RepositoryHealth(database, now).read(company, source)).rejects.toThrow("repository_health_clock_regressed");
  });

  it("rejects invalid configuration before querying storage", async () => {
    const database = port();
    const health = new RepositoryHealth(database, now);
    await expect(health.read("", source)).rejects.toThrow("invalid_company");
    await expect(health.read(company, { repo: "bad", paths: source.paths })).rejects.toThrow();
    await expect(health.read(company, { ...source, paths: [] })).rejects.toThrow();
    expect(database.query).not.toHaveBeenCalled();
    expect(database.execute).not.toHaveBeenCalled();
  });
});
