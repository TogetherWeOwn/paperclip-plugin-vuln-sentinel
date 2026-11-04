import { randomUUID } from "node:crypto";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "./claims.js";
import { GitHubLockfiles, normalizeRepositorySources, type RepositorySource, type RepositoryLockfiles } from "./github-lockfiles.js";
import { canonicalJson } from "./identity.js";
import { SourceJournal, type StoredLockfiles } from "./source-journal.js";
import { SourceAttention, text, timestamp } from "./source-http.js";

const DAY = 86_400_000;
const ID = /^[a-f0-9]{64}$/u;
const TOKEN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const CODE = /^[a-z0-9_]{1,96}$/u;

export interface SourcePoll {
  companyId: string;
  source: RepositorySource;
  token: string;
}

export interface CurrentSource extends SourcePoll {
  snapshotId: string;
  startedAt: string;
  completedAt: string;
  stored: StoredLockfiles;
}

interface Attempt {
  token: string;
  source: RepositorySource;
  state: "polling" | "ready" | "attention";
  startedAt: string;
  completedAt: string | null;
  snapshotId: string | null;
  attentionCode: string | null;
}
interface PollState {
  version: 1;
  cacheSnapshotId: string | null;
  attempt: Attempt | null;
}
interface Row { revision: number; bundle: PollState }
const empty = (): PollState => ({ version: 1, cacheSnapshotId: null, attempt: null });
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const source = (value: RepositorySource) => normalizeRepositorySources([value])[0]!;

/** DB ordering, not commit lexicography or caller timestamps, selects the last-started poll. */
export class SourcePollStore {
  private readonly table: string;
  private readonly journal: SourceJournal;
  constructor(private readonly db: PluginDatabaseClient, private readonly now = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Source poll namespace does not match the packaged migration");
    this.table = `"${db.namespace}".source_polls`;
    this.journal = new SourceJournal(db, now);
  }

  private async read(companyId: string, repo: string): Promise<Row | null> {
    text(companyId, "invalid_company", 256);
    const rows = await this.db.query<Row>(
      `SELECT revision, bundle FROM ${this.table} WHERE company_id = $1 AND repo = $2`, [companyId, repo],
    );
    const row = rows[0];
    if (!row) return null;
    const state = row.bundle;
    if (!Number.isSafeInteger(row.revision) || row.revision < 0 || !state || state.version !== 1
      || (state.cacheSnapshotId !== null && !ID.test(state.cacheSnapshotId))) throw new SourceAttention("invalid_source_poll");
    if (state.attempt !== null) {
      const attempt = state.attempt;
      if (!attempt || !TOKEN.test(attempt.token) || !same(source(attempt.source), attempt.source)
        || attempt.source.repo !== repo || !["polling", "ready", "attention"].includes(attempt.state)) {
        throw new SourceAttention("invalid_source_poll");
      }
      timestamp(attempt.startedAt, "invalid_source_poll_time");
      if (attempt.state === "polling") {
        if (attempt.completedAt !== null || attempt.snapshotId !== null || attempt.attentionCode !== null) {
          throw new SourceAttention("invalid_source_poll");
        }
      } else {
        timestamp(attempt.completedAt, "invalid_source_poll_time");
        if (Date.parse(attempt.completedAt!) < Date.parse(attempt.startedAt)
          || (attempt.state === "ready" && (!ID.test(attempt.snapshotId!) || state.cacheSnapshotId !== attempt.snapshotId || attempt.attentionCode !== null))
          || (attempt.state === "attention" && (attempt.snapshotId !== null || typeof attempt.attentionCode !== "string" || !CODE.test(attempt.attentionCode)))) {
          throw new SourceAttention("invalid_source_poll");
        }
      }
    }
    return row;
  }

  private async change(companyId: string, repo: string, row: Row, bundle: PollState): Promise<boolean> {
    const result = await this.db.execute(
      `UPDATE ${this.table} SET bundle = $4, revision = revision + 1
       WHERE company_id = $1 AND repo = $2 AND revision = $3`,
      [companyId, repo, row.revision, canonicalJson(bundle)],
    );
    return result.rowCount === 1;
  }

  async begin(companyId: string, configured: RepositorySource): Promise<SourcePoll> {
    const normalized = source(configured);
    text(companyId, "invalid_company", 256);
    await this.db.execute(
      `INSERT INTO ${this.table} (company_id, repo, bundle) VALUES ($1, $2, $3)
       ON CONFLICT (company_id, repo) DO NOTHING`, [companyId, normalized.repo, canonicalJson(empty())],
    );
    const token = randomUUID();
    for (let retry = 0; retry < 32; retry++) {
      const row = await this.read(companyId, normalized.repo);
      if (!row) throw new SourceAttention("missing_source_poll");
      const bundle: PollState = { ...row.bundle, attempt: {
        token, source: normalized, state: "polling", startedAt: this.now().toISOString(),
        completedAt: null, snapshotId: null, attentionCode: null,
      } };
      if (await this.change(companyId, normalized.repo, row, bundle)) return { companyId, source: normalized, token };
    }
    throw new SourceAttention("source_poll_contention");
  }

  private bound(row: Row | null, poll: SourcePoll): Attempt {
    const attempt = row?.bundle.attempt;
    if (!attempt || attempt.token !== poll.token || !same(attempt.source, source(poll.source))) {
      throw new SourceAttention("source_poll_superseded");
    }
    return attempt;
  }

  async cached(poll: SourcePoll): Promise<RepositoryLockfiles | null> {
    const row = await this.read(poll.companyId, source(poll.source).repo);
    this.bound(row, poll);
    const id = row!.bundle.cacheSnapshotId;
    if (!id) return null;
    const stored = await this.journal.readLockfiles(poll.companyId, id);
    if (!stored || stored.lockfiles.repo !== poll.source.repo) throw new SourceAttention("source_cache_binding_mismatch");
    // This is only immutable HTTP cache material, never a selected current artifact.
    return stored.lockfiles;
  }

  async complete(poll: SourcePoll, snapshotId: string): Promise<void> {
    const stored = await this.journal.readLockfiles(poll.companyId, snapshotId);
    const normalized = source(poll.source);
    if (!stored || stored.lockfiles.repo !== normalized.repo
      || !same(stored.lockfiles.files.map(file => file.path).sort(), normalized.paths)) {
      throw new SourceAttention("source_poll_snapshot_mismatch");
    }
    for (let retry = 0; retry < 32; retry++) {
      const row = await this.read(poll.companyId, normalized.repo);
      const attempt = this.bound(row, poll);
      if (attempt.state === "ready" && attempt.snapshotId === snapshotId) return;
      if (attempt.state !== "polling") throw new SourceAttention("source_poll_settled");
      const completedAt = this.now().toISOString();
      if (Date.parse(completedAt) < Date.parse(attempt.startedAt)) throw new SourceAttention("source_poll_clock_regressed");
      if (await this.change(poll.companyId, normalized.repo, row!, {
        version: 1, cacheSnapshotId: snapshotId, attempt: { ...attempt, state: "ready", snapshotId, completedAt },
      })) return;
    }
    throw new SourceAttention("source_poll_contention");
  }

  async fail(poll: SourcePoll, attentionCode: string): Promise<void> {
    if (typeof attentionCode !== "string" || !CODE.test(attentionCode)) throw new SourceAttention("invalid_source_attention_code");
    for (let retry = 0; retry < 32; retry++) {
      const row = await this.read(poll.companyId, source(poll.source).repo);
      const attempt = this.bound(row, poll);
      if (attempt.state === "attention" && attempt.attentionCode === attentionCode) return;
      // A batch may fail after a ready write committed but its response was lost. Hold it too.
      const completedAt = new Date(Math.max(this.now().getTime(), Date.parse(attempt.startedAt))).toISOString();
      if (await this.change(poll.companyId, poll.source.repo, row!, { ...row!.bundle,
        attempt: { ...attempt, state: "attention", snapshotId: null, attentionCode, completedAt },
      })) return;
    }
    throw new SourceAttention("source_poll_contention");
  }

  private fresh(attempt: Attempt, maxAgeMs: number): void {
    const now = this.now().getTime();
    const age = now - Date.parse(attempt.startedAt);
    if (!Number.isFinite(now) || age < 0 || age > maxAgeMs || Date.parse(attempt.completedAt!) > now) {
      throw new SourceAttention("current_source_stale");
    }
  }

  async current(companyId: string, configured: RepositorySource, maxAgeMs = DAY): Promise<CurrentSource> {
    if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs <= 0 || maxAgeMs > DAY) throw new SourceAttention("invalid_source_max_age");
    const normalized = source(configured);
    const row = await this.read(companyId, normalized.repo);
    const attempt = row?.bundle.attempt;
    if (!attempt) throw new SourceAttention("missing_current_source");
    if (!same(attempt.source, normalized)) throw new SourceAttention("source_configuration_changed");
    if (attempt.state !== "ready") throw new SourceAttention(attempt.state === "attention" ? "current_source_attention" : "current_source_pending");
    this.fresh(attempt, maxAgeMs);
    const stored = await this.journal.readLockfiles(companyId, attempt.snapshotId!);
    if (!stored || stored.lockfiles.repo !== normalized.repo
      || !same(stored.lockfiles.files.map(file => file.path).sort(), normalized.paths)) throw new SourceAttention("source_poll_snapshot_mismatch");
    if ((await this.read(companyId, normalized.repo))?.revision !== row!.revision) throw new SourceAttention("source_poll_superseded");
    this.fresh(attempt, maxAgeMs);
    return { companyId, source: normalized, token: attempt.token, snapshotId: attempt.snapshotId!,
      startedAt: attempt.startedAt, completedAt: attempt.completedAt!, stored };
  }

  async assertCurrent(selected: CurrentSource, maxAgeMs = DAY): Promise<void> {
    const current = await this.current(selected.companyId, selected.source, maxAgeMs);
    if (current.token !== selected.token || current.snapshotId !== selected.snapshotId) throw new SourceAttention("source_poll_superseded");
  }
}

/** Explicit read-only orchestration; no scheduler, decisions, issue effects or rescan resolution. */
export class RepositorySourceSync {
  constructor(private readonly polls: SourcePollStore, private readonly journal: SourceJournal, private readonly github: GitHubLockfiles) {}

  async read(companyId: string, configured: RepositorySource[]): Promise<CurrentSource[]> {
    const sources = normalizeRepositorySources(configured);
    const polls: SourcePoll[] = [];
    try {
      for (const configuredSource of sources) polls.push(await this.polls.begin(companyId, configuredSource));
      const previous = (await Promise.all(polls.map(poll => this.polls.cached(poll)))).filter(value => value !== null);
      const snapshots = await this.github.read(sources, previous);
      // Retain every raw response before selecting any repository. Partial batches return no result.
      const ids: string[] = [];
      for (const snapshot of snapshots) ids.push(await this.journal.recordLockfiles(companyId, snapshot));
      for (const [index, poll] of polls.entries()) await this.polls.complete(poll, ids[index]!);
      const selected = await Promise.all(sources.map(configuredSource => this.polls.current(companyId, configuredSource)));
      for (const [index, value] of selected.entries()) {
        if (value.token !== polls[index]!.token) throw new SourceAttention("source_poll_superseded");
      }
      return selected;
    } catch (error) {
      const code = error instanceof SourceAttention && CODE.test(error.code) ? error.code : "repository_sync_failed";
      // Failure to persist attention leaves a polling fence, not an older ready selection.
      await Promise.allSettled(polls.map(poll => this.polls.fail(poll, code)));
      throw new SourceAttention(code);
    }
  }
}
