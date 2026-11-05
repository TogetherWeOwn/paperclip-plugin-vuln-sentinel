import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { OsvSource } from "./osv.js";
import { SourceDecisions, type SourceDecisionResult } from "./source-decisions.js";
import { SourceAttention, timestamp, type SourceFetch } from "./source-http.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";
import { ThreatFeeds, type EpssModel } from "./threat-feeds.js";
import { ThreatJournal } from "./threat-journal.js";

export interface RepositoryScanOptions {
  epssDate: string;
  // Trusted, independently verified runtime config; never inferred from an API response.
  epssModel: EpssModel;
}

export interface RepositoryScanResult {
  status: "attention";
  startedAt: string;
  completedAt: string;
  decisions: SourceDecisionResult;
  attention: string[];
}

/** Explicit OSV fallback to fenced local projections; no worker, scheduler or native effects. */
export class RepositoryScan {
  private readonly sources: SourceJournal;
  private readonly polls: SourcePollStore;
  private readonly threats: ThreatJournal;
  private readonly decisions: SourceDecisions;
  private readonly osv: OsvSource;
  private readonly feeds: ThreatFeeds;
  constructor(db: PluginDatabaseClient, fetch: SourceFetch, private readonly now = () => new Date()) {
    this.sources = new SourceJournal(db, now);
    this.polls = new SourcePollStore(db, now);
    this.threats = new ThreatJournal(db);
    this.decisions = new SourceDecisions(db, now);
    this.osv = new OsvSource(fetch, now);
    this.feeds = new ThreatFeeds(fetch, now);
  }

  async run(selection: CurrentSource, options: RepositoryScanOptions): Promise<RepositoryScanResult> {
    const selected = structuredClone(selection);
    const config = structuredClone(options);
    const startedAt = timestamp(this.now().toISOString(), "invalid_repository_scan_time");
    const deadline = () => {
      const elapsed = this.now().getTime() - Date.parse(startedAt);
      if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > 600_000) throw new SourceAttention("repository_scan_deadline");
    };
    const current = async () => {
      deadline();
      await this.polls.assertCurrent(selected);
      deadline();
    };
    await current();
    const osv = await this.osv.query(selected.stored.inventory.dependencies);
    await current();
    const cves = [...new Set([...osv.records.flatMap(record => [record.id, ...record.aliases, ...record.upstream]),
      ...osv.unavailableIds])].filter(id => /^CVE-\d{4}-\d{4,}$/u.test(id)).sort();
    const kev = await this.feeds.kev();
    await current();
    const epss = await this.feeds.epss(cves, config.epssDate, config.epssModel);
    await current();
    // Feeds precede the retained observation time. All raw evidence must be durable
    // before SourceDecisions derives or writes a finding/routing projection.
    const scan = await this.sources.recordOsv(selected.companyId, selected.snapshotId, osv);
    const threatId = await this.threats.record(selected.companyId, { kev, epss });
    await current();
    const decisions = await this.decisions.observe(selected, scan.snapshotId, threatId);
    await current();
    return { status: "attention", startedAt, completedAt: this.now().toISOString(), decisions,
      attention: [...new Set([...decisions.attention,
        "dependabot_source_switch_not_enabled", "native_publication_disabled", "enabled_pilot_not_run"])],
    };
  }
}
