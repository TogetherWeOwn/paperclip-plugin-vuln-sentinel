import { discoveryCoverage, GitHubRepositoryDiscovery } from "./github-discovery.js";
import { GitHubLockfiles } from "./github-lockfiles.js";
import { repository } from "./github-repository.js";
import { SourceJournal } from "./source-journal.js";
import { SourcePollStore, type CurrentSource, type SourcePoll } from "./source-polls.js";
import { SourceAttention } from "./source-http.js";

/** Read-only library integration. Reserve before network I/O; retain discovery before content/selection. */
export class DiscoveredRepositorySourceSync {
  constructor(
    private readonly polls: SourcePollStore,
    private readonly journal: SourceJournal,
    private readonly discovery: GitHubRepositoryDiscovery,
    private readonly github: GitHubLockfiles,
  ) {}

  async read(companyId: string, repositories: string[]): Promise<CurrentSource[]> {
    if (!Array.isArray(repositories) || repositories.length > 50) throw new SourceAttention("repository_capacity");
    const repos = repositories.map(repository);
    if (new Set(repos).size !== repos.length) throw new SourceAttention("duplicate_repository");
    const polls: SourcePoll[] = [];
    try {
      for (const repo of repos) polls.push(await this.polls.beginDiscovery(companyId, repo));
      const cachedTrees = (await Promise.all(polls.map(poll => this.polls.cachedDiscovery(poll)))).filter(value => value !== null);
      const discoveries = await this.discovery.read(repos, cachedTrees);
      const discoveryIds: string[] = [];
      // Unsupported/unbound coverage is retained as evidence, never silently narrowed to supported paths.
      for (const snapshot of discoveries) discoveryIds.push(await this.journal.recordDiscovery(companyId, snapshot));
      if (discoveries.some(snapshot => discoveryCoverage(snapshot).attention.length)) throw new SourceAttention("discovery_coverage_attention");
      for (const [index, poll] of polls.entries()) polls[index] = await this.polls.bindDiscovery(poll, discoveryIds[index]!);
      const cachedFiles = (await Promise.all(polls.map(poll => this.polls.cached(poll)))).filter(value => value !== null);
      const snapshots = await this.github.readDiscovered(discoveries, cachedFiles);
      const ids: string[] = [];
      for (const [index, snapshot] of snapshots.entries()) ids.push(await this.journal.recordLockfiles(companyId, snapshot, discoveryIds[index]!));
      for (const [index, poll] of polls.entries()) await this.polls.complete(poll, ids[index]!);
      const selected = await Promise.all(polls.map(poll => this.polls.current(companyId, poll.source)));
      for (const [index, value] of selected.entries()) {
        if (value.token !== polls[index]!.token) throw new SourceAttention("source_poll_superseded");
      }
      return selected;
    } catch (error) {
      const code = error instanceof SourceAttention && /^[a-z0-9_]{1,96}$/u.test(error.code) ? error.code : "discovered_repository_sync_failed";
      // A failed attention write leaves a discovering/polling fence, not an earlier ready selection.
      await Promise.allSettled(polls.map(poll => this.polls.fail(poll, code)));
      throw new SourceAttention(code);
    }
  }
}
