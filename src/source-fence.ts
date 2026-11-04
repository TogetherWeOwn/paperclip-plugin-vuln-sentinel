import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson } from "./identity.js";
import type { SourceSelection } from "./model.js";
import type { CurrentSource } from "./source-polls.js";

export function sourceSelection(selected: CurrentSource): SourceSelection {
  return { pollRevision: selected.pollRevision, token: selected.token, snapshotId: selected.snapshotId };
}

/** Only embed in a mutating statement, after validating the full retained selection.
 * The row lock serializes the dependent write against begin/complete/fail, including
 * a poll update that commits while this statement waits. EXISTS alone is not a fence.
 */
export function sourceFence(selected: CurrentSource, firstParameter: number): { sql: string; params: unknown[] } {
  const [company, repo, revision, bundle] = Array.from({ length: 4 }, (_, index) => `$${firstParameter + index}`);
  return {
    sql: `EXISTS (SELECT 1 FROM "${DATABASE_NAMESPACE}".source_polls
      WHERE company_id = ${company} AND repo = ${repo} AND revision = ${revision}
      AND bundle = ${bundle}::jsonb
      AND statement_timestamp() >= (${bundle}::jsonb->'attempt'->>'completedAt')::timestamptz
      AND statement_timestamp() <= (${bundle}::jsonb->'attempt'->>'startedAt')::timestamptz + interval '1 day'
      FOR UPDATE)`,
    params: [selected.companyId, selected.source.repo, selected.pollRevision, canonicalJson({
      version: 1, cacheSnapshotId: selected.snapshotId, attempt: {
        token: selected.token, source: selected.source, state: "ready", startedAt: selected.startedAt,
        completedAt: selected.completedAt, snapshotId: selected.snapshotId, attentionCode: null,
      },
    })],
  };
}
