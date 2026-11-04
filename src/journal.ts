import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { decide } from "./matcher.js";
import type { Decision, FindingInput } from "./model.js";
import { sourceFence, sourceSelection } from "./source-fence.js";
import { SourceAttention } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";

export interface StoredDecision {
  company_id: string;
  origin_id: string;
  decision_id: string;
  input_sha256: string;
  rules_version: string;
  input_bundle: FindingInput;
  decision_bundle: Decision;
  observed_at: string | null;
  persisted_at: string;
}

/** Append-only evidence revisions; issue delivery is a separate, guarded effect. */
export class DecisionJournal {
  private readonly decisions: string;
  private readonly findings: string;
  constructor(private readonly db: PluginDatabaseClient, private readonly now = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Journal namespace does not match the packaged migration");
    this.decisions = `"${db.namespace}".decision_records`;
    this.findings = `"${db.namespace}".finding_records`;
  }

  async record(companyId: string, input: FindingInput): Promise<{ decisionId: string; decision: Decision }> {
    if (input.provenance.sourceSelection) throw new SourceAttention("source_selection_requires_fenced_write");
    return this.persist(companyId, structuredClone(input));
  }

  /** Retain evidence, but advance a current finding head only under the source row lock. */
  async recordCurrent(selection: CurrentSource, input: FindingInput): Promise<{ decisionId: string; decision: Decision }> {
    const selected = structuredClone(selection);
    const bundle = structuredClone(input);
    if (bundle.repo.toLowerCase() !== selected.source.repo || bundle.provenance.artifactKind !== "lockfile"
      || bundle.provenance.artifactDigest !== selected.stored.lockfiles.artifactDigest) {
      throw new SourceAttention("decision_source_binding_mismatch");
    }
    await new SourcePollStore(this.db, this.now).assertCurrent(selected);
    bundle.provenance.sourceSelection = sourceSelection(selected);
    return this.persist(selected.companyId, bundle, selected);
  }

  private async persist(companyId: string, bundle: FindingInput, selected?: CurrentSource): Promise<{ decisionId: string; decision: Decision }> {
    const decision = decide(bundle);
    const decisionId = sha256(`${decision.rulesVersion}|${decision.inputSha256}`);
    const { originId, repo, remediationUnit, aliasGroup } = decision.identity;
    const observedAt = Number.isFinite(Date.parse(bundle.provenance.observedAt)) ? bundle.provenance.observedAt : null;
    // Persist the complete input before advancing the finding head. A crash between
    // these statements leaves history, not a dangling head; replay finishes the head.
    await this.db.execute(
      `INSERT INTO ${this.decisions}
       (company_id, origin_id, decision_id, input_sha256, rules_version, input_bundle, decision_bundle, observed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (company_id, origin_id, decision_id) DO NOTHING`,
      [companyId, originId, decisionId, decision.inputSha256, decision.rulesVersion,
        canonicalJson(bundle), canonicalJson(decision), observedAt],
    );
    const params = [companyId, originId, repo, remediationUnit, aliasGroup, decisionId, observedAt];
    const newer = `(COALESCE(EXCLUDED.latest_observed_at, '-infinity'::timestamptz) > COALESCE(finding_records.latest_observed_at, '-infinity'::timestamptz)
      OR (COALESCE(EXCLUDED.latest_observed_at, '-infinity'::timestamptz) = COALESCE(finding_records.latest_observed_at, '-infinity'::timestamptz)
        AND EXCLUDED.latest_decision_id > finding_records.latest_decision_id))`;
    if (selected) {
      const fence = sourceFence(selected, 9);
      const advance = `(finding_records.source_poll_revision IS NULL
        OR EXCLUDED.source_poll_revision > finding_records.source_poll_revision OR ${newer})`;
      const result = await this.db.execute(
        `INSERT INTO ${this.findings}
         (company_id, origin_id, repo, remediation_unit, alias_group, latest_decision_id, latest_observed_at, source_poll_revision)
         SELECT $1, $2, $3, $4, $5, $6, $7::timestamptz, $8::integer WHERE ${fence.sql}
         ON CONFLICT (company_id, origin_id) DO UPDATE
         SET latest_decision_id = CASE WHEN ${advance} THEN EXCLUDED.latest_decision_id ELSE finding_records.latest_decision_id END,
             latest_observed_at = CASE WHEN ${advance} THEN EXCLUDED.latest_observed_at ELSE finding_records.latest_observed_at END,
             source_poll_revision = EXCLUDED.source_poll_revision
         WHERE finding_records.source_poll_revision IS NULL OR finding_records.source_poll_revision <= EXCLUDED.source_poll_revision`,
        [...params, selected.pollRevision, ...fence.params],
      );
      if (result.rowCount !== 1) throw new SourceAttention("source_fence_rejected");
    } else {
      await this.db.execute(
        `INSERT INTO ${this.findings}
         (company_id, origin_id, repo, remediation_unit, alias_group, latest_decision_id, latest_observed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (company_id, origin_id) DO UPDATE
         SET latest_decision_id = EXCLUDED.latest_decision_id, latest_observed_at = EXCLUDED.latest_observed_at
         WHERE finding_records.source_poll_revision IS NULL AND ${newer}`, params,
      );
    }
    return { decisionId, decision };
  }

  async read(companyId: string, originId: string, decisionId: string): Promise<StoredDecision | null> {
    const rows = await this.db.query<StoredDecision>(
      `SELECT * FROM ${this.decisions} WHERE company_id = $1 AND origin_id = $2 AND decision_id = $3`,
      [companyId, originId, decisionId],
    );
    return rows[0] ?? null;
  }

  async latest(companyId: string, originId: string): Promise<StoredDecision | null> {
    const rows = await this.db.query<StoredDecision>(
      `SELECT d.* FROM ${this.decisions} d JOIN ${this.findings} f
       ON d.company_id = f.company_id AND d.origin_id = f.origin_id AND d.decision_id = f.latest_decision_id
       WHERE f.company_id = $1 AND f.origin_id = $2`,
      [companyId, originId],
    );
    return rows[0] ?? null;
  }
}
