import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import { decide } from "./matcher.js";
import type { Decision, FindingInput } from "./model.js";

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
  constructor(private readonly db: PluginDatabaseClient) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Journal namespace does not match the packaged migration");
    this.decisions = `"${db.namespace}".decision_records`;
    this.findings = `"${db.namespace}".finding_records`;
  }

  async record(companyId: string, input: FindingInput): Promise<{ decisionId: string; decision: Decision }> {
    const bundle = structuredClone(input);
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
    await this.db.execute(
      `INSERT INTO ${this.findings}
       (company_id, origin_id, repo, remediation_unit, alias_group, latest_decision_id, latest_observed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (company_id, origin_id) DO UPDATE
       SET latest_decision_id = EXCLUDED.latest_decision_id, latest_observed_at = EXCLUDED.latest_observed_at
       WHERE COALESCE(EXCLUDED.latest_observed_at, '-infinity'::timestamptz) > COALESCE(finding_records.latest_observed_at, '-infinity'::timestamptz)
       OR (COALESCE(EXCLUDED.latest_observed_at, '-infinity'::timestamptz) = COALESCE(finding_records.latest_observed_at, '-infinity'::timestamptz)
           AND EXCLUDED.latest_decision_id > finding_records.latest_decision_id)`,
      [companyId, originId, repo, remediationUnit, aliasGroup, decisionId, observedAt],
    );
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
