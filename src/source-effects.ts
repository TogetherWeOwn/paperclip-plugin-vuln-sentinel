import { randomUUID } from "node:crypto";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE, type RecoveryProof } from "./claims.js";
import { canonicalJson } from "./identity.js";
import type { SourceSelection } from "./model.js";
import { sourceFence, sourceSelection } from "./source-fence.js";
import { SourceAttention, text, timestamp } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";

const HASH = /^[a-f0-9]{64}$/u;
const TOKEN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
export interface SourceEffectIntent {
  executionId: string;
  originId: string;
  publicationRevision: number;
  contentSha256: string;
  routingSha256?: string;
}
export interface SourceEffectBarrier extends SourceEffectIntent {
  version: 1;
  companyId: string;
  repo: string;
  token: string;
  selection: SourceSelection;
  acquiredAt: string;
}

function validate(barrier: SourceEffectBarrier): void {
  if (!barrier || barrier.version !== 1 || !TOKEN.test(barrier.token)
    || !HASH.test(barrier.originId) || !HASH.test(barrier.contentSha256)
    || (barrier.routingSha256 !== undefined && !HASH.test(barrier.routingSha256))
    || !Number.isInteger(barrier.publicationRevision) || barrier.publicationRevision <= 0
    || barrier.publicationRevision > 2147483646 || !barrier.selection
    || !Number.isSafeInteger(barrier.selection.pollRevision) || barrier.selection.pollRevision < 1
    || !TOKEN.test(barrier.selection.token) || !HASH.test(barrier.selection.snapshotId)
    || !/^[\w.-]+\/[\w.-]+$/u.test(barrier.repo) || barrier.repo !== barrier.repo.toLowerCase()) {
    throw new SourceAttention("invalid_source_effect_barrier");
  }
  text(barrier.companyId, "invalid_company", 256);
  text(barrier.executionId, "invalid_source_effect_execution", 256);
  timestamp(barrier.acquiredAt, "invalid_source_effect_time");
}

/** Durable DB half of the host-effect protocol, not a publication permit by itself.
 * Every poll mutation uses the same row. No age/deadline/worker death releases it.
 */
export class SourceEffects {
  private readonly table: string;
  private readonly polls: SourcePollStore;
  constructor(private readonly db: PluginDatabaseClient, private readonly now = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Source effect namespace does not match the packaged migration");
    this.table = `"${db.namespace}".source_polls`;
    this.polls = new SourcePollStore(db, now);
  }

  async read(companyId: string, repo: string): Promise<SourceEffectBarrier | null> {
    text(companyId, "invalid_company", 256);
    if (!/^[\w.-]+\/[\w.-]+$/u.test(repo) || repo !== repo.toLowerCase()) throw new SourceAttention("invalid_source_effect_repo");
    const rows = await this.db.query<{ effect_barrier: SourceEffectBarrier | null }>(
      `SELECT effect_barrier FROM ${this.table} WHERE company_id = $1 AND repo = $2`, [companyId, repo],
    );
    const barrier = rows[0]?.effect_barrier;
    if (barrier == null) return null;
    validate(barrier);
    if (barrier.companyId !== companyId || barrier.repo !== repo) throw new SourceAttention("source_effect_binding_mismatch");
    return barrier;
  }

  async reserve(selected: CurrentSource, intent: SourceEffectIntent): Promise<SourceEffectBarrier> {
    const barrier: SourceEffectBarrier = {
      ...intent, version: 1, companyId: selected.companyId, repo: selected.source.repo,
      token: randomUUID(), selection: sourceSelection(selected), acquiredAt: this.now().toISOString(),
    };
    validate(barrier);
    await this.polls.assertCurrent(selected);
    const fence = sourceFence(selected, 4);
    // The UPDATE locks the poll row itself. A racing begin either wins first, or
    // rechecks effect_barrier IS NULL after our write and cannot advance the poll.
    try {
      await this.db.execute(
        `UPDATE ${this.table} SET effect_barrier = $3
         WHERE company_id = $1 AND repo = $2 AND effect_barrier IS NULL AND ${fence.sql}`,
        [barrier.companyId, barrier.repo, canonicalJson(barrier), ...fence.params],
      );
    } catch { /* A lost response is not ownership; read the exact durable token below. */ }
    const stored = await this.read(barrier.companyId, barrier.repo);
    if (!stored || canonicalJson(stored) !== canonicalJson(barrier)) throw new SourceAttention("source_effect_reservation_rejected");
    return stored;
  }

  /** The verifier must independently bind terminal execution AND settled host
   * effects to this barrier token. Strings/hashes supplied by a caller are not
   * authentication. No installed runtime verifier or automatic recovery exists.
   */
  async release(
    barrier: SourceEffectBarrier,
    verifySettled: (barrier: SourceEffectBarrier) => Promise<RecoveryProof | null>,
  ): Promise<boolean> {
    validate(barrier);
    const expected = canonicalJson(barrier);
    const current = await this.read(barrier.companyId, barrier.repo);
    if (!current || canonicalJson(current) !== expected) return false;
    const proof = await verifySettled(structuredClone(current));
    if (!proof || proof.previousClaimToken !== current.token) throw new SourceAttention("source_effect_settlement_unproven");
    for (const value of [proof.terminalExecutionReceipt, proof.settledHostEffectsReceipt, proof.auditRef]) {
      text(value, "source_effect_settlement_unproven", 4096);
      if (!value.trim()) throw new SourceAttention("source_effect_settlement_unproven");
    }
    const receipt = canonicalJson([{ barrier: current, proof, releasedAt: this.now().toISOString() }]);
    const result = await this.db.execute(
      `UPDATE ${this.table} SET effect_barrier = NULL, effect_history = effect_history || $4::jsonb
       WHERE company_id = $1 AND repo = $2 AND effect_barrier = $3::jsonb
       AND jsonb_typeof(effect_history) = 'array'
       AND octet_length((effect_history || $4::jsonb)::text) <= 1048576`,
      [current.companyId, current.repo, expected, receipt],
    );
    return result.rowCount === 1;
  }
}
