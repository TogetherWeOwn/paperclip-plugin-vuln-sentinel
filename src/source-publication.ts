import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE, publicationHash, type DeliveryInput, type RecoveryProof } from "./claims.js";
import { canonicalJson, sha256 } from "./identity.js";
import type { RoutingSnapshot } from "./routing.js";
import { sourceSelection } from "./source-fence.js";
import { SourceEffects, type SourceEffectBarrier } from "./source-effects.js";
import { SourceAttention } from "./source-http.js";
import { SourcePollStore, type CurrentSource } from "./source-polls.js";

interface PinnedRouting { bundle: RoutingSnapshot; effect_token: string | null }

/** Internal publication coordination, not an ingestion or recovery endpoint.
 * A partial reservation is intentionally held until independently verified settlement.
 */
export class SourcePublicationStore {
  private readonly table: string;
  private readonly effects: SourceEffects;
  constructor(private readonly db: PluginDatabaseClient, private readonly now = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Publication namespace does not match the packaged migration");
    this.table = `"${db.namespace}".delivery_routing`;
    this.effects = new SourceEffects(db, now);
  }

  async reserve(selected: CurrentSource, snapshot: RoutingSnapshot, input: DeliveryInput, executionId: string): Promise<SourceEffectBarrier> {
    if (input.companyId !== selected.companyId || input.publicationRevision === undefined) {
      throw new SourceAttention("source_publication_binding_mismatch");
    }
    const bundle = canonicalJson(snapshot);
    const barrier = await this.effects.reserve(selected, {
      executionId, originId: input.originId, publicationRevision: input.publicationRevision,
      contentSha256: publicationHash(input), routingSha256: sha256(bundle),
    });
    // No host call occurs between the two pins. A racing routing mutation either
    // wins first (and this exact-bundle CAS fails) or rechecks the pin and is held.
    try {
      await this.db.execute(
        `UPDATE ${this.table} SET effect_token = $3
         WHERE company_id = $1 AND repo = $2 AND effect_token IS NULL AND bundle = $4::jsonb`,
        [barrier.companyId, barrier.repo, barrier.token, bundle],
      );
    } catch { /* Only exact readback below grants ownership after a lost response. */ }
    await this.assertPinned(barrier);
    return barrier;
  }

  async assertPinned(barrier: SourceEffectBarrier): Promise<void> {
    const stored = await this.effects.read(barrier.companyId, barrier.repo);
    if (!barrier.routingSha256 || !stored || canonicalJson(stored) !== canonicalJson(barrier)) {
      throw new SourceAttention("source_publication_barrier_mismatch");
    }
    const rows = await this.db.query<PinnedRouting>(
      `SELECT bundle, effect_token FROM ${this.table} WHERE company_id = $1 AND repo = $2`,
      [barrier.companyId, barrier.repo],
    );
    const row = rows[0];
    if (!row || row.effect_token !== barrier.token || sha256(canonicalJson(row.bundle)) !== barrier.routingSha256) {
      throw new SourceAttention("source_publication_routing_mismatch");
    }
  }

  async assertDispatch(selected: CurrentSource, barrier: SourceEffectBarrier): Promise<void> {
    if (selected.companyId !== barrier.companyId || selected.source.repo !== barrier.repo
      || canonicalJson(sourceSelection(selected)) !== canonicalJson(barrier.selection)) {
      throw new SourceAttention("source_publication_binding_mismatch");
    }
    await new SourcePollStore(this.db, this.now).assertCurrent(selected);
    await this.assertPinned(barrier);
    // Check again synchronously at dispatch, after all asynchronous validation.
    const now = this.now().getTime();
    if (Date.parse(selected.startedAt) > now || Date.parse(selected.completedAt) > now
      || now - Date.parse(selected.startedAt) > 86400000) throw new SourceAttention("source_publication_expired");
  }

  /** Call from a later trusted integration once the execution is terminal and all
   * its host effects are settled. A successful library result is not that proof.
   */
  async settle(barrier: SourceEffectBarrier, verify: (barrier: SourceEffectBarrier) => Promise<RecoveryProof | null>): Promise<boolean> {
    if (!barrier.routingSha256) throw new SourceAttention("source_publication_binding_mismatch");
    await this.effects.release(barrier, verify);
    // The retained settlement audit also repairs a crash/lost response between
    // clearing the source pin and clearing routing. It cannot clear a newer token.
    const result = await this.db.execute(
      `UPDATE ${this.table} SET effect_token = NULL
       WHERE company_id = $1 AND repo = $2 AND effect_token = $3
       AND EXISTS (SELECT 1 FROM "${this.db.namespace}".source_polls
         WHERE company_id = $1 AND repo = $2 AND effect_history @> $4::jsonb)`,
      [barrier.companyId, barrier.repo, barrier.token, canonicalJson([{ barrier }])],
    );
    return result.rowCount === 1;
  }
}
