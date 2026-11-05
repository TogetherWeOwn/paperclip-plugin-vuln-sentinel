import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE } from "./claims.js";
import { validateDependabotSnapshot, type DependabotSnapshot } from "./dependabot.js";
import { canonicalJson, sha256 } from "./identity.js";
import { SourceAttention } from "./source-http.js";

function snapshotId(snapshot: DependabotSnapshot): string {
  return sha256(canonicalJson(["dependabot-snapshot-v1", snapshot]));
}

/** Immutable observed alerts only. No mutable source choice or negative safety conclusion. */
export class DependabotJournal {
  private readonly table: string;
  constructor(private readonly db: PluginDatabaseClient) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Dependabot journal namespace does not match the packaged migration");
    this.table = `"${db.namespace}".dependabot_snapshots`;
  }

  async record(companyId: string, snapshot: DependabotSnapshot): Promise<string> {
    const bundle = structuredClone(snapshot);
    validateDependabotSnapshot(bundle);
    const id = snapshotId(bundle);
    await this.db.execute(
      `INSERT INTO ${this.table} (company_id, snapshot_id, bundle) VALUES ($1, $2, $3)
       ON CONFLICT (company_id, snapshot_id) DO NOTHING`, [companyId, id, canonicalJson(bundle)],
    );
    const stored = await this.read(companyId, id);
    if (!stored || canonicalJson(stored) !== canonicalJson(bundle)) throw new SourceAttention("dependabot_persistence_mismatch");
    return id;
  }

  async read(companyId: string, id: string): Promise<DependabotSnapshot | null> {
    if (!/^[a-f0-9]{64}$/u.test(id)) throw new SourceAttention("invalid_dependabot_snapshot_id");
    const rows = await this.db.query<{ snapshot_id: string; bundle: DependabotSnapshot }>(
      `SELECT snapshot_id, bundle FROM ${this.table} WHERE company_id = $1 AND snapshot_id = $2`, [companyId, id],
    );
    const row = rows[0];
    if (!row) return null;
    validateDependabotSnapshot(row.bundle);
    if (row.snapshot_id !== id || snapshotId(row.bundle) !== id) throw new SourceAttention("stored_dependabot_hash_mismatch");
    return row.bundle;
  }
}
