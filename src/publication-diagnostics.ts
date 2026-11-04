import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { DATABASE_NAMESPACE, FINDING_ORIGIN_KIND, WEEKLY_ORIGIN_KIND } from "./claims.js";
import { repository } from "./github-repository.js";
import { object, text, timestamp } from "./source-http.js";

const HASH = /^[a-f0-9]{64}$/u;
const STATES = ["reserved", "creating", "linked", "refreshing", "indeterminate", "quarantined"] as const;
type ClaimState = typeof STATES[number];
type Observation = "observed" | "missing" | "unavailable" | "invalid";
interface PinObservation {
  status: Observation;
  revision: number | null;
  pinned: boolean | null;
}
export interface PublicationDiagnosticResult {
  status: "attention";
  companyId: string;
  repo: string;
  observedAt: string;
  // Static library limitation, NOT authenticated installed-host capability discovery.
  publication: { enabled: false; ownershipMap: "publication-ownership-map/v1"; admissibility: "not_admissible"; supportedMethods: [] };
  source: PinObservation & { historyBytes: number | null; historyIsArray: boolean | null };
  routing: PinObservation & { bundleBytes: number | null; containers: number | null };
  claims: {
    status: Observation;
    coverage: "routing_containers_only";
    counts: Record<ClaimState, number> | null;
    missing: number | null;
    attempts: number | null;
    oldestClaimedAt: string | null;
  };
  attention: string[];
}

const revision = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const bytes = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const pin = (): PinObservation => ({ status: "missing", revision: null, pinned: null });

/** Read-only, non-atomic worker-state diagnostics. Never authority, recovery or a publication permit. */
export class PublicationDiagnostics {
  constructor(private readonly db: Pick<PluginDatabaseClient, "namespace" | "query">, private readonly now = () => new Date()) {
    if (db.namespace !== DATABASE_NAMESPACE) throw new Error("Publication diagnostic namespace does not match the packaged migration");
  }

  async read(companyId: string, repo: string): Promise<PublicationDiagnosticResult> {
    text(companyId, "invalid_company", 256);
    const canonicalRepo = repository(repo);
    const result: PublicationDiagnosticResult = {
      status: "attention", companyId, repo: canonicalRepo,
      observedAt: timestamp(this.now().toISOString(), "invalid_publication_diagnostic_time"),
      publication: { enabled: false, ownershipMap: "publication-ownership-map/v1", admissibility: "not_admissible", supportedMethods: [] },
      source: { ...pin(), historyBytes: null, historyIsArray: null },
      routing: { ...pin(), bundleBytes: null, containers: null },
      claims: { status: "unavailable", coverage: "routing_containers_only", counts: null, missing: null, attempts: null, oldestClaimedAt: null },
      attention: ["native_publication_disabled", "publication_ownership_map_not_admissible", "worker_state_not_authority",
        "diagnostics_not_atomic", "claims_not_repository_exhaustive", "enabled_pilot_not_run"],
    };
    const schema = `"${this.db.namespace}"`;
    try {
      const rows = await this.db.query<{ revision: unknown; pinned: unknown; history_bytes: unknown; history_is_array: unknown }>(
        `SELECT revision, effect_barrier IS NOT NULL AS pinned,
         octet_length(effect_history::text) AS history_bytes, jsonb_typeof(effect_history) = 'array' AS history_is_array
         FROM ${schema}.source_polls WHERE company_id = $1 AND repo = $2`, [companyId, canonicalRepo],
      );
      if (rows.length > 1) throw new Error("Duplicate source row");
      const row = rows[0];
      if (row) {
        if (!revision(row.revision) || typeof row.pinned !== "boolean" || !bytes(row.history_bytes)
          || typeof row.history_is_array !== "boolean") throw new Error("Invalid source summary");
        result.source = { status: "observed", revision: row.revision, pinned: row.pinned,
          historyBytes: row.history_bytes, historyIsArray: row.history_is_array };
        if (row.pinned) result.attention.push("source_pin_present");
        if (!row.history_is_array) result.attention.push("source_history_invalid");
        if (row.history_bytes >= 1048576) result.attention.push("source_history_capacity");
      }
    } catch {
      result.source.status = "unavailable";
      result.attention.push("source_diagnostics_unavailable");
    }
    // Bounds are applied in SQL before returning a potentially corrupt routing bundle.
    let origins: Array<{ originId: string; originKind: string }> | null = null;
    try {
      const rows = await this.db.query<{ revision: unknown; pinned: unknown; bundle_bytes: unknown; bundle: unknown }>(
        `SELECT revision, effect_token IS NOT NULL AS pinned, octet_length(bundle::text) AS bundle_bytes,
         CASE WHEN octet_length(bundle::text) <= 1048576 THEN bundle ELSE NULL END AS bundle
         FROM ${schema}.delivery_routing WHERE company_id = $1 AND repo = $2`, [companyId, canonicalRepo],
      );
      if (rows.length > 1) throw new Error("Duplicate routing row");
      const row = rows[0];
      if (row) {
        if (!revision(row.revision) || typeof row.pinned !== "boolean" || !bytes(row.bundle_bytes)) throw new Error("Invalid routing summary");
        result.routing = { status: "invalid", revision: row.revision, pinned: row.pinned, bundleBytes: row.bundle_bytes, containers: null };
        if (row.pinned) result.attention.push("routing_pin_present");
        if (row.bundle_bytes > 1048576) result.attention.push("routing_diagnostics_capacity");
        else {
          const bundle = object(row.bundle, "invalid_routing_diagnostics");
          if (bundle.version !== 1 || !Array.isArray(bundle.containers) || bundle.containers.length > 2000) throw new Error("Invalid routing containers");
          const mapped = bundle.containers.map(value => {
            const container = object(value, "invalid_routing_diagnostics");
            if (typeof container.originId !== "string" || !HASH.test(container.originId)
              || (container.originKind !== FINDING_ORIGIN_KIND && container.originKind !== WEEKLY_ORIGIN_KIND)) throw new Error("Invalid routing origin");
            return { originId: container.originId, originKind: container.originKind };
          });
          if (new Set(mapped.map(value => value.originId)).size !== mapped.length) throw new Error("Duplicate routing origin");
          origins = mapped;
          result.routing.status = "observed";
          result.routing.containers = mapped.length;
        }
      }
    } catch {
      if (result.routing.status !== "invalid") result.routing.status = "unavailable";
      result.attention.push("routing_diagnostics_unavailable");
    }
    if (origins !== null) {
      try {
        const rows = origins.length ? await this.db.query<{
          origin_id: unknown; origin_kind: unknown; state: unknown; attempt_count: unknown; claimed_at: unknown;
        }>(
          `SELECT origin_id, origin_kind, state, attempt_count,
           to_char(claimed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS claimed_at
           FROM ${schema}.card_claims WHERE company_id = $1 AND origin_id = ANY($2::text[]) LIMIT 2001`, [companyId, origins.map(value => value.originId)],
        ) : [];
        const expected = new Map(origins.map(value => [value.originId, value.originKind]));
        const seen = new Set<string>();
        const counts = Object.fromEntries(STATES.map(state => [state, 0])) as Record<ClaimState, number>;
        let attempts = 0;
        let oldest: string | null = null;
        for (const row of rows) {
          if (typeof row.origin_id !== "string" || !expected.has(row.origin_id) || expected.get(row.origin_id) !== row.origin_kind
            || seen.has(row.origin_id) || !STATES.includes(row.state as ClaimState) || !bytes(row.attempt_count)) throw new Error("Invalid claim summary");
          const claimedAt = timestamp(row.claimed_at, "invalid_claim_time");
          if (Date.parse(claimedAt) > Date.parse(result.observedAt)) throw new Error("Future claim time");
          seen.add(row.origin_id);
          counts[row.state as ClaimState]++;
          attempts += row.attempt_count;
          if (!Number.isSafeInteger(attempts)) throw new Error("Invalid attempt total");
          if (oldest === null || Date.parse(claimedAt) < Date.parse(oldest)) oldest = claimedAt;
        }
        result.claims = { status: "observed", coverage: "routing_containers_only", counts,
          missing: origins.length - rows.length, attempts, oldestClaimedAt: oldest };
        if (rows.length) result.attention.push("mapped_claims_require_independent_verification");
        if (counts.creating + counts.refreshing + counts.indeterminate + counts.quarantined > 0) result.attention.push("mapped_claim_uncertainty");
      } catch {
        result.claims.status = "unavailable";
        result.attention.push("claim_diagnostics_unavailable");
      }
    }
    if (result.source.status === "missing") result.attention.push("source_diagnostics_missing");
    if (result.routing.status === "missing") result.attention.push("routing_diagnostics_missing");
    return result;
  }
}
