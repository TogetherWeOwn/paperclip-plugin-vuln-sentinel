import { valid } from "semver";
import { parse as parseToml } from "smol-toml";
import { parseDocument } from "yaml";
import { sha256 } from "./identity.js";
import { object, SourceAttention, text } from "./source-http.js";

export interface CrateTuple { name: string; version: string }

export interface RustInventoryReports {
  check: string;
  syft: string;
  grype: string;
  cargoLock?: string;
  // Caller expectations bind observations only; they are not authenticated receipts.
  expected: { sourceSha: string; imageId: string; configId: string };
}

export interface RustInventoryObservation {
  status: "attention";
  authenticated: false;
  resolutionEligible: false;
  runtimeCompleteness: "not_proven";
  deployedBinding: "not_proven";
  lockfileComparison: "matched" | "not_observed";
  sourceSha: string;
  imageId: string;
  configId: string;
  runtime: CrateTuple[];
  locked: CrateTuple[];
  lockfileOnly: CrateTuple[];
  grypeMatches: number;
  reportSha256: { check: string; syft: string; grype: string; cargoLock: string | null };
  toolVersions: { syft: string; grype: string };
  reasons: string[];
}

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_TUPLES = 10_000;
const reject = (code: string): never => { throw new SourceAttention(code); };
const key = (tuple: CrateTuple) => `${tuple.name}@${tuple.version}`;
const equal = (left: CrateTuple[], right: CrateTuple[]) => left.length === right.length
  && left.every((tuple, index) => key(tuple) === key(right[index]!));

function bounded(content: string): void {
  if (typeof content !== "string" || !content.length || Buffer.byteLength(content) > MAX_BYTES) {
    reject("rust_report_size");
  }
}

function report(content: string): Record<string, unknown> {
  bounded(content);
  try {
    const parsed = object(JSON.parse(content), "invalid_rust_report");
    const document = parseDocument(content, { schema: "json", uniqueKeys: true, strict: true });
    if (document.errors.length || document.warnings.length) reject("ambiguous_rust_json");
    return parsed;
  } catch (error) {
    if (error instanceof SourceAttention) throw error;
    return reject("invalid_rust_report");
  }
}

function rows(value: unknown): unknown[] {
  if (!Array.isArray(value) || value.length > MAX_TUPLES) return reject("rust_tuple_capacity_or_shape");
  return value;
}

function tuple(value: unknown): CrateTuple {
  const row = object(value, "invalid_crate_tuple");
  const name = text(row.name, "invalid_crate_name", 256);
  const version = text(row.version, "invalid_crate_version", 256);
  // semver.valid omits build metadata; preserve Cargo's complete tuple identity.
  if (!/^[A-Za-z0-9_-]+$/u.test(name) || valid(version) !== version.split("+")[0]) reject("invalid_crate_tuple");
  return { name, version };
}

function tuples(value: unknown, unique = true): CrateTuple[] {
  const parsed = rows(value).map(tuple);
  const result = new Map(parsed.map(row => [key(row), row]));
  if (unique && result.size !== parsed.length) reject("duplicate_crate_tuple");
  return [...result.values()].sort((a, b) => key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);
}

function digest(value: unknown, prefixed = false): string {
  const result = text(value, "invalid_rust_digest", 71);
  if (!(prefixed ? /^sha256:[a-f0-9]{64}$/u : /^[a-f0-9]{64}$/u).test(result)) reject("invalid_rust_digest");
  return result;
}

function source(value: unknown, imageId: string, configId: string): void {
  const metadata = object(value, "missing_native_image_source");
  if (metadata.userInput !== imageId || metadata.imageID !== configId) reject("native_image_binding_mismatch");
}

/** Offline consistency only. Never produces RescanEvidence, VEX, policy inputs or a publication permit. */
export function observeRustInventory(input: RustInventoryReports): RustInventoryObservation {
  const check = report(input.check);
  const syft = report(input.syft);
  const grype = report(input.grype);
  const sourceSha = text(check.source_sha, "invalid_rust_source_sha", 64);
  if (!/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(sourceSha)) reject("invalid_rust_source_sha");
  const imageId = digest(check.image_id, true);
  const configId = digest(check.config_id, true);
  if (sourceSha !== input.expected.sourceSha || imageId !== input.expected.imageId || configId !== input.expected.configId) {
    reject("rust_expected_binding_mismatch");
  }
  const hashes = object(check.sha256, "missing_rust_report_hashes");
  const lockHash = digest(hashes["Cargo.lock"]);
  if (digest(hashes["runtime-crates.syft.json"]) !== sha256(input.syft)
    || digest(hashes["runtime-crates.grype.json"]) !== sha256(input.grype)) reject("rust_report_hash_mismatch");

  const runtime = tuples(check.runtime_crate_tuples);
  const locked = tuples(check.locked_crate_tuples);
  const lockfileOnly = tuples(check.lockfile_only);
  if (!runtime.length || !locked.length) reject("empty_rust_inventory");
  if (check.runtime_crates !== runtime.length || check.locked_crates !== locked.length) reject("rust_count_mismatch");
  if (check.runtime_completeness !== "not_proven" || check.suppressed_count !== 0) reject("unsupported_rust_evidence_claim");
  const runtimeKeys = new Set(runtime.map(key));
  const lockedKeys = new Set(locked.map(key));
  if (runtime.some(row => !lockedKeys.has(key(row)))
    || !equal(lockfileOnly, locked.filter(row => !runtimeKeys.has(key(row))))) reject("rust_partition_mismatch");

  const syftSource = object(syft.source, "missing_native_image_source");
  const grypeSource = object(grype.source, "missing_native_image_source");
  if (syftSource.type !== "image" || grypeSource.type !== "image") reject("unsupported_native_source");
  source(syftSource.metadata, imageId, configId);
  source(grypeSource.target, imageId, configId);
  const native = rows(syft.artifacts).map(value => {
    const row = object(value, "invalid_native_crate");
    if (row.type !== "rust-crate" || row.foundBy !== "cargo-auditable-binary-cataloger") reject("unsupported_native_crate");
    return tuple(row);
  });
  if (!equal(tuples(native), runtime)) reject("native_crate_set_mismatch");
  const matches = rows(grype.matches);
  if (check.grype_matches !== matches.length) reject("rust_match_count_mismatch");
  for (const match of matches) {
    const artifact = object(object(match, "invalid_grype_match").artifact, "invalid_grype_artifact");
    if (artifact.type !== "rust-crate" || !runtimeKeys.has(key(tuple(artifact)))) reject("unbound_grype_match");
  }
  if (grype.ignoredMatches !== undefined && rows(grype.ignoredMatches).length) reject("suppressed_grype_matches");
  const syftTool = object(syft.descriptor, "missing_native_tool");
  const grypeTool = object(grype.descriptor, "missing_native_tool");
  if (syftTool.name !== "syft" || grypeTool.name !== "grype") reject("unsupported_native_tool");
  const toolVersions = {
    syft: text(syftTool.version, "missing_syft_version", 256),
    grype: text(grypeTool.version, "missing_grype_version", 256),
  };

  let lockfileComparison: RustInventoryObservation["lockfileComparison"] = "not_observed";
  if (input.cargoLock !== undefined) {
    bounded(input.cargoLock);
    if (sha256(input.cargoLock) !== lockHash) reject("rust_lockfile_hash_mismatch");
    try {
      const lock = parseToml(input.cargoLock);
      if (lock.version !== 3 && lock.version !== 4) reject("unsupported_rust_lockfile");
      // L is the unique name/version view, even when Cargo has multiple sources.
      if (!equal(tuples(lock.package, false), locked)) reject("rust_lockfile_set_mismatch");
    } catch (error) {
      if (error instanceof SourceAttention) throw error;
      reject("invalid_rust_lockfile");
    }
    lockfileComparison = "matched";
  }
  return {
    status: "attention", authenticated: false, resolutionEligible: false,
    runtimeCompleteness: "not_proven", deployedBinding: "not_proven", lockfileComparison,
    sourceSha, imageId, configId, runtime, locked, lockfileOnly, grypeMatches: matches.length,
    reportSha256: { check: sha256(input.check), syft: sha256(input.syft), grype: sha256(input.grype),
      cargoLock: input.cargoLock === undefined ? null : sha256(input.cargoLock) },
    toolVersions,
    reasons: ["producer_authentication_not_verified", "deployed_digest_not_verified", "runtime_completeness_not_proven",
      "scanner_execution_and_policy_not_verified", "build_target_and_toolchain_not_verified", "native_binary_metadata_not_verified",
      ...(lockfileComparison === "not_observed" ? ["independent_lockfile_not_observed"] : [])],
  };
}
