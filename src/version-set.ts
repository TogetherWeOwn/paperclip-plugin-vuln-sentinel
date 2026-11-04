import { canonicalJson, findingIdentity } from "./identity.js";
import type { DecisionInput, FindingInput, VersionSetInput } from "./model.js";
import { SourceAttention } from "./source-http.js";

const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/** Validate a retained same-action set; never union incompatible scope or proof. */
export function versionInputs(input: VersionSetInput): FindingInput[] {
  const { aggregationVersion, versions, ...common } = input;
  if (aggregationVersion !== 1 || !Array.isArray(versions) || versions.length < 2 || versions.length > 2000
    || "version" in common || "versionEvidence" in common) {
    throw new SourceAttention("invalid_version_set");
  }
  let previous: string | null = null;
  return versions.map(tuple => {
    if (typeof tuple.version !== "string" || !tuple.version || (previous !== null && compare(previous, tuple.version) >= 0)
      || canonicalJson(Object.keys(tuple).sort()) !== canonicalJson(["version", "versionEvidence"])) {
      throw new SourceAttention("invalid_version_set");
    }
    previous = tuple.version;
    return structuredClone({ ...common, ...tuple });
  });
}

/** Full batch prevalidation happens before any decisions or routing writes. */
export function aggregateFindingInputs(raw: FindingInput[]): DecisionInput[] {
  if (raw.length > 2000) throw new SourceAttention("version_set_capacity_exceeded");
  const groups = new Map<string, FindingInput[]>();
  for (const value of raw) {
    if ("versions" in value || "aggregationVersion" in value) throw new SourceAttention("invalid_version_set");
    const input = structuredClone(value);
    const origin = findingIdentity(input).originId;
    const group = groups.get(origin) ?? [];
    group.push(input);
    groups.set(origin, group);
  }
  return [...groups.entries()].sort(([a], [b]) => compare(a, b)).map(([, group]) => {
    if (group.length === 1) return group[0]!;
    group.sort((a, b) => compare(a.version, b.version));
    const { version: _, versionEvidence: __, ...common } = group[0]!;
    const expected = canonicalJson(common);
    const versions = group.map(({ version, versionEvidence, ...context }) => {
      // Scope, aliases/revisions, targets, feeds, fixes and function/platform/Go
      // evidence must agree. Broader per-version enrichment needs its own reducer.
      if (canonicalJson(context) !== expected) throw new SourceAttention("version_set_context_mismatch");
      return { version, versionEvidence };
    });
    const aggregate: VersionSetInput = { ...common, aggregationVersion: 1, versions };
    versionInputs(aggregate);
    return aggregate;
  });
}
