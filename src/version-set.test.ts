import { describe, expect, it } from "vitest";
import { canonicalJson, findingIdentity, sha256 } from "./identity.js";
import { decide } from "./matcher.js";
import type { FindingInput, VersionSetInput } from "./model.js";
import { binding, closure, finding, goScan } from "./test/fixtures.js";
import { aggregateFindingInputs, versionInputs } from "./version-set.js";

const tuple = (version: string, status: FindingInput["versionEvidence"]["status"], patch: Partial<FindingInput> = {}) => finding({
  version, functions: { ...closure(), ownHits: 1 },
  versionEvidence: { ...binding(), status, complete: status !== "unknown", tool: "osv-range" }, ...patch,
});
const group = (inputs: FindingInput[]): VersionSetInput => {
  const result = aggregateFindingInputs(inputs);
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty("versions");
  return result[0] as VersionSetInput;
};

const statuses = ["affected", "outside", "unknown"] as const;
describe("same-action all-version aggregation", () => {
  it.each(statuses.flatMap(a => statuses.map(b => [a, b] as const)))("reduces %s + %s without hash/timestamp ordering", (a, b) => {
    const inputs = [tuple("1.0.0", a), tuple("3.0.0", b)];
    const input = group(inputs);
    const result = decide(input);
    expect(result.applicability).toBe(a === "affected" || b === "affected" ? "affected"
      : a === "unknown" || b === "unknown" ? "unknown" : "dropped");
    expect(result.identity).toEqual(findingIdentity(inputs[0]!));
    expect(result.versionDecisions).toEqual(inputs.map(value => {
      const decision = decide(value);
      return { version: value.version, inputSha256: decision.inputSha256, applicability: decision.applicability,
        matchedRule: decision.matchedRule, trace: decision.trace };
    }));
    expect(result.proposedVex).toBeNull();
    expect(result.delivery === "none").toBe(a === "outside" && b === "outside");
  });

  it("keeps the original per-tuple residual semantics when only range evidence proves affectedness", () => {
    const result = decide(group([tuple("1", "outside", { functions: null }), tuple("2", "affected", { functions: null })]));
    expect(result).toMatchObject({ applicability: "unknown", matchedRule: 8, delivery: "finding", proposedVex: null });
  });

  it("retains every tuple as reproducible evidence and does not mutate caller input", () => {
    const inputs = [tuple("3.0.0", "outside"), tuple("1.0.0", "affected"), tuple("2.0.0", "unknown")];
    const before = structuredClone(inputs);
    const input = group(inputs);
    expect(inputs).toEqual(before);
    expect(versionInputs(input)).toEqual([before[1], before[2], before[0]]);
    const result = decide(input);
    expect(input.provenance).toEqual(before[0]!.provenance);
    expect(result.inputSha256).toBe(sha256(canonicalJson(input)));
    expect(result.rulesVersion).toBe("1.0.7+all-versions.1");
    expect(decide(structuredClone(input))).toEqual(result);
  });

  it("is invariant across every enumeration of a three-version set", () => {
    const a = tuple("1", "affected"), b = tuple("2", "unknown"), c = tuple("3", "outside");
    const expected = decide(group([a, b, c]));
    for (const inputs of [[a, c, b], [b, a, c], [b, c, a], [c, a, b], [c, b, a]]) {
      expect(decide(group(inputs))).toEqual(expected);
    }
  });

  it("changes revision hash even when only a non-winning tuple's evidence changes", () => {
    const input = group([tuple("1", "affected"), tuple("2", "outside")]);
    const changed = structuredClone(input);
    changed.versions[1]!.versionEvidence.complete = false;
    expect(decide(changed).inputSha256).not.toBe(decide(input).inputSha256);
    expect(decide(changed).applicability).toBe("affected");
  });

  it("never lets an outside tuple suppress an active KEV version or dev-scope P0", () => {
    const patch = { scope: "development" as const, provenance: { ...finding().provenance,
      kev: { catalogVersion: "fixture", aliases: ["CVE-2026-12345"] } } };
    expect(decide(group([tuple("1", "outside", patch), tuple("2", "unknown", patch)]))).toMatchObject({
      applicability: "affected", matchedRule: 2, priority: 0, slaDays: 1, delivery: "immediate", proposedVex: null,
    });
  });

  it("holds every outside tuple when matching artifact digests are blank", () => {
    const inputs = [tuple("1.0.0", "outside"), tuple("2.0.0", "outside")];
    for (const input of inputs) {
      input.provenance.artifactDigest = " ";
      input.versionEvidence.artifactDigest = " ";
    }
    const input = group(inputs);
    const before = structuredClone(input);
    const result = decide(input);
    expect(result).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding",
      proposedVex: null, proposedRemediation: null });
    expect(result.versionDecisions).toHaveLength(2);
    expect(result.versionDecisions!.every(decision => decision.applicability === "unknown")).toBe(true);
    expect(input).toEqual(before);
    expect(decide(structuredClone(input))).toEqual(result);
  });

  it("preserves rule 1 over P0 when every version has complete negative evidence", () => {
    const patch = { provenance: { ...finding().provenance, kev: { catalogVersion: "fixture", aliases: ["CVE-2026-12345"] } } };
    expect(decide(group([tuple("1", "outside", patch), tuple("2", "outside", patch)]))).toMatchObject({
      applicability: "dropped", matchedRule: 1, delivery: "none", proposedVex: null,
    });
  });

  it("requires every non-dropped tuple's negative proof before proposing full-set VEX", () => {
    const patch = { functions: closure() };
    expect(decide(group([tuple("1", "outside", patch), tuple("2", "affected", patch)]))).toMatchObject({
      applicability: "not_affected", matchedRule: 5, delivery: "none", proposedVex: { justification: "vulnerable_code_not_present" },
    });
    expect(decide(group([tuple("1", "unknown", patch), tuple("2", "affected", patch)]))).toMatchObject({
      applicability: "unknown", matchedRule: 8, delivery: "finding", proposedVex: null,
    });
  });

  it.each(["blank", "inherited"])("holds all outside tuples when range-tool provenance is %s", kind => {
    const inputs = [tuple("1.0.0", "outside"), tuple("2.0.0", "outside")];
    for (const input of inputs) {
      if (kind === "blank") input.provenance.toolVersions["osv-range"] = "\t ";
      else {
        input.versionEvidence.tool = "constructor";
        input.provenance.toolVersions = {};
      }
    }
    const result = decide(group(inputs));
    expect(result).toMatchObject({ rulesVersion: "1.0.7+all-versions.1", applicability: "unknown",
      matchedRule: 8, delivery: "finding", proposedVex: null, proposedRemediation: null });
    expect(result.versionDecisions).toHaveLength(2);
    for (const decision of result.versionDecisions!) {
      expect(decision).toMatchObject({ applicability: "unknown", matchedRule: 8 });
    }
  });

  it("keeps blank KEV coverage unknown across all installed tuples instead of proposing VEX", () => {
    const patch = { functions: closure(), provenance: { ...finding().provenance,
      kev: { catalogVersion: "\t ", aliases: [] } } };
    const input = group([tuple("1", "outside", patch), tuple("2", "affected", patch)]);
    const before = structuredClone(input);
    const result = decide(input);
    expect(result).toMatchObject({ applicability: "unknown", matchedRule: 8, delivery: "finding",
      proposedVex: null, proposedRemediation: null });
    expect(result.versionDecisions!.map(decision => decision.applicability)).toEqual(["dropped", "unknown"]);
    expect(input).toEqual(before);
    expect(decide(structuredClone(input))).toEqual(result);
  });

  it.each(["status", "reflectOrUnsafe"] as const)("holds all-version Go VEX when %s is missing", field => {
    const patch = { ecosystem: "Go" as const, go: { ...goScan(), status: "package_only" as const } };
    Reflect.deleteProperty(patch.go, field);
    const input = group([tuple("1", "outside", patch), tuple("2", "affected", patch)]);
    const before = structuredClone(input);
    const result = decide(input);
    expect(result).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding",
      proposedVex: null, proposedRemediation: null });
    expect(result.versionDecisions!.map(decision => decision.applicability)).toEqual(["dropped", "unknown"]);
    expect(input).toEqual(before);
    expect(decide(structuredClone(input))).toEqual(result);
  });

  it("does not drop an all-version action when one range completeness flag is nonboolean", () => {
    const inputs = [tuple("1", "outside"), tuple("2", "outside")];
    Object.assign(inputs[1]!.versionEvidence, { complete: "false" });
    const input = group(inputs);
    const before = structuredClone(input);
    const result = decide(input);
    expect(result).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding",
      proposedVex: null, proposedRemediation: null });
    expect(result.versionDecisions!.map(decision => decision.applicability)).toEqual(["dropped", "unknown"]);
    expect(input).toEqual(before);
    expect(decide(structuredClone(input))).toEqual(result);
  });

  it.each(["confirmedInAdvisory", "fullDependencyClosure", "allSourcesAvailable"] as const)(
    "holds all-version function VEX when %s is truthy but nonboolean", field => {
      const patch = { functions: closure() };
      Object.assign(patch.functions, { [field]: "false" });
      const input = group([tuple("1", "outside", patch), tuple("2", "affected", patch)]);
      const before = structuredClone(input);
      const result = decide(input);
      expect(result).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding",
        proposedVex: null, proposedRemediation: null });
      expect(result.versionDecisions!.map(decision => decision.applicability)).toEqual(["dropped", "unknown"]);
      expect(input).toEqual(before);
      expect(decide(structuredClone(input))).toEqual(result);
    },
  );

  it("holds all-version fix proposals when compatibility verification is nonboolean", () => {
    const patch = { fixedVersion: "4.0.0", compatibleFixVerified: true };
    Object.assign(patch, { compatibleFixVerified: "false" });
    const input = group([tuple("1", "outside", patch), tuple("2", "affected", patch)]);
    const before = structuredClone(input);
    const result = decide(input);
    expect(result).toMatchObject({ matchedRule: 8, applicability: "affected", delivery: "finding",
      proposedVex: null, proposedRemediation: null });
    expect(result.versionDecisions!.map(decision => decision.applicability)).toEqual(["dropped", "affected"]);
    expect(input).toEqual(before);
    expect(decide(structuredClone(input))).toEqual(result);
  });

  it("keeps dev priority/SLA and compatible fix proposals separate from negative tuples", () => {
    const patch = { scope: "development" as const, fixedVersion: "4.0.0", compatibleFixVerified: true };
    expect(decide(group([tuple("1", "outside", patch), tuple("2", "affected", patch)]))).toMatchObject({
      applicability: "affected", matchedRule: 6, priority: 3, slaDays: 90, delivery: "weekly",
      proposedRemediation: { kind: "grouped_dependabot_security_pr", fixedVersion: "4.0.0" },
    });
  });

  it("groups only an identical remediation identity, retaining independent actions and singleton behavior", () => {
    const inputs = [tuple("1", "affected"), tuple("2", "outside"), tuple("3", "affected", { package: "other" }),
      tuple("4", "affected", { fixedVersion: "5" })];
    const actions = aggregateFindingInputs(inputs);
    expect(actions).toHaveLength(3);
    expect(actions.filter(action => "versions" in action)).toHaveLength(1);
    expect(aggregateFindingInputs([inputs[0]!])).toEqual([inputs[0]]);
    expect(aggregateFindingInputs([])).toEqual([]);
    expect(actions.map(action => findingIdentity(action).originId)).toEqual(actions.map(action => findingIdentity(action).originId).sort());
  });

  it.each([
    { scope: "development" }, { direct: false }, { compatibleFixVerified: true }, { severity: "critical" }, { cvss4Base: 9 },
    { aliases: [...finding().aliases, { id: "CVE-2026-12345", aliases: [], upstream: [], modified: null, withdrawn: null }] },
    { buildTargets: ["other"] }, { deployedTags: ["other"] }, { functions: null },
    { platform: { ...binding(), complete: true, tool: "rustsec", buildTargets: [], excludedTargets: [] } },
    { provenance: { ...finding().provenance, observedAt: "2026-11-05T00:00:00Z" } },
    { provenance: { ...finding().provenance, artifactDigest: "other" } },
    { provenance: { ...finding().provenance, osvSnapshotId: "other" } },
  ] satisfies Partial<FindingInput>[]) ("holds incompatible non-version context: %j", patch => {
    expect(() => group([tuple("1", "affected"), tuple("2", "outside", patch)])).toThrow("version_set_context_mismatch");
  });

  it("rejects duplicate versions, even when their evidence happens to agree", () => {
    expect(() => group([tuple("1", "affected"), tuple("1", "affected")])).toThrow("invalid_version_set");
    expect(() => group([tuple("1", "affected"), tuple("1", "outside")])).toThrow("invalid_version_set");
  });

  it.each(["empty", "single", "unsorted", "duplicate", "nested", "wrong_version", "header_tuple", "capacity", "missing_set", "version_type"])("rejects malformed group %s", failure => {
    const input = group([tuple("1", "affected"), tuple("2", "outside")]);
    if (failure === "empty") input.versions = [];
    if (failure === "single") input.versions.pop();
    if (failure === "unsorted") input.versions.reverse();
    if (failure === "duplicate") input.versions[1]!.version = "1";
    if (failure === "nested") Object.assign(input.versions[1]!, { versions: [] });
    if (failure === "wrong_version") Object.assign(input, { aggregationVersion: 2 });
    if (failure === "header_tuple") Object.assign(input, { version: "pretend-single" });
    if (failure === "capacity") input.versions = Array.from({ length: 2001 }, (_, i) => ({ ...input.versions[0]!, version: String(i) }));
    if (failure === "missing_set") {
      Reflect.deleteProperty(input, "versions");
      input.aliases[0]!.withdrawn = "2026-11-02T00:00:00Z";
    }
    if (failure === "version_type") Object.assign(input.versions[1]!, { version: 2 });
    expect(() => decide(input)).toThrow("invalid_version_set");
  });

  it("bounds batch size and forbids feeding an aggregate into the single-input grouping boundary", () => {
    expect(() => aggregateFindingInputs(Array.from({ length: 2001 }, () => finding()))).toThrow("version_set_capacity_exceeded");
    const value = group([tuple("1", "affected"), tuple("2", "outside")]);
    expect(() => aggregateFindingInputs([value as unknown as FindingInput])).toThrow("invalid_version_set");
  });
});
