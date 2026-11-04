import { describe, expect, it } from "vitest";
import { decide } from "./matcher.js";
import type { FindingInput } from "./model.js";
import { canonicalJson, findingIdentity, sha256 } from "./identity.js";
import { binding, closure, finding, goScan } from "./test/fixtures.js";

function withEpss(probability: number | null): FindingInput {
  const input = finding();
  input.provenance.epss!.probability = probability;
  return input;
}

function urgent(): FindingInput {
  const input = finding({ scope: "development", functions: closure() });
  input.provenance.kev!.aliases = ["CVE-2026-12345"];
  return input;
}

describe("deterministic report-only rules", () => {
  it("rule 0 records independent provenance and a reproducible input digest on every result", () => {
    const input = finding();
    const result = decide(input);
    expect(result.provenance).toEqual(input.provenance);
    expect(result.inputSha256).toBe(sha256(canonicalJson(input)));
    expect(decide(structuredClone(input))).toEqual(result);
    input.provenance.kev!.catalogVersion = "changed-after-decision";
    expect(result.provenance.kev!.catalogVersion).toBe("2026.11.04");
    expect(result.trace[0]).toBe(0);
  });

  it("rule 1 exclusion and withdrawal precede KEV, while uncertain exclusion does not", () => {
    const outside = urgent();
    outside.versionEvidence.status = "outside";
    expect(decide(outside)).toMatchObject({ matchedRule: 1, applicability: "dropped", delivery: "none" });
    outside.versionEvidence.artifactDigest = "old";
    expect(decide(outside)).toMatchObject({ matchedRule: 2, priority: 0 });
    const withdrawn = urgent();
    withdrawn.aliases[0]!.withdrawn = "2026-11-03T00:00:00Z";
    expect(decide(withdrawn).matchedRule).toBe(1);
    withdrawn.aliases[0]!.withdrawn = "bad metadata";
    withdrawn.provenance.kev!.aliases = [];
    expect(decide(withdrawn)).toMatchObject({ matchedRule: 8, applicability: "unknown" });
  });

  it("stale range exclusion cannot drop a revised advisory", () => {
    const input = finding();
    input.versionEvidence.status = "outside";
    input.aliases[0]!.modified = "2026-11-03T00:00:00Z";
    expect(decide(input)).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding" });
  });

  it.each(["platform", "go", "functions"] as const)("stale %s proof cannot suppress a revised advisory", kind => {
    const input = finding({ functions: closure() });
    if (kind === "platform") Object.assign(input, { ecosystem: "crates.io", platform: {
      complete: true, tool: "rustsec", ...binding(), buildTargets: ["linux/amd64"], excludedTargets: ["linux/amd64"],
    } });
    if (kind === "go") Object.assign(input, { ecosystem: "Go", go: { ...goScan(), status: "package_only" } });
    input.aliases[0]!.modified = "2026-11-03T00:00:00Z";
    input.versionEvidence.advisoryModified = input.aliases[0]!.modified;
    expect(decide(input)).toMatchObject({ matchedRule: 8, applicability: "unknown", proposedVex: null });
  });

  it("rule 2 traverses aliases/upstream and cannot be lowered or weekly batched", () => {
    const input = urgent();
    input.aliases.push({ id: "CVE-2026-12345", upstream: ["MAL-2026-1"], aliases: [], modified: null, withdrawn: null });
    input.provenance.kev = null;
    expect(decide(input)).toMatchObject({ matchedRule: 2, applicability: "affected", priority: 0, delivery: "immediate", slaDays: 1, proposedVex: null });
    expect(decide(urgent()).priority).toBe(0);
  });

  it("rule 3 proposes expiring all-alias VEX only for complete RustSec target exclusion", () => {
    const input = finding({ ecosystem: "crates.io", platform: {
      complete: true, tool: "rustsec", ...binding(),
      buildTargets: ["linux/amd64"], excludedTargets: ["linux/amd64"],
    } });
    expect(decide(input)).toMatchObject({ matchedRule: 3, delivery: "none", applicability: "not_affected", proposedVex: {
      aliases: ["CVE-2026-12345", "GHSA-example"], expiresAt: "2027-02-02T04:30:00.000Z",
      artifactDigest: "sha256:artifact", justification: "vulnerable_code_not_present",
    } });
    for (const patch of [{ complete: false }, { artifactDigest: "old" }, { buildTargets: [] }, { tool: "unversioned" }]) {
      expect(decide({ ...input, platform: { ...input.platform!, ...patch } })).toMatchObject({ applicability: "unknown", matchedRule: 8, proposedVex: null });
    }
    input.buildTargets.push("darwin/arm64");
    expect(decide(input).applicability).toBe("unknown");
  });

  it.each(["package_only", "module_only"] as const)("rule 4 complete Go %s evidence proposes execute-path VEX", status => {
    expect(decide(finding({ ecosystem: "Go", go: { ...goScan(), status } }))).toMatchObject({
      matchedRule: 4, applicability: "not_affected", proposedVex: { justification: "vulnerable_code_not_in_execute_path" },
    });
  });

  it("rule 4 symbol hit jumps over contradictory function absence to remediation", () => {
    const result = decide(finding({ ecosystem: "Go", go: goScan(), functions: closure(), fixedVersion: "1.0.1", compatibleFixVerified: true }));
    expect(result).toMatchObject({ matchedRule: 6, applicability: "affected", proposedVex: null });
    expect(result.trace).toEqual([0, 4, 6, 7]);
  });

  it.each([
    { complete: false }, { targets: ["darwin/arm64"] }, { tags: ["different"] },
    { reflectOrUnsafe: true }, { status: "failed" as const }, { artifactDigest: "old" },
  ])("rule 4 incomplete/mismatched/reflect Go evidence goes directly to residual: %j", patch => {
    expect(decide(finding({ ecosystem: "Go", go: { ...goScan(), ...patch }, fixedVersion: "1.0.1", compatibleFixVerified: true })))
      .toMatchObject({ matchedRule: 8, applicability: "unknown", proposedRemediation: null, proposedVex: null });
  });

  it("rule 5 distinguishes full-closure absence, own hits, and dependency hits", () => {
    const input = finding({ functions: closure(), fixedVersion: "1.0.1", compatibleFixVerified: true });
    expect(decide(input)).toMatchObject({ matchedRule: 5, applicability: "not_affected", proposedRemediation: null });
    input.functions!.ownHits = 1;
    expect(decide(input)).toMatchObject({ matchedRule: 6, applicability: "affected" });
    input.functions!.dependencyHits = 1;
    expect(decide(input)).toMatchObject({ matchedRule: 8, applicability: "unknown", proposedRemediation: null });
    input.compatibleFixVerified = false;
    input.functions!.dependencyHits = 0;
    expect(decide(input)).toMatchObject({ matchedRule: 8, applicability: "affected" });
  });

  it.each([
    { fullDependencyClosure: false }, { allSourcesAvailable: false }, { confirmedInAdvisory: false },
    { complete: false }, { artifactDigest: "old" }, { ownHits: -1 }, { dependencyHits: 0.5 },
  ])("rule 5 missing evidence never proves not affected: %j", patch => {
    expect(decide(finding({ functions: { ...closure(), ...patch } }))).toMatchObject({
      matchedRule: 8, applicability: "unknown", proposedVex: null,
    });
  });

  it("rule 6 no-function-data still permits a compatible fix but does not invent reachability", () => {
    expect(decide(finding({ fixedVersion: "1.0.1", compatibleFixVerified: true, direct: false }))).toMatchObject({
      matchedRule: 6, applicability: "unknown", proposedRemediation: { kind: "grouped_dependabot_security_pr" },
    });
  });

  it.each([
    ["crates.io", "example-package", "cargo update -p example-package --precise 1.0.1"],
    ["Go", "example.org/module", "go get example.org/module@1.0.1"],
    ["PyPI", "example-package", "uv lock --upgrade-package example-package"],
  ] as const)("rule 6 %s transitive proposal has an exact command", (ecosystem, pkg, command) => {
    const result = decide(finding({ ecosystem, package: pkg, direct: false, fixedVersion: "1.0.1", compatibleFixVerified: true,
      go: ecosystem === "Go" ? goScan() : null }));
    expect(result.proposedRemediation).toEqual({ kind: "command", command, package: pkg, fixedVersion: "1.0.1" });
  });

  it("rule 6 does not propose executable advisory interpolation", () => {
    expect(decide(finding({ package: "pkg;command", fixedVersion: "1.0.1", compatibleFixVerified: true })).proposedRemediation).toBeNull();
    expect(decide(finding({ fixedVersion: "1.0.1;command", compatibleFixVerified: true })).proposedRemediation).toBeNull();
  });

  it.each([
    ["runtime", 1, "finding"], ["mixed", 1, "finding"], ["unknown", 1, "finding"], ["development", 2, "weekly"],
  ] as const)("rule 7 post-pass applies once after fix routing for %s scope", (scope, priority, delivery) => {
    const input = withEpss(0.04);
    Object.assign(input, { scope, fixedVersion: "1.0.1", compatibleFixVerified: true });
    expect(decide(input)).toMatchObject({ matchedRule: 6, priority, delivery });
    expect(decide(input).trace.filter(rule => rule === 7)).toHaveLength(1);
  });

  it("rule 7 saturates at P3; low runtime and all dev delivery batch weekly", () => {
    expect(decide(finding({ scope: "development" }))).toMatchObject({ priority: 3, delivery: "weekly", slaDays: 90 });
    expect(decide(finding({ scope: "development", severity: "low" })).priority).toBe(3);
    expect(decide(finding({ severity: "low" }))).toMatchObject({ priority: 3, delivery: "weekly" });
  });

  it("rule 8 records unknown and no negative/remediation effect when evidence is missing", () => {
    expect(decide(finding())).toMatchObject({ matchedRule: 8, applicability: "unknown", priority: 2, slaDays: 30 });
    const input = finding({ functions: closure() });
    input.provenance.kev = null;
    expect(decide(input)).toMatchObject({ matchedRule: 8, applicability: "unknown", proposedVex: null });
    input.provenance.observedAt = "invalid";
    expect(decide(input).applicability).toBe("unknown");
    input.aliases = [];
    expect(decide(input).applicability).toBe("unknown");
  });

  it.each([null, NaN, -0.01, 1.1])("missing/invalid EPSS %s uses severity, not percentile", probability => {
    const input = withEpss(probability);
    expect(decide(input).priority).toBe(2);
    expect(decide(input).reasons[0]).toContain("severity fallback");
  });

  it("priority thresholds use EPSS probability and runtime Critical, then CVSS4/High", () => {
    expect(decide(withEpss(0.03999)).priority).toBe(2);
    expect(decide(withEpss(0.04)).priority).toBe(1);
    expect(decide(finding({ severity: "critical" })).priority).toBe(1);
    expect(decide(finding({ severity: "critical", scope: "mixed" })).priority).toBe(1);
    expect(decide(finding({ severity: "unknown", cvss4Base: 7 })).priority).toBe(2);
    expect(decide(finding({ severity: "unknown", cvss4Base: 10.1 })).priority).toBe(3);
  });
});

const negativeProofs = [
  { name: "range exclusion", rule: 1, create: () => {
    const input = finding();
    input.versionEvidence.status = "outside";
    return { input, evidence: input.versionEvidence };
  } },
  { name: "RustSec target exclusion", rule: 3, create: () => {
    const platform = { ...binding(), complete: true, tool: "rustsec",
      buildTargets: ["linux/amd64"], excludedTargets: ["linux/amd64"] };
    return { input: finding({ ecosystem: "crates.io", platform }), evidence: platform };
  } },
  { name: "Go symbol absence", rule: 4, create: () => {
    const go = { ...goScan(), status: "package_only" as const };
    return { input: finding({ ecosystem: "Go", go }), evidence: go };
  } },
  { name: "full-closure function absence", rule: 5, create: () => {
    const functions = closure();
    return { input: finding({ functions }), evidence: functions };
  } },
];

describe("negative proof tool-version coverage", () => {
  it.each(negativeProofs)("keeps complete, versioned $name evidence eligible", ({ create, rule }) => {
    expect(decide(create().input)).toMatchObject({ matchedRule: rule, delivery: "none" });
  });

  it.each(negativeProofs.flatMap(proof => [undefined, "", " ", "\t\n"].map(version => ({ ...proof, version }))))(
    "holds $name with missing/blank tool version $version before negative or fix proposals", ({ create, version }) => {
      const { input, evidence } = create();
      if (version === undefined) delete input.provenance.toolVersions[evidence.tool];
      else input.provenance.toolVersions[evidence.tool] = version;
      input.fixedVersion = "1.0.1";
      input.compatibleFixVerified = true;
      const before = structuredClone(input);
      const result = decide(input);
      expect(result).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding",
        proposedVex: null, proposedRemediation: null, provenance: before.provenance });
      expect(input).toEqual(before);
      expect(decide(structuredClone(input))).toEqual(result);
    },
  );

  it.each(["toString", "constructor", "__proto__"].flatMap(tool => ["range", "functions"].map(kind => ({ tool, kind }))))(
    "does not mistake inherited $tool for a recorded $kind tool version", ({ tool, kind }) => {
      const { input, evidence } = negativeProofs[kind === "range" ? 0 : 3]!.create();
      evidence.tool = tool;
      input.provenance.toolVersions = kind === "functions" ? { "osv-range": "fixture-1" } : {};
      expect(decide(input)).toMatchObject({ matchedRule: 8, applicability: "unknown", delivery: "finding",
        proposedVex: null, proposedRemediation: null });
    },
  );

  it.each(["toString", "constructor", "__proto__"].flatMap(tool => ["range", "functions"].map(kind => ({ tool, kind }))))(
    "keeps an explicit own $tool version as ordinary $kind provenance", ({ tool, kind }) => {
      const proof = negativeProofs[kind === "range" ? 0 : 3]!;
      const { input, evidence } = proof.create();
      evidence.tool = tool;
      input.provenance.toolVersions = { [tool]: "fixture-1" };
      // Function absence still depends on the separately versioned affected-range proof.
      if (kind === "functions") input.provenance.toolVersions["osv-range"] = "fixture-1";
      expect(decide(input)).toMatchObject({ matchedRule: proof.rule, delivery: "none" });
    },
  );

  it.each(["KEV", "MAL"])("missing range-tool provenance cannot suppress %s P0", kind => {
    const input = urgent();
    input.versionEvidence.status = "outside";
    input.versionEvidence.tool = "toString";
    input.provenance.toolVersions = {};
    if (kind === "MAL") {
      input.aliases[0]!.aliases.push("MAL-2026-1");
      input.provenance.kev = null;
    }
    expect(decide(input)).toMatchObject({ matchedRule: 2, applicability: "affected", priority: 0,
      delivery: "immediate", proposedVex: null, proposedRemediation: null });
  });
});

describe("finding identities", () => {
  it("uses canonical repo, remediation unit, and the lexical minimum over the complete alias graph", () => {
    const input = finding({ repo: "Example/Service" });
    input.aliases.push({ id: "GHSA-other", aliases: ["CVE-2026-12345", "CVE-2025-10000"], upstream: ["GO-2025-1"], modified: null, withdrawn: null });
    const identity = findingIdentity(input);
    expect(identity).toMatchObject({ repo: "example/service", aliasGroup: "CVE-2025-10000", remediationUnit: "npm:example-package@unfixed" });
    expect(identity.aliases).toEqual(["CVE-2025-10000", "CVE-2026-12345", "GHSA-example", "GHSA-other", "GO-2025-1"]);
    expect(identity.originId).toBe(sha256(`${identity.repo}|${identity.remediationUnit}|${identity.aliasGroup}`));
    input.aliases.reverse();
    expect(findingIdentity(input)).toEqual(identity);
  });

  it("modified time, artifact and EPSS do not mutate identity, but fix target and alias minimum do", () => {
    const input = finding();
    const identity = findingIdentity(input);
    input.aliases[0]!.modified = "2026-11-04T00:00:00Z";
    input.provenance.artifactDigest = "new artifact";
    input.provenance.epss!.date = "2026-11-05";
    expect(findingIdentity(input)).toEqual(identity);
    input.fixedVersion = "1.0.1";
    expect(findingIdentity(input).originId).not.toBe(identity.originId);
    input.fixedVersion = null;
    input.aliases[0]!.aliases.push("CVE-2020-1");
    expect(findingIdentity(input).originId).not.toBe(identity.originId);
  });

  it("rejects ambiguous delimiters instead of sharing an origin", () => {
    expect(() => findingIdentity(finding({ package: "a|b" }))).toThrow("identity component");
  });
});
