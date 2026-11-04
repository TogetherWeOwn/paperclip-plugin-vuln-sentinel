import type { FindingInput } from "../model.js";

export function finding(patch: Partial<FindingInput> = {}): FindingInput {
  return {
    repo: "example/service", ecosystem: "npm", package: "example-package", version: "1.0.0",
    fixedVersion: null, compatibleFixVerified: false, direct: true,
    advisoryId: "GHSA-example",
    aliases: [{ id: "GHSA-example", aliases: ["CVE-2026-12345"], upstream: [], modified: "2026-11-01T00:00:00Z", withdrawn: null }],
    versionEvidence: { status: "affected", ...binding(), tool: "osv-range", complete: true },
    scope: "runtime", severity: "high", cvss4Base: null, buildTargets: ["linux/amd64"], deployedTags: [],
    platform: null, go: null, functions: null,
    provenance: {
      observedAt: "2026-11-04T04:30:00Z", artifactDigest: "sha256:artifact",
      source: { kind: "osv", queriedAt: "2026-11-04T04:29:00Z", snapshotSha256: null },
      epss: { date: "2026-11-04", modelVersion: "v5", probability: 0.01 },
      kev: { catalogVersion: "2026.11.04", aliases: [] },
      toolVersions: { rustsec: "fixture-1", govulncheck: "fixture-1", "closure-grep": "fixture-1", "osv-range": "fixture-1" },
    },
    ...patch,
  };
}

export const binding = () => ({
  artifactDigest: "sha256:artifact", advisoryId: "GHSA-example", advisoryModified: "2026-11-01T00:00:00Z",
});

export const closure = () => ({
  complete: true, tool: "closure-grep", ...binding(),
  confirmedInAdvisory: true, fullDependencyClosure: true, allSourcesAvailable: true,
  ownHits: 0, dependencyHits: 0,
});

export const goScan = () => ({
  complete: true, tool: "govulncheck", ...binding(),
  targets: ["linux/amd64"], tags: [], status: "symbol_hit" as const, reflectOrUnsafe: false,
});
