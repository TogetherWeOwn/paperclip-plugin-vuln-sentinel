import type { FindingInput } from "../model.js";
import type { RescanEvidence } from "../rescan.js";
import type { RoutingMember } from "../routing.js";

export function rescan(member: RoutingMember, input: FindingInput): RescanEvidence {
  return {
    companyId: "company-a", repo: input.repo, findingId: member.findingId, decisionId: member.decisionId,
    ecosystem: input.ecosystem, package: input.package, aliases: [...member.aliases],
    advisoryModified: member.advisoryModified, previousArtifactDigest: member.artifactDigest,
    artifactDigest: `sha256:${"a".repeat(64)}`, artifactKind: input.provenance.artifactKind!,
    sourceRevision: "b".repeat(40), startedAt: "2026-11-05T04:00:00Z", completedAt: "2026-11-05T04:15:00Z",
    status: "absent", reportSha256: "c".repeat(64), tool: "scanner", toolVersions: { scanner: "fixture-1" },
    bindingEvidenceRef: "fixture-source-and-deployment-binding", lineageEvidenceRef: "fixture-same-artifact-lineage",
    coverage: {
      complete: true, unfiltered: true, fullLockfile: true, fullDependencyClosure: true, runtimeCompleteness: "proven",
      completenessEvidenceRef: "fixture-independent-completeness-proof",
      buildTargets: [...input.buildTargets], deployedTags: [...input.deployedTags],
    },
  };
}
