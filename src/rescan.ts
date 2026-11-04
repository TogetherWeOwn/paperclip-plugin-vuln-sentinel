import { canonicalJson, sha256 } from "./identity.js";
import type { FindingInput } from "./model.js";
import type { RoutingMember } from "./routing.js";

/** Trusted-adapter output, never a raw scanner callback or a user assertion. */
export interface RescanEvidence {
  companyId: string;
  repo: string;
  findingId: string;
  decisionId: string;
  ecosystem: FindingInput["ecosystem"];
  package: string;
  aliases: string[];
  advisoryModified: string | null;
  previousArtifactDigest: string;
  artifactDigest: string;
  artifactKind: NonNullable<FindingInput["provenance"]["artifactKind"]>;
  sourceRevision: string;
  startedAt: string;
  completedAt: string;
  status: "absent" | "present" | "unknown" | "failed";
  reportSha256: string;
  tool: string;
  toolVersions: Record<string, string>;
  bindingEvidenceRef: string;
  lineageEvidenceRef: string;
  coverage: {
    complete: boolean;
    unfiltered: boolean;
    fullLockfile: boolean;
    fullDependencyClosure: boolean;
    runtimeCompleteness: "proven" | "not_proven";
    completenessEvidenceRef: string;
    buildTargets: string[];
    deployedTags: string[];
  };
}

export interface ResolutionRecord {
  evidenceId: string;
  recordedAt: string;
  evidence: RescanEvidence;
}

const text = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
const time = (value: string) => /^\d{4}-\d{2}-\d{2}T/.test(value) ? Date.parse(value) : NaN;
const hash = (value: string) => /^[a-f0-9]{64}$/.test(value);
const contains = (actual: string[], expected: string[]) => Array.isArray(actual)
  && actual.every(text) && expected.every(value => actual.includes(value));
const same = (actual: string[], expected: string[]) => contains(actual, expected) && contains(expected, actual);

export const rescanEvidenceId = (evidence: RescanEvidence): string => sha256(canonicalJson(evidence));

/** Return a hold reason; absence alone, including native Rust absence, is never proof. */
export function rescanRejection(member: RoutingMember, input: FindingInput, evidence: RescanEvidence, now: string): string | null {
  if (evidence.findingId !== member.findingId || evidence.decisionId !== member.decisionId
    || evidence.ecosystem !== member.ecosystem || evidence.package !== member.package
    || !contains(evidence.aliases, member.aliases) || evidence.advisoryModified !== member.advisoryModified) {
    return "Rescan does not cover the current finding, alias closure and advisory revision";
  }
  if (!input.provenance.artifactKind || evidence.artifactKind !== input.provenance.artifactKind
    || evidence.previousArtifactDigest !== member.artifactDigest
    || !/^sha256:[a-f0-9]{64}$/.test(evidence.artifactDigest)
    || evidence.artifactDigest === member.artifactDigest
    || !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/.test(evidence.sourceRevision)
    || !text(evidence.bindingEvidenceRef) || !text(evidence.lineageEvidenceRef)) {
    return "A new immutable artifact of the same kind needs verified source/deployment binding and lineage";
  }
  if (!Number.isFinite(time(now)) || !member.observedAt || !Number.isFinite(time(member.observedAt))
    || !Number.isFinite(time(evidence.startedAt)) || !Number.isFinite(time(evidence.completedAt))
    || time(evidence.startedAt) <= time(member.observedAt)
    || time(evidence.completedAt) < time(evidence.startedAt) || time(evidence.completedAt) > time(now)) {
    return "Rescan timing is missing, stale, reversed or in the future";
  }
  if (evidence.status !== "absent" || !hash(evidence.reportSha256)
    || !text(evidence.tool) || !evidence.toolVersions || !text(evidence.toolVersions[evidence.tool])
    || !Object.keys(evidence.toolVersions).length
    || !Object.entries(evidence.toolVersions).every(([tool, version]) => text(tool) && text(version))) {
    return "A successful absent result needs a hashed report and pinned tool provenance";
  }
  const coverage = evidence.coverage;
  if (!coverage || coverage.complete !== true || coverage.unfiltered !== true || coverage.fullLockfile !== true
    || !text(coverage.completenessEvidenceRef)
    || !same(coverage.buildTargets, input.buildTargets) || !same(coverage.deployedTags, input.deployedTags)
    || (evidence.artifactKind !== "lockfile" && (coverage.fullDependencyClosure !== true
      || coverage.runtimeCompleteness !== "proven"))) {
    return "Complete relevant coverage is unproven; lockfile-only/native absence cannot resolve a finding";
  }
  return null;
}
