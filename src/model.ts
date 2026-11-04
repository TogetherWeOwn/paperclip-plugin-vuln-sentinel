export const RULES_VERSION = "1.0.1";

export type Priority = 0 | 1 | 2 | 3;
export type Applicability = "affected" | "not_affected" | "unknown" | "dropped";
export type Scope = "runtime" | "development" | "mixed" | "unknown";
export type Ecosystem = "npm" | "crates.io" | "Go" | "PyPI";

export interface Advisory {
  id: string;
  aliases: string[];
  upstream: string[];
  modified: string | null;
  withdrawn: string | null;
}

export interface SourceSelection {
  pollRevision: number;
  token: string;
  snapshotId: string;
}

export interface Provenance {
  observedAt: string;
  sourceSelection?: SourceSelection;
  osvSnapshotId?: string;
  threatSnapshotId?: string;
  artifactDigest: string;
  artifactKind?: "lockfile" | "image" | "go_binary" | "rust_binary" | "worker_bundle";
  source: { kind: "osv"; queriedAt: string; snapshotSha256: string | null }
    | { kind: "dependabot"; updatedAt: string };
  epss: { date: string; modelVersion: string; probability: number | null; snapshotSha256?: string } | null;
  kev: { catalogVersion: string; aliases: string[]; snapshotSha256?: string } | null;
  toolVersions: Record<string, string>;
  severityAttention?: string[];
}

export interface BoundEvidence {
  artifactDigest: string;
  advisoryId: string;
  advisoryModified: string | null;
  tool: string;
  complete: boolean;
}

export interface PlatformEvidence extends BoundEvidence {
  buildTargets: string[];
  excludedTargets: string[];
}

export interface GoEvidence extends BoundEvidence {
  targets: string[];
  tags: string[];
  status: "symbol_hit" | "package_only" | "module_only" | "failed";
  reflectOrUnsafe: boolean;
}

export interface FunctionEvidence extends BoundEvidence {
  confirmedInAdvisory: boolean;
  fullDependencyClosure: boolean;
  allSourcesAvailable: boolean;
  ownHits: number;
  dependencyHits: number;
}

export interface FindingInput {
  repo: string;
  ecosystem: Ecosystem;
  package: string;
  version: string;
  fixedVersion: string | null;
  compatibleFixVerified: boolean;
  direct: boolean;
  aliases: Advisory[];
  advisoryId: string;
  versionEvidence: BoundEvidence & { status: "affected" | "outside" | "unknown" };
  scope: Scope;
  severity: "critical" | "high" | "moderate" | "low" | "unknown";
  cvss4Base: number | null;
  buildTargets: string[];
  deployedTags: string[];
  platform: PlatformEvidence | null;
  go: GoEvidence | null;
  functions: FunctionEvidence | null;
  provenance: Provenance;
}

/** Same-action installed tuples sharing every non-version input and provenance field. */
export interface VersionSetInput extends Omit<FindingInput, "version" | "versionEvidence"> {
  aggregationVersion: 1;
  versions: Array<Pick<FindingInput, "version" | "versionEvidence">>;
}

export type DecisionInput = FindingInput | VersionSetInput;

export interface FindingIdentity {
  originId: string;
  repo: string;
  remediationUnit: string;
  aliasGroup: string;
  aliases: string[];
}

export type Remediation = { kind: "grouped_dependabot_security_pr"; package: string; fixedVersion: string }
  | { kind: "command"; command: string; package: string; fixedVersion: string };

export interface ProposedVex {
  status: "not_affected";
  justification: "vulnerable_code_not_present" | "vulnerable_code_not_in_execute_path";
  aliases: string[];
  artifactDigest: string;
  expiresAt: string;
}

export interface Decision {
  rulesVersion: string;
  identity: FindingIdentity;
  advisoryModified: string | null;
  applicability: Applicability;
  matchedRule: 1 | 2 | 3 | 4 | 5 | 6 | 8;
  trace: number[];
  priority: Priority;
  slaDays: 1 | 7 | 30 | 90;
  delivery: "none" | "immediate" | "finding" | "weekly";
  proposedRemediation: Remediation | null;
  proposedVex: ProposedVex | null;
  reasons: string[];
  provenance: Provenance;
  inputSha256: string;
  versionDecisions?: Array<{
    version: string;
    inputSha256: string;
    applicability: Applicability;
    matchedRule: Decision["matchedRule"];
    trace: number[];
  }>;
}
