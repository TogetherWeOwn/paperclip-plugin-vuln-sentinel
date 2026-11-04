export const RULES_VERSION = "1.0.0";

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

export interface Provenance {
  observedAt: string;
  artifactDigest: string;
  artifactKind?: "lockfile" | "image" | "go_binary" | "rust_binary" | "worker_bundle";
  source: { kind: "osv"; queriedAt: string; snapshotSha256: string | null }
    | { kind: "dependabot"; updatedAt: string };
  epss: { date: string; modelVersion: string; probability: number | null } | null;
  kev: { catalogVersion: string; aliases: string[] } | null;
  toolVersions: Record<string, string>;
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
}
