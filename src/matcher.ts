import { canonicalJson, findingIdentity, sha256 } from "./identity.js";
import { RULES_VERSION } from "./model.js";
import type { BoundEvidence, Decision, DecisionInput, FindingInput, Priority, ProposedVex, Remediation } from "./model.js";
import { versionInputs } from "./version-set.js";
import { SourceAttention } from "./source-http.js";

const SLA = [1, 7, 30, 90] as const;
const sameSet = (a: string[], b: string[]) =>
  new Set(a).size === new Set(b).size && a.every(item => b.includes(item));
const validTime = (value: string | null): value is string =>
  value !== null && /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value));

function bound(input: FindingInput, evidence: BoundEvidence): boolean {
  const advisory = input.aliases.find(item => item.id === input.advisoryId);
  return evidence.complete && input.provenance.artifactDigest.length > 0
    && evidence.artifactDigest === input.provenance.artifactDigest
    && evidence.advisoryId === input.advisoryId && validTime(evidence.advisoryModified)
    && evidence.advisoryModified === advisory?.modified
    && !!input.provenance.toolVersions[evidence.tool];
}

function proposedRemediation(input: FindingInput): Remediation | null {
  if (!input.compatibleFixVerified || !input.fixedVersion) return null;
  const { package: pkg, fixedVersion } = input;
  // Advisory-controlled strings may be displayed as commands, never evaluated.
  if (!/^[a-zA-Z0-9@/_.-]+$/.test(pkg) || pkg.startsWith("-")
    || !/^[a-zA-Z0-9][a-zA-Z0-9.+_-]*$/.test(fixedVersion)) return null;
  if (input.direct || input.ecosystem === "npm") {
    return { kind: "grouped_dependabot_security_pr", package: pkg, fixedVersion };
  }
  const command = input.ecosystem === "crates.io" ? `cargo update -p ${pkg} --precise ${fixedVersion}`
    : input.ecosystem === "Go" ? `go get ${pkg}@${fixedVersion}`
      : input.ecosystem === "PyPI" ? `uv lock --upgrade-package ${pkg}` : null;
  return command === null ? null : { kind: "command", command, package: pkg, fixedVersion };
}

export function decide(raw: DecisionInput): Decision {
  if (!("versions" in raw)) {
    if ("aggregationVersion" in raw) throw new SourceAttention("invalid_version_set");
    return decideVersion(raw);
  }
  const input = structuredClone(raw);
  const inputs = versionInputs(input);
  const decisions = inputs.map(decideVersion);
  // A negative tuple cannot suppress either affected evidence or residual unknown.
  const rank = { affected: 0, unknown: 1, not_affected: 2, dropped: 3 };
  const winner = [...decisions].sort((a, b) => rank[a.applicability] - rank[b.applicability])[0]!;
  const actionable = decisions.filter(decision => decision.delivery !== "none");
  const priority = Math.min(...(actionable.length ? actionable : decisions).map(decision => decision.priority)) as Priority;
  const deliveryOrder = ["immediate", "finding", "weekly", "none"] as const;
  const delivery = deliveryOrder.find(value => actionable.some(decision => decision.delivery === value)) ?? "none";
  const proposedRemediation = actionable.length && actionable.every(decision =>
    canonicalJson(decision.proposedRemediation) === canonicalJson(winner.proposedRemediation)) ? winner.proposedRemediation : null;
  const negatives = decisions.filter(decision => decision.applicability !== "dropped");
  const proposedVex = !actionable.length && negatives.length && negatives.every(decision =>
    canonicalJson(decision.proposedVex) === canonicalJson(winner.proposedVex)) ? winner.proposedVex : null;
  return {
    ...winner, rulesVersion: `${RULES_VERSION}+all-versions.1`, inputSha256: sha256(canonicalJson(input)),
    priority, slaDays: SLA[priority], delivery, proposedRemediation, proposedVex,
    reasons: [...winner.reasons, "All installed tuples evaluated; affected then unknown outrank negative tuples. See per-version traces."],
    versionDecisions: decisions.map((decision, index) => ({
      version: inputs[index]!.version, inputSha256: decision.inputSha256,
      applicability: decision.applicability, matchedRule: decision.matchedRule, trace: decision.trace,
    })),
  };
}

function decideVersion(raw: FindingInput): Decision {
  const input = structuredClone(raw);
  const identity = findingIdentity(input);
  const advisory = input.aliases.find(item => item.id === input.advisoryId);
  const trace = [0];
  const reasons: string[] = [];
  const probability = input.provenance.epss?.probability;
  const epssValid = typeof probability === "number" && Number.isFinite(probability)
    && probability >= 0 && probability <= 1
    && !!input.provenance.epss?.date && !!input.provenance.epss.modelVersion;
  if (!epssValid) reasons.push("EPSS unavailable or invalid; severity fallback");
  const urgent = identity.aliases.some(id => id.startsWith("MAL-")
    || input.provenance.kev?.aliases.includes(id));
  let priority: Priority = urgent ? 0
    : (epssValid && probability >= 0.04)
      || (input.severity === "critical" && (input.scope === "runtime" || input.scope === "mixed")) ? 1
      : input.severity === "high" || (input.cvss4Base !== null && Number.isFinite(input.cvss4Base)
        && input.cvss4Base >= 7 && input.cvss4Base <= 10) ? 2 : 3;
  if (input.scope === "development" && priority !== 0) priority = Math.min(3, priority + 1) as Priority;

  const finish = (
    applicability: Decision["applicability"],
    matchedRule: Decision["matchedRule"],
    reason: string,
    proposedVex: ProposedVex | null = null,
    remediation: Remediation | null = null,
  ): Decision => {
    trace.push(matchedRule);
    const negative = applicability === "dropped" || applicability === "not_affected";
    if (!negative && matchedRule !== 2) trace.push(7);
    return {
      rulesVersion: RULES_VERSION, identity, advisoryModified: advisory?.modified ?? null,
      applicability, matchedRule, trace, priority, slaDays: SLA[priority],
      delivery: negative ? "none" : priority === 0 ? "immediate"
        : input.scope === "development" || priority === 3 ? "weekly" : "finding",
      proposedRemediation: remediation, proposedVex, reasons: [...reasons, reason],
      provenance: input.provenance, inputSha256: sha256(canonicalJson(input)),
    };
  };
  const vex = (justification: ProposedVex["justification"]): ProposedVex => ({
    status: "not_affected", justification, aliases: identity.aliases,
    artifactDigest: input.provenance.artifactDigest,
    expiresAt: new Date(Date.parse(input.provenance.observedAt) + 90 * 86400000).toISOString(),
  });
  const residual = (reason: string) => finish("unknown", 8, reason);

  if (advisory && validTime(advisory.withdrawn)) return finish("dropped", 1, "Advisory withdrawn");
  if (input.versionEvidence.status === "outside" && bound(input, input.versionEvidence)) {
    return finish("dropped", 1, "Version proven outside all affected ranges");
  }
  if (urgent) return finish("affected", 2, "MAL identifier or KEV alias; scope cannot suppress P0");
  if (!advisory) return residual("Missing source advisory");
  if (advisory.withdrawn !== null && !validTime(advisory.withdrawn)) return residual("Invalid withdrawal metadata");
  if (!validTime(input.provenance.observedAt)) return residual("Invalid observation timestamp");
  if (!input.provenance.kev?.catalogVersion) return residual("KEV coverage unavailable");
  if (input.versionEvidence.status === "unknown" || !bound(input, input.versionEvidence)) {
    return residual("Affected-range coverage unavailable or artifact mismatch");
  }
  if (input.ecosystem === "crates.io" && input.platform) {
    if (!bound(input, input.platform) || input.platform.tool !== "rustsec"
      || !input.buildTargets.length || !sameSet(input.platform.buildTargets, input.buildTargets)) {
      return residual("RustSec build-target coverage incomplete");
    }
    if (input.buildTargets.every(target => input.platform!.excludedTargets.includes(target))) {
      return finish("not_affected", 3, "RustSec excludes every configured target", vex("vulnerable_code_not_present"));
    }
  }
  let applicability: "affected" | "unknown" = "unknown";
  let skipFunctions = false;
  if (input.ecosystem === "Go") {
    const scan = input.go;
    if (!scan || !bound(input, scan) || scan.tool !== "govulncheck" || scan.status === "failed"
      || !input.buildTargets.length || !sameSet(scan.targets, input.buildTargets)
      || !sameSet(scan.tags, input.deployedTags)) return residual("govulncheck coverage incomplete or mismatched");
    if (scan.reflectOrUnsafe) return residual("Reflect/unsafe requires residual review");
    if (scan.status === "symbol_hit") {
      trace.push(4);
      applicability = "affected";
      skipFunctions = true;
    } else {
      return finish("not_affected", 4, "Complete govulncheck scan has no symbol hit", vex("vulnerable_code_not_in_execute_path"));
    }
  }
  if (!skipFunctions && input.functions) {
    const scan = input.functions;
    if (!bound(input, scan) || !scan.confirmedInAdvisory || !scan.fullDependencyClosure
      || !scan.allSourcesAvailable || !Number.isSafeInteger(scan.ownHits) || scan.ownHits < 0
      || !Number.isSafeInteger(scan.dependencyHits) || scan.dependencyHits < 0) {
      return residual("Affected-function scan lacks confirmed full-closure evidence");
    }
    if (scan.dependencyHits > 0) return residual("Dependency function hit requires residual review");
    if (scan.ownHits === 0) {
      return finish("not_affected", 5, "Confirmed functions absent from full closure", vex("vulnerable_code_not_present"));
    }
    trace.push(5);
    applicability = "affected";
  }
  const remediation = proposedRemediation(input);
  return remediation ? finish(applicability, 6, "Verified compatible-fix proposal", null, remediation)
    : finish(applicability, 8, "No verified compatible-fix proposal");
}
