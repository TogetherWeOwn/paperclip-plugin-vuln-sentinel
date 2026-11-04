import type { FindingInput } from "./model.js";
import { object, SourceAttention } from "./source-http.js";

export const OSV_SEVERITY_VERSION = "1.0.0";
type Severity = FindingInput["severity"];
const ORDER: Severity[] = ["critical", "high", "moderate", "low", "unknown"];
const METRICS: Record<string, string[]> = {
  AV: ["N", "A", "L", "P"], AC: ["L", "H"], PR: ["N", "L", "H"], UI: ["N", "R"],
  S: ["U", "C"], C: ["N", "L", "H"], I: ["N", "L", "H"], A: ["N", "L", "H"],
  E: ["X", "H", "F", "P", "U"], RL: ["X", "U", "W", "T", "O"], RC: ["X", "C", "R", "U"],
  CR: ["X", "H", "M", "L"], IR: ["X", "H", "M", "L"], AR: ["X", "H", "M", "L"],
  MAV: ["X", "N", "A", "L", "P"], MAC: ["X", "L", "H"], MPR: ["X", "N", "L", "H"],
  MUI: ["X", "N", "R"], MS: ["X", "U", "C"], MC: ["X", "N", "L", "H"],
  MI: ["X", "N", "L", "H"], MA: ["X", "N", "L", "H"],
};

/** FIRST v3.0/v3.1 Base equations only; never a temporal/environmental or v4 score. */
export function cvssV3Base(vector: string): number | null {
  if (typeof vector !== "string" || vector.length > 1024) return null;
  const [prefix, ...parts] = vector.split("/");
  if (prefix !== "CVSS:3.0" && prefix !== "CVSS:3.1") return null;
  const values = new Map<string, string>();
  for (const part of parts) {
    const pair = part.split(":");
    if (pair.length !== 2) return null;
    const [key, value] = pair as [string, string];
    if (!Object.hasOwn(METRICS, key) || !METRICS[key]!.includes(value) || values.has(key)) return null;
    values.set(key, value);
  }
  if (["AV", "AC", "PR", "UI", "S", "C", "I", "A"].some(key => !values.has(key))) return null;
  const weight = (key: string, weights: Record<string, number>) => weights[values.get(key)!]!;
  const changed = values.get("S") === "C";
  const impacts = { N: 0, L: 0.22, H: 0.56 };
  const iss = 1 - (1 - weight("C", impacts)) * (1 - weight("I", impacts)) * (1 - weight("A", impacts));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * weight("AV", { N: 0.85, A: 0.62, L: 0.55, P: 0.2 })
    * weight("AC", { L: 0.77, H: 0.44 })
    * weight("PR", changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })
    * weight("UI", { N: 0.85, R: 0.62 });
  // FIRST Appendix A's integer Roundup avoids a floating-point extra tenth.
  const integer = Math.round(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10) * 100_000);
  return integer % 10_000 === 0 ? integer / 100_000 : (Math.floor(integer / 10_000) + 1) / 10;
}

export interface OsvSeverityObservation {
  version: typeof OSV_SEVERITY_VERSION;
  severity: Severity;
  scores: Array<{ vector: string; base: number }>;
  attention: string[];
}

/** Reported source context, not applicability, runtime scope, a fix or an absence proof. */
export function observeOsvSeverity(
  raw: unknown, dependency: { ecosystem: string; package: string },
): OsvSeverityObservation {
  const row = object(raw, "invalid_advisory");
  const severities: Severity[] = [];
  const scores = new Map<string, number>();
  const attention = new Set<string>();
  if (row.database_specific !== undefined) {
    const database = object(row.database_specific, "invalid_database_specific");
    if (database.severity !== undefined) {
      const label = typeof database.severity === "string" ? database.severity.toLowerCase() : "";
      const severity = label === "medium" ? "moderate" : label;
      if (ORDER.includes(severity as Severity) && severity !== "unknown") severities.push(severity as Severity);
      else attention.add("unrecognized_severity_label");
    }
  }
  let entries = 0;
  const read = (value: unknown) => {
    if (value === undefined) return;
    if (!Array.isArray(value) || value.length > 100 || (entries += value.length) > 2_000) {
      throw new SourceAttention("severity_capacity_or_shape");
    }
    for (const entry of value) {
      const item = object(entry, "invalid_severity_entry");
      if (item.type !== "CVSS_V3") {
        attention.add(item.type === "CVSS_V4" ? "cvss_v4_not_scored" : "unsupported_severity_type");
        continue;
      }
      const base = typeof item.score === "string" ? cvssV3Base(item.score) : null;
      if (base === null) {
        attention.add("invalid_cvss_v3_vector");
        continue;
      }
      scores.set(item.score as string, base);
      // The matcher has no "none" severity. A zero score is not a safety decision.
      if (base === 0) attention.add("zero_cvss_not_absence_evidence");
      else severities.push(base >= 9 ? "critical" : base >= 7 ? "high" : base >= 4 ? "moderate" : "low");
    }
  };
  read(row.severity);
  if (row.affected !== undefined) {
    if (!Array.isArray(row.affected) || row.affected.length > 10_000) throw new SourceAttention("invalid_affected");
    for (const entry of row.affected) {
      const affected = object(entry, "invalid_affected");
      const pkg = object(affected.package, "missing_affected_package");
      if (pkg.ecosystem === dependency.ecosystem && pkg.name === dependency.package) read(affected.severity);
    }
  }
  const severity = ORDER.find(value => severities.includes(value)) ?? "unknown";
  if (severity === "unknown") attention.add("severity_not_observed");
  return {
    version: OSV_SEVERITY_VERSION, severity,
    scores: [...scores.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([vector, base]) => ({ vector, base })),
    attention: [...attention].sort(),
  };
}
