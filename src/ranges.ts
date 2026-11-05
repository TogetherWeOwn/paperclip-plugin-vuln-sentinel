import semver from "semver";

export interface OsvRange {
  type: string;
  events: Array<Record<string, string>>;
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  versions?: string[];
  ranges?: OsvRange[];
}

export type VersionStatus = "affected" | "outside" | "unknown";
export const OSV_RANGES_VERSION = "1.1.0";

function strictSemver(value: string): boolean {
  const parsed = semver.parse(value);
  // semver.valid accepts leading v/whitespace and strips valid build metadata.
  return parsed !== null && value === parsed.version + (parsed.build.length ? `+${parsed.build.join(".")}` : "");
}

function semverRange(version: string, range: OsvRange): VersionStatus {
  if (range.type !== "SEMVER" || !strictSemver(version) || !range.events.length) return "unknown";
  let open: string | null = null;
  let previous: string | null = null;
  let hit = false;
  let closingKind: string | null = null;
  const limits: string[] = [];
  for (const event of range.events) {
    const entries = Object.entries(event);
    if (entries.length !== 1) return "unknown";
    const [kind, value] = entries[0]!;
    if (!["introduced", "fixed", "last_affected", "limit"].includes(kind)
      || !(value === "0" && kind === "introduced" || value === "*" && kind === "limit" || strictSemver(value))) {
      return "unknown";
    }
    // OSV BeforeLimits applies to the whole range, independently of its intervals.
    if (kind === "limit") {
      limits.push(value);
      continue;
    }
    if (value === "0" && previous !== null) return "unknown";
    if (previous !== null && value !== "0" && semver.lt(value, previous)) return "unknown";
    if (kind === "introduced") {
      if (open !== null) return "unknown";
      open = value;
    } else {
      if (open === null || closingKind !== null && closingKind !== kind) return "unknown";
      closingKind = kind;
      const aboveStart = open === "0" || semver.gte(version, open);
      const belowEnd = kind === "last_affected" ? semver.lte(version, value) : semver.lt(version, value);
      hit ||= aboveStart && belowEnd;
      open = null;
    }
    if (value !== "0") previous = value;
  }
  // Missing introduction, malformed later events or mixed closing kinds never prove exclusion.
  if (previous === null && open === null) return "unknown";
  if (open !== null) hit ||= open === "0" || semver.gte(version, open);
  const beforeLimits = !limits.length || limits.some(value => value === "*" || semver.lt(version, value));
  return hit && beforeLimits ? "affected" : "outside";
}

/** Unsupported ecosystems/range types are unknown, never proof of exclusion. */
export function osvVersionStatus(
  affected: OsvAffected[], ecosystem: string, name: string, version: string,
): VersionStatus {
  const matching = affected.filter(item => item.package?.ecosystem === ecosystem && item.package.name === name);
  if (!matching.length || !version) return "unknown";
  let unknown = ecosystem === "npm" && !strictSemver(version);
  for (const item of matching) {
    if (item.versions?.includes(version)) return "affected";
    if (ecosystem === "npm" && item.versions?.some(value => !strictSemver(value))) unknown = true;
    const ranges = item.ranges ?? [];
    if (!ranges.length && !item.versions?.length) unknown = true;
    for (const range of ranges) {
      const status = ecosystem === "npm" ? semverRange(version, range) : "unknown";
      if (status === "affected") return "affected";
      if (status === "unknown") unknown = true;
    }
  }
  return unknown ? "unknown" : "outside";
}
