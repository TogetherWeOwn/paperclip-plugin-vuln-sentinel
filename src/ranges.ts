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

function semverRange(version: string, range: OsvRange): VersionStatus {
  if (range.type !== "SEMVER" || !semver.valid(version) || !range.events.length) return "unknown";
  let open: string | null = null;
  let previous: string | null = null;
  let hit = false;
  for (const event of range.events) {
    const entries = Object.entries(event);
    if (entries.length !== 1) return "unknown";
    const [kind, value] = entries[0]!;
    if (!["introduced", "fixed", "last_affected", "limit"].includes(kind)
      || (value !== "0" || kind !== "introduced") && !semver.valid(value)) return "unknown";
    if (value === "0" && kind === "introduced" && previous !== null) return "unknown";
    if (previous !== null && value !== "0" && semver.lt(value, previous)) return "unknown";
    if (kind === "introduced") {
      if (open !== null) return "unknown";
      open = value;
    } else {
      if (open === null) return "unknown";
      const aboveStart = open === "0" || semver.gte(version, open);
      const belowEnd = kind === "last_affected" ? semver.lte(version, value) : semver.lt(version, value);
      hit ||= aboveStart && belowEnd;
      open = null;
    }
    if (value !== "0") previous = value;
  }
  if (open !== null) hit ||= open === "0" || semver.gte(version, open);
  return hit ? "affected" : "outside";
}

/** Unsupported ecosystems/range types are unknown, never proof of exclusion. */
export function osvVersionStatus(
  affected: OsvAffected[], ecosystem: string, name: string, version: string,
): VersionStatus {
  const matching = affected.filter(item => item.package?.ecosystem === ecosystem && item.package.name === name);
  if (!matching.length || !version) return "unknown";
  let unknown = false;
  for (const item of matching) {
    if (item.versions?.includes(version)) return "affected";
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
