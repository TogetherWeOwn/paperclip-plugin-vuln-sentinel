import { createHash } from "node:crypto";
import type { Advisory, FindingIdentity, FindingInput } from "./model.js";

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
}

export function aliasClosure(advisories: Advisory[], seed: string): string[] {
  const connected = new Set([seed]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const advisory of advisories) {
      const ids = [advisory.id, ...advisory.aliases, ...advisory.upstream];
      if (!ids.some(id => connected.has(id))) continue;
      for (const id of ids) {
        if (!connected.has(id)) {
          connected.add(id);
          changed = true;
        }
      }
    }
  }
  return [...connected].sort();
}

export function findingIdentity(input: Pick<FindingInput, "repo" | "ecosystem" | "package" | "fixedVersion" | "aliases" | "advisoryId">): FindingIdentity {
  if (!/^[\w.-]+\/[\w.-]+$/.test(input.repo)) throw new Error("Expected canonical owner/repo");
  const aliases = aliasClosure(input.aliases, input.advisoryId);
  for (const component of [input.package, input.fixedVersion ?? "unfixed", ...aliases]) {
    if (!component || /[|\s\x00-\x1f]/.test(component)) throw new Error("Invalid finding identity component");
  }
  const repo = input.repo.toLowerCase();
  const remediationUnit = `${input.ecosystem}:${input.package}@${input.fixedVersion ?? "unfixed"}`;
  const aliasGroup = aliases[0]!;
  return { repo, remediationUnit, aliasGroup, aliases, originId: sha256(`${repo}|${remediationUnit}|${aliasGroup}`) };
}
