import { describe, expect, it } from "vitest";
import { cvssV3Base, observeOsvSeverity, OSV_SEVERITY_VERSION } from "./osv-severity.js";
import { canonicalJson, sha256 } from "./identity.js";
import { osvFindingInputs, parseOsvRecord, type OsvSnapshot } from "./osv.js";
import { decide } from "./matcher.js";

const dep = { ecosystem: "npm" as const, package: "example", version: "1.0.0" };
const critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
const moderate = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
const low = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N";
const zero = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
const score = (vector: unknown, type = "CVSS_V3") => ({ type, score: vector });
const affected = (severity: unknown, name = dep.package) => ({ package: { ecosystem: dep.ecosystem, name }, severity });

function snapshot(raws: Record<string, unknown>[]): OsvSnapshot {
  const content = {
    queriedAt: "2026-11-04T00:00:00.000Z", unavailableIds: [],
    observations: [{ dependency: dep, advisoryIds: [raws[0]!.id as string] }],
    records: raws.map(raw => parseOsvRecord(raw, raw.id as string)),
  };
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}
function raw(id: string, vector: string, aliases: string[] = []) {
  return {
    id, aliases, modified: "2026-11-03T00:00:00.000Z", severity: [score(vector)],
    affected: [{ package: { ecosystem: dep.ecosystem, name: dep.package }, versions: [dep.version] }],
  };
}
const context = { repo: "example/repo", artifactDigest: `sha256:${"a".repeat(64)}`, observedAt: "2026-11-04T00:00:00.000Z" };

describe("strict FIRST CVSS v3 Base scoring", () => {
  it.each([
    [critical, 9.8], [critical.replace("S:U", "S:C"), 10],
    [critical.replace("UI:N", "UI:R"), 8.8],
    [critical.replace("PR:N", "PR:L"), 8.8],
    [critical.replace("S:U", "S:C").replace("PR:N", "PR:L"), 9.9],
    [critical.replace("S:U", "S:C").replace("PR:N", "PR:H"), 9.1],
    [high, 7.5], [moderate, 5.3], [low, 3.3], [zero, 0], [zero.replace("S:U", "S:C"), 0],
  ])("scores %s as %s", (vector, expected) => {
    expect(cvssV3Base(vector as string)).toBe(expected);
    expect(cvssV3Base((vector as string).replace("3.1", "3.0"))).toBe(expected);
  });

  it("accepts arbitrary order and valid optional metrics but scores Base only", () => {
    const reordered = `CVSS:3.1/${critical.split("/").slice(1).reverse().join("/")}`;
    expect(cvssV3Base(reordered)).toBe(9.8);
    expect(cvssV3Base(`${critical}/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:U/MC:N/MI:N/MA:N`)).toBe(9.8);
  });

  it.each([
    "", "9.8", critical.toLowerCase(), ` ${critical}`, `${critical}\n`,
    critical.replace("CVSS:3.1", "CVSS:4.0"), critical.replace("CVSS:3.1", "CVSS:2.0"),
    critical.replace("/A:H", ""), critical.replace("AV:N", "AV:X"), critical.replace("PR:N", "PR:Z"),
    `${critical}/AV:N`, `${critical}/AV:L`, `${critical}/E:X/E:X`, `${critical}/OTHER:X`,
    `${critical}/E:Z`, `${critical}/E:`, `${critical}/E:X:Z`, `${critical}/`,
    critical.replace("C:H", "C:HH"), `${critical}/constructor:N`, `${critical}/__proto__:N`, "x".repeat(1025),
  ])("rejects invalid or unsupported vector %#", vector => expect(cvssV3Base(vector)).toBeNull());

  it("bounds every Base combination to one finite decimal without optional-score drift", () => {
    for (const AV of ["N", "A", "L", "P"]) for (const AC of ["L", "H"])
      for (const PR of ["N", "L", "H"]) for (const UI of ["N", "R"]) for (const S of ["U", "C"])
        for (const C of ["N", "L", "H"]) for (const I of ["N", "L", "H"]) for (const A of ["N", "L", "H"]) {
          const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
          const base = cvssV3Base(vector)!;
          expect(base).toBeGreaterThanOrEqual(0);
          expect(base).toBeLessThanOrEqual(10);
          expect(Number.isInteger(base * 10)).toBe(true);
          expect(cvssV3Base(`${vector}/E:U/MC:N/MI:N/MA:N`)).toBe(base);
        }
  });
});

describe("conservative OSV severity enrichment", () => {
  it.each([[critical, "critical"], [high, "high"], [moderate, "moderate"], [low, "low"]])(
    "derives %s as %s", (vector, severity) => {
      expect(observeOsvSeverity({ severity: [score(vector)] }, dep)).toEqual({
        version: OSV_SEVERITY_VERSION, severity, scores: [{ vector, base: cvssV3Base(vector) }], attention: [],
      });
    },
  );

  it.each(["CRITICAL", "HIGH", "MODERATE", "LOW", "MEDIUM"])("retains reported %s", label => {
    expect(observeOsvSeverity({ database_specific: { severity: label } }, dep).severity)
      .toBe(label === "MEDIUM" ? "moderate" : label.toLowerCase());
  });

  it("never downgrades a label or another vector, independent of input order", () => {
    const source = { database_specific: { severity: "CRITICAL" }, severity: [score(low), score(high), score(zero)] };
    const result = observeOsvSeverity(source, dep);
    expect(result.severity).toBe("critical");
    expect(observeOsvSeverity({ ...source, severity: [...source.severity].reverse() }, dep)).toEqual(result);
    expect(observeOsvSeverity({ severity: [score(low), score(high)] }, dep).severity).toBe("high");
  });

  it("deduplicates exact vectors and reads only exact matching package severity", () => {
    const result = observeOsvSeverity({ severity: [score(moderate), score(moderate)], affected: [
      affected([score(high)]), affected([score(critical)], "other"),
      { ...affected([score(critical)]), package: { ecosystem: "PyPI", name: dep.package } },
    ] }, dep);
    expect(result.severity).toBe("high");
    expect(result.scores).toHaveLength(2);
  });

  it.each([
    { ecosystem: "npm", name: "Example" },
    { ecosystem: "npm", name: "example-extra" },
    { ecosystem: "npm", name: "@scope/example" },
    { ecosystem: "npm", name: "example " },
    { ecosystem: "NPM", name: dep.package },
    { ecosystem: "PyPI", name: dep.package },
  ])("does not import severity from a nonmatching package %#", pkg => {
    for (const severity of [[score(critical)], null, { score: critical }]) {
      const result = observeOsvSeverity({ severity: [score(low)], affected: [
        { package: pkg, severity }, affected([score(moderate)]),
      ] }, dep);
      expect(result).toEqual({
        version: OSV_SEVERITY_VERSION, severity: "moderate",
        scores: [low, moderate].sort().map(vector => ({ vector, base: cvssV3Base(vector) })), attention: [],
      });
    }
  });

  it.each([
    { severity: null, reason: "severity_capacity_or_shape" },
    { severity: {}, reason: "severity_capacity_or_shape" },
    { severity: [null], reason: "invalid_severity_entry" },
    { severity: Array.from({ length: 101 }, () => score(high)), reason: "severity_capacity_or_shape" },
  ])(
    "does not ignore malformed exact-package severity %#", ({ severity, reason }) => {
      expect(() => observeOsvSeverity({ severity: [score(high)], affected: [affected(severity)] }, dep))
        .toThrow(reason);
    },
  );

  it("keeps missing exact-package severity unknown despite unrelated critical evidence", () => {
    const source = { affected: [affected(undefined), affected([score(critical)], "other")] };
    expect(observeOsvSeverity(source, dep)).toEqual({
      version: OSV_SEVERITY_VERSION, severity: "unknown", scores: [], attention: ["severity_not_observed"],
    });
  });

  it.each([
    [low, moderate, high], [low, high, moderate], [moderate, low, high],
    [moderate, high, low], [high, low, moderate], [high, moderate, low],
  ])("reduces repeated exact-package rows independently of ordering %#", (a, b, c) => {
    const source = { severity: [score(a)], affected: [affected([score(b)]), affected([score(c), score(a)])] };
    expect(observeOsvSeverity(source, dep)).toEqual({
      version: OSV_SEVERITY_VERSION, severity: "high",
      scores: [low, moderate, high].sort().map(vector => ({ vector, base: cvssV3Base(vector) })), attention: [],
    });
  });

  it.each([
    [{}, "severity_not_observed"],
    [{ severity: [score(zero)] }, "zero_cvss_not_absence_evidence"],
    [{ severity: [score("9.8")] }, "invalid_cvss_v3_vector"],
    [{ severity: [score(9.8)] }, "invalid_cvss_v3_vector"],
    [{ severity: [score(critical, "CVSS_V4")] }, "cvss_v4_not_scored"],
    [{ severity: [score(critical, "CVSS_V2")] }, "unsupported_severity_type"],
    [{ database_specific: { severity: "urgent" } }, "unrecognized_severity_label"],
  ])("marks unscored/missing data attention %#", (source, reason) => {
    const result = observeOsvSeverity(source, dep);
    expect(result.severity).toBe("unknown");
    expect(result.attention).toContain(reason);
    expect(result).not.toHaveProperty("cvss4Base");
  });

  it("keeps valid severity with attention for malformed and unsupported peers", () => {
    const result = observeOsvSeverity({ severity: [score(high), score("oops"), score("CVSS:4.0/...", "CVSS_V4")] }, dep);
    expect(result.severity).toBe("high");
    expect(result.attention).toEqual(["cvss_v4_not_scored", "invalid_cvss_v3_vector"]);
  });

  it.each([
    [null, "invalid_advisory"], [{ database_specific: null }, "invalid_database_specific"],
    [{ severity: null }, "severity_capacity_or_shape"], [{ severity: {} }, "severity_capacity_or_shape"],
    [{ severity: [null] }, "invalid_severity_entry"],
    [{ severity: Array.from({ length: 101 }, () => score(high)) }, "severity_capacity_or_shape"],
    [{ affected: {} }, "invalid_affected"], [{ affected: [null] }, "invalid_affected"],
    [{ affected: [{}] }, "missing_affected_package"],
  ])("rejects malformed/capacity input %#", (source, reason) => {
    expect(() => observeOsvSeverity(source, dep)).toThrow(reason as string);
  });

  it("bounds total severity work across matching affected rows without partial output", () => {
    const source = { affected: Array.from({ length: 21 }, () => affected(Array.from({ length: 100 }, () => score(high)))) };
    expect(() => observeOsvSeverity(source, dep)).toThrow("severity_capacity_or_shape");
  });

  it("does not mutate source data or the matching dependency", () => {
    const source = { severity: [score(critical)], affected: [affected([score(high)])] };
    const before = canonicalJson([source, dep]);
    observeOsvSeverity(source, dep);
    expect(canonicalJson([source, dep])).toBe(before);
  });

  it("normalizes retained raw vectors without changing the raw-record schema", () => {
    const retained = snapshot([raw("GHSA-example", high)]);
    const before = canonicalJson(retained);
    expect(retained.records[0]!.severity).toBe("unknown");
    const [input] = osvFindingInputs(retained, context);
    expect(input!.severity).toBe("high");
    expect(decide(input!).priority).toBe(2);
    expect(input!.cvss4Base).toBeNull();
    expect(input!.provenance.severityAttention).toEqual([]);
    expect(input!.provenance.toolVersions["vuln-sentinel-osv-severity"]).toBe(OSV_SEVERITY_VERSION);
    expect(canonicalJson(retained)).toBe(before);
    expect(osvFindingInputs(retained, context)).toEqual([input]);
  });

  it("reduces active aliases at their highest severity and excludes withdrawn aliases", () => {
    const first = raw("GHSA-a", low, ["GHSA-b", "GHSA-c"]);
    const second = raw("GHSA-b", high);
    const third = { ...raw("GHSA-c", critical), withdrawn: "2026-11-03T00:00:00.000Z" };
    const [input] = osvFindingInputs(snapshot([first, second, third]), context);
    expect(input!.severity).toBe("high");
    expect(input!.versionEvidence.status).toBe("affected");
    expect(decide(input!).priority).toBe(2);
  });

  it.each([
    { ecosystem: "npm", name: "Example" },
    { ecosystem: "npm", name: "other" },
    { ecosystem: "PyPI", name: dep.package },
  ])("binds retained package-level severity to each exact query tuple %#", pkg => {
    const source = {
      ...raw("GHSA-example", low), severity: [], affected: [
        { ...affected([score(moderate)]), versions: [dep.version] },
        { package: pkg, versions: [dep.version], severity: [score(critical)] },
      ],
    };
    const retained = snapshot([source]);
    retained.observations.push({ dependency: { ecosystem: pkg.ecosystem as "npm" | "PyPI", package: pkg.name, version: dep.version },
      advisoryIds: [source.id] });
    const { snapshotSha256: _, ...content } = retained;
    retained.snapshotSha256 = sha256(canonicalJson(content));
    const before = canonicalJson(retained);
    const inputs = osvFindingInputs(retained, context);
    expect(inputs.map(input => input.severity)).toEqual(["moderate", "critical"]);
    expect(inputs.map(input => input.versionEvidence.status)).toEqual(["affected", "affected"]);
    for (const input of inputs) {
      expect(input.provenance.source).toEqual({ kind: "osv", queriedAt: retained.queriedAt,
        snapshotSha256: retained.snapshotSha256 });
      expect(input.provenance.toolVersions["vuln-sentinel-osv-severity"]).toBe(OSV_SEVERITY_VERSION);
      expect(input.scope).toBe("unknown");
      expect(input.cvss4Base).toBeNull();
      expect(input.compatibleFixVerified).toBe(false);
      expect(decide(input).proposedVex).toBeNull();
    }
    expect(canonicalJson(retained)).toBe(before);
    expect(osvFindingInputs(structuredClone(retained), context)).toEqual(inputs);
  });

  it.each([low, moderate, high, critical])(
    "retains distinct source and decision hashes when severity changes without a modified change %#", vector => {
      const original = snapshot([raw("GHSA-example", zero)]);
      const revised = snapshot([raw("GHSA-example", vector)]);
      const before = canonicalJson(original);
      const [oldInput] = osvFindingInputs(original, context);
      const [newInput] = osvFindingInputs(revised, context);
      expect(oldInput!.versionEvidence.advisoryModified).toBe(newInput!.versionEvidence.advisoryModified);
      expect(oldInput!.severity).toBe("unknown");
      expect(newInput!.severity).toBe(observeOsvSeverity(revised.records[0]!.raw, dep).severity);
      expect(original.records[0]!.rawSha256).not.toBe(revised.records[0]!.rawSha256);
      expect(original.snapshotSha256).not.toBe(revised.snapshotSha256);
      const previous = decide(oldInput!);
      const next = decide(newInput!);
      expect(previous.inputSha256).not.toBe(next.inputSha256);
      expect(previous.identity).toEqual(next.identity);
      expect(next.provenance).toEqual(newInput!.provenance);
      expect(next.proposedVex).toBeNull();
      expect(next.proposedRemediation).toBeNull();
      expect(canonicalJson(original)).toBe(before);
      expect(decide(osvFindingInputs(original, context)[0]!)).toEqual(previous);
    },
  );

  it.each([
    { severity: null, reason: "severity_capacity_or_shape" },
    { severity: {}, reason: "severity_capacity_or_shape" },
    { severity: [null], reason: "invalid_severity_entry" },
    { severity: Array.from({ length: 101 }, () => score(high)), reason: "severity_capacity_or_shape" },
  ])("holds retained normalization for malformed exact-package severity %#", ({ severity, reason }) => {
    const source = { ...raw("GHSA-example", high), affected: [
      { ...affected(severity), versions: [dep.version] },
    ] };
    const retained = snapshot([source]);
    const before = canonicalJson(retained);
    expect(() => osvFindingInputs(retained, context)).toThrow(reason);
    expect(canonicalJson(retained)).toBe(before);
  });

  it("retains known severity and missing-alias attention without treating it as absence", () => {
    const source = raw("GHSA-example", high, ["CVE-2026-1234"]);
    const retained = snapshot([source]);
    retained.unavailableIds = ["CVE-2026-1234"];
    const { snapshotSha256: _, ...content } = retained;
    retained.snapshotSha256 = sha256(canonicalJson(content));
    const [input] = osvFindingInputs(retained, context);
    expect(input!.severity).toBe("high");
    expect(input!.provenance.severityAttention).toEqual(["severity_not_observed"]);
    expect(input!.versionEvidence.status).toBe("affected");
    expect(decide(input!).priority).toBe(2);
    expect(decide(input!).proposedVex).toBeNull();
    expect(decide(input!).proposedRemediation).toBeNull();
  });

  it("carries unsupported severity attention without inventing v4, scope or absence", () => {
    const source = raw("GHSA-example", zero);
    source.severity.push(score("CVSS:4.0/...", "CVSS_V4"));
    const [input] = osvFindingInputs(snapshot([source]), context);
    expect(input!.severity).toBe("unknown");
    expect(input!.provenance.severityAttention).toEqual([
      "cvss_v4_not_scored", "severity_not_observed", "zero_cvss_not_absence_evidence",
    ]);
    expect(input!.cvss4Base).toBeNull();
    expect(input!.scope).toBe("unknown");
    expect(input!.fixedVersion).toBeNull();
    expect(input!.versionEvidence.status).toBe("affected");
    expect(decide(input!).applicability).toBe("unknown");
    expect(decide(input!).proposedVex).toBeNull();
  });
});
