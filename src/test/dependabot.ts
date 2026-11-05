export const dependabotTime = "2026-11-04T08:00:00.000Z";

export function dependabotAlert(number = 1) {
  const vulnerability = { package: { ecosystem: "npm", name: "example" }, severity: "high",
    vulnerable_version_range: "< 2.0.0", first_patched_version: { identifier: "2.0.0" } };
  return { number, state: "open", repository: { full_name: "Example/Project" },
    created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-03T00:00:00Z",
    dependency: { package: { ...vulnerability.package }, manifest_path: "package-lock.json", scope: "development", relationship: "transitive" },
    security_vulnerability: structuredClone(vulnerability),
    security_advisory: { ghsa_id: "GHSA-2345-6789-cfgh", cve_id: "CVE-2026-12345", severity: "high",
      identifiers: [{ type: "GHSA", value: "GHSA-2345-6789-cfgh" }, { type: "CVE", value: "CVE-2026-12345" }],
      published_at: "2026-10-01T00:00:00Z", updated_at: "2026-11-02T00:00:00Z", withdrawn_at: null,
      vulnerabilities: [vulnerability] } };
}
