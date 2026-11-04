import { parseKev, ThreatFeeds, type EpssModel, type ThreatSnapshot } from "../threat-feeds.js";

export const feedTime = "2026-11-04T04:30:00.000Z";
export const scoreDate = "2026-11-03";
export const epssModel: EpssModel = {
  version: "fixture-model", effectiveFrom: "2026-06-15", effectiveUntil: "2027-01-01",
  reference: "https://example.invalid/model-release",
};
export const rawKev = () => ({
  title: "Fixture catalog", catalogVersion: "2026.11.03", dateReleased: "2026-11-03T12:00:00Z", count: 1,
  vulnerabilities: [{ cveID: "CVE-2026-12345", dateAdded: scoreDate }],
});
export const epssResponse = (data: unknown[] = []) => ({
  status: "OK", "status-code": 200, version: "1.0", access: "public", total: data.length, offset: 0, limit: 100, data,
});
export const epssScore = (cve = "CVE-2026-12345", epss = "0.04", percentile = "0.99") => ({ cve, epss, percentile, date: scoreDate });
export async function threatSnapshot(): Promise<ThreatSnapshot> {
  const feeds = new ThreatFeeds(async () => new Response(JSON.stringify(epssResponse([epssScore()]))), () => new Date(feedTime));
  return { kev: parseKev(rawKev(), feedTime), epss: await feeds.epss(["CVE-2026-12345"], scoreDate, epssModel) };
}
