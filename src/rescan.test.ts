import type { PGlite } from "@electric-sql/pglite";
import type { PluginDatabaseClient } from "@paperclipai/plugin-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DATABASE_NAMESPACE } from "./claims.js";
import { ContainerPublication } from "./publication.js";
import { DeliveryRouting } from "./routing.js";
import type { RoutingMember } from "./routing.js";
import type { FindingInput } from "./model.js";
import type { RescanEvidence } from "./rescan.js";
import { finding } from "./test/fixtures.js";
import { testDatabase } from "./test/database.js";
import { FakeIssues } from "./test/issues.js";
import { rescan } from "./test/rescans.js";

let postgres: PGlite;
let db: PluginDatabaseClient;
let routing: DeliveryRouting;
let now: string;
const company = "company-a";
const repo = "example/service";
const weekly = (patch: Partial<FindingInput> = {}) => {
  const input = finding({ scope: "development", ...patch });
  input.provenance.artifactKind = "lockfile";
  return input;
};
const snapshot = () => routing.snapshot(company, repo);
const apply = (receipt: RescanEvidence) => routing.applyRescan(company, repo, receipt);
async function observed(input = weekly()): Promise<RoutingMember> {
  const result = await routing.observe(company, input);
  return (await snapshot()).members.find(item => item.findingId === result.findingId)!;
}
const later = (input: FindingInput, observedAt = "2026-11-06T00:00:00Z"): FindingInput => ({
  ...input, provenance: { ...input.provenance, observedAt },
});

beforeAll(async () => { ({ postgres, db } = await testDatabase()); }, 30000);
beforeEach(async () => {
  await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.delivery_routing, ${DATABASE_NAMESPACE}.decision_records, ${DATABASE_NAMESPACE}.finding_records, ${DATABASE_NAMESPACE}.card_claims`);
  now = "2026-11-05T05:00:00Z";
  routing = new DeliveryRouting(db, () => new Date(now));
});
afterAll(async () => { await postgres.close(); });

describe("complete new-digest rescan evidence", () => {
  it("resolves only the bound member and retains its immutable evidence, original SLA and bucket", async () => {
    const input = weekly();
    const member = await observed(input);
    const other = await observed(weekly({ package: "unrelated" }));
    const receipt = rescan(member, input);
    expect((await apply(receipt)).status).toBe("recorded");
    const after = await snapshot();
    expect(after.members[0]).toMatchObject({ ...member, state: "resolved" });
    expect(after.members[0]!.resolutions).toHaveLength(1);
    expect(after.members[0]!.resolutions![0]!.evidence).toEqual(receipt);
    expect(after.members[1]).toEqual(other);
    expect(after.containers[0]!.revision).toBe(3);
    expect(after.containers[0]!.memberIds).toEqual([member.findingId, other.findingId]);
  });

  const invalid: Array<[string, (receipt: RescanEvidence) => void]> = [
    ["company", value => { value.companyId = "other-company"; }],
    ["repository", value => { value.repo = "example/other"; }],
    ["member", value => { value.findingId = "unknown"; }],
    ["decision revision", value => { value.decisionId = "stale"; }],
    ["ecosystem", value => { value.ecosystem = "Go"; }],
    ["package", value => { value.package = "other-package"; }],
    ["alias closure", value => { value.aliases = ["GHSA-example"]; }],
    ["advisory revision", value => { value.advisoryModified = "2026-11-02T00:00:00Z"; }],
    ["previous artifact", value => { value.previousArtifactDigest = "sha256:other"; }],
    ["artifact kind", value => { value.artifactKind = "image"; }],
    ["mutable artifact", value => { value.artifactDigest = "registry.example/image:latest"; }],
    ["source revision", value => { value.sourceRevision = "main"; }],
    ["binding receipt", value => { value.bindingEvidenceRef = ""; }],
    ["lineage receipt", value => { value.lineageEvidenceRef = ""; }],
    ["stale scan", value => { value.startedAt = "2026-11-03T00:00:00Z"; }],
    ["invalid scan time", value => { value.startedAt = "invalid"; }],
    ["reversed scan time", value => { value.completedAt = "2026-11-05T03:00:00Z"; }],
    ["future scan", value => { value.completedAt = "2026-11-07T00:00:00Z"; }],
    ["present finding", value => { value.status = "present"; }],
    ["unknown result", value => { value.status = "unknown"; }],
    ["failed scan", value => { value.status = "failed"; }],
    ["missing report", value => { value.reportSha256 = ""; }],
    ["missing tools", value => { value.toolVersions = {}; }],
    ["unversioned scanner", value => { value.tool = "not-in-provenance"; }],
    ["suppressed results", value => { value.coverage.unfiltered = false; }],
    ["missing version", value => { value.toolVersions = { scanner: "" }; }],
    ["partial coverage", value => { value.coverage.complete = false; }],
    ["missing locked view", value => { value.coverage.fullLockfile = false; }],
    ["missing completeness receipt", value => { value.coverage.completenessEvidenceRef = ""; }],
    ["wrong targets", value => { value.coverage.buildTargets = ["linux/arm64"]; }],
    ["wrong tags", value => { value.coverage.deployedTags = ["not-deployed"]; }],
  ];
  it.each(invalid)("holds %s without resolving or losing the receipt", async (_, change) => {
    const input = weekly();
    const member = await observed(input);
    const receipt = rescan(member, input);
    change(receipt);
    expect((await apply(receipt)).status).toBe("attention");
    expect((await apply(receipt)).status).toBe("attention");
    const after = await snapshot();
    expect(after.members[0]).toEqual(member);
    expect(after.rescanHolds).toHaveLength(1);
    expect(after.rescanHolds![0]!.evidence).toEqual(receipt);
    expect(after.containers[0]!.revision).toBe(1);
  });

  it("cannot resolve an old input with unknown artifact kind or the same digest", async () => {
    const input = weekly();
    delete input.provenance.artifactKind;
    const member = await observed(input);
    const receipt = { ...rescan(member, input), artifactKind: "lockfile" as const };
    expect((await apply(receipt)).status).toBe("attention");
    const fresh = weekly({ package: "immutable" });
    fresh.provenance.artifactDigest = `sha256:${"a".repeat(64)}`;
    const other = await observed(fresh);
    expect((await apply(rescan(other, fresh))).status).toBe("attention");
    expect((await snapshot()).members.every(item => item.state === "unresolved")).toBe(true);
  });

  it.each(["image", "go_binary", "rust_binary", "worker_bundle"] as const)("requires independent runtime completeness and full sources for %s", async kind => {
    const input = weekly({ ecosystem: kind === "rust_binary" ? "crates.io" : "npm" });
    input.provenance.artifactKind = kind;
    const member = await observed(input);
    const receipt = rescan(member, input);
    receipt.coverage.runtimeCompleteness = "not_proven";
    expect((await apply(receipt)).status).toBe("attention");
    receipt.coverage.runtimeCompleteness = "proven";
    receipt.coverage.fullDependencyClosure = false;
    expect((await apply(receipt)).status).toBe("attention");
    receipt.coverage.fullDependencyClosure = true;
    expect((await apply(receipt)).status).toBe("recorded");
  });

  it("does not let missing current journal evidence certify resolution", async () => {
    const input = weekly();
    const member = await observed(input);
    await postgres.exec(`TRUNCATE ${DATABASE_NAMESPACE}.decision_records`);
    expect((await apply(rescan(member, input))).status).toBe("attention");
    expect((await snapshot()).members[0]).toEqual(member);
  });

  it("supersession is not a rescan resolution", async () => {
    const input = weekly({ fixedVersion: "1.1.0" });
    const member = await observed(input);
    await routing.observe(company, later(weekly({ fixedVersion: "1.2.0" })), {
      kind: "replacement", predecessorId: member.findingId, evidenceRef: "fixture-same-action",
    });
    expect((await apply(rescan(member, input))).status).toBe("attention");
    expect((await snapshot()).members.map(item => item.state)).toEqual(["superseded", "unresolved"]);
  });
});

describe("rescan replay, concurrency and reopening", () => {
  it("concurrent receipt replay records one resolution and one publication revision", async () => {
    const input = weekly();
    const member = await observed(input);
    const receipt = rescan(member, input);
    await Promise.all(Array.from({ length: 16 }, () => apply(receipt)));
    const after = await snapshot();
    expect(after.members[0]!.resolutions).toHaveLength(1);
    expect(after.containers[0]!.revision).toBe(2);
    expect((await apply(receipt)).status).toBe("reused");
    expect(await snapshot()).toEqual(after);
  });

  it("resolving different members concurrently cannot overwrite either resolution", async () => {
    const a = weekly();
    const b = weekly({ package: "other" });
    const first = await observed(a);
    const second = await observed(b);
    await Promise.all([apply(rescan(first, a)), apply(rescan(second, b))]);
    const after = await snapshot();
    expect(after.members.every(item => item.state === "resolved" && item.resolutions?.length === 1)).toBe(true);
    expect(after.containers[0]!.revision).toBe(4);
  });

  it("a newer finding racing a rescan always ends unresolved; a stale receipt cannot win", async () => {
    const input = weekly();
    const member = await observed(input);
    await Promise.all([apply(rescan(member, input)), routing.observe(company, later(input))]);
    expect((await snapshot()).members[0]!.state).toBe("unresolved");
  });

  it("modified-advisory observation reopens the original member; old receipt replay cannot resolve it again", async () => {
    const input = weekly();
    const member = await observed(input);
    const receipt = rescan(member, input);
    await apply(receipt);
    // A new advisory revision invalidates proof even if observed before the rescan completed.
    const changed = later(input, "2026-11-05T04:10:00Z");
    changed.aliases = changed.aliases.map(alias => ({ ...alias, modified: "2026-11-05T04:05:00Z" }));
    const result = await routing.observe(company, changed);
    expect(result.container!.originId).toBe(member.deliveryOrigin);
    const reopened = (await snapshot()).members[0]!;
    expect(reopened).toMatchObject({ state: "unresolved", firstObservedAt: member.firstObservedAt, deadlineAt: member.deadlineAt });
    expect(reopened.resolutions).toHaveLength(1);
    expect((await apply(receipt)).status).toBe("reused");
    expect((await snapshot()).members[0]).toEqual(reopened);
  });

  it.each(["2026-11-05T03:00:00Z", "2026-11-05T04:10:00Z", "2026-11-06T00:00:00Z"])("identical/older replay is inert, but a new finding at %s reopens conservatively", async observedAt => {
    const input = weekly();
    const member = await observed(input);
    await apply(rescan(member, input));
    const resolved = (await snapshot()).members[0]!;
    await routing.observe(company, input);
    await routing.observe(company, later(input, "2026-11-03T03:00:00Z"));
    expect((await snapshot()).members[0]).toEqual(resolved);
    await routing.observe(company, later(input, observedAt));
    expect((await snapshot()).members[0]!.state).toBe("unresolved");
  });

  it("newly learned aliases invalidate resolution that did not cover them, without moving membership", async () => {
    const input = weekly();
    const member = await observed(input);
    await apply(rescan(member, input));
    const alias = weekly();
    alias.aliases[0]!.aliases.push("AAA-new-alias");
    await routing.observe(company, alias);
    const after = await snapshot();
    expect(after.members[0]).toMatchObject({ state: "unresolved", deliveryOrigin: member.deliveryOrigin });
    expect(after.members[0]!.resolutions).toHaveLength(1);
    expect(after.containers).toHaveLength(1);
  });

  it("a lost commit response replays safely without a second resolution", async () => {
    const input = weekly();
    const member = await observed(input);
    let fail = true;
    const faulty: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      const result = await db.execute(sql, params);
      if (fail && sql.includes("delivery_routing") && sql.startsWith("UPDATE")) { fail = false; throw new Error("Response lost"); }
      return result;
    } };
    const receipt = rescan(member, input);
    await expect(new DeliveryRouting(faulty, () => new Date(now)).applyRescan(company, repo, receipt)).rejects.toThrow("Response lost");
    expect((await apply(receipt)).status).toBe("reused");
    expect((await snapshot()).members[0]!.resolutions).toHaveLength(1);
  });

  it("CAS contention/capacity failures leave the member unresolved and require receipt replay", async () => {
    const input = weekly();
    const member = await observed(input);
    const receipt = rescan(member, input);
    let attempts = 0;
    const contended: PluginDatabaseClient = { ...db, execute: async (sql, params) => {
      if (sql.includes("delivery_routing") && sql.startsWith("UPDATE")) { attempts++; return { rowCount: 0 }; }
      return db.execute(sql, params);
    } };
    await expect(new DeliveryRouting(contended, () => new Date(now)).applyRescan(company, repo, receipt)).rejects.toThrow("contention budget");
    expect(attempts).toBe(32);
    receipt.bindingEvidenceRef = "x".repeat(1048576);
    await expect(apply(receipt)).rejects.toThrow("capacity exceeded");
    expect((await snapshot()).members[0]).toEqual(member);
  });
});

describe("report-only publication preserves per-member resolution", () => {
  it("reopening one member leaves an unrelated resolved member unchanged in the original batch", async () => {
    const a = weekly();
    const b = weekly({ package: "unrelated" });
    const first = await observed(a);
    const second = await observed(b);
    const issues = new FakeIssues();
    const publisher = new ContainerPublication(db, issues);
    const publish = () => publisher.publish(company, repo, first.deliveryOrigin!, "triage", true);
    await publish();
    await apply(rescan(first, a));
    await apply(rescan(second, b));
    expect((await publish()).status).toBe("updated");
    // Resolution is evidence only, never an automatic native issue close.
    expect(issues.rows.get("issue-1")!.status).toBe("todo");
    issues.rows.get("issue-1")!.status = "done";
    expect((await publish()).status).toBe("reused");
    const unrelated = (await snapshot()).members[1]!;
    now = "2026-11-10T05:00:00Z";
    await routing.observe(company, later(a, now));
    expect((await publish()).status).toBe("reopened");
    expect((await snapshot()).members[1]).toEqual(unrelated);
    expect(issues.bodies.get("issue-1")).toContain(`Finding ${second.findingId} — P3 — resolved`);
    expect(issues.creates).toHaveLength(1);
    expect((await snapshot()).containers).toHaveLength(1);
  });

  it("publishing a new resolved revision never reopens an externally closed container", async () => {
    const input = weekly();
    const member = await observed(input);
    const issues = new FakeIssues();
    const publisher = new ContainerPublication(db, issues);
    const publish = () => publisher.publish(company, repo, member.deliveryOrigin!, "triage", true);
    await publish();
    issues.rows.get("issue-1")!.status = "cancelled";
    await apply(rescan(member, input));
    expect((await publish()).status).toBe("updated");
    expect(issues.rows.get("issue-1")!.status).toBe("cancelled");
    expect(issues.updates.at(-1)![1]).not.toHaveProperty("status");
    expect((await publish()).status).toBe("reused");
  });

  it("publication rejects a resolved flag without valid resolution evidence", async () => {
    const input = weekly();
    const member = await observed(input);
    const bundle = await snapshot();
    bundle.members[0]!.state = "resolved";
    await db.execute(`UPDATE "${DATABASE_NAMESPACE}".delivery_routing SET bundle = $3 WHERE company_id = $1 AND repo = $2`,
      [company, repo, JSON.stringify(bundle)]);
    const issues = new FakeIssues();
    await expect(new ContainerPublication(db, issues).publish(company, repo, member.deliveryOrigin!, "triage", true)).rejects.toThrow("no valid complete");
    expect(issues.creates).toHaveLength(0);
  });
});
