import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { ClaimStore, DATABASE_NAMESPACE, DecisionJournal, DeliveryRouting, SourceDecisions, SourceJournal, SourcePollStore, ThreatFeeds, ThreatJournal, parseKev, parseOsvRecord, canonicalJson, sha256 } from "../dist/index.js";
import { finding } from "../src/test/fixtures.ts";
import { rescan } from "../src/test/rescans.ts";

if (!process.argv[2]) {
  console.error("Usage: npm run check:host -- /absolute/path/to/installed/plugin-database.js");
  process.exit(2);
}
const {
  validatePluginMigrationStatement, validatePluginRuntimeExecute,
  validatePluginRuntimeQuery, derivePluginDatabaseNamespace,
} = await import(pathToFileURL(resolve(process.argv[2])).href);
if (derivePluginDatabaseNamespace("togetherweown.vuln-sentinel") !== DATABASE_NAMESPACE) {
  throw new Error("Installed host namespace derivation differs from the packaged migration");
}
let count = 0;
const directory = new URL("../migrations/", import.meta.url);
for (const file of (await readdir(directory)).filter(name => name.endsWith(".sql")).sort()) {
  for (const sql of (await readFile(new URL(file, directory), "utf8")).split(";").filter(value => value.trim())) {
    validatePluginMigrationStatement(sql, DATABASE_NAMESPACE);
    count++;
  }
}
function parameters(sql, params) {
  const indexes = [...sql.matchAll(/\$(\d+)/g)].map(match => Number(match[1]));
  if (Math.max(...indexes) !== params.length || new Set(indexes).size !== params.length) {
    throw new Error("SQL parameter count mismatch");
  }
}
let storedDecision;
const storedSources = new Map();
const storedThreats = new Map();
let storedPoll;
let storedRouting = { version: 1, members: [], containers: [], attention: [] };
let routingRevision = 0;
const db = {
  namespace: DATABASE_NAMESPACE,
  execute: async (sql, params) => {
    validatePluginRuntimeExecute(sql, DATABASE_NAMESPACE);
    parameters(sql, params);
    count++;
    if (sql.includes("source_snapshots")) {
      storedSources.set(params[1], { snapshot_id: params[1], source_kind: params[2], repo: params[3], source_sha: params[4], bundle: JSON.parse(params[5]) });
    }
    if (sql.includes("threat_snapshots")) {
      storedThreats.set(params[1], { snapshot_id: params[1], bundle: JSON.parse(params[2]) });
    }
    if (sql.startsWith(`INSERT INTO "${DATABASE_NAMESPACE}".source_polls`)) {
      storedPoll ??= { revision: 0, bundle: JSON.parse(params[2]) };
    }
    if (sql.startsWith(`UPDATE "${DATABASE_NAMESPACE}".source_polls`)) {
      storedPoll = { revision: storedPoll.revision + 1, bundle: JSON.parse(params[3]) };
    }
    if (sql.startsWith(`INSERT INTO "${DATABASE_NAMESPACE}".decision_records`)) {
      storedDecision = { company_id: params[0], origin_id: params[1], decision_id: params[2],
        input_sha256: params[3], rules_version: params[4], input_bundle: JSON.parse(params[5]), decision_bundle: JSON.parse(params[6]) };
    }
    if (sql.includes("delivery_routing") && sql.startsWith("UPDATE")) {
      storedRouting = JSON.parse(params[3]);
      routingRevision++;
    }
    return { rowCount: 1 };
  },
  query: async (sql, params) => {
    validatePluginRuntimeQuery(sql, DATABASE_NAMESPACE);
    parameters(sql, params);
    count++;
    if (sql.includes("source_snapshots")) return storedSources.has(params[1]) ? [storedSources.get(params[1])] : [];
    if (sql.includes("source_polls")) return storedPoll ? [structuredClone(storedPoll)] : [];
    if (sql.includes("threat_snapshots")) return storedThreats.has(params[1]) ? [storedThreats.get(params[1])] : [];
    if (sql.includes("delivery_routing")) {
      return [{ revision: routingRevision, bundle: storedRouting }];
    }
    return storedDecision && sql.includes("decision_records") ? [storedDecision] : [];
  },
};
const store = new ClaimStore(db);
const key = { companyId: "fixture-company", originId: "a".repeat(64) };
await store.acquire(key, "fixture-token");
await store.read(key);
await store.change(key, "fixture-token", "reserved", {
  state: "linked", issue_id: "fixture-issue", advisory_modified: null, recovery_audit: [],
  published_revision: 1, published_sha256: "b".repeat(64),
});
const journal = new DecisionJournal(db);
const input = finding();
input.provenance.artifactKind = "lockfile";
const { decision, decisionId } = await journal.record("fixture-company", input);
await journal.read("fixture-company", decision.identity.originId, decisionId);
await journal.latest("fixture-company", decision.identity.originId);
storedDecision = {
  company_id: "fixture-company", origin_id: decision.identity.originId, input_sha256: decision.inputSha256,
  input_bundle: input, decision_bundle: decision, decision_id: decisionId,
};
const routing = new DeliveryRouting(db, () => new Date("2026-11-05T05:00:00Z"));
await routing.observe("fixture-company", input);
const snapshot = await routing.snapshot("fixture-company", decision.identity.repo);
const receipt = { ...rescan(snapshot.members[0], input), companyId: "fixture-company" };
const result = await routing.applyRescan("fixture-company", decision.identity.repo, receipt);
if (result.status !== "recorded" || storedRouting.members[0].state !== "resolved") {
  throw new Error("Host-validator fixture did not exercise the rescan resolution update");
}
const sources = new SourceJournal(db, () => new Date("2026-11-04T04:31:00Z"));
const content = '{"lockfileVersion":3,"packages":{"":{}}}';
const file = { path: "package-lock.json", content, sha256: sha256(content), etag: null,
  blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") };
const lockfileId = await sources.recordLockfiles("fixture-company", {
  repo: "example/project", sourceSha: "a".repeat(40), defaultBranch: "main", files: [file],
  artifactDigest: `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}`,
});
await sources.readLockfiles("fixture-company", lockfileId);
const polls = new SourcePollStore(db, () => new Date("2026-11-04T04:31:00Z"));
const configured = { repo: "example/project", paths: [file.path] };
const poll = await polls.begin("fixture-company", configured);
await polls.cached(poll);
await polls.complete(poll, lockfileId);
const selected = await polls.current("fixture-company", configured);
await polls.assertCurrent(selected);
const fencedInput = structuredClone(input);
fencedInput.repo = configured.repo;
fencedInput.provenance.artifactDigest = selected.stored.lockfiles.artifactDigest;
fencedInput.versionEvidence.artifactDigest = fencedInput.provenance.artifactDigest;
const fencedRouting = new DeliveryRouting(db, () => new Date("2026-11-04T04:31:00Z"));
await fencedRouting.observeCurrent(selected, fencedInput);
if (!storedRouting.members.some(member => member.sourceSelection?.token === selected.token)) {
  throw new Error("Host-validator fixture did not exercise source-fenced journal and routing writes");
}
const nextPoll = await polls.begin("fixture-company", configured);
if ((await polls.cached(nextPoll))?.sourceSha !== "a".repeat(40)) throw new Error("Host-validator fixture did not exercise retained cache binding");
await polls.fail(nextPoll, "fixture_failure");
const held = await polls.current("fixture-company", configured).then(() => false, error => error.code === "current_source_attention");
if (!held) throw new Error("Host-validator fixture did not exercise failed-poll fencing");
const osv = { queriedAt: "2026-11-04T04:30:00Z", observations: [], records: [], unavailableIds: [] };
const scan = await sources.recordOsv("fixture-company", lockfileId, { ...osv, snapshotSha256: sha256(canonicalJson(osv)) });
const storedScan = await sources.readOsv("fixture-company", scan.snapshotId);
if (!storedScan || storedScan.inputs.length !== 0) throw new Error("Host-validator fixture did not exercise source replay");
const feedTime = "2026-11-04T04:29:00Z";
const feeds = new ThreatFeeds(async () => new Response(JSON.stringify({
  status: "OK", "status-code": 200, version: "1.0", total: 0, offset: 0, limit: 100, data: [],
})), () => new Date(feedTime));
const threats = new ThreatJournal(db);
const threatId = await threats.record("fixture-company", {
  kev: parseKev({ catalogVersion: "2026.11.03", dateReleased: "2026-11-03T00:00:00Z", count: 1,
    vulnerabilities: [{ cveID: "CVE-2026-99999", dateAdded: "2026-11-03" }] }, feedTime),
  epss: await feeds.epss(["CVE-2026-12345"], "2026-11-03", {
    version: "fixture-model", effectiveFrom: "2026-01-01", effectiveUntil: "2027-01-01", reference: "fixture-release",
  }),
});
await threats.read("fixture-company", threatId);
const enriched = await threats.enrich("fixture-company", threatId, [input]);
if (enriched[0]?.provenance.threatSnapshotId !== threatId) throw new Error("Host-validator fixture did not exercise persisted feed enrichment");
const populatedContent = JSON.stringify({ lockfileVersion: 3, packages: {
  "": { dependencies: { lib: "1.2.3" } },
  "node_modules/lib": { version: "1.2.3", resolved: "https://registry.npmjs.org/lib/-/lib-1.2.3.tgz" },
  "node_modules/parent/node_modules/lib": { version: "3.0.0", resolved: "https://registry.npmjs.org/lib/-/lib-3.0.0.tgz" },
} });
const populatedFile = { ...file, content: populatedContent, sha256: sha256(populatedContent),
  blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(populatedContent)}\0`).update(populatedContent).digest("hex") };
const populatedId = await sources.recordLockfiles("fixture-company", {
  repo: configured.repo, sourceSha: "b".repeat(40), defaultBranch: "main", files: [populatedFile],
  artifactDigest: `sha256:${sha256(canonicalJson([[populatedFile.path, populatedFile.sha256]]))}`,
});
const retainedPoll = await polls.begin("fixture-company", configured);
await polls.complete(retainedPoll, populatedId);
const retainedSelection = await polls.current("fixture-company", configured);
const retainedOsv = { queriedAt: "2026-11-04T04:31:00Z", unavailableIds: [],
  observations: ["1.2.3", "3.0.0"].map(version => ({ dependency: { ecosystem: "npm", package: "lib", version }, advisoryIds: ["GHSA-fixture"] })),
  records: [parseOsvRecord({ id: "GHSA-fixture", modified: "2026-11-01T00:00:00Z", affected: [{
    package: { ecosystem: "npm", name: "lib" }, versions: ["1.2.3"],
  }] }, "GHSA-fixture")],
};
const retainedScan = await sources.recordOsv("fixture-company", populatedId, { ...retainedOsv, snapshotSha256: sha256(canonicalJson(retainedOsv)) });
const orchestrated = await new SourceDecisions(db, () => new Date("2026-11-04T04:31:00Z"))
  .observe(retainedSelection, retainedScan.snapshotId, threatId);
if (orchestrated.counters.decisions !== 1 || orchestrated.counters.dependencies !== 2
  || storedDecision.input_bundle.provenance.osvSnapshotId !== retainedScan.snapshotId
  || storedDecision.input_bundle.versions?.length !== 2 || storedDecision.decision_bundle.versionDecisions?.length !== 2
  || storedDecision.decision_bundle.applicability !== "unknown") {
  throw new Error("Host-validator fixture did not exercise complete all-version retained-source orchestration");
}
console.log(`Installed host validators accepted ${count} migration/runtime statements; namespace and parameters match. No host database writes.`);
