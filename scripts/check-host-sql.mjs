import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { ClaimStore, DATABASE_NAMESPACE, DecisionJournal, DeliveryRouting, SourceJournal, canonicalJson, sha256 } from "../dist/index.js";
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
const osv = { queriedAt: "2026-11-04T04:30:00Z", observations: [], records: [] };
const scan = await sources.recordOsv("fixture-company", lockfileId, { ...osv, snapshotSha256: sha256(canonicalJson(osv)) });
const storedScan = await sources.readOsv("fixture-company", scan.snapshotId);
if (!storedScan || storedScan.inputs.length !== 0) throw new Error("Host-validator fixture did not exercise source replay");
console.log(`Installed host validators accepted ${count} migration/runtime statements; namespace and parameters match. No host database writes.`);
