import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ClaimStore, DATABASE_NAMESPACE, DecisionJournal } from "../dist/index.js";
import { finding } from "../src/test/fixtures.ts";

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
const db = {
  namespace: DATABASE_NAMESPACE,
  execute: async (sql, params) => {
    validatePluginRuntimeExecute(sql, DATABASE_NAMESPACE);
    const indexes = [...sql.matchAll(/\$(\d+)/g)].map(match => Number(match[1]));
    if (Math.max(...indexes) !== params.length || new Set(indexes).size !== params.length) {
      throw new Error("SQL parameter count mismatch");
    }
    count++;
    return { rowCount: 1 };
  },
  query: async sql => {
    validatePluginRuntimeQuery(sql, DATABASE_NAMESPACE);
    count++;
    return [];
  },
};
const store = new ClaimStore(db);
const key = { companyId: "fixture-company", originId: "a".repeat(64) };
await store.acquire(key, "fixture-token");
await store.read(key);
await store.change(key, "fixture-token", "reserved", {
  state: "linked", issue_id: "fixture-issue", advisory_modified: null, recovery_audit: [],
});
const journal = new DecisionJournal(db);
const { decision, decisionId } = await journal.record("fixture-company", finding());
await journal.read("fixture-company", decision.identity.originId, decisionId);
await journal.latest("fixture-company", decision.identity.originId);
console.log(`Installed host validators accepted ${count} migration/runtime statements; namespace and parameters match. No host database writes.`);
