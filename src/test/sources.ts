import { createHash } from "node:crypto";
import type { RepositoryLockfiles } from "../github-lockfiles.js";
import { canonicalJson, sha256 } from "../identity.js";
import { parseOsvRecord, type OsvSnapshot } from "../osv.js";

export function sourceLockfiles(): RepositoryLockfiles {
  const content = JSON.stringify({ lockfileVersion: 3, packages: {
    "": { dependencies: { lib: "^1.2.3" } },
    "node_modules/lib": { version: "1.2.3", resolved: "https://registry.npmjs.org/lib/-/lib-1.2.3.tgz" },
  } });
  const file = { path: "package-lock.json", content, sha256: sha256(content), etag: '"fixture"',
    blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") };
  return { repo: "example/project", sourceSha: "a".repeat(40), defaultBranch: "main", files: [file],
    artifactDigest: `sha256:${sha256(canonicalJson([[file.path, file.sha256]]))}` };
}

export function sourceOsv(): OsvSnapshot {
  const record = parseOsvRecord({ id: "GHSA-fixture", modified: "2026-11-01T00:00:00Z", affected: [{
    package: { name: "lib", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
  }] }, "GHSA-fixture");
  const content = { queriedAt: "2026-11-04T04:30:00Z", observations: [{
    dependency: { ecosystem: "npm" as const, package: "lib", version: "1.2.3" }, advisoryIds: [record.id],
  }], records: [record], unavailableIds: [] };
  return { ...content, snapshotSha256: sha256(canonicalJson(content)) };
}
