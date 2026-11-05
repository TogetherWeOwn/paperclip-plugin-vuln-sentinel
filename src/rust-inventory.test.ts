import { describe, expect, it } from "vitest";
import { sha256 } from "./identity.js";
import { observeRustInventory, type RustInventoryReports } from "./rust-inventory.js";

const a = { name: "example", version: "1.0.0" };
const b = { name: "example", version: "2.0.0" };
const c = { name: "workspace", version: "0.1.0" };
const imageId = `sha256:${"a".repeat(64)}`;
const configId = `sha256:${"b".repeat(64)}`;
const sourceSha = "c".repeat(40);
const cargoLock = `version = 4\n${[a, b, c].map(row => `[[package]]\nname = "${row.name}"\nversion = "${row.version}"\n`).join("")}`;

function fixture() {
  const metadata = { userInput: imageId, imageID: configId };
  const check = {
    source_sha: sourceSha, image_id: imageId, config_id: configId,
    sha256: { "Cargo.lock": sha256(cargoLock), "runtime-crates.syft.json": "", "runtime-crates.grype.json": "" },
    runtime_crates: 2, locked_crates: 3, grype_matches: 0,
    runtime_crate_tuples: [a, c], locked_crate_tuples: [a, b, c], lockfile_only: [b],
    runtime_completeness: "not_proven", suppressed_count: 0,
  };
  const syft = {
    artifacts: [a, c].map(row => ({ ...row, type: "rust-crate", foundBy: "cargo-auditable-binary-cataloger" })),
    source: { type: "image", metadata }, descriptor: { name: "syft", version: "1.56.0" },
  };
  const grype = {
    matches: [] as unknown[], source: { type: "image", target: structuredClone(metadata) },
    descriptor: { name: "grype", version: "0.121.1" } as { name: string; version?: string },
    ignoredMatches: undefined as unknown[] | undefined,
  };
  const encode = (withLock = true): RustInventoryReports => {
    const syftContent = JSON.stringify(syft);
    const grypeContent = JSON.stringify(grype);
    check.sha256["runtime-crates.syft.json"] = sha256(syftContent);
    check.sha256["runtime-crates.grype.json"] = sha256(grypeContent);
    return { check: JSON.stringify(check), syft: syftContent, grype: grypeContent,
      ...(withLock ? { cargoLock } : {}), expected: { sourceSha, imageId, configId } };
  };
  return { check, syft, grype, encode };
}

describe("offline Rust producer observations", () => {
  it("keeps the exact R/L/O partition and every installed version, without resolving anything", () => {
    const input = fixture().encode();
    const result = observeRustInventory(input);
    expect(result).toMatchObject({ status: "attention", authenticated: false, resolutionEligible: false,
      runtimeCompleteness: "not_proven", deployedBinding: "not_proven", lockfileComparison: "matched",
      runtime: [a, c], locked: [a, b, c], lockfileOnly: [b], grypeMatches: 0,
      sourceSha, imageId, configId, toolVersions: { syft: "1.56.0", grype: "0.121.1" } });
    expect(result.reportSha256).toEqual({ check: sha256(input.check), syft: sha256(input.syft),
      grype: sha256(input.grype), cargoLock: sha256(cargoLock) });
    expect(result.reasons).toContain("runtime_completeness_not_proven");
    expect(input).toEqual(fixture().encode());
  });

  it("does not treat the producer's claimed L or lock hash as independent lockfile verification", () => {
    const result = observeRustInventory(fixture().encode(false));
    expect(result.lockfileComparison).toBe("not_observed");
    expect(result.reportSha256.cargoLock).toBeNull();
    expect(result.reasons).toContain("independent_lockfile_not_observed");
    expect(result.resolutionEligible).toBe(false);
  });

  it("is deterministic under reordered tuples and allows the exact R = L special case", () => {
    const f = fixture();
    f.check.runtime_crate_tuples = [c, a, b];
    f.check.locked_crate_tuples.reverse();
    f.check.runtime_crates = 3;
    f.check.lockfile_only = [];
    f.syft.artifacts.push({ ...b, type: "rust-crate", foundBy: "cargo-auditable-binary-cataloger" });
    const result = observeRustInventory(f.encode());
    expect(result.runtime).toEqual([a, b, c]);
    expect(result.lockfileOnly).toEqual([]);
    expect(result.runtimeCompleteness).toBe("not_proven");
  });

  it("deduplicates Cargo's source-specific package rows only in the unique L tuple view", () => {
    const f = fixture();
    const input = f.encode();
    input.cargoLock = cargoLock + `[[package]]\nname = "example"\nversion = "1.0.0"\nsource = "git+https://example.invalid/repo"\n`;
    f.check.sha256["Cargo.lock"] = sha256(input.cargoLock);
    input.check = JSON.stringify(f.check);
    expect(observeRustInventory(input).locked).toEqual([a, b, c]);
  });

  it("preserves Cargo build metadata as tuple identity rather than erasing it", () => {
    const f = fixture();
    const first = { name: "wasi", version: "0.11.1+wasi-snapshot-preview1" };
    const second = { name: "wasi", version: "0.11.1+another-build" };
    f.check.runtime_crate_tuples = [first];
    f.check.locked_crate_tuples = [first, second];
    f.check.lockfile_only = [second];
    f.check.runtime_crates = 1;
    f.check.locked_crates = 2;
    f.syft.artifacts = [{ ...first, type: "rust-crate", foundBy: "cargo-auditable-binary-cataloger" }];
    const result = observeRustInventory(f.encode(false));
    expect(result.runtime).toEqual([first]);
    expect(result.lockfileOnly).toEqual([second]);
    expect(result.locked).toHaveLength(2);
  });

  it("retains positive scanner counts rather than turning them into absence", () => {
    const f = fixture();
    f.grype.matches.push({ artifact: { ...a, type: "rust-crate" }, vulnerability: { id: "TEST-advisory" } });
    f.check.grype_matches = 1;
    const result = observeRustInventory(f.encode());
    expect(result.grypeMatches).toBe(1);
    expect(result.resolutionEligible).toBe(false);
  });

  it.each([
    ["duplicate runtime", (f: ReturnType<typeof fixture>) => f.check.runtime_crate_tuples.push(a)],
    ["duplicate locked", f => f.check.locked_crate_tuples.push(b)],
    ["duplicate complement", f => f.check.lockfile_only.push(b)],
    ["missing complement", f => { f.check.lockfile_only = []; }],
    ["overlapping complement", f => { f.check.lockfile_only = [a, b]; }],
    ["unknown runtime", f => { f.check.runtime_crate_tuples[0] = { name: "unexpected", version: "1.0.0" }; }],
    ["empty runtime", f => { f.check.runtime_crate_tuples = []; f.check.runtime_crates = 0; }],
    ["empty locked", f => { f.check.locked_crate_tuples = []; f.check.locked_crates = 0; }],
    ["wrong runtime count", f => { f.check.runtime_crates = 3; }],
    ["wrong locked count", f => { f.check.locked_crates = 2; }],
    ["missing native tuple", f => { f.syft.artifacts.pop(); }],
    ["extra native tuple", f => f.syft.artifacts.push({ ...b, type: "rust-crate", foundBy: "cargo-auditable-binary-cataloger" })],
    ["duplicate native tuple", f => f.syft.artifacts.push(f.syft.artifacts[0]!)],
    ["wrong cataloger", f => { f.syft.artifacts[0]!.foundBy = "cargo-lock-cataloger"; }],
    ["wrong native type", f => { f.syft.artifacts[0]!.type = "npm"; }],
    ["bad tuple version", f => { f.check.runtime_crate_tuples[0] = { ...a, version: "latest" }; }],
    ["bad tuple name", f => { f.check.runtime_crate_tuples[0] = { ...a, name: "a/b" }; }],
    ["mutable image tag", f => { f.check.image_id = "bot:latest"; }],
    ["bad source SHA", f => { f.check.source_sha = "main"; }],
    ["claimed completeness", f => { f.check.runtime_completeness = "proven"; }],
    ["reported suppression", f => { f.check.suppressed_count = 1; }],
    ["ignored scanner matches", f => { f.grype.ignoredMatches = [{}]; }],
    ["scanner count mismatch", f => { f.check.grype_matches = 1; }],
    ["scanner unknown tuple", f => { f.grype.matches = [{ artifact: { ...b, type: "rust-crate" } }]; f.check.grype_matches = 1; }],
    ["scanner bad match", f => { f.grype.matches = [{}]; f.check.grype_matches = 1; }],
    ["wrong scanner source", f => { f.grype.source.target.imageID = imageId; }],
    ["wrong native source", f => { f.syft.source.metadata.userInput = "bot:latest"; }],
    ["nonimage source", f => { f.syft.source.type = "directory"; }],
    ["missing scanner version", f => { delete f.grype.descriptor.version; }],
    ["wrong native tool", f => { f.syft.descriptor.name = "other"; }],
  ] satisfies Array<[string, (f: ReturnType<typeof fixture>) => unknown]>)("rejects %s, even after hashes are recomputed", (_, change) => {
    const f = fixture();
    change(f);
    expect(() => observeRustInventory(f.encode())).toThrow();
  });

  it.each(["sourceSha", "imageId", "configId"] as const)("rejects a different expected %s", field => {
    const input = fixture().encode();
    input.expected[field] = "different";
    expect(() => observeRustInventory(input)).toThrow("rust_expected_binding_mismatch");
  });

  it.each(["syft", "grype", "cargoLock"] as const)("rejects changed %s bytes without hash repair", field => {
    const input = fixture().encode();
    input[field] += "\n";
    expect(() => observeRustInventory(input)).toThrow(/hash_mismatch/);
  });

  it.each(["check", "syft", "grype"] as const)("rejects missing, invalid, ambiguous and oversized %s JSON", field => {
    for (const content of ["", "null", "[]", "{", '{"a":1,"a":2}', " ".repeat(8 * 1024 * 1024 + 1)]) {
      const input = fixture().encode();
      input[field] = content;
      expect(() => observeRustInventory(input)).toThrow();
    }
  });

  it("rejects oversized tuple arrays without truncating them", () => {
    const f = fixture();
    f.check.runtime_crate_tuples = Array.from({ length: 10_001 }, () => a);
    expect(() => observeRustInventory(f.encode())).toThrow("rust_tuple_capacity_or_shape");
  });

  it.each(["version = 2\n", "not toml", cargoLock.replace('version = "2.0.0"', 'version = "3.0.0"')])("rejects an invalid or mismatched independent lockfile", content => {
    const f = fixture();
    f.check.sha256["Cargo.lock"] = sha256(content);
    const input = f.encode();
    input.cargoLock = content;
    expect(() => observeRustInventory(input)).toThrow();
  });
});
