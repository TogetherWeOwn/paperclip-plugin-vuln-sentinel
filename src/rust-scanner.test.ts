import { describe, expect, it } from "vitest";
import { canonicalJson, sha256 } from "./identity.js";
import { observeRustScanner, type RustScannerReports } from "./rust-inventory.js";

function fixture() {
  const crate = { name: "example", version: "1.0.0" };
  const imageId = `sha256:${"a".repeat(64)}`;
  const configId = `sha256:${"b".repeat(64)}`;
  const layerId = `sha256:${"c".repeat(64)}`;
  const binaryPath = "/app/example";
  const binaryHash = "d".repeat(64);
  const sourceSha = "e".repeat(40);
  const metadata = { userInput: imageId, imageID: configId };
  const toolVersions = { syft: "1.56.0", grype: "0.121.1" };
  const syftConfig: Record<string, unknown> = {
    catalogers: { requested: { default: ["cargo-auditable-binary-cataloger", "file"] }, used: [
      "cargo-auditable-binary-cataloger", "file-content-cataloger", "file-digest-cataloger",
      "file-executable-cataloger", "file-metadata-cataloger",
    ] }, search: { scope: "squashed" }, files: { hashers: ["sha-1", "sha-256"] },
  };
  const grypeConfig: Record<string, unknown> = {
    search: { scope: "squashed" }, "only-fixed": false, "only-notfixed": false, "ignore-wontfix": "",
    exclude: [], "vex-documents": [], "vex-add": [], ignore: [],
  };
  const syft = {
    artifacts: [{ ...crate, type: "rust-crate", foundBy: "cargo-auditable-binary-cataloger",
      metadataType: "rust-cargo-audit-entry", metadata: { ...crate },
      locations: [{ path: binaryPath, accessPath: binaryPath, layerID: layerId }] }],
    files: [{ location: { path: binaryPath, layerID: layerId },
      metadata: { type: "RegularFile", size: 123 }, executable: { format: "elf", hasEntrypoint: true },
      digests: [{ algorithm: "sha256", value: binaryHash }] }],
    source: { type: "image", metadata },
    descriptor: { name: "syft", version: toolVersions.syft, configuration: syftConfig },
  };
  const grype = { matches: [], ignoredMatches: [] as unknown[] | undefined,
    source: { type: "image", target: metadata },
    descriptor: { name: "grype", version: toolVersions.grype, configuration: grypeConfig } };
  const check = { source_sha: sourceSha, image_id: imageId, config_id: configId,
    runtime_crate_tuples: [crate], locked_crate_tuples: [crate], lockfile_only: [],
    runtime_crates: 1, locked_crates: 1, grype_matches: 0, suppressed_count: 0, runtime_completeness: "not_proven",
    sha256: { "Cargo.lock": "f".repeat(64), "runtime-crates.syft.json": "", "runtime-crates.grype.json": "" } };
  const scannerExpected: RustScannerReports["scannerExpected"] = { binaryPath, toolVersions, binarySha256: binaryHash };
  const encode = (): RustScannerReports => {
    const syftContent = JSON.stringify(syft);
    const grypeContent = JSON.stringify(grype);
    check.sha256["runtime-crates.syft.json"] = sha256(syftContent);
    check.sha256["runtime-crates.grype.json"] = sha256(grypeContent);
    return { check: JSON.stringify(check), syft: syftContent, grype: grypeContent,
      expected: { sourceSha, imageId, configId }, scannerExpected: structuredClone(scannerExpected) };
  };
  return { syft, grype, syftConfig, grypeConfig, check, scannerExpected, encode };
}

describe("offline native scanner and binary observations", () => {
  it("binds native tuples to the exact reported binary while retaining every authority gap", () => {
    const f = fixture();
    const input = f.encode();
    const before = structuredClone(input);
    const result = observeRustScanner(input);
    expect(result).toMatchObject({ status: "attention", authenticated: false, resolutionEligible: false,
      scannerPolicy: "not_proven", binary: { path: "/app/example", layerId: `sha256:${"c".repeat(64)}`,
        sha256: "d".repeat(64), digestComparison: "matched" }, grypeIgnoreRules: 0,
      suppressionAccounting: "reported_empty", inventory: { lockfileComparison: "not_observed",
        runtimeCompleteness: "not_proven", deployedBinding: "not_proven", resolutionEligible: false } });
    expect(result.configurationSha256).toEqual({ syft: sha256(canonicalJson(f.syftConfig)),
      grype: sha256(canonicalJson(f.grypeConfig)) });
    expect(result.reasons).toEqual(expect.arrayContaining(["scanner_policy_not_proven",
      "binary_bytes_not_independently_verified", "reported_configuration_is_not_execution_proof"]));
    expect(input).toEqual(before);
    expect(observeRustScanner(input)).toEqual(result);
  });

  it("does not assume ignore rules are harmless or absent suppression fields mean zero", () => {
    const f = fixture();
    f.grypeConfig.ignore = [{ package: { type: "deb", name: "kernel-headers" } }];
    f.grype.ignoredMatches = undefined;
    delete f.scannerExpected.binarySha256;
    const result = observeRustScanner(f.encode());
    expect(result).toMatchObject({ scannerPolicy: "not_proven", grypeIgnoreRules: 1,
      suppressionAccounting: "not_observed", binary: { digestComparison: "not_observed" } });
    expect(result.reasons).toEqual(expect.arrayContaining(["grype_ignore_rules_require_independent_review",
      "grype_suppression_accounting_not_observed", "independent_binary_digest_not_observed"]));
  });

  it("retains config changes in hashes without turning them into policy approval", () => {
    const f = fixture();
    const before = observeRustScanner(f.encode());
    f.grypeConfig["show-suppressed"] = true;
    const after = observeRustScanner(f.encode());
    expect(after.configurationSha256.grype).not.toBe(before.configurationSha256.grype);
    expect(after.scannerPolicy).toBe("not_proven");
  });

  it("allows unrelated reported executable files without confusing them with the expected binary", () => {
    const f = fixture();
    const other = structuredClone(f.syft.files[0]!);
    other.location.path = "/lib/other";
    f.syft.files.unshift(other);
    expect(observeRustScanner(f.encode()).binary.path).toBe("/app/example");
  });

  it.each([
    ["missing configuration", (f: ReturnType<typeof fixture>) => { f.syft.descriptor.configuration = undefined as never; }],
    ["missing catalogers", f => { delete f.syftConfig.catalogers; }],
    ["lockfile cataloger", f => { f.syftConfig.catalogers = { requested: { default: ["rust"] }, used: [] }; }],
    ["duplicate used cataloger", f => {
      const catalogers = f.syftConfig.catalogers as { used: string[] };
      catalogers.used[1] = catalogers.used[0]!;
    }],
    ["missing executable cataloger", f => {
      const catalogers = f.syftConfig.catalogers as { used: string[] };
      catalogers.used = catalogers.used.filter(name => name !== "file-executable-cataloger");
    }],
    ["extra requested cataloger", f => {
      const catalogers = f.syftConfig.catalogers as { requested: { default: string[] } };
      catalogers.requested.default.push("cargo-lock-cataloger");
    }],
    ["missing file hasher", f => { f.syftConfig.files = { hashers: ["sha-1"] }; }],
    ["wrong Syft scope", f => { f.syftConfig.search = { scope: "all-layers" }; }],
    ["wrong Grype scope", f => { f.grypeConfig.search = { scope: "all-layers" }; }],
    ["Syft exclude", f => { f.syftConfig.exclude = ["**/example"]; }],
    ["only fixed", f => { f.grypeConfig["only-fixed"] = true; }],
    ["only not fixed", f => { f.grypeConfig["only-notfixed"] = true; }],
    ["unknown only fixed", f => { delete f.grypeConfig["only-fixed"]; }],
    ["wrong type only fixed", f => { f.grypeConfig["only-fixed"] = "false"; }],
    ["ignore wontfix", f => { f.grypeConfig["ignore-wontfix"] = "all"; }],
    ["excluded binary", f => { f.grypeConfig.exclude = ["/app/example"]; }],
    ["VEX document", f => { f.grypeConfig["vex-documents"] = ["file.json"]; }],
    ["VEX status", f => { f.grypeConfig["vex-add"] = ["not_affected"]; }],
    ["missing filter accounting", f => { delete f.grypeConfig.exclude; }],
    ["invalid ignore rule", f => { f.grypeConfig.ignore = [null]; }],
    ["missing ignore accounting", f => { delete f.grypeConfig.ignore; }],
    ["ignored matches", f => { f.grype.ignoredMatches = [{}]; }],
    ["wrong Syft version", f => { f.scannerExpected.toolVersions.syft = "other"; }],
    ["wrong Grype version", f => { f.scannerExpected.toolVersions.grype = "other"; }],
    ["missing binary", f => { f.syft.files = []; }],
    ["duplicate binary", f => { f.syft.files.push(structuredClone(f.syft.files[0]!)); }],
    ["wrong binary path", f => { f.scannerExpected.binaryPath = "/app/other"; }],
    ["relative binary path", f => { f.scannerExpected.binaryPath = "app/example"; }],
    ["dot binary path", f => { f.scannerExpected.binaryPath = "/app/./example"; }],
    ["parent binary path", f => { f.scannerExpected.binaryPath = "/app/../example"; }],
    ["double slash binary path", f => { f.scannerExpected.binaryPath = "/app//example"; }],
    ["wrong digest expectation", f => { f.scannerExpected.binarySha256 = "f".repeat(64); }],
    ["missing binary digest", f => { f.syft.files[0]!.digests = []; }],
    ["duplicate binary digest", f => { f.syft.files[0]!.digests.push(f.syft.files[0]!.digests[0]!); }],
    ["invalid binary digest", f => { f.syft.files[0]!.digests[0]!.value = "bad"; }],
    ["invalid layer", f => { f.syft.files[0]!.location.layerID = "latest"; }],
    ["symlink binary", f => { f.syft.files[0]!.metadata.type = "SymbolicLink"; }],
    ["empty binary", f => { f.syft.files[0]!.metadata.size = 0; }],
    ["noninteger binary size", f => { f.syft.files[0]!.metadata.size = 1.5; }],
    ["nonELF binary", f => { f.syft.files[0]!.executable.format = "mach-o"; }],
    ["no entrypoint", f => { f.syft.files[0]!.executable.hasEntrypoint = false; }],
    ["wrong crate metadata type", f => { f.syft.artifacts[0]!.metadataType = "lockfile"; }],
    ["wrong crate metadata", f => { f.syft.artifacts[0]!.metadata.version = "2.0.0"; }],
    ["missing crate location", f => { f.syft.artifacts[0]!.locations = []; }],
    ["ambiguous crate location", f => { f.syft.artifacts[0]!.locations.push(f.syft.artifacts[0]!.locations[0]!); }],
    ["crate at other binary", f => { f.syft.artifacts[0]!.locations[0]!.path = "/app/other"; }],
    ["crate at other layer", f => { f.syft.artifacts[0]!.locations[0]!.layerID = `sha256:${"a".repeat(64)}`; }],
    ["crate via other path", f => { f.syft.artifacts[0]!.locations[0]!.accessPath = "/app/other"; }],
    ["oversized file list", f => { f.syft.files = Array.from({ length: 10_001 }, () => f.syft.files[0]!); }],
    ["oversized ignore list", f => { f.grypeConfig.ignore = Array.from({ length: 10_001 }, () => ({})); }],
  ] satisfies Array<[string, (f: ReturnType<typeof fixture>) => unknown]>)('rejects %s even with repaired report hashes', (_, change) => {
    const f = fixture();
    change(f);
    expect(() => observeRustScanner(f.encode())).toThrow();
  });
});
