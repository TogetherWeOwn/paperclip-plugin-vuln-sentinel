# Source-only library delivery

## Delivered boundary

This delivery preserves checkpoint `ad6ae6225e0dfc32ef130f3efe10f48f68f499fb`
(tree `0c672e487ecf902b9244623b6afd7ca4dd8d9e50`). It delivers existing library
source for review, not a completed vulnerability service or installed plugin.
No rule 0–8 is claimed operationally complete. The original installation and
report-only pilot acceptance remain open and unchanged.

**Publication: NOT ADMISSIBLE / OFF. Trusted acquisition, adapter and method
version sets: EMPTY. Registration: rejecting, not implemented by this package.**
The frozen `publication-ownership-map/v1` at consumer source `5c0f718` and migrations
001–012 approves no trusted version. Later local library commits do not inherit
approval. The complete authority adapter and partial rejecting-registration
lifecycle/journal groundwork both remain deferred. This document implements neither.

Keep both source/routing pins and claim uncertainty whenever the authority contract
requires them. Never retry an ambiguous create or issue a second create. Local
hashes, compare-and-swap, callback strings and worker-written journals cannot certify
authenticated acquisition, complete host effects, settlement or cleanup authority.

## Package and export inventory

`package.json` declares private ESM package
`@togetherweown/paperclip-plugin-vuln-sentinel@0.1.0`, requiring Node >=24. There is
one export, `.`: `dist/index.js` with `dist/index.d.ts`. There are no subpath exports,
CLI `bin`, manifest, plugin worker, registration entrypoint or registered jobs.
`src/index.ts` is the complete public barrel; module names below are source paths,
not additional package exports. `npm run build` emits the library and declarations;
build output is ignored, not committed.

The package file allowlist is `dist`, `migrations`, `README.md` (npm also includes
package metadata). This is not registry publication or installation authorization.
The `docs` directory and verification script are source-review materials outside
that allowlist; the source checkout is the delivery, not an installable plugin.

| Source modules | Public values from the barrel | Public types from the barrel |
| --- | --- | --- |
| `matcher`, `version-set` | `decide`, `aggregateFindingInputs`, `versionInputs` | See `model` below |
| `identity`, `ranges` | `aliasClosure`, `canonicalJson`, `findingIdentity`, `sha256`, `osvVersionStatus`, `OSV_RANGES_VERSION` | `OsvAffected`, `OsvRange`, `VersionStatus` |
| `inventory` | `parseLockfileInventory`, `INVENTORY_TOOLS` | `LockfileInventory`, `InventoryDependency`, `InventoryFile` |
| `rust-inventory` | `observeRustInventory`, `observeRustScanner` | `CrateTuple`, `RustInventoryReports`, `RustInventoryObservation`, `RustScannerReports`, `RustScannerObservation` |
| `npm-manifest`, `npm-root-context` | `observeNpmManifest`, `NPM_MANIFEST_VERSION`, `observeNpmRootContext`, `NPM_ROOT_CONTEXT_VERSION` | `NpmManifestObservation`, `NpmRootContextObservation` |
| `pnpm-importer-context` | `observePnpmImporterContext`, `PNPM_IMPORTER_CONTEXT_VERSION` | `PnpmImporterContextObservation` |
| `cargo-manifest`, `cargo-lockfile-context` | `observeCargoManifest`, `CARGO_MANIFEST_VERSION`, `observeCargoLockfileContext`, `CARGO_LOCKFILE_CONTEXT_VERSION` | `CargoManifestCandidate`, `CargoManifestObservation`, `CargoLockfileContextObservation` |
| `osv`, `osv-fixes`, `osv-severity` | `OsvSource`, `osvFindingInputs`, `parseOsvRecord`, `observeOsvFixes`, `OSV_FIXES_VERSION`, `cvssV3Base`, `observeOsvSeverity`, `OSV_SEVERITY_VERSION` | `OsvDependency`, `OsvRecord`, `OsvSnapshot`, `OsvFixObservation`, `OsvFixCandidate`, `OsvSeverityObservation` |
| `github-discovery`, `github-lockfiles`, `source-http` | `GitHubRepositoryDiscovery`, `discoveryCoverage`, `validateRepositoryDiscovery`, `GitHubLockfiles`, `SourceAttention` | `RepositoryDiscovery`, `RepositoryTreeEntry`, `DiscoveryCoverage`, `RepositorySource`, `RepositoryLockfiles`, `LockfileBlob`, `SourceFetch` |
| `dependabot`, `dependabot-journal`, `dependabot-context` | `DependabotSource`, `validateDependabotSnapshot`, `DependabotJournal`, `DependabotContext` | `DependabotRead`, `DependabotAlert`, `DependabotSnapshot`, `DependabotTupleContext`, `DependabotAlertContext`, `DependabotRepositoryContext` |
| `threat-feeds`, `threat-journal` | `ThreatFeeds`, `parseKev`, `enrichThreats`, `enrichThreatInputs`, `validateThreatSnapshot`, `ThreatJournal` | `KevSnapshot`, `EpssModel`, `EpssSnapshot`, `ThreatSnapshot` |
| `source-journal`, `source-polls`, `discovered-source-sync` | `SourceJournal`, `SourcePollStore`, `RepositorySourceSync`, `DiscoveredRepositorySourceSync` | `StoredLockfiles`, `StoredOsvScan`, `SourcePoll`, `CurrentSource` |
| `source-decisions`, `repository-scan`, `source-comparison` | `SourceDecisions`, `RepositoryScan`, `SourceComparison` | `SourceDecisionResult`, `RepositoryScanOptions`, `RepositoryScanResult`, `SourceComparisonResult`, `OsvComparisonObservation` |
| `journal`, `routing` | `DecisionJournal`, `DeliveryRouting`, `WEEKLY_ORIGIN_KIND`, `utcWeekStart`, `weeklyOrigin` | `StoredDecision`, `RoutingSnapshot`, `RoutingMember`, `RoutingContainer`, `RoutingResult`, `RemediationRelationship` |
| `claims` | `CardDelivery`, `ClaimStore`, `DATABASE_NAMESPACE`, `FINDING_ORIGIN_KIND` | `Claim`, `DeliveryInput`, `DeliveryResult`, `IssuePort`, `RecoveryProof` |
| `publication`, `source-publication`, `source-effects`, `rescan` | `ContainerPublication`, `SourcePublicationStore`, `SourceEffects` | `PublicationResult`, `SourcePublicationResult`, `SourceEffectIntent`, `SourceEffectBarrier`, `RescanEvidence`, `ResolutionRecord` |
| `publication-diagnostics`, `repository-health` | `PublicationDiagnostics`, `RepositoryHealth` | `PublicationDiagnosticResult`, `RepositoryHealthResult` |
| `model` (wildcard export) | `RULES_VERSION` | `Priority`, `Applicability`, `Scope`, `Ecosystem`, `Advisory`, `SourceSelection`, `Provenance`, `BoundEvidence`, `PlatformEvidence`, `GoEvidence`, `FunctionEvidence`, `FindingInput`, `VersionSetInput`, `DecisionInput`, `FindingIdentity`, `Remediation`, `ProposedVex`, `Decision` |

Internal helpers such as `github-repository`, `pnpm-yaml` and `source-fence` are not
public barrel exports. Runtime dependencies are exact pins: `semver@7.7.4`,
`smol-toml@1.9.1`, `yaml@2.9.1`. The plugin SDK is a development dependency used for
type-only imports; it does not register or enable this library. Existing
`migrations/001`–`012` are source/schema fixtures shipped with the checkpoint, not
new or executed host DDL. No migration is added or changed in this delivery.

## Claim → evidence → gap matrix

All tests below are repository-relative paths under `src/`. Tests describe library
regressions, not independent authentication or operational acceptance. Their actual
final-head results must be recorded separately; a listed test is not a claim it ran.

| Library claim supported at this checkpoint | Evidence files | Limits / missing acceptance |
| --- | --- | --- |
| Deterministic normalized-input rules, priority/scope post-pass and version-set reduction retain provenance | `matcher.test.ts`, `version-set.test.ts`, `ranges.test.ts`, `journal.test.ts` | Synthetic validated inputs; no operational completion of rules 0–8, authenticated evidence producer or deployed artifact/reachability coverage |
| Strict npm OSV range proofs, retained exact-package CVSS v3 observations and reported fix boundaries | `osv.test.ts`, `osv-severity.test.ts`, `osv-fixes.test.ts` | No CVSS v4 scoring; unsupported/absent evidence stays unknown; reported fixes do not certify release availability, owner association or compatible all-version remediation |
| Exact-tree manifest observations and bounded candidate comparisons | `npm-manifest.test.ts`, `npm-root-context.test.ts`, `pnpm-importer-context.test.ts`, `cargo-manifest.test.ts`, `cargo-lockfile-context.test.ts` | No verified workspace/member/installed-owner association, dependency resolution, stronger scope or compatible-fix claim; observations retain attention/unknown and conflicts |
| Bounded locked-entry inventories and offline Rust producer observations | `inventory.test.ts`, `rust-inventory.test.ts`, `rust-scanner.test.ts` | npm v2/v3, pnpm v9, Cargo v3/v4 only; no complete closure, native scanner execution, source authenticity or coverage inferred from empty results |
| Immutable discovery, content reads, raw retention and source-poll ordering | `github-discovery.test.ts`, `github-lockfiles.test.ts`, `source-journal.test.ts`, `source-polls.test.ts`, `discovered-source-sync.test.ts` | Injected fake HTTP and in-memory PGlite; ETag/content identity is not trusted acquisition or an authenticated host boundary; no enabled source transport/job |
| Retained OSV/feed orchestration into local fenced decisions/routing | `source-decisions.test.ts`, `repository-scan.test.ts`, `threat-feeds.test.ts`, `threat-journal.test.ts` | Fake responses and retained fixtures, not live acquisition/scans, scheduled refresh or native publication; no live EPSS model configuration claim |
| Bound Dependabot observations, path/tuple joins and query-only source comparison | `dependabot.test.ts`, `dependabot-journal.test.ts`, `dependabot-context.test.ts`, `source-comparison.test.ts` | No provider selection/switching/reconciliation, permission-aware fallback, complete repository coverage or automatic policy enrichment |
| Local claims, weekly routing, lineage and publication guard/recovery mechanisms | `claims.test.ts`, `routing.test.ts`, `publication.test.ts`, `source-publication.test.ts`, `source-effects.test.ts`, `source-fence.test.ts` | Fake native issues/callbacks and worker-writable stores; not admissible effect authority. No ambiguous-create retry or second create is authorized |
| Rescan result validation and retained resolution history at a typed library boundary | `rescan.test.ts` | Fixture receipt strings are not authenticated real scanner receipts, host settlement or permission to resolve a live finding |
| Read-only held-publication diagnostics and disabled repository health observations | `publication-diagnostics.test.ts`, `repository-health.test.ts` | No installed health endpoint/counters, enabled jobs, managed triage project or operational runbook |

`src/test/database.ts` applies the existing schema to in-memory PGlite. This can
exercise SQL predicates and interleaved local callers, not real authenticated
pooled-DB/cross-process/restart boundaries. `src/test/issues.ts` and the source,
threat, Dependabot and rescan helpers are fixtures, not actual host adapters.
`check:host` can inspect SQL with an explicitly supplied installed validator module,
but is optional source compatibility evidence, not host writes or authority approval.

### Authority acceptance — all twelve groups NOT RUN

The following labels summarize the unchanged authority contract; they do not replace
or narrow its full scenarios, bindings or identifiers. None is satisfied by this
source delivery, local regression tests, fake HTTP, PGlite or fixture receipts.

| Group | Actual authority-boundary acceptance | Status |
| --- | --- | --- |
| 1 | Clean create/reuse/refresh/reopen/no-effect and complete authenticated effect graph | NOT RUN |
| 2 | Admission/seal races in both orders, including pause before send | NOT RUN |
| 3 | Pending handlers/callbacks/descendants at return and old-token rejection | NOT RUN |
| 4 | Committed create followed by logging/response/ack/link-CAS loss | NOT RUN |
| 5 | Timeout/late commit/concurrent handler/cancellation/death/early empty lookup | NOT RUN |
| 6 | Crash/restart at every reservation, send, commit, outcome, seal, audit and cleanup step | NOT RUN |
| 7 | Concurrent verifiers/outcomes/certificates and exact-owner cleanup replay | NOT RUN |
| 8 | Forged receipts and every identity/version/token/source/member/routing/payload/destination/reopen mismatch | NOT RUN |
| 9 | Journal/store ambiguity and missing/duplicate/incomplete effect membership | NOT RUN |
| 10 | Every alternate/manual/legacy/retry path, reused RPC IDs and two publications | NOT RUN |
| 11 | Freshness expiry during admitted work without releasing retained bindings | NOT RUN |
| 12 | Actual authenticated pooled-DB/cross-process/restart boundary and projection cleanup | NOT RUN |

## Finite delivery delta ledger

Beyond the exact checkpoint, only these delivery corrections are included:

1. This source inventory, claim/evidence/gap matrix and unchanged acceptance holds.
2. README navigation to this document and the native install-policy requirement.
3. `.npmrc`: three-day native npm release-age filtering and lifecycle-script refusal.
   No dependency manifest, lockfile or exemption changes.
4. `.github/workflows/ci.yml`: pinned, read-only source verification using the existing
   test/typecheck/build commands, workflow lint and redacted secret scanning. Draft
   PRs skip the library suite; ready/source changes run it, docs-only changes skip
   it, and default-branch/nightly runs verify the full library. No deploy, source
   scan, package release, plugin job or runtime registration is introduced.

5. `.github/workflows/codeql.yml`: pinned JavaScript/TypeScript advanced analysis,
   with no dependency installation or build, bounded permissions and timeouts,
   draft skips and weekly coverage. It does not acquire vulnerability feeds.
6. `src/inventory.ts`: replace all slashes when comparing the encoded npm tarball
   path. The existing `npmName` validation admits at most one slash, so accepted
   inputs and retained inventory/version identity are unchanged. `inventory.test.ts`
   explicitly covers the already-supported encoded scoped name in npm v2 and v3.
7. `src/repository-scan.test.ts`: exact parsed host matching for fake CISA/EPSS
   responses and the no-GitHub-request assertion, rather than URL substrings.
8. `src/source-journal.test.ts`: assert the fixture starts with an object opener,
   then splice the intentional lone-surrogate field into that position. This is
   malformed fixture construction, not a string sanitizer.

These are finite delivery/CodeQL corrections, not new policy or capability.
All other library/test source and all migrations remain byte-identical to the
checkpoint. Final Git head/tree, delta paths, actual commands/results, native
reviews and required GitHub Actions evidence belong in the delivery record,
pinned to the reviewed head. Historical **2,460 tests / 37 files** is not
final-head verification; the two encoded-tarball cases also need Actions evidence.

### Install-policy evidence and limits

The delivery environment uses Node `24.21.0` and npm `11.19.0`, which recognizes
`min-release-age=3` and `ignore-scripts=true`. CI pins the same Node release (which
bundles npm `11.19.0`) and rejects unsupported older npm. Root scripts contain no
install/prepare/pack lifecycle hooks. The lock's only `hasInstallScript` entry is
optional Darwin-only `fsevents@2.3.3`; it is skipped on Linux. All lifecycle hooks
are refused; exceptions are empty. Named `check`, typecheck, test and build commands
are intentionally executed after inspection.

A frozen lock and a successful `npm ci` do not retrospectively prove publication
age, provenance or dependency safety. All locked resolved URLs use the npm registry;
there are no Git/local/direct-URL dependency sources. This delivery does not update
dependencies, loosen security-update policy or enable scripts. Checksum-pinned
workflow tools are downloaded into separate temporary directories, not installed as
workspace dependencies.

CodeQL is not silently treated as passed. The repository was separately made
public after publication review, allowing free advanced analysis; empty-language
default setup was separately disabled because it blocked advanced uploads.
Neither setting transition is analysis coverage. Actual successful analysis,
alert disposition and required checks must be verified on the delivery head
before merge. No paid feature, check waiver or security exception is introduced.
The inherited org standards workflow remains controlling. Full test suites,
typecheck/build and security CI run on GitHub Actions, not on the shared host.

## Explicit exclusions and stopping condition

No CVSS v4, provider switching/reconciliation, stronger compatible-fix/owner/workspace/
release/all-version assertions, new runtime entrypoint/manifest/registration/job/
transport, authority implementation/mirror/protocol, migration/DDL, live acquisition/
scan, installation/configuration, finding publication/assignment/mass wakeup,
remediation/dismissal, production action, Docker allocation or plugin LLM call is
part of this delivery. Actual runtime wiring, complete coverage, authenticated
receipts, operational health/counters/runbook, operator installation and two real
consecutive report-only runs remain missing pilot acceptance.

Source-only merge does not close the original consumer, permit authority re-entry,
install or enable the package, start another source-policy feature slice or trigger
a release. Stop after reviewed source-only merge and evidence handoff. Production
classification and all normal merge/release gates still apply independently.

REA angle: reuse the existing retained-source/ETag, exact-byte/tree identity and
negative authority mapping as evidence of this library boundary; do not add another
reverse-engineering pass, transport, resolver, scheduler or authority mirror.
