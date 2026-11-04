# Vulnerability Sentinel

Deterministic vulnerability matching and report-only triage for Paperclip.

## Implementation status

**Core implementation only; not an installable plugin or an enabled pilot yet.**
There is deliberately no worker/manifest entrypoint. Nothing schedules scans,
contacts an advisory provider, mutates a repository, or creates live issues just
by importing this package or running its tests. Explicit read-only source adapters
accept an injected HTTP transport; all adapter tests use fake responses.

**Publication contract: NOT ADMISSIBLE.** The frozen
`publication-ownership-map/v1` review of consumer source `5c0f718` and migrations
001–012 approves **no trusted adapter or method version**. Source, routing, claim,
link, pin and history records are worker writable. Exact-owner CAS, matching hashes,
callback proof strings and worker mirrors are not authenticated source or settlement
authority. Newer source revisions do not inherit compatibility approval. Keep
publication off; do not connect these library effect/recovery callbacks to a trusted
adapter. Independent source and local report work may continue.

Implemented:

- Deterministic rule evaluation, mandatory scope/priority post-pass, proposed
  remediation, proposed expiring VEX, and all-alias finding identity.
- Append-only input/provenance/decision journal in the plugin DB namespace.
- A shared atomic issue-creation guard with exact-origin lookup, unassigned
  report-only creates, modified-advisory refresh/reopen, and fenced recovery.
- Conservative OSV npm SEMVER range evaluation. Unsupported range syntax or
  ecosystems return `unknown`, never proof that a package is outside a range.
- Durable two-level finding/container routing, UTC weekly buckets, sticky membership,
  P0 promotion requests, alias redirects and evidenced replacement lineage.
- Explicit report-only container rendering/publication through the same guard,
  with monotonic revision/content checks, original-batch P0 promotion, and external
  closure-mismatch reopening. Tests use only fake native issues.
- Validated complete-new-digest per-member rescan resolution, retained receipt
  history, conservative reopening and unrelated resolved-member isolation. This is
  a trusted-adapter library boundary, not a live scanner callback endpoint.

- Read-only immutable GitHub tracked-tree manifest/lockfile discovery, exact-tree
  content binding, default-SHA/ETag snapshots, bounded OSV querybatch pagination/detail
  hydration and conservative normalization.
- npm v2/v3, pnpm v9 and Cargo v3/v4 locked-entry inventories with explicit attention
  states and no inferred runtime/development scope or full-closure completeness.
- Immutable raw lockfile/inventory and OSV source journal, exact query-tuple coverage,
  replay-safe inserts and readback validation before returning normalized inputs.
- Read-only organization Dependabot alert traversal with bound cursor pagination,
  separate unavailable/attention states and immutable company-scoped raw evidence.
  Exact-path installed-tuple context is available separately; neither library is
  source switching, repository coverage or policy enrichment.
- Bounded recursive OSV alias/upstream hydration, explicit unavailable documents,
  raw/derived graph checks and conservative connected-source normalization.
- Read-only KEV and date-pinned EPSS adapters, all-alias enrichment and immutable
  company-scoped feed evidence before decisions. No API/model-version guessing.
- Durable company/repository source-poll fences and explicit GitHub→raw-source
  synchronization, including discovery reservations before network I/O, retained
  discovery→content binding and separate cache-only/freshness-bounded selection.
  Late older success/failure cannot replace a newer poll's selected source or hold.
- Source-fenced local decision-head/routing writes, with same-statement source row
  locking, DB poll-revision ordering and retained source-selection provenance.
  The legacy publication API holds source-selected evidence for attention.
- Fixture-only source-pinned publication library integration: exact routing snapshot
  and rendered payload binding, guarded single-invocation dispatch, deadline revocation
  and exact-owner cleanup machinery. This is not an admissible authority boundary;
  worker-written history and callback proofs do not supply an independent host audit.
- Explicit retained OSV/feed→source-fenced decision/routing orchestration, with exact
  parent references, current and historical freshness checks, and coverage attention.
- Same-action all-version reduction for identical non-version context, retaining
  every tuple/proof/trace in one deterministic journal revision before routing.
- Retained Dependabot observations joined to exact current repository/lockfile path,
  package/version/location context, with explicit unsupported and nonmatching states.
- Explicit OSV→retained feeds→source-fenced local decision/routing scan orchestration,
  with current-source/deadline checks and no native publication or enabled pilot.
- Query-only retained Dependabot/OSV comparison for the same current lockfile source,
  preserving mismatches and ambiguous alias bridges without policy mutation or switching.

Still required before installation/pilot acceptance: runtime discovery/source-poll
wiring, manifest/workspace association, other lockfile formats and complete coverage, live source-pinned publication wiring
and trusted host-effect settlement verification, verified scope/fix/severity enrichment
(including incompatible per-version contexts),
Dependabot permission switching, scheduled KEV/EPSS refresh and verified live model
configuration, live rescan receipt verification, manifest/jobs and weekly job scheduling,
managed triage project, health/counters, operator runbook and installation, and two
real consecutive report-only scans. No worker is wired to the explicit publication
API; no weekly batch or per-finding issue has been emitted on a live host.

## Conservative OSV range proofs

The npm `SEMVER` evaluator follows [OSV's range/event and evaluation semantics](https://ossf.github.io/osv-schema/).
Version strings must be strict SemVer 2.0.0, not values silently normalized from a
leading `v`, whitespace or partial version. Valid prereleases use SemVer precedence;
valid build metadata is preserved during validation and ignored for range ordering.
A malformed installed version or npm version enumeration cannot establish exclusion.
An exact reported positive remains positive; enumerations and ranges are additive.

`limit` is a range-wide constraint, not a fixing version or an interval closer.
A candidate must precede **any** explicit limit (or the implicit infinite limit
when none are present). The bare `*` limit is supported as infinity. Limits can
appear anywhere without changing the introduction/fix timeline. Missing introductions,
mixed `fixed`/`last_affected`, malformed events and unsupported syntax remain unknown,
even when a limit alone would exclude the candidate. Non-limit timelines must still
be ordered and alternating; unsorted/ambiguous streams and non-bare wildcard limits
are conservatively unknown rather than guessed. Other ecosystems/range types are
still unsupported by the range comparator, not silently treated as npm SemVer.

Every newly normalized input retains `vuln-sentinel-osv-ranges: 1.1.0` in tool
provenance. Raw records, raw snapshot identities, schema and SQL writers are unchanged;
historical decisions are not rewritten. Corrected observations produce new versioned
inputs through the existing source fences. No range result supplies a verified fix,
runtime safety, a rescan receipt, member resolution or publication authority.

Offline coverage includes strict-version failures, prerelease/build boundaries,
range-wide limits, mixed-event rejection, a 432-case boundary grid and retained-source
concurrent replay. These tests are not real scans or pilot acceptance.

REA angle: reuse the pinned SemVer library's precedence comparator and OSV's published
schema/pseudocode; validate canonical input explicitly rather than relying on its
permissive parser or adding another matching engine.

## Offline exact-tree npm manifest observations

`observeNpmManifest(discovery, path, content, candidate?)` checks a regular tracked
`package.json` against the exact retained repository discovery, Git blob identity
and any reported UTF-8 byte size. It records source commit/tree/discovery and raw
content identities. Duplicate JSON keys (including escaped duplicates), non-JSON
syntax, malformed declarations, symlinks, submodules and mismatched bytes fail
closed. It performs no fetch, package-manager/script execution or database write.

Every `dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies`
declaration remains separate. An optional stable npm candidate is compared by exact
package name against a narrow declared-range subset: full canonical stable-version
exact/caret/tilde/comparators, intersected by whitespace or joined by `||`. Partial,
wildcard, tag, prerelease/build, alias, workspace, file, URL and Git specifiers stay
unsupported/unknown. Other ecosystems and noncanonical candidates are rejected, not
interpreted with npm semantics. Null comparison means that declaration was not queried.
Per-row `matches`/`does_not_match` is **only declared range membership**, never an
advisory applicability result or verified upgrade. Contradictory cross-section rows
are retained rather than choosing override/peer semantics or suppressing a constraint.

Every result stays `attention`, `scope: "unknown"`, `direct: null` and
`compatibleFixVerified: false`. The observer does not associate installed tuples,
lockfiles, workspaces, complete owner constraints, transitive paths or alias targets.
Workspace/override/resolution/pnpm/peer metadata and bundled-dependency fields add
explicit unevaluated attention. A missing declaration is not evidence that the package
is absent, transitive, dev-only or safe. It proves no release availability, current
source freshness/authenticity, compatible all-version fix, remediation, rescan resolution
or publication permission. No result is fed to rule 6 or alters normalized fix fields.

Input is bounded to 2 MiB, 10,000 declarations across all sections and 1 MiB expanded
observation data, failing rather than truncating. Specifiers are limited to 256
characters and eight sets of eight comparator tokens. Versioned content identities,
deterministic replay/input immutability and all capacity holds have offline coverage;
these are not real scans or pilot acceptance. Publication remains NOT ADMISSIBLE/off.

REA angle: reuse existing exact-tree/blob checks, duplicate-aware JSON validation and
the pinned SemVer library, without running package-manager resolution or adding a
second matcher, source transport, authority mirror or runtime entrypoint.

## Offline npm root declaration context

`observeNpmRootContext(discovery, snapshot, lockfilePath, manifestContent, candidate?)` binds
all supplied lockfile bytes to the retained commit/tree, reparses the inventory and
validates the exact colocated `package.json`. For one explicit npm v2/v3 lockfile
or shrinkwrap, it compares that manifest's declarations with the reported
`packages[""]` root record. Every section is retained separately: literal equal
specifiers, different specifiers, manifest-only and lockfile-only rows. Semantic
range equivalence and optional/peer/override precedence are not guessed. Duplicate
JSON keys, malformed declarations, mismatched tree/blob/size or source bindings,
lossy UTF-8 and unsupported selected formats fail closed.

Version `1.1.0` optionally compares one canonical stable npm candidate against each
exact-name declaration on **both** sides, sharing the manifest observer's bounded
range evaluator. `manifestCandidateRangeMatch` and `lockfileCandidateRangeMatch`
retain `matches`, `does_not_match` or `unknown` independently. Unsupported syntax
is unknown, not exclusion; a missing side, unrelated package or omitted candidate
has a null comparison. The corresponding specifier fields and retained
`manifest.candidate` distinguish those cases. Literal differences remain differences
even if both ranges accept the candidate, and cross-section conflicts are not
collapsed into optional/peer/override precedence. Unsupported root specifiers,
missing declarations and candidate mismatches add explicit attention. Other
ecosystems and prerelease/build/noncanonical candidates are rejected before
comparison, even if the manifest has no declaration for the package.

Candidate comparison is declared-range membership only. It neither selects a
version nor resolves the candidate against installed tuples. Matching both sides,
even alongside an OSV-reported fixing boundary, cannot prove release availability,
complete owner/workspace/transitive constraints or an all-version compatible fix.
All original inventory versions and locations remain unchanged; no candidate is
substituted into inventory or normalized policy inputs. The observer version and
candidate/result data participate in the content hash; old observations are not
rewritten or upgraded into authority.

The result includes every same-name npm inventory tuple and location **in the
selected lockfile**, not just one installed version. `rootLocatorReported` only
records whether `node_modules/<reported-package-name>` occurs among those locations.
These are name-only candidates, never resolved dependency or ownership edges.
Aliases, local/workspace references and hoisted/transitive paths are not resolved;
an absent candidate or declaration proves no package absence, safety or scope.
Inventory attention is retained, and known colocated alternate lockfiles add a
selection hold rather than silently choosing a package manager. Nested workspace
owners, transitive constraints and root metadata remain unevaluated.

Results remain `attention`, `scope: "unknown"`, `direct: null` and
`compatibleFixVerified: false`, including when every declaration agrees. Raw
manifest/lockfile, discovery, inventory and observer-version identities support
deterministic offline replay, not source authenticity/freshness, a current-source
permit, complete owner constraints, compatible all-version fix or release
availability. Nothing feeds rule 6, changes normalized fix fields, resolves members
or authorizes publication. The function has no HTTP, database, issue or runtime
port. No schema, writer or authority mapping is changed.

Existing input bounds apply; the observer also fails rather than truncating above
10,000 combined declaration rows or 1 MiB expanded output. Offline tests cover
multiple versions/locations, alias and workspace holds, section conflicts, partial
inventory, exact byte/source binding, malformed/duplicate records, capacity,
per-side candidate membership/unknown/null, OSV-boundary non-promotion and
replay/input immutability. They are not enabled scans or pilot acceptance;
publication remains NOT ADMISSIBLE/off.

REA angle: reuse the existing exact-tree manifest observer and inventory parser,
retaining the lockfile's explicit root declarations rather than executing npm,
adding another resolver, or promoting colocated paths into trusted owner evidence.

## Offline reported OSV fixing boundaries

`observeOsvFixes(snapshot, dependency)` validates the complete retained raw/derived
snapshot and requires the exact queried package/version tuple. For stable canonical
npm versions, it observes strictly newer `fixed` boundaries only in supported SEMVER
ranges that affect the installed tuple and exclude the boundary itself. Enumerations,
`limit`, `last_affected`, unsupported/malformed ranges, unrelated packages, withdrawn
records and ranges that do not affect the tuple cannot supply fixing candidates.
Prerelease/build-version contexts and other ecosystems remain unsupported here, even
though the applicability evaluator supports valid npm prerelease/build ordering.

Every candidate is then checked against **every active source in its alias/upstream
closure**, including all matching affected rows and enumerated versions. Results
retain per-source `affected`/`outside`/`unknown` observations: a positive conflict wins,
and missing/unsupported aliases prevent an all-outside result. Disconnected advisory
groups stay separate. Exact raw advisory hashes/revisions, snapshot/query identity and
observer/evaluator versions remain available for deterministic offline replay.

`outside_reported_ranges` is only a reported-source observation. It is **not** release
availability, manifest/workspace compatibility, complete source discovery, fresh/current
source selection, producer authentication, runtime safety or remediation evidence. Every
report is `attention` with `compatibleFixVerified: false`. No candidate is selected as
a recommendation or fed to matcher rule 6; the normalizer's `fixedVersion` remains null.
Verified manifest constraints, release availability and compatible all-version context
still need independent integration. The observer accepts no HTTP, DB, issue or runtime
port, mutates no snapshot/projection and cannot resolve findings or release either pin.

The observer fails rather than truncating at 100 unique candidates per group, 100,000
weighted evaluation work units or 1 MiB expanded report data. Tests cover alias conflicts,
missing sources, exact package binding, malformed/non-fixing events, unsupported contexts,
replay/input immutability and each capacity hold. These are not enabled scans or pilot
acceptance; publication remains NOT ADMISSIBLE/off.

REA angle: reuse retained raw OSV records, existing alias closure and the conservative
versioned range evaluator, without another matcher, package-manager execution, registry
request, scheduler, dependency or authority record.

## Retained OSV severity enrichment

OSV normalization now combines reported qualitative severity and strict CVSS v3.0/
v3.1 **Base** scores from retained raw advisories. It takes the highest known severity
across active aliases, global vectors and exact ecosystem/package affected-row
vectors; unrelated package rows and withdrawn aliases do not contribute. A lower
vector cannot override a higher label. Medium labels map to the matcher's `moderate`.
No CVSS score changes affected-range status, scope, fixes, VEX or rescan eligibility.

`cvssV3Base` implements the [FIRST v3.1 Base equations and integer Roundup](https://www.first.org/cvss/v3.1/specification-document),
also shared by [v3.0](https://www.first.org/cvss/v3.0/specification-document).
Every required metric must occur once with a valid value. Valid optional temporal/
environmental metrics are checked but do not affect the Base score. Unknown metrics,
duplicates, malformed and oversized vectors are not scored. This is not a CVSS v4
calculator, and v3 scores are never stored in `cvss4Base`.

Missing, zero, malformed or unsupported scores remain explicit severity attention;
a zero score is not evidence of non-exposure. Valid labels/vectors alongside those
gaps remain available without claiming complete severity coverage. Structural and
capacity failures hold instead of returning partial scoring. The local source report
surfaces these attention codes, and each decision retains them and the scorer version
in provenance alongside its immutable raw OSV snapshot. Existing raw-record parsing,
source snapshot identities, database schema and SQL writers are unchanged; new
normalization yields a versioned decision input, not a rewrite of historical decisions.

Tests are offline, including all 2,592 Base-metric combinations, known-score vectors,
active/withdrawn alias reduction, exact-package filtering and retained-source concurrent
replay. This is source-policy library work only, not a live scan, source switch,
trusted receipt, installed runtime or publication permit. CVSS v4, verified scope/fix
context and the remaining installation/pilot gates are still outstanding.

REA angle: reuse the retained raw-source journal and FIRST's published equations;
no scoring service, new dependency, alternate policy engine or parallel scheduler.

## Read-only publication diagnostics

`PublicationDiagnostics.read(companyId, repo)` accepts only the namespace query
interface. It observes source/routing pin **presence**, row revisions, source-history
shape/size and mapped claim-state/attempt counts, without returning tokens, raw proof
history, issue IDs or stored error text. It never calls an issue transport, mutates a
record, releases either pin, invokes a verifier or retries an uncertain claim.

The report always returns `attention`, `enabled: false`, `not_admissible` and an empty
supported-method set. These are static library limitations, **not** authenticated
installed-host capability discovery or a registration endpoint. Missing, corrupt,
over-capacity or unavailable observations never become successful absence. Routing
bundles over 1 MiB are withheld in SQL; malformed or duplicate container identities
prevent claim enumeration. Claim reads are bounded to the exact company's mapped
container origins. Claims have no repository column: orphan, legacy and unmapped claims
are deliberately **not** covered. Empty counts cannot certify zero repository claims,
settlement or permission for a create. Each count describes stored worker state only,
not independently verified effect accounting or successful enabled-pilot stage counts.

Reads are not an atomic snapshot; concurrent changes can make observations disagree.
Even two absent pins, a linked claim or worker-written CLOSED/settlement history cannot
prove cleanup completion or permit successor acquisition. Exceptions are sanitized and
not retried. These diagnostics do not validate applicability/current-source freshness,
establish runtime safety, start a pilot timestamp or enable a health endpoint/job.

Before any future trusted integration, fixed host operations need independently
protected source/routing/claim ownership, full immutable original binding, all-attempt
admission and permanent closure accounting, later authenticated CLOSED-membership
verification, one unique host audit **before** exact-owner cleanup, and a completion
gate barring successors until both canonical and consumer pins are cleaned. Unknown
outcomes retain both pins and claim uncertainty. Never import/take over/refresh an
uncertain claim, connect empty-lookup recovery or issue a second create. The existing
exact-owner CAS is reusable cleanup machinery only; implementing a new authority map
requires explicit compatibility review, not a callback or worker mirror.

## Disabled repository health library

`RepositoryHealth.read(companyId, configuredSource)` composes retained-current-source
validation and the publication diagnostics above. It makes namespace queries only;
no provider, scanner, issue transport, registration or verifier is invoked. It does
not change any record, pin, claim, schema or SQL writer. There is no health endpoint,
worker, manifest or scheduled job.

The bounded output reports only a validated source's immutable reference, poll revision,
start/completion times, age, discovery-binding presence, and inventory file/dependency/
parse-issue counts. Counts describe retained inventory, **not** scan stages, successful
cards or an enabled pilot. Raw lockfiles, package locators, poll/claim/pin tokens,
proof history and error text are not returned. Missing, pending, failed, stale,
corrupt or superseded evidence withholds the whole source summary; it never falls
back to cache. Source selection is revalidated after diagnostics, including same-byte
new-token races. Reads are not atomic; independent diagnostic observations can differ.
A discovery binding or fully parsed configured paths proves neither actual manifest
association nor exhaustive repository/dependency/runtime coverage.

Every result remains `attention`, `library_only`, publication disabled/inadmissible,
with no supported trusted methods. Pilot start and successful-scan count remain **null**,
not fabricated zeroes or timestamps from offline work. Advisory/feed freshness and
enabled-stage counters are explicitly not observed by this helper. Source availability,
empty counts, absent pins or worker-written history cannot authorize publication,
registration, claim recovery, pin cleanup, source switching, member resolution or a
runtime safety conclusion. Runtime health/counter persistence, operator installation
and real pilot acceptance remain unimplemented.

REA angle: reuse the existing source-poll/immutable-journal validators and sanitized
publication diagnostics rather than inventing a latest-health table, authority map,
parallel scheduler or alternate issue system. Tests use in-memory PGlite only.

## Offline Rust producer observations

`observeRustInventory` accepts retained reconciliation, native Syft and Grype JSON
bytes and expected source/image/config identities. It checks report hashes, native
cataloger/tuple consistency, exact R ⊆ L and O = L − R accounting, counts, image
source consistency and reported suppression. Missing, malformed, duplicated,
over-capacity, inconsistent or unsupported evidence throws a sanitized attention
error; nothing is truncated into a successful empty inventory. Multiple installed
versions remain separate. Positive Grype match counts are preserved, not interpreted
as a policy verdict.

An optional independent `Cargo.lock` must match both the claimed byte hash and the
complete unique L tuple set. Without it, `lockfileComparison` is `not_observed`:
the producer's L array and hash cannot verify themselves. Even `matched` is only
byte/set consistency, not authenticated build provenance. O means **lockfile-only /
not reported in this native inventory**, never safe, dev-only, unreachable or absent
from the executable. Complete lockfile development/CI/supply-chain findings remain.

Every output stays `attention`, unauthenticated, resolution-ineligible, runtime
completeness unproven and deployed binding unproven. Tool versions are observations,
not verified toolchain pins. Scanner execution/exit status, configuration and policy,
expected binary metadata, build target, provenance authenticity, freshness and actual
deployment/completeness evidence still require independent verification. No trusted
receipt, `RescanEvidence`, decision input, VEX or publication permit is produced.
This pure offline helper makes no network/DB/issue calls and changes no records,
pins, claims, schema, SQL writers or runtime integration. No scanner runs or pilot
acceptance are implied by reading already-preserved reports.

`observeRustScanner` additionally checks the reported scanner configuration and
expected binary metadata, reusing all inventory/hash checks above. Caller-supplied
expected tool versions, absolute binary path and optional binary SHA-256 are only
consistency expectations, not authenticated pins. The supported report shape must
request native Cargo/file catalogers, report their use and SHA-256 file hashing, and
use squashed-image scope. Explicit fixed/unfixed-only, exclusion and VEX filtering
is rejected. Missing required Grype filter fields are rejected, not defaulted.

Every native crate must identify that one binary path/access path and layer, with
matching crate metadata. Exactly one corresponding regular, nonempty ELF file with
an entrypoint and SHA-256 digest is required. Duplicate files/digests, other layers,
symlinks, unsupported metadata and capacity errors hold the observation. Other
image files are not treated as Rust inventory or proof of full image coverage.
No binary bytes are opened, hashed or executed by this helper. Even a digest that
matches the caller's expectation is not independent binary/provenance verification.

Configuration hashes and the count of reported Grype ignore rules are retained.
Ignore rules are **not** assumed harmless, including scanner defaults targeting
other package types. Any such rules require independent policy review. A missing
`ignoredMatches` field is explicitly `not_observed`, never zero suppressions;
an explicit empty array is only `reported_empty`. Neither case proves an unfiltered
scan. Outputs always remain `attention`, unauthenticated, resolution-ineligible and
`scannerPolicy: not_proven`, retaining the inventory's existing evidence gaps.
Reported configuration is not execution/exit-status proof, toolchain verification,
a current vulnerability database, deployment binding or runtime completeness. This
adds no trusted receipt, policy input, runtime endpoint or publication authority.

## Development

Node 24 or later:

```sh
npm ci --ignore-scripts
npm run check
```

`check` runs strict typechecking, the repository's tests, and the library build.
Tests use PGlite's PostgreSQL engine in memory for the actual namespace migrations,
primary-key claims, conditional transitions, and journal writes. They do not use a
host database, GitHub token, live Paperclip issue, external advisory service, or
LLM. PGlite concurrency tests interleave callers through its connection; they do
not claim to exercise the host's pooled connection transport.

Where an installed host module is available, also run:

```sh
npm run check:host -- /absolute/path/to/installed/plugin-database.js
```

This checks generated SQL with that host's real validators and namespace derivation,
without opening a host database or executing any writes there.

## Rule and evidence contract

`decide(FindingInput)` takes a **normalized, validated evidence bundle**, not raw
scanner output or untrusted JSON. Source readers validate the provider structures
described below, but the full runtime ingestion pipeline is not implemented and no
endpoint accepts such a bundle yet. Evidence-producing adapters must verify the
claimed coverage rather than inferring it from an empty search result.

- Rule 0 retains the complete provenance bundle. A rule-1 range exclusion or
  withdrawal precedes the MAL/KEV override. MAL/KEV cannot take a later negative
  route, be downgraded for dev-only scope, or wait for weekly delivery.
- Platform, Go, function, and range evidence bind to both the artifact digest and
  the exact advisory revision. Tool versions must exist. Stale or missing proof
  is `unknown`, not `not_affected`.
- Go proof must match every deployed target and tag. Symbol hits jump over
  function absence; reflect/unsafe and incomplete scans go to residual review.
- Function absence requires confirmed advisory functions and complete sources for
  the entire dependency closure. A dependency hit overrides an own-code hit and
  goes to residual review. Repo-only absence is never sufficient.
- Compatible-fix routing does not bypass the priority post-pass or invent
  reachability. Remediation is a proposal only. No command is executed, PR opened,
  alert dismissed, ignore file written, or issue auto-closed.
- EPSS uses probability, not percentile. Invalid/missing EPSS uses severity.
  Development scope must be proven; mixed or unknown scope is not dev-only.
- Proposed VEX is bound to its artifact and includes every alias. It is not a
  scanner dismissal or committed exception mirror.

The journal preserves the full input, tool/feed provenance (including explicit
unavailable values), output, rules version, and deterministic revision hash.
Replaying a stored input with its recorded rules version reproduces its decision.
New observations append history without overwriting the old evidence. A monotonic,
deterministic head prevents an older concurrent observation from rolling back the
finding record.

Finding identity is the SHA-256 of the lowercase canonical `owner/repo`, remediation
unit, and lexical minimum of the connected advisory aliases/upstream IDs, joined
with `|`. The remediation unit is `ecosystem:package@target-fixed-version` (or
`@unfixed` when no target is known). Components reject ambiguous separators. A new
target or changed alias minimum produces a different identity; lineage and batch
membership must be reconciled by the later delivery layer, not silently retagged.

## Read-only source adapters, before runtime integration

### Organization Dependabot observations (not source switching)

`DependabotSource.read(organization)` explicitly traverses the organization's alert
endpoint once per cursor page, without state, scope, severity or repository filters.
Only fixed `api.github.com` requests receive its injected token. Next links must retain
that exact organization, endpoint, ordering and page size, with one nonempty `after`
cursor and no extra parameters, credentials or fragment. Redirects and retries are
refused. Cycles, repeated alert identities, partial-page failures, malformed records,
empty pages with next cursors and exhausted budgets require attention, not partial
success. Traversal is bounded to 20 pages / 2,000 alerts / 8 MiB retained evidence.

Missing credentials and an initial non-rate-limited 403/404 return a distinct
`unavailable` reason, not an empty alert set or proof that a permission grant is absent.
OSV may continue independently while runtime health surfaces that reason. A 401,
rate-limited 403/429, later-page 403/404, 304 without cache, or any other failure is
attention. The adapter does not switch providers or infer an App grant from a response.
The alert contract is based on the [GitHub REST documentation](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-an-organization),
using the same API version as the existing GitHub adapters; all tests are fake HTTP.

A successful traversal means only **observed alerts visible to that credential**.
It does not prove all configured repositories are visible, that Dependabot is enabled
on them, or a point-in-time consistent organization snapshot. Open, dismissed, fixed
and auto-dismissed states are retained; none resolves a member or proves safe absence.
The observations preserve exact alert/advisory revisions, known identifiers, package,
manifest, reported scope/relationship, vulnerable range and patch hint. Null context
stays null. A vulnerable range is not an installed version; a patch hint is not a
verified compatible fix. No artifact/source-poll binding, full alias closure, independent
manifest association or current freshness is established. Unsupported future schema
values hold the read rather than silently weakening priority or coverage.

`DependabotJournal` (migration 012) validates and retains raw pages, their exact cursor
chain, query/completion interval and content hash under a company-scoped immutable ID.
Sequential/concurrent replay does not overwrite history. Readback revalidates raw
hashes/records before exposing a snapshot; failed or lost persistence responses return
no successful reference. There is no mutable latest source, cache/ETag reuse, routing,
negative decision, source-selection fence, HTTP callback or publication integration.
Content hashes do not authenticate a producer. Retention/capacity health, verified
repository coverage and artifact-bound source normalization/switching remain runtime
prerequisites; this library is not enabled or pilot acceptance.

`DependabotContext.bind(currentSource, dependabotSnapshotId)` reads only retained,
company-scoped evidence and revalidates the full current source before and after the
join. The org query must start at/after source-poll completion, finish by now and be
no more than one day old. Even empty observations need these checks. Organization,
source token/revision, immutable lockfile snapshot/digest/commit and raw alert snapshot
references are retained in a versioned deterministic context hash; replay does not
restamp the observed time. A later poll selecting identical bytes is a different
selection, not permission to reuse an earlier query as current.

An alert's reported manifest path must **exactly equal** a selected, successfully
parsed lockfile path. No `package.json`→`package-lock.json`, root→workspace, case-folded
or other manifest association is guessed. Exact package identity selects every
candidate installed version and all its locators in that file, not the same package
in another file. Stable npm versions support only a bounded conjunction of explicit
GitHub comparators; prereleases, other grammar and other ecosystems remain unknown.
Every candidate tuple is retained, including nonmatching versions. Nonmatches are
context, never a negative applicability proof. Fixed/dismissed/withdrawn observations,
missing files/packages and partial inventories remain attention, not resolution.

Derived context is bounded to 8 MiB, checking expansion incrementally; exceeding
capacity holds the whole result rather than silently truncating alerts or tuples.
The output is always `attention`. A `matched_observation` means only that an open
observation matches these installed tuples; GitHub supplies no commit-bound alert
receipt or point-in-time consistent org view. Reported scope/relationship and patch
hints remain raw hints, **not** applied policy or a verified compatible fix. This is
not full alias closure, repository visibility, independently verified manifest/workspace
association, source switching, authentication, a publication permit or a rescan. It
writes no decisions, routing, issue claims or new mutable latest-source state. The
immutable parents suffice to reproduce the context; there is no context callback.

`SourceComparison.read(currentSource, dependabotSnapshotId, osvSnapshotId)` compares
only retained evidence. It reuses the exact-inventory context above, requires OSV's
exact immutable lockfile parent and a query at/after the current poll completion,
and checks freshness and source supersession again before return, including empty
results. It makes namespace queries only; no HTTP request, projection write, source
selection, claim/pin mutation or native issue operation occurs.

Each alert tuple retains its exact path/locators and all OSV groups sharing both the
installed ecosystem/package/version and at least one observed advisory identifier.
Shared identifiers are correspondence only: two separate OSV groups bridged by an
alert remain separate and explicitly ambiguous. No aliases are merged or identities
retagged. Unmatched OSV groups and unmatched alert tuples remain visible. Missing
manifest association stays in the original context, not a guessed tuple join.
Range, severity and withdrawal disagreements remain attention; unsupported ranges
and unavailable OSV aliases remain unknown/incomplete. Provider revisions are
retained separately, never equated by timestamps. Scope/relationship/patch hints do
not alter policy, priority, remediation targets, provenance or VEX. Even agreement
is not a commit-bound alert receipt, verified repository coverage or absence proof.

The bounded result always remains `attention` with `policySource: osv_unchanged`,
source-switch/publication/pilot holds and a versioned deterministic content hash.
Repeated comparisons do not restamp either observation. Expansion beyond 8 MiB
holds the whole result instead of truncating it; storage failures return no completed
comparison. Reads are not an atomic snapshot or a continuing publication permit.
This is preparation for explicit source-policy reconciliation, not its implementation,
provider switching, authentication, runtime wiring, registration or enablement. No
supported trusted method is added. Neither empty nor matching observations resolve
a member, close an issue, release pins, recover a claim or start a pilot timestamp.

REA angle: reused the shipped GitHub Upstream fixed-origin/redirect refusal and explicit
rate-limit classification, plus this package's bounded HTTP and immutable namespace
journal/context patterns. No scheduler, token broker or alternative issue system is introduced.


`GitHubRepositoryDiscovery.read(repositories, previousDiscoveries)` gets default commit
and root-tree identities for all selected repositories in one GraphQL call, validating
every head before requesting trees. Recursive trees use immutable tree IDs. Truncated,
missing, malformed, duplicate-path, orphaned-parent and over-capacity responses hold the
invocation; they never certify empty/complete coverage. Validated unchanged-commit trees
can be reused without a tree request; changed commits require a new tree read. A commit
whose tree identity disagrees with its cached identity is held.

Discovery retains canonical tracked entry metadata with a versioned content hash.
`discoveryCoverage` inventories known manifest and supported/unsupported lockfile names,
including nested paths, without executing or fetching repository code. Symlinks and
submodules are not followed; unsupported formats/paths, unbound manifests, too many
lockfiles and oversized lockfiles remain attention. Only same-directory filename
candidates avoid a missing-binding hold: a root lockfile does not silently prove a nested
workspace manifest is covered. Even a candidate does not prove actual manifest/dependency
association. Known filenames are not an exhaustive inventory of every artifact class.
Coverage is explicitly **tracked tree only**, never full dependency sources or runtime
completeness. Ignored/generated files, external dependency sources and submodules are not
scanned by this reader.

`GitHubLockfiles.readDiscovered(discoveries, previousSnapshots)` uses the exact discovered
commit without a second heads query. Before content requests, discovery attention holds
the whole read. Each fetched, cached or ETag-reused file must also match its discovered
Git blob identity and any reported size. Valid bytes from a different tree cannot pass
merely because their own content hash is valid. The existing immutable content/cache
checks remain unchanged. Both APIs use bounded fixed-provider HTTP and fake tests only;
no worker wires them yet. `DiscoveredRepositorySourceSync` supplies durable discovery and
source-poll integration as an explicit library operation, described below. A supplied
hash is not authentication, and discovery is not a current-source publication permit.

`DiscoveredRepositorySourceSync.read(companyId, repositories)` reserves a discovering
poll for every repository **before any network request**, fencing older ready evidence
even while the new paths are unknown. One GraphQL request obtains heads; cached validated
discovery can avoid unchanged tree reads. Every returned discovery is retained in the
company-scoped source journal before any content read. Coverage attention holds the
whole batch; supported paths are never silently selected around unsupported/unbound
entries. The poll binds the exact retained discovery and its complete supported path
set under its original token before content fetching at the discovered commit.

Lockfile/inventory records bind the discovery snapshot ID. Both insertion and later
readback revalidate repository, commit, branch, exact file set, blob identity and size.
Only matching discovery-bound completion may select that poll. Same-statement downstream
source fences include this binding. Changed trees/paths cannot reuse an obsolete configured
subset, and same-content/different-commit evidence retains distinct source identities.
Restarting the adapters reuses only validated immutable discovery/content as cache material;
current readiness and freshness still require a new completed poll. Lost responses,
persistence failures and stale invocations leave attention or an unfinished poll, not an
older ready selection. A publication pin also prevents beginning a discovery poll.

This is not an enabled job, atomic multi-repository publication, actual manifest/workspace
association, exhaustive artifact inventory, full dependency closure or runtime completeness.
Parsed inventory coverage remains conservative. No issue effect or member resolution occurs.

`GitHubLockfiles.read(configuredSources, previousSnapshots)` gets all configured
repositories' default heads in one GraphQL request. Any GraphQL error, missing head
or repository identity mismatch holds the whole read before content fetching. It
fetches only configured paths at immutable commit SHAs, never branch names. An
unchanged SHA reuses validated cached bytes without a content request; a changed
SHA makes ETag-conditional reads. A 304 requires the same repository/path's cached
ETag and verified content. Missing files, permission/rate errors and malformed
responses never silently reuse an older artifact or certify complete coverage.

Content requires a complete base64 UTF-8 file, exact byte size and matching Git
blob SHA-1; each file also stores SHA-256. The aggregate artifact digest binds sorted
paths/content hashes, separately from source commit identity. Returned snapshots
are values to persist, not a mutable latest-head cache: overlapping reads cannot
change another read's snapshot. `SourceJournal` persists these immutable values;
`RepositorySourceSync` wires it to fenced source selection, described below. No
worker wires those selections into decisions/publication yet. Configured-path
coverage is NOT proof that all lockfiles or the full dependency closure have been
discovered or parsed. These
hashes are content bindings, not authenticated deployment receipts.

`OsvSource.query(validatedDependencies)` deduplicates package tuples and makes
100-query batches with independent per-query page tokens. It hydrates every
returned advisory and recursively discovers each alias/upstream ID once, with
shared-node/cycle deduplication under the original request/deadline budget. Exact
batch/detail revision equality is required for batch IDs; every available linked
record also requires a valid non-future revision. Raw advisory JSON, canonical
content hashes and the graph/observations are retained in a timestamped snapshot.
Sub-millisecond revision precision is retained.

A batch ID returning 404 is a failed scan. A referenced alias/upstream ID returning
404 is retained explicitly in `unavailableIds`, never treated as withdrawn or
outside. Other HTTP/transport/pagination/size/budget failures throw attention,
not partial success. Normalization rechecks raw/derived equality, graph coverage,
unique observations/records, seed reachability and hashes. An unreferenced injected
record or omitted discovered edge cannot silently enter a decision. Unavailable
nodes have unknown revision/affectedness and prevent all-withdrawn/all-outside
negative conclusions. Known active affected evidence remains available; all IDs
still participate in MAL/KEV matching and finding identity. The eventual runtime
must surface unavailable nodes as source attention, not complete alias coverage.
This graph is the observed OSV closure, not proof that every external advisory
source in the world has been discovered.

`osvFindingInputs(snapshot, lockfileContext)` checks snapshot integrity and binds
conservative inputs to the lockfile digest. It supplies only supported range proof,
validated withdrawal, known database severity and observed aliases. Connected
source records produce one finding per package tuple: any active affected source
wins, every active source must prove outside for an exclusion, and a withdrawn
alias cannot erase an active source. The highest known active severity is retained.
Unsupported ranges remain unknown. It does not guess dependency scope, directness,
compatible fixes, CVSS scores, function/platform/Go proof, KEV or EPSS. The separate
feed adapter below supplies KEV/EPSS only from validated, retained snapshots; without
it KEV absence continues to force residual unknown under the existing matcher.
Full runtime source/enrichment integration is required before publishing pilot
decisions. An empty query result never resolves an existing member or establishes
runtime safety.
Snapshots/raw advisory content must be durably retained before journaling decisions;
`SourceJournal` provides that library boundary, but no worker wires it yet. Typed
cached/snapshot arguments are internal trusted values, not raw JSON ingestion
endpoints; their hashes are not authentication and must not be exposed as caller
authorization.

### Locked-entry inventory and durable source records

`parseLockfileInventory(snapshot)` rejects strings that cannot round-trip through
UTF-8 before validating content/blob hashes and the configured path-set digest.
A lone surrogate is not silently replaced with `U+FFFD`: matching hashes over
replacement bytes cannot prove exact source text. Any such file rejects the whole
snapshot before parsing or journal writes (`invalid_inventory_utf8`), including
unsupported files. Valid Unicode, literal `U+FFFD` and escaped JSON source text are
retained unchanged. This checks the supplied string, not the authenticity or
losslessness of an earlier byte-to-string decoder.
It then parses npm `package-lock.json`/`npm-shrinkwrap.json` v2/v3,
pnpm v9 and Cargo v3/v4. It deduplicates OSV query tuples while retaining every
installed location and locked version. npm aliases require the real package name
and matching official registry tarball identity; pnpm retains scoped/peer-version
entries and checks importer/snapshot references. Cargo keeps the full registry
locked set, never substitutes native R for locked L and never drops O = L − R.
Canonical SemVer prereleases and build metadata are preserved byte-for-byte in
query tuples and installed locations. Equal-precedence versions such as `1.2.3`,
`1.2.3+one` and `1.2.3+two` remain distinct identities; ordering equivalence is not
query-coverage equality. Noncanonical prefixes/whitespace and malformed identifiers
still require attention. Parser `0.1.2` and semver `7.7.4` are recorded in provenance.
This does not expand the separate stable-only declaration/fixing-candidate APIs.

Local/workspace links, Git/custom sources, missing entries, unsupported formats and
versions, malformed/duplicate keys, ambiguous versions and unverified registry
identity require attention. A malformed file discards its partial parse; valid
entries in other files remain available for positive observations. YAML aliases,
merge/custom tags are not accepted. No package script, package manager, scanner or
repository code runs during parsing. The patched YAML/TOML libraries are exact
pins; dependency installation uses `--ignore-scripts`.

`configuredPathsParsed` means only that the configured entries were parsed, NOT
that every repository manifest/lockfile, optional target or dependency source was
discovered. Repository discovery, full dependency closure and runtime completeness
remain `not_proven`. Every dependency's scope is `unknown` and directness is unset:
dev/platform flags, peer context, lockfile-only presence or native absence do not
justify lowering priority, VEX or runtime resolution. Unknown sources/coverage must
be surfaced by runtime health as attention, not an empty successful scan. Go,
Python, other lockfile schemas, verified scope/directness and discovery/runtime
integration remain unimplemented. Inventories are bounded at 10,000 entries / 2,000 unique query tuples;
limits never silently truncate into a completeness claim.

`SourceJournal.recordLockfiles(companyId, snapshot)` durably saves raw bytes plus
the inventory. Explicit immutable IDs can be read back for GitHub cache reuse;
this journal has no mutable latest-head pointer. The separate poll store below
selects references without replacing journal history.
`recordOsv(companyId, lockfileSnapshotId, snapshot)`
requires an exact match between inventory query tuples and OSV observations,
validates raw/normalized advisory equality, revision times and snapshot hashes,
then persists raw OSV/query time/coverage before returning conservative inputs.
Both record and replay return the inventory/attention states alongside inputs.
An empty result is never a rescan receipt. No decision, routing, issue effect or
closure happens in this journal.

The company-scoped primary key and content-derived IDs make sequential/concurrent
replay idempotent. Lost responses can be replayed without overwriting old evidence;
readback verifies the hash and parent source binding. Records are bounded at 16 MiB
each, with no eviction. The eventual enabled runtime must add retention/capacity
health and enforce source selection fences in downstream decision/publication
writes, retaining the immutable references. Parser upgrades fail closed on historical
inventory/version mismatch: old records and source selections are never rewritten
or silently reinterpreted. Explicitly recording the same retained bytes with parser
`0.1.2` appends a distinct content-derived inventory/snapshot ID; old references remain
held, and an old OSV observation with stripped build metadata cannot satisfy new
exact-tuple coverage. No automatic migration, current-source promotion, historical
recovery or live reacquisition is enabled. An installed runtime upgrade still needs
a separately verified migration/replay and source-selection plan.

### Fenced source selection, before downstream runtime integration

`SourcePollStore` (migration 007) separates **immutable HTTP cache material** from a
**selected source as of the latest-started successful poll**. Before HTTP, `begin`
uses repository/company-scoped revision-CAS to persist a fresh random poll token,
normalized configured paths and start time. It invalidates the prior selection but
retains its immutable snapshot reference only for cache reuse. DB ordering, not
caller timestamps or lexical commit ordering, chooses the eligible poll. A real
force-reset/default-branch change can therefore select an older commit without
letting an older overlapping request roll back a newer observation.

`complete` requires a durable, validated raw snapshot for the exact company, repo
and configured path set. Its token/revision-predicated update selects that ID only
if the attempt remains pending. Same-token/same-ID completion replay is idempotent;
a different ID or a settled failed attempt cannot replace it. A late older success
or failure cannot change a newer attempt. Starting another read is safe because
these adapters only read providers; this is not lease takeover for native issues
or other non-idempotent effects.

`current` requires matching configuration, a ready token, valid retained bytes and
a poll start no more than 24 hours old (callers can request a tighter bound). Future
start/completion times, missing bytes and corrupt pointers fail closed. A second
revision read detects supersession during source readback. Returned inventory
attention/coverage is preserved: a selected source does not mean repository
discovery, successful complete parsing, full closure or runtime completeness.
A pending/failed poll cannot silently return an older source as current, even when
that older source remains available as cache material. A crash after reservation
leaves a pending fence until a fresh explicit poll; there is no automatic scheduler.

`RepositorySourceSync.read(companyId, sources)` reserves every configured repo,
loads validated cache material, invokes the existing one-call GraphQL/SHA/ETag
reader, retains all resulting raw snapshots/inventories, and only then completes
and reads back the selections. Provider/storage/selection failures return no batch
result and hold that attempt's repositories. Failure to persist the attention state
leaves the pending fence; it never restores older readiness. A committed completion
with a lost response is conservatively held. The next fresh poll can recover using
the retained cache. Errors retain only validated attention codes, not transport or
database messages. No decisions, native issues, resolution or LLM calls occur.

These are per-repository **as-of** selections, not an atomic multi-repo view, a
promise that GitHub has not changed since polling, or authorization for an effect.
`assertCurrent` detects invalidated returned selections (including a newer poll
selecting identical bytes), but check-then-write is not a transaction. The local
journal/routing APIs below add same-statement locking. Native HTTP publication
uses the separately pinned integration below; merely calling `assertCurrent` before
an HTTP request does not solve that race. There is no enabled worker.
The low-level completion boundary trusts its adapter's link between poll and raw
response; caller-supplied hashes/tokens do not authenticate that link. None of
these internal typed APIs is exposed as a raw JSON callback endpoint.

REA angle: reuse the existing immutable journal and repository revision-CAS pattern,
not plugin-state timestamps, a process-local mutex, or a second scheduler. Tests
interleave PGlite callers and fake HTTP; they are not pooled-host or pilot evidence.

### Source-fenced local decisions and routing

`DecisionJournal.recordCurrent(selection, input)` and
`DeliveryRouting.observeCurrent(selection, input, relationship?)` are explicit
trusted-adapter boundaries for **lockfile** findings. They clone their inputs,
validate the full retained selection, require matching repo/digest/artifact kind,
and persist the token, immutable lockfile snapshot ID and DB poll revision in the
input/decision provenance. These IDs bind evidence; they do not authenticate a
producer or prove that arbitrary caller enrichment was derived from the raw data.
`SourceDecisions` below derives inputs from retained OSV/feed records and checks
freshness/coverage; the worker must still wire it and surface attention.

Immutable history is inserted first. Advancing the finding head uses an
`INSERT … SELECT` with a locking source-row predicate in the **same SQL statement**.
Routing uses the same predicate in its revision-CAS `UPDATE`. Both predicates match
the exact company/repo, ready-state bundle and poll revision and acquire
`FOR UPDATE` on the source row. This serializes the dependent mutation against
`begin`, `complete` and `fail`. A plain `EXISTS` or a separate `assertCurrent` would
not supply that serialization. The database statement clock additionally rejects
future completions or poll starts older than one day; application validation also
checks freshness. A source can become obsolete immediately after the statement:
these projections are as-of evidence, not a lasting publication permit.

New poll revisions take precedence over observation timestamps, including a
force-reset head or the same bytes selected by a new token. Within one poll,
observation time and decision hash retain deterministic ordering. Migration 008
adds the finding head's poll revision. Unfenced journal writes cannot replace a
source-fenced head, and legacy `observe` refuses to route source-selected evidence
or mutate a repository projection containing source-selected members. Those legacy
APIs are not the current-source runtime path.

Head and routing writes are individually fenced, **not one transaction together**.
A crash or supersession can leave durable decision history/head without a routing
change. A current replay repairs the projection; stale replay cannot apply it.
No-op routing verifies the selection again before returning. Routing CAS retries
retain competing same-source membership. Neither history insertion nor an empty
OSV result resolves existing findings.

`ContainerPublication.publish` returns attention for source-selected members (or
source-selected journal evidence), before any native issue lookup/create/update.
The legacy fixture-only publication path is not authorization to bypass that
hold. `publishCurrent` below provides a separate pinned library path, not an
installed runtime. Trusted host-effect settlement and rescan receipt integration
remain required before an enabled worker/pilot. Local
PostgreSQL-engine tests inject races immediately before writes and exercise
crash/lost-response replay; they do not prove pooled-host transport behavior or
real pilot acceptance.

### Retained-source decision orchestration

`SourceDecisions.observe(selection, osvSnapshotId, threatSnapshotId)` is an explicit
library path, not a worker, HTTP endpoint, scan scheduler or pilot. It accepts only
retained evidence references, never caller-normalized inputs. It validates the
current company/repository selection, reads and revalidates the immutable OSV scan
and inventory, requires the exact lockfile parent snapshot, and loads the same
company's raw threat snapshot. An equal digest from another commit/snapshot is not
interchangeable with the selected parent.

OSV query time must follow source-poll completion, precede the retained observation
and be no older than one day at execution. Even a later poll of identical bytes
requires a query after its completion. Feed evidence must be fresh both at that
retained observation and now. These checks include empty result sets: an old scan
or feed cannot be made current by replaying its old timestamp. Enrichment checks
all finding aliases before any decision writes, and provenance retains the exact
OSV snapshot ID as well as threat, lockfile and poll references. Replay does not
re-stamp the observation or create new evidence merely because time passed.

`aggregateFindingInputs` groups same-action installed tuples by remediation identity
before any writes. Singleton inputs and their existing rule hashes are unchanged.
A multi-version `VersionSetInput` retains the identical common context and every
version/range-proof tuple in a canonical sorted set. Reconstructing a tuple gives
its full original input; `decide` runs the unchanged rules independently on every
tuple. The one action then reduces affected over unknown over negative results,
never letting an outside/withdrawn/not-affected tuple hide an actionable version.
An affected result means at least one tuple is affected, not that every tuple is.
The minimum actionable priority and fastest actionable delivery are retained.
Remediation is proposed only when actionable tuples agree, and VEX only when all
non-dropped tuples agree on the negative proposal. All-dropped sets have no VEX or
delivery; a negative observation still never resolves a member.

The journal stores one complete set/decision revision, with a versioned
`1.0.0+all-versions.1` reducer, input hash and each tuple's decision hash,
applicability and rule trace. Tuple enumeration order does not change the action
or hash. No tuple-level decision head competes with the aggregate via timestamp
or lexical hash ordering. Current poll/lockfile/OSV/feed references apply to every
reconstructed input; the existing source fence covers the whole action head and
routing mutation. Replay retains one member and its original container.

This reducer deliberately requires **identical non-version context**, including
scope, aliases/revisions, targets, fixes, function/platform/Go proof and provenance.
Differing contexts require `version_set_context_mismatch` attention before writes,
not an invented scope/absence/compatible-fix union. Duplicate versions, malformed
or nested sets, unknown reducer versions and more than 2,000 tuple inputs are held.
This covers the retained OSV path's conservative shared context; broader
per-version enrichment needs an explicit compatible reducer before integration.
The set covers observed advisory associations, not every unreported installed tuple
or proof of repository/alias/runtime completeness. Immutable raw inventory/OSV
coverage remains authoritative. No new native publication path is enabled.

Each local mutation uses the existing source-fenced path. Source and freshness are
checked again before return, including empty/no-op batches. This is not an atomic
batch: supersession, expiration or storage failure can leave earlier individually
fenced decisions/routing durable. Failure returns no completed batch result; a
current replay repairs it without duplicating membership. A source can change
immediately after return, so the result is not a native publication permit.

The result deliberately remains `attention`: repository discovery, full dependency
closure and runtime completeness are not proven by the configured inventory. It
retains every file's parse issues, unavailable-alias attention, routing attention,
and bounded dependency/observation/decision counters. Those counters count this
invocation's evaluations, not new cards or a successful enabled pilot. Positive
findings from valid parsed entries remain actionable local members despite other
parse gaps. Empty results never remove/resolve prior membership or establish
runtime absence. No native issue claim, lookup, create/update, remediation,
dismissal, production effect, assignment, scanner or inference call occurs.

### Explicit OSV repository scan library (not an enabled pilot)

`RepositoryScan.run(currentSource, {epssDate, epssModel})` composes the existing OSV,
feed, immutable journal and source-fenced local decision/routing libraries. It takes
an already selected source, not arbitrary package tuples or caller-normalized findings.
The future runtime must first obtain a fresh fenced selection through the repository
sync; this helper does not discover repos, fetch lockfiles, schedule scans or choose a
provider. OSV remains the only policy source here. Dependabot context is deliberately
separate until alias/policy reconciliation and source switching are implemented.

It queries every retained inventory tuple and hydrates OSV's observed alias graph,
requests EPSS for every CVE including unavailable linked IDs, and fetches KEV. Feed
requests finish before recording the OSV observation time. Raw OSV and feed evidence
are both durably saved before `SourceDecisions` derives any local projection. Missing
scores preserve severity fallback; the caller must supply independently verified
model/date config. Test mappings are not live verification. No GitHub credential is
accepted by this helper or sent to OSV/FIRST/CISA.

Current source is checked around stages and before return, including empty scans.
The 10-minute invocation bound is checked around asynchronous source validation;
individual adapters retain their shorter request/query budgets. This is not hard
cancellation of submitted reads or storage calls. Supersession, provider/storage
failure or elapsed/retrograde clock prevents a completed report result. Raw evidence
or earlier individually fenced local projections may already be durable; the batch
is not atomic. Current replay repairs local membership without creating issues.

Results retain immutable evidence IDs, coverage attention, dependency/observation/
decision counters and scan start/end times. These are invocation counts, not new
cards, enabled-pilot counters or a pilot-start timestamp. Even two offline sequential
or overlapping calls are not real two-run zero-duplicate acceptance. Empty later
scans never remove or resolve prior membership. The result explicitly retains
`native_publication_disabled`, `dependabot_source_switch_not_enabled` and
`enabled_pilot_not_run`. No issue transport, worker entrypoint, settlement verifier,
rescan callback, managed resource, scheduler or inference client is wired here.

REA angle: compose existing installed-SDK namespace journals and source-fenced reducers;
keep source discovery, policy, native effects and trusted host settlement as separate
boundaries rather than building a second scheduler or allowing a raw callback to
assert coverage. Tests use PGlite and fake provider HTTP only.

### Retained KEV and EPSS evidence, before runtime refresh

`ThreatFeeds.kev()` reads only CISA's fixed JSON feed, requiring a nonempty complete
count, unique valid CVEs and valid release/added dates no later than the fetch time.
It retains the raw catalog, catalog version, release/fetch times and content hash.
No match in a valid catalog is distinct from missing/partial catalog coverage.

`ThreatFeeds.epss(cves, date, model)` reads only FIRST's fixed API, deduplicating up
to 2,000 CVEs into 100-ID date-pinned requests. It checks the protocol status/version,
query offset/limit/total, exact requested CVE/date membership, duplicate entries and
probability/percentile bounds. It does not accept shifted pages, mixed dates or
silently truncated results. Missing scores remain `null`, never zero. Probability,
not percentile, controls priority. A no-CVE call makes no HTTP request.

The EPSS API protocol `version` is **not** a model version. A trusted runtime
configuration must supply the verified model version, effective date interval
(exclusive upper bound) and release-evidence reference. The query date must fall
inside it. Test model mappings are fixtures, not verification of a live model or
permission to enable the pilot. A later model release needs new verified config;
the adapter cannot invent a mapping or infer it from the API envelope. No live
provider contract/model check or scheduled refresh job is implemented yet.

`enrichThreats`/`enrichThreatInputs` validate raw/derived feed snapshots, require
fetch/query times no more than 48 hours old and a score date no more than 72 hours
old at the input's recorded observation, and reject future evidence. The runtime
must fetch feeds before recording that observation. Every CVE in the full observed
alias/upstream graph must have been requested. The maximum known probability is
used across aliases, while all missing scores remain in raw evidence. If no score
is available, the existing severity fallback applies. KEV through any alias still produces
P0 regardless of development scope. The adapters do not infer scope, compatible
fixes, function absence or deployed/runtime completeness.

`ThreatJournal` (migration 006) persists the full raw catalogs/responses, exact CVE
query coverage, dates and model reference before its `enrich` method returns inputs.
Company-scoped content-derived IDs, immutable inserts and validated readback make
sequential/concurrent and lost-response replay safe. Inputs reference both feed
hashes and the combined durable snapshot ID. Capacity is 16 MiB per snapshot, with
no eviction or mutable latest-feed pointer. Storage/retention, source attention and
refresh health still need runtime wiring; a content hash authenticates no producer.

The offline integration regression exercises lockfile→OSV (including an unavailable
alias)→retained feeds→rules→routing twice with one durable member/container and no
native issue claims. This is not enabled-pilot or real two-run duplicate evidence.
All HTTP tests use fake responses. Legacy OSV snapshots without explicit unavailable
ID accounting require an explicit rehydration/migration before reuse; the new
normalizer fails closed rather than interpreting missing coverage as complete.

All source readers use fixed provider URLs, refuse redirects, sanitize transport errors,
and perform no automatic retries. Each request is limited to 30 seconds / 4 MiB;
an invocation is limited to 4 minutes / 128 calls, with no partial result on budget
exhaustion. OSV limits are 2,000 dependency tuples/finding associations, 20 pages
per query and 8 MiB retained snapshot data. GitHub limits are 50 repositories,
10 configured paths each, 2 MiB per file and 8 MiB aggregate content. Exceeding a
limit requires attention and future resumable polling, never truncation or safety
inference. No credentials reach OSV; GitHub credentials are sent only to the fixed
GitHub API origin. Tests use fake HTTP only, not provider or pilot evidence.

REA angle: the shipped GitHub Upstream HTTP layer is the reference for conditional
ETags, one GraphQL request, redirect refusal and explicit error states. This adapter
adds immutable commit/blob binding and bounded bodies without a token broker or
parallel scheduler.

## Durable routing, before publication

`DeliveryRouting.observe(companyId, input, relationship?)` journals the full input
and decision before assigning a delivery container. Its repository-scoped DB row
uses revision-predicated compare-and-swap, not plugin state or a process mutex.
One successful update commits membership, lineage and alias redirects together.
A crash or lost response is repaired by replay; the reducer performs no host effects.

- Weekly origins hash a JSON tuple with an explicit versioned domain, company,
  canonical repository and UTC Monday week start. They never reuse a member hash.
  The first persisted weekly-eligible observation assigns the bucket using the
  injected host clock. Replays, rollover and non-P0 delivery reclassification do
  not migrate an existing delivery link. Individual SLA clocks do not reset.
- Initial P0 uses a per-finding container with immediate publication intent. A
  weekly member becoming P0 sets urgent/immediate intent on its original weekly
  container, without a split issue or a second actionable membership. Container
  deadlines never extend; member priorities and evidence remain independent.
- An unambiguous alias-minimum change adds a retained identity-key redirect and
  keeps the original delivery origin. A bridge joining multiple existing records
  returns durable attention instead of silently merging, retagging or duplicating.
- Changed fix targets require an evidenced same-action replacement or independent
  remediation relationship from the trusted ingestion layer. A replacement creates
  a successor, retains historical membership, and marks the predecessor superseded,
  **not fixed**. Conflicting concurrent replacements require reconciliation.
- Negative applicability remains a proposal. Container closure, elapsed time,
  changed fix hints, and arbitrary new artifact observations never establish
  remediation. Only the separate complete-rescan receipt boundary below can
  resolve an individual member; external closure never changes member state.

This is a bounded pilot projection: at most 2,000 members and 1 MiB per repository,
with at most 32 CAS attempts per invocation. Capacity/contention failures retain
journal evidence, throw an attention-required error and permit no issue effect.
Runtime health must surface those errors before installation. It is not a general
unbounded organization ledger; scaling requires a measured storage migration.
Native issue links and creation guards are separate from this routing projection;
`ContainerPublication` connects them through the shared origin-kind-aware guard.

## Per-member rescan resolution

`DeliveryRouting.applyRescan(companyId, canonicalRepo, RescanEvidence)` accepts
**normalized, independently verified trusted-adapter evidence**, not raw scanner
JSON or caller-supplied completeness assertions. There is no runtime endpoint or
adapter yet. Hashes identify evidence; they do not authenticate its producer. The
integration must verify report bytes, source/deployed digest and same-artifact
lineage receipts, full relevant advisory/alias coverage and independent inventory
completeness before constructing this value. Mutable tags, CI image IDs without
production binding, ignored/VEX-filtered findings and empty native inventories
are not valid absence proof. A lockfile receipt resolves only lockfile risk, never
runtime exposure; artifact kind must match the original finding's provenance.
Older records without a known kind remain held until a validated observation.

The library checks the current finding/decision/package/ecosystem, every retained
alias and exact advisory revision; a new immutable SHA-256 artifact of the same
kind; immutable source revision; binding/lineage/completeness references; a scan
started after the finding observation and completed by receipt recording time;
a hashed successful absent report with the scanner's tool version; unfiltered
complete lockfile coverage and exact build targets/tags. Runtime artifacts also
require full dependency sources and independently proven runtime completeness.

In particular, Rust native R within locked L, and lockfile-only O = L − R, are
separate views. O is only “not reported in this native inventory”, never safe,
dev-only, unreachable or absent from the executable. `runtime_completeness:
not_proven`, subset accounting and sentinel names cannot resolve runtime risk.
The complete locked development/CI/supply-chain view remains required. The
producer's R/L/O receipt parser and deployed-digest verification are still pending.

Accepted resolution plus full receipt/hash/history commits through the same
repository revision-CAS as observation, affecting only its bound member. Rejected
receipts are retained once in `rescanHolds` with attention reasons, without
certifying resolution. Supersession is not resolution. Duplicate receipt replay,
including a replay after reopening, cannot append another resolution or reactivate
an old proof. Contention/capacity errors throw and require replay; they never issue
a host effect. These histories share the existing 1 MiB pilot capacity limit.

A newer finding observation, modified advisory or newly learned uncovered alias
conservatively reopens that member in its original container. Identical/older
replay is inert unless it expands uncovered aliases. A late observation is not
silently discarded merely because it predates rescan completion. Previous proof
history, original bucket/SLA and unrelated resolved members remain unchanged.

Resolution does **not** close a native issue, dismiss an alert, commit VEX or
perform remediation. Publication verifies resolved-member receipt consistency
before rendering it. A new fully resolved revision refreshes an externally closed
container without reopening it; unresolved members still trigger original-container
reopening. Runtime health must surface held scans and any newer artifact with
missing/ambiguous evidence as unknown/attention; historical resolution never
establishes safety for a later artifact.

## Explicit container publication

`ContainerPublication.publish(companyId, canonicalRepo, originId, projectId, weeklyDue?)`
loads the original durable container and all of its journaled member decisions.
It validates the mapping and artifact-bound input hashes before any host effect.
The body includes independent member priorities, deadlines, aliases, evidence,
proposed commands/VEX and predecessor/successor links. Missing/malformed evidence
or a body exceeding 128 KiB fails closed; it is never silently truncated.

- Until the existing host job passes `weeklyDue = true`, an unpublished non-urgent
  weekly container is deferred without acquiring a creation claim. Initial P0 and
  a weekly-to-P0 promotion bypass that delay. There is no new scheduler here.
- An already-claimed container is always handled under its original origin kind
  and ID. A later P0 updates/reopens the original weekly issue, never a dedicated
  urgent copy. A pending/indeterminate claim remains fenced even during escalation.
- Successful publication records both the container revision and a content hash.
  Older revisions cannot overwrite or reopen newer publications. Identical replay
  performs no update. Conflicting content at the same revision requires attention,
  rather than allowing a different writer or renderer to overwrite it silently.
- A closed container with actionable unresolved members is a closure mismatch, not
  a fix. The versioned publication API reopens that same issue, without changing
  any member state. Once open, same-revision replay is a no-op. Repeated external
  closure is a new mismatch; it is not permission to mark members remediated.
- A timed-out refresh is not safe to retry merely because its linked issue is
  visible. Reconciliation requires independent terminal-execution **and** settled
  host-effect receipts before releasing a known in-flight update. Without them,
  even a higher-priority/newer container revision remains delivery-unknown.

This is a tested library effect boundary, not an enabled plugin or batching/pilot
acceptance. No scan, live publication, installation or configuration has run.
Live receipt validation/ingestion, job integration and real two-run zero-duplicate
evidence remain required. Library rescan tests are not real pilot acceptance.

## Source-effect barrier primitive (no enabled runtime)

`SourceEffects.reserve(currentSource, intent)` implements the **database half** of
cross-HTTP fencing. It atomically pins the exact ready source row with a unique
barrier token, an execution reference and the proposed origin/revision/body hash.
The existing full retained-source validation runs first; the reserving UPDATE then
matches and locks the exact poll bundle/revision and checks database-time freshness.
It reads back its exact durable token/content, including after a lost write response.
A failed read grants no ownership. Another reservation cannot take over that row.

Every `SourcePollStore` mutation now requires `effect_barrier IS NULL` in the same
UPDATE as its revision CAS. Thus either a new poll wins before reservation and the
old reservation fails, or reservation wins and the new poll cannot advance. This
also prevents same-token failure from invalidating a pinned ready source. The
barrier is scoped to company/repository, not a process-local lock or a transaction
held open across HTTP. Other companies/repositories can continue independently.
No expiry, stale age, worker termination or empty issue lookup releases it.

`SourceEffects.release(barrier, verifySettled)` requires a trusted integration
verifier to independently bind **terminal execution and settled host effects** to
that exact barrier token. A null/mismatched/incomplete proof holds the barrier.
A conditional single-row UPDATE appends the barrier/proof/release-time audit and
clears the pin together. Concurrent release appends once; an old token cannot clear
a subsequent barrier. A lost release response is uncertain, never permission to
repeat an issue effect. Malformed or over-1-MiB audit history holds rather than
silently discarding receipts. The history limit needs operator-facing health and a
reviewed archival path before sustained operation.

**The primitive alone is not a publication permit.** Intent hashes are identifiers,
not authentication or proof of current container contents. The coordinator below
adds routing/payload binding and guarded dispatch. It still requires an independent
trusted runtime verifier; fixture proof strings are not host-effect receipts.
The legacy `ContainerPublication.publish` still holds source-selected evidence
before native issue lookups/creates/updates.

### Source-pinned publication integration (library only)

`ContainerPublication.publishCurrent(selection, origin, project, execution, weeklyDue?)`
clones the current source and validates the original container, every member and
its retained decision. All members and input/decision provenance must bind to that
same source selection and lockfile digest. Mixed/old selections are attention,
not silently republished as current. This conservative hold also applies to
historical superseded/resolved members; a future historical-evidence policy must
be explicit before relaxing it. Weekly timing, P0 promotion, full evidence bodies,
128-KiB capacity and the original claim/revision/content guard are preserved.

Before any issue call, `SourcePublicationStore` pins the source with the execution,
origin, revision, exact publication content hash and full routing snapshot hash.
Migration 010 adds a separate routing pin. Its exact-bundle CAS either freezes that
snapshot or fails without dispatch; a racing mutation cannot change the snapshot
under the pin. Every routing mutation, including rescan and legacy writes, now
checks the pin in its CAS. A crash or failed second pin can leave a source-only
hold. Neither partial acquisition nor a lost read response authorizes dispatch.
Other decision history/head writes may continue; the pinned routing snapshot and
its immutable member decisions are the publication's as-of evidence.

Each issue lookup/create/update revalidates the source, source pin, routing pin and
snapshot hash. Dispatch closes at the earlier of source freshness expiry and the
invocation deadline, and also closes when the helper returns. Checks run again
synchronously after asynchronous validation, so a guard suspended past timeout
cannot later send, even if uncertainty recording delays the return. A submitted
request can still commit after timeout; its durable pins and issue claim remain.
There is no automatic retry or API for resuming dispatch on an existing barrier.

Even a created/reused/no-effect result retains both pins. In a later execution,
`SourcePublicationStore.settle(barrier, verifier)` requires independently verified
terminal execution **and** settled host effects before releasing the source pin.
Only that exact retained settlement audit can clear the matching routing token.
Replay repairs a crash/lost response between the two cleanup writes and cannot
clear a newer token. A result, age, timeout, worker death or empty lookup is not
settlement. The verifier must establish no sender can resume and no host request
can commit late; caller strings and hashes cannot prove either fact.

The required trusted boundary is publication-scoped admission and durable accounting
outside the worker's writable namespace: register every attempt before forwarding,
reject duplicate/late sends, join full handler/descendant completion, irreversibly
close the exact invocation, and expose authenticated evidence to a later verifier.
Positive acknowledgements alone are insufficient without a complete final attempt
set. A truly empty invocation still needs positive closure/completeness proof.
Unknown sends, lost outcomes and incomplete crash recovery retain the pins; there
is no automatic ambiguous-create retry. Existing in-memory RPC/handler tracking
and cooperative drain are reusable hooks, not durable settlement certificates.

No installed verifier, worker or callback endpoint is supplied here. The frozen
ownership review rejects this pinned library path as a runtime authority boundary:
generic namespace SQL can bypass its guards, and the stored source/routing/claim
versions and cleanup history are worker writable. Do not wire either publication
path or its callback proofs to a trusted adapter. A future fixed host boundary must
admit every issue attempt and every alternate writer, preserve full original binding,
and support independent later verification/audit-before-cleanup. Execution references
cannot come from raw caller JSON. No transport may retry ambiguous mutations.
Interleaved PGlite/fake-transport regressions are not pooled-host, authenticated
cross-HTTP or pilot evidence.

## Creation safety and reconciliation

`ClaimStore` uses the installed SDK's `PluginDatabaseClient`; `CardDelivery` accepts
a structurally compatible subset of the issue client. It never uses plugin state
as a mutex. Namespace migrations target the installed host's derived namespace
for `togetherweown.vuln-sentinel`; the constructor rejects a different namespace.

Every conforming writer must go through the same helper:

1. Insert the `(company_id, origin_id)` claim atomically. A lost response requires
   reading the exact durable token before proceeding.
2. Look up the exact company/origin-kind/origin-id, **including closed issues**,
   before any create. Link one existing issue; quarantine multiple results.
3. Durably transition the token-fenced owner to `creating`, recheck ownership,
   then call `issues.create` once with no automatic transport retry. The issue
   transport supplied to the helper must not retry this non-idempotent method.
4. Link the returned issue ID through a conditional token/state update. Any
   uncertain create/link outcome remains fenced. Linked issues are reused, never
   replaced automatically if they disappear.
5. The legacy per-finding API refreshes/reopens only for a newer known advisory
   modification. Versioned container publication instead uses monotonic container
   revisions, plus explicit unresolved-member closure reconciliation as above.

A four-minute internal deadline bounds an invocation. **Timeout is not
cancellation:** a submitted host request can still commit later. Thirty minutes
is an attention/reconciliation threshold, never permission to steal a claim.
Replay/restart therefore cannot initiate a second create for an ambiguous attempt.

The legacy `reconcile` fixture path can relink an issue found by lookup, and has an
optional callback-based empty-lookup recovery branch. **Neither is an approved trusted
adapter recovery path.** Do not connect the empty-lookup branch, import/take over/refresh
uncertain claims or infer settlement from a visible issue. No automatic second create
is permitted. Worker termination, age, RPC timeout or a retry click proves nothing about
late effects. A future host-authorized repair can restore only the exact known committed
issue/link after independent later CLOSED-membership verification and durable audit;
otherwise preserve uncertainty and both pins. No runtime endpoint exposes recovery.
Library recovery history/tombstones are retained but worker writable, not authority;
no automatic expiry or delete resets the guard.

This is **at-most-once create-attempt safety for conforming writers**, not
unconditional exactly-once/eventual issue creation. It intentionally sacrifices
automatic liveness. Out-of-band creates are diagnosed as collisions, never
auto-deleted. Operator-facing health will need to surface the fenced claim's age,
token, attempt count, last error, and reconciliation instructions before this is
installed.

## Reuse and contributing

The implementation uses Paperclip's installed namespace-DB and issue APIs, not a
parallel scheduler, task system, or token broker. The shipped GitHub Upstream
plugin's exact-origin lookup and ETag patterns are the reference for the remaining
integration. No inference client or LLM dependency is included.

Follow the organization [contribution guidelines](https://github.com/TogetherWeOwn/.github/blob/main/CONTRIBUTING.md)
and [pipeline standard](https://github.com/TogetherWeOwn/.github/blob/main/PIPELINE-STANDARD.md).
