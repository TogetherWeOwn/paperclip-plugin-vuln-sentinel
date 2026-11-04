# Vulnerability Sentinel

Deterministic vulnerability matching and report-only triage for Paperclip.

## Implementation status

**Core implementation only; not an installable plugin or an enabled pilot yet.**
There is deliberately no worker/manifest entrypoint. Nothing schedules scans,
contacts an advisory provider, mutates a repository, or creates live issues just
by importing this package or running its tests. Explicit read-only source adapters
accept an injected HTTP transport; all adapter tests use fake responses.

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

- Read-only GitHub default-SHA/ETag lockfile snapshots, content/hash validation,
  bounded OSV querybatch pagination/detail hydration and conservative normalization.
- npm v2/v3, pnpm v9 and Cargo v3/v4 locked-entry inventories with explicit attention
  states and no inferred runtime/development scope or full-closure completeness.
- Immutable raw lockfile/inventory and OSV source journal, exact query-tuple coverage,
  replay-safe inserts and readback validation before returning normalized inputs.
- Bounded recursive OSV alias/upstream hydration, explicit unavailable documents,
  raw/derived graph checks and conservative connected-source normalization.
- Read-only KEV and date-pinned EPSS adapters, all-alias enrichment and immutable
  company-scoped feed evidence before decisions. No API/model-version guessing.
- Durable company/repository source-poll fences and explicit GitHub→raw-source
  synchronization, with separate cache-only and freshness-bounded source selection.
  Late older success/failure cannot replace a newer poll's selected source or hold.
- Source-fenced local decision-head/routing writes, with same-statement source row
  locking, DB poll-revision ordering and retained source-selection provenance.
  Source-selected native publication is held for attention, not silently unfenced.
- Explicit retained OSV/feed→source-fenced decision/routing orchestration, with exact
  parent references, current and historical freshness checks, and coverage attention.
- Same-action all-version reduction for identical non-version context, retaining
  every tuple/proof/trace in one deterministic journal revision before routing.

Still required before installation/pilot acceptance: repository/manifest discovery,
other lockfile formats and complete coverage, source-fenced native publication
integration, verified scope/fix/severity enrichment (including incompatible per-version contexts),
Dependabot permission switching, scheduled KEV/EPSS refresh and verified live model
configuration, live rescan receipt verification, manifest/jobs and weekly job scheduling,
managed triage project, health/counters, operator runbook and installation, and two
real consecutive report-only scans. No worker is wired to the explicit publication
API; no weekly batch or per-finding issue has been emitted on a live host.

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

`parseLockfileInventory(snapshot)` verifies content/blob hashes and the configured
path-set digest before parsing npm `package-lock.json`/`npm-shrinkwrap.json` v2/v3,
pnpm v9 and Cargo v3/v4. It deduplicates OSV query tuples while retaining every
installed location and locked version. npm aliases require the real package name
and matching official registry tarball identity; pnpm retains scoped/peer-version
entries and checks importer/snapshot references. Cargo keeps the full registry
locked set, never substitutes native R for locked L and never drops O = L − R.

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
Python, other lockfile schemas, verified scope/directness and discovery remain
unimplemented. Inventories are bounded at 10,000 entries / 2,000 unique query tuples;
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
writes, retaining the immutable references. A future parser-version change needs an explicit
historical-inventory migration/replay strategy; readback never silently replaces
stored coverage with new parser semantics.

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
still needs a source-fenced effect protocol; merely calling `assertCurrent` before
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
The existing fixture-only publication path is not authorization to bypass that
hold. Coordinating source changes with indeterminate remote effects, and trusted
rescan receipt integration, remain required before an enabled worker/pilot. Local
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

## Source-effect barrier primitive (publication remains held)

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

**This does not yet enable native publication.** Intent hashes are identifiers,
not authentication or proof of current container contents. The primitive does not
freeze routing, bind the rendered body to all member decisions, authorize dispatch,
prevent a late sender after settlement, or implement a trusted runtime verifier.
The next integration must enforce those boundaries, recheck freshness before
sending, and keep ambiguous requests pinned until independently settled. Fixture
proof strings test the callback contract only; they are not host-effect receipts.
`ContainerPublication` still returns attention for every source-selected member
or journal record, before all native issue lookups/creates/updates.

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

`reconcile` may relink an issue definitively found by exact lookup. An empty lookup,
worker termination, or a person clicking retry is insufficient to permit another
attempt. The optional recovery verifier is an integration boundary: it must
independently verify both terminal execution and settled outstanding host effects,
with an audit reference bound to the previous token. No runtime endpoint exposes
this capability. Without both receipts, delivery remains `delivery_unknown`.
Recovery audit entries and claim tombstones are retained; no automatic expiry or
delete resets the guard.

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
