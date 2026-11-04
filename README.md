# Vulnerability Sentinel

Deterministic vulnerability matching and report-only triage for Paperclip.

## Implementation status

**Core implementation only; not an installable plugin or an enabled pilot yet.**
There is deliberately no worker/manifest entrypoint. Nothing schedules scans,
contacts an advisory provider, mutates a repository, or creates live issues just
by importing this package or running its tests.

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

Still required before installation/pilot acceptance: source ingestion and runtime
validation, GitHub default-SHA/ETag caching, OSV querybatch and Dependabot switching,
KEV/EPSS refresh, verified new-artifact resolution, manifest/jobs and weekly job
scheduling, managed triage project, health/counters, operator runbook and installation,
and two real consecutive report-only scans. No worker is wired to the explicit
publication API; no weekly batch or per-finding issue has been emitted on a live host.

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
scanner output or untrusted JSON. Runtime ingestion/validation is not implemented
and no endpoint accepts such a bundle yet. Evidence-producing adapters must verify
the claimed coverage rather than inferring it from an empty search result.

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
- Negative applicability remains a proposal. There is deliberately no API that
  treats container closure, elapsed time, changed fix hints, or arbitrary new
  artifact observations as proof of remediation. Verified new-artifact rescan
  resolution is still unimplemented; external-closure reconciliation only reopens
  the same container and never changes member state.

This is a bounded pilot projection: at most 2,000 members and 1 MiB per repository,
with at most 32 CAS attempts per invocation. Capacity/contention failures retain
journal evidence, throw an attention-required error and permit no issue effect.
Runtime health must surface those errors before installation. It is not a general
unbounded organization ledger; scaling requires a measured storage migration.
Native issue links and creation guards are separate from this routing projection;
`ContainerPublication` connects them through the shared origin-kind-aware guard.

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
Complete new-digest rescan resolution, preservation of unrelated resolved members,
job integration and real two-run zero-duplicate evidence remain required.

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
