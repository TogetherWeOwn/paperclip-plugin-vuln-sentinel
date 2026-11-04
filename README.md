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

Still required before installation/pilot acceptance: source ingestion and runtime
validation, GitHub default-SHA/ETag caching, OSV querybatch and Dependabot switching,
KEV/EPSS refresh, weekly delivery semantics, manifest/jobs, managed triage project,
health/counters, operator runbook and installation, and two real consecutive
report-only scans. Weekly batch topology requires source-spec clarification; this
core does not substitute per-finding issues for that delivery class.

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
5. Only a newer known advisory modification refreshes/reopens the linked issue.
   Same/old/unknown revision replays do not reopen it again.

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
