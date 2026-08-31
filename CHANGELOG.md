# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Execution binding**, opt-in per chain via `Guard.issue(agentId, authority, {schemaVersion: 2})`
  (schema version 1 is unchanged and remains the default): `check`/`recordDenial` now allocate a
  `callId` (fail-closed, with meters restored, if `crypto.randomBytes` throws) and return it on
  `Decision.callId`; `check` gains `authorizedParams`/`capture`/`adapter` options and refuses
  further calls once the node is `complete()`d (`ReasonCode.NODE_FINALIZED`).
  `Guard.recordOutcome(callId, bodyState, options)` binds what a body-owning wrapper observed
  afterwards — `returned`/`raised`/`abandoned`/`deferred`, with `errorCode` required exactly when
  raised. `complete()` returns a plain `boolean` on a `schemaVersion: 1` chain (byte-and-type
  unchanged from every prior release) and a `CompletionResult` on `schemaVersion: 2` only — see
  its doc comment for the JavaScript limits of its truthiness bridge, since unlike Python's
  `__bool__`, `if (guard.complete())` cannot be made to read `false` there — and refuses on v2
  while calls are pending; `revoke`/`revokeAgent` snapshot still-pending callIds onto the `kill`
  entry as `pending_at_kill` without clearing them, so a late `recordOutcome` after a kill is
  still accepted. `check`/`recordOutcome` roll back meters and re-throw on ANY pre-commit failure
  (not only a `crypto.randomBytes` failure), and `recordOutcome` marks a call outcomed only after
  its append actually commits, so a pre-commit failure leaves the call retryable. `Guard.issue`
  refuses `{schemaVersion: 2, auditOverwrite: true}` — the restart rule has no escape hatch on v2.
  Arguments are committed via `params_c14n_v1` (`params.ts`): `SHA-256(rawSalt || JCS(params))`,
  never the raw value; validated against the language-neutral vector file also published for
  Python (`test/fixtures/params_c14n_v1.json`). `verifyBundle` gains `execution_binding`: per-call
  observed/unobserved/unaccounted (an outcome must be bound correctly — right node, right order —
  to count as observed), per-node finalized/in_progress/revoked/revoked_with_pending, an aggregate
  clean/incomplete/failed, and `params_coverage` (computed over every valid allow) as its own axis
  — `{status: "not applicable"}` for a schema-version-1 bundle. `verifyBundle` also gains
  `root_version_mismatch`/`mixed_entry_versions` checks (a chain is created at one schema version
  and never mixes), requires exactly one root event (`checks.root`), does strict, null-aware,
  type-checked schema validation on every conditional field (`capture`/`adapter` are now
  REQUIRED, not merely paired, on every v2 allow — a bare `check()` with no `capture` supplied
  gets a truthful guard-attributed `pre_hook_only` default rather than leaving the ledger silent;
  any allow-only field on a `deny`, or any v2-only field on a `schemaVersion: 1` entry
  — `v2_field_on_v1` — is invalid), and accepts an optional `expectedAnchor`/`expectedHead` to
  verify against an independently retained reference point instead of only the bundle's own
  enclosed anchor. `AuditLog` gains `CommittedAuditError` (a
  post-commit persistence failure after the entry is already in the in-memory chain) and
  overwrite protection (constructing over a `path` that already names a non-empty ledger now
  throws unless `overwrite: true`). The LangGraph adapter (`adapters/langgraph`) is the reference
  wiring: `guardNode`/`guardTool` snapshot a call's arguments once, immutably, before invocation
  and call `recordOutcome` on a `schemaVersion: 2` guard, sync and async, reporting a
  generator/promise-like result as `deferred` and an `AbortController`-driven cancellation as
  `abandoned`; wrapping an async callable on a `schemaVersion: 1` guard stays byte-and-type
  unchanged (never itself becomes an async function). Mirrors attenu-guard (Python) 0.9.0's
  execution-binding layer plus its post-review merge-gate hardening, byte-for-byte on every
  reason-code string; ported test suite: `test/execution-binding.test.ts` (82 cases),
  `test/params-c14n-vectors.test.ts` (the shared parity vectors), plus adapter and evidence
  coverage in `test/adapter-langgraph.test.ts`/`test/evidence.test.ts`.

## [0.3.1] — 2026-08-30

### Fixed
- Integers beyond the RFC 8785 safe range (±(2**53-1)) are now rejected — at canonicalization, at
  `RowLimit`/`SpendCap`/`CallLimit` construction, and by `load` (as `malformed`) — instead of
  silently colliding with a neighbouring integer once serialized as a double. The interop suite
  will show 20 vectors, and `valid_jcs_big_integer`/`valid_jcs_exponent_form` will pin different
  values, once the Python package ships them; until then the affected interop assertions are a
  known, expected failure (see the README note on `npm run fixtures`).
- `verifyBundle` and `AuditLog.verifyAnchor` now check the bundle/anchor schema version and chain
  identity instead of ignoring them, so a bundle for the wrong version or the wrong chain no
  longer verifies.

## [0.3.0] — 2026-08-29

### Changed
- Scope values now use the same lowercase, dot-separated grammar as Python.
  Only a complete terminal `.*` wildcard is valid; it covers any depth below
  the segment boundary. Constructors and wire verification reject malformed
  scope syntax.

### Added
- The two malformed-wildcard vectors from Python bring the shared interop suite
  to 19 vectors.

## [0.2.1] — 2026-08-29

### Changed
- `c14n` is informational; producers still emit it, while verifiers enforce RFC 8785 JCS from canonical bytes and hashes regardless of the label.

## [0.2.0] — 2026-08-29

### Changed
- **RFC 8785 JCS is the only canonicalization format.** Delegation Tokens must
  declare `c14n: JCS` and already carry canonical header and payload bytes.
  Ledger entries, anchors and evidence bundles now carry the same marker and
  use JCS for every hash and signature. There is no legacy or dual-format reader.
- The canonicalizer now uses ECMAScript number serialization, raw Unicode and
  UTF-16 code-unit member ordering, and rejects non-finite numbers, duplicate
  members, lone surrogates, unsupported values and cyclic structures.
- Cross-language fixtures now target Python `attenu-guard` 0.7 and include all
  17 published interop vectors. The new reason codes are `non_finite`,
  `duplicate_member`, `canonicalization_required` and `non_canonical`.

### Added
- **Delegation-chain verification.** `load(tokens, signer, {rootKeyIds, now})` runs the
  Internet-Draft's Offline Verification Algorithm over a chain of Delegation Tokens and
  returns a `VerifiedChain` whose `permits` authorises against the leaf authority. All
  five in-scope steps are checked in the draft's order — JWS signatures with an
  alg-confusion guard, the `par_hash` byte commitment compared in constant time,
  `del_depth`/`del_max_depth` bounds, subsumption via `Authority.isNarrowerThan`, and the
  time claims including `exp` monotonicity along the chain — denying on the first failure
  with a `WireError` carrying a `WireReasonCode`. Holder binding (`cnf`/DPoP) and status-list
  revocation, the draft's steps 6 and 7, are out of scope in both implementations.
  `b64urlEncode`/`b64urlDecode` are exported alongside it.
- The 17 language-independent interop vectors from the Python repository are generated
  into `test/fixtures/vectors/` and asserted here: the valid chain verifies and yields the
  leaf authority, and each adversarial chain is rejected for exactly the reason it declares.

## [0.1.1] — 2026-08-28

### Changed
- Releases are published from GitHub Actions with npm trusted publishing (OIDC) and provenance attestations; no tokens are stored anywhere. Node 20 is the minimum.

## [0.1.0] — 2026-08-28

First release: the TypeScript implementation of attenu-guard.

### Added

- **Offline verifier.** `verifyBundle` checks integrity, monotonicity
  (child ⊆ parent) and containment from an evidence bundle alone, with the
  signed anchor verified when a key is supplied. HS256 and Ed25519 anchors are
  both read. `AuditLog.verify` checks a raw `.jsonl` ledger's hash chain.
  `delegationGraph` and `denials` fold a bundle into the reviewer's view.
- **Core enforcement.** `Authority` (scopes with `family.*` wildcards, typed
  ceilings, TTL), `Guard.issue`, `delegate` (the meet: scopes intersect,
  ceilings take the tighter bound, TTL the shorter; a request wider than the
  parent comes back narrowed), `check` returning a `Decision`, `enforce`
  throwing `AuthorityDenied`, `wouldAllow` and `wouldDelegate` as pure dry-runs,
  chain depth and fanout ceilings, cascade `revoke` and principal-scoped
  `revokeAgent`, strike policy, and a hash-chained audit log.
- **Ceilings:** `RowLimit`, `SpendCap`, `CallLimit` (optionally scoped, and
  self-metering), `EgressRank`, `Allow`, `Deny`, `Prefix`, plus
  `registerCeiling` for custom ones. An unrecognised constraint type denies
  rather than going unenforced.
- **Evidence custody.** `exportBundle` with task redaction and a strict mode
  that refuses to carry any field outside the published ledger allow-list.
- **LangGraph.js adapter** (`attenu-guard/adapters/langgraph`): `guardTool`,
  `guardTools`, `guardNode`, `addGuardedNode`, `delegateTo`, `toolArgs`. The
  adapter never imports the framework.
- **CLI:** `attenu-guard verify <file> [--hs256-key HEX | --pubkey HEX] [--kid KID]`,
  matching the Python CLI's output lines and exit codes.
- **Cross-language fixtures.** `tools/gen_fixtures.py` generates
  `test/fixtures/` from the Python package; the suite reproduces every vector,
  and a further test has the Python CLI verify a ledger and bundle written here.

### Notes

- Zero runtime dependencies. ESM and CommonJS builds, types included, Node 18+.
- Canonical JSON is byte-identical to Python's
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, including ASCII
  escaping and number formatting. Documents that will be re-hashed are parsed
  with number literals preserved.
