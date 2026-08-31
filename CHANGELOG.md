# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Adapter mirror of the Python batch-1/batch-2 adversarial review.** The TS package ships
  exactly one adapter surface (`src/adapters/langgraph.ts` — `package.json`'s `exports` map
  declares nothing besides `.` and `./adapters/langgraph`; no A2A, no generic wrapper, no
  separate LangChain.js seam), and execution binding was already fully wired into both
  `guardNode` and `guardTool` as of 0.4.0. Each Python defect class was checked against this
  specific adapter, against pinned `@langchain/core@1.2.9`/`@langchain/langgraph@1.4.13` source
  (installed and grepped directly, not assumed), rather than ported by analogy — see the module
  doc comment's own "Adversarial review" section for the full per-class evidence. Six of the
  seven classes came back genuinely inapplicable to this adapter's architecture (no composable
  middleware chain in either pinned framework package; one wrapper per call, no second gate; no
  cross-hook correlation map to collide or grow unbounded; `isDeferredResult` already covers
  JavaScript's whole lazy-result landscape; no external multi-phase hook dispatch to lose an
  event across; `src/`'s only runtime import is a lazy `@langchain/langgraph`, correctly
  undeclared as a hard dependency, matching the README's own "zero runtime dependencies" claim).
  One real, TS-specific gap was found in the snapshot-commitment family and fixed:
  - `snapshotParams`/`snapshotToolParams`'s fallback, taken when `structuredClone` cannot clone
    the value being snapshotted (a function, a class instance it refuses, anything sharing an
    object graph with one of those), was a bare shallow copy — `{args: [...args]}` makes a fresh
    OUTER array, but every element INSIDE it is the same live reference as the real call
    arguments. Reproduced directly before fixing: `snapshot.args[0] === liveArg` was `true`, and
    a mutation of `liveArg` after the call was visible through the "snapshot" — violating the
    adapter's own documented guarantee ("an IMMUTABLE snapshot... taken BEFORE the wrapped
    callable runs"). Checked the specific `toJSON` vector first: `structuredClone` does NOT
    consult a `toJSON` method or any other user-overridable protocol the way Python's
    `copy.deepcopy` consults `__deepcopy__` (verified empirically — a hostile class's own
    `toJSON` returning fabricated data is simply ignored, and a successful clone is never the
    same reference); only the FAILURE path aliased.
  - Fixed with a new `freeze()` function (exported for direct testing, the same reason every
    Python adapter's own `_freeze()` is imported directly by its tests — the audit log never
    exposes the raw snapshot value, only its hash, so "does this alias" is not otherwise
    observable): safe JSON-primitive leaves pass through verbatim, plain objects/arrays are
    rebuilt fresh and recursively, and anything else (a function, a class instance, a
    `Map`/`Set`/`Date`/`RegExp`, a `Symbol`, a `BigInt`) becomes a safe string representation —
    never the live reference. This is `structuredClone`'s support matrix happening to overlap
    with what the audit log's own JCS canonicalizer (`params.ts`) can hash, unconditionally,
    matching the same invariant every Python adapter's `_freeze()` already holds, rather than
    scoped narrowly to only the cases proven to reach a hash mismatch. Guards a circular
    reference with a `WeakSet` (`structuredClone` handles cycles natively; the whole point of
    this function is the cases it could NOT handle, one of which could still be cyclic). A
    welcome side effect: because `freeze()` sanitizes an otherwise-unsupported value BEFORE it
    is ever handed to `params.ts`'s `commit()`, a call that used to commit no hash at all
    (`paramsHashReason: "unsupported"`) now commits a real, verifiable one.
  - Tests added in `test/adapter-langgraph.test.ts`: two direct unit tests on `freeze()` itself
    (never aliases the unclonable value's own case; never aliases a mutable SIBLING sharing the
    same object graph as an unclonable value — the mixed case), one guarding the circular
    reference, and one end-to-end test per wrapper (`guardNode`, `guardTool`) driving an
    unclonable argument through the real call path and asserting a genuine, matching
    `authorizedParamsHash`/`invokedParamsHash` pair is committed rather than `"unsupported"`.
- **D14 — `Guard.check()` registered a `PRE_HOOK_ONLY` allow as pending, wedging `complete()`
  forever.** Mirrors the fix landing in the Python `attenu-guard` reference implementation
  (`guard.py`, same defect, same root cause): `registerPending` ran unconditionally for every
  `schemaVersion: 2` allow, in both the normal commit path and the `CommittedAuditError` path,
  with no regard for `capture`. A bare `check()` (or any explicit `capture: Capture.PRE_HOOK_ONLY`)
  is an honest promise of NO terminal observation — nothing is ever going to call `recordOutcome`
  for it — yet it was registered pending exactly like a `WRAPPER_SYNC`/`WRAPPER_ASYNC`/
  `FRAMEWORK_POST_HOOK` allow, so `complete()` refused forever for a node with only
  `PRE_HOOK_ONLY` calls. The offline verifier already treated a missing `PRE_HOOK_ONLY` outcome
  as merely `unobserved` (`evidence.ts`'s execution-binding report), so runtime and offline
  semantics disagreed. Fixed: a call is now registered pending only when its capture is one of
  `WRAPPER_SYNC`/`WRAPPER_ASYNC`/`FRAMEWORK_POST_HOOK` — in both the normal path and the
  `CommittedAuditError` path. A bare/`PRE_HOOK_ONLY` allow never enters the pending set, so
  `complete()` finalizes immediately, and the verifier's `unobserved` classification for it now
  matches the runtime's own view.

## [0.4.0] — 2026-08-31

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
