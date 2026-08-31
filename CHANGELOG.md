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
    `toJSON` returning fabricated data is simply ignored, and the clone is never the same
    OBJECT reference for that specific case); only the FAILURE path aliased for a hostile
    `toJSON`. See the release-gate correction below for why "a successful clone never aliases"
    was still wrong as a general claim (a `SharedArrayBuffer` clones "successfully" to a
    DIFFERENT object that shares the SAME underlying memory).
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
  - **Delta review, two more edits to `freeze()` itself:**
    - **Medium-low, required:** the plain-object branch built the rebuilt object with an
      `out[k] = freeze(v, seen)` accumulation loop. A plain `JSON.parse('{"__proto__": {...}}')`
      result genuinely has `"__proto__"` as an OWN, ENUMERABLE data property (`Object.keys`
      lists it — JSON has no notion of prototypes, so this is reachable from ordinary untrusted
      input, not a contrived shape) — but assigning through `out[k] = v` for that specific key
      name does not create a data property at all; it sets the accumulator's own `[[Prototype]]`
      via `Object.prototype`'s own `__proto__` accessor instead. The key then vanished from the
      rebuilt object's own enumerable keys entirely — a params-commitment completeness gap
      (substitution on that key would be invisible to a params mismatch) that `structuredClone`'s
      own success path, and Python's `_freeze()`, do not have. Fixed with
      `Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, freeze(v, seen)]))`, which
      always defines genuine data properties, `__proto__` included. Test added: a
      `JSON.parse`-created `__proto__` own key beside an unclonable sibling (forcing the
      fallback) — the key survives into the snapshot with its value, and the rebuilt object's
      own prototype is unaffected.
    - **Nit, ride-along:** the array branch used `value.map((v) => freeze(v, seen))` —
      `Array.prototype.map` SKIPS a hole in a sparse array rather than visiting it, so a hole
      would survive into the snapshot as a hole too, unlike every other absent value `freeze()`
      turns into a plain `null`. Fixed with `Array.from(value, (v) => freeze(v, seen))`, which
      visits every index up to `.length`, densifying a hole to `undefined` (then `null`, same as
      any other `undefined`). Test added: `freeze([1, , 3])` equals `[1, null, 3]`, with a real
      (densified) element at index 1, not a hole.
  - **Release-gate correction (CRITICAL + HIGH): `freeze()` was still only a FALLBACK, run only
    when `structuredClone` THREW — a successful clone bypassed it entirely, and "a successful
    clone never aliases" (asserted above) was not actually true.** Three bypasses, each
    reproduced directly before fixing: (1) a circular object clones successfully —
    `structuredClone` handles cycles natively — so `freeze()` never ran on it at all; the
    circularity then reached `params.ts`'s own hash-commitment walk, which has NO cycle guard,
    and crashed with `RangeError: Maximum call stack size exceeded` before authorization or the
    tool body ever ran. (2) A sparse array clones successfully too, holes preserved, bypassing
    `freeze()`'s own densification (added above) entirely — it reached `params.ts` as
    `paramsHashReason: "unsupported"` instead of a real, densified, hashable snapshot. (3) A
    `SharedArrayBuffer` clones to a DISTINCT wrapper object that shares the SAME underlying
    memory, by design — a "successful" clone that is not independent at all. Fixed by making
    `freeze()` the ONLY snapshot path, unconditionally: `structuredClone` is no longer called
    anywhere in this adapter. Also fixed in the same pass: the cycle guard (`seen`) was a
    single, MUTABLE `WeakSet` shared across the whole call, added to but never removed from —
    so a DAG's repeated sibling reference (the SAME object appearing twice as two different
    keys' values, never as its own ancestor) was wrongly reported `"<circular>"` on its second
    occurrence, reproduced directly: `freeze({a: shared, b: shared})` came back
    `{"a": {...}, "b": "<circular>"}`. Renamed to `active`, a PATH-ACTIVE `ReadonlySet` — a
    fresh `Set` unioned in at each recursive call, never mutated in place or shared across
    sibling branches. Separately, HIGH: the array and object branches (`Array.from`/`.map()` and
    `Object.entries()`) invoke the value's OWN protocols — a hostile `[Symbol.iterator]`
    override can yield ANYTHING regardless of an array's real indexed properties (reproduced:
    `[1, , 3]` with a hostile iterator froze as `[999]`), and a getter is INVOKED by
    `Object.entries()`, with no guarantee of being invoked only once (reproduced: with an
    unclonable sibling forcing the old fallback, a getter with a side effect was observed three
    times across the old clone-attempt/freeze/body sequence, and the committed snapshot was the
    SECOND of three observations, not the first). Fixed: both branches now walk
    `Object.getOwnPropertyDescriptor` directly (arrays by a `.length`-bounded index loop, objects
    by `Object.keys`) — pure introspection, never invoking user code — and an accessor property
    (`.get`/`.set` present) is encoded as the literal string `"<accessor>"` rather than read at
    all. **A regression caught and fixed before this same commit landed:** rewriting the
    object branch's write-back re-introduced the EXACT `out[key] = value` bug the `__proto__`
    fix above had already closed (a bracket assignment to the literal key `"__proto__"` sets the
    accumulator's prototype instead of a data property) — caught by running the existing
    `__proto__` test against the rewrite, not assumed fixed; corrected with
    `Object.defineProperty` in the loop instead. Six new tests added, each driving the REAL
    wrapper (`guardNode`/`guardTool`), not `freeze()` directly — the earlier circular test
    guarded the wrong path (it passed even while the actual wrapper crashed): circular input,
    sparse array, hostile custom iterator, getter, `SharedArrayBuffer`, and a DAG's repeated
    reference, all via `test/adapter-langgraph.test.ts`.
  - **Release-gate correction (HIGH): `isDeferredResult` missed a plain `AsyncIterable`.** The
    async branch required the result to have its OWN `.next` method, matching a self-iterating
    async generator — but the JavaScript async-iterable protocol only requires a callable
    `[Symbol.asyncIterator]()`, which can return a SEPARATE object that has `.next`, without the
    iterable itself ever having one. Reproduced directly before fixing: a plain object
    implementing only `[Symbol.asyncIterator]()` was recorded `BodyState.RETURNED`, not
    `DEFERRED`. Fixed: the async check no longer requires an own `.next` (the sync check, which
    DOES require it, was deliberately left alone — dropping it there would misdetect a plain
    `Array`/`Set`/`Map` as deferred, since those implement `Symbol.iterator` too without their
    contents being lazily produced; there is no equivalent JavaScript built-in that implements
    `Symbol.asyncIterator` over already-computed values, so this asymmetry is not itself a gap).
    The module doc comment's own "whole lazy-result landscape" claim is narrowed to list exactly
    what `isDeferredResult` checks, rather than asserting completeness. Two tests added: the
    async-iterable case now scores `DEFERRED`; a plain array result is confirmed to still score
    `RETURNED` (pinning that the sync branch's requirement was deliberately kept).
  - **Release-gate correction (HIGH): three disagreeing version fields.** `package.json` said
    `0.4.0`; `package-lock.json`'s root `"version"` said `0.3.1` (stale since before the 0.4.0
    bump — `npm install` never re-synced it); `src/version.ts`'s exported `VERSION` — the
    constant `guard.ts` and both `adapters/langgraph.ts` wrappers use to attribute every v2
    ledger entry's `adapter.version` field — said `0.3.0`. The release workflow
    (`.github/workflows/release.yml`) only ever checks the pushed tag against `package.json`, so
    it would have published while shipped ledger attribution was still wrong. Every v2 ledger
    entry produced by the shipped 0.4.0 release has been misreporting `adapter.version` as
    `"0.3.0"`. Fixed: all three aligned to the CURRENT `0.4.0` (no version bump as part of this
    fix — that is the operator's call at release time). Added
    `test/version-consistency.test.ts`, a new CI-run test (not only a release-time check)
    asserting `package.json`, `package-lock.json`'s root version (both the top-level field and
    its `packages[""].version` copy, which have drifted independently before), and the exported
    `VERSION` all agree, every run, not only at tag time.
  - **Release-gate finding, MEDIUM: `test/wire-vectors.test.ts` enumerated and scored 19 of the
    20 published interop vectors, silently.** `reject_unsafe_integer` — anticipated in this
    package's own `[0.3.1]` CHANGELOG entry below ("will show 20 vectors... once the Python
    package ships them") and shipped by Python's own `[0.9.0]` — has had its fixture file
    present on disk (byte-identical to Python's) since, but `VECTOR_NAMES` itself was never
    updated to include it, and the test's own count assertion (`19`) masked the omission rather
    than catching it. Fixed: added to `VECTOR_NAMES`, the count and test name updated to `20`,
    and the stale `.github/workflows/ci.yml` comment ("19-vector... >=0.8 ships this") corrected
    to `20-vector`/`>=0.9` (Python's own `[0.9.0]` CHANGELOG entry is where
    `reject_unsafe_integer.json` shipped, matching the pip constraint
    `attenu-guard>=0.9,<0.10` already pinned two lines below that comment).
  - **Release-gate finding, LOW: the interop matrix had no early warning for the NEXT Python
    minor.** `ci.yml`'s `interop` job pins `attenu-guard>=0.9,<0.10` deliberately — the committed
    fixtures match that release, and the job's own last step re-generates and diffs them, so
    pinning to it is correct, not stale. But nothing in this repo would notice a 0.10.0 that
    breaks wire compatibility until someone widened that pin by hand. Added a second job,
    `interop-next`, that runs the same cross-language suite against `attenu-guard>=0.10,<0.11` —
    gated on a `pip index versions` check so it reports success without running anything while
    0.10.0 is unpublished (confirmed against the live PyPI index: 0.9.0 is current, no 0.10.x
    yet), and starts actually exercising the suite the moment the operator ships it, with no
    workflow edit required either way.
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
