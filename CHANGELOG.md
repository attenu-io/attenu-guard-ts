# Changelog

All notable changes to this package are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this package
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- The seven language-independent interop vectors from the Python repository are generated
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
