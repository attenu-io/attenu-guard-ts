# Changelog

One line per change. The long-form notes for each version (reasoning, review findings, migration detail) are in [`docs/release-notes/`](docs/release-notes/README.md).

Versions follow semantic versioning.

## [0.6.0] - 2026-09-02

### Added
- Added `test/fixtures/vectors/bundles/bundle_vectors_v1.json`, 8 bundle-verifier interop vectors matching the Python reference byte-for-byte.
- `verifyBundle()` — reports `failure_details` alongside `failures`, one structured `{reason, seq, node, call_id, detail}` entry per failure.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.6.0.md

## [0.5.0] - 2026-08-31

### Fixed
- `freeze()` — snapshot fallback could alias live call arguments and mishandle `__proto__`/sparse arrays/hostile getters; now the sole snapshot path.
- `Guard.check()` — a bare/`PRE_HOOK_ONLY` allow no longer registers as pending, so `complete()` no longer wedges forever waiting for an outcome.
- `freeze()` — ran attacker code before authorization on Proxy/boxed values; now checks `Proxy` first, returns `FREEZE_UNSUPPORTED` instead of a string.
- `freeze()` — `"<accessor>"`/`"<circular>"` sentinel strings could collide with a matching real argument; both now use `FREEZE_UNSUPPORTED`.
- `interop-next` CI check — a failed `pip index versions` query silently read as "not published yet"; now fails the job instead.

### Added
- Added execution binding (`schemaVersion: 2`): `check`/`recordOutcome` bind call outcomes via `callId`; `verifyBundle` reports `execution_binding` coverage.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.5.0.md

## [0.3.1] - 2026-08-30

### Fixed
- Integers beyond the RFC 8785 safe range are now rejected (canonicalization, `RowLimit`/`SpendCap`/`CallLimit`, `load`) instead of silently colliding.
- `verifyBundle` and `AuditLog.verifyAnchor` now check schema version and chain identity, so a bundle for the wrong version or chain fails to verify.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.3.1.md

## [0.3.0] - 2026-08-29

### Changed
- Scope values now use the same lowercase, dot-separated grammar as Python.

### Added
- The two malformed-wildcard vectors from Python bring the shared interop suite to 19 vectors.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.3.0.md

## [0.2.1] - 2026-08-29

### Changed
- `c14n` is informational; producers still emit it, while verifiers enforce RFC 8785 JCS from canonical bytes and hashes regardless of the label.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.2.1.md

## [0.2.0] - 2026-08-29

### Changed
- RFC 8785 JCS is now the only canonicalization format across Delegation Tokens, ledger entries, anchors, and evidence bundles; no dual-format reader.
- Canonicalizer now uses ECMAScript number serialization and UTF-16 ordering, rejecting non-finite numbers, duplicates, lone surrogates, and cycles.
- Cross-language fixtures now target Python `attenu-guard` 0.7 and include all 17 published interop vectors.

### Added
- Added `load(tokens, signer, {rootKeyIds, now})`, running the offline verification algorithm over a Delegation Token chain and returning a `VerifiedChain`.
- Added the 17 language-independent interop vectors from the Python repo to `test/fixtures/vectors/`; each adversarial chain is rejected for its declared reason.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.2.0.md

## [0.1.1] - 2026-08-28

### Changed
- Releases are published from GitHub Actions with npm trusted publishing (OIDC) and provenance attestations; no tokens are stored anywhere.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.1.1.md

## [0.1.0] - 2026-08-28

### Added
- Added `verifyBundle` (integrity, monotonicity, containment, HS256/Ed25519 anchor check), `AuditLog.verify`, and `delegationGraph`/`denials`.
- Added core enforcement: `Authority`, `Guard.issue`/`delegate`/`check`/`enforce`, chain depth/fanout ceilings, `revoke`/`revokeAgent`, audit log.
- Added ceilings: `RowLimit`, `SpendCap`, `CallLimit` (scoped, self-metering), `EgressRank`, `Allow`, `Deny`, `Prefix`, plus `registerCeiling` for custom types.
- Added `exportBundle` with task redaction and a strict mode that refuses any field outside the published ledger allow-list.
- Added the LangGraph.js adapter (`attenu-guard/adapters/langgraph`): `guardTool`, `guardNode`, `addGuardedNode`, `delegateTo`, `toolArgs`.
- Added the CLI: `attenu-guard verify <file> [--hs256-key HEX | --pubkey HEX] [--kid KID]`, matching the Python CLI's output and exit codes.
- Added cross-language fixtures: `tools/gen_fixtures.py` builds `test/fixtures/` from the Python package; the Python CLI verifies ledgers/bundles here.

### Notes
- Zero runtime dependencies.
- Canonical JSON is byte-identical to Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, including ASCII escaping and number formatting.

Full notes: https://github.com/attenu-io/attenu-guard-ts/blob/main/docs/release-notes/v0.1.0.md
