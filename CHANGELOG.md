# Changelog

One line per change. The long-form notes for each version (reasoning, review findings, migration detail) are in [`docs/release-notes/`](docs/release-notes/README.md).

Versions follow semantic versioning.

## [Unreleased]

## [0.8.0] - 2026-09-03

### Added
- Observer envelopes (envelope v1), matching Python 0.13.0 byte for byte — a witness's Ed25519 signature over the IDENTITY of one committed ledger entry (`chain_id`, `node`, `seq`, `entry_hash`, `event`, and `call_id` on an allow), carried beside the ledger in a bundle's top-level `envelopes` array. `signEnvelope()`, `verifyEnvelopes()`, `envelopeSubject()`, `envelopeSigningInput()`, and `exportBundle(..., { envelopes })`. The signature is over `JCS(envelope minus "sig")`, the same canonicalization every other signed surface uses
- `verifyBundle()` — `witnessKeys` (the trust set: `[{kid, alg, public_key_hex}]` or a `{kid: publicKey}` record) and `envelopeBytes` (the envelope bytes as received, which only `envelope_non_canonical` needs). Per-entry state `witness-signed` / `process-asserted` in `report.envelopes`, with the report line `witness-signed (matched|not_matched|indeterminate)`; a process-asserted entry gets no result. `checks.envelopes` is `"not present"` on a bundle carrying none, which is every bundle written before this release
- Seven named envelope failures, in `ENVELOPE_FAILURES` and in the same `failures`/`failure_details` list as every other bundle failure: `envelope_unknown_version`, `envelope_unknown_member`, `envelope_subject_mismatch`, `envelope_duplicate_subject`, `envelope_non_canonical`, `envelope_unknown_witness`, `envelope_bad_signature`
- Vendored observer-envelope interop vectors (`test/fixtures/vectors/envelopes/envelope_vectors_v1.json`), revision `envelope_vectors_v1.1`, eighteen cases, copied byte for byte from the Python repository where the generator is their single writer. `test/envelope-vectors.test.ts` scores all eighteen, pins the file's sha256, and proves cross-language byte parity two ways: the witness seeds derive to the public keys the file carries, and signing the same entry with the same seed reproduces the same signature (Ed25519 is deterministic)
- **One entry, at most one envelope.** A second envelope naming a `subject.seq` an earlier envelope in the same array already named is `envelope_duplicate_subject` at the covered entry, and that entry reports `process-asserted` rather than `witness-signed`. Without the rule the per-entry state was written once per envelope and the last one read won, so the same bundle in the other array order scored differently and anyone able to append an envelope could decide what an earlier witness said. The first envelope's result is still reported as what that witness said. Corpus row 17, `reject_duplicate_subject`, carries two valid envelopes over one entry from two trusted witnesses, `matched` then `not_matched`
- `attenu-guard verify --witness-keys FILE` — the trust set for a bundle's observer envelopes, as the vector file's `[{kid, alg, public_key_hex}]` array or a whole vector case. Without it every envelope in a bundle failed `envelope_unknown_witness` and the CLI could not verify a witness-signed bundle at all; the failure still stands when no file is given, and the output now names the flag. Output and exit code match the Python CLI's, as every other verify line does
- **`witness.alg` is checked against the contract**, not against the trust-set row: v1 defines `EdDSA` and no other algorithm, so anything else is `envelope_unknown_witness`. `"alg": "none"` on both sides verified as witness-signed; `"HS256"` reached the Ed25519 verifier and was reported as `envelope_bad_signature`, the right verdict for the wrong reason. `witnessKeys` rows declaring another alg are refused when the trust set is built. Corpus row 18, `reject_unknown_alg`
- **`verifyBundle()` reports on hostile bundle content and never throws.** Every envelope member is an untrusted JSON value of any type. A `seq` that is not an integer, an `event` or a `witness.kid` that is not a string, a `sig` that is not a hex string, and a value JCS cannot represent are each a named reason at a defined position rather than a mis-found Map lookup or an exception. `v: true` was already refused here and accepted by Python, which is the other half of the same class
- Malformed caller inputs are refused rather than coerced: an `envelopeBytes` entry that is not hex or bytes reports `envelope_non_canonical` for that envelope; a `witnessKeys` row whose key is not 64 hex characters or 32 bytes, or whose `kid` is not a string, throws naming the kid when the trust set is built

### Changed
- Two failure strings drop a language-specific type name so both implementations report the same bytes: `subject is not a JSON object` (was `subject is str`/`subject is string`) and `<level> member set is not an object` (was the type's name). Reachable only on hostile input; no committed vector exercised either
- `pyRepr` renders booleans and containers the way Python's `repr` does, so a hostile value interpolated into a failure string matches across the two implementations
- `exportBundle({ redactTask: true, envelopes: [...] })` throws: redaction rewrites every entry hash, so envelopes signed over the unredacted ledger shipped bound to entries that no longer existed and failed `envelope_subject_mismatch`. Export the redacted bundle first, sign over ITS entries, then export again with those envelopes
- `test/evidence.test.ts` compares `checks` against `expected_reports.json` as a superset rather than exactly: the fixture is written by the PINNED Python release, which predates `checks.envelopes`. Every check the fixture names must still match, and the only permitted extra key is named in the test

## [0.7.1] - 2026-09-03

### Added
- Vendored bundle interop vectors updated to revision `bundle_vectors_v1.2` — five appended cases: `valid_bundle_v2_literal` (the root holds `{crm.read, mail.send}`, so the child's scopes are a literal subset) and, derived from it, `reject_increased_ttl_literal`, `reject_loosened_ceiling_literal`, `reject_null_ttl_literal`, `reject_omitted_ceiling_literal`. The v1.1 ttl/ceiling rows are rejected by a verifier that compares scope lists literally and never checks ttl or ceilings (0.6.0 was one), for a scope reason at the declared position, so they never discriminated it; the four new rows can fail only on the dimension they are about. `version` stays `bundle_vectors_v1`; no case changed

## [0.7.0] - 2026-09-03

### Fixed
- `verifyBundle()` monotonicity: a delegation that widened only ttl or only a ceiling verified CLEAN whenever the child's scopes were literally a subset of the parent's — the check was gated on a literal, non-wildcard-aware scope difference, so a `false` from `isNarrowerThan` was discarded. A child that outlived its parent, raised a ceiling, dropped a ceiling its parent held, or carried no ttl at all now fails, and the message names the dimension (`ttl 7200 > parent 3600`, `ceiling max_rows<=250 looser than parent max_rows<=100`), byte-identical to Python. The scope-widening string is unchanged

### Added
- Vendored bundle interop vectors updated to revision `bundle_vectors_v1.1` — four appended cases: `reject_widened_scope`, `reject_uncontained_allow`, `reject_increased_ttl` and `reject_loosened_ceiling`; `version` stays `bundle_vectors_v1`

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
