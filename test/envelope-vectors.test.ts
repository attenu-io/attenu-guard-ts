/**
 * test/envelope-vectors.test.ts — the observer-envelope interop vectors
 * (`test/fixtures/vectors/envelopes/envelope_vectors_v1.json`) and the envelope contract they are
 * scored against.
 *
 * The wire vectors pin what a delegation TOKEN means; the bundle vectors pin what the LEDGER of a
 * run has to satisfy; these pin the one question neither can answer — was this delegation event
 * signed by something OUTSIDE the process that wrote it? An envelope is a witness's Ed25519
 * signature over the IDENTITY of one committed ledger entry, carried beside the ledger in the
 * bundle's top-level `envelopes` array. It is never required: an absent one is the status quo and
 * every entry reports `process-asserted`. A present one has to verify.
 *
 * The file is copied VERBATIM from attenu-guard (Python)'s
 * `tests/vectors/envelopes/envelope_vectors_v1.json`, where `tests/vectors/generate_envelopes.py`
 * is its single writer and `tests/test_envelope_vectors.py` self-checks it against that build's
 * own `verify_bundle()`. Copying the bytes rather than rebuilding them is the point: a second
 * generator would be a second source of truth. The sha256 below pins which bytes these are.
 *
 * Three things are asserted here, the same three the Python suite asserts:
 *
 *   1. every case scores exactly as it declares — the verdict, every declared
 *      {reason, seq, node} at that position, AND the per-entry state for every entry;
 *   2. the two scoring rules on where an extra may land — an envelope failure lands only on a hop
 *      that envelope covers, and no chain-level integrity failure is ever raised because an
 *      envelope failed;
 *   3. cross-language byte parity: the witness keys derive to the same public keys here, and
 *      signing the same entry with the same seed produces the same 64 signature bytes, so the
 *      corpus is not merely scored the same way but signed the same way.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import type { CJson, Json } from "../src/canonical.js";
import { canonicalBytes } from "../src/canonical.js";
import {
  ENVELOPE_ALG,
  ENVELOPE_FAILURES,
  ENVELOPE_SUBJECT_MEMBERS,
  ENVELOPE_TYP,
  ENVELOPE_VERSION,
  PROCESS_ASSERTED,
  WITNESS_SIGNED,
  envelopeSigningInput,
  envelopeSubject,
  exportBundle,
  signEnvelope,
  verifyBundle,
  verifyEnvelopes,
  type Bundle,
  type Envelope,
  type FailureDetail,
  type WitnessKey,
} from "../src/evidence.js";
import { Authority } from "../src/authority.js";
import { RowLimit } from "../src/ceilings.js";
import { Guard } from "../src/guard.js";
import { Ed25519Signer, HS256TestSigner } from "../src/wire.js";
import { resolve } from "node:path";

import { REPO_ROOT, fixturePath, fixtureText } from "./helpers.js";

const VECTOR_FILE = "vectors/envelopes/envelope_vectors_v1.json";

/**
 * The sha256 of the vendored file. It pins WHICH bytes this suite scored, the way an independent
 * run pins the corpus it ran. It moves only when a case is appended, which also moves `revision`.
 */
const VECTOR_SHA256 = "6a57d75ebec881d39d5a1805793a20f9a6d7bff021b70782dcb57c43b276df64";

interface ExpectedFailure {
  reason: string;
  seq: Json;
  node: Json;
}

interface VectorCase {
  name: string;
  description: string;
  signer: { alg: string; kid: string; secret_hex: string } | null;
  witness_keys: WitnessKey[];
  bundle: Bundle;
  expect: "accept" | "reject";
  expect_states: Record<string, string>;
  expect_failures: ExpectedFailure[];
  canonical_hex?: string;
  raw_hex?: string;
}

interface VectorFile {
  version: string;
  revision: string;
  description: string;
  cases: VectorCase[];
}

// JSON.parse, deliberately: it preserves member order for string keys, and `valid_jcs_reorder`'s
// whole point is a non-canonical SOURCE order that a re-sorting reader would destroy.
const DOCUMENT = JSON.parse(fixtureText(VECTOR_FILE)) as VectorFile;


/** The seq the corpus's spawn sits at, and the allow that follows it. */
const SPAWN_SEQ = 1;
const ALLOW_SEQ = 2;

function byName(name: string): VectorCase {
  const c = DOCUMENT.cases.find((x) => x.name === name);
  assert.ok(c !== undefined, `no case named ${name}`);
  return c;
}

function signerFor(c: VectorCase): HS256TestSigner | null {
  if (c.signer === null) return null;
  assert.equal(c.signer.alg, "HS256", "these anchors are HS256; the verifier must be told so");
  return new HS256TestSigner(Buffer.from(c.signer.secret_hex, "hex"), c.signer.kid);
}

function verify(c: VectorCase) {
  return verifyBundle(c.bundle, signerFor(c), {
    witnessKeys: c.witness_keys,
    envelopeBytes: c.raw_hex === undefined ? null : [Buffer.from(c.raw_hex, "hex")],
  });
}

function positions(details: readonly FailureDetail[]): ExpectedFailure[] {
  return details.map((d) => ({ reason: d.reason, seq: d.seq, node: d.node }));
}

function includesPosition(reported: ExpectedFailure[], expected: ExpectedFailure): boolean {
  return reported.some((r) => r.reason === expected.reason && r.seq === expected.seq && r.node === expected.node);
}

// =============================================================================================
// The committed vectors
// =============================================================================================

test("the vendored file is the exact bytes Python's generator wrote", () => {
  const bytes = readFileSync(fixturePath(VECTOR_FILE));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), VECTOR_SHA256);
});

test("the vector file declares its version and every expected case, in order", () => {
  // `version` is the compatibility contract and does not move when cases are appended;
  // `revision` is the additive counter that does. Cases are appended, never inserted.
  assert.equal(DOCUMENT.version, "envelope_vectors_v1");
  assert.equal(DOCUMENT.revision, "envelope_vectors_v1.1");
  assert.deepEqual(
    DOCUMENT.cases.map((c) => c.name),
    [
      // envelope v0 as amended by v0.1 — the fifteen rows as posted.
      "valid_spawn_envelope",
      "valid_allow_envelope",
      "valid_jcs_reorder",
      "absent_envelope",
      "indeterminate_result",
      "reject_rehashed_chain_sparse",
      "reject_subject_mismatch",
      "reject_bad_signature",
      "reject_unknown_version",
      "reject_non_canonical",
      "reject_member_without_bump",
      "reject_masked_bundle_mutation",
      "reject_rehashed_chain_anchored",
      "reject_rehashed_chain_unanchored",
      "reject_unknown_witness",
      // Appended at @safal207's proposal, so nothing above it moved.
      "reject_locator_mismatch",
      // Appended at revision v1.1: the duplicate-subject rule, and the algorithm check.
      "reject_duplicate_subject",
      "reject_unknown_alg",
    ],
  );
});

test("every case carries the trust set and a state for every entry", () => {
  for (const c of DOCUMENT.cases) {
    assert.ok(c.description.trim().length > 0, c.name);
    assert.ok(c.witness_keys.length > 0, c.name);
    for (const key of c.witness_keys) {
      assert.equal(key.alg, ENVELOPE_ALG, c.name);
      assert.equal(Buffer.from(key.public_key_hex, "hex").length, 32, c.name);
    }
    assert.deepEqual(
      Object.keys(c.expect_states).map(Number).sort((a, b) => a - b),
      c.bundle.entries.map((e) => e["seq"] as unknown as number),
      c.name,
    );
    for (const state of Object.values(c.expect_states)) {
      assert.ok(state === WITNESS_SIGNED || state === PROCESS_ASSERTED, `${c.name}: ${state}`);
    }
    for (const f of c.expect_failures) {
      assert.deepEqual(Object.keys(f).sort(), ["node", "reason", "seq"], c.name);
    }
  }
});

test("every accepting case verifies with no failures and reports its declared states", () => {
  for (const c of DOCUMENT.cases.filter((x) => x.expect === "accept")) {
    const report = verify(c);
    assert.ok(report.ok, `${c.name}: ${report.failures.join(" | ")}`);
    assert.deepEqual(report.failures, [], c.name);
    assert.deepEqual(c.expect_failures, [], c.name);
    assert.deepEqual(report.envelopes.states, c.expect_states, c.name);
  }
});

test("every rejecting case reports each declared failure at its declared position", () => {
  for (const c of DOCUMENT.cases.filter((x) => x.expect === "reject")) {
    const report = verify(c);
    assert.equal(report.ok, false, c.name);
    assert.ok(c.expect_failures.length > 0, `${c.name}: a rejecting case must declare a failure`);
    const reported = positions(report.failure_details);
    for (const expected of c.expect_failures) {
      assert.ok(
        includesPosition(reported, expected),
        `${c.name}: missing ${JSON.stringify(expected)} in ${JSON.stringify(reported)}`,
      );
    }
    assert.deepEqual(report.envelopes.states, c.expect_states, c.name);
  }
});

test("the declared minimal set is minimal", () => {
  // Every declared failure must be one the verifier genuinely reports for THAT bundle.
  for (const c of DOCUMENT.cases) {
    const reasons = new Set(verify(c).failure_details.map((d) => d.reason));
    for (const expected of c.expect_failures) {
      assert.ok(reasons.has(expected.reason), `${c.name}: ${expected.reason}`);
    }
  }
});

test("each of the seven named envelope failures is required by a row", () => {
  const required = new Set<string>();
  for (const c of DOCUMENT.cases) {
    for (const f of c.expect_failures) if (f.reason.startsWith("envelope_")) required.add(f.reason);
  }
  assert.deepEqual([...required].sort(), [...ENVELOPE_FAILURES].sort());
});

// ---- the two scoring rules from envelope v0.1, section 5 ------------------------------------

test("an envelope failure lands only on a hop that envelope covers", () => {
  for (const c of DOCUMENT.cases) {
    const covered = new Set((c.bundle.envelopes ?? []).map((e) => (e.subject as Record<string, Json>)["seq"]));
    for (const d of verify(c).failure_details) {
      if (!d.reason.startsWith("envelope_")) continue;
      assert.ok(covered.has(d.seq), `${c.name}: ${d.reason} landed at seq ${String(d.seq)}, which no envelope covers`);
    }
  }
});

test("the sparse row reports at the covered hop and never at the skipped one", () => {
  const c = byName("reject_rehashed_chain_sparse");
  assert.deepEqual((c.bundle.envelopes ?? []).map((e) => (e.subject as Record<string, Json>)["seq"]), [ALLOW_SEQ]);
  assert.deepEqual(
    verify(c)
      .failure_details.filter((d) => d.reason.startsWith("envelope_"))
      .map((d) => [d.reason, d.seq]),
    [["envelope_subject_mismatch", ALLOW_SEQ]],
  );
});

test("no chain-level integrity failure is raised because an envelope failed", () => {
  // Fresh anchor, and no anchor: neither may produce an integrity failure at all.
  for (const name of ["reject_masked_bundle_mutation", "reject_rehashed_chain_unanchored"]) {
    const report = verify(byName(name));
    assert.deepEqual(report.failure_details.map((d) => d.reason), ["envelope_subject_mismatch"], name);
    assert.equal(report.checks.integrity, true, name);
    assert.equal(report.checks.monotonicity, true, name);
    assert.equal(report.checks.containment, true, name);
  }
  // The original anchor over a rewritten chain: this is where it comes from.
  for (const name of ["reject_rehashed_chain_sparse", "reject_rehashed_chain_anchored"]) {
    assert.equal(verify(byName(name)).checks.anchor, "FAILED", name);
  }
});

// ---- the rows that would be vacuous if built carelessly -------------------------------------

test("the reorder row is in a non-canonical source order at every level", () => {
  // If this envelope were written with its members sorted, the row would be a duplicate of
  // valid_spawn_envelope and would test nothing. JSON.parse preserves the file's order.
  const envelope = byName("valid_jcs_reorder").bundle.envelopes![0]! as unknown as Record<string, unknown>;
  const levels: Record<string, unknown>[] = [
    envelope,
    envelope["subject"] as Record<string, unknown>,
    envelope["observed"] as Record<string, unknown>,
    envelope["witness"] as Record<string, unknown>,
  ];
  for (const obj of levels) {
    const keys = Object.keys(obj);
    assert.notDeepEqual(keys, [...keys].sort(), JSON.stringify(keys));
  }
  const sortedElsewhere = Object.keys(byName("valid_spawn_envelope").bundle.envelopes![0]!);
  assert.deepEqual(sortedElsewhere, [...sortedElsewhere].sort());
});

test("the reorder row is the same envelope as the spawn row, and declares its JCS preimage", () => {
  const reordered = byName("valid_jcs_reorder");
  const envelope = reordered.bundle.envelopes![0]!;
  const original = byName("valid_spawn_envelope").bundle.envelopes![0]!;
  assert.equal(envelope.sig, original.sig);
  assert.deepEqual(canonicalBytes(envelope as unknown as CJson), canonicalBytes(original as unknown as CJson));
  // Scored on both halves: it accepts, AND the bytes the verifier canonicalized equal
  // `canonical_hex` — the bytes themselves, not a digest over them.
  assert.equal(envelopeSigningInput(envelope as unknown as Record<string, CJson>).toString("hex"), reordered.canonical_hex);
  assert.ok(verify(reordered).ok);
});

test("the non-canonical row supplies bytes that differ from JCS of what they parse to", () => {
  const c = byName("reject_non_canonical");
  const raw = Buffer.from(c.raw_hex!, "hex");
  const envelope = c.bundle.envelopes![0]!;
  assert.deepEqual(JSON.parse(raw.toString("utf8")), envelope);
  assert.notDeepEqual(raw, canonicalBytes(envelope as unknown as CJson));
  // Without the received bytes the failure cannot be raised at all: the parse discarded the only
  // trace of it, which is exactly why the row carries them.
  const blind = verifyBundle(c.bundle, signerFor(c), { witnessKeys: c.witness_keys });
  assert.ok(!blind.failure_details.some((d) => d.reason === "envelope_non_canonical"));
});

test("the absent row carries no envelopes member at all", () => {
  const c = byName("absent_envelope");
  assert.equal("envelopes" in c.bundle, false);
  const report = verify(c);
  assert.ok(report.ok);
  assert.equal(report.checks.envelopes, "not present");
  assert.deepEqual(new Set(Object.values(report.envelopes.states)), new Set([PROCESS_ASSERTED]));
  assert.deepEqual(new Set(Object.values(report.envelopes.lines)), new Set([PROCESS_ASSERTED]));
});

test("the unanchored row is the only one with no signer and no anchor", () => {
  for (const c of DOCUMENT.cases) {
    const unanchored = c.name === "reject_rehashed_chain_unanchored";
    assert.equal(c.signer === null, unanchored, c.name);
    assert.equal(!("anchor" in c.bundle), unanchored, c.name);
  }
});

test("the report line prints the state and the result together", () => {
  assert.equal(verify(byName("valid_spawn_envelope")).envelopes.lines[String(SPAWN_SEQ)], "witness-signed (matched)");
  assert.equal(
    verify(byName("indeterminate_result")).envelopes.lines[String(SPAWN_SEQ)],
    "witness-signed (indeterminate)",
  );
  // A process-asserted entry gets no result.
  assert.equal(verify(byName("valid_spawn_envelope")).envelopes.lines["0"], PROCESS_ASSERTED);
});

// =============================================================================================
// Cross-language byte parity
// =============================================================================================

/** The published seed derivation the Python generator uses, recomputed here. */
function witnessSeed(name: string): Buffer {
  return createHash("sha256").update(Buffer.from(`attenu-guard-envelope-vectors-v1:${name}`, "utf8")).digest();
}

test("the witness keys derive to the same public keys the file carries", () => {
  const keys = byName("valid_spawn_envelope").witness_keys;
  const derived = ["witness-a", "witness-b"].map((n) =>
    Ed25519Signer.fromPrivateBytes(witnessSeed(n)).publicBytesRaw().toString("hex"),
  );
  assert.deepEqual(keys.map((k) => k.public_key_hex), derived);
});

test("signing the same entry with the same seed produces the same signature bytes", () => {
  // Ed25519 is deterministic (RFC 8032 derives the nonce from the key and the message), so this
  // is byte parity with the Python signer, not merely agreement on what verifies.
  const c = byName("valid_spawn_envelope");
  const built = signEnvelope(c.bundle.entries, SPAWN_SEQ, witnessSeed("witness-a"), "witness-interop-v1", {
    result: "matched",
    at: "2026-09-01T11:00:00Z",
    method: "sidecar:ledger-tail",
  });
  assert.deepEqual(built, c.bundle.envelopes![0]);
});

// =============================================================================================
// The envelope surface, at the sites no committed case reaches
// =============================================================================================

const BASE = byName("valid_spawn_envelope");
const SEED = witnessSeed("witness-a");
const KID = "witness-interop-v1";

function envelope(result: "matched" | "not_matched" | "indeterminate" = "matched"): Envelope {
  return signEnvelope(BASE.bundle.entries, SPAWN_SEQ, SEED, KID, {
    result,
    at: "2026-09-01T11:00:00Z",
    method: "sidecar:ledger-tail",
  });
}

function resign(e: Envelope): Envelope {
  const body: Record<string, CJson> = {};
  for (const [k, v] of Object.entries(e)) if (k !== "sig") body[k] = v as CJson;
  return { ...body, sig: Ed25519Signer.fromPrivateBytes(SEED, KID).sign(envelopeSigningInput(body)).toString("hex") } as unknown as Envelope;
}

function scored(envelopes: Envelope[], witnessKeys: unknown = BASE.witness_keys) {
  return verifyEnvelopes(
    { entries: BASE.bundle.entries, envelopes },
    { witnessKeys: witnessKeys as readonly WitnessKey[] | null },
  );
}

test("the third result reports its own line", () => {
  const report = scored([envelope("not_matched")]);
  assert.ok(report.ok);
  assert.equal(report.lines[String(SPAWN_SEQ)], "witness-signed (not_matched)");
});

test("a result outside the vocabulary cannot be signed", () => {
  assert.throws(() =>
    signEnvelope(BASE.bundle.entries, SPAWN_SEQ, SEED, KID, {
      result: "probably" as "matched",
      at: "x",
      method: "y",
    }),
  );
});

test("an allow subject carries call_id and a spawn subject does not", () => {
  const allow = envelopeSubject(BASE.bundle.entries, ALLOW_SEQ);
  const spawn = envelopeSubject(BASE.bundle.entries, SPAWN_SEQ);
  assert.deepEqual(Object.keys(allow).sort(), [...ENVELOPE_SUBJECT_MEMBERS.get("allow")!].sort());
  assert.deepEqual(Object.keys(spawn).sort(), [...ENVELOPE_SUBJECT_MEMBERS.get("spawn")!].sort());
  assert.equal(allow["call_id"], BASE.bundle.entries[ALLOW_SEQ]!["call_id"]);
});

test("v1 defines no subject for any other event", () => {
  for (const seq of [0, 3]) {
    assert.throws(() => envelopeSubject(BASE.bundle.entries, seq), Error, `seq ${seq}`);
  }
});

test("an envelope naming an event v1 has no subject for is a subject mismatch", () => {
  const e = envelope();
  e.subject["event"] = "outcome";
  assert.deepEqual(scored([resign(e)]).failure_details.map((d) => d.reason), ["envelope_subject_mismatch"]);
});

test("a subject missing a required member is a subject mismatch", () => {
  const e = envelope();
  delete e.subject["chain_id"];
  const report = scored([resign(e)]);
  assert.deepEqual(report.failure_details.map((d) => d.reason), ["envelope_subject_mismatch"]);
  assert.equal(report.failure_details[0]!.seq, SPAWN_SEQ);
});

test("a member added outside the subject is also unknown_member", () => {
  for (const where of ["envelope", "observed", "witness"] as const) {
    const e = envelope();
    const target = where === "envelope" ? (e as unknown as Record<string, CJson>) : (e[where] as Record<string, CJson>);
    target["note"] = "extra";
    assert.deepEqual(scored([resign(e)]).failure_details.map((d) => d.reason), ["envelope_unknown_member"], where);
  }
});

test("a different typ is an unknown version", () => {
  const e = envelope();
  e.typ = `${ENVELOPE_TYP}-v2`;
  assert.deepEqual(scored([resign(e)]).failure_details.map((d) => d.reason), ["envelope_unknown_version"]);
});

test("a subject naming a seq this bundle has no entry for", () => {
  const e = envelope();
  e.subject["seq"] = 99;
  const detail = scored([resign(e)]).failure_details[0]!;
  assert.equal(detail.reason, "envelope_subject_mismatch");
  assert.deepEqual([detail.seq, detail.node], [99, null]);
});

test("no trust set is an empty one rather than a skipped check", () => {
  assert.deepEqual(scored([envelope()], null).failure_details.map((d) => d.reason), ["envelope_unknown_witness"]);
});

test("a trust set may be given as a plain kid-to-key record", () => {
  const keys = { [KID]: Ed25519Signer.fromPrivateBytes(SEED).publicBytesRaw() };
  assert.ok(
    verifyEnvelopes({ entries: BASE.bundle.entries, envelopes: [envelope()] }, { witnessKeys: keys }).ok,
  );
});

test("a bundle with no envelopes reports every entry process-asserted", () => {
  const report = scored([]);
  assert.ok(report.ok);
  assert.deepEqual(new Set(Object.values(report.states)), new Set([PROCESS_ASSERTED]));
  assert.deepEqual(report.witness_signed, []);
});

test("exportBundle omits the envelopes member when there are none", () => {
  const signer = new HS256TestSigner(Buffer.from("k", "utf8"), "k");
  const guard = Guard.issue("a", new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(1)], ttl: 60 }), {
    chainId: "t",
  });
  guard.check("crm.read");
  assert.equal("envelopes" in exportBundle(guard.auditLog(), signer), false);
  const withEnvelope = exportBundle(guard.auditLog(), signer, { envelopes: [envelope()] });
  assert.deepEqual(withEnvelope.envelopes, [envelope()]);
});

// ---- one entry, at most one envelope (v1.1) -------------------------------------------------

test("a second envelope over a covered entry is a duplicate subject", () => {
  // The committed row scores the two-valid-envelopes case; this pins the surface it reports
  // through, including that the first witness's result survives in `results`.
  const report = scored([envelope(), envelope("not_matched")]);
  assert.equal(report.ok, false);
  assert.deepEqual(report.failure_details.map((d) => d.reason), ["envelope_duplicate_subject"]);
  const detail = report.failure_details[0]!;
  assert.deepEqual([detail.seq, detail.node], [SPAWN_SEQ, BASE.bundle.entries[SPAWN_SEQ]!["node"]]);
  assert.equal(report.states[String(SPAWN_SEQ)], PROCESS_ASSERTED);
  assert.deepEqual(report.witness_signed, []);
  assert.equal(report.lines[String(SPAWN_SEQ)], PROCESS_ASSERTED);
  assert.equal(report.results[String(SPAWN_SEQ)], "matched");
});

test("the duplicate rule makes the score independent of array order", () => {
  // The defect this rule closes: with the states keyed by seq and overwritten per envelope, the
  // SAME two envelopes in the other order reported the other result and no failure at all.
  const first = envelope();
  const second = envelope("not_matched");
  for (const envelopes of [[first, second], [second, first]]) {
    const report = scored(envelopes);
    assert.equal(report.ok, false);
    assert.deepEqual(report.failure_details.map((d) => d.reason), ["envelope_duplicate_subject"]);
    assert.equal(report.states[String(SPAWN_SEQ)], PROCESS_ASSERTED);
  }
});

test("an entry claimed by a broken envelope is claimed", () => {
  // "Valid or not": the FIRST envelope names seq 1 and fails on its own subject, so a later
  // honest one over the same entry is still the second observation of it.
  const broken = JSON.parse(JSON.stringify(envelope())) as Envelope;
  broken.subject["entry_hash"] = "0".repeat(64);
  const report = scored([resign(broken), envelope()]);
  assert.equal(report.ok, false);
  assert.deepEqual(report.failure_details.map((d) => d.reason), [
    "envelope_subject_mismatch",
    "envelope_duplicate_subject",
  ]);
  assert.equal(report.states[String(SPAWN_SEQ)], PROCESS_ASSERTED);
});

test("envelopes over different entries are not duplicates", () => {
  const allow = signEnvelope(BASE.bundle.entries, ALLOW_SEQ, SEED, KID, {
    result: "matched",
    at: "2026-09-01T11:00:00Z",
    method: "sidecar:ledger-tail",
  });
  const report = scored([envelope(), allow]);
  assert.ok(report.ok, report.failures.join(" | "));
  assert.deepEqual(report.witness_signed, [SPAWN_SEQ, ALLOW_SEQ]);
});

test("a duplicate naming a seq this bundle has no entry for is not a duplicate", () => {
  // An entry is claimed only once `subject.seq` FINDS one.
  const stray = JSON.parse(JSON.stringify(envelope())) as Envelope;
  stray.subject["seq"] = 99;
  const report = scored([resign(stray), resign(JSON.parse(JSON.stringify(stray)) as Envelope)]);
  assert.deepEqual(report.failure_details.map((d) => d.reason), [
    "envelope_subject_mismatch",
    "envelope_subject_mismatch",
  ]);
});

test("exportBundle refuses to redact and carry envelopes in one call", () => {
  // Redaction rewrites every entry hash, so envelopes signed over the unredacted ledger would
  // ship bound to entries that no longer exist and fail envelope_subject_mismatch.
  const signer = new HS256TestSigner(Buffer.from("k", "utf8"), "k");
  const guard = Guard.issue("a", new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(1)], ttl: 60 }), {
    chainId: "t",
  });
  guard.delegate("b", new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(1)], ttl: 30 }), "secret prompt");
  const redacted = exportBundle(guard.auditLog(), signer, { redactTask: true });
  const witness = signEnvelope(redacted.entries, 1, SEED, KID, {
    result: "matched",
    at: "2026-09-01T11:00:00Z",
    method: "sidecar:ledger-tail",
  });
  assert.throws(
    () => exportBundle(guard.auditLog(), signer, { redactTask: true, envelopes: [witness] }),
    /sign envelopes over the redacted ledger/,
  );
  // The documented order works: export redacted, sign over ITS entries, export again.
  const bundle = exportBundle(guard.auditLog(), signer, { redactTask: true });
  bundle.envelopes = [witness];
  const keys = { [KID]: Ed25519Signer.fromPrivateBytes(SEED).publicBytesRaw() };
  const report = verifyEnvelopes(bundle, { witnessKeys: keys });
  assert.ok(report.ok, report.failures.join(" | "));
  assert.deepEqual(report.witness_signed, [1]);
});

test("the envelope version and typ constants match the contract", () => {
  assert.equal(ENVELOPE_VERSION, 1);
  assert.equal(ENVELOPE_TYP, "delegation-event-observation");
  assert.equal(ENVELOPE_ALG, "EdDSA");
});

// =============================================================================================
// Hostile bundle content: verifyBundle reports, it never throws
// =============================================================================================
//
// A bundle is attacker-supplied. Every envelope member is therefore an untrusted JSON value of
// ANY type, and the one thing a verifier may never do with one is throw: a caller that has to
// wrap `verifyBundle` in try/catch cannot tell a rejected bundle from a crashed verifier, and a
// crash on a malformed bundle is a denial of service against whoever is checking it. Python
// raised on five of these; TypeScript's Map lookups do not throw but MIS-FIND, which is worse.
// Both now report the same reason at the same position for the same value.

/** JSON values a parser yields and the scorer must survive. */
const HOSTILE: Json[] = [
  { a: 1 } as unknown as Json,
  [1] as unknown as Json,
  true,
  false,
  null,
  1.5,
  -1,
  0,
  "",
  "zz",
  "0".repeat(63),
  Number.MAX_SAFE_INTEGER + 2,
];

/** Every member of the envelope, at every level v1 defines. */
const MEMBER_PATHS: string[][] = [
  ["v"], ["typ"], ["sig"], ["subject"], ["observed"], ["witness"],
  ["subject", "chain_id"], ["subject", "node"], ["subject", "seq"],
  ["subject", "entry_hash"], ["subject", "event"],
  ["observed", "result"], ["observed", "at"], ["observed", "method"],
  ["witness", "kid"], ["witness", "alg"],
];

function mutated(path: string[], value: Json): Bundle {
  const bundle = JSON.parse(JSON.stringify(BASE.bundle)) as Bundle;
  const envelope = bundle.envelopes![0]! as unknown as Record<string, unknown>;
  let target = envelope;
  for (const member of path.slice(0, -1)) target = target[member] as Record<string, unknown>;
  target[path[path.length - 1]!] = value;
  return bundle;
}

test("no hostile value in any envelope member makes verifyBundle throw", () => {
  const signer = signerFor(BASE);
  const honest = canonicalBytes(BASE.bundle.envelopes![0]! as unknown as CJson);
  const rawVariants: (readonly (Buffer | string | null)[] | null)[] = [
    null, [honest], ["zz"], [null],
  ];
  const allowed = new Set<string>([...ENVELOPE_FAILURES, "integrity(anchor)"]);
  for (const path of MEMBER_PATHS) {
    for (const value of HOSTILE) {
      for (const envelopeBytes of rawVariants) {
        const label = `${path.join(".")}=${JSON.stringify(value) ?? "undefined"}`;
        const report = verifyBundle(mutated(path, value), signer, {
          witnessKeys: BASE.witness_keys,
          envelopeBytes,
        });
        // Every mutation moves the envelope away from the bytes the witness signed, so every one
        // must reject — surviving is not the same as being accepted.
        assert.equal(report.ok, false, label);
        assert.ok(report.failures.length > 0, label);
        for (const d of report.failure_details) assert.ok(allowed.has(d.reason), `${label}: ${d.reason}`);
      }
    }
  }
});

test("a subject seq that is not an integer is a mismatch positioned nowhere", () => {
  // `seq` is the one subject member used as a lookup KEY. Python raised on an unhashable one and
  // found the entry at seq 1 for `true`; a JS Map silently finds nothing and then reports at the
  // wrong position. The guard makes both say the same thing.
  for (const value of [{ a: 1 } as unknown as Json, [1] as unknown as Json, true, false, 1.5, "1", null]) {
    const report = verifyEnvelopes(mutated(["subject", "seq"], value), {
      witnessKeys: BASE.witness_keys,
    });
    const detail = report.failure_details[0]!;
    assert.equal(detail.reason, "envelope_subject_mismatch", JSON.stringify(value));
    assert.deepEqual([detail.seq, detail.node], [null, null], JSON.stringify(value));
    assert.match(detail.detail, /subject seq is not an integer/);
  }
});

test("a subject event that is not a string is a subject mismatch", () => {
  for (const value of [{ a: 1 } as unknown as Json, [1] as unknown as Json, true, 5, null]) {
    const report = verifyEnvelopes(mutated(["subject", "event"], value), {
      witnessKeys: BASE.witness_keys,
    });
    assert.equal(report.failure_details[0]!.reason, "envelope_subject_mismatch");
    assert.match(report.failure_details[0]!.detail, /subject event is not a string/);
  }
});

test("a witness kid that is not a string is an unknown witness", () => {
  for (const value of [{ a: 1 } as unknown as Json, [1] as unknown as Json, 5, null, true]) {
    const report = verifyEnvelopes(mutated(["witness", "kid"], value), {
      witnessKeys: BASE.witness_keys,
    });
    const detail = report.failure_details[0]!;
    assert.equal(detail.reason, "envelope_unknown_witness");
    assert.match(detail.detail, /witness kid is not a string/);
  }
});

test("a sig that is not a string is a bad signature", () => {
  for (const value of [12345, true, ["ab"] as unknown as Json, { a: 1 } as unknown as Json, 0, false, null]) {
    const report = verifyEnvelopes(mutated(["sig"], value), { witnessKeys: BASE.witness_keys });
    const detail = report.failure_details[0]!;
    assert.equal(detail.reason, "envelope_bad_signature", JSON.stringify(value));
    assert.match(detail.detail, /sig is not a hex string/);
  }
});

// =============================================================================================
// witness.alg, and the trust set as caller configuration
// =============================================================================================

function withAlg(alg: Json): Bundle {
  const bundle = JSON.parse(JSON.stringify(BASE.bundle)) as Bundle;
  const e = bundle.envelopes![0]! as unknown as Record<string, unknown>;
  (e["witness"] as Record<string, unknown>)["alg"] = alg;
  bundle.envelopes = [resign(e as unknown as Envelope)];
  return bundle;
}

test("an alg other than EdDSA is an unknown witness", () => {
  // "none" is the row the corpus pins; HS256 is the other shape of the same hole — it reached
  // the Ed25519 verifier and was reported as a SIGNATURE failure, naming the wrong cause.
  for (const alg of ["none", "HS256", "ES256", "", null, 1] as Json[]) {
    const report = verifyEnvelopes(withAlg(alg), { witnessKeys: BASE.witness_keys });
    const detail = report.failure_details[0]!;
    assert.equal(detail.reason, "envelope_unknown_witness", JSON.stringify(alg));
    assert.match(detail.detail, /is not 'EdDSA'/);
  }
});

test("a trust set row naming another algorithm is refused", () => {
  // The other half: "none" on BOTH sides used to agree with itself and verify. It cannot even
  // be configured now.
  const rows = BASE.witness_keys.map((k) => ({ ...k }));
  rows[0]!.alg = "none";
  assert.throws(() => verifyEnvelopes(BASE.bundle, { witnessKeys: rows }), /witness-interop-v1.*EdDSA/s);
});

test("a trust set key that is not a key is refused and names the kid", () => {
  // A number coerced to bytes would fabricate zero bytes, and every envelope from that witness
  // would then fail on its signature — a misconfiguration read as a bad witness.
  const bad: unknown[] = [32, Buffer.from("short"), "zz".repeat(32), "aa".repeat(31), null];
  for (const value of bad) {
    assert.throws(
      () => verifyEnvelopes(BASE.bundle, { witnessKeys: { [KID]: value } as never }),
      new RegExp(KID),
      String(value),
    );
  }
  assert.throws(() => verifyEnvelopes(BASE.bundle, { witnessKeys: [{ kid: 5 }] as never }), /kid must be a string/);
});

test("a list row with a bad public key is refused and names the kid", () => {
  for (const bad of ["zz".repeat(32), "aa".repeat(31), "", null, 32]) {
    const rows = BASE.witness_keys.map((k) => ({ ...k })) as unknown as Record<string, unknown>[];
    rows[0]!["public_key_hex"] = bad;
    assert.throws(() => verifyEnvelopes(BASE.bundle, { witnessKeys: rows as never }), new RegExp(KID));
  }
});

test("a well formed trust set still verifies in both forms", () => {
  // The validation must not have narrowed what a correct caller may pass.
  const publicKey = Ed25519Signer.fromPrivateBytes(SEED).publicBytesRaw();
  const forms: (readonly WitnessKey[] | Record<string, Buffer | string>)[] = [
    BASE.witness_keys,
    { [KID]: publicKey },
    { [KID]: publicKey.toString("hex") },
  ];
  for (const witnessKeys of forms) {
    assert.ok(verifyEnvelopes(BASE.bundle, { witnessKeys }).ok);
  }
});

test("envelope bytes that are not hex or bytes are reported, not coerced", () => {
  for (const raw of [12345, ["ab"], { a: 1 }, "zz", "abc", 0.5]) {
    const report = verifyEnvelopes(BASE.bundle, {
      witnessKeys: BASE.witness_keys,
      envelopeBytes: [raw as never],
    });
    const detail = report.failure_details[0]!;
    assert.equal(detail.reason, "envelope_non_canonical", String(raw));
    assert.match(detail.detail, /envelope_bytes entry is not hex or bytes/);
  }
});

test("the received bytes still verify when they are hex or bytes", () => {
  const honest = canonicalBytes(BASE.bundle.envelopes![0]! as unknown as CJson);
  for (const raw of [honest, honest.toString("hex"), new Uint8Array(honest)]) {
    assert.ok(
      verifyEnvelopes(BASE.bundle, {
        witnessKeys: BASE.witness_keys,
        envelopeBytes: [raw as never],
      }).ok,
    );
  }
});

test("pyRepr renders hostile values the way Python's repr does", () => {
  // The two implementations report the same failure strings, and a JSON spelling of a container
  // or a boolean would not match. These are the exact strings Python produced for the same
  // envelopes: `witness alg=<repr> is not 'EdDSA'`.
  const expected: [Json, string][] = [
    [true, "True"],
    [false, "False"],
    [null, "None"],
    [1, "1"],
    ["none", "'none'"],
    [{ a: 1 } as unknown as Json, "{'a': 1}"],
    [[1, "x"] as unknown as Json, "[1, 'x']"],
  ];
  for (const [value, repr] of expected) {
    const report = verifyEnvelopes(withAlg(value), { witnessKeys: BASE.witness_keys });
    assert.equal(
      report.failure_details[0]!.detail,
      `envelope_unknown_witness: witness alg=${repr} is not 'EdDSA'; envelope v1 defines ` +
        "Ed25519 and no other algorithm",
    );
  }
});

test("the scorer reports exactly the seven declared envelope failures", () => {
  // The TypeScript half of the Python anti-drift guard: the reasons are read out of
  // `scoreEnvelope`'s own body rather than taken from the tuple that names them, so a reason
  // added to one implementation and not the other cannot pass unnoticed in either direction.
  const source = readFileSync(resolve(REPO_ROOT, "src", "evidence.ts"), "utf8");
  const body = source.split("\nfunction scoreEnvelope(")[1]!.split("\nfunction ")[0]!;
  const found = new Set([...body.matchAll(/(?:report|fail\.add)\(\s*"([^"]+)"/g)].map((m) => m[1]!));
  assert.ok(found.size > 0, "no reason literals found in scoreEnvelope");
  assert.deepEqual([...found].sort(), [...ENVELOPE_FAILURES].sort());
});
