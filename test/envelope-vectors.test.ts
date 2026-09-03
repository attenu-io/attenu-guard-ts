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
import { fixturePath, fixtureText } from "./helpers.js";

const VECTOR_FILE = "vectors/envelopes/envelope_vectors_v1.json";

/**
 * The sha256 of the vendored file. It pins WHICH bytes this suite scored, the way an independent
 * run pins the corpus it ran. It moves only when a case is appended, which also moves `revision`.
 */
const VECTOR_SHA256 = "952fa1b4e33f13d8e0f205773300785e33f64017416845ee21e71934b10dbb85";

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
  assert.equal(DOCUMENT.revision, "envelope_vectors_v1.0");
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

test("each of the six named envelope failures is required by a row", () => {
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

test("two envelopes on the same entry both have to verify", () => {
  const good = envelope();
  const broken = JSON.parse(JSON.stringify(good)) as Envelope;
  broken.subject["entry_hash"] = "0".repeat(64);
  const report = scored([good, resign(broken)]);
  assert.equal(report.ok, false);
  // The good one still puts the entry in witness-signed; the broken one is still reported.
  assert.equal(report.states[String(SPAWN_SEQ)], WITNESS_SIGNED);
  assert.deepEqual(report.failure_details.map((d) => d.reason), ["envelope_subject_mismatch"]);
});

test("the envelope version and typ constants match the contract", () => {
  assert.equal(ENVELOPE_VERSION, 1);
  assert.equal(ENVELOPE_TYP, "delegation-event-observation");
  assert.equal(ENVELOPE_ALG, "EdDSA");
});
