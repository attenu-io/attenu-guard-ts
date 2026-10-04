/**
 * `not_after` on a trust-set row (attenu-io/attenu-guard#22), and the witness the envelope
 * summary names for each witness-signed entry.
 *
 * A `witnessKeys` row may carry `not_after`, an RFC 3339 date-time in UTC. A row whose
 * `not_after` is at or before the verification time is left out of the trust set, so an envelope
 * naming its kid fails `envelope_unknown_witness` — the existing reason — with a message that says
 * the key expired and when. A malformed `not_after` throws, naming the kid, as every other bad row
 * does: the trust set is the caller's configuration, not bundle content. A row without it is
 * trusted exactly as before.
 *
 * Scored against the vendored envelope corpus, so the bundle here is the one every implementation
 * scores. The rows are copied, never edited in place.
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  PROCESS_ASSERTED,
  WITNESS_SIGNED,
  verifyBundle,
  verifyEnvelopes,
  type Bundle,
  type WitnessKey,
} from "../src/evidence.js";
import { HS256TestSigner } from "../src/wire.js";
import { fixtureText } from "./helpers.js";

interface VectorCase {
  name: string;
  signer: { alg: string; kid: string; secret_hex: string } | null;
  witness_keys: WitnessKey[];
  bundle: Bundle;
  raw_hex?: string;
}

const CASES = (JSON.parse(fixtureText("vectors/envelopes/envelope_vectors_v1.json")) as { cases: VectorCase[] }).cases;
const BASE = CASES.find((c) => c.name === "valid_spawn_envelope")!;
const SIGNER = new HS256TestSigner(Buffer.from(BASE.signer!.secret_hex, "hex"), BASE.signer!.kid);

/** The entry the corpus's envelope covers, and the kid it names. The other row stays valid. */
const SPAWN_SEQ = 1;
const SPAWN_NODE = "vectors:n1";
const KID = "witness-interop-v1";
const OTHER = "witness-interop-v1-b";

const NOW = new Date("2026-10-04T12:00:00.000Z");

/** The corpus trust set, with `not_after` set on the row named `kid`. */
function keys(notAfter: unknown, kid: string = KID): WitnessKey[] {
  return BASE.witness_keys.map((row) => (row.kid === kid ? ({ ...row, not_after: notAfter } as WitnessKey) : row));
}

function verifyAt(witnessKeys: WitnessKey[], now: Date | string | number | undefined = NOW) {
  return verifyBundle(BASE.bundle, SIGNER, { witnessKeys, now });
}

/** The failure an expired row's envelope gets: the unknown-witness wording, then the expiry. */
function expiredLine(notAfter: string): string {
  return (
    `envelope_unknown_witness: witness kid='${KID}' alg='EdDSA' is not in the trusted witness keys ` +
    `(['${OTHER}']): the key expired at not_after='${notAfter}'`
  );
}

function malformed(kid: string, repr: string): { message: string } {
  return {
    message:
      `witness key '${kid}': not_after must be an RFC 3339 UTC date-time such as ` +
      `'2026-10-05T00:00:00Z', got ${repr}`,
  };
}

function assertTrusted(report: ReturnType<typeof verifyAt>, label: string): void {
  assert.equal(report.ok, true, `${label}: ${report.failures.join("; ")}`);
  assert.equal(report.envelopes.states[String(SPAWN_SEQ)], WITNESS_SIGNED, label);
  assert.equal(report.envelopes.witnesses[String(SPAWN_SEQ)], KID, label);
}

function assertExpired(report: ReturnType<typeof verifyAt>, notAfter: string, label: string): void {
  assert.equal(report.ok, false, label);
  assert.deepEqual(report.failures, [expiredLine(notAfter)], label);
  assert.deepEqual(
    report.failure_details.map((d) => [d.reason, d.seq, d.node, d.call_id]),
    [["envelope_unknown_witness", SPAWN_SEQ, SPAWN_NODE, null]],
    label,
  );
  assert.equal(report.envelopes.states[String(SPAWN_SEQ)], PROCESS_ASSERTED, label);
  assert.deepEqual(report.envelopes.witnesses, {}, label);
  assert.equal(report.checks.envelopes, "FAILED", label);
  // The ledger is untouched: only the envelope layer moved.
  assert.equal(report.checks.integrity && report.checks.monotonicity && report.checks.containment, true, label);
}

test("a row without not_after is trusted exactly as before", () => {
  assertTrusted(verifyAt(BASE.witness_keys), "no not_after");
  assertTrusted(verifyAt(BASE.witness_keys, undefined), "no not_after, no now");
});

test("a row whose not_after is after the verification time is trusted", () => {
  assertTrusted(verifyAt(keys("2026-10-04T12:00:00.001Z")), "one millisecond after");
  assertTrusted(verifyAt(keys("2027-01-01T00:00:00Z")), "next year");
});

test("a row whose not_after is before the verification time is left out of the trust set", () => {
  assertExpired(verifyAt(keys("2026-10-01T00:00:00Z")), "2026-10-01T00:00:00Z", "three days before");
});

test("not_after equal to the verification time has expired: at or before, not only before", () => {
  assertExpired(verifyAt(keys("2026-10-04T12:00:00Z")), "2026-10-04T12:00:00Z", "equal");
});

test("the fraction is kept to the microsecond, as Python keeps it", () => {
  assertTrusted(verifyAt(keys("2026-10-04T12:00:00.000001Z")), "one microsecond after");
  // 900 ns after, but the digits past the microsecond are dropped: equal, so expired.
  assertExpired(verifyAt(keys("2026-10-04T12:00:00.0000009Z")), "2026-10-04T12:00:00.0000009Z", "sub-microsecond");
});

test("now may be a string in the not_after grammar, compared to the microsecond", () => {
  assertExpired(
    verifyAt(keys("2026-10-04T12:00:00.000001Z"), "2026-10-04T12:00:00.000001Z"),
    "2026-10-04T12:00:00.000001Z",
    "equal to the microsecond",
  );
  assertTrusted(verifyAt(keys("2026-10-04T12:00:00.000002Z"), "2026-10-04T12:00:00.000001Z"), "one microsecond later");
  assert.throws(
    () => verifyAt(keys("2027-01-01T00:00:00Z"), "tomorrow"),
    /now must be a valid Date, an RFC 3339 UTC date-time .* or seconds since the epoch; got 'tomorrow'/,
  );
});

test("t and z may be lower case, and the message repeats not_after as the row wrote it", () => {
  assertTrusted(verifyAt(keys("2026-10-05t00:00:00z")), "lower case, after");
  assertExpired(verifyAt(keys("2026-10-04t11:59:59.5z")), "2026-10-04t11:59:59.5z", "lower case, before");
});

test("without now, the verification time is the current time", () => {
  assertExpired(verifyAt(keys("2000-01-01T00:00:00Z"), undefined), "2000-01-01T00:00:00Z", "long past");
  assertTrusted(verifyAt(keys("9999-12-31T23:59:59Z"), undefined), "far future");
});

test("a leap day and a year below 100 are real dates", () => {
  // `Date.UTC` would read year 50 as 1950; this year is 50, and it is long past.
  assertExpired(verifyAt(keys("0050-01-01T00:00:00Z")), "0050-01-01T00:00:00Z", "year 50");
  assertExpired(verifyAt(keys("2024-02-29T23:59:59Z")), "2024-02-29T23:59:59Z", "leap day");
});

test("an expired row neither adds nor removes a kid another row trusts", () => {
  const valid = BASE.witness_keys.find((row) => row.kid === KID)!;
  const expired = { ...valid, not_after: "2026-01-01T00:00:00Z" };
  assertTrusted(verifyAt([expired, valid]), "expired row first");
  assertTrusted(verifyAt([valid, expired]), "expired row last");
});

test("an expired row for a kid no envelope names changes nothing", () => {
  assertTrusted(verifyAt(keys("2026-01-01T00:00:00Z", OTHER)), "the other row expired");
});

test("a malformed not_after throws, naming the kid", () => {
  const cases: [unknown, string][] = [
    ["2026-10-04", "'2026-10-04'"],
    ["2026-10-04T12:00:00", "'2026-10-04T12:00:00'"],
    // A numeric offset is refused, even the one that means UTC.
    ["2026-10-04T12:00:00+00:00", "'2026-10-04T12:00:00+00:00'"],
    ["2026-10-04T12:00:00+02:00", "'2026-10-04T12:00:00+02:00'"],
    ["2026-10-04T12:00:00-00:00", "'2026-10-04T12:00:00-00:00'"],
    ["2026-10-04 12:00:00Z", "'2026-10-04 12:00:00Z'"],
    ["2026-10-04T12:00:00.Z", "'2026-10-04T12:00:00.Z'"],
    // ASCII digits only: fullwidth digits are digits to Python's `\d` and `int`, never here.
    ["\uff12\uff10\uff12\uff16-10-04T12:00:00Z", "'\uff12\uff10\uff12\uff16-10-04T12:00:00Z'"],
    ["2026-02-29T00:00:00Z", "'2026-02-29T00:00:00Z'"],
    ["2026-13-01T00:00:00Z", "'2026-13-01T00:00:00Z'"],
    ["2026-10-04T24:00:00Z", "'2026-10-04T24:00:00Z'"],
    ["2026-10-04T12:60:00Z", "'2026-10-04T12:60:00Z'"],
    ["2026-10-04T12:00:60Z", "'2026-10-04T12:00:60Z'"],
    ["0000-01-01T00:00:00Z", "'0000-01-01T00:00:00Z'"],
    ["", "''"],
    [null, "None"],
    [true, "True"],
    [1759579200, "1759579200"],
  ];
  for (const [value, repr] of cases) {
    assert.throws(() => verifyAt(keys(value)), malformed(KID, repr), String(value));
  }
});

test("a malformed not_after throws on a row no envelope names, too", () => {
  assert.throws(() => verifyAt(keys("soon", OTHER)), malformed(OTHER, "'soon'"));
});

test("a row is checked in Python's order: alg, then not_after, then the public key", () => {
  const row = BASE.witness_keys[0]!;
  assert.throws(() => verifyAt([{ ...row, alg: "none", not_after: "garbage" } as WitnessKey]), /alg must be 'EdDSA'/);
  assert.throws(
    () => verifyAt([{ ...row, public_key_hex: "00", not_after: "garbage" } as WitnessKey]),
    malformed(row.kid, "'garbage'"),
  );
  assert.throws(
    () => verifyAt([{ ...row, public_key_hex: "00", not_after: "2000-01-01T00:00:00Z" } as WitnessKey]),
    /public_key_hex must be 64 hex characters/,
    "an expired row is still a row: expiry never excuses a bad key",
  );
});

test("verifyEnvelopes takes the verification time too", () => {
  const report = verifyEnvelopes(BASE.bundle, { witnessKeys: keys("2026-10-01T00:00:00Z"), now: NOW });
  assert.equal(report.ok, false);
  assert.deepEqual(report.failures, [expiredLine("2026-10-01T00:00:00Z")]);
  assert.equal(report.states[String(SPAWN_SEQ)], PROCESS_ASSERTED);
  const current = verifyEnvelopes(BASE.bundle, { witnessKeys: keys("2027-01-01T00:00:00Z"), now: NOW });
  assert.equal(current.ok, true);
  assert.equal(current.states[String(SPAWN_SEQ)], WITNESS_SIGNED);
});

/** 2026-10-04T12:00:00Z in seconds since the epoch, as Python's `datetime(...).timestamp()` gives it. */
const NOW_SECONDS = 1791115200;

test("now may be seconds since the epoch, read as Python's datetime.fromtimestamp reads them", () => {
  assert.equal(NOW_SECONDS, NOW.getTime() / 1000);
  assertExpired(verifyAt(keys("2026-10-04T12:00:00Z"), NOW_SECONDS), "2026-10-04T12:00:00Z", "equal");
  assertTrusted(verifyAt(keys("2026-10-04T12:00:00.000001Z"), NOW_SECONDS), "one microsecond after");
  // The fraction is rounded half-even to the microsecond. Python gives .007812 for .0078125 (a
  // tie, kept even) and .023438 for .0234375 (a tie, rounded up to even); half-up would not.
  assertExpired(verifyAt(keys("2026-10-04T12:00:00.007812Z"), NOW_SECONDS + 0.0078125), "2026-10-04T12:00:00.007812Z", "tie down");
  assertTrusted(verifyAt(keys("2026-10-04T12:00:00.007813Z"), NOW_SECONDS + 0.0078125), "tie down, one after");
  assertExpired(verifyAt(keys("2026-10-04T12:00:00.023438Z"), NOW_SECONDS + 0.0234375), "2026-10-04T12:00:00.023438Z", "tie up");
  assertTrusted(verifyAt(keys("2026-10-04T12:00:00.023439Z"), NOW_SECONDS + 0.0234375), "tie up, one after");
  // The earliest time Python's datetime holds is accepted; anything before it is not.
  assertExpired(verifyAt(keys("0001-01-01T00:00:00Z"), -62135596800), "0001-01-01T00:00:00Z", "year 1");
});

test("an invalid now is refused rather than read as some time", () => {
  assert.throws(() => verifyAt(keys("2027-01-01T00:00:00Z"), new Date(Number.NaN)), /got an invalid Date/);
  assert.throws(() => verifyAt(keys("2027-01-01T00:00:00Z"), true as never), /seconds since the epoch; got True/);
  // A JavaScript millisecond epoch is tens of millennia ahead in seconds, past what Python's
  // datetime holds, and both implementations refuse it rather than read it as some time.
  for (const bad of [Date.now(), 1.76e12, -62135596800.5, 253402300799.9999999, Number.NaN, Infinity]) {
    assert.throws(
      () => verifyAt(keys("2027-01-01T00:00:00Z"), bad),
      /is not a representable time in seconds since the epoch/,
      String(bad),
    );
  }
});

test("witnesses names a kid exactly where results names a result, on every corpus case", () => {
  for (const c of CASES) {
    const signer = c.signer === null ? null : new HS256TestSigner(Buffer.from(c.signer.secret_hex, "hex"), c.signer.kid);
    const report = verifyBundle(c.bundle, signer, {
      witnessKeys: c.witness_keys,
      envelopeBytes: c.raw_hex === undefined ? null : [Buffer.from(c.raw_hex, "hex")],
    });
    const { results, witnesses } = report.envelopes;
    assert.deepEqual(Object.keys(witnesses).sort(), Object.keys(results).sort(), c.name);
    for (const seq of Object.keys(witnesses)) {
      const named = (c.bundle.envelopes ?? []).some(
        (e) => e.subject?.["seq"] === Number(seq) && e.witness?.["kid"] === witnesses[seq],
      );
      assert.ok(named, `${c.name}: seq ${seq} names a kid an envelope over it carries`);
    }
  }
  assert.deepEqual(verifyAt(BASE.witness_keys).envelopes.witnesses, { [String(SPAWN_SEQ)]: KID });
});
