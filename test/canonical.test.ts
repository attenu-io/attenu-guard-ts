/** RFC 8785 JCS is the one canonical form used by every signed/hashed surface. */

import assert from "node:assert/strict";
import test from "node:test";

import {
  DuplicateMemberError,
  LoneSurrogateError,
  MAX_SAFE_INTEGER,
  NonFiniteNumberError,
  RawNumber,
  UnsafeIntegerError,
  UnsupportedTypeError,
  canonicalJson,
  parseJson,
  toPlain,
} from "../src/canonical.js";
import { fixtureJson } from "./helpers.js";

interface CanonicalVector {
  source: string;
  canonical: string;
}

const vectors = fixtureJson<CanonicalVector[]>("canonical_vectors.json");

test("every Python-written document re-serialises to its RFC 8785 bytes", () => {
  assert.ok(vectors.length > 0, "fixtures are present");
  for (const v of vectors) {
    assert.equal(canonicalJson(parseJson(v.source)), v.canonical, `source: ${v.source}`);
  }
});

test("toPlain strips RawNumber wrappers", () => {
  const parsed = parseJson('{"a":1,"b":[2.5,{"c":100}]}');
  assert.deepEqual(toPlain(parsed), { a: 1, b: [2.5, { c: 100 }] });
  const raw = (parsed as any).b[1].c as RawNumber;
  assert.ok(raw instanceof RawNumber);
  assert.equal(raw.raw, "100");
  assert.equal(raw.value, 100);
});

test("JCS uses ECMAScript number spelling and rejects non-finite values", () => {
  // 1e16 and 1e21 (large-magnitude integral values) moved out of this case: they
  // are now rejected as unsafe integers rather than rendered — see the
  // dedicated "unsafe integers" tests below. 9e15 stays inside the safe range
  // and still demonstrates the plain-decimal (non-exponential) rendering.
  assert.equal(
    canonicalJson([100.0, -0, 1e-6, 1e-7, 9e15]),
    "[100,0,0.000001,1e-7,9000000000000000]",
  );
  for (const value of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonicalJson(value), NonFiniteNumberError);
  }
  assert.throws(() => parseJson("1e400"), NonFiniteNumberError);
  assert.throws(() => parseJson("NaN"), NonFiniteNumberError);
});

test("unsafe integers are rejected instead of silently colliding", () => {
  // The boundary: the largest safe integer round-trips exactly; one past it throws.
  assert.equal(canonicalJson(MAX_SAFE_INTEGER), String(MAX_SAFE_INTEGER));
  assert.equal(canonicalJson(-MAX_SAFE_INTEGER), String(-MAX_SAFE_INTEGER));
  for (const value of [MAX_SAFE_INTEGER + 1, -(MAX_SAFE_INTEGER + 1)]) {
    assert.throws(() => canonicalJson(value), UnsafeIntegerError);
  }
  // The collision this closes: 2**53 and 2**53+1 used to render as identical
  // bytes (JS itself already conflates them: `9007199254740992 ===
  // 9007199254740993` is true). Now the larger one throws instead of silently
  // matching the smaller one's bytes.
  const two53 = 2 ** 53;
  assert.throws(() => canonicalJson({ max: two53 }), UnsafeIntegerError);
  assert.throws(() => canonicalJson({ max: two53 + 1 }), UnsafeIntegerError);

  // The parser keeps the ORIGINAL literal text, so a value whose text is
  // unsafe is rejected even where `Number(raw)` alone might mislead: parsing
  // "9007199254740993" and letting IT round to 9007199254740992 must not be
  // mistaken for the safe value 9007199254740992 was never actually sent.
  assert.throws(() => canonicalJson(parseJson("9007199254740993")), UnsafeIntegerError);
  assert.equal(canonicalJson(parseJson(String(MAX_SAFE_INTEGER))), String(MAX_SAFE_INTEGER));
  // Exponential-form text (not a bare integer literal) is still caught by the
  // value-based check once it parses to an unsafe integral double.
  assert.throws(() => canonicalJson(parseJson("1e21")), UnsafeIntegerError);
  // A non-integer value is never flagged, no matter its magnitude class.
  assert.equal(canonicalJson(1e-7), "1e-7");
});

test("JCS emits Unicode verbatim and rejects lone surrogates", () => {
  assert.equal(canonicalJson("café 😀 監査"), '"café 😀 監査"');
  assert.equal(canonicalJson('\t\n\r\\"'), '"\\t\\n\\r\\\\\\""');
  assert.equal(canonicalJson("\u0000\u001f"), '"\\u0000\\u001f"');
  assert.throws(() => canonicalJson("\ud800"), LoneSurrogateError);
  assert.throws(() => canonicalJson({ "\udfff": 1 }), LoneSurrogateError);
  assert.throws(() => parseJson('"\\ud800"'), LoneSurrogateError);
});

test("object names sort by UTF-16 code units", () => {
  assert.equal(canonicalJson({ "\ue000": 1, "\u{10000}": 2 }), '{"𐀀":2,"":1}');
});

test("the parser rejects duplicates and malformed documents", () => {
  assert.throws(() => parseJson('{"a":1,"a":2}'), DuplicateMemberError);
  assert.throws(() => parseJson("{"), SyntaxError);
  assert.throws(() => parseJson("{} {}"), SyntaxError);
  assert.throws(() => parseJson('{"a" 1}'), SyntaxError);
  assert.throws(() => parseJson('"unterminated'), SyntaxError);
  assert.throws(() => parseJson('"raw\ncontrol"'), SyntaxError);
});

test("values outside the closed JSON model are rejected", () => {
  assert.throws(() => canonicalJson(undefined as any), UnsupportedTypeError);
  assert.throws(() => canonicalJson(1n as any), UnsupportedTypeError);
  assert.throws(() => canonicalJson(new Date(0) as any), UnsupportedTypeError);
  assert.throws(() => canonicalJson([1, undefined] as any), UnsupportedTypeError);
  assert.throws(() => canonicalJson({ get value() { return 1; } } as any), UnsupportedTypeError);
  const accessor: any[] = [1];
  Object.defineProperty(accessor, "0", { get: () => 1, enumerable: true });
  assert.throws(() => canonicalJson(accessor), UnsupportedTypeError);
  const cyclic: any[] = [];
  cyclic.push(cyclic);
  assert.throws(() => canonicalJson(cyclic), UnsupportedTypeError);
});
