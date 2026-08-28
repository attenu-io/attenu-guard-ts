/**
 * Canonical serialisation must be byte-identical to Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))`. Everything else in
 * the library — hashes, seals, anchors — rests on that.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  compareCodePoints,
  parseJson,
  pyJsonDumps,
  pyNumber,
  pyString,
  RawNumber,
  sortedStrings,
  toPlain,
} from "../src/canonical.js";
import { fixtureJson } from "./helpers.js";

interface CanonicalVector {
  source: string;
  canonical: string;
}

const vectors = fixtureJson<CanonicalVector[]>("canonical_vectors.json");

test("every Python-written document re-serialises to its canonical bytes", () => {
  assert.ok(vectors.length > 0, "fixtures are present");
  for (const v of vectors) {
    assert.equal(canonicalJson(parseJson(v.source)), v.canonical, `source: ${v.source}`);
  }
});

test("the raw-preserving parser round-trips Python's own output", () => {
  for (const v of vectors) {
    // Re-serialising with Python's DEFAULT separators reproduces the source.
    assert.equal(pyJsonDumps(parseJson(v.source)), v.source);
  }
});

test("toPlain strips RawNumber wrappers", () => {
  const parsed = parseJson('{"a": 1, "b": [2.5, {"c": 100.0}]}');
  assert.deepEqual(toPlain(parsed), { a: 1, b: [2.5, { c: 100 }] });
  const raw = (parsed as any).b[1].c as RawNumber;
  assert.ok(raw instanceof RawNumber);
  assert.equal(raw.raw, "100.0");
  assert.equal(raw.value, 100);
});

test("a float literal survives re-serialisation, so a Python hash reproduces", () => {
  // A JavaScript number cannot remember that the document said 100.0, which is
  // exactly why the parser keeps the literal.
  assert.equal(canonicalJson(parseJson('{"max": 100.0}')), '{"max":100.0}');
  assert.equal(canonicalJson({ max: 100 }), '{"max":100}');
});

test("pyNumber matches CPython's json for the cases JSON.stringify gets wrong", () => {
  const expected: [number, string][] = [
    [0, "0"],
    [-0, "-0.0"],
    [1, "1"],
    [-1, "-1"],
    [100, "100"],
    [1e15, "1000000000000000"],
    [1e20, "100000000000000000000"],
    [1e21, "1e+21"],
    [0.1, "0.1"],
    [2.5, "2.5"],
    [1 / 3, "0.3333333333333333"],
    [1e-5, "1e-05"],
    [1e-7, "1e-07"],
    [-1.5e-9, "-1.5e-09"],
    [1.25e-4, "0.000125"],
    [123.456, "123.456"],
  ];
  for (const [value, want] of expected) {
    assert.equal(pyNumber(value), want, `pyNumber(${want})`);
  }
});

test("strings are escaped the way ensure_ascii does", () => {
  assert.equal(pyString("café"), '"caf\\u00e9"');
  assert.equal(pyString("😀"), '"\\ud83d\\ude00"');
  assert.equal(pyString("\x7f"), '"\\u007f"');
  assert.equal(pyString("a/b"), '"a/b"'); // the solidus is not escaped
  assert.equal(pyString('\t\n\r\\"'), '"\\t\\n\\r\\\\\\""');
  assert.equal(pyString("\x00\x1f"), '"\\u0000\\u001f"');
  assert.equal(pyString("\u2028"), '"\\u2028"');
});

test("keys sort by code point, and undefined values are omitted", () => {
  assert.equal(canonicalJson({ b: 1, a: 2, C: 3, _: 4 }), '{"C":3,"_":4,"a":2,"b":1}');
  assert.equal(canonicalJson({ a: 1, b: undefined } as any), '{"a":1}');
  assert.equal(canonicalJson({ a: null }), '{"a":null}');
  assert.deepEqual(sortedStrings(["b", "A", "_", "á"]), ["A", "_", "b", "á"]);
  assert.ok(compareCodePoints("A", "a") < 0);
  assert.equal(compareCodePoints("abc", "abc"), 0);
});

test("the parser rejects malformed documents rather than guessing", () => {
  assert.throws(() => parseJson("{"), SyntaxError);
  assert.throws(() => parseJson("{} {}"), SyntaxError);
  assert.throws(() => parseJson('{"a" 1}'), SyntaxError);
  assert.throws(() => parseJson('"unterminated'), SyntaxError);
});

test("the parser reads escapes, including surrogate pairs", () => {
  assert.equal(parseJson('"\\ud83d\\ude00"'), "😀");
  assert.equal(parseJson('"\\u00e9"'), "é");
  assert.equal(parseJson('"a\\/b"'), "a/b");
  assert.equal(parseJson('"\\t\\n\\r\\b\\f"'), "\t\n\r\b\f");
});
