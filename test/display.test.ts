/**
 * The display rules (display.ts) against the Python implementation's own output.
 *
 * Every expected value below was produced by Python itself: `repr`, and the Python implementation's
 * `_display.escaped` and `_display.shown`, on the same inputs. A value from a ledger or a bundle
 * reaches a terminal through these functions, so a difference here is a difference in what the two
 * CLIs print, and a value that escapes them can end a line and start a forged one.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { parseJson, type CJson } from "../src/canonical.js";
import { escaped, pyRepr, pyStr, pyStrRepr, shown } from "../src/display.js";

/** [text, Python repr(text), _display.escaped(text), _display.shown(text)] */
const STRINGS: [string, string, string, string][] = [["crm.read", "'crm.read'", "\"crm.read\"", "crm.read"], ["n1\nOK", "'n1\\nOK'", "\"n1\\nOK\"", "\"n1\\nOK\""], ["it's", "\"it's\"", "\"it's\"", "it's"], ["say \"hi\"", "'say \"hi\"'", "\"say\\u0020\\\"hi\\\"\"", "\"say\\u0020\\\"hi\\\"\""], ["both ' and \"", "'both \\' and \"'", "\"both\\u0020'\\u0020and\\u0020\\\"\"", "\"both\\u0020'\\u0020and\\u0020\\\"\""], ["back\\slash", "'back\\\\slash'", "\"back\\\\slash\"", "\"back\\\\slash\""], ["tab\there", "'tab\\there'", "\"tab\\there\"", "\"tab\\there\""], ["cr\rhere", "'cr\\rhere'", "\"cr\\rhere\"", "\"cr\\rhere\""], ["nul\u0000del\u007f", "'nul\\x00del\\x7f'", "\"nul\\u0000del\\u007f\"", "\"nul\\u0000del\\u007f\""], ["caf\u00e9", "'caf\u00e9'", "\"caf\\u00e9\"", "\"caf\\u00e9\""], ["\u00a0nbsp", "'\\xa0nbsp'", "\"\\u00a0nbsp\"", "\"\\u00a0nbsp\""], ["line\u2028sep", "'line\\u2028sep'", "\"line\\u2028sep\"", "\"line\\u2028sep\""], ["zero\u200bwidth", "'zero\\u200bwidth'", "\"zero\\u200bwidth\"", "\"zero\\u200bwidth\""], ["emoji \ud83d\ude00", "'emoji \ud83d\ude00'", "\"emoji\\u0020\\ud83d\\ude00\"", "\"emoji\\u0020\\ud83d\\ude00\""], ["lang\udb40\udc01tag", "'lang\\U000e0001tag'", "\"lang\\udb40\\udc01tag\"", "\"lang\\udb40\\udc01tag\""], ["lone\ud800", "'lone\\ud800'", "\"lone\\ud800\"", "\"lone\\ud800\""], ["", "''", "\"\"", "\"\""], ["a b", "'a b'", "\"a\\u0020b\"", "\"a\\u0020b\""], ["x=y,z", "'x=y,z'", "\"x=y,z\"", "x=y,z"], ["\u0085next", "'\\x85next'", "\"\\u0085next\"", "\"\\u0085next\""], ["soft\u00adhyphen", "'soft\\xadhyphen'", "\"soft\\u00adhyphen\"", "\"soft\\u00adhyphen\""]];

/** [value, _display.shown(value), _display.escaped(value)] */
const VALUES: [CJson, string, string][] = [[null, "None", "null"], [true, "True", "true"], [5, "5", "5"], [1.5, "1.5", "1.5"], [[1, "a b"], "[1,\"a\\u0020b\"]", "[1,\"a\\u0020b\"]"], [{"k": "v"}, "{\"k\":\"v\"}", "{\"k\":\"v\"}"], [["x"], "['x']", "[\"x\"]"]];

/** [JSON number literal, Python str(json.loads(literal)), _display.shown, _display.escaped] */
const LITERALS: [string, string, string, string][] = [["3.0", "3.0", "3.0", "3.0"], ["1E2", "100.0", "100.0", "100.0"], ["-0", "0", "0", "0"], ["12345678901234567890", "12345678901234567890", "12345678901234567890", "12345678901234567890"], ["1e16", "1e+16", "1e+16", "1e+16"], ["0.00001", "1e-05", "1e-05", "1e-05"], ["1.5e-7", "1.5e-07", "1.5e-07", "1.5e-07"], ["123.0", "123.0", "123.0", "123.0"], ["7", "7", "7", "7"]];

test("pyStrRepr is Python's repr of a str: the quote it picks, its escapes, its idea of printable", () => {
  for (const [text, repr] of STRINGS) assert.equal(pyStrRepr(text), repr, JSON.stringify(text));
});

test("escaped and shown print a string exactly as the Python implementation does", () => {
  for (const [text, , esc, show] of STRINGS) {
    assert.equal(escaped(text), esc, JSON.stringify(text));
    assert.equal(shown(text), show, JSON.stringify(text));
  }
});

test("shown and escaped agree with Python on non-string values", () => {
  for (const [value, show, esc] of VALUES) {
    assert.equal(shown(value), show, JSON.stringify(value));
    assert.equal(escaped(value), esc, JSON.stringify(value));
  }
  assert.equal(shown(undefined), "None", "an absent value is Python's None");
});

test("a parsed number keeps its literal: 3.0 prints as Python's float, 3 as its int", () => {
  for (const [literal, text, show, esc] of LITERALS) {
    const value = (parseJson(`{"v":${literal}}`) as Record<string, CJson>)["v"]!;
    assert.equal(pyStr(value), text, literal);
    assert.equal(pyRepr(value), text, literal);
    assert.equal(shown(value), show, literal);
    assert.equal(escaped(value), esc, literal);
  }
});

test("no output of shown or escaped holds whitespace or a line break", () => {
  for (const [text] of STRINGS) {
    for (const out of [shown(text), escaped(text)]) assert.doesNotMatch(out, /\s/u, JSON.stringify(text));
  }
});
