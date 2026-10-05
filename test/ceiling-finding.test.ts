/**
 * A ceiling's description, and the same ceiling inside a verifier finding.
 *
 * `describe()` is unchanged: dashboards and `Authority.describe()` print a region called "São Paulo"
 * as it is. Inside a finding, which `attenu-guard verify` prints, every value a bundle supplied goes
 * through the one display rule (display.ts `shown`), so the finding stays on one line. For values in
 * the bare set the two texts agree character for character. Every expected string marked Python is
 * the Python implementation's own output (`evidence._ceiling_in_finding`) for the same ceiling.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { Allow, CallLimit, Deny, EgressRank, Prefix, RowLimit, SpendCap, ceilingFromWire, describe, describeInFinding } from "../src/ceilings.js";

test("describe() is unchanged outside a finding", () => {
  assert.equal(describe(new Allow("region", ["S\u00e3o Paulo"])), "region in [S\u00e3o Paulo]");
  assert.equal(
    new Authority({ scopes: ["docs.write"], ceilings: [new Allow("region", ["S\u00e3o Paulo"])] }).describe(),
    "scopes=[docs.write] ceilings=[region in [S\u00e3o Paulo]] ttl=null",
  );
  // A ceiling this build does not define prints as the Python implementation prints it (attenu-ops#110).
  assert.equal(
    describe(ceilingFromWire({ key: "quota", type: "x-unknown", max: 1 })),
    "quota={'key': 'quota', 'type': 'x-unknown', 'max': 1}",
  );
});

test("a finding prints a built-in ceiling as describe() does for bare values", () => {
  // An allow-list or a deny-list differs in one way: a finding quotes its string members.
  for (const ceiling of [
    new RowLimit(100),
    new SpendCap(2.5),
    new CallLimit(3),
    new CallLimit(3, "fs.write"),
    new EgressRank("internal"),
    new Prefix("path", "data/"),
  ]) {
    assert.equal(describeInFinding(ceiling), describe(ceiling), describe(ceiling));
  }
  assert.equal(describeInFinding(new Allow("region", ["us", "eu"])), "region in ['eu', 'us']");
  assert.equal(describeInFinding(new Deny("tool", ["shell", "rm"])), "tool not in ['rm', 'shell']");
});

test("a finding prints string members through Python's repr", () => {
  // So a finding tells the string "1" from the number 1 (they printed alike), and a member
  // carrying a line break or a control character stays on one line, escaped.
  assert.equal(describeInFinding(new Allow("region", ["S\u00e3o Paulo", "us"])), "region in ['S\u00e3o Paulo', 'us']");
  assert.equal(describeInFinding(new Allow("region", ["eu\nOK", "x\u202e"])), "region in ['eu\\nOK', 'x\\u202e']");
  assert.equal(describeInFinding(new Allow("t", ["1", 1, "True", true, null])), "t in [1, '1', None, True, 'True']");
});

test("a ceiling this build does not define stays on one line, in Python's words", () => {
  // Python describes it as its key, `=`, and the wire object as Python prints a dict; the finding
  // prints that text as it is when it is printable ASCII, and as escaped JSON otherwise.
  assert.equal(
    describeInFinding(ceilingFromWire({ key: "quota", type: "x-unknown", max: 1 })),
    "quota={'key': 'quota', 'type': 'x-unknown', 'max': 1}",
  );
  const text = describeInFinding(ceilingFromWire({ key: "quota\nOK", type: "x-unknown" }));
  assert.equal(text, "\"quota\\nOK={'key':\\u0020'quota\\\\nOK',\\u0020'type':\\u0020'x-unknown'}\"");
  assert.ok(!text.includes("\n"));
  assert.equal(JSON.parse(text), "quota\nOK={'key': 'quota\\nOK', 'type': 'x-unknown'}");
});
