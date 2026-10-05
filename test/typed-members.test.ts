/**
 * `one_of` / `not_one_of` (attenu-ops#110). A member is its JSON type plus its value, in both
 * implementations: a JavaScript Set keeps `true` and 1 apart, and the Python implementation keys
 * its members the same way. A request value that is not a JSON scalar cannot equal any member,
 * and both lists refuse it: a deny-list that waved `["rm"]` through because it is not the string
 * "rm" would fail open. Every expectation here is the Python implementation's answer for the same
 * input.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { canonicalBytes, canonicalJson, type Json } from "../src/canonical.js";
import { Allow, Deny, ceilingFromWire } from "../src/ceilings.js";
import { exportBundle, verifyBundle } from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { ReasonCode } from "../src/reasons.js";
import { HS256TestSigner, b64urlEncode, load } from "../src/wire.js";

const hs256 = new HS256TestSigner(Buffer.from("typed-members"), "typed");

/** `values` with each one's type beside it, so `[1]` and `[true]` cannot pass for each other. */
function typed(values: readonly Json[]): [string, Json][] {
  return values.map((v) => [v === null ? "null" : Array.isArray(v) ? "array" : typeof v, v]);
}

test("one_of [1] refuses true, and each JSON kind is its own member", () => {
  const c = ceilingFromWire({ key: "tier", type: "allow", one_of: [1] });
  assert.equal(c.permits({ tier: 1 }).allowed, true);
  assert.equal(c.permits({ tier: true }).allowed, false);
  assert.equal(new Allow("tier", [0]).permits({ tier: false }).allowed, false);
  assert.equal(new Allow("t", ["1"]).permits({ t: 1 }).allowed, false);
  const deny = ceilingFromWire({ key: "t", type: "deny", not_one_of: [0, false, null, "", "0"] });
  assert.deepEqual(typed(deny.toWire()["not_one_of"] as Json[]), typed(["", 0, "0", false, null]));
});

test("the issue's deny-list re-emits three members, in the order the Python implementation does", () => {
  const c = ceilingFromWire({ key: "region", type: "deny", not_one_of: ["secret", true, 1] });
  assert.equal(canonicalJson(c.toWire()), '{"key":"region","not_one_of":[1,true,"secret"],"type":"deny"}');
  assert.equal(c.describe!(), "region not in [1, True, secret]");
  for (const given of [["1", 1], [1, "1"], ["True", true], [true, "True"]] as Json[][]) {
    assert.deepEqual(typed(new Allow("t", given).toWire()["one_of"] as Json[]), typed(given));
  }
});

test("a negative zero member is 0, after -1", () => {
  const c = ceilingFromWire({ key: "t", type: "allow", one_of: [-0, -1] });
  assert.equal(canonicalJson(c.toWire()), '{"key":"t","one_of":[-1,0],"type":"allow"}');
  assert.equal(c.describe!(), "t in [-1, 0]");
});

test("subsumption and narrowing keep true and 1 apart", () => {
  assert.equal(new Allow("t", [true]).subsumes(new Allow("t", [1])), false);
  assert.equal(new Allow("t", [1, true]).subsumes(new Allow("t", [true])), true);
  assert.equal(new Deny("t", [true]).subsumes(new Deny("t", [1])), false);
  assert.deepEqual((new Allow("t", [1]).narrow(new Allow("t", [true])) as Allow).toWire()["one_of"], []);
  assert.deepEqual(typed((new Deny("t", [1]).narrow(new Deny("t", [true])) as Deny).toWire()["not_one_of"] as Json[]),
    typed([1, true]));
});

test("a request value that is not a JSON scalar is refused by both lists", () => {
  const cases: [unknown, string][] = [
    [["rm"], "an array"],
    [{ rm: 1 }, "an object"],
    [[1], "an array"],
    [10n, "a value that is not JSON"],
  ];
  for (const [value, kind] of cases) {
    for (const [ceiling, name] of [[new Allow("tool", ["rm", 1]), "one_of"], [new Deny("tool", ["rm", 1]), "not_one_of"]] as const) {
      const decision = ceiling.permits({ tool: value as Json });
      assert.equal(decision.allowed, false, `${name} ${String(value)}`);
      assert.equal(decision.reasons.length, 1);
      const reason = decision.reasons[0]!;
      assert.equal(reason.code, ReasonCode.CEILING_EXCEEDED);
      assert.equal(reason.constraint, "tool");
      assert.equal(reason.requested, value);
      assert.deepEqual(typed(reason.limit as Json[]), typed([1, "rm"]));
      assert.equal(reason.message, `${kind} cannot be compared with ${name} members; refused`);
    }
  }
});

test("null, an absent field and the scalars are still compared as before", () => {
  const deny = new Deny("tool", ["rm", 1]);
  assert.equal(deny.permits({ tool: null }).allowed, true);
  assert.equal(deny.permits({}).allowed, true);
  assert.equal(deny.permits({ tool: "ls" }).allowed, true);
  assert.equal(deny.permits({ tool: true }).allowed, true);
  const refused = deny.permits({ tool: "rm" });
  assert.equal(refused.allowed, false);
  assert.equal(refused.reasons[0]!.message, "");
});

test("a field named like an Object.prototype member is absent when the context does not hold it", () => {
  // `ctx["constructor"]` is Object's constructor on any plain object. The Python implementation
  // reads `ctx.get("constructor")`, which is None: the context asserts nothing about that field.
  for (const name of ["constructor", "toString", "__proto__"]) {
    assert.equal(new Allow(name, ["x"]).permits({}).allowed, true, name);
    assert.equal(new Deny(name, ["x"]).permits({}).allowed, true, name);
  }
  assert.equal(new Allow("constructor", ["x"]).permits({ constructor: "x" } as any).allowed, true);
  assert.equal(new Deny("constructor", ["x"]).permits({ constructor: "x" } as any).allowed, false);
});

test("Guard.check refuses a list against a deny-list and records why", () => {
  const guard = Guard.issue("root", new Authority({ scopes: ["shell.run"], ceilings: [new Deny("tool", ["rm"])] }));
  const decision = guard.check("shell.run", { context: { tool: ["rm"] } });
  assert.equal(decision.allowed, false);
  const deny = guard.auditLog().entries.at(-1)!;
  assert.equal(deny["event"], "deny");
  assert.equal(deny["reason"], ReasonCode.CEILING_EXCEEDED);
  assert.equal((deny["reasons"] as any)[0].message, "an array cannot be compared with not_one_of members; refused");
});

/** A one-token chain whose authority carries `constraint` exactly as given. */
function rootToken(constraint: Record<string, Json>): string {
  const part = (o: Record<string, Json>) => b64urlEncode(canonicalBytes(o));
  const header = part({ typ: "at+jwt", alg: "HS256", kid: "typed", c14n: "JCS" });
  const payload = part({
    iss: "typed", sub: "root", aud: null, iat: 0, exp: 60, jti: "n0", del_depth: 0, del_max_depth: 2,
    authorization_details: [{ type: "agent_delegation", scopes: ["crm.read"], constraints: [constraint] }],
  });
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${b64urlEncode(hs256.sign(Buffer.from(signingInput, "ascii")))}`;
}

test("a verified deny-list refuses a list it cannot compare", () => {
  const chain = load([rootToken({ key: "region", type: "deny", not_one_of: ["secret"] })], hs256);
  assert.equal(chain.permits("crm.read", { region: "public" }).allowed, true);
  const decision = chain.permits("crm.read", { region: ["secret"] });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reasons[0]!.message, "an array cannot be compared with not_one_of members; refused");
});

test("an allow of a list or an object is outside an allow-list and a deny-list alike", () => {
  for (const ceiling of [new Allow("tier", [1]), new Deny("tier", [1])]) {
    for (const value of [[1], { a: 1 }] as Json[]) {
      const guard = Guard.issue("root", new Authority({ scopes: ["docs.write"], ceilings: [ceiling] }), {
        chainId: "typed",
      });
      const root = guard.auditLog().entries[0]!;
      guard.auditLog().append("allow", 1, {
        chain_id: root["chain_id"]!, node: root["node"]!, scope: "docs.write", tool: null, context: { tier: value },
      });
      const report = verifyBundle(exportBundle(guard.auditLog(), hs256), hs256);
      assert.equal(report.checks.containment, false, `${ceiling.constructor.name} ${JSON.stringify(value)}`);
      assert.deepEqual(report.failures, [
        "containment: allow of 'docs.write' on typed:n0 outside its authority ['docs.write']",
      ]);
    }
  }
});
