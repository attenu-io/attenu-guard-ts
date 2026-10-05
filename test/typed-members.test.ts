/**
 * `one_of` / `not_one_of` (attenu-ops#110). A member is its JSON type plus its value, in both
 * implementations: a JavaScript Set keeps `true` and 1 apart, and the Python implementation keys
 * its members the same way. A request value that is not a JSON scalar cannot equal any member,
 * and both lists refuse it: a deny-list that waved `["rm"]` through because it is not the string
 * "rm" would fail open. Every expectation here is the Python implementation's answer for the same
 * input.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { AuditLog } from "../src/audit.js";
import { Authority } from "../src/authority.js";
import { canonicalBytes, canonicalJson, parseJson, type Json } from "../src/canonical.js";
import { Allow, Deny, ceilingFromWire } from "../src/ceilings.js";
import { exportBundle, verifyBundle } from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { ReasonCode } from "../src/reasons.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlEncode, load } from "../src/wire.js";

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

/**
 * A chain whose authorities carry each constraint exactly as given: a root token holding the
 * first, and, when there is a second, a child token holding that one, linked by `par_hash`.
 */
function tokens(rootConstraint: Record<string, Json>, childConstraint?: Record<string, Json>): string[] {
  const part = (o: Record<string, Json>) => b64urlEncode(canonicalBytes(o));
  const header = part({ typ: "at+jwt", alg: "HS256", kid: "typed", c14n: "JCS" });
  const sign = (payload: Record<string, Json>) => {
    const signingInput = `${header}.${part(payload)}`;
    return [signingInput, `${signingInput}.${b64urlEncode(hs256.sign(Buffer.from(signingInput, "ascii")))}`];
  };
  const detail = (c: Record<string, Json>) => [{ type: "agent_delegation", scopes: ["crm.read"], constraints: [c] }];
  const [rootInput, root] = sign({
    iss: "typed", sub: "root", aud: null, iat: 0, exp: 60, jti: "n0", del_depth: 0, del_max_depth: 2,
    authorization_details: detail(rootConstraint),
  });
  if (childConstraint === undefined) return [root!];
  const [, child] = sign({
    iss: "typed", sub: "child", aud: null, iat: 0, exp: 30, jti: "n1", del_depth: 1,
    par_hash: b64urlEncode(createHash("sha256").update(rootInput!, "ascii").digest()),
    authorization_details: detail(childConstraint),
  });
  return [root!, child!];
}

function rootToken(constraint: Record<string, Json>): string {
  return tokens(constraint)[0]!;
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

/** Every container a `one_of` / `not_one_of` must not be, with the word its refusal uses. */
const NOT_ARRAYS: [Json, string][] = [
  [{ us: 1 }, "an object"],
  [null, "null"],
  ["us", "a string"],
  [5, "a number"],
  [1.5, "a number"],
  [true, "a boolean"],
];

test("a one_of that is not an array is refused, by the constructor and from the wire", () => {
  // An object used to throw a TypeError of its own words, null became the empty list, and a
  // string became its characters. Each is now refused naming the list and the key, as in the
  // Python implementation (which raises ValueError with the same text).
  for (const [value, kind] of NOT_ARRAYS) {
    for (const [Cls, type, name] of [[Allow, "allow", "one_of"], [Deny, "deny", "not_one_of"]] as const) {
      const message = `${name} of constraint 'region' is ${kind}, not an array`;
      assert.throws(() => new Cls("region", value as any), { name: "TypeError", message });
      assert.throws(() => ceilingFromWire({ key: "region", type, [name]: value }), { name: "TypeError", message });
    }
  }
  assert.throws(
    () => Guard.issue("root", new Authority({ scopes: ["crm.read"], ceilings: [new Allow("region", { us: 1 } as any)] })),
    { name: "TypeError", message: "one_of of constraint 'region' is an object, not an array" },
  );
});

test("an array or a Set is still a list of members, and an absent one_of an empty one", () => {
  for (const given of [["us", "eu"], new Set(["us", "eu"])]) {
    assert.deepEqual(new Allow("region", given).toWire()["one_of"], ["eu", "us"]);
  }
  assert.deepEqual(ceilingFromWire({ key: "region", type: "allow" }).toWire()["one_of"], []);
});

test("a token whose one_of is not an array is malformed", () => {
  for (const [value, kind] of NOT_ARRAYS) {
    for (const [type, name] of [["allow", "one_of"], ["deny", "not_one_of"]] as const) {
      assert.throws(() => load([rootToken({ key: "tier", type, [name]: value })], hs256), (err: unknown) => {
        assert.ok(err instanceof WireError);
        assert.equal(err.reason, WireReasonCode.MALFORMED);
        assert.ok(err.message.endsWith(`${name} of constraint 'tier' is ${kind}, not an array`), err.message);
        return true;
      });
    }
  }
});

/** A ledger holding a root granted `root` and, when given, a spawn granted `child`, as a bundle. */
function unreadableBundle(root: Record<string, Json>, child?: Record<string, Json>) {
  const authority = (c: Record<string, Json>) => ({ scopes: ["docs.write"], constraints: [c], ttl: null });
  const log = new AuditLog();
  log.append("root", 0, { chain_id: "typed", node: "typed:n0", agent: "root", authority: authority(root) });
  if (child !== undefined) {
    log.append("spawn", 1, {
      chain_id: "typed", parent: "typed:n0", node: "typed:n1", agent: "child", task: "t",
      requested: authority(child), granted: authority(child),
    });
  }
  return verifyBundle(exportBundle(log, hs256), hs256);
}

test("a bundle whose one_of is not an array reports the authority unreadable", () => {
  for (const [value, kind] of NOT_ARRAYS) {
    const root = unreadableBundle({ key: "tier", type: "allow", one_of: value });
    assert.equal(root.ok, false);
    assert.equal(root.failures[0], `root typed:n0: unreadable authority (one_of of constraint 'tier' is ${kind}, not an array)`);
    const spawn = unreadableBundle({ key: "tier", type: "allow", one_of: [1] }, { key: "tier", type: "deny", not_one_of: value });
    assert.equal(spawn.ok, false);
    assert.equal(spawn.failures[0], `spawn typed:n1: unreadable granted (not_one_of of constraint 'tier' is ${kind}, not an array)`);
  }
});

test("unknown constraints compare as JSON: the same RFC 8785 bytes", () => {
  // The comparison sorted only the top-level keys, so two objects equal as JSON differed when a
  // nested one listed its keys in another order. Both implementations now compare canonical bytes.
  const cases: [string, string, string, boolean][] = [
    ["a boolean is not a number", '{"v":[true]}', '{"v":[1]}', false],
    ["1.0 is 1", '{"v":1.0}', '{"v":1}', true],
    ["-0 is 0", '{"v":-0}', '{"v":0}', true],
    ["nested key order is not a difference", '{"v":{"a":1,"b":2}}', '{"v":{"b":2,"a":1}}', true],
    ["nor is it deeper down", '{"v":[{"a":{"c":1,"d":2}}]}', '{"v":[{"a":{"d":2,"c":1}}]}', true],
    ["array order is", '{"v":[1,2]}', '{"v":[2,1]}', false],
    ["a string is not the number it spells", '{"v":"1"}', '{"v":1}', false],
    ["null is not false", '{"v":null}', '{"v":false}', false],
    ["identical", '{"v":{"a":[1,"s",null]}}', '{"v":{"a":[1,"s",null]}}', true],
  ];
  const unknown = (members: string) => ceilingFromWire(parseJson(`{"key":"k","type":"x-custom",${members.slice(1)}`));
  for (const [label, a, b, equal] of cases) {
    assert.equal(unknown(a).subsumes(unknown(b)), equal, label);
    assert.equal(unknown(b).subsumes(unknown(a)), equal, label);
  }
  // An integer past 2^53 has no RFC 8785 form: not even an identical copy is the same constraint.
  assert.equal(unknown('{"v":9007199254740992}').subsumes(unknown('{"v":9007199254740992}')), false);
});

test("a chain or a bundle compares unknown constraints as JSON", () => {
  const parent = { key: "k", type: "x-custom", v: [true], w: { a: 1, b: 2 } };
  assert.throws(() => load(tokens(parent, { key: "k", type: "x-custom", v: [1], w: { a: 1, b: 2 } }), hs256), (err: unknown) => {
    assert.ok(err instanceof WireError);
    assert.equal(err.reason, WireReasonCode.NOT_NARROWER);
    return true;
  });
  load(tokens(parent, parent), hs256);
  const narrower = unreadableBundle(parent, { key: "k", type: "x-custom", w: { b: 2, a: 1 }, v: [true] });
  assert.equal(narrower.ok, true);
  const looser = unreadableBundle(parent, { key: "k", type: "x-custom", v: [1], w: { a: 1, b: 2 } });
  assert.deepEqual(looser.failures, [
    "monotonicity: typed:n1 not ⊆ parent typed:n0 (ceiling k={'key': 'k', 'type': 'x-custom', 'v': [1], " +
      "'w': {'a': 1, 'b': 2}} looser than parent k={'key': 'k', 'type': 'x-custom', 'v': [True], 'w': {'a': 1, 'b': 2}})",
  ]);
});
