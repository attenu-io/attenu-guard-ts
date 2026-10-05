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
import { Allow, CallLimit, Deny, EgressRank, Prefix, RowLimit, SpendCap, ceilingFromWire, describe, type Ceiling } from "../src/ceilings.js";
import { exportBundle, verifyBundle } from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { ReasonCode } from "../src/reasons.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlEncode, load } from "../src/wire.js";
import { pyRepr } from "../src/display.js";

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

test("an array or a Set is still a list of members, and an absent one_of is malformed", () => {
  for (const given of [["us", "eu"], new Set(["us", "eu"])]) {
    assert.deepEqual(new Allow("region", given).toWire()["one_of"], ["eu", "us"]);
  }
  // An absent deny-list used to read as an empty one, which bounds nothing.
  assert.throws(() => ceilingFromWire({ key: "region", type: "allow" }),
    { name: "TypeError", message: "one_of of constraint 'region' is absent, not an array" });
  assert.throws(() => ceilingFromWire({ key: "tool", type: "deny" }),
    { name: "TypeError", message: "not_one_of of constraint 'tool' is absent, not an array" });
  assert.deepEqual(ceilingFromWire({ key: "region", type: "allow", one_of: [] }).toWire()["one_of"], []);
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

test("an unknown constraint describes itself and denies in the Python implementation's words", () => {
  // The deny entry a Guard writes carries this reason, so the two implementations must write the
  // same bytes for it: the key as Python's repr prints it, the wire object as Python prints a dict.
  // A key that is not a string no longer loads ("a key that is not a string is malformed").
  const cases: [Record<string, Json>, string, string, Json][] = [
    [{ key: "tier", type: "x-custom", v: [true] }, "tier={'key': 'tier', 'type': 'x-custom', 'v': [True]}",
      "unrecognised constraint type for key='tier'; fail-closed", "tier"],
    [{ key: "t\nOK", type: "x-custom" }, "t\nOK={'key': 't\\nOK', 'type': 'x-custom'}",
      "unrecognised constraint type for key='t\\nOK'; fail-closed", "t\nOK"],
  ];
  for (const [wire, text, message, constraint] of cases) {
    const c = ceilingFromWire(wire);
    assert.equal(describe(c), text);
    const reason = c.permits({}).reasons[0]!;
    assert.equal(reason.code, ReasonCode.UNKNOWN_CONSTRAINT);
    assert.equal(reason.message, message);
    assert.equal(reason.constraint, constraint);
  }
  const authority = Authority.fromWire({ scopes: ["crm.read"], constraints: [cases[0]![0]], ttl: 60 });
  assert.equal(authority.describe(), "scopes=[crm.read] ceilings=[tier={'key': 'tier', 'type': 'x-custom', 'v': [True]}] ttl=60");
  const guard = Guard.issue("root", authority);
  guard.check("crm.read", { context: {} });
  assert.deepEqual(guard.auditLog().entries.at(-1)!["reasons"], [{
    code: "unknown_constraint", constraint: "tier", limit: null, requested: null,
    message: "unrecognised constraint type for key='tier'; fail-closed",
  }]);
});

test("every ceiling refuses a request value of the wrong JSON type, never coercing it", () => {
  // `"50"`, `[50]` and `true` passed a row cap by coercion, `["/tmp/x"]` passed the prefix "/tmp/"
  // as the text "/tmp/x", and `true` passed the prefix "t" as "true". Same words as the Python
  // implementation, one message per ceiling kind.
  const wrong: [string, unknown][] = [
    ["a string", "50"], ["a boolean", true], ["a number", 50], ["an array", [50]], ["an object", { n: 50 }],
    ["a value that is not JSON", 50n],
  ];
  const kinds: [Ceiling, string, string, string, Record<string, Json>][] = [
    [new RowLimit(100), "rows", "a number", "a maximum", {}],
    [new SpendCap(2.5), "spend", "a number", "a maximum", {}],
    [new CallLimit(3), "calls", "a number", "a maximum", {}],
    [new CallLimit(3, "fs.write"), "calls[fs.write]", "a number", "a maximum", { _scope: "fs.write" }],
    [new Prefix("path", "50"), "path", "a string", "a prefix", {}],
    [new EgressRank("any"), "egress", "a string", "an egress rank", {}],
  ];
  for (const [ceiling, field, accepted, against, extra] of kinds) {
    for (const [kind, value] of wrong) {
      if (kind === accepted) continue;
      const decision = ceiling.permits({ [field]: value as Json, ...extra });
      assert.equal(decision.allowed, false, `${ceiling.key} ${kind}`);
      assert.equal(decision.reasons.length, 1);
      const reason = decision.reasons[0]!;
      assert.equal(reason.code, ReasonCode.CEILING_EXCEEDED);
      assert.equal(reason.constraint, ceiling.key);
      assert.equal(reason.requested, value);
      assert.equal(reason.message, `${kind} cannot be compared with ${against}; refused`);
    }
  }
  assert.equal(new Prefix("flag", "t").permits({ flag: true }).allowed, false);
});

test("a value of the right type compares as before, and null or an absent field asserts nothing", () => {
  assert.equal(new RowLimit(100).permits({ rows: 50 }).allowed, true);
  assert.equal(new RowLimit(100).permits({ rows: 500 }).reasons[0]!.message, "");
  assert.equal(new Prefix("path", "/tmp/").permits({ path: "/tmp/x" }).allowed, true);
  assert.equal(new EgressRank("internal").permits({ egress: "any" }).reasons[0]!.message, "");
  for (const [ceiling, field] of [
    [new RowLimit(1), "rows"], [new SpendCap(1), "spend"], [new CallLimit(1), "calls"],
    [new EgressRank("none"), "egress"], [new Prefix("path", "/tmp/"), "path"],
  ] as [Ceiling, string][]) {
    assert.equal(ceiling.permits({ [field]: null }).allowed, true, ceiling.key);
    assert.equal(ceiling.permits({}).allowed, true, ceiling.key);
  }
  // A field named like an Object.prototype member is absent unless the context holds it.
  assert.equal(new Prefix("constructor", "c").permits({}).allowed, true);
  assert.equal(new Prefix("toString", "f").permits({}).allowed, true);
});

test("Guard.check, a verified chain and the bundle verifier refuse a quantity of the wrong type", () => {
  const guard = Guard.issue("root", new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(100)] }));
  assert.equal(guard.check("crm.read", { context: { rows: "50" } }).allowed, false);
  assert.equal((guard.auditLog().entries.at(-1)!["reasons"] as any)[0].message,
    "a string cannot be compared with a maximum; refused");
  const chain = load([rootToken({ key: "max_rows", max: 100 })], hs256);
  assert.equal(chain.permits("crm.read", { rows: 50 }).allowed, true);
  assert.equal(chain.permits("crm.read", { rows: true }).reasons[0]!.message,
    "a boolean cannot be compared with a maximum; refused");
  for (const [ceiling, context] of [
    [new RowLimit(100), { rows: "50" }], [new RowLimit(100), { rows: true }],
    [new Prefix("path", "/tmp/"), { path: ["/tmp/x"] }], [new Prefix("flag", "t"), { flag: true }],
  ] as [Ceiling, Record<string, Json>][]) {
    const g = Guard.issue("root", new Authority({ scopes: ["docs.write"], ceilings: [ceiling] }), { chainId: "typed" });
    const root = g.auditLog().entries[0]!;
    g.auditLog().append("allow", 1, { chain_id: root["chain_id"]!, node: root["node"]!, scope: "docs.write", tool: null, context });
    const report = verifyBundle(exportBundle(g.auditLog(), hs256), hs256);
    assert.deepEqual(report.failures, [
      "containment: allow of 'docs.write' on typed:n0 outside its authority ['docs.write']",
    ], JSON.stringify(context));
  }
});

test("a bound of the wrong type is malformed, from the constructor, the wire, a token and a bundle", () => {
  // Each was accepted: `max: true` read as 1, an unknown rank ranked above "any" and admitted every
  // request, a string `max` or a numeric `prefix` was coerced, and a numeric `field` read ctx["5"].
  // Same text as the Python implementation, which raises ValueError.
  const cases: [() => unknown, string][] = [
    [() => new RowLimit("5" as any), "max of constraint 'max_rows' is a string, not a number"],
    [() => new RowLimit(true as any), "max of constraint 'max_rows' is a boolean, not a number"],
    [() => new SpendCap(null as any), "max of constraint 'max_spend' is null, not a number"],
    [() => new CallLimit([5] as any), "max of constraint 'max_calls' is an array, not a number"],
    [() => new CallLimit("3" as any, "fs.write"), "max of constraint 'max_calls[fs.write]' is a string, not a number"],
    [() => ceilingFromWire({ key: "max_rows" }), "max of constraint 'max_rows' is absent, not a number"],
    [() => ceilingFromWire({ key: "max_spend", max: { n: 5 } }), "max of constraint 'max_spend' is an object, not a number"],
    [() => new Prefix("path", 5 as any), "prefix of constraint 'path' is a number, not a string"],
    [() => ceilingFromWire({ key: "path", type: "prefix" }), "prefix of constraint 'path' is absent, not a string"],
    [() => new EgressRank("everywhere"), "rank of constraint 'egress' is 'everywhere', not 'none', 'internal' or 'any'"],
    [() => new EgressRank("NONE"), "rank of constraint 'egress' is 'NONE', not 'none', 'internal' or 'any'"],
    [() => ceilingFromWire({ key: "egress", rank: 5 }), "rank of constraint 'egress' is a number, not 'none', 'internal' or 'any'"],
    [() => ceilingFromWire({ key: "egress" }), "rank of constraint 'egress' is absent, not 'none', 'internal' or 'any'"],
    [() => new Allow("region", ["us"], 5 as any), "field of constraint 'region' is a number, not a string"],
    [() => new Deny("tool", ["rm"], true as any), "field of constraint 'tool' is a boolean, not a string"],
    [() => new Prefix("path", "/tmp/", ["p"] as any), "field of constraint 'path' is an array, not a string"],
    [() => ceilingFromWire({ key: "region", type: "allow", one_of: ["us"], field: {} }),
      "field of constraint 'region' is an object, not a string"],
    [() => new CallLimit(3, 5 as any), "applies_to of constraint 'max_calls' is a number, not a string"],
    [() => ceilingFromWire({ key: "max_calls[x]", type: "max_calls", max: 3, applies_to: true }),
      "applies_to of constraint 'max_calls' is a boolean, not a string"],
    [() => Guard.issue("root", new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit("5" as any)] })),
      "max of constraint 'max_rows' is a string, not a number"],
  ];
  for (const [build, message] of cases) assert.throws(build, { name: "TypeError", message });
  // null is absent, as before: the context field is the key, and the limit is unscoped.
  assert.equal((ceilingFromWire({ key: "region", type: "allow", one_of: ["us"], field: null }) as Allow).field, null);
  assert.equal(new CallLimit(3, null).key, "max_calls");
  for (const level of ["none", "internal", "any"]) assert.equal(new EgressRank(level).level, level);
  assert.throws(() => load([rootToken({ key: "egress", rank: "everywhere" })], hs256), (err: unknown) => {
    assert.ok(err instanceof WireError);
    assert.equal(err.reason, WireReasonCode.MALFORMED);
    assert.ok(err.message.endsWith("rank of constraint 'egress' is 'everywhere', not 'none', 'internal' or 'any'"), err.message);
    return true;
  });
  assert.equal(unreadableBundle({ key: "max_rows", max: true }).failures[0],
    "root typed:n0: unreadable authority (max of constraint 'max_rows' is a boolean, not a number)");
});

test("a caller's _scope can never move a call to another meter", () => {
  const own = new Authority({ scopes: ["crm.read"], ceilings: [new CallLimit(1, "crm.read")] });
  assert.equal(own.permits("crm.read", { "calls[crm.read]": 2, _scope: "other.x" }).allowed, false);
  const other = new Authority({ scopes: ["crm.read"], ceilings: [new CallLimit(0, "other.*")] });
  assert.equal(other.permits("crm.read", { "calls[other.*]": 1, _scope: "other.x" }).allowed, true);
  const guard = Guard.issue("root", own);
  assert.equal(guard.check("crm.read").allowed, true);
  assert.equal(guard.check("crm.read").allowed, false);
  assert.equal(guard.check("crm.read", { context: { _scope: "other.x" } }).allowed, false);
  const chain = load([rootToken({ key: "max_calls[crm.read]", type: "max_calls", max: 1, applies_to: "crm.read" })], hs256);
  assert.equal(chain.permits("crm.read", { "calls[crm.read]": 2, _scope: "other.x" }).allowed, false);
  const recorded = Guard.issue("root", new Authority({ scopes: ["docs.write"], ceilings: [new CallLimit(1, "docs.write")] }), {
    chainId: "typed",
  });
  const root = recorded.auditLog().entries[0]!;
  recorded.auditLog().append("allow", 1, {
    chain_id: root["chain_id"]!, node: root["node"]!, scope: "docs.write", tool: null,
    context: { "calls[docs.write]": 5, _scope: "other.x" },
  });
  assert.deepEqual(verifyBundle(exportBundle(recorded.auditLog(), hs256), hs256).failures, [
    "containment: allow of 'docs.write' on typed:n0 outside its authority ['docs.write']",
  ]);
});

test("a key that is not a string is malformed on every constraint type", () => {
  // A number, null or a boolean key read String(key) here and a field no JSON context carries in
  // the Python implementation; an absent key loaded here and read the field "undefined".
  const cases: [Record<string, Json>, string][] = [
    [{ type: "allow", one_of: ["us"] }, "absent"], [{ key: 5, type: "allow", one_of: ["us"] }, "a number"],
    [{ key: null, type: "deny", not_one_of: ["rm"] }, "null"], [{ key: true, type: "prefix", prefix: "/" }, "a boolean"],
    [{ key: ["k"], type: "x-custom" }, "an array"], [{ key: { a: 1 }, type: "x-custom" }, "an object"],
    [{ type: "x-custom", v: 1 }, "absent"], [{ max: 5 }, "absent"],
  ];
  for (const [wire, kind] of cases) {
    assert.throws(() => ceilingFromWire(wire), { name: "TypeError", message: `key of a constraint is ${kind}, not a string` });
  }
  assert.throws(() => new Allow(5 as any, ["us"]), { name: "TypeError", message: "key of a constraint is a number, not a string" });
  assert.throws(() => new Deny(null as any, ["rm"]), { name: "TypeError", message: "key of a constraint is null, not a string" });
  assert.throws(() => new Prefix(true as any, "/"), { name: "TypeError", message: "key of a constraint is a boolean, not a string" });
  assert.throws(() => load([rootToken({ key: 5, type: "deny", not_one_of: ["rm"] })], hs256), (err: unknown) => {
    assert.ok(err instanceof WireError);
    assert.equal(err.reason, WireReasonCode.MALFORMED);
    assert.equal(err.message, "invalid authorization_details: key of a constraint is a number, not a string");
    return true;
  });
});

test("an applies_to that is not a scope is malformed", () => {
  for (const value of ["*", "crm", "CRM.READ", "", "crm.", ".crm.read", "crm.*.read", "crm read"]) {
    const message = `applies_to of constraint 'max_calls' is ${pyRepr(value)}, not a scope`;
    assert.throws(() => new CallLimit(3, value), { name: "TypeError", message });
    assert.throws(() => ceilingFromWire({ key: `max_calls[${value}]`, type: "max_calls", max: 3, applies_to: value }),
      { name: "TypeError", message });
  }
  for (const value of ["crm.read", "crm.*", "a.b-c.d_e"]) assert.equal(new CallLimit(3, value).key, `max_calls[${value}]`);
});

test("different ceiling types under one key are not narrower, and meet refuses them", () => {
  const pairs: [Ceiling, Ceiling][] = [
    [new Allow("region", ["us"]), new Deny("region", ["eu"])],
    [new Deny("region", ["eu"]), new Allow("region", ["us"])],
    [new Prefix("region", "u"), new Allow("region", ["us"])],
    [new RowLimit(5), ceilingFromWire({ key: "max_rows", type: "x-custom" })],
    [ceilingFromWire({ key: "max_rows", type: "x-custom" }), new RowLimit(5)],
    [new EgressRank("none"), ceilingFromWire({ key: "egress", type: "prefix", prefix: "n" })],
  ];
  for (const [parent, child] of pairs) {
    assert.equal(parent.subsumes(child), false, parent.key);
    const p = new Authority({ scopes: ["crm.read"], ceilings: [parent], ttl: 60 });
    const c = new Authority({ scopes: ["crm.read"], ceilings: [child], ttl: 60 });
    assert.equal(c.isNarrowerThan(p), false, parent.key);
    assert.throws(() => p.meet(c), {
      name: "TypeError",
      message: `constraint ${pyRepr(parent.key)} has a different ceiling type on each side; neither narrows the other`,
    });
  }
  assert.throws(() => load(tokens({ key: "region", type: "allow", one_of: ["us"] }, { key: "region", type: "deny", not_one_of: ["eu"] }), hs256),
    (err: unknown) => err instanceof WireError && err.reason === WireReasonCode.NOT_NARROWER);
  // It threw TypeError out of verifyBundle; the Python implementation raised AttributeError.
  const report = unreadableBundle({ key: "tier", type: "allow", one_of: [1] }, { key: "tier", type: "deny", not_one_of: [2] });
  assert.equal(report.checks.monotonicity, false);
  assert.deepEqual(report.failures,
    ["monotonicity: typed:n1 not ⊆ parent typed:n0 (ceiling tier not in [2] looser than parent tier in [1])"]);
});

