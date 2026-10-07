/**
 * The findings of the independent security review of the -02 implementation (spec/02-impl,
 * 2026-10-07), case for case the Python reference implementation's
 * tests/test_draft02_review_fixes.py. Numbering follows the review.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Authority, AuthorityError } from "../src/authority.js";
import { toPlain, type Json } from "../src/canonical.js";
import { Allow, CallLimit, RowLimit, type Ceiling } from "../src/ceilings.js";
import * as d from "../src/draft02.js";
import { Guard } from "../src/guard.js";
import { HS256TestSigner, WireError, WireReasonCode, load, type LoadOptions } from "../src/wire.js";
import { mintChain02, payloadOf, repair as repairWith, resign as resignWith, type Mint02Options } from "./mint02.js";

const SECRET = Buffer.from("review-fixes-fixed-secret");
const PRINCIPAL = "acct:finance-ops@example.com";
const AUD = "https://crm.example.com";

const signer = (): HS256TestSigner => new HS256TestSigner(SECRET, "test");
const cnf = (g: Guard) => ({ jkt: `thumb-${g.agentId}` });
const resign = (token: string, mutate: (p: Record<string, any>) => void) => resignWith(token, mutate, signer());
const repair = (tokens: readonly string[]) => repairWith(tokens, signer());

function A02(scopes: string[], ceilings: Ceiling[] = [], ttl = 600): Authority {
  return new Authority({ scopes, ceilings, ttl, profile: "02" });
}

function chain02(): Guard[] {
  const root = Guard.issue("orchestrator", A02(["crm.*"], [new RowLimit(100), new CallLimit(10)], 3600), { maxDepth: 4 });
  const child = root.delegate("summarizer", A02(["crm.read"], [new RowLimit(10), new CallLimit(5)], 900), "t");
  const leaf = child.delegate("formatter", A02(["crm.read"], [new RowLimit(5), new CallLimit(2)], 300), "t");
  return [root, child, leaf];
}

function mint02(path: Guard[], options: Partial<Mint02Options> = {}): string[] {
  return mintChain02(path, signer(), { principal: PRINCIPAL, aud: AUD, cnf, maxDepth: 4, ...options });
}

function reject(tokens: readonly string[], reason: string, options: LoadOptions = {}): WireError {
  try {
    load(tokens, signer(), { draft: "02", ...options });
  } catch (e) {
    assert.ok(e instanceof WireError, `expected a WireError, got ${String(e)}`);
    assert.equal(e.reason, reason, e.message);
    return e;
  }
  assert.fail(`expected ${reason}, the chain verified`);
}

// ---- 1 BLOCKER: a subtree bound is never fed from a node meter ---------------

test("review 1: six calls under a subtree bound of two are all denied when no total is held", () => {
  const root = Guard.issue("root", A02(["a.b"], [new d.MaxSubtree("max_calls", 2)]));
  const k1 = root.delegate("k1", A02(["a.b"], [new d.MaxSubtree("max_calls", 2)]), "t");
  const k2 = root.delegate("k2", A02(["a.b"], [new d.MaxSubtree("max_calls", 2)]), "t");
  const allowed = [root, k1, k2].flatMap((g) => [g.check("a.b").allowed, g.check("a.b").allowed]);
  assert.equal(allowed.filter(Boolean).length, 0, "a subtree total the guard does not hold must deny");
});

test("review 1: a subtree total supplied through the trusted channel is enforced", () => {
  const root = Guard.issue("root", A02(["a.b"], [new d.MaxSubtree("max_calls", 2)]));
  assert.ok(root.check("a.b", { totals: { calls_subtree_total: 2 } }).allowed);
  assert.equal(root.check("a.b", { totals: { calls_subtree_total: 3 } }).allowed, false);
});

test("review 1: the lifetime call bound is still metered by the guard", () => {
  const root = Guard.issue("root", A02(["a.b"], [new CallLimit(2)]));
  assert.deepEqual([1, 2, 3].map(() => root.check("a.b").allowed), [true, true, false]);
  const g2 = Guard.issue("root2", Authority.fromWire(root.authority.toWire(), "02"));
  assert.deepEqual([1, 2, 3].map(() => g2.check("a.b").allowed), [true, true, false]);
});

// ---- 2 MAJOR: the audience is not opt-in at step 8 ---------------------------

test("review 2: permits denies when no audience was ever supplied", () => {
  const v = load(mint02(chain02()), signer(), { draft: "02" });
  const denied = v.permits("crm.read", { rows: 1 }, { totals: { calls: 1 } });
  assert.equal(denied.allowed, false);
  assert.equal(denied.reasons[0]!.code, WireReasonCode.AUDIENCE_MISMATCH);
  assert.ok(v.permits("crm.read", { rows: 1 }, { totals: { calls: 1 }, audience: AUD }).allowed);
});

test("review 2: an audience confirmed at load carries into permits", () => {
  const v = load(mint02(chain02()), signer(), { draft: "02", audience: AUD });
  assert.ok(v.permits("crm.read", { rows: 1 }, { totals: { calls: 1 } }).allowed);
  assert.equal(v.permits("crm.read", { rows: 1 }, { totals: { calls: 1 }, audience: "https://evil.example" }).allowed, false);
});

test("review 2: the default profile is unchanged", () => {
  const root = Guard.issue("o", new Authority({ scopes: ["crm.read"], ttl: 60 }), { maxDepth: 2 });
  const tokens = mintChain02([root], signer(), { principal: PRINCIPAL, aud: AUD, cnf, maxDepth: 2 });
  assert.ok(load(tokens, signer()).permits("crm.read").allowed);
});

// ---- 3 MAJOR: running totals never come from the caller's context -------------

test("review 3: a total in the caller context is ignored and the bound denies", () => {
  const g = Guard.issue("r2", A02(["pay.send"], [new d.MaxLifetime("max_spend", 100)]));
  assert.equal(g.check("pay.send", { context: { spend: 1_000_000, spend_total: 0 } }).allowed, false);
  assert.equal(g.check("pay.send", { context: { spend: 1, spend_total: 0 } }).allowed, false);
});

test("review 3: totals come only from the trusted parameter", () => {
  const g = Guard.issue("r2", A02(["pay.send"], [new d.MaxLifetime("max_spend", 100)]));
  assert.ok(g.check("pay.send", { context: { spend: 1 }, totals: { spend_total: 99 } }).allowed);
  assert.equal(g.check("pay.send", { context: { spend: 1 }, totals: { spend_total: 101 } }).allowed, false);
  // The caller's copy of the key never shadows the trusted one.
  assert.equal(g.check("pay.send", { context: { spend: 1, spend_total: 0 }, totals: { spend_total: 101 } }).allowed, false);
  assert.ok(g.wouldAllow("pay.send", { context: { spend: 1 }, totals: { spend_total: 99 } }).allowed);
});

test("review 3: the same on a verified chain", () => {
  const root = Guard.issue("o", A02(["pay.send"], [new d.MaxLifetime("max_spend", 100)]), { maxDepth: 2 });
  const v = load(mint02([root], { maxDepth: 2 }), signer(), { draft: "02", audience: AUD });
  assert.equal(v.permits("pay.send", { spend: 1, spend_total: 0 }).allowed, false);
  assert.ok(v.permits("pay.send", { spend: 1 }, { totals: { spend_total: 50 } }).allowed);
});

test("review 3: Authority.permits strips totals from the context under -02", () => {
  const a = A02(["a.b"], [new d.MaxSubtree("max_spend", 10)]);
  assert.equal(a.permits("a.b", { spend_subtree_total: 1 }).allowed, false);
  assert.ok(a.permits("a.b", {}, { totals: { spend_subtree_total: 10 } }).allowed);
});

// ---- 4 MAJOR: newline scopes --------------------------------------------------

test("review 4: a trailing newline is not a literal scope", () => {
  for (const s of ["crm.read\n", "crm.*\n", "User.Read\n", "crm.read\r"]) assert.equal(d.classifyScope(s), null, JSON.stringify(s));
});

test("review 4: a chain carrying a newline scope is malformed", () => {
  const tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => (p["authorization_details"][0]["scopes"] = ["crm.read\n"]));
  reject(tokens, WireReasonCode.MALFORMED);
});

// ---- 5 MAJOR: the default path is behaviour-identical to main ----------------

test("review 5: a -01 chain with client_id and per-hop sub verifies under -01", () => {
  const root = Guard.issue("orchestrator", new Authority({ scopes: ["crm.*"], ttl: 600 }), { maxDepth: 3 });
  const child = root.delegate("summarizer", new Authority({ scopes: ["crm.read"], ttl: 300 }), "t");
  const tokens = mintChain02([root, child], signer(), { principal: PRINCIPAL, aud: AUD, cnf, maxDepth: 3 });
  tokens[0] = resign(tokens[0]!, (p) => (p["sub"] = "orchestrator"));
  tokens[1] = resign(tokens[1]!, (p) => (p["sub"] = "summarizer"));
  const repaired = repair(tokens);
  assert.notEqual(payloadOf(repaired[0]!)["sub"], payloadOf(repaired[1]!)["sub"], "precondition: per-hop sub");
  assert.ok(load(repaired, signer()));
});

test("review 5: the -02 profile still denies an altered principal", () => {
  const tokens = mint02(chain02());
  tokens[1] = resign(tokens[1]!, (p) => (p["sub"] = "acct:mallory"));
  reject(repair(tokens), WireReasonCode.PRINCIPAL_ALTERED);
});

// ---- 6 MAJOR: outcome names follow Table 2 -------------------------------------

test("review 6: an altered sub with a broken par_hash is par_hash_mismatch", () => {
  const tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => {
    p["sub"] = "acct:mallory";
    p["par_hash"] = "AAAA";
  });
  reject(tokens, WireReasonCode.PAR_HASH_MISMATCH);
});

test("review 6: a child exp past its parent's with the same iat is expired", () => {
  const tokens = mint02(chain02());
  const parentExp = toPlain<number>(payloadOf(tokens[1]!)["exp"]);
  tokens[2] = resign(tokens[2]!, (p) => (p["exp"] = parentExp + 10));
  reject(tokens, WireReasonCode.EXPIRED);
});

test("review 6: a child raising del_max_depth is not narrower; an equal bound is fine", () => {
  const rootMax = toPlain<number>(payloadOf(mint02(chain02())[0]!)["del_max_depth"]);
  let tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => (p["del_max_depth"] = rootMax + 50));
  reject(tokens, WireReasonCode.NOT_NARROWER);
  tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => (p["del_max_depth"] = rootMax));
  assert.ok(load(tokens, signer(), { draft: "02" }), "an equal bound is fine");
  for (const bad of [0, -1, 2.5, "3", true]) {
    tokens = mint02(chain02());
    tokens[2] = resign(tokens[2]!, (p) => (p["del_max_depth"] = bad));
    reject(tokens, WireReasonCode.MALFORMED);
  }
});

// ---- 7 MINOR: cnf needs a confirmation member -----------------------------------

test("review 7: a cnf object without a confirmation member is malformed", () => {
  const tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => (p["cnf"] = { note: "x" }));
  assert.match(reject(tokens, WireReasonCode.MALFORMED).message, /cnf/);
});

test("review 7: jkt, jwk and x5t#S256 are accepted", () => {
  const cnfs: Record<string, Json>[] = [{ jkt: "t" }, { jwk: { kty: "OKP", crv: "Ed25519", x: "AA" } }, { "x5t#S256": "t" }];
  for (const c of cnfs) {
    assert.ok(load(mint02(chain02(), { cnf: c }), signer(), { draft: "02" }));
  }
});

// ---- 8 MINOR: acceptedAlgs is an array of strings --------------------------------

test("review 8: a bare string or a non-string member is refused as configuration", () => {
  const tokens = mint02(chain02());
  assert.throws(() => load(tokens, signer(), { draft: "02", acceptedAlgs: "HS256" as never }), TypeError);
  assert.throws(() => load(tokens, signer(), { draft: "02", acceptedAlgs: ["HS256", 5] as never }), TypeError);
});

// ---- 9 MINOR: mixed profiles are a refused delegation ------------------------------

test("review 9: meet raises AuthorityError not_narrower", () => {
  assert.throws(
    () => A02(["a.b"]).meet(new Authority({ scopes: ["a.b"], ttl: 600 })),
    (e: unknown) => e instanceof AuthorityError && e.reason === "not_narrower",
  );
});

test("review 9: Guard.delegate records spawn_denied", () => {
  const root = Guard.issue("root", A02(["a.b"]));
  assert.throws(() => root.delegate("kid", new Authority({ scopes: ["a.b"], ttl: 600 }), "t"), AuthorityError);
  assert.ok(root.auditLog().entries.some((e) => e["event"] === "spawn_denied"));
});

// ---- round 2 ------------------------------------------------------------------

test("round 2: an ordinary constraint keyed with _total still reads its field", () => {
  const a = A02(["shop.buy"], [new d.Max("order_total", 100)]);
  assert.equal(a.permits("shop.buy", { order_total: 1_000_000 }).allowed, false);
  assert.ok(a.permits("shop.buy", { order_total: 50 }).allowed);
  const g = Guard.issue("g", a, { strictMetering: true });
  assert.equal(g.check("shop.buy", { context: { order_total: 1_000_000 }, metered: true }).allowed, false);
  assert.ok(g.check("shop.buy", { context: { order_total: 50 }, metered: true }).allowed);
});

test("round 2: strict metering and evaluation read the same context", () => {
  const a = A02(["pay.send"], [new d.MaxLifetime("max_spend", 100), new d.Max("max_spend", 10)]);
  const g = Guard.issue("g", a, { strictMetering: true });
  assert.equal(g.check("pay.send", { context: { spend: 1, spend_total: 5 }, metered: true }).allowed, false);
  assert.ok(g.check("pay.send", { context: { spend: 1 }, totals: { spend_total: 5 }, metered: true }).allowed);
});

test("round 2: only held cumulative fields are cumulative", () => {
  const a = A02(["a.b"], [new d.MaxLifetime("max_spend", 100), new Allow("region_total", ["eu"])]);
  assert.ok(a.permits("a.b", { region_total: "eu" }, { totals: { spend_total: 1 } }).allowed);
  assert.equal(a.permits("a.b", { region_total: "us" }, { totals: { spend_total: 1 } }).allowed, false);
});

test("round 2 A: a per-action max on a count key is refused at construction and at load", () => {
  for (const key of ["max_calls", "max_calls[fs.write]"]) {
    assert.throws(() => new d.Max(key, 1), TypeError, key);
    assert.throws(() => d.ceilingFromWire02({ key, max: 1 }), TypeError, key);
  }
  const tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => p["authorization_details"][0]["constraints"].push({ key: "max_calls[x.y]", max: 1 }));
  reject(tokens, WireReasonCode.MALFORMED);
});

test("round 2 B: a caller-supplied calls cannot override the meter under -02", () => {
  const root = Guard.issue("root", A02(["a.b"], [new CallLimit(2)]));
  assert.ok(root.check("a.b", { context: { calls: 0 } }).allowed);
  assert.ok(root.check("a.b", { context: { calls: 0 } }).allowed);
  assert.equal(root.check("a.b", { context: { calls: 0 } }).allowed, false, "the third call is the meter's third");
  assert.equal(root.check("a.b", { totals: { calls: 0 } }).allowed, false, "nor through totals, in-process");
});

test("round 2 B: the default profile still honours a declared calls", () => {
  const root = Guard.issue("root", new Authority({ scopes: ["a.b"], ceilings: [new CallLimit(2)], ttl: 60 }));
  assert.ok(root.check("a.b", { context: { calls: 1 } }).allowed);
  assert.equal(root.check("a.b", { context: { calls: 3 } }).allowed, false);
});

test("round 2 C: an unheld totals key is loud", () => {
  const a = A02(["a.b"], [new d.MaxLifetime("max_spend", 100), new d.Max("order_total", 5)]);
  assert.throws(() => a.permits("a.b", {}, { totals: { order_total: 0 } }), TypeError); // a per-action field, not a total
  assert.throws(() => a.permits("a.b", {}, { totals: { rows_total: 0 } }), TypeError); // nothing held reads it
  assert.ok(a.permits("a.b", { order_total: 1 }, { totals: { spend_total: 1 } }).allowed);
});

test("round 2 C: the same on the guard and a verified chain", () => {
  const g = Guard.issue("g", A02(["a.b"], [new d.MaxLifetime("max_spend", 100)]));
  assert.throws(() => g.check("a.b", { totals: { spend: 0 } }), TypeError);
  const root = Guard.issue("o", A02(["a.b"], [new d.MaxLifetime("max_spend", 100)]), { maxDepth: 2 });
  const v = load(mint02([root], { maxDepth: 2 }), signer(), { draft: "02", audience: AUD });
  assert.throws(() => v.permits("a.b", null, { totals: { calls: 0 } }), TypeError);
});

test("round 2 D: a bad depth beside an altered sub is depth_invalid", () => {
  const tokens = mint02(chain02());
  tokens[2] = resign(tokens[2]!, (p) => {
    p["sub"] = "acct:mallory";
    p["del_depth"] = 7;
  });
  reject(tokens, WireReasonCode.DEPTH_INVALID);
});

// ---- round 3: two namespaces, never merged --------------------------------------

test("round 3 X1: a total never overwrites a request quantity", () => {
  const a = A02(["shop.buy"], [new d.MaxLifetime("spend", 1000), new d.Max("spend_total", 10)]);
  assert.equal(a.permits("shop.buy", { spend_total: 1_000_000 }, { totals: { spend_total: 0 } }).allowed, false);
  assert.ok(a.permits("shop.buy", { spend_total: 5 }, { totals: { spend_total: 0 } }).allowed);
  const g = Guard.issue("g", a);
  assert.equal(g.check("shop.buy", { context: { spend_total: 1_000_000 }, totals: { spend_total: 0 } }).allowed, false);
});

test("round 3 X2: the meter never replaces a request quantity", () => {
  const g = Guard.issue("g", A02(["a.b"], [new d.MaxLifetime("max_calls", 100), new d.Max("calls", 5)]));
  assert.equal(g.check("a.b", { context: { calls: 1000 } }).allowed, false);
  assert.ok(g.check("a.b", { context: { calls: 3 } }).allowed);
});

test("round 3: a request value never satisfies a cumulative bound", () => {
  const a = A02(["a.b"], [new d.MaxLifetime("spend", 100)]);
  assert.equal(a.permits("a.b", { spend_total: 1 }).allowed, false, "the request cannot assert its own total");
  assert.ok(a.permits("a.b", { spend_total: 1_000_000 }, { totals: { spend_total: 1 } }).allowed);
});

test("round 3: namespaces do not collide for any field name (500 trials)", () => {
  // A small seeded PRNG (mulberry32).
  let s = 3;
  const next = (): number => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)]!;
  const names = ["spend", "spend_total", "calls", "rows", "x_total", "x_subtree_total", "max_rows", "max_spend"];
  for (let i = 0; i < 500; i++) {
    const perKey = pick(names);
    const cumKey = pick(["spend", "max_spend", "max_calls", "x", "rows"]);
    const cum = next() < 0.5 ? new d.MaxLifetime(cumKey, 10) : new d.MaxSubtree(cumKey, 10);
    const per = new d.Max(perKey, 10);
    const a = A02(["a.b"], [cum, per]);
    const pf = per.ctxField;
    const cf = cum.ctxField;
    const label = `${per.describe()} ${cum.describe()}`;
    // A satisfying total in the request and no trusted total: the cumulative bound denies.
    assert.equal(a.permits("a.b", { [cf]: 1 }).allowed, false, label);
    // A violating request value beside a satisfying trusted total: the per-action bound denies.
    assert.equal(a.permits("a.b", { [pf]: 1000 }, { totals: { [cf]: 1 } }).allowed, false, label);
    // A satisfying request value beside a violating trusted total: the cumulative bound denies.
    assert.equal(a.permits("a.b", { [pf]: 1 }, { totals: { [cf]: 1000 } }).allowed, false, label);
    // Both satisfied, each in its own namespace: allowed.
    assert.ok(a.permits("a.b", { [pf]: 1 }, { totals: { [cf]: 1 } }).allowed, label);
  }
});

test("round 3: totals under the default profile is refused", () => {
  assert.throws(
    () => new Authority({ scopes: ["a.b"], ceilings: [new CallLimit(2)], ttl: 60 }).permits("a.b", {}, { totals: { calls: 1 } }),
    TypeError,
  );
  // ...and an empty totals is no totals, on either profile.
  assert.ok(new Authority({ scopes: ["a.b"], ttl: 60 }).permits("a.b", {}, { totals: {} }).allowed);
});
