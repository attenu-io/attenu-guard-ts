/**
 * The -02 profile of the offline verification algorithm (draft-asor-wimse-agent-delegation-chain-02,
 * Sections 3, 4.4, 6 and 6.2), opted into with `load(tokens, signer, { draft: "02" })`.
 *
 * Case for case, the Python reference implementation's tests/test_wire_02.py, minus its minting
 * cases: this library mints nothing, so the chains here come from the test-only minter in
 * mint02.ts. Every rule is paired with an assertion that the DEFAULT path ("01") is unchanged.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { toPlain } from "../src/canonical.js";
import { CallLimit, EgressRank, RowLimit, SpendCap } from "../src/ceilings.js";
import * as d from "../src/draft02.js";
import { Guard } from "../src/guard.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlDecode, b64urlEncode, load, type LoadOptions } from "../src/wire.js";
import { fixtureJson } from "./helpers.js";
import { mintChain02, payloadOf, repair as repairWith, resign as resignWith, signParts, type Mint02Options } from "./mint02.js";

const SECRET = Buffer.from("test-wire-02-fixed-secret");
const PRINCIPAL = "acct:finance-ops@example.com";
const AUD = "https://crm.example.com";
const ORDER = ["none", "internal", "any"];

const signer = (): HS256TestSigner => new HS256TestSigner(SECRET, "test");
const cnf = (g: Guard) => ({ jkt: `thumb-${g.agentId}` });
const resign = (token: string, mutate: (p: Record<string, any>) => void) => resignWith(token, mutate, signer());
const repair = (tokens: readonly string[]) => repairWith(tokens, signer());

function chain(): Guard[] {
  const A = (scopes: string[], ceilings: any[], ttl: number) => new Authority({ scopes, ceilings, ttl, profile: "02" });
  const root = Guard.issue(
    "orchestrator",
    A(["crm.*", "mail.send", "User.Read"], [new RowLimit(1000), new EgressRank("any"), new CallLimit(10), new SpendCap(100)], 3600),
    { maxDepth: 4 },
  );
  const child = root.delegate(
    "summarizer",
    A(["crm.read", "User.Read"], [new RowLimit(100), new EgressRank("internal"), new CallLimit(5), new SpendCap(60)], 900),
    "summarize",
  );
  const leaf = child.delegate(
    "formatter",
    A(["crm.read"], [new RowLimit(10), new EgressRank("none"), new CallLimit(2), new SpendCap(10)], 300),
    "format",
  );
  return [root, child, leaf];
}

function mint(path: Guard[] = chain(), options: Partial<Mint02Options> = {}): string[] {
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

function leafDetail(tokens: readonly string[], mutate: (detail: Record<string, any>) => void): string[] {
  const out = [...tokens];
  out[2] = resign(out[2]!, (p) => mutate(p["authorization_details"][0]));
  return out;
}

// ---- the claim layout ------------------------------------------------------

test("-02 wire: a minted chain carries the -02 claim layout and verifies", () => {
  const tokens = mint();
  const payloads = tokens.map((t) => payloadOf(t) as Record<string, any>);
  assert.deepEqual(payloads.map((p) => p["sub"]), [PRINCIPAL, PRINCIPAL, PRINCIPAL]);
  assert.deepEqual(payloads.map((p) => p["client_id"]), ["orchestrator", "summarizer", "formatter"]);
  const constraints = JSON.stringify(payloads[0]!["authorization_details"][0]["constraints"]);
  assert.ok(constraints.includes(JSON.stringify({ key: "egress", order: ORDER, rank: "any" })));
  assert.ok(constraints.includes('{"key":"max_calls","max_lifetime":10}'));
  const v = load(tokens, signer(), { draft: "02", audience: AUD });
  assert.equal(v.draft, "02");
  assert.equal(v.audience, AUD);
  assert.deepEqual([...v.leafAuthority.scopes], ["crm.read"]);
  assert.equal(v.leafAuthority.profile, "02");
});

test("-02 wire: a default-profile authority is re-expressed under -02", () => {
  const root = Guard.issue("o", new Authority({ scopes: ["crm.*"], ceilings: [new CallLimit(3), new EgressRank("internal")], ttl: 60 }), { maxDepth: 2 });
  const tokens = mint([root], { maxDepth: 2 });
  assert.deepEqual(toPlain<any>(payloadOf(tokens[0]!))["authorization_details"][0]["constraints"], [
    { key: "egress", order: ORDER, rank: "internal" },
    { key: "max_calls", max_lifetime: 3 },
  ]);
  assert.ok(load(tokens, signer(), { draft: "02" }).leafAuthority.ceilings[0] instanceof d.Rank);
});

// ---- Section 3: every claim rule is malformed, before step 1 ---------------

test("-02 wire: missing client_id is malformed", () => {
  const tokens = mint();
  tokens[1] = resign(tokens[1]!, (p) => delete p["client_id"]);
  // The child's signing input changed, so repair the grandchild's commitment: the rule under
  // test must be the only thing wrong.
  assert.match(reject(repair(tokens), WireReasonCode.MALFORMED).message, /client_id/);
});

test("-02 wire: aud null, missing, empty or non-string is malformed", () => {
  const mutations: ((p: Record<string, any>) => void)[] = [
    (p) => (p["aud"] = null),
    (p) => delete p["aud"],
    (p) => (p["aud"] = []),
    (p) => (p["aud"] = [1]),
  ];
  for (const mutate of mutations) {
    const tokens = mint();
    tokens[2] = resign(tokens[2]!, mutate);
    assert.match(reject(tokens, WireReasonCode.MALFORMED).message, /aud/);
  }
});

test("-02 wire: an audience array is accepted and checked", () => {
  const tokens = mint(chain(), { aud: ["https://a.example", AUD] });
  assert.ok(load(tokens, signer(), { draft: "02", audience: AUD }));
  assert.ok(load(tokens, signer(), { draft: "02" })); // no audience given: not checked
  reject(tokens, WireReasonCode.AUDIENCE_MISMATCH, { audience: "https://other.example" });
});

test("-02 wire: audience mismatch at load and in permits", () => {
  const tokens = mint();
  reject(tokens, WireReasonCode.AUDIENCE_MISMATCH, { audience: "https://other.example" });
  const v = load(tokens, signer(), { draft: "02" });
  const ctx = { rows: 1, spend: 1 };
  const denied = v.permits("crm.read", ctx, { totals: { calls: 1 }, audience: "https://other.example" });
  assert.equal(denied.allowed, false);
  assert.equal(denied.reasons[0]!.code, WireReasonCode.AUDIENCE_MISMATCH);
  assert.ok(v.permits("crm.read", ctx, { totals: { calls: 1 }, audience: AUD }).allowed);
});

test("-02 wire: the audience is not checked under -01", () => {
  const root = Guard.issue("o", new Authority({ scopes: ["crm.read"], ttl: 60 }), { maxDepth: 2 });
  const tokens = mintChain02([root], signer(), { principal: PRINCIPAL, aud: AUD, cnf, maxDepth: 2 });
  // A -02-shaped token with no -02 constraint shapes in it verifies under -01 too; the audience
  // option is a -02 rule there, so it is not applied.
  assert.ok(load(tokens, signer(), { audience: "https://other.example" }));
});

test("-02 wire: missing cnf on any token is malformed", () => {
  for (let i = 0; i < 3; i++) {
    const tokens = mint();
    tokens[i] = resign(tokens[i]!, (p) => delete p["cnf"]);
    assert.match(reject(repair(tokens), WireReasonCode.MALFORMED).message, /cnf/);
  }
});

test("-02 wire: principal altered, and an empty root principal", () => {
  const tokens = mint();
  const forged = [...tokens];
  forged[1] = resign(tokens[1]!, (p) => (p["sub"] = "acct:someone-else"));
  reject(repair(forged), WireReasonCode.PRINCIPAL_ALTERED);
  const stripped = [...tokens];
  stripped[0] = resign(tokens[0]!, (p) => (p["sub"] = ""));
  assert.match(reject(repair(stripped), WireReasonCode.MALFORMED).message, /sub/);
});

test("-01 wire: principal invariance is a -02 rule; the default path does not apply it", () => {
  // A chain with no -02 constraint shapes verifies under -01 whatever its sub and client_id say:
  // the -01 algorithm is unchanged, and under it `sub` is the agent id and differs per hop.
  const root = Guard.issue("o", new Authority({ scopes: ["crm.*"], ttl: 60 }), { maxDepth: 3 });
  const child = root.delegate("c", new Authority({ scopes: ["crm.read"], ttl: 30 }), "t");
  const tokens = mintChain02([root, child], signer(), { principal: PRINCIPAL, aud: AUD, cnf, maxDepth: 3 });
  const forged = [...tokens];
  forged[1] = resign(tokens[1]!, (p) => (p["sub"] = "acct:someone-else"));
  assert.ok(load(forged, signer()));
  reject(forged, WireReasonCode.PRINCIPAL_ALTERED);
});

test("-02 wire: parse rules precede the signature check, so the root is covered", () => {
  // A root carrying a detail type the verifier does not implement is malformed even when its
  // signature is also wrong: the -02 classifies at parse, before step 1.
  const tokens = mint();
  const bad = resign(tokens[0]!, (p) => (p["authorization_details"][0]["type"] = "acme_policy"));
  const [h, pl, sig] = bad.split(".") as [string, string, string];
  const corrupted = `${h}.${pl}.${b64urlEncode(Buffer.from(b64urlDecode(sig).map((b) => b ^ 0xff)))}`;
  assert.match(reject([corrupted], WireReasonCode.MALFORMED).message, /agent_delegation/);
});

test("-02 wire: the -01 vectors are malformed under -02 and unchanged under -01", () => {
  const names = [
    "valid_chain", "reject_widened_scope", "reject_exceeded_ceiling", "reject_spliced_parent", "reject_depth_exceeded",
    "reject_nonmonotonic_exp", "reject_bad_signature", "reject_wildcard_widening", "reject_wildcard_boundary",
    "reject_bare_wildcard", "reject_nonterminal_wildcard", "valid_jcs_integral_float", "valid_jcs_exponent_form",
    "valid_jcs_non_ascii", "valid_jcs_utf16_key_order", "valid_jcs_big_integer", "reject_non_finite",
    "reject_duplicate_member", "valid_jcs_unmarked_header", "reject_unsafe_integer",
  ];
  for (const name of names) {
    const v = fixtureJson<any>(`vectors/${name}.json`);
    const s = new HS256TestSigner(Buffer.from(v.signer.secret_hex, "hex"), v.signer.kid);
    // JSON-level rejections keep their own Table 2 names, since parsing precedes the -02 claim
    // checks; every other -01 vector lacks client_id and cnf, so it is malformed.
    assert.throws(
      () => load(v.tokens, s, { now: v.now, draft: "02" }),
      (e: unknown) =>
        e instanceof WireError &&
        [WireReasonCode.MALFORMED, WireReasonCode.NON_FINITE, WireReasonCode.DUPLICATE_MEMBER].includes(e.reason as never),
      name,
    );
    let outcome = "accept";
    try {
      load(v.tokens, s, { now: v.now });
    } catch (e) {
      outcome = (e as WireError).reason;
    }
    assert.equal(outcome, v.expect ?? v.expect_reject_reason, name);
  }
});

test("-02 wire: an -02 chain is malformed under the default profile", () => {
  // The -02 constraint shapes (`order`, `max_lifetime`) are members the -01 verifier does not
  // read, and it refuses what it cannot evaluate. No transition mode (draft -02 3.1).
  reject(mint(), WireReasonCode.MALFORMED, { draft: "01" });
});

test("-02 wire: an unknown draft is refused", () => {
  assert.throws(() => load(mint(), signer(), { draft: "03" as never }), TypeError);
});

// ---- step 1: the accepted-algorithm list -----------------------------------

test("-02 wire: an alg off the list is denied even though its signature verifies", () => {
  const tokens = mint();
  const e = reject(tokens, WireReasonCode.SIGNATURE_INVALID, { acceptedAlgs: ["EdDSA", "ES256"] });
  assert.match(e.message, /accepted list/);
  assert.ok(load(tokens, signer(), { draft: "02", acceptedAlgs: ["HS256", "EdDSA"] }));
  assert.ok(load(tokens, signer(), { draft: "02" })); // defaults to the signer's own
});

test("-01 wire: the accepted-algorithm list is honoured only when given", () => {
  const v = fixtureJson<any>("vectors/valid_chain.json");
  const s = new HS256TestSigner(Buffer.from(v.signer.secret_hex, "hex"), v.signer.kid);
  assert.ok(load(v.tokens, s));
  assert.throws(
    () => load(v.tokens, s, { acceptedAlgs: ["EdDSA"] }),
    (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.SIGNATURE_INVALID,
  );
});

// ---- the authority rules on the wire ---------------------------------------

test("-02 wire: opaque scopes round-trip and narrow by byte identity", () => {
  const root = Guard.issue("o", new Authority({ scopes: ["User.Read", "repo:status"], ttl: 60, profile: "02" }), { maxDepth: 3 });
  const child = root.delegate("c", new Authority({ scopes: ["repo:status"], ttl: 30, profile: "02" }), "t");
  const v = load(mint([root, child]), signer(), { draft: "02", audience: AUD });
  assert.deepEqual([...v.leafAuthority.scopes], ["repo:status"]);
  assert.ok(v.permits("repo:status").allowed);
  assert.equal(v.permits("User.Read").allowed, false);
});

test("-02 wire: Kieran Sweeney's cases", () => {
  reject(leafDetail(mint(), (det) => (det["scopes"] = ["crm.Read"])), WireReasonCode.NOT_NARROWER);
  const root = Guard.issue("o", new Authority({ scopes: ["drive.Read"], ttl: 60, profile: "02" }), { maxDepth: 3 });
  const child = root.delegate("c", new Authority({ scopes: ["drive.Read"], ttl: 30, profile: "02" }), "t");
  for (const scopes of [["drive.*"], ["drive.read"]]) {
    const tokens = mint([root, child]);
    tokens[1] = resign(tokens[1]!, (p) => (p["authorization_details"][0]["scopes"] = scopes));
    reject(tokens, WireReasonCode.NOT_NARROWER);
  }
  assert.ok(load(mint(), signer(), { draft: "02" })); // crm.* covers crm.read
});

test("-02 wire: invalid scopes are malformed", () => {
  for (const bad of ["*", "crm.*.read", "User.*", "crm.re*"]) {
    reject(leafDetail(mint(), (det) => (det["scopes"] = [bad])), WireReasonCode.MALFORMED);
  }
});

test("-02 wire: cumulative bounds narrow only and never cross types", () => {
  reject(
    leafDetail(mint(), (det) => {
      for (const c of det["constraints"]) if ("max_lifetime" in c) c["max_lifetime"] = 50;
    }),
    WireReasonCode.NOT_NARROWER,
  );
  // A lifetime bound where the parent holds a per-action `max` on the same key: no inference.
  reject(
    leafDetail(mint(), (det) => {
      const i = det["constraints"].findIndex((c: any) => c["key"] === "max_spend");
      det["constraints"][i] = { key: "max_spend", max_lifetime: 1 };
    }),
    WireReasonCode.NOT_NARROWER,
  );
  // max_subtree narrows like the others once both hold it.
  const root = Guard.issue("o", new Authority({ scopes: ["a.b"], ceilings: [new d.MaxSubtree("spend", 100)], ttl: 60, profile: "02" }), { maxDepth: 3 });
  const child = root.delegate("c", new Authority({ scopes: ["a.b"], ceilings: [new d.MaxSubtree("spend", 40)], ttl: 30, profile: "02" }), "t");
  const ok = mint([root, child]);
  assert.ok(load(ok, signer(), { draft: "02" }));
  const wider = [...ok];
  wider[1] = resign(ok[1]!, (p) => (p["authorization_details"][0]["constraints"][0]["max_subtree"] = 400));
  reject(wider, WireReasonCode.NOT_NARROWER);
});

test("-02 wire: a cumulative constraint with no total held denies at step 8", () => {
  const v = load(mint(), signer(), { draft: "02", audience: AUD });
  assert.equal(v.permits("crm.read", { rows: 1, spend: 1 }).allowed, false, "no `calls` total: deny");
  assert.ok(v.permits("crm.read", { rows: 1, spend: 1 }, { totals: { calls: 2 } }).allowed);
  assert.equal(v.permits("crm.read", { rows: 1, spend: 1 }, { totals: { calls: 3 } }).allowed, false);
});

test("-02 wire: rank ordering rules", () => {
  const ranks = (det: Record<string, any>) => det["constraints"].filter((c: any) => "rank" in c);
  reject(leafDetail(mint(), (det) => ranks(det).forEach((c: any) => (c["order"] = ["none", "any"]))), WireReasonCode.NOT_NARROWER);
  reject(leafDetail(mint(), (det) => ranks(det).forEach((c: any) => delete c["order"])), WireReasonCode.MALFORMED);
  reject(leafDetail(mint(), (det) => ranks(det).forEach((c: any) => (c["rank"] = "everywhere"))), WireReasonCode.MALFORMED);
});

test("-02 wire: one constraint per key and type", () => {
  const e = reject(leafDetail(mint(), (det) => det["constraints"].push({ key: "max_rows", max: 5 })), WireReasonCode.MALFORMED);
  assert.match(e.message, /one per \(key, type\)/);
  // A range (min + max on one key) on both hops verifies.
  const root = Guard.issue("o", new Authority({ scopes: ["a.b"], ceilings: [new d.Min("t", 1), new d.Max("t", 10)], ttl: 60, profile: "02" }), { maxDepth: 3 });
  const child = root.delegate("c", new Authority({ scopes: ["a.b"], ceilings: [new d.Min("t", 2), new d.Max("t", 9)], ttl: 30, profile: "02" }), "t");
  const v = load(mint([root, child]), signer(), { draft: "02" });
  assert.equal(v.leafAuthority.ceilingsFor("t").length, 2);
});

test("-02 wire: closed objects and the single detail", () => {
  const cases: ((det: Record<string, any>) => void)[] = [
    (det) => (det["constraints"][0]["note"] = "x"),
    (det) => (det["actions"] = ["read"]),
    (det) => (det["type"] = "acme_policy"),
  ];
  for (const mutate of cases) reject(leafDetail(mint(), mutate), WireReasonCode.MALFORMED);
  const tokens = mint();
  tokens[2] = resign(tokens[2]!, (p) => p["authorization_details"].push({ type: "agent_delegation", scopes: [], constraints: [] }));
  assert.match(reject(tokens, WireReasonCode.MALFORMED).message, /exactly one/);
});

test("-02 wire: a single unimplemented constraint type fails closed, not malformed", () => {
  const v = load(leafDetail(mint(), (det) => det["constraints"].push({ key: "quota", cap: 5 })), signer(), { draft: "02", audience: AUD });
  const decision = v.permits("crm.read", { rows: 1, spend: 1 }, { totals: { calls: 1 } });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reasons[0]!.code, "unknown_constraint");
});

test("-02 wire: an unsafe integer is malformed", () => {
  // The canonical encoder refuses to write 2^53, so the token is built from raw bytes.
  const tokens = mint();
  const [h, p] = tokens[2]!.split(".") as [string, string];
  const original = b64urlDecode(p).toString("utf8");
  const raw = original.replace('"exp":300', '"exp":9007199254740992');
  assert.notEqual(raw, original);
  const forged = signParts(h, b64urlEncode(Buffer.from(raw, "utf8")), signer());
  reject([tokens[0]!, tokens[1]!, forged], WireReasonCode.MALFORMED);
});

test("-02 wire: a re-issued parent is not the instance the child commits to", () => {
  const tokens = mint();
  const reissued = resign(tokens[1]!, (p) => {
    p["jti"] = "chain:n1-reissued";
    p["iat"] = 10;
    p["exp"] = 910;
  });
  reject([tokens[0]!, reissued, tokens[2]!], WireReasonCode.PAR_HASH_MISMATCH);
});

test("-02 wire: the Table 2 names the library can report", () => {
  for (const name of [
    "malformed", "non_canonical", "duplicate_member", "non_finite", "signature_invalid", "par_hash_mismatch",
    "depth_invalid", "principal_altered", "not_narrower", "expired", "audience_mismatch",
  ]) {
    assert.ok((Object.values(WireReasonCode) as string[]).includes(name), name);
  }
});
