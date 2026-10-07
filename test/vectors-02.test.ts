/**
 * The draft -02 Delegation Token vectors (`test/fixtures/vectors/draft02/`), copied verbatim from
 * the Python reference implementation's package data (`attenu_guard/vectors/draft02/`, written by
 * its tests/vectors-02/generate_02.py) by tools/gen_fixtures.py.
 *
 * Two claims are checked here. First, every vector scores to its declared outcome under the -02
 * profile, with the vector's `verifier` block (accepted algorithms, audience): the exact reject
 * reason, not merely a rejection. Second, byte parity: this file rebuilds every one of the
 * chains the way the Python generator builds them -- the same `Guard.issue` / `delegate` calls,
 * the same tamper on the same token -- and the tokens must come out byte for byte the ones Python
 * wrote; and every token in the set, decoded, re-encodes to its own bytes, with its authority
 * re-emitted by this library's -02 wire form wherever the -02 parser reads it.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { UnsafeIntegerError, canonicalJson, parseJson, toPlain, type CJson } from "../src/canonical.js";
import { CallLimit, EgressRank, RowLimit, SpendCap, type Ceiling } from "../src/ceilings.js";
import * as d from "../src/draft02.js";
import { Guard } from "../src/guard.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlDecode, b64urlEncode, load } from "../src/wire.js";
import { fixturePath, fixtureJson } from "./helpers.js";
import { encodePart, mintChain02, payloadOf, signParts } from "./mint02.js";

interface Vector02 {
  description: string;
  draft: string;
  signer: { alg: string; kid: string; secret_hex: string };
  verifier: { accepted_algs: string[]; audience: string };
  now: number;
  tokens: string[];
  expect?: string;
  expect_reject_reason?: string;
}

/** Every -02 vector, valid first, in the Python package's `VECTOR_NAMES_02` order. */
const VECTOR_NAMES_02 = [
  "valid_chain",
  "valid_audience_array",
  "valid_opaque_exact",
  "valid_range_min_max",
  "valid_unknown_constraint_identical",
  "reject_principal_altered",
  "reject_root_without_principal",
  "reject_missing_client_id",
  "reject_aud_null",
  "reject_aud_empty_array",
  "reject_audience_mismatch",
  "reject_missing_cnf",
  "reject_cnf_without_confirmation",
  "reject_unsafe_integer",
  "reject_alg_not_accepted",
  "reject_wildcard_over_opaque",
  "reject_opaque_over_wildcard",
  "reject_opaque_case_folded",
  "reject_mixed_case_wildcard",
  "reject_newline_scope",
  "reject_max_lifetime_widened",
  "reject_max_subtree_widened",
  "reject_cross_type_lifetime_for_max",
  "reject_child_exp_exceeds_parent",
  "reject_child_raises_del_max_depth",
  "reject_rank_order_mismatch",
  "reject_rank_without_order",
  "reject_rank_outside_order",
  "reject_duplicate_key_type",
  "reject_constraint_extra_member",
  "reject_detail_extra_member",
  "reject_second_detail",
  "reject_unknown_detail_type",
  "reject_altered_sub_and_par_hash",
  "reject_reissued_parent",
] as const;

const N = VECTOR_NAMES_02.length;

const TABLE_2 = new Set([
  "malformed", "non_canonical", "duplicate_member", "non_finite", "signature_invalid", "par_hash_mismatch",
  "depth_invalid", "principal_altered", "not_narrower", "expired", "holder_binding_failed", "revoked",
  "status_unknown", "audience_mismatch", "scope_not_granted", "ceiling_exceeded", "unknown_constraint",
]);

function vector(name: string): Vector02 {
  return fixtureJson<Vector02>(`vectors/draft02/${name}.json`);
}

function signerFor(v: Vector02): HS256TestSigner {
  assert.equal(v.signer.alg, "HS256");
  return new HS256TestSigner(Buffer.from(v.signer.secret_hex, "hex"), v.signer.kid);
}

/** Score one vector the way an independent implementation is asked to (generate_02.score). */
function score(v: Vector02): string {
  try {
    load(v.tokens, signerFor(v), {
      now: v.now,
      draft: "02",
      acceptedAlgs: v.verifier.accepted_algs,
      audience: v.verifier.audience,
    });
    return "accept";
  } catch (e) {
    assert.ok(e instanceof WireError, `expected a WireError, got ${String(e)}`);
    return e.reason;
  }
}

test("-02 vectors: the directory holds exactly the thirty-five listed files", () => {
  const onDisk = readdirSync(fixturePath("vectors/draft02")).filter((f) => f.endsWith(".json")).sort();
  assert.deepEqual(onDisk, VECTOR_NAMES_02.map((n) => `${n}.json`).sort());
});

test("-02 vectors: all 35 score exactly as declared under the -02 profile", () => {
  let scored = 0;
  for (const name of VECTOR_NAMES_02) {
    const v = vector(name);
    assert.equal(v.draft, "02", name);
    assert.equal(score(v), v.expect ?? v.expect_reject_reason, name);
    scored++;
  }
  assert.equal(scored, 35);
  assert.equal(N, 35);
});

test("-02 vectors: declared reasons are Table 2 names", () => {
  for (const name of VECTOR_NAMES_02) {
    const v = vector(name);
    if (v.expect_reject_reason !== undefined) {
      assert.ok(TABLE_2.has(v.expect_reject_reason), name);
      assert.equal(v.expect, undefined, name);
      assert.ok(name.startsWith("reject_"), name);
    } else {
      assert.equal(v.expect, "accept", name);
      assert.ok(name.startsWith("valid_"), name);
    }
  }
});

test("-02 vectors: the verifier block is load-bearing", () => {
  const mismatch = vector("reject_audience_mismatch");
  mismatch.verifier.audience = "https://crm.example.com";
  assert.equal(score(mismatch), "accept");
  const alg = vector("reject_alg_not_accepted");
  alg.verifier.accepted_algs = ["HS256"];
  assert.equal(score(alg), "accept");
});

test("-02 vectors: every valid token carries the -02 claims", () => {
  for (const name of VECTOR_NAMES_02.filter((n) => n.startsWith("valid_"))) {
    for (const token of vector(name).tokens) {
      const p = toPlain<Record<string, unknown>>(payloadOf(token));
      assert.equal(p["sub"], PRINCIPAL, name);
      assert.ok("client_id" in p && "cnf" in p && p["aud"], name);
    }
  }
});

test("-02 vectors: the -01 set beside them is still the twenty files", () => {
  const top = readdirSync(fixturePath("vectors")).filter((f) => f.endsWith(".json"));
  assert.equal(top.length, 20);
});

test("-02 vectors: the -01 verifier refuses every -02 vector", () => {
  for (const name of VECTOR_NAMES_02) {
    const v = vector(name);
    assert.throws(() => load(v.tokens, signerFor(v), { now: v.now }), WireError, name);
  }
});

// =========================================================================
// Byte parity: the generator, rebuilt
// =========================================================================

const SECRET = Buffer.from("attenu-guard-interop-vectors-draft02-fixed-secret");
const KID = "interop-02";
const PRINCIPAL = "acct:finance-ops@example.com";
const AUDIENCE = "https://crm.example.com";
const ORDER = ["none", "internal", "any"];

const sig = (): HS256TestSigner => new HS256TestSigner(SECRET, KID);

/** generate_02._cnf: a deterministic stand-in for the holder key's JWK thumbprint. */
function cnf(g: Guard): Record<string, string> {
  return { jkt: b64urlEncode(createHash("sha256").update(`holder-key:${g.agentId}`, "utf8").digest()) };
}

function A(scopes: string[], ceilings: Ceiling[], ttl: number): Authority {
  return new Authority({ scopes, ceilings, ttl, profile: "02" });
}

function baseChain(maxDepth = 6): { path: Guard[]; maxDepth: number } {
  const root = Guard.issue(
    "orchestrator",
    A(["crm.*", "mail.send", "User.Read"],
      [new RowLimit(100_000), new EgressRank("any"), new CallLimit(50), new SpendCap(500), new d.MaxSubtree("max_spend", 1000)], 3600),
    { maxDepth },
  );
  const child = root.delegate(
    "summarizer",
    A(["crm.read", "User.Read"],
      [new RowLimit(5_000), new EgressRank("none"), new CallLimit(10), new SpendCap(60), new d.MaxSubtree("max_spend", 400)], 900),
    "summarize Q3 pipeline",
  );
  const leaf = child.delegate(
    "formatter",
    A(["crm.read"], [new RowLimit(100), new EgressRank("none"), new CallLimit(2), new SpendCap(10), new d.MaxSubtree("max_spend", 100)], 300),
    "format for slides",
  );
  return { path: [root, child, leaf], maxDepth };
}

function mint(chain: { path: Guard[]; maxDepth: number }, aud: CJson = AUDIENCE): string[] {
  return mintChain02(chain.path, sig(), { principal: PRINCIPAL, aud: aud as never, cnf, maxDepth: chain.maxDepth });
}

type Payload = Record<string, any>;

/** generate_02._tamper: mutate one token, re-sign it, and re-link and re-sign every later one. */
function tamper(tokens: readonly string[], index: number, mutate: (p: Payload) => void): string[] {
  const out = [...tokens];
  const [h] = out[index]!.split(".") as [string];
  const payload = payloadOf(out[index]!) as Payload;
  mutate(payload);
  out[index] = signParts(h, encodePart(payload), sig());
  let prev = Buffer.from(out[index]!.split(".").slice(0, 2).join("."), "ascii");
  for (let i = index + 1; i < out.length; i++) {
    const [hi] = out[i]!.split(".") as [string];
    const p = payloadOf(out[i]!) as Payload;
    p["par_hash"] = b64urlEncode(createHash("sha256").update(prev).digest());
    out[i] = signParts(hi, encodePart(p), sig());
    prev = Buffer.from(out[i]!.split(".").slice(0, 2).join("."), "ascii");
  }
  return out;
}

const detail = (p: Payload): Payload => p["authorization_details"][0];

function constraint(p: Payload, key: string, ctype: string): Payload {
  const c = detail(p)["constraints"].find((x: Payload) => x["key"] === key && ctype in x);
  if (c === undefined) throw new Error(`no ${ctype} on ${key}`);
  return c;
}

function twoHop(rootScopes: string[], childScopes: string[]): string[] {
  const root = Guard.issue("orchestrator", A(rootScopes, [], 3600), { maxDepth: 2 });
  const worker = root.delegate("worker", A(rootScopes, [], 900), "t");
  return tamper(mint({ path: [root, worker], maxDepth: 2 }), 1, (p) => (detail(p)["scopes"] = [...childScopes]));
}

const base = (): string[] => mint(baseChain());

/** generate_02.GENERATORS, token lists only. */
const GENERATORS: Record<(typeof VECTOR_NAMES_02)[number], () => string[]> = {
  valid_chain: base,
  valid_audience_array: () => mint(baseChain(), ["https://files.example.com", AUDIENCE]),
  valid_opaque_exact: () => {
    const root = Guard.issue("orchestrator", A(["User.Read", "repo:status"], [], 3600), { maxDepth: 2 });
    const worker = root.delegate("worker", A(["repo:status"], [], 900), "status");
    return mint({ path: [root, worker], maxDepth: 2 });
  },
  valid_range_min_max: () => {
    const root = Guard.issue("orchestrator", A(["hr.read"], [new d.Min("tenure_years", 1), new d.Max("tenure_years", 30)], 3600), { maxDepth: 2 });
    const worker = root.delegate("worker", A(["hr.read"], [new d.Min("tenure_years", 2), new d.Max("tenure_years", 10)], 900), "screen");
    return mint({ path: [root, worker], maxDepth: 2 });
  },
  valid_unknown_constraint_identical: () => {
    let t = base();
    t = tamper(t, 1, (p) => detail(p)["constraints"].push({ key: "quota", units: 5 }));
    return tamper(t, 2, (p) => detail(p)["constraints"].push({ key: "quota", units: 5 }));
  },
  reject_principal_altered: () => tamper(base(), 1, (p) => (p["sub"] = "acct:someone-else@example.com")),
  reject_root_without_principal: () => tamper(base(), 0, (p) => (p["sub"] = "")),
  reject_missing_client_id: () => tamper(base(), 2, (p) => delete p["client_id"]),
  reject_aud_null: () => tamper(base(), 2, (p) => (p["aud"] = null)),
  reject_aud_empty_array: () => tamper(base(), 2, (p) => (p["aud"] = [])),
  reject_audience_mismatch: base,
  reject_missing_cnf: () => tamper(base(), 1, (p) => delete p["cnf"]),
  reject_cnf_without_confirmation: () => tamper(base(), 2, (p) => (p["cnf"] = { note: "no key here" })),
  reject_unsafe_integer: () => {
    const root = Guard.issue("parser-probe", A(["probe.read"], [], 60), { maxDepth: 1 });
    const [token] = mint({ path: [root], maxDepth: 1 });
    const [h, p] = token!.split(".") as [string, string];
    const payload = b64urlDecode(p).toString("utf8");
    const unsafe = payload.replace('"exp":60', '"exp":9007199254740992');
    assert.notEqual(unsafe, payload);
    return [signParts(h, b64urlEncode(Buffer.from(unsafe, "utf8")), sig())];
  },
  reject_alg_not_accepted: base,
  reject_wildcard_over_opaque: () => twoHop(["drive.*"], ["drive.Read"]),
  reject_opaque_over_wildcard: () => twoHop(["drive.Read"], ["drive.*"]),
  reject_opaque_case_folded: () => twoHop(["User.Read"], ["user.read"]),
  reject_mixed_case_wildcard: () => twoHop(["User.Read"], ["User.*"]),
  reject_newline_scope: () => twoHop(["crm.*"], ["crm.read\n"]),
  reject_max_lifetime_widened: () => tamper(base(), 2, (p) => (constraint(p, "max_calls", "max_lifetime")["max_lifetime"] = 1000)),
  reject_max_subtree_widened: () => tamper(base(), 2, (p) => (constraint(p, "max_spend", "max_subtree")["max_subtree"] = 5000)),
  reject_cross_type_lifetime_for_max: () =>
    tamper(base(), 2, (p) => {
      const c = constraint(p, "max_rows", "max");
      delete c["max"];
      c["max_lifetime"] = 1;
    }),
  reject_child_exp_exceeds_parent: () => tamper(base(), 2, (p) => (p["exp"] = 910)),
  reject_child_raises_del_max_depth: () => tamper(base(), 2, (p) => (p["del_max_depth"] = 60)),
  reject_rank_order_mismatch: () => tamper(base(), 2, (p) => (constraint(p, "egress", "rank")["order"] = ["none", "any"])),
  reject_rank_without_order: () => tamper(base(), 2, (p) => delete constraint(p, "egress", "rank")["order"]),
  reject_rank_outside_order: () => tamper(base(), 2, (p) => (constraint(p, "egress", "rank")["rank"] = "everywhere")),
  reject_duplicate_key_type: () => tamper(base(), 2, (p) => detail(p)["constraints"].push({ key: "max_rows", max: 50 })),
  reject_constraint_extra_member: () => tamper(base(), 2, (p) => (constraint(p, "max_rows", "max")["note"] = "soft")),
  reject_detail_extra_member: () => tamper(base(), 2, (p) => (detail(p)["actions"] = ["read"])),
  reject_second_detail: () =>
    tamper(base(), 2, (p) => p["authorization_details"].push({ type: "agent_delegation", scopes: ["crm.read"], constraints: [] })),
  reject_unknown_detail_type: () => tamper(base(), 0, (p) => (detail(p)["type"] = "acme_site_policy")),
  reject_altered_sub_and_par_hash: () => {
    const t = base();
    t[2] = signParts(
      t[2]!.split(".")[0]!,
      encodePart({ ...(payloadOf(t[2]!) as Payload), sub: "acct:mallory@example.com", par_hash: "AAAA" }),
      sig(),
    );
    return t;
  },
  reject_reissued_parent: () => {
    const t = base();
    t[1] = signParts(
      t[1]!.split(".")[0]!,
      encodePart({ ...(payloadOf(t[1]!) as Payload), jti: "chain:n1-reissued", iat: 10, exp: 910 }),
      sig(),
    ); // the leaf's par_hash is NOT repaired
    return t;
  },
};

test("-02 byte parity: this library rebuilds all 35 chains byte for byte as Python wrote them", () => {
  let identical = 0;
  for (const name of VECTOR_NAMES_02) {
    const v = vector(name);
    assert.equal(v.signer.secret_hex, SECRET.toString("hex"), name);
    assert.equal(v.signer.kid, KID, name);
    assert.deepEqual(GENERATORS[name](), v.tokens, name);
    identical++;
  }
  assert.equal(identical, 35);
});

test("-02 byte parity: every token re-encodes from its decoded parts to its own bytes", () => {
  let tokens = 0;
  let reemitted = 0;
  for (const name of VECTOR_NAMES_02) {
    const v = vector(name);
    for (const token of v.tokens) {
      const [h, p, s] = token.split(".") as [string, string, string];
      const header = parseJson(b64urlDecode(h).toString("utf8"));
      const payload = parseJson(b64urlDecode(p).toString("utf8")) as Record<string, CJson>;
      tokens++;
      if (name === "reject_unsafe_integer") {
        // 2^53 has no RFC 8785 form this library will write: the canonical encoder refuses it.
        assert.throws(() => canonicalJson(payload), UnsafeIntegerError);
        continue;
      }
      assert.equal(encodePart(header), h, `${name} header`);
      assert.equal(encodePart(payload), p, `${name} payload`);
      assert.equal(b64urlEncode(signerFor(v).sign(Buffer.from(`${h}.${p}`, "ascii"))), s, `${name} signature`);
      // The authority, read by the -02 parser and written back by this library's -02 wire form:
      // the constraints in (key, type) order, each in its -02 shape. Wherever the parser reads
      // the detail, the re-emission is byte-identical to Python's.
      const plain = toPlain<Payload>(payload);
      const d0 = plain["authorization_details"]?.[0];
      let authority: Authority;
      try {
        authority = Authority.fromWire({ scopes: d0["scopes"], constraints: d0["constraints"], ttl: plain["exp"] - plain["iat"] }, "02");
      } catch {
        continue; // a malformed detail: the vector's own subject
      }
      const wire = authority.toWire();
      assert.equal(canonicalJson(wire.scopes), canonicalJson(d0["scopes"]), `${name} scopes`);
      assert.equal(canonicalJson(wire.constraints), canonicalJson(d0["constraints"]), `${name} constraints`);
      reemitted++;
    }
  }
  assert.ok(tokens >= 80, `${tokens} tokens`);
  assert.ok(reemitted >= 70, `only ${reemitted} tokens re-emitted`);
});

test("-02 byte parity: the rank ordering and the lifetime call bound are emitted as Python emits them", () => {
  const leaf = toPlain<Payload>(payloadOf(vector("valid_chain").tokens[2]!));
  assert.deepEqual(detail(leaf)["constraints"], [
    { key: "egress", order: ORDER, rank: "none" },
    { key: "max_calls", max_lifetime: 2 },
    { key: "max_rows", max: 100 },
    { key: "max_spend", max: 10 },
    { key: "max_spend", max_subtree: 100 },
  ]);
  assert.equal(WireReasonCode.AUDIENCE_MISMATCH, "audience_mismatch");
});
