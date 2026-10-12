/**
 * Cross-language differences in the token path (attenu-ops #127), held for this release and
 * fixed in both implementations at once.
 *
 * 1. A Delegation Token whose `scopes` is not an array. Under the default -01 profile the Python
 *    implementation read an object by projection (its member names became the scopes) and
 *    verified the token; this one refused it, but only because `new Set` cannot iterate an
 *    object, with a message about iteration. A `null` scopes list was read as empty here and
 *    refused there. Both now refuse a non-array `scopes` as `malformed`, with the same message,
 *    on both profiles.
 * 2. A `null` constraint list was read as empty here under -01 and refused there. Refused in both.
 * 3. A number whose value is an integer past 2^53 - 1 (`1e+308`, `9007199254740992.0`). This
 *    implementation always refused it by value; the Python implementation refused it only as an
 *    integer literal. Python now applies the value rule; the cases below pin it here so neither
 *    side moves away from it.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { AuditLog, GENESIS } from "../src/audit.js";
import { Authority } from "../src/authority.js";
import { canonicalJson, type CJson } from "../src/canonical.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlEncode, load } from "../src/wire.js";
import { fixtureJson } from "./helpers.js";
import { payloadOf, resign, signParts } from "./mint02.js";

interface Vec {
  draft?: string;
  signer: { alg: string; kid: string; secret_hex: string };
  verifier?: { accepted_algs: string[]; audience: string };
  now: number;
  tokens: string[];
}

const V01 = fixtureJson<Vec>("vectors/valid_chain.json");
const V02 = fixtureJson<Vec>("vectors/draft02/valid_chain.json");

const signerOf = (v: Vec) => new HS256TestSigner(Buffer.from(v.signer.secret_hex, "hex"), v.signer.kid);

function run(v: Vec, tokens: string[]): void {
  load(tokens, signerOf(v), v.draft === "02"
    ? { now: v.now, draft: "02", acceptedAlgs: v.verifier!.accepted_algs, audience: v.verifier!.audience }
    : { now: v.now });
}

function refusal(v: Vec, tokens: string[]): WireError {
  try {
    run(v, tokens);
  } catch (e) {
    assert.ok(e instanceof WireError, `expected a WireError, got ${String(e)}`);
    return e;
  }
  assert.fail("the chain verified");
}

/** The vector's chain with token `index` edited and re-signed; `truncate` keeps DT_0..DT_index. */
function edited(v: Vec, index: number, edit: (p: Record<string, any>) => void, truncate = false): string[] {
  const tokens = truncate ? v.tokens.slice(0, index + 1) : [...v.tokens];
  tokens[index] = resign(tokens[index]!, edit, signerOf(v));
  return tokens;
}

/** DT_0 alone, with `member` written as the JSON text `raw` verbatim, re-signed. */
function rootWithRaw(v: Vec, member: string, raw: string): string[] {
  const token = v.tokens[0]!;
  const payload = payloadOf(token) as Record<string, CJson>;
  payload[member] = "__RAW__";
  const text = canonicalJson(payload as CJson).replace('"__RAW__"', raw);
  return [signParts(token.split(".")[0]!, b64urlEncode(Buffer.from(text, "utf8")), signerOf(v))];
}

const setScopes = (value: unknown) => (p: Record<string, any>) => {
  p["authorization_details"][0]["scopes"] = value;
};

test("#127 control: an unchanged token, re-signed, still verifies on both profiles", () => {
  for (const v of [V01, V02]) {
    run(v, edited(v, v.tokens.length - 1, () => undefined));
    run(v, edited(v, 0, () => undefined, true));
  }
});

test("#127 an object scopes is malformed under -01, on the leaf and on the root, with the Python message", () => {
  for (const tokens of [
    edited(V01, V01.tokens.length - 1, setScopes({ "crm.read": 1 })),
    edited(V01, 0, setScopes({ "crm.read": 1, "mail.send": 1 }), true),
  ]) {
    const e = refusal(V01, tokens);
    assert.equal(e.reason, WireReasonCode.MALFORMED);
    assert.match(e.message, /scopes is an object, not an array/);
  }
});

test("#127 a null or string scopes is malformed under -01", () => {
  for (const [value, kind] of [[null, "null"], ["crm", "a string"]] as const) {
    const e = refusal(V01, edited(V01, 0, setScopes(value), true));
    assert.equal(e.reason, WireReasonCode.MALFORMED, String(value));
    assert.match(e.message, new RegExp(`scopes is ${kind}, not an array`));
  }
});

test("#127 an object scopes is malformed under -02", () => {
  for (const tokens of [
    edited(V02, V02.tokens.length - 1, setScopes({ "crm.read": 1 })),
    edited(V02, 0, setScopes({ "crm.read": 1 }), true),
  ]) {
    assert.equal(refusal(V02, tokens).reason, WireReasonCode.MALFORMED);
  }
});

test("#127 a null constraint list is malformed under -01, as in Python", () => {
  const e = refusal(V01, edited(V01, 0, (p) => void (p["authorization_details"][0]["constraints"] = null), true));
  assert.equal(e.reason, WireReasonCode.MALFORMED);
  assert.match(e.message, /constraints is null, not an array/);
});

test("#127 Authority.fromWire refuses a non-array scopes and a null constraint list on both profiles", () => {
  for (const profile of ["01", "02"] as const) {
    for (const value of [{ "crm.read": 1 }, "crm", null, 5, true]) {
      assert.throws(() => Authority.fromWire({ scopes: value as CJson, constraints: [], ttl: 60 }, profile),
        /scopes is .+, not an array/, `${profile} ${JSON.stringify(value)}`);
    }
    assert.throws(() => Authority.fromWire({ scopes: ["a.b"], constraints: null, ttl: 60 }, profile),
      { message: "constraints is null, not an array" });
    assert.deepEqual([...Authority.fromWire({ scopes: ["crm.read"], constraints: [], ttl: 60 }, profile).scopes], ["crm.read"]);
    assert.equal(Authority.fromWire({ constraints: [], ttl: 60 }, profile).scopes.size, 0);
  }
});

test("#127 a number past 2^53 - 1 by value is malformed at parse, whatever its lexical form", () => {
  for (const v of [V01, V02]) {
    for (const raw of ["1e+308", "1e+21", "9007199254740992.0", "9007199254740992"]) {
      const e = refusal(v, rootWithRaw(v, "exp", raw));
      assert.equal(e.reason, WireReasonCode.MALFORMED, raw);
      assert.match(e.message, /exceeds the safe range/, raw);
    }
    run(v, rootWithRaw(v, "exp", "9007199254740991"));
  }
});

test("#127 a ledger entry carrying such a number has no hash to reproduce: hash mismatch at that entry", () => {
  const payload = {
    v: 2, c14n: "JCS", seq: 0, ts: 0, event: "root", node: "n0",
    authority: { scopes: ["crm.read"], constraints: [], ttl: 1e308 }, prev_hash: GENESIS,
  };
  assert.deepEqual(AuditLog.verify([{ ...payload, hash: "0".repeat(64) }]), [false, "hash mismatch at seq 0"]);
});
