/**
 * A verifier must not report success on a token it did not fully read.
 *
 * Ops #109, and the TypeScript half of a fix that must land in both ports at
 * once: the two implementations are required to accept and refuse exactly the
 * same tokens, and a divergence here would be worse than the original defect.
 *
 * Before this change `authorityFromPayload` read `details[0]` and never looked
 * at the rest, so a token carrying `agent_delegation` first and a second detail
 * after it verified clean while the second detail was discarded without a
 * signal. Demonstrated end-to-end on the released `valid_chain` vector in the
 * Python port: a trailing detail carrying `deny_scopes: ["crm.read"]` was
 * dropped and the chain still permitted `crm.read` -- the verifier permitted
 * the action the issuer's own detail forbade.
 *
 * The failure was silent in exactly one direction, which is the dangerous one:
 * an ignored detail that RESTRICTS authority is lost, while one that GRANTS
 * extra authority is harmless because ignoring it leaves the chain more
 * restrictive.
 *
 * The rule is the same shape and the same place as the draft's existing MUST
 * for an invalid scope ("A verifier that encounters one MUST reject the
 * Delegation Token as malformed before evaluating subsumption").
 */

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/canonical.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlDecode, b64urlEncode, load } from "../src/wire.js";
import { fixtureJson } from "./helpers.js";

interface Vector {
  signer: { alg: string; kid: string; secret_hex: string };
  now: number;
  tokens: string[];
}

const FOREIGN = { type: "wes_enterprise_policy", deny_scopes: ["crm.read"] };

function vector(): Vector {
  return fixtureJson("vectors/valid_chain.json") as unknown as Vector;
}

/**
 * Rebuild the leaf with `extra` appended to its authorization_details.
 *
 * The LEAF is mutated on purpose: no child commits to it through `par_hash`, so
 * the only difference from the published chain is the inserted entry. The
 * payload is re-canonicalised through `canonicalJson` rather than
 * `JSON.stringify`, because the loader enforces RFC 8785 and would otherwise
 * reject for `non_canonical` -- which would prove nothing about this rule.
 */
function leafWith(v: Vector, extra: unknown[]): string[] {
  const leaf = v.tokens[v.tokens.length - 1];
  if (leaf === undefined) throw new Error("vector has no tokens");
  const parts = leaf.split(".");
  const hdr = parts[0];
  const payloadB64 = parts[1];
  if (hdr === undefined || payloadB64 === undefined) throw new Error("leaf token is not a JWS");
  const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8")) as Record<string, unknown>;
  (payload["authorization_details"] as unknown[]).push(...extra);
  const secret = Buffer.from(v.signer.secret_hex, "hex");
  const p = b64urlEncode(Buffer.from(canonicalJson(payload as never), "utf8"));
  const sig = createHmac("sha256", secret).update(`${hdr}.${p}`).digest();
  return [...v.tokens.slice(0, -1), `${hdr}.${p}.${b64urlEncode(sig)}`];
}

function signerFor(v: Vector): HS256TestSigner {
  return new HS256TestSigner(Buffer.from(v.signer.secret_hex, "hex"), v.signer.kid);
}

test("the published vector, unmodified, still verifies", () => {
  const v = vector();
  const chain = load(v.tokens, signerFor(v), { now: v.now });
  assert.equal(chain.permits("crm.read").allowed, true);
});

test("control: the leaf re-signed unchanged still verifies", () => {
  // Without this, a rejection below could mean nothing more than that the test
  // signs badly.
  const v = vector();
  const chain = load(leafWith(v, []), signerFor(v), { now: v.now });
  assert.equal(chain.permits("crm.read").allowed, true);
});

test("an appended foreign detail is refused, not ignored", () => {
  const v = vector();
  assert.throws(
    () => load(leafWith(v, [FOREIGN]), signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.MALFORMED,
  );
});

test("canonicalization is not what stops it", () => {
  // JCS must not be mistaken for the protection. The first reproduction of this
  // defect was rejected `non_canonical` only because it re-serialized with
  // JSON.stringify; going through the canonicaliser produced a token the
  // verifier accepted. The guarantee has to come from the detail-type rule.
  const v = vector();
  assert.throws(
    () => load(leafWith(v, [FOREIGN]), signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.reason !== WireReasonCode.NON_CANONICAL,
  );
});

test("two agent_delegation entries are refused as ambiguous", () => {
  // The draft says Authority is expressed by "an" authorization detail of that
  // type and never says which element to take when several are present. Taking
  // the first silently nominated a winner the document does not.
  const v = vector();
  const second = { type: "agent_delegation", scopes: ["crm.write"], constraints: [] };
  assert.throws(
    () => load(leafWith(v, [second]), signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.MALFORMED,
  );
});

test("the denial names the entry it could not evaluate", () => {
  // A denial a deployer cannot act on is only half a fix.
  const v = vector();
  assert.throws(
    () => load(leafWith(v, [FOREIGN]), signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.message.includes("wes_enterprise_policy"),
  );
});
