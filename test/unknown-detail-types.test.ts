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

import { Authority } from "../src/authority.js";
import { canonicalJson } from "../src/canonical.js";
import { HS256TestSigner, WireError, WireReasonCode, b64urlDecode, b64urlEncode, load } from "../src/wire.js";
import { fixtureJson } from "./helpers.js";

interface Vector {
  signer: { alg: string; kid: string; secret_hex: string };
  now: number;
  tokens: string[];
}

const FOREIGN = { type: "acme_site_policy", deny_scopes: ["crm.read"] };

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

/**
 * Rebuild the leaf with `members` merged INTO its single authorization detail.
 * The cardinality rule never fires here: there is still exactly one entry.
 */
function leafWithDetailMembers(v: Vector, members: Record<string, unknown>): string[] {
  const leaf = v.tokens[v.tokens.length - 1];
  if (leaf === undefined) throw new Error("vector has no tokens");
  const parts = leaf.split(".");
  const hdr = parts[0];
  const payloadB64 = parts[1];
  if (hdr === undefined || payloadB64 === undefined) throw new Error("leaf token is not a JWS");
  const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8")) as Record<string, unknown>;
  const details = payload["authorization_details"] as Record<string, unknown>[];
  Object.assign(details[0] as Record<string, unknown>, members);
  const secret = Buffer.from(v.signer.secret_hex, "hex");
  const p = b64urlEncode(Buffer.from(canonicalJson(payload as never), "utf8"));
  const sig = createHmac("sha256", secret).update(`${hdr}.${p}`).digest();
  return [...v.tokens.slice(0, -1), `${hdr}.${p}.${b64urlEncode(sig)}`];
}

test("a member inside the single detail is refused, not dropped", () => {
  // The regression the first fix missed. One entry, so the cardinality rule
  // never fires; before the member check this verified clean and still
  // permitted crm.read while `deny_scopes` said not to.
  const v = vector();
  assert.throws(
    () => load(leafWithDetailMembers(v, { deny_scopes: ["crm.read"] }), signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.MALFORMED,
  );
});

test("RFC 9396 common members are refused", () => {
  // `actions`, `locations`, `datatypes`, `identifier` and `privileges` are
  // common members of ANY authorization detail object, and the draft's token
  // format cites RFC 9396 by name, so an issuer restricting this way is doing
  // the sanctioned thing.
  const v = vector();
  for (const [member, value] of [
    ["actions", ["read"]],
    ["locations", ["https://api.example.com"]],
    ["datatypes", ["contacts"]],
    ["identifier", "acct-1"],
    ["privileges", ["read"]],
  ] as [string, unknown][]) {
    assert.throws(
      () => load(leafWithDetailMembers(v, { [member]: value }), signerFor(v), { now: v.now }),
      (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.MALFORMED,
      `member ${member} was not refused`,
    );
  }
});

test("critical: true is refused", () => {
  // `critical` means "do not ignore me". Ignoring it was the worst case.
  const v = vector();
  assert.throws(
    () => load(leafWithDetailMembers(v, { critical: true }), signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.MALFORMED,
  );
});

test("a second typed value inside a constraint is refused, not resolved", () => {
  // `min` alongside `max` used to keep the max and drop the floor, producing a
  // constraint byte-identical to one that never carried a floor.
  const v = vector();
  const leaf = v.tokens[v.tokens.length - 1];
  if (leaf === undefined) throw new Error("vector has no tokens");
  const parts = leaf.split(".");
  const hdr = parts[0];
  const payloadB64 = parts[1];
  if (hdr === undefined || payloadB64 === undefined) throw new Error("leaf token is not a JWS");
  const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8")) as Record<string, unknown>;
  const details = payload["authorization_details"] as Record<string, unknown>[];
  const constraints = (details[0] as Record<string, unknown>)["constraints"] as Record<string, unknown>[];
  (constraints[0] as Record<string, unknown>)["min"] = 9999;
  const secret = Buffer.from(v.signer.secret_hex, "hex");
  const p = b64urlEncode(Buffer.from(canonicalJson(payload as never), "utf8"));
  const sig = createHmac("sha256", secret).update(`${hdr}.${p}`).digest();
  assert.throws(
    () => load([...v.tokens.slice(0, -1), `${hdr}.${p}.${b64urlEncode(sig)}`], signerFor(v), { now: v.now }),
    (e: unknown) => e instanceof WireError && e.reason === WireReasonCode.MALFORMED,
  );
});

test("normalising ceilings are not rejected", () => {
  // The false positive that nearly shipped, and the gap that hid it.
  //
  // A first version of this rule compared whole VALUES. That cannot tell "we
  // ignored a member" from "we normalised a value", and three built-ins
  // legitimately normalise: Allow/Deny emit one_of / not_one_of sorted and hold
  // them as sets, and toWire omits `field` when it equals `key`.
  //
  // RFC 8785 canonicalises object member ORDER and never reorders array
  // elements, and the draft puts no ordering or uniqueness requirement on
  // one_of. Every case below is therefore a conformant constraint a third-party
  // issuer may legitimately send, and value equality called all of them
  // malformed.
  //
  // These exist because NO fixture in either repo carries an allow, deny or
  // prefix constraint, so the "every constraint round-trips" regression check
  // only ever exercised the ceilings that emit what they read, and passed
  // vacuously.
  const conformant: Record<string, unknown>[] = [
    { key: "region", type: "allow", one_of: ["us-west", "us-east"] },
    { key: "region", type: "deny", not_one_of: ["b", "a"] },
    { key: "region", type: "allow", one_of: ["a", "a"] },
    { key: "region", type: "allow", one_of: ["us"], field: "region" },
    { key: "region", type: "allow", one_of: ["us"], field: "zone" },
    { key: "path", type: "prefix", prefix: "/srv/" },
  ];
  for (const c of conformant) {
    const a = Authority.fromWire({ scopes: ["crm.read"], constraints: [c], ttl: 10 } as never);
    assert.equal(a.ceilings.length, 1, `rejected a conformant constraint: ${JSON.stringify(c)}`);
  }
});

test("an extra member on a normalising ceiling is still refused", () => {
  // The narrowed rule must not have become a no-op for the types it exempted.
  assert.throws(() =>
    Authority.fromWire({
      scopes: ["crm.read"],
      constraints: [{ key: "region", type: "allow", one_of: ["us"], deny_scopes: ["x"] }],
      ttl: 10,
    }),
  );
});

test("a rewritten key is refused", () => {
  // `key` is the one member whose VALUE is load-bearing: subsumption pairs
  // ceilings by it, so a rewritten key is a different dimension. CallLimit
  // rewrites it when applies_to is present, and the member test cannot see that
  // because the member set is unchanged.
  assert.throws(() =>
    Authority.fromWire({
      scopes: ["crm.read"],
      constraints: [{ key: "max_calls", type: "max_calls", max: 5, applies_to: "fs.write" }],
      ttl: 10,
    } as never),
  );
});

test("field is exempt only on evidence it was parsed", () => {
  // ctxFieldOf falls back to a hardcoded ctxField and then to key, so for the
  // metered built-ins -- which never read `field` at all -- it returned the
  // input's value by coincidence and `field` rode through unread. The test is
  // now the attribute the constructor actually populated.
  for (const c of [
    { key: "max_rows", max: 5, field: "rows" },
    { key: "max_spend", max: 5, field: "spend" },
    { key: "egress", rank: "none", field: "egress" },
  ]) {
    assert.throws(
      () => Authority.fromWire({ scopes: ["crm.read"], constraints: [c], ttl: 10 } as never),
      `field rode through unread on ${JSON.stringify(c)}`,
    );
  }
});

test("an unknown constraint TYPE still fails closed rather than becoming a parse error", () => {
  // The distinction worth keeping: the draft requires an unknown constraint
  // type to DENY the action, never to be treated as unconstrained. Turning it
  // into a parse error would lose that.
  const a = Authority.fromWire({ scopes: ["crm.read"], constraints: [{ key: "max_widgets", max: 5 }], ttl: 10 });
  assert.equal(a.ceilings.length, 1);
  assert.equal(a.permits("crm.read", {}).allowed, false);
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
    (e: unknown) => e instanceof WireError && e.message.includes("acme_site_policy"),
  );
});
