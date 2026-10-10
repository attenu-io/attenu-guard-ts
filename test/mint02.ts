/**
 * A test-only minter for draft -02 Delegation Chains, built the way the Python reference
 * implementation's `wire.serialize_chain(..., draft="02")` builds them.
 *
 * The TypeScript library mints nothing (wire.ts): issuing is the side that holds the signing key.
 * The -02 tests still need chains, and the cross-language byte check needs them built from the
 * same in-process objects the Python generator uses (`Guard.issue` / `delegate` with the same
 * authorities), so that every byte the TypeScript library is responsible for -- the attenuated
 * authority, its -02 constraint shapes and their order, RFC 8785 -- is compared with Python's.
 * The envelope around those bytes (header, claim layout, par_hash, HS256) is assembled here, from
 * the -02 Section 3 claim list.
 */

import { createHash } from "node:crypto";

import { Authority } from "../src/authority.js";
import { canonicalJson, parseJson, type CJson, type Json } from "../src/canonical.js";
import type { Guard } from "../src/guard.js";
import { b64urlDecode, b64urlEncode, type Signer } from "../src/wire.js";

export interface Mint02Options {
  principal?: string | null;
  aud?: Json;
  cnf?: ((guard: Guard) => Json) | Record<string, Json> | null;
  iss?: string;
  iat?: number;
  /** The chain's max_depth (`Guard.issue`'s option); DT_0 carries it plus one as `del_max_depth`. */
  maxDepth: number;
}

/** One base64url JWS part: the RFC 8785 bytes of `value`. */
export function encodePart(value: CJson): string {
  return b64urlEncode(Buffer.from(canonicalJson(value), "utf8"));
}

/** A token's payload, parsed (number literals kept, so it re-encodes to the same bytes). */
export function payloadOf(token: string): Record<string, CJson> {
  return parseJson(b64urlDecode(token.split(".")[1]!).toString("utf8")) as Record<string, CJson>;
}

/** `header.payload` re-signed with `signer`. */
export function signParts(headerB64: string, payloadB64: string, signer: Signer): string {
  const sig = signer.sign(Buffer.from(`${headerB64}.${payloadB64}`, "ascii"));
  return `${headerB64}.${payloadB64}.${b64urlEncode(sig)}`;
}

/**
 * Serialize `path` (root first, leaf last; each the previous one's delegate) as a -02 Delegation
 * Chain. Refuses, as the Python minter does, what the -02 verifier would reject as malformed.
 */
export function mintChain02(path: readonly Guard[], signer: Signer, options: Mint02Options): string[] {
  const { principal = null, aud = null, cnf = null, iss = "attenu-guard", iat = 0, maxDepth } = options;
  if (typeof principal !== "string" || principal === "") throw new Error("draft -02 requires principal");
  const audOk = typeof aud === "string" || (Array.isArray(aud) && aud.length > 0 && aud.every((a) => typeof a === "string"));
  if (!audOk) throw new Error("draft -02 requires aud to be a string or a non-empty array of strings");
  if (cnf === null) throw new Error("draft -02 requires cnf");
  const tokens: string[] = [];
  let prevSigningInput: Buffer | null = null;
  path.forEach((guard, depth) => {
    // Re-expressed under the -02 whatever profile it was built under, as Python's
    // `_authority_detail(authority, "02")` does.
    const a = guard.authority;
    const authority = new Authority({ scopes: a.scopes, ceilings: a.ceilings, ttl: a.ttl, profile: "02" });
    if (authority.ttl === null) throw new Error("a Delegation Token requires a finite ttl");
    const wire = authority.toWire();
    const holder = typeof cnf === "function" ? cnf(guard) : cnf;
    if (holder === null || typeof holder !== "object" || Array.isArray(holder) || Object.keys(holder).length === 0) {
      throw new Error("draft -02 requires a non-empty cnf object on every token");
    }
    const header = { typ: "at+jwt", alg: signer.alg, kid: signer.kid ?? null, c14n: "JCS" };
    const payload: Record<string, Json> = {
      iss,
      sub: principal,
      aud,
      iat,
      exp: iat + authority.ttl,
      jti: guard.nodeId,
      authorization_details: [{ type: "agent_delegation", scopes: wire.scopes, constraints: wire.constraints }],
      del_depth: depth,
      client_id: guard.agentId,
      cnf: holder,
    };
    if (depth === 0) payload["del_max_depth"] = maxDepth + 1;
    else payload["par_hash"] = b64urlEncode(createHash("sha256").update(prevSigningInput!).digest());
    const headerB64 = encodePart(header);
    const payloadB64 = encodePart(payload);
    prevSigningInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
    tokens.push(signParts(headerB64, payloadB64, signer));
  });
  return tokens;
}

/** Mutate a token's payload and re-sign it (canonical bytes, valid signature). */
export function resign(token: string, mutate: (payload: Record<string, any>) => void, signer: Signer): string {
  const headerB64 = token.split(".")[0]!;
  const payload = payloadOf(token);
  mutate(payload);
  return signParts(headerB64, encodePart(payload as CJson), signer);
}

/**
 * Recompute par_hash down the chain after an earlier token was re-signed, so a test isolates the
 * rule it is about from par_hash_mismatch.
 */
export function repair(tokens: readonly string[], signer: Signer): string[] {
  const out = [...tokens];
  for (let i = 1; i < out.length; i++) {
    const [h, p] = out[i - 1]!.split(".");
    const expected = b64urlEncode(createHash("sha256").update(Buffer.from(`${h}.${p}`, "ascii")).digest());
    if (payloadOf(out[i]!)["par_hash"] !== expected) {
      out[i] = resign(out[i]!, (pl) => {
        pl["par_hash"] = expected;
      }, signer);
    }
  }
  return out;
}
