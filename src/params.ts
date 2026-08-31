/**
 * params.ts — the `params_c14n_v1` argument commitment (docs/execution-binding spec section 4).
 *
 * Two observations, two hashes: `authorized_params_hash` (on the `allow` entry, from what
 * `Guard.check` was called with) and `invoked_params_hash` (on the `outcome` entry, from what the
 * body-owning wrapper observed immediately before the actual invocation). Substitution between
 * them is visible only because both exist; neither raw value is ever logged.
 *
 * Commitment: `SHA-256(rawSalt || UTF8(JCS(params)))`, lowercase hex — `rawSalt` is the chain's
 * 16-byte `paramsSalt` (see chain.ts), fixed for the chain's lifetime; `JCS(params)` reuses
 * `canonicalBytes` verbatim (RFC 8785), so the numeric domain and encoding rules are identical to
 * every other signing surface in this library.
 *
 * One divergence from the Python module this mirrors, deliberately closed rather than inherited:
 * Python's general `canonical.dumps` tolerates an out-of-range INTEGRAL float (e.g. `1e20`) —
 * needed for a pinned JCS-divergence-class test — so `attenu_guard.params` runs its own domain
 * pre-check in front of it. TypeScript's `canonicalBytes` has no such tolerance: because
 * JavaScript has one numeric type, `checkSafeInteger` already rejects EVERY unsafe integer,
 * literal or float-shaped alike (see canonical.ts's `UnsafeIntegerError`). The spec's rule for
 * this profile is stated runtime-neutrally — "every mathematically integral number outside
 * ±(2^53−1) is rejected, regardless of the host's numeric type" — so this module still runs its
 * OWN independent domain check (mirroring Python's `_has_unsafe_integral_float`) rather than
 * leaning on `canonicalBytes`'s already-strict behaviour: that behaviour is an accident of
 * JavaScript having no int/float distinction, not a promise `params.ts` should depend on.
 *
 * Outside the domain (either reason): no hash, and the caller writes `paramsHashReason:
 * "unsupported"` on the record whose hash is absent — never throws. A caller that never attempts
 * a commitment at all writes neither field; "unsupported" and "never attempted" are deliberately
 * distinguishable states, not folded into one.
 */

import { createHash } from "node:crypto";

import { CanonicalizationError, MAX_SAFE_INTEGER, canonicalBytes, type Json } from "./canonical.js";

export const PARAMS_C14N_VERSION = "params_c14n_v1";
export const SALT_HEX_LEN = 32; // 16 raw bytes, hex-encoded

/** `"unsupported"` — the one reason a params commitment can be absent. */
export const ParamsHashReason = {
  UNSUPPORTED: "unsupported",
} as const;

export type ParamsHashReasonValue = (typeof ParamsHashReason)[keyof typeof ParamsHashReason];

export const PARAMS_HASH_REASONS: ReadonlySet<string> = new Set(Object.values(ParamsHashReason));

/**
 * The 16 raw bytes a chain's `paramsSalt` (32 lowercase hex chars, on the `root` entry) decodes
 * to. Throws on anything else — a malformed salt must fail loudly, not silently hash against the
 * wrong number of bytes.
 */
export function decodeSalt(paramsSaltHex: string): Buffer {
  if (!/^[0-9a-f]{32}$/.test(paramsSaltHex)) {
    throw new Error(
      `params_salt must decode to 16 raw bytes; got ${JSON.stringify(paramsSaltHex)}`,
    );
  }
  return Buffer.from(paramsSaltHex, "hex");
}

/**
 * `true` if `value` contains, anywhere in its structure, a number that is mathematically integral
 * and exceeds ±`MAX_SAFE_INTEGER` — the params_c14n_v1 domain boundary, checked independently of
 * `canonicalBytes` (see the module doc comment).
 */
function hasUnsafeIntegralNumber(value: unknown): boolean {
  if (typeof value === "number") {
    return Number.isFinite(value) && Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER;
  }
  if (Array.isArray(value)) {
    return value.some(hasUnsafeIntegralNumber);
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some(hasUnsafeIntegralNumber);
  }
  return false;
}

/**
 * `[hashHex, reason]`. `hashHex` is the lowercase-hex `params_c14n_v1` commitment, or `null` if
 * `params` is outside the domain — in which case `reason === ParamsHashReason.UNSUPPORTED`.
 * Exactly one of the two is non-null.
 */
export function commit(paramsValue: Json, rawSalt: Buffer): [string | null, string | null] {
  if (hasUnsafeIntegralNumber(paramsValue)) {
    return [null, ParamsHashReason.UNSUPPORTED];
  }
  let encoded: Buffer;
  try {
    encoded = canonicalBytes(paramsValue as never); // UTF8(JCS(params)) — canonicalBytes already returns UTF-8 bytes
  } catch (e) {
    if (e instanceof CanonicalizationError) {
      return [null, ParamsHashReason.UNSUPPORTED];
    }
    throw e;
  }
  const h = createHash("sha256");
  h.update(rawSalt);
  h.update(encoded);
  return [h.digest("hex"), null];
}
