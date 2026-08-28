/**
 * wire.ts — the signing and verification backends.
 *
 * Anchors and delegation tokens are signed over canonical JSON bytes. Two
 * backends ship, matching the Python library's `attenu_guard.wire`:
 *
 *   `HS256TestSigner`  stdlib HMAC-SHA256, for tests, examples and local dev;
 *   `Ed25519Signer`    the production signer the Internet-Draft requires, with
 *                      `Ed25519Verifier` for anyone holding only the public half.
 *
 * Everything here is built on Node's own `node:crypto`, so the package keeps
 * zero runtime dependencies. Ed25519 keys are wrapped in the fixed DER prefixes
 * below rather than pulled from a library.
 */

import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

/**
 * The pluggable signing and verification backend. `alg` is the JOSE algorithm
 * identifier that goes in a token header.
 */
export interface Signer {
  readonly alg: string;
  readonly kid?: string | null;
  sign(signingInput: Buffer): Buffer;
  verify(signingInput: Buffer, sig: Buffer, keyId?: string | null): boolean;
}

/**
 * stdlib HMAC-SHA256 signer — the default for tests, examples and local dev,
 * because it needs no key management at all.
 *
 * NOT FOR PRODUCTION. HMAC is symmetric: `sign` and `verify` use the identical
 * secret, so anyone able to verify a bundle is also able to forge one. That
 * precludes the property the draft is built around — public offline
 * verification at an untrusted enforcement point — because every verifier would
 * have to hold the minting secret. Use `Ed25519Signer` in production; this
 * class exists so the wire format and the interop fixtures can be exercised
 * with no key distribution.
 */
export class HS256TestSigner implements Signer {
  readonly alg = "HS256";
  readonly kid: string;

  constructor(
    private readonly secret: Buffer,
    kid = "test",
  ) {
    this.kid = kid;
  }

  sign(signingInput: Buffer): Buffer {
    return createHmac("sha256", this.secret).update(signingInput).digest();
  }

  verify(signingInput: Buffer, sig: Buffer, _keyId?: string | null): boolean {
    // `keyId` is accepted for parity with multi-key signers but not used for
    // key selection: this signer holds exactly one secret. The comparison is
    // constant-time to avoid a signature-forgery timing oracle.
    const expected = this.sign(signingInput);
    return expected.length === sig.length && timingSafeEqual(expected, sig);
  }
}

// Fixed DER wrappers for raw Ed25519 keys (RFC 8410). A raw 32-byte public key
// becomes a SubjectPublicKeyInfo by prefixing the first; a raw 32-byte private
// key becomes a PKCS#8 PrivateKeyInfo by prefixing the second.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function publicKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) {
    throw new Error(`an Ed25519 public key is 32 bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function privateKeyFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) {
    throw new Error(`an Ed25519 private key is 32 bytes, got ${raw.length}`);
  }
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicBytes(key: KeyObject): Buffer {
  const der = key.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32));
}

function rawPrivateBytes(key: KeyObject): Buffer {
  const der = key.export({ format: "der", type: "pkcs8" });
  return Buffer.from(der.subarray(der.length - 32));
}

/**
 * The production signer the draft requires ("Implementations MUST support
 * Ed25519"); JOSE alg "EdDSA". Public-key, so — unlike `HS256TestSigner` — a
 * verifier never needs the signing secret, which is exactly what offline
 * verification at an untrusted edge depends on.
 */
export class Ed25519Signer implements Signer {
  readonly alg = "EdDSA";
  readonly kid: string;
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;

  constructor(privateKey?: KeyObject, kid = "ed25519-1") {
    if (privateKey === undefined) {
      const pair = generateKeyPairSync("ed25519");
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
    } else {
      this.privateKey = privateKey;
      this.publicKey = createPublicKey(privateKey);
    }
    this.kid = kid;
  }

  /** A signer wrapping a freshly generated keypair. */
  static generate(kid = "ed25519-1"): Ed25519Signer {
    return new Ed25519Signer(undefined, kid);
  }

  /** Rebuild a signer from the 32 raw bytes `privateBytesRaw` produced. */
  static fromPrivateBytes(raw: Buffer, kid = "ed25519-1"): Ed25519Signer {
    return new Ed25519Signer(privateKeyFromRaw(raw), kid);
  }

  sign(signingInput: Buffer): Buffer {
    return cryptoSign(null, signingInput, this.privateKey);
  }

  verify(signingInput: Buffer, sig: Buffer, _keyId?: string | null): boolean {
    try {
      return cryptoVerify(null, signingInput, this.publicKey, sig);
    } catch {
      return false;
    }
  }

  /** The 32-byte raw public key — a trust anchor to distribute out of band. */
  publicBytesRaw(): Buffer {
    return rawPublicBytes(this.publicKey);
  }

  /** The 32-byte raw private key — what a key FILE stores, never a repo. */
  privateBytesRaw(): Buffer {
    return rawPrivateBytes(this.privateKey);
  }
}

/**
 * The public-key-only counterpart of `Ed25519Signer` — what a console, an
 * auditor or an ingest server holds. It verifies anchors signed by the matching
 * private key and can never sign: `sign` throws.
 */
export class Ed25519Verifier implements Signer {
  readonly alg = "EdDSA";
  readonly kid: string;
  private readonly publicKey: KeyObject;

  constructor(publicBytesRaw: Buffer, kid = "ed25519-1") {
    this.publicKey = publicKeyFromRaw(publicBytesRaw);
    this.kid = kid;
  }

  sign(_signingInput: Buffer): Buffer {
    throw new Error("Ed25519Verifier holds no private key and cannot sign");
  }

  verify(signingInput: Buffer, sig: Buffer, _keyId?: string | null): boolean {
    try {
      return cryptoVerify(null, signingInput, this.publicKey, sig);
    } catch {
      return false;
    }
  }

  publicBytesRaw(): Buffer {
    return rawPublicBytes(this.publicKey);
  }
}
