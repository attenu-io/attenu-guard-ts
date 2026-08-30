/**
 * Hash-chained audit log — the open, verifiable record of every authority decision.
 *
 * Each event is appended as one JSON line whose `hash` covers the event plus the
 * previous line's hash. Any insertion, deletion or reordering breaks the chain
 * and is detectable offline by anyone, with no vendor in the loop.
 *
 * The schema is versioned and published as `schema/agent-audit.schema.json` in
 * the Python distribution, so other tools (SIEMs, observability) can ingest it.
 * The hashes computed here are byte-identical to the Python library's for
 * identical content — see `canonical.ts` for how that is guaranteed.
 */

import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import {
  canonicalBytes,
  canonicalJson,
  parseJson,
  toPlain,
  type CJson,
} from "./canonical.js";
import type { Signer } from "./wire.js";

export const SCHEMA_VERSION = 1;
export const GENESIS = "0".repeat(64);

/** One line of the ledger. */
export type LedgerEntry = Record<string, CJson>;

/** A local destination that receives every entry after the file write. */
export interface Sink {
  write(entry: LedgerEntry): void;
}

/** A signed external commitment to a chain head. */
export interface Anchor {
  v: number;
  c14n: "JCS";
  chain_id: string;
  seq: number;
  head: string;
  ts: number | string;
  kid: string | null;
  sig: string;
  /** Set by `exportBundle`; not part of the signed body. */
  verified?: boolean;
  [key: string]: CJson | undefined;
}

/** `sha256(prev_hash || canonical(event-without-hash))`, as hex. */
export function hashEntry(prevHash: string, payload: LedgerEntry): string {
  const h = createHash("sha256");
  h.update(Buffer.from(prevHash, "utf8"));
  h.update(canonicalBytes(payload));
  return h.digest("hex");
}

function asNumber(value: CJson | undefined): number | undefined {
  const plain = toPlain(value);
  return typeof plain === "number" ? plain : undefined;
}

function withoutHash(entry: LedgerEntry): LedgerEntry {
  const out: LedgerEntry = {};
  for (const [k, v] of Object.entries(entry)) {
    if (k !== "hash") out[k] = v;
  }
  return out;
}

export interface AuditLogInit {
  /** Where to append the `.jsonl` ledger. Omit for an in-memory log. */
  path?: string | null;
  /** Local sinks; each gets every entry after the file write. */
  sinks?: readonly Sink[];
}

/** Append-only, hash-chained decision log. */
export class AuditLog {
  readonly path: string | null;
  private readonly sinks: readonly Sink[];
  private prev = GENESIS;
  private seq = 0;
  private readonly _entries: LedgerEntry[] = [];

  /**
   * Timestamps are injected by the caller (the `Guard` uses a monotonic
   * counter) so the log stays deterministic in tests and reproducible in
   * replay. In production the runtime supplies a trusted timestamp.
   */
  constructor(init: AuditLogInit | string | null = {}) {
    const opts: AuditLogInit = typeof init === "string" || init === null ? { path: init } : init;
    this.path = opts.path ?? null;
    this.sinks = opts.sinks ?? [];
    if (this.path) {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(this.path, ""); // fresh log
    }
  }

  append(event: string, ts: number | string, fields: LedgerEntry = {}): LedgerEntry {
    const payload: LedgerEntry = {
      v: SCHEMA_VERSION,
      c14n: "JCS",
      seq: this.seq,
      ts,
      event,
      ...fields,
      prev_hash: this.prev,
    };
    payload["hash"] = hashEntry(this.prev, payload);
    this.prev = payload["hash"] as string;
    this.seq += 1;
    this._entries.push(payload);
    if (this.path) {
      appendFileSync(this.path, canonicalJson(payload) + "\n");
    }
    for (const sink of this.sinks) sink.write(payload);
    return payload;
  }

  get entries(): LedgerEntry[] {
    return this._entries.slice();
  }

  get length(): number {
    return this._entries.length;
  }

  [Symbol.iterator](): Iterator<LedgerEntry> {
    return this.entries[Symbol.iterator]();
  }

  // ---- verification -----------------------------------------------------

  /** `[seq, hash]` of the last entry — the chain head; `[-1, GENESIS]` if empty. */
  head(): [number, string] {
    if (this._entries.length === 0) return [-1, GENESIS];
    const last = this._entries[this._entries.length - 1]!;
    return [asNumber(last["seq"])!, last["hash"] as string];
  }

  private chainIdHint(): string {
    return chainIdOf(this._entries);
  }

  /**
   * A signed external COMMITMENT to the chain head. Publish it out of band; a
   * later `verifyAnchor` then catches a log that was fully rewritten and
   * re-hashed, which plain `verify` cannot — a consistent rewrite reproduces
   * its own hashes. The signed head hash is the fixed point.
   */
  anchor(signer: Signer, ts: number | string = 0): Anchor {
    const [seq, head] = this.head();
    const body = { v: SCHEMA_VERSION, c14n: "JCS" as const, chain_id: this.chainIdHint(), seq, head, ts };
    return {
      ...body,
      kid: signer.kid ?? null,
      sig: signer.sign(canonicalBytes(body)).toString("hex"),
    };
  }

  /** The chain reproduces AND its head matches a SIGNED anchor. */
  static verifyAnchor(
    entries: readonly LedgerEntry[],
    anchor: Record<string, CJson> | null | undefined,
    signer: Signer,
  ): [boolean, string | null] {
    const a = anchor ?? {};
    const body: Record<string, CJson> = {};
    for (const k of ["v", "chain_id", "seq", "head", "ts"]) body[k] = a[k] ?? null;
    for (const [key, value] of Object.entries(a)) {
      if (key !== "kid" && key !== "sig" && key !== "verified") body[key] = value;
    }
    const sigHex = (toPlain(a["sig"]) as string) ?? "";
    if (typeof sigHex !== "string" || !/^(?:[0-9a-fA-F]{2})*$/.test(sigHex)) {
      return [false, "anchor signature not hex"];
    }
    const sig = Buffer.from(sigHex, "hex");
    const kid = toPlain(a["kid"]) as string | null;
    if (!signer.verify(canonicalBytes(body), sig, kid)) {
      return [false, "anchor signature invalid"];
    }
    const [ok, err] = AuditLog.verify(entries);
    if (!ok) return [false, err];
    if (entries.length === 0) return [asNumber(a["seq"]) === -1, null];
    if (toPlain(a["chain_id"]) !== firstChainId(entries)) {
      return [false, "anchor chain_id does not match the ledger entries"];
    }
    const last = entries[entries.length - 1]!;
    if (last["hash"] !== toPlain(a["head"]) || asNumber(last["seq"]) !== asNumber(a["seq"])) {
      return [false, "anchor head does not match the ledger head (ledger rewritten?)"];
    }
    return [true, null];
  }

  /** Recompute the chain. Returns `[ok, firstBadReason]`. */
  static verify(entries: readonly LedgerEntry[]): [boolean, string | null] {
    let prev = GENESIS;
    let expectedSeq = 0;
    for (const e of entries) {
      const seq = asNumber(e["seq"]);
      if (seq !== expectedSeq) {
        return [false, `seq gap at ${expectedSeq} (got ${formatSeq(e["seq"])})`];
      }
      const stored = e["hash"];
      const payload = withoutHash(e);
      if (toPlain(payload["prev_hash"]) !== prev) {
        return [false, `prev_hash mismatch at seq ${expectedSeq}`];
      }
      if (hashEntry(prev, payload) !== stored) {
        return [false, `hash mismatch at seq ${expectedSeq}`];
      }
      prev = stored as string;
      expectedSeq += 1;
    }
    return [true, null];
  }

  /** Read a `.jsonl` ledger, keeping every number's original literal. */
  static load(path: string): LedgerEntry[] {
    return AuditLog.parseLines(readFileSync(path, "utf8"));
  }

  /** Parse `.jsonl` text into entries. Blank lines are skipped. */
  static parseLines(text: string): LedgerEntry[] {
    return text
      .split(/\r?\n/)
      .filter((line) => line.trim() !== "")
      .map((line) => parseJson(line) as LedgerEntry);
  }
}

function formatSeq(value: CJson | undefined): string {
  const plain = toPlain(value);
  return plain === undefined || plain === null ? "None" : String(plain);
}

/** The first `chain_id` any entry carries, or `"chain"`. */
export function chainIdOf(entries: readonly LedgerEntry[]): string {
  for (const e of entries) {
    const id = toPlain(e["chain_id"]);
    if (typeof id === "string" && id) return id;
  }
  return "chain";
}

/**
 * The first `chain_id` any entry carries, or `null` if none do. Unlike
 * `chainIdOf` (which defaults to `"chain"` for display/anchoring purposes),
 * `verifyAnchor` needs to know whether the entries genuinely assert a chain
 * identity at all, so a missing one is `null`, not a fabricated default.
 */
function firstChainId(entries: readonly LedgerEntry[]): string | null {
  for (const e of entries) {
    const id = toPlain(e["chain_id"]);
    if (typeof id === "string" && id) return id;
  }
  return null;
}
