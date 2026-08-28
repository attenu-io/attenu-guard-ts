/**
 * reasons.ts — the machine-readable outcome vocabulary for authorization decisions.
 *
 * Every policy evaluation produces a `Decision` carrying zero or more `Reason`s.
 * A denial without a reason is a bug, so every deny path attaches at least one
 * `Reason` with a stable code from `ReasonCode`.
 *
 * The code strings — not the classes — are the contract. They are what the audit
 * ledger stores and what survives a process or language boundary, so they match
 * the Python library's `attenu_guard.reasons` value for value.
 */

import type { Json } from "./canonical.js";

/**
 * Stable string constants for machine-readable denial reasons. Never rename an
 * existing value; add new ones instead.
 */
export const ReasonCode = {
  SCOPE_NOT_GRANTED: "scope_not_granted",
  CEILING_EXCEEDED: "ceiling_exceeded",
  EXPIRED: "expired",
  REVOKED: "revoked",
  INTEGRITY: "integrity",
  DEPTH_EXCEEDED: "depth_exceeded",
  FANOUT_EXCEEDED: "fanout_exceeded",
  UNMETERED: "unmetered",
  /** Fail-closed outcome for a ceiling type this build does not recognise. */
  UNKNOWN_CONSTRAINT: "unknown_constraint",
  // Structural failures — the reason strings an `AuthorityError` carries when a
  // DELEGATION is refused. These are the published v0.1 audit vocabulary.
  CHAIN_REVOKED: "chain_revoked",
  AGENT_BANNED: "agent_banned",
  TTL_EXPIRED: "ttl_expired",
  MAX_DEPTH: "max_depth",
  MAX_FANOUT: "max_fanout",
  CHAIN_CEILING: "chain_ceiling",
  /** The principal holds no authority at all in this chain. */
  NO_AUTHORITY: "no_authority",
} as const;

export type ReasonCodeValue = (typeof ReasonCode)[keyof typeof ReasonCode];

/**
 * WHY a denied scope was not in the node's authority — the ledger's answer to
 * "held, or over-reach?". The library records what its caller states; it never
 * derives. Never rename a value.
 */
export const Disposition = {
  /** Known, curated, waiting on a human decision. */
  HELD_PENDING_GRANT: "held_pending_grant",
  /** Resolvable only to a tier-2 heuristic that is never granted. */
  WITHHELD_TIER2: "withheld_tier2",
  /** No authority known for this tool at all. */
  UNRESOLVED: "unresolved",
  /** Resolved and grantable, but not held by THIS node — real over-reach. */
  OUT_OF_AUTHORITY: "out_of_authority",
} as const;

export type DispositionValue = (typeof Disposition)[keyof typeof Disposition];

export const DISPOSITIONS: ReadonlySet<string> = new Set(Object.values(Disposition));

export interface ReasonInit {
  /** Which ceiling or dimension, e.g. "max_rows". */
  constraint?: string | null;
  /** The bound that applied. */
  limit?: Json;
  /** The value or action that violated it. */
  requested?: Json;
  /** Free-text, human-readable detail. */
  message?: string;
}

/** One specific cause of a denial. */
export class Reason {
  readonly code: string;
  readonly constraint: string | null;
  readonly limit: Json;
  readonly requested: Json;
  readonly message: string;

  constructor(code: string, init: ReasonInit = {}) {
    this.code = code;
    this.constraint = init.constraint ?? null;
    this.limit = init.limit ?? null;
    this.requested = init.requested ?? null;
    this.message = init.message ?? "";
  }

  toDict(): Record<string, Json> {
    return {
      code: this.code,
      constraint: this.constraint,
      limit: this.limit,
      requested: this.requested,
      message: this.message,
    };
  }

  toString(): string {
    const bits = [this.code];
    if (this.constraint !== null) bits.push(`constraint=${this.constraint}`);
    if (this.limit !== null) bits.push(`limit=${renderValue(this.limit)}`);
    if (this.requested !== null) bits.push(`requested=${renderValue(this.requested)}`);
    const line = bits.join(" ");
    return this.message ? `${line}: ${this.message}` : line;
  }
}

function renderValue(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(renderValue).join(", ")}]`;
  if (value !== null && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * The result of a policy evaluation. Truthiness lives on `.allowed` — JavaScript
 * has no `__bool__`, so call sites read `if (decision.allowed)`.
 *
 * `determiningNode` names the chain node whose state was decisive.
 */
export class Decision {
  constructor(
    readonly allowed: boolean,
    readonly reasons: readonly Reason[] = [],
    readonly determiningNode: string | null = null,
  ) {}

  /** A single human-readable line — for logs, CLIs and error messages. */
  explain(): string {
    if (this.allowed) return "allowed";
    if (this.reasons.length === 0) return "denied";
    return "denied: " + this.reasons.map((r) => r.toString()).join("; ");
  }

  toDict(): Record<string, Json> {
    return {
      allowed: this.allowed,
      reasons: this.reasons.map((r) => r.toDict()),
      determining_node: this.determiningNode,
    };
  }

  static allow(node: string | null = null): Decision {
    return new Decision(true, [], node);
  }

  static deny(reasons: Reason | readonly Reason[], node: string | null = null): Decision {
    const list = reasons instanceof Reason ? [reasons] : Array.from(reasons);
    return new Decision(false, list, node);
  }
}
