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
  // 0.9.0 execution-binding transition (schema_version=2 chains only — see guard.ts):
  /** `check` refused: the node already called `complete()`. */
  NODE_FINALIZED: "node_finalized",
  /**
   * The CSPRNG failed while allocating `callId`; fail-closed — the call is denied and
   * nothing is written.
   */
  CALL_ID_UNAVAILABLE: "call_id_unavailable",
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

/**
 * What the adapter's code path WILL observe for a given `check`ed call (0.9.0 execution binding)
 * — recorded on the `allow` entry alongside `adapter` (module/version/hookPath). Describes
 * observation CAPABILITY only, never a claim of quality: a verifier routes a call into
 * observed/unobserved reporting from this label, never trusts it as evidence on its own.
 */
export const Capture = {
  /** The adapter's wrapper calls the body itself, synchronously. */
  WRAPPER_SYNC: "wrapper_sync",
  /** ... and awaits it. */
  WRAPPER_ASYNC: "wrapper_async",
  /** The framework itself calls back after the body runs. */
  FRAMEWORK_POST_HOOK: "framework_post_hook",
  /** The adapter sees the call authorized but never observes it finish. */
  PRE_HOOK_ONLY: "pre_hook_only",
} as const;

export type CaptureValue = (typeof Capture)[keyof typeof Capture];

export const CAPTURES: ReadonlySet<string> = new Set(Object.values(Capture));

/**
 * The `outcome` record's observation of how a body-owning wrapper's call ended (0.9.0 execution
 * binding, docs/execution-binding spec section 3) — an OBSERVATION, not a judgment about the
 * world. There is no `executed`/`blocked`/`timeout`/`cancelled` at this layer; each of those
 * words claims knowledge a wrapper does not always have. Adapters emitting into a richer outcome
 * vocabulary own that mapping.
 */
export const BodyState = {
  /** The body returned to the wrapper. */
  RETURNED: "returned",
  /** It raised (`errorCode` required, from the exception's class/constructor name). */
  RAISED: "raised",
  /** The wrapper stopped observing while the body may still run. */
  ABANDONED: "abandoned",
  /** The wrapper returned a generator/stream/future it does not itself consume. */
  DEFERRED: "deferred",
} as const;

export type BodyStateValue = (typeof BodyState)[keyof typeof BodyState];

export const BODY_STATES: ReadonlySet<string> = new Set(Object.values(BodyState));

/**
 * `Guard.complete()`'s return value (0.9.0, docs/execution-binding spec section 1): whether the
 * node was actually finalized, and — when it refused because calls are still pending an outcome
 * — the `callId`s it is waiting on.
 *
 * Python's equivalent is bool-coercible via `__bool__`, so `if guard.complete():` keeps reading
 * naturally there. JavaScript has no such hook for `if` — `ToBoolean` on any object is
 * unconditionally `true`, so an `if (guard.complete())` check cannot be bridged to `false` no
 * matter what this class defines, and neither can `assert.equal`/`assert.strictEqual` from
 * `node:assert/strict` (no coercion at all — this project's own test suite uses it, so its
 * existing `assert.equal(g.complete(), true)`-shaped call sites were updated to read
 * `.completed` rather than relying on a bridge that cannot exist for them). What CAN be bridged:
 * `valueOf()` returns `.completed`, so contexts that genuinely coerce via `==`/`!=` (loose
 * equality), template literals, and arithmetic still read as the bare boolean `complete()` used
 * to return. Read `.completed` explicitly wherever you would have written `if (guard.complete())`.
 */
export class CompletionResult {
  constructor(
    readonly completed: boolean,
    readonly pendingCallIds: readonly string[] = [],
  ) {}

  valueOf(): boolean {
    return this.completed;
  }

  toString(): string {
    return String(this.completed);
  }
}

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
    /**
     * 0.9.0 execution binding: set only on a `schemaVersion: 2` chain (`Guard.check` /
     * `Guard.recordDenial`); `null` on schema-version-1 chains and on any `Decision` built
     * outside a `Guard` transition (`wouldAllow`, tests).
     */
    readonly callId: string | null = null,
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
      call_id: this.callId,
    };
  }

  /** A copy of this Decision with `callId` set — mirrors Python's `dataclasses.replace`. */
  withCallId(callId: string | null): Decision {
    return new Decision(this.allowed, this.reasons, this.determiningNode, callId);
  }

  static allow(node: string | null = null): Decision {
    return new Decision(true, [], node);
  }

  static deny(reasons: Reason | readonly Reason[], node: string | null = null): Decision {
    const list = reasons instanceof Reason ? [reasons] : Array.from(reasons);
    return new Decision(false, list, node);
  }
}
