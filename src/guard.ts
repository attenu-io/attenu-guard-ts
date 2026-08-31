/**
 * Guard — the runtime object a developer actually holds.
 *
 *   `Guard.issue(...)`  a fresh root Guard, starting a new delegation chain.
 *   `delegate(...)`     a child Guard whose authority is the attenuated meet of
 *                       this guard's authority and what was requested. It never
 *                       widens — there is no method that can. Throws
 *                       `AuthorityError` on a STRUCTURAL failure (revoked or
 *                       expired parent, integrity failure, depth/fanout).
 *   `check(...)`        authorize an action. Returns a `Decision`; it never
 *                       throws on a policy denial, because a denial is a normal
 *                       outcome to reason about, not a bug. Every allow and
 *                       deny is appended to the audit log.
 *   `enforce(...)`      `check` and throw `AuthorityDenied` if not allowed —
 *                       the hard-stop gate for callers that want to fail fast.
 *   `wouldAllow(...)`   the same policy evaluation as `check`, as a pure
 *                       dry-run: it writes NOTHING to the audit log, so a
 *                       planner can ask "could I do this?" without leaving a
 *                       record as though the action had been attempted.
 *   `revoke(...)`       cascade-revoke a node (by default this one) and its
 *                       whole subtree.
 *
 * `AuthorityError` and `AuthorityDenied` are deliberately distinct: a policy
 * denial is not an error.
 *
 * The audit log's `event` strings keep the original vocabulary
 * (`spawn`/`spawn_denied`/`kill`) even though the API reads
 * issue/delegate/revoke. That field is a separately-versioned published wire
 * contract that verifiers depend on.
 *
 * ## Execution binding (0.9.0, `Guard.issue(agentId, authority, {schemaVersion: 2})` only)
 *
 * `schemaVersion: 1` chains (the default — nothing below applies to them) behave EXACTLY as they
 * did before 0.9.0: no `callId`, no pending tracking, no `NODE_FINALIZED` refusal, `check`'s new
 * `authorizedParams`/`capture`/`adapter` options throw if supplied. A caller opts in per chain,
 * once, at `Guard.issue` — schema versions never mix within a chain
 * (docs/execution-binding spec section 9).
 *
 * On a `schemaVersion: 2` chain, `check`'s transition is, in order:
 *
 *   1. refuse if the node is already `complete()`d (`ReasonCode.NODE_FINALIZED`);
 *   2. otherwise evaluate authority/ceilings and update meters (`evaluate` + auto-metering,
 *      unchanged from schema version 1);
 *   3. allocate `callId` — 16 bytes from `crypto.randomBytes`, lowercase hex; if that throws, the
 *      call is denied and NOTHING is appended (`ReasonCode.CALL_ID_UNAVAILABLE`);
 *   4. commit the entry (append to the audit log — may throw `CommittedAuditError` if persistence
 *      fails AFTER the in-memory commit; this method attaches `.decision` to that error before it
 *      propagates, per spec section 1: "carries the committed entry and the decision");
 *   5. register an allowed call as pending (even across a `CommittedAuditError` — spec: "the
 *      guard registers an allowed call as pending before raising");
 *   6. return the `Decision`, which now carries `.callId`.
 *
 * `recordOutcome` is the producer API a body-owning wrapper calls once it knows how the call
 * ended; `complete` refuses (returns a falsy-in-`==` `CompletionResult`) while calls are still
 * pending; `revoke`/`revokeAgent` snapshot the still-pending callIds onto the `kill` entry as
 * `pending_at_kill` without clearing them — a late `recordOutcome` after a kill is accepted.
 *
 * JavaScript has no analogue of Python's `__bool__`, so unlike the Python library,
 * `if (guard.complete())` cannot be made to read `false` on refusal — see `CompletionResult`'s
 * own doc comment in reasons.ts for exactly what IS and is not bridged.
 */

import type { Json } from "./canonical.js";
import { Authority, AuthorityError } from "./authority.js";
import { AuditLog, CommittedAuditError, type LedgerEntry, type Sink } from "./audit.js";
import { Chain, MonotonicClock, type Clock, type Node } from "./chain.js";
import { ctxFieldOf, isMetered, type Ceiling, type Context } from "./ceilings.js";
import {
  BODY_STATES,
  BodyState,
  CAPTURES,
  Capture,
  CompletionResult,
  DISPOSITIONS,
  Decision,
  Disposition,
  Reason,
  ReasonCode,
} from "./reasons.js";
import * as paramsMod from "./params.js";
import { ParamsHashReason } from "./params.js";
import { VERSION } from "./version.js";
import { randomBytes } from "node:crypto";
import type { StrikePolicy } from "./strikes.js";

/**
 * Thrown only by `enforce`. Carries the full `Decision`, so a caller can branch
 * on `err.decision.reasons[0].code` instead of parsing a message string.
 */
export class AuthorityDenied extends Error {
  constructor(readonly decision: Decision) {
    super(decision.explain());
    this.name = "AuthorityDenied";
  }
}

/**
 * Thrown by `Guard.recordOutcome` when `callId` already has a recorded outcome in this chain's
 * lifetime. A programming error in the caller (a wrapper observing the same call twice), not a
 * policy outcome — "exactly one outcome per callId, enforced at append" (docs/execution-binding
 * spec section 3).
 */
export class DuplicateOutcomeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DuplicateOutcomeError";
  }
}

/**
 * A monotonic integer for audit sequencing, distinct from the wall clock used
 * for TTL expiry — it keeps the log's ordering deterministic regardless of
 * clock resolution.
 */
class SeqClock {
  private t = 0;
  now(): number {
    this.t += 1;
    return this.t;
  }
}

export interface IssueOptions {
  task?: string;
  chainId?: string;
  maxDepth?: number;
  maxFanout?: number;
  /** Where to write the `.jsonl` ledger. Omit for an in-memory log. */
  auditPath?: string | null;
  clock?: Clock;
  /** Refuse a metered call that omits a held metered ceiling's context field. */
  strictMetering?: boolean;
  strikes?: StrikePolicy | null;
  auditSinks?: readonly Sink[];
  /**
   * 0.9.0: pass `2` to opt this WHOLE chain into execution binding (`callId`,
   * `capture`/`adapter`, params commitments, `recordOutcome` — see the module doc comment).
   * Default `1`, unchanged from every prior release. A chain never mixes schema versions.
   */
  schemaVersion?: number;
  /** Allow opening an `auditPath` that already names a non-empty ledger, replacing it. */
  auditOverwrite?: boolean;
}

/** `{module, version, hookPath}` — the adapter code path that produced an execution-bound record. */
export interface AdapterInfo {
  module: string;
  version: string;
  hookPath: string;
}

export interface CheckOptions {
  context?: Context | null;
  /** Marks the call as consuming a metered resource; see `strictMetering`. */
  metered?: boolean;
  /** The tool label recorded on the ledger entry. */
  tool?: string | null;
  /** What the caller knows about WHY this scope would be absent. */
  disposition?: string | null;
  /**
   * 0.9.0 execution binding (`schemaVersion: 2` chains only): the exact tool-call JSON object
   * presented at authorization time. Hashed via `params_c14n_v1`, never logged. Omit entirely to
   * opt this call out of the commitment (distinct from passing `null`, an authorized-params value
   * of JSON `null`).
   */
  authorizedParams?: Json;
  /**
   * 0.9.0 execution binding: one of the `Capture` constants describing what the caller's wrapper
   * will be able to observe. Required together with `adapter`.
   */
  capture?: string | null;
  /** 0.9.0 execution binding: the adapter code path, required together with `capture`. */
  adapter?: AdapterInfo | null;
}

export interface RecordDenialOptions {
  scope?: string | null;
  tool?: string | null;
  context?: Context | null;
  disposition?: string | null;
}

/** `{type, ref, digest}` — unverified carriage from an external observer (spec section 7). */
export interface ReceiptInfo {
  type: string;
  ref: string;
  digest: string;
}

export interface RecordOutcomeOptions {
  /** Required exactly when `bodyState === BodyState.RAISED`; a normalized exception class name. */
  errorCode?: string | null;
  /**
   * The JSON object the wrapper observed immediately before the actual invocation — hashed the
   * same way as `check`'s `authorizedParams`. Omit entirely to opt out (distinct from `null`).
   */
  invokedParams?: Json;
  /** Observation start to observation end, milliseconds. Required. */
  durationMs: number;
  /** Unverified carriage, `{type, ref, digest}` (docs/execution-binding spec section 7). */
  receipt?: ReceiptInfo | null;
}

export class Guard {
  private constructor(
    private readonly node: Node,
    private readonly chain: Chain,
    private readonly audit: AuditLog,
    private readonly seq: SeqClock,
    private readonly strict: boolean,
    private readonly strikes: StrikePolicy | null,
  ) {}

  // ---- factory ----------------------------------------------------------

  /**
   * A fresh root Guard, starting a new delegation chain. `schemaVersion: 2` opts the whole chain
   * into 0.9.0 execution binding — see the module doc comment.
   *
   * `auditOverwrite: true` (silently replace an existing non-empty ledger at `auditPath`) is
   * REFUSED on a `schemaVersion: 2` chain: the restart rule has no escape hatch on v2 — a v2
   * process restart must always open a NEW audit path, never overwrite an old one, so that a
   * pending call from before the restart stays truthfully unaccounted rather than vanishing
   * under a fresh chain at the same path. v1 keeps the flag exactly as before.
   */
  static issue(agentId: string, authority: Authority, options: IssueOptions = {}): Guard {
    const chainId = options.chainId ?? "chain";
    const schemaVersion = options.schemaVersion ?? 1;
    if (schemaVersion !== 1 && schemaVersion !== 2) {
      throw new Error(`unsupported schemaVersion ${schemaVersion}; expected 1 or 2`);
    }
    if (schemaVersion === 2 && options.auditOverwrite) {
      throw new Error(
        "auditOverwrite: true is not permitted on a schemaVersion: 2 chain — the restart rule " +
          "has no escape hatch on v2 (docs/execution-binding spec section 1). Open a new audit " +
          "path for the new chain instead; v1 chains may still set auditOverwrite: true.",
      );
    }
    const chain = new Chain(chainId, {
      maxDepth: options.maxDepth ?? 6,
      maxFanout: options.maxFanout ?? 16,
      clock: options.clock ?? new MonotonicClock(),
    });
    const audit = new AuditLog({
      path: options.auditPath ?? null,
      sinks: options.auditSinks ?? [],
      schemaVersion,
      overwrite: options.auditOverwrite ?? false,
    });
    const seq = new SeqClock();
    const node = chain.addRoot(agentId, authority, options.task ?? "root");
    const rootFields: LedgerEntry = {
      chain_id: chainId,
      node: node.nodeId,
      agent: agentId,
      authority: authority.toWire() as unknown as Json,
    };
    if (schemaVersion === 2) {
      chain.paramsSalt = randomBytes(16);
      rootFields["params_salt"] = chain.paramsSalt.toString("hex");
    }
    audit.append("root", seq.now(), rootFields);
    return new Guard(node, chain, audit, seq, options.strictMetering ?? false, options.strikes ?? null);
  }

  // ---- identity ---------------------------------------------------------

  get nodeId(): string {
    return this.node.nodeId;
  }

  get chainId(): string {
    return this.chain.chainId;
  }

  get authority(): Authority {
    return this.node.authority;
  }

  /** The `agentId` this Guard was issued or delegated to. */
  get agentId(): string {
    return this.node.agentId;
  }

  /** Has this node — or an ancestor — been revoked? */
  get isRevoked(): boolean {
    return this.chain.isRevoked(this.node.nodeId);
  }

  /** Has this node's TTL elapsed? */
  get isExpired(): boolean {
    return this.chain.isExpired(this.node);
  }

  /** Did the holder mark this node's work finished? */
  get isComplete(): boolean {
    return this.node.complete;
  }

  /**
   * 0.9.0: the schema version this Guard's chain was issued at (1 or 2 — see
   * `Guard.issue({schemaVersion})`). Adapters use this to decide whether to pass
   * `capture`/`adapter`/`authorizedParams` to `check` and call `recordOutcome` afterwards,
   * rather than reaching into the audit log directly.
   */
  get schemaVersion(): number {
    return this.audit.schemaVersion;
  }

  private get isV2(): boolean {
    return this.schemaVersion === 2;
  }

  /** Is `other` an ancestor of this guard in the same chain? */
  isDescendantOf(other: Guard): boolean {
    if (other.chain !== this.chain) return false;
    let node: Node | undefined = this.node;
    while (node !== undefined && node.parentId !== null) {
      if (node.parentId === other.node.nodeId) return true;
      node = this.chain.nodes.get(node.parentId);
    }
    return false;
  }

  /**
   * Mark this node's work FINISHED — one `done` event.
   *
   * On a `schemaVersion: 2` chain, returns a `CompletionResult` (see its own doc comment in
   * reasons.ts for the JavaScript-specific limits of its truthiness bridge) and refuses — a
   * falsy-by-`.completed` `CompletionResult` carrying `.pendingCallIds` — while this node has
   * `allow`ed calls that have not yet reported an outcome; completing while a call is still open
   * would be a false claim that the node's work is finished. Idempotent:
   * `CompletionResult(false, [])` if already marked.
   *
   * On a `schemaVersion: 1` chain (the default) this returns a plain `boolean`, byte-and-type
   * IDENTICAL to every release before 0.9.0 — v1 never gained pending-call awareness, so there is
   * nothing new to report and no reason to change its return type. Purely a lifecycle marker
   * either way — it does NOT change authority; revocation is the hard stop.
   */
  complete(): boolean | CompletionResult {
    const v2 = this.isV2;
    if (this.node.complete) return v2 ? new CompletionResult(false, []) : false;
    const pending = v2 ? this.chain.pendingFor(this.node.nodeId) : [];
    if (pending.length > 0) return new CompletionResult(false, pending); // only reachable on v2
    this.node.complete = true;
    this.append("done", {
      chain_id: this.chainId,
      node: this.node.nodeId,
      agent: this.node.agentId,
    });
    return v2 ? new CompletionResult(true, []) : true;
  }

  // ---- delegation -------------------------------------------------------

  /**
   * Create a child Guard. The child's authority is `this.authority.meet(request)`
   * — provably narrower than this guard's by construction. A request wider than
   * what this guard holds comes back narrowed, not refused.
   *
   * Throws `AuthorityError` for structural failures (revoked or expired parent,
   * integrity failure, depth/fanout overflow). Those are invalid calls, not
   * policy outcomes, so they are not expressed as a Decision.
   */
  delegate(agentId: string, request: Authority, task: string): Guard {
    let child: Node;
    try {
      child = this.chain.addChild(this.node.nodeId, agentId, request, task);
    } catch (e) {
      if (e instanceof AuthorityError) {
        this.append("spawn_denied", {
          chain_id: this.chainId,
          parent: this.node.nodeId,
          agent: agentId,
          task,
          reason: e.reason,
          detail: e.detail,
        });
      }
      throw e;
    }
    this.append("spawn", {
      chain_id: this.chainId,
      parent: this.node.nodeId,
      node: child.nodeId,
      agent: agentId,
      task,
      requested: request.toWire() as unknown as Json,
      granted: child.authority.toWire() as unknown as Json,
    });
    return new Guard(child, this.chain, this.audit, this.seq, this.strict, this.strikes);
  }

  /**
   * A pure dry-run of `delegate`'s structural preconditions (revoked or expired
   * parent, banned agent, depth/fanout ceilings): creates no node, consumes no
   * fanout, writes nothing. The granted authority would be
   * `this.authority.meet(request)`.
   */
  wouldDelegate(agentId: string, _request?: Authority): Decision {
    const err = this.chain.delegationError(this.node.nodeId, agentId);
    if (err === null) return Decision.allow(this.node.nodeId);
    return Decision.deny(new Reason(err.reason, { message: err.message }), this.node.nodeId);
  }

  private append(event: string, fields: LedgerEntry): LedgerEntry {
    return this.audit.append(event, this.seq.now(), fields);
  }

  // ---- policy evaluation ------------------------------------------------

  /**
   * The actual policy evaluation, shared verbatim by `check` and `wouldAllow`.
   * Node state (integrity, revocation, TTL) is checked before scope and
   * ceilings, because a compromised or revoked node's scope grants are moot.
   */
  private evaluate(scope: string, context: Context, metered: boolean): Decision {
    const { node, chain } = this;
    const auth = node.authority;
    const nid = node.nodeId;

    if (!chain.verifyIntegrity(node)) {
      return Decision.deny(
        new Reason(ReasonCode.INTEGRITY, { message: "authority state failed its integrity seal" }),
        nid,
      );
    }
    if (chain.isRevoked(nid)) {
      return Decision.deny(
        new Reason(ReasonCode.REVOKED, { message: "node has been revoked" }),
        nid,
      );
    }
    if (chain.isExpired(node)) {
      const age = chain.clock.now() - node.issuedAt;
      return Decision.deny(
        new Reason(ReasonCode.EXPIRED, {
          limit: auth.ttl,
          requested: age,
          message: "authority ttl has elapsed",
        }),
        nid,
      );
    }

    // Strict metering: a call flagged as consuming a metered resource must
    // DECLARE every metered dimension this node holds a ceiling on; any it
    // omits is refused rather than silently treated as free. Checked PER
    // CEILING, not "is the context empty?" — a partial context that mentions
    // egress but forgets rows would otherwise let the row ceiling go
    // unevaluated, which is the exact slip a per-tool context function makes.
    if (this.strict && metered) {
      const missing = auth.ceilings
        .filter((c) => isMetered(c) && !(ctxFieldOf(c) in context))
        .map((c) => c.key);
      if (missing.length > 0) {
        const held = auth.ceilings.filter(isMetered).map((c) => c.key);
        return Decision.deny(
          new Reason(ReasonCode.UNMETERED, {
            constraint: missing.join(","),
            message:
              `metered=True but context omits [${missing.map((m) => `'${m}'`).join(", ")}]; ` +
              `metered ceilings held: [${held.map((m) => `'${m}'`).join(", ")}]`,
          }),
          nid,
        );
      }
    }

    const decision = auth.permits(scope, context);
    if (decision.determiningNode === null) {
      return new Decision(decision.allowed, decision.reasons, nid);
    }
    return decision;
  }

  private static checkDisposition(disposition: string | null | undefined): void {
    if (disposition !== null && disposition !== undefined && !DISPOSITIONS.has(disposition)) {
      throw new Error(
        `unknown disposition ${JSON.stringify(disposition)}; expected one of ` +
          `${Array.from(DISPOSITIONS).sort().join(", ")}`,
      );
    }
  }

  private logDecision(
    decision: Decision,
    scope: string,
    tool: string | null,
    context: Context,
    disposition: string | null,
    extraFields?: LedgerEntry,
  ): LedgerEntry {
    const event = decision.allowed ? "allow" : "deny";
    const fields: LedgerEntry = {
      chain_id: this.chainId,
      node: this.node.nodeId,
      scope,
      tool,
      context: { ...context } as unknown as Json,
    };
    if (!decision.allowed) {
      // "reason" is a single code string, the shape the published schema
      // documents and every existing consumer reads. "reasons" is the full
      // structured list for anyone who wants every violated Reason.
      const reason = decision.reasons.length > 0 ? decision.reasons[0]!.code : null;
      fields["reason"] = reason;
      fields["reasons"] = decision.reasons.map((r) => r.toDict()) as unknown as Json;
      // "disposition": WHY the scope was absent — the caller's statement, or,
      // for a plain scope_not_granted the caller did not explain, the library's
      // own truth: out_of_authority. Allow entries never carry it.
      const d =
        disposition ??
        (reason === ReasonCode.SCOPE_NOT_GRANTED ? Disposition.OUT_OF_AUTHORITY : null);
      if (d !== null) fields["disposition"] = d;
    }
    if (extraFields) Object.assign(fields, extraFields);
    return this.append(event, fields);
  }

  // ---- enforcement ------------------------------------------------------

  private callLimits(): Ceiling[] {
    return this.node.authority.ceilings.filter((c) => String(c.key).startsWith("max_calls"));
  }

  /**
   * Fill in `calls` / `calls[<pattern>]` for every held call ceiling the caller
   * left undeclared, reading the per-(node, pattern) meter. Returns the limits
   * that were auto-filled AND apply to this scope, to be counted on allow.
   */
  private autoMeter(scope: string, ctx: Context): Ceiling[] {
    const filled: Ceiling[] = [];
    for (const c of this.callLimits()) {
      const field = c.ctxField ?? "calls";
      if (field in ctx) continue; // an explicit count wins
      const applies = c.appliesToScope ? c.appliesToScope(scope) : true;
      ctx[field] = this.chain.callsSoFar(this.node.nodeId, c.meterKey ?? "*") + (applies ? 1 : 0);
      if (applies) filled.push(c);
    }
    return filled;
  }

  private static attachCallId(decision: Decision, callId: string | null): Decision {
    return callId === null ? decision : decision.withCallId(callId);
  }

  /**
   * `[hashHex, reason]` against this chain's `paramsSalt` — see params.ts. `[null, null]` if the
   * caller omitted the option entirely (opted out of this specific commitment).
   */
  private paramsCommitment(value: Json | undefined): [string | null, string | null] {
    if (value === undefined) return [null, null];
    const salt = this.chain.paramsSalt;
    if (salt === null) return [null, ParamsHashReason.UNSUPPORTED]; // cannot happen for a properly-issued v2 chain
    return paramsMod.commit(value, salt);
  }

  private static validateCaptureAdapter(capture: string | null, adapter: AdapterInfo | null): void {
    if (capture !== null && !CAPTURES.has(capture)) {
      throw new Error(
        `unknown capture ${JSON.stringify(capture)}; expected one of ` +
          `${Array.from(CAPTURES).sort().join(", ")}`,
      );
    }
    if (capture !== null && adapter === null) {
      throw new Error(
        "adapter: {module, version, hookPath} is required alongside capture " +
          "(docs/execution-binding spec section 2)",
      );
    }
    if (adapter !== null) {
      const missing = (["module", "version", "hookPath"] as const).filter(
        (k) => !(k in (adapter as unknown as Record<string, unknown>)),
      );
      if (missing.length > 0) {
        throw new Error(`adapter is missing ${JSON.stringify(missing)}; expected module/version/hookPath`);
      }
    }
  }

  /**
   * Authorize an action. Returns a `Decision`; it does not throw on a denial.
   * Every call — allow or deny — is appended to the audit log.
   *
   * Auto-metering: when this node holds a `CallLimit` and the caller did not
   * supply `calls`, the guard supplies the running count for (node, pattern)
   * itself, including this call, and increments it on allow. An explicit
   * `calls` in the context always wins.
   *
   * `authorizedParams`/`capture`/`adapter` (0.9.0, `schemaVersion: 2` chains only — throws
   * otherwise): the execution-binding inputs, see the module doc comment and
   * docs/execution-binding spec sections 1-4. On a schema-version-2 chain, the returned
   * `Decision.callId` is what a later `recordOutcome` call binds to.
   */
  check(scope: string, options: CheckOptions = {}): Decision {
    const disposition = options.disposition ?? null;
    Guard.checkDisposition(disposition); // refuse before anything reaches the ledger
    const isV2 = this.isV2;
    const authorizedParams = options.authorizedParams;
    const capture = options.capture ?? null;
    const adapter = options.adapter ?? null;
    if (!isV2 && (authorizedParams !== undefined || capture !== null || adapter !== null)) {
      throw new Error(
        "authorizedParams/capture/adapter require a schemaVersion: 2 chain " +
          "(Guard.issue(..., {schemaVersion: 2}))",
      );
    }
    Guard.validateCaptureAdapter(capture, adapter);

    const ctx: Context = { ...(options.context ?? {}) };
    const nid = this.node.nodeId;

    // 1. refuse if the node is finalized (v2 only — a v1 chain's `complete()` has always been a
    //    pure informational marker that leaves authority, and `check`, untouched).
    let decision: Decision;
    let filled: Ceiling[];
    if (isV2 && this.node.complete) {
      decision = Decision.deny(
        new Reason(ReasonCode.NODE_FINALIZED, { message: "node already finalized (complete())" }),
        nid,
      );
      filled = [];
    } else {
      // 2. evaluate authority/ceilings; update meters on allow.
      filled = this.autoMeter(scope, ctx);
      decision = this.evaluate(scope, ctx, options.metered ?? false);
      if (decision.allowed) {
        for (const c of filled) this.chain.countCall(nid, c.meterKey ?? "*");
      }
    }

    // 3. allocate callId (v2 only) — fail-closed, nothing written, if the CSPRNG throws.
    let callId: string | null = null;
    if (isV2) {
      try {
        callId = randomBytes(16).toString("hex");
      } catch (exc) {
        // Pre-commit failure (spec section 1): meters are restored, nothing is pending, the call
        // is denied, nothing is appended.
        if (decision.allowed) {
          for (const c of filled) this.chain.uncountCall(nid, c.meterKey ?? "*");
        }
        return Decision.deny(new Reason(ReasonCode.CALL_ID_UNAVAILABLE, { message: String(exc) }), nid);
      }
    }

    const extra: LedgerEntry = {};
    if (isV2) {
      extra["call_id"] = callId;
      if (decision.allowed) {
        if (capture !== null) {
          extra["capture"] = capture;
          extra["adapter"] = {
            module: adapter!.module,
            version: adapter!.version,
            hook_path: adapter!.hookPath,
          } as unknown as Json;
        } else {
          // A bare check() with no wrapper IS itself an observation, honestly described:
          // authorization was observed; execution was not. The guard supplies this default
          // rather than leaving capture/adapter absent, so every v2 allow carries them — the
          // verifier requires both (merge-gate item 4); the caller-facing API stays optional,
          // the ledger is not.
          extra["capture"] = Capture.PRE_HOOK_ONLY;
          extra["adapter"] = { module: "attenu-guard", version: VERSION, hook_path: "Guard.check" } as unknown as Json;
        }
        const [ph, preason] = this.paramsCommitment(authorizedParams);
        if (ph !== null) extra["authorized_params_hash"] = ph;
        else if (preason !== null) extra["params_hash_reason"] = preason;
      }
    }

    // 4. commit (append) — a post-commit persistence failure throws CommittedAuditError; attach
    //    `.decision` (spec: "carries the committed entry and the decision") before it propagates,
    //    and still register the pending call first (step 5). ANY OTHER exception here (e.g. a
    //    canonicalization failure while hashing the entry, inside AuditLog.append's hashEntry
    //    call, which runs BEFORE its commit point) is a pre-commit failure exactly like the
    //    CSPRNG case above: meters are restored, nothing is pending, and the exception is
    //    re-thrown as-is (not swallowed into a Decision — unlike CSPRNG exhaustion, a malformed
    //    context/authorizedParams value is the caller's error, and this library's convention
    //    elsewhere is to throw on malformed input, not silently deny).
    try {
      this.logDecision(decision, scope, options.tool ?? null, ctx, disposition, extra);
    } catch (exc) {
      if (exc instanceof CommittedAuditError) {
        const decisionWithId = Guard.attachCallId(decision, callId);
        if (isV2 && decision.allowed) this.chain.registerPending(nid, callId!);
        exc.decision = decisionWithId;
      } else if (decision.allowed) {
        for (const c of filled) this.chain.uncountCall(nid, c.meterKey ?? "*");
      }
      throw exc;
    }

    decision = Guard.attachCallId(decision, callId);
    // 5. register pending (allows only).
    if (isV2 && decision.allowed) this.chain.registerPending(nid, callId!);
    // 6. fall through to strike-policy handling, then return.

    if (
      !decision.allowed &&
      this.strikes !== null &&
      this.strikes.enabled &&
      !this.chain.isRevoked(nid)
    ) {
      const count = this.chain.recordStrike(this.strikes.key(nid, scope));
      if (count >= this.strikes.n) {
        const revoked = this.chain.revoke(nid);
        const killExtra = isV2 ? this.pendingAtKill(revoked) : {};
        this.append("kill", {
          chain_id: this.chainId,
          target: nid,
          reason: "strike_policy",
          scope,
          strikes: count,
          mode: this.strikes.mode,
          revoked,
          ...killExtra,
        });
      }
    }
    return decision;
  }

  /**
   * `check`, and throw `AuthorityDenied` if not allowed. The hard-stop gate:
   * use this where a denial should abort the caller rather than be branched on.
   */
  enforce(scope: string, options: CheckOptions = {}): void {
    const decision = this.check(scope, options);
    if (!decision.allowed) throw new AuthorityDenied(decision);
  }

  /**
   * A pure dry-run: identical policy evaluation to `check`, but it never throws
   * and — critically — writes NOTHING to the audit log. Never allocates a `callId`
   * (there is nothing to bind an outcome to).
   */
  wouldAllow(scope: string, options: CheckOptions = {}): Decision {
    const ctx: Context = { ...(options.context ?? {}) };
    this.autoMeter(scope, ctx); // read the meters, never consume them
    return this.evaluate(scope, ctx, options.metered ?? false);
  }

  /**
   * Put an ADAPTER-LEVEL refusal on the audit trail as a `deny` event and
   * return it as a Decision — for denials that happen UPSTREAM of policy
   * evaluation: an agent the chain never delegated to, a tool with no declared
   * permissions, unparseable tool arguments. Nothing is evaluated; the caller
   * has already decided, and this records it in the same tamper-evident log.
   *
   * `scope` defaults to `tool` (or "-"), because the published schema requires
   * a string scope on allow and deny events.
   *
   * On a `schemaVersion: 2` chain this also allocates and attaches a `callId` (same fail-closed
   * CSPRNG handling as `check`) — every allow/deny entry carries one; a deny never expects an
   * outcome.
   */
  recordDenial(
    reason: Reason | string,
    message = "",
    options: RecordDenialOptions = {},
  ): Decision {
    Guard.checkDisposition(options.disposition ?? null);
    const r = reason instanceof Reason ? reason : new Reason(String(reason), { message });
    const decision = Decision.deny(r, this.node.nodeId);
    const isV2 = this.isV2;
    const tool = options.tool ?? null;

    let callId: string | null = null;
    if (isV2) {
      try {
        callId = randomBytes(16).toString("hex");
      } catch {
        return Decision.deny(r, this.node.nodeId); // fail-closed: nothing written
      }
    }
    try {
      this.logDecision(
        decision,
        options.scope ?? tool ?? "-",
        tool,
        { ...(options.context ?? {}) },
        options.disposition ?? null,
        isV2 ? { call_id: callId } : undefined,
      );
    } catch (exc) {
      if (exc instanceof CommittedAuditError) {
        exc.decision = Guard.attachCallId(decision, callId);
      }
      throw exc;
    }
    return Guard.attachCallId(decision, callId);
  }

  /**
   * The body-owning wrapper's report of how an `allow`ed call (identified by `callId`, from that
   * `check` call's `Decision.callId`) ended. `schemaVersion: 2` chains only.
   *
   * `bodyState` is one of the `BodyState` constants. `errorCode` is required exactly when
   * `bodyState === BodyState.RAISED` (a normalized exception class name, never a message) and
   * forbidden otherwise. `durationMs` (observation start to observation end) is required.
   * `invokedParams` is the corresponding JSON object the wrapper observed immediately before the
   * actual invocation — hashed the same way as `check`'s `authorizedParams`; omit the option to
   * opt out. `receipt` is unverified carriage, `{type, ref, digest}`.
   *
   * Exactly one outcome per `callId` is enforced here (throws `DuplicateOutcomeError`); a second
   * outcome for the same callId is a caller bug, not a policy outcome. A callId that was never
   * pending anywhere in this chain (bound to a deny, or foreign) is still recorded — this is a
   * best-effort runtime cleanup, not a gate; the offline verifier is what flags
   * `outcome_without_allow`/`cross_ref` from the ledger alone.
   */
  recordOutcome(callId: string, bodyState: string, options: RecordOutcomeOptions): LedgerEntry {
    if (!this.isV2) {
      throw new Error(
        "recordOutcome requires a schemaVersion: 2 chain (Guard.issue(..., {schemaVersion: 2}))",
      );
    }
    if (!BODY_STATES.has(bodyState)) {
      throw new Error(
        `unknown bodyState ${JSON.stringify(bodyState)}; expected one of ` +
          `${Array.from(BODY_STATES).sort().join(", ")}`,
      );
    }
    const errorCode = options.errorCode ?? null;
    if (bodyState === BodyState.RAISED) {
      if (typeof errorCode !== "string" || !errorCode) {
        throw new Error("errorCode is required (a non-empty string) when bodyState === BodyState.RAISED");
      }
    } else if (errorCode !== null) {
      throw new Error("errorCode is only permitted when bodyState === BodyState.RAISED");
    }
    const durationMs = options.durationMs;
    if (!Number.isInteger(durationMs) || durationMs < 0) {
      throw new Error(`durationMs must be a non-negative integer; got ${JSON.stringify(durationMs)}`);
    }
    const receipt = options.receipt ?? null;
    if (receipt !== null) {
      const r = receipt as unknown as Record<string, unknown>;
      const missing = (["type", "ref", "digest"] as const).filter((k) => !(k in r));
      if (missing.length > 0) {
        throw new Error(`receipt is missing ${JSON.stringify(missing)}; expected type/ref/digest`);
      }
      for (const k of ["type", "ref"] as const) {
        if (typeof r[k] !== "string" || !r[k]) {
          throw new Error(`receipt[${JSON.stringify(k)}] must be a non-empty string`);
        }
      }
      if (typeof r["digest"] !== "string" || !/^[0-9a-f]{64}$/.test(r["digest"] as string)) {
        throw new Error(
          "receipt['digest'] must be a lowercase-hex SHA-256 digest (64 hex characters) — spec section 7",
        );
      }
    }

    // Exactly one outcome per callId, "enforced at append" (spec section 3): peek first, but
    // only COMMIT the outcomed/pending state AFTER the append actually reaches its commit point
    // — see below. A pre-commit failure here (e.g. a canonicalization failure while hashing this
    // entry) must leave callId exactly as unresolved as before this call, so a corrected retry
    // is still possible and `complete()` does not wrongly believe the call was accounted for.
    if (this.chain.isOutcomed(callId)) {
      throw new DuplicateOutcomeError(`callId ${JSON.stringify(callId)} already has a recorded outcome`);
    }
    const fields: LedgerEntry = {
      chain_id: this.chainId,
      node: this.node.nodeId,
      call_id: callId,
      body_state: bodyState,
      duration_ms: durationMs,
    };
    if (errorCode !== null) fields["error_code"] = errorCode;
    const [ph, preason] = this.paramsCommitment(options.invokedParams);
    if (ph !== null) fields["invoked_params_hash"] = ph;
    else if (preason !== null) fields["params_hash_reason"] = preason;
    if (receipt !== null) fields["receipt"] = { ...receipt } as unknown as Json;

    let entry: LedgerEntry;
    try {
      entry = this.append("outcome", fields);
    } catch (exc) {
      if (exc instanceof CommittedAuditError) {
        // post-commit: the outcome DID reach the in-memory chain; it is now safe (and correct)
        // to mark it done and drop it from pending before the persistence failure propagates.
        this.chain.markOutcomed(callId);
        this.chain.resolvePending(callId);
      }
      throw exc;
    }
    // success: commit the bookkeeping only now, never before.
    this.chain.markOutcomed(callId);
    this.chain.resolvePending(callId);
    return entry;
  }

  // ---- chain controls ---------------------------------------------------

  /**
   * `{pending_at_kill: [...]}` — the still-open callIds across every node a kill revoked,
   * snapshotted (NOT cleared: a late `recordOutcome` after this kill is still accepted — spec
   * section 1). Only meaningful on v2 chains; call only when `isV2`.
   */
  private pendingAtKill(revokedNodes: readonly string[]): LedgerEntry {
    const pending = new Set<string>();
    for (const nid of revokedNodes) {
      for (const c of this.chain.pendingFor(nid)) pending.add(c);
    }
    return { pending_at_kill: Array.from(pending).sort() as unknown as Json };
  }

  /** Cascade-revoke a node — by default this one — and its whole subtree. */
  revoke(nodeId?: string | null): string[] {
    const target = nodeId ?? this.node.nodeId;
    const revoked = this.chain.revoke(target);
    const extra = this.isV2 ? this.pendingAtKill(revoked) : {};
    this.append("kill", { chain_id: this.chainId, target, revoked, ...extra });
    return revoked;
  }

  /**
   * Revoke an agent BY NAME, chain-wide: every node it holds is cascade-revoked
   * and no node may `delegate` to it again. Use this — not `revoke(nodeId)` —
   * when the intent is "this principal is done", because frameworks hand off to
   * the same agent freely and a fresh `delegate` would otherwise mint it clean
   * authority.
   */
  revokeAgent(agentId: string): string[] {
    const revoked = this.chain.revokeAgent(agentId);
    const extra = this.isV2 ? this.pendingAtKill(revoked) : {};
    this.append("kill", {
      chain_id: this.chainId,
      target: this.node.nodeId,
      agent: agentId,
      revoked,
      ...extra,
    });
    return revoked;
  }

  // ---- provable narrowing -----------------------------------------------

  /**
   * Is this guard's authority provably narrower than `parent`'s? Exactly the
   * relation an offline verifier applies to two wire tokens.
   */
  isNarrowerThan(parent: Guard): boolean {
    return this.authority.isNarrowerThan(parent.authority);
  }

  // ---- introspection ----------------------------------------------------

  auditLog(): AuditLog {
    return this.audit;
  }

  graph(): Record<string, Json> {
    return this.chain.graph();
  }
}
