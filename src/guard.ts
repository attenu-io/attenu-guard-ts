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
 */

import type { Json } from "./canonical.js";
import { Authority, AuthorityError } from "./authority.js";
import { AuditLog, type LedgerEntry, type Sink } from "./audit.js";
import { Chain, MonotonicClock, type Clock, type Node } from "./chain.js";
import { ctxFieldOf, isMetered, type Ceiling, type Context } from "./ceilings.js";
import { DISPOSITIONS, Decision, Disposition, Reason, ReasonCode } from "./reasons.js";
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
}

export interface CheckOptions {
  context?: Context | null;
  /** Marks the call as consuming a metered resource; see `strictMetering`. */
  metered?: boolean;
  /** The tool label recorded on the ledger entry. */
  tool?: string | null;
  /** What the caller knows about WHY this scope would be absent. */
  disposition?: string | null;
}

export interface RecordDenialOptions {
  scope?: string | null;
  tool?: string | null;
  context?: Context | null;
  disposition?: string | null;
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

  /** A fresh root Guard, starting a new delegation chain. */
  static issue(agentId: string, authority: Authority, options: IssueOptions = {}): Guard {
    const chainId = options.chainId ?? "chain";
    const chain = new Chain(chainId, {
      maxDepth: options.maxDepth ?? 6,
      maxFanout: options.maxFanout ?? 16,
      clock: options.clock ?? new MonotonicClock(),
    });
    const audit = new AuditLog({
      path: options.auditPath ?? null,
      sinks: options.auditSinks ?? [],
    });
    const seq = new SeqClock();
    const node = chain.addRoot(agentId, authority, options.task ?? "root");
    audit.append("root", seq.now(), {
      chain_id: chainId,
      node: node.nodeId,
      agent: agentId,
      authority: authority.toWire() as unknown as Json,
    });
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
   * Mark this node's work FINISHED — one `done` event, idempotent. Purely a
   * lifecycle marker for the ledger and downstream analytics (a delegation that
   * never reached `done` was cut short); it does NOT change authority.
   * Revocation is the hard stop.
   */
  complete(): boolean {
    if (this.node.complete) return false;
    this.node.complete = true;
    this.append("done", {
      chain_id: this.chainId,
      node: this.node.nodeId,
      agent: this.node.agentId,
    });
    return true;
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
  ): void {
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
    this.append(event, fields);
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

  /**
   * Authorize an action. Returns a `Decision`; it does not throw on a denial.
   * Every call — allow or deny — is appended to the audit log.
   *
   * Auto-metering: when this node holds a `CallLimit` and the caller did not
   * supply `calls`, the guard supplies the running count for (node, pattern)
   * itself, including this call, and increments it on allow. An explicit
   * `calls` in the context always wins.
   */
  check(scope: string, options: CheckOptions = {}): Decision {
    const disposition = options.disposition ?? null;
    Guard.checkDisposition(disposition); // refuse before anything reaches the ledger
    const ctx: Context = { ...(options.context ?? {}) };
    const filled = this.autoMeter(scope, ctx);
    const decision = this.evaluate(scope, ctx, options.metered ?? false);
    if (decision.allowed) {
      for (const c of filled) this.chain.countCall(this.node.nodeId, c.meterKey ?? "*");
    }
    this.logDecision(decision, scope, options.tool ?? null, ctx, disposition);
    if (
      !decision.allowed &&
      this.strikes !== null &&
      this.strikes.enabled &&
      !this.chain.isRevoked(this.node.nodeId)
    ) {
      const count = this.chain.recordStrike(this.strikes.key(this.node.nodeId, scope));
      if (count >= this.strikes.n) {
        const revoked = this.chain.revoke(this.node.nodeId);
        this.append("kill", {
          chain_id: this.chainId,
          target: this.node.nodeId,
          reason: "strike_policy",
          scope,
          strikes: count,
          mode: this.strikes.mode,
          revoked,
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
   * and — critically — writes NOTHING to the audit log.
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
   */
  recordDenial(
    reason: Reason | string,
    message = "",
    options: RecordDenialOptions = {},
  ): Decision {
    Guard.checkDisposition(options.disposition ?? null);
    const r = reason instanceof Reason ? reason : new Reason(String(reason), { message });
    const decision = Decision.deny(r, this.node.nodeId);
    const tool = options.tool ?? null;
    this.logDecision(
      decision,
      options.scope ?? tool ?? "-",
      tool,
      { ...(options.context ?? {}) },
      options.disposition ?? null,
    );
    return decision;
  }

  // ---- chain controls ---------------------------------------------------

  /** Cascade-revoke a node — by default this one — and its whole subtree. */
  revoke(nodeId?: string | null): string[] {
    const target = nodeId ?? this.node.nodeId;
    const revoked = this.chain.revoke(target);
    this.append("kill", { chain_id: this.chainId, target, revoked });
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
    this.append("kill", {
      chain_id: this.chainId,
      target: this.node.nodeId,
      agent: agentId,
      revoked,
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
