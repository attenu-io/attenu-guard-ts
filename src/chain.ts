/**
 * Chain state — the live delegation graph, TTL, integrity and cascade revocation.
 *
 * A Chain tracks the tree of delegations rooted at one top-level task and
 * enforces the structural invariants no single-agent policy model can express:
 *
 *   * monotonic attenuation: every child authority <= its parent's (via `meet`);
 *   * time bounds: an authority stops authorizing once its TTL elapses;
 *   * depth and fanout ceilings on the tree;
 *   * aggregate ceilings summed across the whole chain;
 *   * cascade revocation: revoking any node revokes its whole subtree;
 *   * in-process integrity: each node's authority is sealed with a per-chain
 *     secret, so accidental (or unsophisticated) mutation of node state is
 *     caught at check time.
 *
 * That last one raises the bar against bugs and casual tampering only — code
 * running in the same process can read the secret. Real tamper-resistance comes
 * from the signed, offline-verifiable evidence bundle; the in-process library
 * tier trusts its own process.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { canonicalBytes, type Json } from "./canonical.js";
import { Authority, AuthorityError } from "./authority.js";

/** A source of seconds for TTL expiry. Injectable so tests are deterministic. */
export interface Clock {
  now(): number;
}

/** The default wall clock: monotonic seconds. */
export class MonotonicClock implements Clock {
  now(): number {
    return performance.now() / 1000;
  }
}

/** A test clock the caller advances by hand. */
export class ManualClock implements Clock {
  constructor(private t = 0) {}
  now(): number {
    return this.t;
  }
  advance(seconds: number): void {
    this.t += seconds;
  }
  set(seconds: number): void {
    this.t = seconds;
  }
}

export interface Node {
  nodeId: string;
  parentId: string | null;
  agentId: string;
  authority: Authority;
  task: string;
  depth: number;
  issuedAt: number;
  revoked: boolean;
  /** Lifecycle end marker: informational, never widens or narrows authority. */
  complete: boolean;
  children: string[];
  /** HMAC of the authority under the chain secret. */
  seal: string;
}

export interface ChainInit {
  maxDepth?: number;
  maxFanout?: number;
  clock?: Clock;
}

export class Chain {
  readonly chainId: string;
  readonly maxDepth: number;
  readonly maxFanout: number;
  readonly clock: Clock;
  readonly nodes = new Map<string, Node>();

  private readonly revokedNodes = new Set<string>(); // grow-only
  private readonly bannedAgents = new Set<string>(); // grow-only
  private nextId = 0;
  private readonly consumed = new Map<string, number>();
  private readonly calls = new Map<string, number>(); // "node pattern" -> count
  private readonly strikes = new Map<string, number>();
  private readonly secret = randomBytes(32); // per-chain integrity key

  // 0.9.0 execution binding (schemaVersion=2 chains only; see guard.ts):
  /** 16 raw bytes, set once by `Guard.issue`; shared by every node in the chain (see params.ts). */
  paramsSalt: Buffer | null = null;
  private readonly pending = new Map<string, Set<string>>(); // nodeId -> callIds awaiting an outcome
  private readonly outcomed = new Set<string>(); // callIds that already received an outcome, chain-wide

  constructor(chainId: string, init: ChainInit = {}) {
    this.chainId = chainId;
    this.maxDepth = init.maxDepth ?? 6;
    this.maxFanout = init.maxFanout ?? 16;
    this.clock = init.clock ?? new MonotonicClock();
  }

  // ---- integrity --------------------------------------------------------

  private seal(authority: Authority): string {
    return createHmac("sha256", this.secret)
      .update(canonicalBytes(authority.toWire() as unknown as Json))
      .digest("hex");
  }

  verifyIntegrity(node: Node): boolean {
    const expected = Buffer.from(this.seal(node.authority), "utf8");
    const actual = Buffer.from(node.seal, "utf8");
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  newNodeId(): string {
    return `${this.chainId}:n${this.nextId++}`;
  }

  addRoot(agentId: string, authority: Authority, task: string): Node {
    const nodeId = this.newNodeId();
    const node: Node = {
      nodeId,
      parentId: null,
      agentId,
      authority,
      task,
      depth: 0,
      issuedAt: this.clock.now(),
      revoked: false,
      complete: false,
      children: [],
      seal: this.seal(authority),
    };
    this.nodes.set(nodeId, node);
    return node;
  }

  // ---- ttl --------------------------------------------------------------

  isExpired(node: Node): boolean {
    const ttl = node.authority.ttl;
    if (ttl === null) return false;
    return this.clock.now() - node.issuedAt > ttl;
  }

  /**
   * The structural preconditions for `addChild`, WITHOUT mutating anything:
   * the `AuthorityError` that `addChild` would throw, or `null` if the
   * delegation is currently permitted.
   */
  delegationError(parentId: string, agentId: string): AuthorityError | null {
    const parent = this.nodes.get(parentId);
    if (parent === undefined) {
      return new AuthorityError(`no such node ${parentId}`, "no_authority", { parent: parentId });
    }
    if (this.isRevoked(parentId)) {
      return new AuthorityError("cannot delegate from a revoked node", "chain_revoked", {
        parent: parentId,
      });
    }
    if (this.bannedAgents.has(agentId)) {
      return new AuthorityError(
        `agent '${agentId}' has been revoked in this chain`,
        "agent_banned",
        { agent: agentId },
      );
    }
    if (!this.verifyIntegrity(parent)) {
      return new AuthorityError("parent authority failed integrity check", "integrity", {
        parent: parentId,
      });
    }
    if (this.isExpired(parent)) {
      return new AuthorityError("cannot delegate from an expired authority", "ttl_expired", {
        parent: parentId,
      });
    }
    if (parent.depth + 1 > this.maxDepth) {
      return new AuthorityError(
        `delegation depth ${parent.depth + 1} exceeds max_depth ${this.maxDepth}`,
        "max_depth",
        { max_depth: this.maxDepth },
      );
    }
    if (parent.children.length + 1 > this.maxFanout) {
      return new AuthorityError(`fanout exceeds max_fanout ${this.maxFanout}`, "max_fanout", {
        max_fanout: this.maxFanout,
      });
    }
    return null;
  }

  addChild(parentId: string, agentId: string, requested: Authority, task: string): Node {
    const err = this.delegationError(parentId, agentId);
    if (err !== null) throw err;
    const parent = this.nodes.get(parentId)!;

    // THE attenuation step: the child's authority is the meet, never a copy.
    const childAuth = parent.authority.meet(requested);
    // Defensive re-assertion of the core invariant. It must always hold.
    if (!childAuth.isNarrowerThan(parent.authority)) {
      throw new AuthorityError("attenuation invariant violated", "integrity", {
        parent: parentId,
      });
    }

    const nodeId = this.newNodeId();
    const node: Node = {
      nodeId,
      parentId,
      agentId,
      authority: childAuth,
      task,
      depth: parent.depth + 1,
      issuedAt: this.clock.now(),
      revoked: false,
      complete: false,
      children: [],
      seal: this.seal(childAuth),
    };
    this.nodes.set(nodeId, node);
    parent.children.push(nodeId);
    return node;
  }

  // ---- revocation -------------------------------------------------------

  /** Revoke `nodeId` and its whole subtree. Returns the ids revoked by this call. */
  revoke(nodeId: string): string[] {
    const revokedNow: string[] = [];
    const stack = [nodeId];
    while (stack.length > 0) {
      const nid = stack.pop()!;
      if (this.revokedNodes.has(nid)) continue;
      const node = this.nodes.get(nid);
      if (node === undefined) continue;
      this.revokedNodes.add(nid);
      node.revoked = true;
      revokedNow.push(nid);
      stack.push(...node.children);
    }
    return revokedNow;
  }

  isRevoked(nodeId: string): boolean {
    return this.revokedNodes.has(nodeId);
  }

  /**
   * PRINCIPAL-scoped revocation: cascade-revoke every node held by `agentId`
   * and ban the agent, so no node in this chain can delegate to it again.
   * Closes the re-delegation bypass where a framework hands off again to a
   * revoked agent and would otherwise mint it a fresh child from a still-valid
   * parent.
   */
  revokeAgent(agentId: string): string[] {
    this.bannedAgents.add(agentId);
    const revokedNow: string[] = [];
    for (const [nid, node] of Array.from(this.nodes.entries())) {
      if (node.agentId === agentId && !this.revokedNodes.has(nid)) {
        revokedNow.push(...this.revoke(nid));
      }
    }
    return revokedNow;
  }

  isBanned(agentId: string): boolean {
    return this.bannedAgents.has(agentId);
  }

  // ---- aggregate budgets ------------------------------------------------

  /** Add to a chain-wide running total, throwing if it passes the ceiling. */
  consume(key: string, amount: number, chainCeiling: number | null): void {
    const total = (this.consumed.get(key) ?? 0) + amount;
    if (chainCeiling !== null && total > chainCeiling) {
      throw new AuthorityError(
        `chain aggregate ${key}=${total} exceeds chain ceiling ${chainCeiling}`,
        "chain_ceiling",
        { key, total, ceiling: chainCeiling },
      );
    }
    this.consumed.set(key, total);
  }

  private static meterKey(nodeId: string, pattern: string): string {
    return `${nodeId} ${pattern}`;
  }

  callsSoFar(nodeId: string, pattern: string): number {
    return this.calls.get(Chain.meterKey(nodeId, pattern)) ?? 0;
  }

  countCall(nodeId: string, pattern: string): number {
    const k = Chain.meterKey(nodeId, pattern);
    const n = (this.calls.get(k) ?? 0) + 1;
    this.calls.set(k, n);
    return n;
  }

  /**
   * Undo one `countCall` — used when a call's metering was applied but the transition then failed
   * BEFORE the commit point (0.9.0: `callId` allocation; spec section 1, "meters are restored"),
   * so the meter reads as if the call had never been evaluated.
   */
  uncountCall(nodeId: string, pattern: string): number {
    const k = Chain.meterKey(nodeId, pattern);
    const n = Math.max(0, (this.calls.get(k) ?? 0) - 1);
    this.calls.set(k, n);
    return n;
  }

  /** Count a denial for the strike policy; returns the running total. */
  recordStrike(key: string): number {
    const n = (this.strikes.get(key) ?? 0) + 1;
    this.strikes.set(key, n);
    return n;
  }

  // ---- execution binding: pending calls + exactly-one-outcome (0.9.0, schemaVersion=2 chains) --

  /** An `allow`ed call now awaits an outcome. */
  registerPending(nodeId: string, callId: string): void {
    let set = this.pending.get(nodeId);
    if (set === undefined) {
      set = new Set<string>();
      this.pending.set(nodeId, set);
    }
    set.add(callId);
  }

  /**
   * Remove `callId` from whichever node's pending set holds it (`recordOutcome`'s job); returns
   * that nodeId, or `null` if it was not pending anywhere in this chain. A callId that never was
   * pending (e.g. bound to a deny, or foreign) is left for the offline verifier to flag — this is
   * a best-effort runtime cleanup, not a gate.
   */
  resolvePending(callId: string): string | null {
    for (const [nid, calls] of this.pending) {
      if (calls.has(callId)) {
        calls.delete(callId);
        return nid;
      }
    }
    return null;
  }

  pendingFor(nodeId: string): string[] {
    return Array.from(this.pending.get(nodeId) ?? []).sort();
  }

  /**
   * Peek: has `callId` already received an outcome? Split from `markOutcomed` so a caller (see
   * `Guard.recordOutcome`) can check BEFORE attempting the append and commit AFTER it actually
   * succeeds — a pre-commit failure must leave `callId` exactly as unresolved as it was.
   */
  isOutcomed(callId: string): boolean {
    return this.outcomed.has(callId);
  }

  /**
   * Commit `callId` as having received its outcome. Call ONLY after the outcome entry has
   * actually reached the audit log's commit point (a plain successful append, or a
   * `CommittedAuditError` post-commit failure) — never before (see `Guard.recordOutcome`).
   */
  markOutcomed(callId: string): void {
    this.outcomed.add(callId);
  }

  graph(): Record<string, Json> {
    return {
      chain_id: this.chainId,
      nodes: Array.from(this.nodes.values()).map((n) => ({
        id: n.nodeId,
        parent: n.parentId,
        agent: n.agentId,
        task: n.task,
        depth: n.depth,
        revoked: n.revoked,
        authority: n.authority.toWire() as unknown as Json,
      })),
    };
  }
}
