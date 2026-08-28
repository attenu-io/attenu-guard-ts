/**
 * evidence.ts — the offline bundle exporter and verifier.
 *
 * A delegation ledger is only worth as much as an auditor's ability to check it
 * WITHOUT the engine that produced it. A bundle is self-contained — the
 * hash-chained ledger plus a signed anchor — and three invariants are checked
 * from that bundle ALONE:
 *
 *   integrity     the hash chain reproduces AND matches the out-of-band signed
 *                 anchor. A consistent full rewrite, which the chain check
 *                 alone cannot catch, fails here: the anchor's head is the
 *                 fixed point.
 *   monotonicity  every delegation is child ⊆ parent — the granted authority on
 *                 each `spawn` is narrower than the parent node's authority.
 *   containment   every `allow` action's scope was within the acting node's
 *                 authority: no action was authorized outside what the node held.
 *
 *     const bundle = exportBundle(guard.auditLog(), signer);
 *     const report = verifyBundle(bundle, signer);
 *
 * No engine state is consulted — the bundle is the whole input, which is the
 * point. This is byte-compatible with the Python library's
 * `attenu_guard.evidence`.
 */

import {
  canonicalBytes,
  compareCodePoints,
  parseJson,
  toPlain,
  type CJson,
  type Json,
} from "./canonical.js";
import { createHash } from "node:crypto";

import { AuditLog, SCHEMA_VERSION, chainIdOf, hashEntry, GENESIS, type Anchor, type LedgerEntry } from "./audit.js";
import { Authority } from "./authority.js";
import type { Context } from "./ceilings.js";
import type { Signer } from "./wire.js";

/**
 * The COMPLETE set of top-level ledger field names the library emits. Custody
 * guarantee: an exported bundle may carry ONLY these — an unknown field is
 * exactly where a raw tool argument would be smuggled, so it is a leak, not a
 * curiosity. `exportBundle({strict: true})` throws on any field outside this set.
 *
 * `task` is free text (a delegated prompt) and `context` is an object; both are
 * redactable for transport.
 */
export const LEDGER_FIELDS: ReadonlySet<string> = new Set([
  "v",
  "seq",
  "ts",
  "event",
  "prev_hash",
  "hash",
  "chain_id",
  "node",
  "parent",
  "agent",
  "task",
  "scope",
  "tool",
  "context",
  "reason",
  "reasons",
  "authority",
  "requested",
  "granted",
  "target",
  "revoked",
  "strikes",
  "mode",
  "disposition",
]);

/**
 * Thrown by `exportBundle({strict: true})` when a bundle would carry a field or
 * context key outside the allow-list — potential customer data the custody
 * contract says must not leave the premises.
 */
export class EvidenceLeakError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceLeakError";
  }
}

export interface RedactionViolation {
  event_index: number;
  event: Json;
  field?: string;
  context_key?: string;
}

export interface RedactionReport {
  ok: boolean;
  violations: RedactionViolation[];
}

export interface Bundle {
  v: number;
  chain_id: string;
  entries: LedgerEntry[];
  anchor: Anchor;
  redaction: RedactionReport;
  note: string;
}

function redactTask(t: CJson | undefined): CJson | undefined {
  if (t === undefined || t === null || t === "" || t === 0 || t === false) return t;
  const s = String(toPlain(t));
  const h = createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex").slice(0, 12);
  return `redacted:len=${s.length}:h=${h}`;
}

/**
 * Every top-level field must be in `LEDGER_FIELDS`; if `contextAllowlist` is
 * given, every context key must be in it. `task` free text is allowed
 * structurally but is redacted by `exportBundle({redactTask: true})` for
 * transport — its raw value is the caller's to keep, not this library's.
 */
export function redactionReport(
  entries: readonly LedgerEntry[],
  contextAllowlist?: Iterable<string> | null,
): RedactionReport {
  const allow = contextAllowlist === undefined || contextAllowlist === null ? null : new Set(contextAllowlist);
  const violations: RedactionViolation[] = [];
  entries.forEach((e, i) => {
    for (const f of Object.keys(e)) {
      if (!LEDGER_FIELDS.has(f)) {
        violations.push({ event_index: i, event: toPlain(e["event"]), field: f });
      }
    }
    if (allow !== null) {
      const ctx = (e["context"] ?? {}) as Record<string, CJson>;
      if (ctx !== null && typeof ctx === "object" && !Array.isArray(ctx)) {
        for (const k of Object.keys(ctx)) {
          if (!allow.has(k)) {
            violations.push({ event_index: i, event: toPlain(e["event"]), context_key: k });
          }
        }
      }
    }
  });
  return { ok: violations.length === 0, violations };
}

/** A signed commitment to the head of `entries` — mirrors `AuditLog.anchor`. */
export function anchorFor(
  entries: readonly LedgerEntry[],
  signer: Signer,
  ts: number | string = 0,
): Anchor {
  let seq: number;
  let head: string;
  if (entries.length === 0) {
    seq = -1;
    head = "GENESIS";
  } else {
    const last = entries[entries.length - 1]!;
    const rawSeq = toPlain(last["seq"]);
    seq = typeof rawSeq === "number" ? rawSeq : entries.length - 1;
    head = last["hash"] as string;
  }
  const body = { v: SCHEMA_VERSION, chain_id: chainIdOf(entries), seq, head, ts };
  return { ...body, kid: signer.kid ?? null, sig: signer.sign(canonicalBytes(body)).toString("hex") };
}

export interface ExportOptions {
  ts?: number | string;
  contextAllowlist?: Iterable<string> | null;
  /** Replace free-text `task` fields with a length-and-hash marker. */
  redactTask?: boolean;
  /** Throw `EvidenceLeakError` on any field outside the allow-list. */
  strict?: boolean;
}

/**
 * A self-contained evidence bundle: the full ledger plus a signed anchor over
 * its head.
 *
 * With `redactTask`, free-text `task` fields are replaced by a length-and-hash
 * marker BEFORE the anchor is computed, so the transported bundle carries no
 * raw prompt text yet still verifies — redaction is not tampering, because it
 * only ever removes. With `strict`, the bundle is checked against
 * `LEDGER_FIELDS` (and `contextAllowlist` if given) and an `EvidenceLeakError`
 * is thrown on any field outside it.
 */
export function exportBundle(
  auditLog: AuditLog | readonly LedgerEntry[],
  signer: Signer,
  options: ExportOptions = {},
): Bundle {
  const source = auditLog instanceof AuditLog ? auditLog.entries : auditLog;
  const entries: LedgerEntry[] = source.map((e) => ({ ...e }));

  if (options.redactTask) {
    for (const e of entries) {
      if ("task" in e) e["task"] = redactTask(e["task"]) as CJson;
    }
    // Re-hash the chain so the redacted form is what the anchor covers.
    let prev = GENESIS;
    for (const e of entries) {
      e["prev_hash"] = prev;
      const payload: LedgerEntry = {};
      for (const [k, v] of Object.entries(e)) if (k !== "hash") payload[k] = v;
      e["hash"] = hashEntry(prev, payload);
      prev = e["hash"] as string;
    }
  }

  const report = redactionReport(entries, options.contextAllowlist ?? null);
  if (options.strict && !report.ok) {
    throw new EvidenceLeakError(
      `${report.violations.length} field(s) outside the ledger allow-list: ` +
        JSON.stringify(report.violations.slice(0, 5)),
    );
  }
  const anchor = anchorFor(entries, signer, options.ts ?? 0);
  anchor.verified = AuditLog.verifyAnchor(entries, anchor as Record<string, CJson>, signer)[0];
  return {
    v: SCHEMA_VERSION,
    chain_id: chainIdOf(entries),
    entries,
    anchor,
    redaction: report,
    note: "offline-verifiable: attenu_guard.evidence.verify_bundle(bundle, signer)",
  };
}

/**
 * A ledger field, or `null` when it is absent. Python's `dict.get` yields `None`
 * for a missing key and that `None` reaches the caller as a value; JavaScript
 * would hand back `undefined`, which is not the same thing to a `deepEqual` or a
 * JSON serialiser. Every field read for a report goes through here.
 */
function orNull(value: CJson | undefined): Json {
  const plain = toPlain(value);
  return plain === undefined ? null : plain;
}

interface NodeAuthorities {
  auth: Map<string, Authority>;
  parent: Map<string, string | null>;
  failures: string[];
}

/**
 * `node -> Authority` and `node -> parent`, reconstructed from `root` and
 * `spawn` events alone. No engine state.
 */
function nodeAuthorities(entries: readonly LedgerEntry[]): NodeAuthorities {
  const auth = new Map<string, Authority>();
  const parent = new Map<string, string | null>();
  const failures: string[] = [];
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    const node = toPlain(e["node"]) as string;
    if (ev === "root") {
      try {
        auth.set(node, Authority.fromWire(e["authority"] ?? null));
      } catch (exc) {
        failures.push(`root ${node}: unreadable authority (${(exc as Error).message})`);
      }
    } else if (ev === "spawn") {
      parent.set(node, (toPlain(e["parent"]) as string | null) ?? null);
      try {
        auth.set(node, Authority.fromWire(e["granted"] ?? null));
      } catch (exc) {
        failures.push(`spawn ${node}: unreadable granted (${(exc as Error).message})`);
      }
    }
  }
  return { auth, parent, failures };
}

export interface GraphNode {
  agent: Json;
  task: Json;
  parent: Json;
  scopes: string[];
  allows: number;
  denies: number;
  revoked: boolean;
  complete: boolean;
  denials_by_disposition: Record<string, number>;
}

export interface DelegationGraph {
  chain_id: Json;
  nodes: Record<string, GraphNode>;
  edges: { parent: string; child: string }[];
}

/**
 * A view of the chain from the bundle: each node with its agent, task,
 * authority, parent and per-node action counts — what a reviewer or a UI
 * renders. Derived from the ledger alone.
 */
export function delegationGraph(bundle: Partial<Bundle>): DelegationGraph {
  const entries = bundle.entries ?? [];
  const { auth, parent } = nodeAuthorities(entries);
  const meta: Record<string, GraphNode> = {};
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    const n = toPlain(e["node"]) as string;
    if (ev === "root" || ev === "spawn") {
      const a = auth.get(n);
      meta[n] = {
        agent: orNull(e["agent"]),
        task: orNull(e["task"]),
        parent: orNull(e["parent"]),
        scopes: a ? Array.from(a.scopes).sort(compareCodePoints) : [],
        allows: 0,
        denies: 0,
        revoked: false,
        complete: false,
        denials_by_disposition: {},
      };
    } else if (ev === "allow" && meta[n]) {
      meta[n]!.allows += 1;
    } else if (ev === "deny" && meta[n]) {
      meta[n]!.denies += 1;
      // A deny without a disposition is named by its reason.
      const d = (toPlain(e["disposition"]) ?? toPlain(e["reason"]) ?? "unstated") as string;
      meta[n]!.denials_by_disposition[d] = (meta[n]!.denials_by_disposition[d] ?? 0) + 1;
    } else if (ev === "done" && meta[n]) {
      meta[n]!.complete = true;
    } else if (ev === "kill") {
      for (const r of (toPlain(e["revoked"]) as string[] | null) ?? []) {
        if (meta[r]) meta[r]!.revoked = true;
      }
    }
  }
  const edges: { parent: string; child: string }[] = [];
  for (const [child, p] of parent) {
    if (p) edges.push({ parent: p, child });
  }
  return { chain_id: orNull(bundle.chain_id), nodes: meta, edges };
}

export interface DenialRow {
  node: Json;
  agent: Json;
  tool: Json;
  scope: Json;
  disposition: Json;
  reason: Json;
  count: number;
  first_seq: number;
  last_seq: number;
}

/**
 * Deny events grouped by (node, tool, scope, disposition) — the rows a decisions
 * queue renders: "should this agent be allowed to <tool>?", with how often it
 * asked and why it was refused. A pure fold over the ledger, ordered by first
 * occurrence.
 */
export function denials(bundle: Partial<Bundle>): DenialRow[] {
  const entries = bundle.entries ?? [];
  const agentOf = new Map<string, Json>();
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    if (ev === "root" || ev === "spawn") {
      agentOf.set(toPlain(e["node"]) as string, orNull(e["agent"]));
    }
  }
  const rows = new Map<string, DenialRow>();
  for (const e of entries) {
    if (toPlain(e["event"]) !== "deny") continue;
    const node = orNull(e["node"]);
    const key = JSON.stringify([node, orNull(e["tool"]), orNull(e["scope"]), orNull(e["disposition"])]);
    const seq = toPlain(e["seq"]) as number;
    const existing = rows.get(key);
    if (existing === undefined) {
      rows.set(key, {
        node,
        agent: agentOf.get(node as string) ?? null,
        tool: orNull(e["tool"]),
        scope: orNull(e["scope"]),
        disposition: orNull(e["disposition"]),
        reason: orNull(e["reason"]),
        count: 1,
        first_seq: seq,
        last_seq: seq,
      });
    } else {
      existing.count += 1;
      existing.last_seq = seq;
    }
  }
  return Array.from(rows.values()).sort((a, b) => a.first_seq - b.first_seq);
}

export interface VerifyChecks {
  integrity: boolean;
  monotonicity: boolean;
  containment: boolean;
  anchor: "not checked" | "verified" | "FAILED";
}

export interface VerifyReport {
  ok: boolean;
  checks: VerifyChecks;
  failures: string[];
  nodes: number;
  actions_checked: number;
  chain_id: Json;
}

/**
 * Verify integrity, monotonicity and containment from the bundle alone.
 *
 * `signer` is the verifier for the bundle's signed anchor — a public key, or
 * the test signer. Without one the hash chain, monotonicity and containment are
 * still checked but the anchor signature is NOT; the report says so
 * (`checks.anchor === "not checked"`), and `ok` then means "consistent,
 * unverified by key": a consistent full rewrite by someone holding the key
 * cannot be excluded without the key.
 */
export function verifyBundle(bundle: Partial<Bundle>, signer: Signer | null = null): VerifyReport {
  const entries = bundle.entries ?? [];
  const anchor = (bundle.anchor ?? {}) as Record<string, CJson>;
  const checks: VerifyChecks = {
    integrity: false,
    monotonicity: false,
    containment: false,
    anchor: "not checked",
  };
  const failures: string[] = [];

  // (1) integrity: the hash chain, plus the signed anchor when a key is given.
  const [okChain, err] = AuditLog.verify(entries);
  if (!okChain) failures.push(`integrity: ${err}`);
  if (signer !== null) {
    const [okAnchor, aerr] = AuditLog.verifyAnchor(entries, anchor, signer);
    checks.anchor = okAnchor ? "verified" : "FAILED";
    if (!okAnchor) failures.push(`integrity(anchor): ${aerr}`);
    checks.integrity = okChain && okAnchor;
  } else {
    checks.integrity = okChain;
  }

  const { auth, parent, failures: afail } = nodeAuthorities(entries);
  failures.push(...afail);

  // (2) monotonicity: every child ⊆ its parent.
  let mono = true;
  for (const [node, pid] of parent) {
    if (pid === null || !auth.has(pid) || !auth.has(node)) continue;
    const child = auth.get(node)!;
    const p = auth.get(pid)!;
    const extra = Array.from(child.scopes).filter((s) => !p.scopes.has(s));
    if (!child.isNarrowerThan(p) && extra.length > 0) {
      mono = false;
      failures.push(
        `monotonicity: ${node} not ⊆ parent ${pid} (child scopes ` +
          `[${extra.sort(compareCodePoints).map((s) => `'${s}'`).join(", ")}] not held by parent)`,
      );
    }
  }
  checks.monotonicity = mono && afail.length === 0;

  // (3) containment: every allowed action's scope within the acting node's authority.
  let contained = true;
  let actions = 0;
  for (const e of entries) {
    if (toPlain(e["event"]) !== "allow") continue;
    actions += 1;
    const node = toPlain(e["node"]) as string;
    const scope = toPlain(e["scope"]) as string;
    const ctx = (toPlain(e["context"]) as Context | null) ?? {};
    const a = auth.get(node);
    if (a === undefined) {
      contained = false;
      failures.push(`containment: allow on unknown node ${node}`);
      continue;
    }
    if (!a.permits(scope, ctx).allowed) {
      contained = false;
      failures.push(
        `containment: allow of '${scope}' on ${node} outside its authority ` +
          `[${Array.from(a.scopes).sort(compareCodePoints).map((s) => `'${s}'`).join(", ")}]`,
      );
    }
  }
  checks.containment = contained;

  const ok =
    checks.integrity && checks.monotonicity && checks.containment && failures.length === 0;
  return {
    ok,
    checks,
    failures,
    nodes: auth.size,
    actions_checked: actions,
    chain_id: orNull(bundle.chain_id),
  };
}

/** Read a bundle from JSON text, keeping every number's original literal. */
export function parseBundle(text: string): Bundle {
  return parseJson(text) as unknown as Bundle;
}
