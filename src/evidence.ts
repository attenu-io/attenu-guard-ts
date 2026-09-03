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
 * `report.failures` is the human-readable list — its strings are a published
 * contract, other implementations parse them — and `report.failure_details` is
 * its machine-readable twin: one entry per string, same order, same count,
 * `{reason, seq, node, call_id, detail}`. It exists so a conformance suite can
 * assert WHICH check failed and WHERE, not merely that something did. The
 * bundle-level interop vectors under `test/fixtures/vectors/bundles/` are scored
 * against exactly that shape.
 *
 * No engine state is consulted — the bundle is the whole input, which is the
 * point. This is byte-compatible with the Python library's
 * `attenu_guard.evidence`.
 */

import {
  canonicalBytes,
  compareCodePoints,
  parseJson,
  pyNumber,
  RawNumber,
  sortedStrings,
  toPlain,
  type CJson,
  type Json,
} from "./canonical.js";
import { createHash } from "node:crypto";

import { AuditLog, SCHEMA_VERSION, chainIdOf, hashEntry, GENESIS, type Anchor, type LedgerEntry } from "./audit.js";
import { Authority } from "./authority.js";
import { describe as describeCeiling, type Context } from "./ceilings.js";
import { CAPTURES, BODY_STATES, BodyState, Capture } from "./reasons.js";
import { PARAMS_HASH_REASONS } from "./params.js";
import { Ed25519Signer, Ed25519Verifier, type Signer } from "./wire.js";

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
  "c14n",
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
  // 0.9.0 execution binding (schemaVersion=2 chains): every field named in the spec.
  "call_id",
  "capture",
  "adapter",
  "authorized_params_hash",
  "params_hash_reason",
  "params_salt",
  "body_state",
  "error_code",
  "invoked_params_hash",
  "duration_ms",
  "receipt",
  "pending_at_kill",
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

/**
 * Bundle schema versions this build knows how to verify. 2 (0.9.0): execution binding — callId,
 * capture/adapter, outcome events, params commitments. v1 bundles verify exactly as before;
 * `executionBinding` reports `{status: "not applicable"}` for them (docs/execution-binding spec
 * section 9).
 */
export const SUPPORTED_BUNDLE_VERSIONS: ReadonlySet<number> = new Set([1, 2]);

/**
 * The chain's declared schema version, read off the `root` entry (falls back to `SCHEMA_VERSION`
 * for an empty/rootless list — the historical default).
 */
function bundleVersion(entries: readonly LedgerEntry[]): number {
  for (const e of entries) {
    if (toPlain(e["event"]) === "root" && "v" in e) {
      return toPlain(e["v"]) as number;
    }
  }
  return SCHEMA_VERSION;
}

export interface Bundle {
  v: number;
  c14n: "JCS";
  chain_id: string;
  entries: LedgerEntry[];
  anchor: Anchor;
  redaction: RedactionReport;
  note: string;
  /**
   * Observer envelopes, when the bundle carries any: a witness's signature over the identity of
   * a ledger entry. Omitted entirely when there are none, so a bundle without them is
   * byte-for-byte what `exportBundle` has always produced.
   */
  envelopes?: Envelope[];
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
  const body = { v: bundleVersion(entries), c14n: "JCS" as const, chain_id: chainIdOf(entries), seq, head, ts };
  return { ...body, kid: signer.kid ?? null, sig: signer.sign(canonicalBytes(body)).toString("hex") };
}

export interface ExportOptions {
  ts?: number | string;
  contextAllowlist?: Iterable<string> | null;
  /** Replace free-text `task` fields with a length-and-hash marker. */
  redactTask?: boolean;
  /** Throw `EvidenceLeakError` on any field outside the allow-list. */
  strict?: boolean;
  /**
   * Observer envelopes (`signEnvelope`) to carry beside the ledger. Omitted from the bundle
   * entirely when absent or empty, so a bundle without them is unchanged. Cannot be combined
   * with `redactTask` in one call: sign over the redacted ledger the export produces.
   */
  envelopes?: readonly Envelope[] | null;
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
 *
 * ORDER MATTERS with `redactTask`: redaction rewrites every entry hash, so envelopes signed
 * over the unredacted ledger no longer bind to the entries that ship and would all fail
 * `envelope_subject_mismatch`. Giving both throws `Error` rather than exporting a bundle that
 * cannot verify. Export the redacted bundle first, then `signEnvelope` over ITS entries, then
 * export again with those envelopes.
 */
export function exportBundle(
  auditLog: AuditLog | readonly LedgerEntry[],
  signer: Signer,
  options: ExportOptions = {},
): Bundle {
  if (options.redactTask && (options.envelopes?.length ?? 0) > 0) {
    throw new Error(
      "sign envelopes over the redacted ledger: export with redact_task=True first, then " +
        "sign_envelope over the exported entries",
    );
  }
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
  const bundle: Bundle = {
    v: bundleVersion(entries),
    c14n: "JCS",
    chain_id: chainIdOf(entries),
    entries,
    anchor,
    redaction: report,
    note: "offline-verifiable: attenu_guard.evidence.verify_bundle(bundle, signer)",
  };
  const envelopes = options.envelopes ?? null;
  if (envelopes !== null && envelopes.length > 0) bundle.envelopes = [...envelopes];
  return bundle;
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

/**
 * One structured failure — the machine-readable twin of one `failures` string.
 *
 * `reason` is a stable token: the text before the first `:` in `detail`, with
 * the two historical exceptions whose message names a NODE there
 * (`unreadable_authority`, `unreadable_granted`) and so state their reason
 * explicitly. `seq`/`node` are the offending entry's own fields, both `null`
 * when the failure is chain-level with nothing single to point at. Same field
 * names and same values as the Python implementation's `failure_details`.
 */
export interface FailureDetail {
  reason: string;
  seq: Json;
  node: Json;
  call_id: Json;
  detail: string;
}

/** Where a failure happened, when the failure is about one entry. */
interface FailurePosition {
  seq?: Json;
  node?: Json;
  callId?: Json;
}

/**
 * The verifier's failure list, kept in two shapes that cannot drift apart.
 *
 * `messages` is the string list `verifyBundle` has always returned as
 * `failures`; those exact strings are a published contract, so they are never
 * reworded here. `details` is the structured twin of each one, appended in the
 * same call. Every failure in this module goes through `add`, so a new check
 * cannot add a message without its twin — `test/bundle-vectors.test.ts` greps
 * this file for a direct append to a failure list and fails on one, and asserts
 * the two lists stay in step at every site.
 */
class FailureLog {
  readonly messages: string[] = [];
  readonly details: FailureDetail[] = [];

  add(reason: string, detail: string, position: FailurePosition = {}): void {
    const { seq = null, node = null, callId = null } = position;
    this.messages.push(detail);
    this.details.push({ reason, seq, node, call_id: callId, detail });
  }

  extend(other: FailureLog): void {
    this.messages.push(...other.messages);
    this.details.push(...other.details);
  }

  get length(): number {
    return this.messages.length;
  }
}

interface NodeAuthorities {
  auth: Map<string, Authority>;
  parent: Map<string, string | null>;
  failures: FailureLog;
  /**
   * The `root`/`spawn` entry each node was DEFINED by, so a node-level failure
   * (monotonicity) can name the seq of the delegation that caused it, not only
   * the node.
   */
  definedBy: Map<string, LedgerEntry>;
}

/**
 * `node -> Authority` and `node -> parent`, reconstructed from `root` and
 * `spawn` events alone. No engine state.
 */
/**
 * Why `child` is not ⊆ `parent`, rendered for the monotonicity failure message.
 *
 * Called only once `Authority.isNarrowerThan` has already returned false, and it walks the
 * dimensions in the ORDER that relation compares them — scopes, then ceilings by key, then ttl
 * — so the message names the dimension that actually failed. Every dimension the relation can
 * fail on has a branch here:
 *
 *   scopes    a scope the parent does not cover (wildcard-aware);
 *   ceilings  a key the parent bounds and the child does not (child unbounded there, so MORE
 *             powerful), or one the child bounds more loosely than the parent;
 *   ttl       a child that never expires under a parent that does, or one that outlives it.
 *
 * Reports the FIRST failing dimension: one message per unsound delegation. Byte-identical to
 * the Python `evidence._monotonicity_detail`, since these strings are a published contract that
 * both implementations are scored against.
 */
function monotonicityDetail(child: Authority, parent: Authority): string {
  // Unchanged since 0.1.0, byte for byte. A scope failure always leaves this list non-empty:
  // a scope literally present in the parent's set is covered by it, so anything the parent
  // does not cover is also absent from that set.
  if (!Array.from(child.scopes).every((s) => parent.coversScope(s))) {
    const extra = Array.from(child.scopes).filter((s) => !parent.scopes.has(s));
    return (
      `child scopes [${extra.sort(compareCodePoints).map((s) => `'${s}'`).join(", ")}] ` +
      `not held by parent`
    );
  }

  const childByKey = new Map(child.ceilings.map((c) => [String(c.key), c]));
  const parentKeys = parent.ceilings.map((c) => String(c.key)).sort(compareCodePoints);
  for (const key of parentKeys) {
    const parentCeiling = parent.ceilings.find((c) => String(c.key) === key)!;
    const childCeiling = childByKey.get(key);
    if (childCeiling === undefined) {
      return `ceiling ${key} unbounded, parent holds ${describeCeiling(parentCeiling)}`;
    }
    if (!parentCeiling.subsumes(childCeiling)) {
      return (
        `ceiling ${describeCeiling(childCeiling)} looser than parent ` +
        `${describeCeiling(parentCeiling)}`
      );
    }
  }

  if (parent.ttl !== null) {
    if (child.ttl === null) return `ttl unbounded, parent ${pyNumber(parent.ttl)}`;
    if (child.ttl > parent.ttl) {
      return `ttl ${pyNumber(child.ttl)} > parent ${pyNumber(parent.ttl)}`;
    }
  }

  // Only reachable if a future dimension is added to `isNarrowerThan` without a branch here;
  // it exists so that such a dimension cannot fail SILENTLY.
  return "child not narrower than parent";
}

function nodeAuthorities(entries: readonly LedgerEntry[]): NodeAuthorities {
  const auth = new Map<string, Authority>();
  const parent = new Map<string, string | null>();
  const failures = new FailureLog();
  const definedBy = new Map<string, LedgerEntry>();
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    const node = toPlain(e["node"]) as string;
    if (ev === "root") {
      definedBy.set(node, e);
      try {
        auth.set(node, Authority.fromWire(e["authority"] ?? null));
      } catch (exc) {
        // One of the two historical messages that name a node before their colon rather than a
        // reason token, so the reason is stated here instead of parsed out of the string.
        failures.add("unreadable_authority", `root ${node}: unreadable authority (${(exc as Error).message})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
        });
      }
    } else if (ev === "spawn") {
      definedBy.set(node, e);
      parent.set(node, (toPlain(e["parent"]) as string | null) ?? null);
      try {
        auth.set(node, Authority.fromWire(e["granted"] ?? null));
      } catch (exc) {
        failures.add("unreadable_granted", `spawn ${node}: unreadable granted (${(exc as Error).message})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
        });
      }
    }
  }
  return { auth, parent, failures, definedBy };
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
  version: boolean;
  chain_id: boolean;
  root: boolean;
  expected_anchor: "not checked" | "verified" | "FAILED";
  /**
   * `"not present"` on a bundle with no `envelopes` array, which is every bundle written before
   * observer envelopes existed. Like `anchor`, it is a status string rather than a pass/fail
   * boolean, and a failed envelope already lands its own entry in `failures`.
   */
  envelopes: "not present" | "verified" | "FAILED";
}

/** Python-style repr for the small set of value types these failure messages carry. */
function pyRepr(value: Json): string {
  if (value === null) return "None";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return `'${value}'`;
  return JSON.stringify(value);
}

// =============================================================================================
// Observer envelopes (envelope v1) — the TypeScript half of `attenu_guard.evidence`'s.
//
// One question a reader of a bundle cannot answer today: was this delegation event signed by
// something OUTSIDE the process that wrote it? An envelope is a witness's signature over the
// IDENTITY of one committed ledger entry — never over its contents, which the entry's own hash
// already covers. Envelopes travel beside the ledger in a top-level `envelopes` array; no entry
// changes, so a bundle without them stays valid exactly as it is today.
//
// An envelope is never REQUIRED. An absent one is the status quo and changes nothing. A present
// one has to verify: a broken envelope lands in the same failure list as the chain-level checks
// and the bundle rejects. Byte-compatible with the Python implementation, and scored against the
// same `envelope_vectors_v1.json`.
// =============================================================================================

/**
 * The only envelope version this build knows. The version commits the exact signed member set of
 * the WHOLE envelope, the subject included, so a member added anywhere is a new version and the
 * digest cannot widen silently.
 */
export const ENVELOPE_VERSION = 1;
/** The only `typ` at v1. A different one is a different contract, not a different envelope. */
export const ENVELOPE_TYP = "delegation-event-observation";
/** The envelope's own member set at v1. */
export const ENVELOPE_MEMBERS: ReadonlySet<string> = new Set([
  "v",
  "typ",
  "subject",
  "observed",
  "witness",
  "sig",
]);
/**
 * The subject member set, keyed by `event`. v1 defines a subject for `spawn` and `allow` and for
 * no other event. `entry_hash` is the BINDING member — the only evidence of WHICH entry the
 * witness signed — and the rest are locators, whose job is to find the entry without hashing
 * every entry.
 */
export const ENVELOPE_SUBJECT_MEMBERS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["spawn", new Set(["chain_id", "node", "seq", "entry_hash", "event"])],
  ["allow", new Set(["chain_id", "node", "seq", "entry_hash", "event", "call_id"])],
]);
const ENVELOPE_OBSERVED_MEMBERS: ReadonlySet<string> = new Set(["result", "at", "method"]);
const ENVELOPE_WITNESS_MEMBERS: ReadonlySet<string> = new Set(["kid", "alg"]);
/**
 * `observed.result`'s closed vocabulary. `not_matched` requires evidence that CONTRADICTS the
 * event; `indeterminate` is the residual state, and covers thin or absent evidence. No verifier
 * decision turns on the result: it is reported next to the state, never instead of it.
 */
export const ENVELOPE_RESULTS = ["matched", "not_matched", "indeterminate"] as const;
export type EnvelopeResult = (typeof ENVELOPE_RESULTS)[number];
/** The JOSE identifier for Ed25519, and the only `witness.alg` v1 defines. */
export const ENVELOPE_ALG = "EdDSA";
/**
 * A verifying envelope's state. It says where the signature came from and NOTHING about
 * authority — the witness is whoever holds the key `witness.kid` names, which nothing in the
 * envelope makes the delegation parent.
 */
export const WITNESS_SIGNED = "witness-signed";
/**
 * No envelope, or one that does not verify. It covers two facts a bundle does not separate — a
 * hop nobody undertook to cover, and a hop a witness undertook to cover and never did — and v1
 * takes the weaker reading of the two.
 */
export const PROCESS_ASSERTED = "process-asserted";
export type EnvelopeState = typeof WITNESS_SIGNED | typeof PROCESS_ASSERTED;

/** The seven named envelope failures, in the order this build checks them. */
export const ENVELOPE_FAILURES = [
  "envelope_unknown_version",
  "envelope_unknown_member",
  "envelope_subject_mismatch",
  "envelope_duplicate_subject",
  "envelope_non_canonical",
  "envelope_unknown_witness",
  "envelope_bad_signature",
] as const;

/** One observer envelope, as it appears in `bundle.envelopes`. */
export interface Envelope {
  v: number;
  typ: string;
  subject: Record<string, CJson>;
  observed: Record<string, CJson>;
  witness: Record<string, CJson>;
  sig: string;
}

/** One trusted witness key, in the shape the vector file carries. */
export interface WitnessKey {
  kid: string;
  alg: string;
  public_key_hex: string;
}

/**
 * The bytes a witness signs: `JCS(envelope minus its "sig" member)`.
 *
 * The same RFC 8785 canonicalization the ledger has signed with since 0.7.0 — one
 * implementation, not a second one for envelopes.
 */
export function envelopeSigningInput(envelope: Record<string, CJson>): Buffer {
  const body: Record<string, CJson> = {};
  for (const [k, v] of Object.entries(envelope)) if (k !== "sig") body[k] = v;
  return canonicalBytes(body);
}

/**
 * seq -> the entry's hash RECOMPUTED from the bundle, never read off the entry.
 *
 * `entry_hash` in a subject is checked against this. The walk mirrors `AuditLog.verify`, so an
 * entry whose stored `hash` was replaced does not get to supply the value it is compared against.
 */
function recomputedHashes(entries: readonly LedgerEntry[]): Map<Json, string | null> {
  const out = new Map<Json, string | null>();
  let prev = GENESIS;
  entries.forEach((e, i) => {
    const payload: LedgerEntry = {};
    for (const [k, v] of Object.entries(e)) if (k !== "hash") payload[k] = v;
    let computed: string | null;
    try {
      computed = hashEntry(prev, payload);
    } catch {
      // An unhashable payload has no recomputable hash; that IS the break, at this entry.
      computed = null;
    }
    out.set(orNull(e["seq"]) ?? i, computed);
    prev = computed ?? GENESIS;
  });
  return out;
}

/**
 * The v1 subject for the entry at `seq`, recomputed from the ledger.
 *
 * Throws when `seq` names no entry, or names one whose `event` v1 defines no subject for.
 */
export function envelopeSubject(entries: readonly LedgerEntry[], seq: number): Record<string, CJson> {
  const entry = entries.find((e) => toPlain(e["seq"]) === seq);
  if (entry === undefined) throw new Error(`no entry at seq ${seq}`);
  const event = toPlain(entry["event"]) as string;
  if (!ENVELOPE_SUBJECT_MEMBERS.has(event)) {
    throw new Error(`envelope v${ENVELOPE_VERSION} defines no subject for event '${event}'`);
  }
  const subject: Record<string, CJson> = {
    chain_id: orNull(entry["chain_id"]) as CJson,
    node: orNull(entry["node"]) as CJson,
    seq,
    entry_hash: recomputedHashes(entries).get(seq) ?? null,
    event,
  };
  if (event === "allow") subject["call_id"] = orNull(entry["call_id"]) as CJson;
  return subject;
}

/** What a witness asserts about the event it signed. */
export interface Observation {
  result?: EnvelopeResult;
  at: string;
  method: string;
}

/**
 * An observer envelope over the entry at `seq`, signed with the 32-byte Ed25519 `seed`.
 *
 * `entries` is the ledger the subject is recomputed from — a witness signs the identity of an
 * entry that already exists, never a claim it composes itself. That makes the ledger it is
 * signed over part of the signature: sign over the entries AS THEY WILL SHIP. With
 * `exportBundle({redactTask: true})` those are the redacted entries, so export first and sign
 * over the exported bundle's `entries` — `exportBundle` refuses to redact and carry envelopes in
 * one call for exactly this reason.
 */
export function signEnvelope(
  entries: readonly LedgerEntry[],
  seq: number,
  seed: Buffer,
  kid: string,
  observed: Observation,
): Envelope {
  const result = observed.result ?? "matched";
  if (!(ENVELOPE_RESULTS as readonly string[]).includes(result)) {
    throw new Error(`observed.result must be one of [${ENVELOPE_RESULTS.join(", ")}], got '${result}'`);
  }
  const body: Record<string, CJson> = {
    v: ENVELOPE_VERSION,
    typ: ENVELOPE_TYP,
    subject: envelopeSubject(entries, seq),
    observed: { result, at: observed.at, method: observed.method },
    witness: { kid, alg: ENVELOPE_ALG },
  };
  const sig = Ed25519Signer.fromPrivateBytes(seed, kid).sign(envelopeSigningInput(body));
  return { ...body, sig: sig.toString("hex") } as unknown as Envelope;
}

/**
 * kid -> `[alg, raw public key]`, from the vector file's own `witness_keys` shape or from a plain
 * `{kid: publicKeyBytes}` record.
 *
 * `null`/absent means no trust anchor is configured, which is an EMPTY set, not an absent check:
 * an envelope naming a kid nobody trusts is `envelope_unknown_witness`, and that is the honest
 * answer whether the trust set is empty or merely does not contain it.
 */
function trustedWitnesses(
  witnessKeys: readonly WitnessKey[] | Record<string, Buffer | string> | null | undefined,
): Map<string, [string, Buffer]> {
  const trusted = new Map<string, [string, Buffer]>();
  if (witnessKeys === null || witnessKeys === undefined) return trusted;
  if (Array.isArray(witnessKeys)) {
    for (const k of witnessKeys) {
      trusted.set(k.kid, [k.alg, Buffer.from(k.public_key_hex ?? "", "hex")]);
    }
    return trusted;
  }
  for (const [kid, key] of Object.entries(witnessKeys)) {
    trusted.set(kid, [ENVELOPE_ALG, typeof key === "string" ? Buffer.from(key, "hex") : key]);
  }
  return trusted;
}

/**
 * The report line: the state and the result together, in the same form for all three results. A
 * process-asserted entry gets no result.
 */
function envelopeLine(state: EnvelopeState, result: Json): string {
  return state === WITNESS_SIGNED ? `${state} (${String(result)})` : state;
}

/** What `verifyEnvelopes` and `verifyBundle`'s `envelopes` field report. */
export interface EnvelopeSummary {
  status: "verified" | "FAILED" | "not present";
  count: number;
  /** The seqs a verifying envelope covers, ascending. */
  witness_signed: number[];
  /** Every entry's seq -> its state. Coverage is explicit, never assumed dense. */
  states: Record<string, EnvelopeState>;
  /** The `observed.result` of each witness-signed entry. */
  results: Record<string, Json>;
  /** The report line for each entry: `witness-signed (matched)`, or `process-asserted`. */
  lines: Record<string, string>;
  failures: string[];
}

export interface VerifyEnvelopesOptions {
  /** The trust set: the vector file's `witness_keys`, or a `{kid: publicKey}` record. */
  witnessKeys?: readonly WitnessKey[] | Record<string, Buffer | string> | null;
  /**
   * The envelope bytes AS RECEIVED, positionally aligned with `bundle.envelopes` (entries may be
   * null). Only `envelope_non_canonical` needs them, and only where a deployment kept them.
   */
  envelopeBytes?: readonly (Buffer | string | null)[] | null;
}

/**
 * Score every envelope in the bundle and derive the per-entry state.
 *
 * Two rules bind where a failure may land: an envelope failure lands only on the hop that
 * envelope covers, never on a hop coverage skipped; and no chain-level integrity failure is ever
 * raised because an envelope failed — that one comes from a real anchor mismatch and from
 * nothing else.
 *
 * One entry, at most one envelope. A second envelope naming a `subject.seq` an earlier one in
 * this array already named is `envelope_duplicate_subject`, and the entry falls back to
 * `process-asserted`: two observations of one event contradict each other by construction —
 * whoever appends the second decides what the first said, and an entry whose coverage is
 * disputed must not read as clean.
 */
function scoreEnvelopes(
  entries: readonly LedgerEntry[],
  envelopes: readonly Envelope[],
  trusted: Map<string, [string, Buffer]>,
  rawBytes: readonly (Buffer | string | null)[] | null,
): [EnvelopeSummary, FailureLog] {
  const fail = new FailureLog();
  const states: Record<string, EnvelopeState> = {};
  const results: Record<string, Json> = {};
  entries.forEach((e, i) => {
    states[String(orNull(e["seq"]) ?? i)] = PROCESS_ASSERTED;
  });

  // The hash walk is what an envelope's binding member is checked against; a bundle carrying
  // none does not pay for it. Every entry is process-asserted in that case, which is the status
  // quo and exactly what this reports.
  const bySeq = new Map<Json, LedgerEntry>();
  let recomputed = new Map<Json, string | null>();
  if (envelopes.length > 0) {
    entries.forEach((e, i) => bySeq.set(orNull(e["seq"]) ?? i, e));
    recomputed = recomputedHashes(entries);
  }

  // seq -> how many envelopes in this array named it, valid or not. `scoreEnvelope` counts an
  // envelope in as soon as its subject names an entry this bundle has.
  const claims = new Map<string, number>();

  envelopes.forEach((envelope, index) => {
    const raw = rawBytes !== null && index < rawBytes.length ? rawBytes[index] ?? null : null;
    const covered = scoreEnvelope(envelope, index, bySeq, recomputed, trusted, raw, fail, claims);
    if (covered === null) return;
    states[String(covered.seq)] = WITNESS_SIGNED;
    results[String(covered.seq)] = covered.result;
  });

  // The first envelope's result stands in `results` — it is what that witness said, and the
  // duplicate does not erase it — but the STATE falls back, so a contradicted entry never
  // reports witness-signed and the bundle rejects.
  for (const [seq, count] of claims) {
    if (count > 1) states[seq] = PROCESS_ASSERTED;
  }

  const lines: Record<string, string> = {};
  for (const [seq, state] of Object.entries(states)) {
    lines[seq] = envelopeLine(state, results[seq] ?? null);
  }
  const summary: EnvelopeSummary = {
    status: fail.length === 0 ? "verified" : "FAILED",
    count: envelopes.length,
    witness_signed: Object.entries(states)
      .filter(([, state]) => state === WITNESS_SIGNED)
      .map(([seq]) => Number(seq))
      .sort((a, b) => a - b),
    states,
    results,
    lines,
    failures: [...fail.messages],
  };
  return [summary, fail];
}

/** Python `repr` for a member set, so both implementations print the same failure strings. */
function reprList(values: readonly string[]): string {
  return `[${values.map((v) => `'${v}'`).join(", ")}]`;
}

/**
 * One envelope, checked in the order the seven named failures are defined in.
 *
 * Returns the covered entry for an envelope that verified, and `null` for one that did not.
 * Every failure is positioned on the entry the envelope COVERS, found by `subject.seq` — the
 * locators are checked against that entry, not used to find it.
 *
 * `claims` is the caller's seq -> count of the envelopes that have named each entry so far, and
 * this function updates it. An envelope claims its entry as soon as `subject.seq` finds one,
 * BEFORE the rest of the subject is checked, so a second envelope over an entry an earlier one
 * already named is `envelope_duplicate_subject` whether either of them is otherwise sound: the
 * point of the check is that no one can decide what an earlier witness said by appending after
 * it.
 */
function scoreEnvelope(
  envelope: Envelope,
  index: number,
  bySeq: Map<Json, LedgerEntry>,
  recomputed: Map<Json, string | null>,
  trusted: Map<string, [string, Buffer]>,
  raw: Buffer | string | null,
  fail: FailureLog,
  claims: Map<string, number>,
): { seq: Json; node: Json; result: Json } | null {
  const isRecord = (v: unknown): v is Record<string, CJson> =>
    v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof RawNumber);

  const subject: unknown = isRecord(envelope) ? envelope["subject"] : undefined;

  function position(): [Json, Json] {
    const s = isRecord(subject) ? (toPlain(subject["seq"]) as Json) : null;
    const entry = bySeq.get(s);
    if (entry === undefined) return [typeof s === "number" ? s : null, null];
    return [orNull(entry["seq"]), orNull(entry["node"])];
  }

  function report(reason: string, detail: string): null {
    const [seq, node] = position();
    fail.add(reason, `${reason}: ${detail}`, { seq, node });
    return null;
  }

  if (!isRecord(envelope)) {
    fail.add("envelope_unknown_version", `envelope_unknown_version: envelope #${index} is not a JSON object`);
    return null;
  }

  // (1) version — a `v` or `typ` this build does not know is a DIFFERENT CONTRACT, and nothing
  // further about it can be read safely.
  const v = toPlain(envelope["v"] as CJson) as Json;
  const typ = toPlain(envelope["typ"] as CJson) as Json;
  if (v !== ENVELOPE_VERSION || typ !== ENVELOPE_TYP) {
    return report(
      "envelope_unknown_version",
      `envelope v=${pyRepr(v)} typ=${pyRepr(typ)}, this build knows v=${ENVELOPE_VERSION} ` +
        `typ='${ENVELOPE_TYP}'`,
    );
  }

  // (2) member sets — the version commits the exact signed member set of the whole envelope, so
  // a member added ANYWHERE is a new version that did not declare itself.
  const levels: [string, unknown, ReadonlySet<string>][] = [
    ["envelope", envelope, ENVELOPE_MEMBERS],
    ["observed", envelope["observed"], ENVELOPE_OBSERVED_MEMBERS],
    ["witness", envelope["witness"], ENVELOPE_WITNESS_MEMBERS],
  ];
  for (const [label, value, expected] of levels) {
    const members = isRecord(value) ? sortedStrings(Object.keys(value)) : null;
    if (members === null || members.length !== expected.size || members.some((m) => !expected.has(m))) {
      const got = members === null ? (value === null ? "null" : typeof value) : reprList(members);
      return report(
        "envelope_unknown_member",
        `${label} member set is ${got}, expected ${reprList(sortedStrings(expected))}`,
      );
    }
  }

  // (3) subject — the event decides the member set; a member ADDED to it is unknown_member, one
  // MISSING is subject_mismatch (a subject that does not say what it covers).
  if (!isRecord(subject)) {
    const kind = subject === null ? "null" : typeof subject;
    return report("envelope_subject_mismatch", `subject is ${kind}, expected a JSON object`);
  }
  const event = toPlain(subject["event"]) as Json;
  const expectedMembers = typeof event === "string" ? ENVELOPE_SUBJECT_MEMBERS.get(event) : undefined;
  if (expectedMembers === undefined) {
    return report(
      "envelope_subject_mismatch",
      `subject event=${pyRepr(event)}; envelope v${ENVELOPE_VERSION} defines a subject for ` +
        `${reprList(sortedStrings(ENVELOPE_SUBJECT_MEMBERS.keys()))} and no other event`,
    );
  }
  const present = sortedStrings(Object.keys(subject));
  const added = present.filter((m) => !expectedMembers.has(m));
  if (added.length > 0) {
    return report(
      "envelope_unknown_member",
      `subject member set is ${reprList(present)}, expected ` +
        `${reprList(sortedStrings(expectedMembers))} for a ${event} subject`,
    );
  }
  const missing = sortedStrings(expectedMembers).filter((m) => !(m in subject));
  if (missing.length > 0) {
    return report(
      "envelope_subject_mismatch",
      `subject is missing ${reprList(missing)}, which a ${event} subject requires`,
    );
  }

  // (3a) the binding member. `seq` is the lookup key, so there is nothing to compare it against;
  // the entry it finds supplies the hash the subject is checked against.
  const subjectSeq = toPlain(subject["seq"]) as Json;
  const entry = bySeq.get(subjectSeq);
  if (entry === undefined) {
    return report("envelope_subject_mismatch", `no entry at seq ${pyRepr(subjectSeq)} in this bundle`);
  }
  const seq = orNull(entry["seq"]);

  // (3a') one entry, at most one envelope. Counted here, before anything else about this
  // envelope is judged, so the rule cannot be sidestepped by making the second envelope
  // defective in some other way as well.
  const claimKey = String(seq);
  const already = claims.get(claimKey) ?? 0;
  claims.set(claimKey, already + 1);
  if (already > 0) {
    return report(
      "envelope_duplicate_subject",
      `seq ${claimKey} is already covered by an earlier envelope in this bundle; two ` +
        "observations of one event contradict each other by construction, so this entry is not " +
        "witness-signed",
    );
  }

  const computed = recomputed.get(seq) ?? null;
  const claimed = toPlain(subject["entry_hash"]) as Json;
  if (claimed !== computed) {
    return report(
      "envelope_subject_mismatch",
      `subject entry_hash ${pyRepr(claimed)} != the hash recomputed for seq ${String(seq)} from ` +
        `this bundle (${pyRepr(computed)})`,
    );
  }

  // (3b) the locators, checked against the SAME entry `seq` found. A matching locator attests
  // nothing on its own; a disagreeing one is the same failure at the same position.
  const locators: [string, Json][] = [
    ["chain_id", orNull(entry["chain_id"])],
    ["node", orNull(entry["node"])],
    ["event", orNull(entry["event"])],
  ];
  if (event === "allow") locators.push(["call_id", orNull(entry["call_id"])]);
  for (const [member, actual] of locators) {
    const stated = toPlain(subject[member]) as Json;
    if (stated !== actual) {
      return report(
        "envelope_subject_mismatch",
        `subject ${member}=${pyRepr(stated)} != ${pyRepr(actual)} on the entry at seq ${String(seq)}`,
      );
    }
  }

  // (4) canonicality — an invariant SEPARATE from the signature: the received bytes must equal
  // JCS of what they parse to. It can only be raised where the bytes as received are supplied,
  // because formatting and escaping do not survive a parse.
  let nonCanonical = false;
  if (raw !== null) {
    const received = typeof raw === "string" ? Buffer.from(raw, "hex") : raw;
    let recanonicalized: Buffer | null = null;
    try {
      recanonicalized = canonicalBytes(envelope as unknown as CJson);
    } catch (err) {
      nonCanonical = true;
      report("envelope_non_canonical", `the envelope cannot be canonicalized: ${String(err)}`);
    }
    if (recanonicalized !== null && !recanonicalized.equals(received)) {
      nonCanonical = true;
      report(
        "envelope_non_canonical",
        "the bytes as received are not JCS of what they parse to " +
          `(${received.length} received, ${recanonicalized.length} canonical)`,
      );
    }
  }

  // (5) the witness key. A signature that verifies under some OTHER trusted key is not
  // witness-signed: the kid names the key, and that is the key it has to verify under.
  const witness = envelope["witness"] as Record<string, CJson>;
  const kid = toPlain(witness["kid"]) as Json;
  const alg = toPlain(witness["alg"]) as Json;
  const known = typeof kid === "string" ? trusted.get(kid) : undefined;
  if (known === undefined || known[0] !== alg) {
    return report(
      "envelope_unknown_witness",
      `witness kid=${pyRepr(kid)} alg=${pyRepr(alg)} is not in the trusted witness keys ` +
        `(${reprList(sortedStrings(trusted.keys()))})`,
    );
  }

  // (6) the signature, over JCS(envelope minus "sig").
  const sigHex = toPlain(envelope["sig"]) as Json;
  const signature = typeof sigHex === "string" && /^[0-9a-fA-F]*$/.test(sigHex)
    ? Buffer.from(sigHex, "hex")
    : Buffer.alloc(0);
  let verified = false;
  try {
    verified = new Ed25519Verifier(known[1], kid as string).verify(
      envelopeSigningInput(envelope),
      signature,
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    return report("envelope_bad_signature", `the signature does not verify under the key kid=${pyRepr(kid)} names`);
  }
  if (nonCanonical) return null;
  return { seq, node: orNull(entry["node"]), result: toPlain(envelope["observed"]["result"]) as Json };
}

/**
 * Score a bundle's observer envelopes on their own, without the ledger checks.
 *
 * Returns `{ok, ...summary, failure_details}`. `states` maps every entry's seq to
 * `witness-signed` or `process-asserted`; `lines` is the report line for each.
 */
export function verifyEnvelopes(
  bundle: Partial<Bundle>,
  options: VerifyEnvelopesOptions = {},
): EnvelopeSummary & { ok: boolean; failure_details: FailureDetail[] } {
  const [summary, fail] = scoreEnvelopes(
    bundle.entries ?? [],
    bundle.envelopes ?? [],
    trustedWitnesses(options.witnessKeys ?? null),
    options.envelopeBytes ?? null,
  );
  return { ok: fail.length === 0, ...summary, failure_details: fail.details };
}

// =============================================================================================
// Execution binding (0.9.0): offline checks over callId/allow/outcome, from the ledger alone —
// docs/execution-binding spec section 5. schemaVersion=2 chains only; a v1 bundle's
// executionBinding is `{status: "not applicable"}`.
// =============================================================================================

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * `true` when `field` is EXPLICITLY present on `e` with a JSON `null` value — distinct from the
 * key being absent entirely. A conditional field (`authorized_params_hash`, `capture`, ...) must
 * be either a valid value or ABSENT; an explicit `null` is neither, and reading `e[field]` alone
 * cannot tell the two apart (both come back as `undefined`/`null`-ish), so every validator checks
 * membership first.
 */
function presentButNull(e: LedgerEntry, field: string): boolean {
  return field in e && toPlain(e[field]) === null;
}

function validCallId(e: LedgerEntry): string | null {
  if (presentButNull(e, "call_id")) {
    return "call_id is explicitly null (must be a valid call_id or absent)";
  }
  const cid = toPlain(e["call_id"]);
  if (typeof cid !== "string" || !HEX32.test(cid)) {
    return `call_id missing or malformed (${pyRepr(cid ?? null)})`;
  }
  return null;
}

function validHashField(e: LedgerEntry, field: string): string | null {
  if (presentButNull(e, field)) {
    return `${field} is explicitly null (must be a valid hash or absent)`;
  }
  const v = toPlain(e[field]);
  if (v === undefined || v === null) return null;
  if (typeof v !== "string" || !HEX64.test(v)) {
    return `${field} malformed (${pyRepr(v)})`;
  }
  return null;
}

function validParamsHashReason(e: LedgerEntry, hashField: string): string | null {
  if (presentButNull(e, "params_hash_reason")) {
    return "params_hash_reason is explicitly null (must be a valid reason or absent)";
  }
  const reason = toPlain(e["params_hash_reason"]) as Json;
  if (reason !== null && reason !== undefined && !PARAMS_HASH_REASONS.has(reason as string)) {
    return `params_hash_reason ${pyRepr(reason)} not a known value`;
  }
  const hash = toPlain(e[hashField]);
  if (reason !== null && reason !== undefined && hash !== null && hash !== undefined) {
    return `params_hash_reason present alongside ${hashField} (illegal conditional field)`;
  }
  return null;
}

function isPlainRecord(v: unknown): v is Record<string, Json> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function validateAllow(e: LedgerEntry): string | null {
  let err = validCallId(e);
  if (err) return err;
  if (presentButNull(e, "capture")) {
    return "capture is explicitly null (must be a valid Capture value)";
  }
  if (presentButNull(e, "adapter")) {
    return "adapter is explicitly null (must be a valid adapter object)";
  }
  const capture = toPlain(e["capture"]);
  const adapter = toPlain(e["adapter"]);
  // Mandatory on every v2 allow (not merely paired with each other): a bare check() with no
  // wrapper is ITSELF pre_hook_only observation, and Guard.check() supplies that truthfully —
  // there is no honest reason for a v2 allow to lack capture/adapter, so absence is now invalid,
  // not "no claim made" (merge-gate item 4).
  if (capture === null || capture === undefined) {
    return "capture is required on every v2 allow";
  }
  if (!CAPTURES.has(capture as string)) {
    return `capture ${pyRepr(capture as Json)} not a known value`;
  }
  if (adapter === null || adapter === undefined) {
    return "adapter is required alongside capture on every v2 allow";
  }
  if (!isPlainRecord(adapter)) {
    return "adapter must be an object with module/version/hook_path";
  }
  for (const k of ["module", "version", "hook_path"] as const) {
    const v = (adapter as Record<string, Json>)[k];
    if (typeof v !== "string" || !v) {
      return `adapter[${JSON.stringify(k)}] must be a non-empty string`;
    }
  }
  err = validHashField(e, "authorized_params_hash");
  if (err) return err;
  return validParamsHashReason(e, "authorized_params_hash");
}

/** Fields that only ever belong on an `allow` entry — illegal on a `deny`, on any schema version. */
const ALLOW_ONLY_FIELDS = ["capture", "adapter", "authorized_params_hash", "params_hash_reason"] as const;

function validateDeny(e: LedgerEntry): string | null {
  const err = validCallId(e);
  if (err) return err;
  const leaked = ALLOW_ONLY_FIELDS.filter((f) => f in e).sort();
  if (leaked.length > 0) {
    return `deny carries allow-only field(s) ${JSON.stringify(leaked)}`;
  }
  return null;
}

function validateOutcome(e: LedgerEntry): string | null {
  const err0 = validCallId(e);
  if (err0) return err0;
  if (presentButNull(e, "body_state")) return "body_state is explicitly null";
  const bodyState = toPlain(e["body_state"]) as Json;
  if (typeof bodyState !== "string" || !BODY_STATES.has(bodyState)) {
    return `body_state ${pyRepr(bodyState ?? null)} not a known value`;
  }
  if (presentButNull(e, "error_code")) {
    return "error_code is explicitly null (must be a non-empty string or absent)";
  }
  const errorCode = toPlain(e["error_code"]);
  if (bodyState === BodyState.RAISED) {
    if (typeof errorCode !== "string" || !errorCode) {
      return "error_code required when body_state == raised";
    }
  } else if (errorCode !== null && errorCode !== undefined) {
    return "error_code present but body_state != raised (illegal conditional field)";
  }
  if (presentButNull(e, "duration_ms")) return "duration_ms is explicitly null";
  const duration = toPlain(e["duration_ms"]);
  if (typeof duration !== "number" || !Number.isInteger(duration) || duration < 0) {
    return `duration_ms invalid (${pyRepr((duration as Json) ?? null)})`;
  }
  const err1 = validHashField(e, "invoked_params_hash");
  if (err1) return err1;
  const err2 = validParamsHashReason(e, "invoked_params_hash");
  if (err2) return err2;
  if (presentButNull(e, "receipt")) {
    return "receipt is explicitly null (must be a valid receipt or absent)";
  }
  const receipt = toPlain(e["receipt"]);
  if (receipt !== null && receipt !== undefined) {
    if (!isPlainRecord(receipt)) return "receipt must be an object with type/ref/digest";
    for (const k of ["type", "ref"] as const) {
      const v = (receipt as Record<string, Json>)[k];
      if (typeof v !== "string" || !v) {
        return `receipt[${JSON.stringify(k)}] must be a non-empty string`;
      }
    }
    const digest = (receipt as Record<string, Json>)["digest"];
    if (typeof digest !== "string" || !HEX64.test(digest)) {
      return "receipt['digest'] must be a lowercase-hex SHA-256 digest (64 hex characters)";
    }
  }
  return null;
}

/**
 * v2 root only: `params_salt` is MANDATORY (spec section 4 — the whole chain's argument
 * commitments are computed against it) and must be 32 lowercase hex characters (16 raw bytes).
 */
function validateRoot(e: LedgerEntry): string | null {
  if (presentButNull(e, "params_salt")) return "params_salt is explicitly null";
  const salt = toPlain(e["params_salt"]);
  if (typeof salt !== "string" || !/^[0-9a-f]{32}$/.test(salt)) {
    return `params_salt missing or malformed on the v2 root entry (${pyRepr((salt as Json) ?? null)})`;
  }
  return null;
}

/** v2 kill only: `pending_at_kill`, when present, must be a list of call_id-shaped strings. */
function validateKill(e: LedgerEntry): string | null {
  if (presentButNull(e, "pending_at_kill")) {
    return "pending_at_kill is explicitly null (must be a list or absent)";
  }
  const pending = toPlain(e["pending_at_kill"]);
  if (pending === null || pending === undefined) return null;
  if (!Array.isArray(pending) || pending.some((c) => typeof c !== "string" || !HEX32.test(c))) {
    return `pending_at_kill must be a list of call_id-shaped strings (${pyRepr(pending as Json)})`;
  }
  return null;
}

/**
 * `complete | partial | none`, from how many calls carry both hashes — computed over EVERY valid
 * allow (spec section 5: "how many calls carry both hashes"), not only calls that already have
 * an outcome: a call still pending necessarily lacks `invoked_params_hash` and so correctly
 * counts against coverage, not merely outside the sample.
 */
function paramsCoverage(
  allows: ReadonlyMap<string, LedgerEntry>,
  outcomes: ReadonlyMap<string, LedgerEntry>,
  invalidAllowIds: ReadonlySet<string>,
): "complete" | "partial" | "none" {
  let total = 0;
  let both = 0;
  for (const [cid, allowE] of allows) {
    if (invalidAllowIds.has(cid)) continue;
    total += 1;
    const oc = outcomes.get(cid);
    if (toPlain(allowE["authorized_params_hash"]) && oc !== undefined && toPlain(oc["invoked_params_hash"])) {
      both += 1;
    }
  }
  if (total === 0 || both === 0) return "none";
  return both === total ? "complete" : "partial";
}

export type ExecutionBinding =
  // `failures` is present on the "not applicable" (v1) shape only when a v2-only field leaked
  // onto a v1 entry (merge-gate item 4/(c)) — a v1 bundle with no such leak omits it entirely,
  // matching the historical `{status: "not applicable"}` shape byte for byte.
  | { status: "not applicable"; failures?: string[] }
  | {
      aggregate: "clean" | "incomplete" | "failed";
      params_coverage: "complete" | "partial" | "none";
      per_call: Record<string, "observed" | "unobserved" | "unaccounted">;
      per_node_lifecycle: Record<string, "finalized" | "in_progress" | "revoked" | "revoked_with_pending">;
      failures: string[];
    };

/**
 * Every field the library ever writes only under `schemaVersion: 2` (spec sections 1-7). A
 * `schemaVersion: 1` chain must carry NONE of them — including `call_id`: v1 never allocates one.
 */
const V2_ONLY_FIELDS = [
  "call_id",
  "capture",
  "adapter",
  "authorized_params_hash",
  "params_hash_reason",
  "params_salt",
  "body_state",
  "error_code",
  "invoked_params_hash",
  "duration_ms",
  "receipt",
  "pending_at_kill",
] as const;

/**
 * Every v2-only field found on any entry of a `schemaVersion: 1` bundle — mixed-version data,
 * invalid regardless of which field it is (merge-gate item 4/(c)).
 */
function v2FieldLeaksOnV1(entries: readonly LedgerEntry[]): FailureLog {
  const failures = new FailureLog();
  for (const e of entries) {
    const leaked = V2_ONLY_FIELDS.filter((f) => f in e).sort();
    if (leaked.length > 0) {
      failures.add(
        "v2_field_on_v1",
        `v2_field_on_v1: seq=${pyRepr(toPlain(e["seq"]) as Json)} event=${pyRepr(toPlain(e["event"]) as Json)} ` +
          `carries v2-only field(s) ${JSON.stringify(leaked)} on a schemaVersion: 1 entry`,
        { seq: orNull(e["seq"]), node: orNull(e["node"]) },
      );
    }
  }
  return failures;
}

/**
 * `[the execution_binding report, its failures]`. The report's own `failures` key keeps its
 * historical list-of-strings shape — the structured twins ride alongside it rather than inside
 * it, so this sub-report's published shape is unchanged.
 */
function executionBinding(entries: readonly LedgerEntry[], bundleV: Json): [ExecutionBinding, FailureLog] {
  if (bundleV === 1) {
    const leaked = v2FieldLeaksOnV1(entries);
    return leaked.length > 0
      ? [{ status: "not applicable", failures: leaked.messages }, leaked]
      : [{ status: "not applicable" }, new FailureLog()];
  }
  if (bundleV !== 2) return [{ status: "not applicable" }, new FailureLog()];

  const failures = new FailureLog();
  const seenCallIds = new Map<string, [string, string | null, number | null]>(); // callId -> [event, node, seq]
  const allows = new Map<string, LedgerEntry>();
  const outcomes = new Map<string, LedgerEntry>();
  const invalidAllowIds = new Set<string>();
  const nodes = new Set<string>();
  const finalizedNodes = new Set<string>();
  const revokedNodes = new Set<string>();

  for (const e of entries) {
    const ev = toPlain(e["event"]);
    const node = toPlain(e["node"]) as string | null;
    const seqForEvent = toPlain(e["seq"]) as number | null;
    if (ev === "root") {
      if (node !== null) nodes.add(node);
      const err = validateRoot(e);
      if (err) {
        failures.add("invalid_root", `invalid_root: ${err} (seq ${pyRepr(seqForEvent)})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
        });
      }
    } else if (ev === "spawn") {
      if (node !== null) nodes.add(node);
    } else if (ev === "done") {
      if (node !== null) finalizedNodes.add(node);
    } else if (ev === "kill") {
      for (const r of (toPlain(e["revoked"]) as string[] | null) ?? []) revokedNodes.add(r);
      const err = validateKill(e);
      if (err) {
        failures.add("invalid_kill", `invalid_kill: ${err} (seq ${pyRepr(seqForEvent)})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
        });
      }
    }

    if (ev === "allow" || ev === "deny") {
      const cid = toPlain(e["call_id"]) as string | null;
      const seq = toPlain(e["seq"]) as number | null;
      if (cid !== null && cid !== undefined) {
        const prior = seenCallIds.get(cid);
        if (prior !== undefined) {
          // Positioned on the SECOND sighting: the entry that re-used a call_id is the offending
          // record, the first one having been legitimate when it was written.
          failures.add(
            "duplicate_call_id",
            `duplicate_call_id: call_id ${cid} on seq ${pyRepr(seq)} (${ev}) already used at seq ` +
              `${pyRepr(prior[2])} (${prior[0]})`,
            { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: cid },
          );
        } else {
          seenCallIds.set(cid, [ev, node, seq]);
        }
      }
      const err = ev === "allow" ? validateAllow(e) : validateDeny(e);
      if (err) {
        failures.add(`invalid_${ev}`, `invalid_${ev}: ${err} (seq ${pyRepr(seq)})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
          callId: cid ?? null,
        });
        if (ev === "allow" && cid !== null && cid !== undefined) invalidAllowIds.add(cid);
        continue;
      }
      if (ev === "allow" && cid !== null && cid !== undefined) allows.set(cid, e);
    } else if (ev === "outcome") {
      const cid = toPlain(e["call_id"]) as string | null;
      const seq = toPlain(e["seq"]) as number | null;
      const err = validateOutcome(e);
      if (err) {
        failures.add("invalid_outcome", `invalid_outcome: ${err} (seq ${pyRepr(seq)})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
          callId: cid ?? null,
        });
        continue;
      }
      if (cid !== null && outcomes.has(cid)) {
        failures.add(
          "duplicate_outcome",
          `duplicate_outcome: call_id ${cid} at seq ${pyRepr(seq)} (first at seq ` +
            `${pyRepr(toPlain(outcomes.get(cid)!["seq"]) as Json)})`,
          { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: cid },
        );
        continue;
      }
      if (cid !== null) outcomes.set(cid, e);
    }
  }

  // Bind each outcome to its allow: outcome_without_allow / cross_ref / outcome_before_allow /
  // params_mismatch. `boundOk`: callIds whose outcome exists AND passed identity+order binding
  // (node match, seq after the allow) — spec's "observed (an outcome exists, bound correctly)".
  // Failing params_mismatch does NOT itself un-bind a call: the call plainly WAS observed, only
  // its recorded content disagrees with what was authorized (spec: "parameter equality is
  // established only for calls where both hashes are present; elsewhere only identity and order
  // binding was checked" — params_mismatch is that separate concern).
  // Every failure in this loop is about a PAIR, and is positioned on the `outcome` entry: the
  // allow was a complete, valid record when it was written, and it is the outcome that fails to
  // bind to it (or reports different arguments than were authorized).
  const boundOk = new Set<string>();
  for (const [cid, oc] of outcomes) {
    const allowE = allows.get(cid);
    if (allowE === undefined) {
      failures.add(
        "outcome_without_allow",
        `outcome_without_allow: call_id ${cid} at seq ${pyRepr(toPlain(oc["seq"]) as Json)} has no allow in this chain`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid },
      );
      continue;
    }
    const nodeOk = toPlain(allowE["node"]) === toPlain(oc["node"]);
    if (!nodeOk) {
      failures.add(
        "cross_ref",
        `cross_ref: call_id ${cid} allow on node ${pyRepr(toPlain(allowE["node"]) as Json)} but ` +
          `outcome on node ${pyRepr(toPlain(oc["node"]) as Json)}`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid },
      );
    }
    const ocSeq = toPlain(oc["seq"]);
    const allowSeq = toPlain(allowE["seq"]);
    const orderOk = typeof ocSeq === "number" && typeof allowSeq === "number" && ocSeq > allowSeq;
    if (!orderOk) {
      failures.add(
        "outcome_before_allow",
        `outcome_before_allow: call_id ${cid} outcome seq ${pyRepr((ocSeq as Json) ?? null)} not ` +
          `after allow seq ${pyRepr((allowSeq as Json) ?? null)}`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid },
      );
    }
    const ah = toPlain(allowE["authorized_params_hash"]);
    const ih = toPlain(oc["invoked_params_hash"]);
    if (ah !== null && ah !== undefined && ih !== null && ih !== undefined && ah !== ih) {
      failures.add(
        "params_mismatch",
        `params_mismatch: call_id ${cid} authorized_params_hash ${ah} != invoked_params_hash ${ih}`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid },
      );
    }
    if (nodeOk && orderOk) boundOk.add(cid);
  }

  // Per-call observation + per-node pending, from valid allows only.
  const perCall: Record<string, "observed" | "unobserved" | "unaccounted"> = {};
  const nodePending = new Map<string, string[]>();
  for (const [cid, allowE] of allows) {
    if (invalidAllowIds.has(cid)) continue;
    // Spec order matters: "observed" (an outcome exists, BOUND CORRECTLY) is checked FIRST —
    // not merely "a callId-matching outcome exists somewhere", which a cross_ref'd or
    // misordered outcome would satisfy despite being wrong. Only once no correctly-bound outcome
    // exists does capture decide unobserved (none was promised) vs unaccounted (one was, and
    // none arrived correctly).
    if (boundOk.has(cid)) {
      perCall[cid] = "observed";
      continue;
    }
    const capture = toPlain(allowE["capture"]);
    if (capture === null || capture === undefined || capture === Capture.PRE_HOOK_ONLY) {
      perCall[cid] = "unobserved";
    } else {
      perCall[cid] = "unaccounted";
      const node = toPlain(allowE["node"]) as string;
      const list = nodePending.get(node) ?? [];
      list.push(cid);
      nodePending.set(node, list);
    }
  }

  // Per-node lifecycle. "revoked" (clean kill, nothing pending) is not one of the spec's three
  // named states (finalized/in_progress/revoked_with_pending) — it names the gap those three
  // leave for a cleanly-killed node, distinct from revoked_with_pending, and never escalates the
  // aggregate (mirrors the Python reference implementation's report).
  const lifecycle: Record<string, "finalized" | "in_progress" | "revoked" | "revoked_with_pending"> = {};
  for (const n of nodes) {
    if (finalizedNodes.has(n)) {
      lifecycle[n] = "finalized";
    } else if (revokedNodes.has(n)) {
      lifecycle[n] = (nodePending.get(n)?.length ?? 0) > 0 ? "revoked_with_pending" : "revoked";
    } else {
      lifecycle[n] = "in_progress";
    }
  }

  // Aggregate: clean < incomplete < failed — never downgrade once escalated.
  const order: Record<string, number> = { clean: 0, incomplete: 1, failed: 2 };
  let aggregate: "clean" | "incomplete" | "failed" = "clean";
  const escalate = (level: "clean" | "incomplete" | "failed") => {
    if (order[level]! > order[aggregate]!) aggregate = level;
  };

  if (failures.length > 0) {
    // Any binding failure or invalid record is a genuine inconsistency, not a benign gap — worse
    // than "incomplete", which the spec reserves for gaps that are no producer fault.
    escalate("failed");
  }
  for (const [n, state] of Object.entries(lifecycle)) {
    if (state === "finalized" && (nodePending.get(n)?.length ?? 0) > 0) {
      escalate("failed"); // an unaccounted call in a finalized node (spec section 5)
    } else if (state === "in_progress" || state === "revoked_with_pending") {
      escalate("incomplete");
    }
  }
  if (Object.values(perCall).some((s) => s === "unobserved")) escalate("incomplete");

  return [
    {
      aggregate,
      params_coverage: paramsCoverage(allows, outcomes, invalidAllowIds),
      per_call: perCall,
      per_node_lifecycle: lifecycle,
      failures: failures.messages,
    },
    failures,
  ];
}

/**
 * `[seq, node]` of the FIRST entry the hash chain does not reproduce at — position only.
 *
 * `AuditLog.verify` stays the authority on WHETHER the chain is broken and on the message this
 * module reports; this walk exists so the structured twin of that message can say WHERE, which
 * the message's own text does not expose in a parseable form. Mirrors `AuditLog.verify`'s walk
 * exactly (same seq/prev_hash/hash order). `[null, null]` when nothing entry-local is wrong — a
 * consistently re-hashed ledger fails against the signed anchor, not here, and that failure is
 * chain-level.
 */
function integrityPosition(entries: readonly LedgerEntry[]): [Json, Json] {
  let prev: Json = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i]!;
    const payload: LedgerEntry = {};
    for (const [k, v] of Object.entries(e)) {
      if (k !== "hash") payload[k] = v;
    }
    let broken: boolean;
    try {
      broken =
        orNull(e["seq"]) !== i ||
        orNull(payload["prev_hash"]) !== prev ||
        hashEntry(prev as string, payload) !== orNull(e["hash"]);
    } catch {
      // An unhashable payload is itself the break, at this entry.
      return [orNull(e["seq"]), orNull(e["node"])];
    }
    if (broken) return [orNull(e["seq"]), orNull(e["node"])];
    prev = orNull(e["hash"]);
  }
  return [null, null];
}

export interface VerifyReport {
  ok: boolean;
  checks: VerifyChecks;
  failures: string[];
  /**
   * The structured twin of `failures`: same order, same count, one
   * `{reason, seq, node, call_id, detail}` per string, so a conformance suite can assert the
   * reason AND the position of every failure instead of matching prose.
   */
  failure_details: FailureDetail[];
  nodes: number;
  actions_checked: number;
  chain_id: Json;
  execution_binding: ExecutionBinding;
  /**
   * The observer-envelope layer: the per-entry state for EVERY entry, the result and report line
   * for each, and the failures (which are also in `failures`/`failure_details`).
   */
  envelopes: EnvelopeSummary;
  /** Which anchor mode this verification ran against. */
  verified_against: "expected_anchor" | "bundle_anchor";
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
 *
 * Verifying against ONLY the bundle's own enclosed anchor detects tampering since that anchor,
 * nothing earlier — a fully rewritten bundle whose attacker also controls (or omits) the anchor
 * is invisible to that check alone (spec section 5). `options.expectedAnchor` (a full anchor
 * object, e.g. one retained from an earlier `exportBundle`) or `options.expectedHead` (a bare
 * `[seq, hash]` tuple) let a caller supply an INDEPENDENTLY RETAINED reference point; when given,
 * the bundle's actual `(seq, hash, chainId, v)` must equal it exactly, or `checks.expected_anchor`
 * reports `"FAILED"` and the mismatch lands in `failures`. `report.verified_against` names which
 * mode ran.
 *
 * `failure_details` is the structured twin of `failures`: same order, same count, one
 * `{reason, seq, node, call_id, detail}` entry per string.
 */
export interface VerifyBundleOptions {
  /** An independently retained anchor object to verify the bundle's actual head against. */
  expectedAnchor?: Record<string, CJson> | Anchor | null;
  /** An independently retained `[seq, hash]` to verify the bundle's actual head against. */
  expectedHead?: readonly [number, string] | null;
  /**
   * The trust set for the bundle's observer envelopes, if it carries any: the vector file's
   * `[{kid, alg, public_key_hex}]` shape, or a `{kid: publicKey}` record. Absent is an EMPTY
   * trust set, not a skipped check — an envelope naming a key nobody trusts is
   * `envelope_unknown_witness`.
   */
  witnessKeys?: readonly WitnessKey[] | Record<string, Buffer | string> | null;
  /**
   * The envelope bytes AS RECEIVED, positionally aligned with `bundle.envelopes`. Only
   * `envelope_non_canonical` needs them, and only where a deployment kept them.
   */
  envelopeBytes?: readonly (Buffer | string | null)[] | null;
}

export function verifyBundle(
  bundle: Partial<Bundle>,
  signer: Signer | null = null,
  options: VerifyBundleOptions = {},
): VerifyReport {
  const entries = bundle.entries ?? [];
  const anchor = (bundle.anchor ?? {}) as Record<string, CJson>;
  const anchorPresent = Object.keys(anchor).length > 0;
  const checks: VerifyChecks = {
    integrity: false,
    monotonicity: false,
    containment: false,
    anchor: "not checked",
    version: false,
    chain_id: false,
    root: false,
    expected_anchor: "not checked",
    envelopes: "not present",
  };
  const log = new FailureLog();

  // (0) version: the bundle must declare a schema version this build understands, and — when
  // an anchor is present — the anchor must be anchoring THAT version, not a different one.
  const bundleV = toPlain(bundle.v as CJson | undefined) as Json;
  let versionOk = typeof bundleV === "number" && SUPPORTED_BUNDLE_VERSIONS.has(bundleV);
  if (!versionOk) {
    const supported = Array.from(SUPPORTED_BUNDLE_VERSIONS).sort((a, b) => a - b);
    log.add("unsupported_version", `unsupported_version: bundle v=${pyRepr(bundleV)} not in [${supported.join(", ")}]`);
  }
  const anchorV = toPlain(anchor["v"]) as Json;
  if (anchorPresent && anchorV !== bundleV) {
    versionOk = false;
    log.add(
      "anchor_version_mismatch",
      `anchor_version_mismatch: anchor v=${pyRepr(anchorV)} != bundle v=${pyRepr(bundleV)}`,
    );
  }

  // (0a) exactly one root: a rootless bundle (or one splicing in a second root) would otherwise
  // sail through monotonicity/containment trivially — there is nothing to anchor those checks to.
  const rootEvents = entries.filter((e) => toPlain(e["event"]) === "root");
  checks.root = rootEvents.length === 1;
  if (!checks.root) {
    log.add("missing_root", `missing_root: bundle has ${rootEvents.length} root event(s), expected exactly 1`);
  }
  const rootEntry = rootEvents.length === 1 ? rootEvents[0] : undefined;

  // 0.9.0: a chain is created at ONE schema version and never mixes (spec section 9) — the root
  // entry's v must equal the bundle's declared v, and no OTHER entry may carry a different v.
  if (rootEntry !== undefined && toPlain(rootEntry["v"]) !== bundleV) {
    versionOk = false;
    log.add(
      "root_version_mismatch",
      `root_version_mismatch: root v=${pyRepr(toPlain(rootEntry["v"]) as Json)} != bundle v=${pyRepr(bundleV)}`,
      { seq: orNull(rootEntry["seq"]), node: orNull(rootEntry["node"]) },
    );
  }
  const mixedEntries = entries.filter((e) => toPlain(e["v"]) !== bundleV);
  const mixed = Array.from(new Set(mixedEntries.map((e) => toPlain(e["v"])))).sort(
    (a, b) => (typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b))),
  );
  if (mixed.length > 0) {
    versionOk = false;
    // One aggregate message over every offending entry (unchanged); the twin is positioned on
    // the first of them, which is where a reader looks.
    log.add(
      "mixed_entry_versions",
      `mixed_entry_versions: entries declare v in [${mixed.map((v) => pyRepr(v as Json)).join(", ")}], bundle v=${pyRepr(bundleV)}`,
      { seq: orNull(mixedEntries[0]!["seq"]), node: orNull(mixedEntries[0]!["node"]) },
    );
  }
  checks.version = versionOk;

  // (0c) independently retained expected anchor/head: verified against the BUNDLE's actual
  // computed head, never against its own (possibly forged) enclosed anchor.
  const { expectedAnchor = null, expectedHead = null } = options;
  if (expectedAnchor !== null || expectedHead !== null) {
    const actualSeq = entries.length > 0 ? entries.length - 1 : -1;
    const actualHead = entries.length > 0 ? (entries[entries.length - 1]!["hash"] as string) : GENESIS;
    let expectedOk = true;
    if (expectedHead !== null) {
      const [expSeq, expHash] = expectedHead;
      if (actualSeq !== expSeq || actualHead !== expHash) {
        expectedOk = false;
        log.add(
          "expected_head_mismatch",
          `expected_head_mismatch: bundle head is (seq=${actualSeq}, hash=${actualHead}) but the ` +
            `independently retained expected head is (seq=${expSeq}, hash=${expHash})`,
        );
      }
    }
    if (expectedAnchor !== null) {
      const ea = expectedAnchor as Record<string, CJson>;
      if (
        toPlain(ea["seq"]) !== actualSeq ||
        toPlain(ea["head"]) !== actualHead ||
        toPlain(ea["chain_id"]) !== toPlain(bundle.chain_id as CJson | undefined) ||
        toPlain(ea["v"]) !== bundleV
      ) {
        expectedOk = false;
        log.add(
          "expected_anchor_mismatch",
          "expected_anchor_mismatch: the bundle's actual (seq, head, chainId, v) does not match " +
            "the independently retained expected anchor",
        );
      }
    }
    checks.expected_anchor = expectedOk ? "verified" : "FAILED";
  }

  // (0b) chain identity: the bundle, every entry, and — when an anchor is present — the anchor
  // must all name the SAME chain. Without this a correctly-signed, internally-consistent bundle
  // for a DIFFERENT chain could be handed to a verifier who believes it is checking this one.
  const bundleChainId = orNull(bundle.chain_id as CJson | undefined);
  const foreign = entries.find((e) => orNull(e["chain_id"]) !== bundleChainId);
  const entriesOk = foreign === undefined;
  if (foreign !== undefined) {
    log.add("chain_id_mismatch", `chain_id_mismatch: an entry does not carry chain_id=${pyRepr(bundleChainId)}`, {
      seq: orNull(foreign["seq"]),
      node: orNull(foreign["node"]),
    });
  }
  const anchorChainId = orNull(anchor["chain_id"]);
  const anchorChainOk = !anchorPresent || anchorChainId === bundleChainId;
  if (!anchorChainOk) {
    log.add(
      "chain_id_mismatch",
      `chain_id_mismatch: anchor chain_id=${pyRepr(anchorChainId)} != bundle chain_id=${pyRepr(bundleChainId)}`,
    );
  }
  checks.chain_id = entriesOk && anchorChainOk;

  // (1) integrity: the hash chain, plus the signed anchor when a key is given.
  const [okChain, err] = AuditLog.verify(entries);
  if (!okChain) {
    const [badSeq, badNode] = integrityPosition(entries);
    log.add("integrity", `integrity: ${err}`, { seq: badSeq, node: badNode });
  }
  if (signer !== null) {
    const [okAnchor, aerr] = AuditLog.verifyAnchor(entries, anchor, signer);
    checks.anchor = okAnchor ? "verified" : "FAILED";
    // Chain-level by construction: the anchor commits to the head of the WHOLE ledger, so a
    // consistently re-hashed chain has no single offending entry to point at.
    if (!okAnchor) log.add("integrity(anchor)", `integrity(anchor): ${aerr}`);
    checks.integrity = okChain && okAnchor;
  } else {
    checks.integrity = okChain;
  }

  const { auth, parent, failures: afail, definedBy } = nodeAuthorities(entries);
  log.extend(afail);

  // (2) monotonicity: every child ⊆ its parent.
  let mono = true;
  for (const [node, pid] of parent) {
    if (pid === null || !auth.has(pid) || !auth.has(node)) continue;
    const child = auth.get(node)!;
    const p = auth.get(pid)!;
    // 0.6.x: the subsumption relation ALONE decides. This used to be gated on a literal,
    // non-wildcard-aware scope difference, which silently accepted a delegation that widened
    // only ttl or a ceiling whenever the child's scopes happened to be literally a subset of
    // the parent's — the child was more powerful and the bundle verified clean.
    if (!child.isNarrowerThan(p)) {
      mono = false;
      const spawnE = definedBy.get(node);
      log.add(
        "monotonicity",
        `monotonicity: ${node} not ⊆ parent ${pid} (${monotonicityDetail(child, p)})`,
        { seq: spawnE === undefined ? null : orNull(spawnE["seq"]), node },
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
      log.add("containment", `containment: allow on unknown node ${node}`, {
        seq: orNull(e["seq"]),
        node: orNull(e["node"]),
        callId: orNull(e["call_id"]),
      });
      continue;
    }
    if (!a.permits(scope, ctx).allowed) {
      contained = false;
      log.add(
        "containment",
        `containment: allow of '${scope}' on ${node} outside its authority ` +
          `[${Array.from(a.scopes).sort(compareCodePoints).map((s) => `'${s}'`).join(", ")}]`,
        { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: orNull(e["call_id"]) },
      );
    }
  }
  checks.containment = contained;

  const [eb, ebFailures]: [ExecutionBinding, FailureLog] = versionOk
    ? executionBinding(entries, bundleV)
    : [{ status: "not applicable" }, new FailureLog()];
  if (eb.failures !== undefined && eb.failures.length > 0) log.extend(ebFailures);

  // (4) observer envelopes. Never required — an absent envelope is the status quo and changes
  // nothing — but a PRESENT one has to verify, and a broken one lands in this same list. The
  // per-entry state is reported either way, so a reader sees which hops were covered before
  // reading which one failed.
  const [envelopeSummary, envelopeFailures] = scoreEnvelopes(
    entries,
    bundle.envelopes ?? [],
    trustedWitnesses(options.witnessKeys ?? null),
    options.envelopeBytes ?? null,
  );
  if (bundle.envelopes === undefined) {
    envelopeSummary.status = "not present";
  } else {
    checks.envelopes = envelopeSummary.status;
    log.extend(envelopeFailures);
  }

  // "anchor", "expected_anchor" and "envelopes" are excluded here — each carries a status
  // string, not a plain pass/fail boolean, and a failed check on any of them already lands its
  // own entry in `failures`, which the `ok` computation still gates on.
  const ok =
    checks.integrity &&
    checks.monotonicity &&
    checks.containment &&
    checks.version &&
    checks.chain_id &&
    checks.root &&
    log.length === 0;
  return {
    ok,
    checks,
    failures: log.messages,
    failure_details: log.details,
    nodes: auth.size,
    actions_checked: actions,
    chain_id: orNull(bundle.chain_id),
    execution_binding: eb,
    envelopes: envelopeSummary,
    verified_against: expectedAnchor !== null || expectedHead !== null ? "expected_anchor" : "bundle_anchor",
  };
}

/** Read a bundle from JSON text, keeping every number's original literal. */
export function parseBundle(text: string): Bundle {
  return parseJson(text) as unknown as Bundle;
}
