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
  intOr,
  integral,
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
import { describeInFinding, wireKeyOf, type Context } from "./ceilings.js";
import { pyRepr, pyStr, pyStrRepr, shown } from "./display.js";
import { CAPTURES, BODY_STATES, POLICIES, BodyState, Capture } from "./reasons.js";
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
  // `detail` is library-written on a refusal (max_depth, max_fanout, chain_revoked, agent_banned,
  // integrity, ttl_expired, aggregate ceiling) and carries only structural values -- an agent or
  // parent id, a numeric limit, a ceiling key. Same class as `node`/`parent`/`agent`; never free
  // text like `task`, never caller-supplied like `context`.
  //
  // Its absence was not cosmetic: LEDGER_FIELDS gates `exportBundle({strict: true})`, so custody
  // mode threw on ANY run that refused a delegation, reporting a field this library wrote as
  // though it were customer data. Kept in step with the Python port.
  "detail",
  // `policy` marks an allow the chain never authorized (an `allowUnlisted` passthrough) — see
  // reasons.Policy and the containment check below. Not a v2-only field.
  "policy",
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
  /** The ledger entry the failure is about: one of the bundle's own entry objects, never a copy. */
  entry?: LedgerEntry | null;
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
  /**
   * A third list in step with those two: the ledger entry each failure is about, or `null` for a
   * failure about no single entry. It stays out of `details`, whose member set is the published
   * contract, and `entryIndices` turns it into positions in the bundle's `entries`, which
   * `verifyBundle` reports as `failure_entries`. A position is exact where a seq is not: an
   * entry's seq can be missing, null, a boolean or a duplicate, and its index is still its own.
   */
  readonly about: (LedgerEntry | null)[] = [];

  add(reason: string, detail: string, position: FailurePosition = {}): void {
    const { seq = null, node = null, callId = null, entry = null } = position;
    this.messages.push(detail);
    this.details.push({ reason, seq, node, call_id: callId, detail });
    this.about.push(entry);
  }

  extend(other: FailureLog): void {
    this.messages.push(...other.messages);
    this.details.push(...other.details);
    this.about.push(...other.about);
  }

  /**
   * For each failure, the index in `entries` of the entry it is about, or `null`. Found by
   * identity: every entry a check reports on is one of these objects.
   */
  entryIndices(entries: readonly LedgerEntry[]): (number | null)[] {
    const at = new Map<LedgerEntry, number>();
    entries.forEach((e, i) => {
      if (!at.has(e)) at.set(e, i);
    });
    return this.about.map((e) => (e === null ? null : (at.get(e) ?? null)));
  }

  get length(): number {
    return this.messages.length;
  }
}

interface NodeAuthorities {
  auth: Map<string, Authority>;
  /** A spawned node -> its `parent` member as written, whatever its type. */
  parent: Map<string, Json>;
  failures: FailureLog;
  /**
   * The `root`/`spawn` entry each node was DEFINED by, so a node-level failure
   * (monotonicity) can name the seq of the delegation that caused it, not only
   * the node.
   */
  definedBy: Map<string, LedgerEntry>;
}

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
      `child scopes ${reprList(extra.sort(compareCodePoints))} ` +
      `not held by parent`
    );
  }

  const childByKey = new Map(child.ceilings.map((c) => [String(c.key), c]));
  const parentKeys = parent.ceilings.map((c) => String(c.key)).sort(compareCodePoints);
  for (const key of parentKeys) {
    const parentCeiling = parent.ceilings.find((c) => String(c.key) === key)!;
    const childCeiling = childByKey.get(key);
    if (childCeiling === undefined) {
      return `ceiling ${shown(wireKeyOf(parentCeiling))} unbounded, parent holds ${describeInFinding(parentCeiling)}`;
    }
    if (!parentCeiling.subsumes(childCeiling)) {
      return (
        `ceiling ${describeInFinding(childCeiling)} looser than parent ` +
        `${describeInFinding(parentCeiling)}`
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

/**
 * `node -> Authority` and `node -> parent`, reconstructed from `root` and `spawn` events in ledger
 * order. No engine state.
 *
 * A node id is a string, and a node is defined once, by the root or by one spawn. A root or a
 * spawn whose `node` is not a string defines nothing and is reported unreadable here. A second
 * definition of a node is left out of these maps, so every later check reads the first one, and
 * `verifyBundle`'s monotonicity check reports it. `parent` maps a spawned node to its `parent`
 * member as written, whatever its type; whether that names a node defined earlier is judged there
 * too. The Python implementation's `_node_authorities`.
 */
function nodeAuthorities(entries: readonly LedgerEntry[]): NodeAuthorities {
  const auth = new Map<string, Authority>();
  const parent = new Map<string, Json>();
  const failures = new FailureLog();
  const definedBy = new Map<string, LedgerEntry>();
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    if (ev !== "root" && ev !== "spawn") continue;
    const node = toPlain(e["node"]) as Json | undefined;
    const position = { seq: orNull(e["seq"]), node: orNull(e["node"]), entry: e };
    if (typeof node !== "string") {
      // One of the two historical messages that name a node before their colon rather than a
      // reason token, so the reason is stated here instead of parsed out of the string.
      if (ev === "root") {
        failures.add("unreadable_authority", `root ${shown(e["node"])}: unreadable authority (node is not a string)`, position);
      } else {
        failures.add("unreadable_granted", `spawn ${shown(e["node"])}: unreadable granted (node is not a string)`, position);
      }
      continue;
    }
    if (definedBy.has(node)) continue; // defined twice: verifyBundle reports it
    definedBy.set(node, e);
    if (ev === "root") {
      try {
        auth.set(node, Authority.fromWire(e["authority"] ?? null));
      } catch (exc) {
        failures.add("unreadable_authority", `root ${shown(e["node"])}: unreadable authority (${(exc as Error).message})`, position);
      }
    } else {
      parent.set(node, orNull(e["parent"]));
      try {
        auth.set(node, Authority.fromWire(e["granted"] ?? null));
      } catch (exc) {
        failures.add("unreadable_granted", `spawn ${shown(e["node"])}: unreadable granted (${(exc as Error).message})`, position);
      }
    }
  }
  return { auth, parent, failures, definedBy };
}

/**
 * Record the nodes a `kill` entry revokes, node -> that kill's own `seq`; the first kill stands.
 * Only string ids in a list count: anything else names no node. The Python implementation's
 * `_note_revoked`.
 */
function noteRevoked(entry: LedgerEntry, revokedAt: Map<string, CJson | undefined>): void {
  const revoked = entry["revoked"];
  if (!Array.isArray(revoked)) return;
  for (const node of revoked) {
    if (typeof node === "string" && !revokedAt.has(node)) revokedAt.set(node, entry["seq"]);
  }
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
    const raw = toPlain(e["node"]) as Json | undefined;
    if (typeof raw !== "string" && ev !== "kill") continue; // a node id is a string; anything else names no node
    const n = raw as string;
    if (ev === "root" || ev === "spawn") {
      if (Object.hasOwn(meta, n)) continue; // defined once: the first definition stands
      const a = auth.get(n);
      setOwn(meta, n, {
        agent: orNull(e["agent"]),
        task: orNull(e["task"]),
        parent: orNull(e["parent"]),
        scopes: a ? Array.from(a.scopes).sort(compareCodePoints) : [],
        allows: 0,
        denies: 0,
        revoked: false,
        complete: false,
        denials_by_disposition: {},
      });
    } else if (ev === "allow" && Object.hasOwn(meta, n)) {
      meta[n]!.allows += 1;
    } else if (ev === "deny" && Object.hasOwn(meta, n)) {
      meta[n]!.denies += 1;
      // A deny without a disposition is named by its reason.
      const d = (toPlain(e["disposition"]) ?? toPlain(e["reason"]) ?? "unstated") as string;
      meta[n]!.denials_by_disposition[d] = (meta[n]!.denials_by_disposition[d] ?? 0) + 1;
    } else if (ev === "done" && Object.hasOwn(meta, n)) {
      meta[n]!.complete = true;
    } else if (ev === "kill") {
      const revoked = new Map<string, CJson | undefined>();
      noteRevoked(e, revoked);
      for (const r of revoked.keys()) {
        if (Object.hasOwn(meta, r)) meta[r]!.revoked = true;
      }
    }
  }
  const edges: { parent: string; child: string }[] = [];
  for (const [child, p] of parent) {
    if (typeof p === "string" && p !== "") edges.push({ parent: p, child });
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
  /** Which refusal event this row folds: `"deny"` (an action) or `"spawn_denied"` (a delegation). */
  event: Json;
  /** The sub-agent a `spawn_denied` refused; `null` on a `deny` row. */
  requested: Json;
  count: number;
  first_seq: number;
  last_seq: number;
}

/**
 * Every refusal on the ledger, grouped by (node, tool, scope, disposition, requested) — the rows
 * a Decisions queue renders: "should this agent be allowed to <tool>?", with how often it asked
 * and why it was refused. A pure fold over the ledger; no engine, no state. Ordered by first
 * occurrence.
 *
 * Two events are refusals, and both are folded here. A `deny` is a refused ACTION: it carries the
 * tool and scope, and `requested` is null. A `spawn_denied` is a refused DELEGATION — the chain
 * would not mint the child (revoked/expired parent, depth/fanout overflow) — recorded once, by
 * `Guard.delegate()`, on the PARENT node that asked; its `requested` names the sub-agent that was
 * refused, and it has no tool or scope because no action was ever authorized. An operator's queue
 * that folded only `deny` would show a refused tool call and miss a refused hand-off, which is the
 * larger event of the two.
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
    const ev = toPlain(e["event"]);
    if (ev !== "deny" && ev !== "spawn_denied") continue;
    // `spawn_denied` names the acting node in `parent` (there is no child node to name — that is
    // what was refused), so it is folded onto the node that asked.
    const node = ev === "spawn_denied" ? orNull(e["parent"]) : orNull(e["node"]);
    const requested = ev === "spawn_denied" ? orNull(e["agent"]) : null;
    const key = JSON.stringify([
      node,
      orNull(e["tool"]),
      orNull(e["scope"]),
      orNull(e["disposition"]),
      requested,
    ]);
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
        event: ev,
        requested,
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
  /**
   * Every entry's top-level fields are within `LEDGER_FIELDS`. False means the bundle carries a
   * field this verifier does not evaluate, so reporting success would be reporting it on an entry
   * that was only partly read.
   */
  ledger_fields: boolean;
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

// `pyRepr` and `pyStr` (display.ts) are Python's `repr` and `str` for the values these failure
// messages carry. Both implementations report the same failure bytes, so the distinction between
// `{x}` and `{x!r}` is load-bearing, and `pyRepr` escapes a string exactly as `repr` does.

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
 * envelope makes the delegation parent. The signature covers the entry's hash and chain position
 * plus what the witness-key holder observed; it does not attest that the action was permitted.
 * Monotonicity and containment answer that, from the ledger.
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

/**
 * One trusted witness key, in the shape the vector file carries.
 *
 * `not_after` is optional: an RFC 3339 date-time in UTC, written with `Z`, such as
 * `2026-10-05T00:00:00Z`. A row whose `not_after` is at or before the verification time is left
 * out of the trust set, so an envelope naming its kid fails `envelope_unknown_witness`, and the
 * message says the key expired and when. A row without it is trusted as before.
 */
export interface WitnessKey {
  kid: string;
  alg: string;
  public_key_hex: string;
  not_after?: string;
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
 * Where `states` and `results` file an entry: its seq when it has one, as the integer when it is
 * integral (`intOr`: `1.0` is filed as 1), and its index when it has none. The Python
 * implementation's `_state_key`, rendered as a record key. It is a report key, never a lookup: an
 * envelope finds the entry it covers through `subjectIndex`.
 */
export function stateKey(e: LedgerEntry, index: number): string {
  return String("seq" in e ? orNull(intOr(e["seq"])) : index);
}

/**
 * Each entry's hash RECOMPUTED from the bundle, by index, never read off the entry.
 *
 * `entry_hash` in a subject is checked against this. The walk mirrors `AuditLog.verify`, so an
 * entry whose stored `hash` was replaced does not get to supply the value it is compared against.
 * By index, not by seq: an entry's seq can be missing, another entry's, or not an integer.
 */
function recomputedHashes(entries: readonly LedgerEntry[]): (string | null)[] {
  const out: (string | null)[] = [];
  let prev = GENESIS;
  for (const e of entries) {
    const payload: LedgerEntry = {};
    for (const [k, v] of Object.entries(e)) if (k !== "hash") payload[k] = v;
    let computed: string | null;
    try {
      computed = hashEntry(prev, payload);
    } catch {
      // An unhashable payload has no recomputable hash; that IS the break, at this entry.
      computed = null;
    }
    out.push(computed);
    prev = computed ?? GENESIS;
  }
  return out;
}

/**
 * subject.seq -> the index of the entry an envelope naming that seq covers.
 *
 * An entry is keyed by its own seq when that is an integral number and not a boolean, as the
 * schema's integer type defines (`integral`: `1.0` is 1), and by its index when it has no seq
 * member at all. An entry whose seq is a boolean, a string, null, or a fractional number is keyed
 * by nothing, so no envelope covers it: in Python, keyed by the raw value, `"seq": true` took the
 * envelope written for seq 1, and here a null seq was keyed by its index. Where two entries share
 * a key the later one is covered, as it always was. The Python implementation's `_subject_index`.
 */
function subjectIndex(entries: readonly LedgerEntry[]): Map<number, number> {
  const keyed = new Map<number, number>();
  entries.forEach((e, i) => {
    if (!("seq" in e)) {
      keyed.set(i, i);
      return;
    }
    const seq = integral(e["seq"]);
    if (seq !== null) keyed.set(seq, i);
  });
  return keyed;
}

/**
 * Two `seq` or `v` values are the same: equal integers when either is integral (`integral`), so
 * `1.0` is 1; otherwise the same value of the same type, so `true` is not 1 and `"1"` is not 1. An
 * absent value is null, as Python's `dict.get` reads it. The Python implementation's
 * `_same_number`.
 */
function sameNumber(a: CJson | undefined, b: CJson | undefined): boolean {
  const ia = integral(a);
  const ib = integral(b);
  if (ia !== null || ib !== null) return ia === ib;
  const pa = orNull(a);
  const pb = orNull(b);
  return pyTypeOf(pa) === pyTypeOf(pb) && pyEquals(pa, pb);
}

/** The Python type of a parsed JSON value, which tells a boolean from a number as `type()` does. */
function pyTypeOf(value: Json): string {
  if (value === null) return "NoneType";
  if (Array.isArray(value)) return "list";
  if (typeof value === "number") return Number.isInteger(value) ? "int" : "float";
  return typeof value === "object" ? "dict" : typeof value;
}

/**
 * Python's `==` on two parsed JSON values: numbers and booleans by value (`True == 1`), strings by
 * text, lists and objects member by member.
 */
function pyEquals(a: Json, b: Json): boolean {
  const x: Json = typeof a === "boolean" ? Number(a) : a;
  const y: Json = typeof b === "boolean" ? Number(b) : b;
  if (typeof x !== "object" || typeof y !== "object" || x === null || y === null) return x === y;
  if (Array.isArray(x) || Array.isArray(y)) {
    return Array.isArray(x) && Array.isArray(y) && x.length === y.length && x.every((v, i) => pyEquals(v, y[i]!));
  }
  const keys = Object.keys(x);
  return (
    keys.length === Object.keys(y).length && keys.every((k) => Object.hasOwn(y, k) && pyEquals(x[k]!, y[k]!))
  );
}

/** Python's `{value!r}` of an integral-or-not `seq` or `v`: the integer when it is integral (`intOr`). */
function reprIntOr(value: CJson | undefined): string {
  return pyRepr((intOr(value) ?? null) as CJson);
}

/**
 * The distinct versions of `values`, as a Python set holds them: two that Python's `==` calls equal
 * are one (`True` and 1 included), and the first of them stays. A list or an object has no place
 * in a Python set (Python raises there), and each is kept on its own.
 */
function pySetOf(values: readonly CJson[]): CJson[] {
  const seen = new Set<string>();
  const out: CJson[] = [];
  for (const value of values) {
    const plain = toPlain(value);
    const key =
      plain === null
        ? "None"
        : typeof plain === "boolean" || typeof plain === "number"
          ? `n:${Number(plain) === 0 ? 0 : Number(plain)}`
          : typeof plain === "string"
            ? `s:${plain}`
            : null;
    if (key !== null) {
      if (seen.has(key)) continue;
      seen.add(key);
    }
    out.push(value);
  }
  return out;
}

/**
 * The order `mixed_entry_versions` lists versions in: numbers in numeric order, and anything else
 * after them by its Python `repr`, so a boolean beside a string still sorts. The Python
 * implementation's `_version_order`.
 */
function compareVersions(a: CJson, b: CJson): number {
  const numberOf = (v: CJson): number | null =>
    v instanceof RawNumber ? v.value : typeof v === "number" ? v : null;
  const na = numberOf(a);
  const nb = numberOf(b);
  if (na !== null && nb !== null) return na - nb;
  if (na !== null) return -1;
  if (nb !== null) return 1;
  return compareCodePoints(pyRepr(a), pyRepr(b));
}

/**
 * The v1 subject for the entry at `seq`, recomputed from the ledger.
 *
 * `seq` finds its entry the way a verifier finds it (`subjectIndex`), so the subject is the one the
 * verifier will check it against. Throws when `seq` names no entry, or names one whose `event` v1
 * defines no subject for.
 */
export function envelopeSubject(entries: readonly LedgerEntry[], seq: number): Record<string, CJson> {
  const n = integral(seq);
  const at = n === null ? undefined : subjectIndex(entries).get(n);
  if (n === null || at === undefined) throw new Error(`no entry at seq ${seq}`);
  const entry = entries[at]!;
  const event = toPlain(entry["event"]) as string;
  if (!ENVELOPE_SUBJECT_MEMBERS.has(event)) {
    throw new Error(`envelope v${ENVELOPE_VERSION} defines no subject for event '${event}'`);
  }
  const subject: Record<string, CJson> = {
    chain_id: orNull(entry["chain_id"]) as CJson,
    node: orNull(entry["node"]) as CJson,
    seq: n,
    entry_hash: recomputedHashes(entries)[at] ?? null,
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
 * The 32-byte Ed25519 public key for `kid`, or an `Error` naming it.
 *
 * A trust set is CALLER CONFIGURATION, not bundle content, so a malformed row is a mistake in the
 * deployment and failing loudly is the only way it does not become a silent downgrade: coercing a
 * number would fabricate zero bytes, and every envelope from that witness would then fail on its
 * SIGNATURE, reading as a witness who signed badly rather than as a trust set never configured.
 */
function witnessPublicKey(kid: string, value: unknown): Buffer {
  if (typeof value === "string") {
    if (value.length !== 64) {
      throw new Error(
        `witness key ${pyStrRepr(kid)}: public_key_hex must be 64 hex characters (a 32-byte Ed25519 key), ` +
          `got ${value.length}`,
      );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(value)) {
      throw new Error(`witness key ${pyStrRepr(kid)}: public_key_hex is not hexadecimal`);
    }
    return Buffer.from(value, "hex");
  }
  if (value instanceof Uint8Array) {
    if (value.length !== 32) {
      throw new Error(`witness key ${pyStrRepr(kid)}: an Ed25519 public key is 32 bytes, got ${value.length}`);
    }
    return Buffer.from(value);
  }
  throw new Error(`witness key ${pyStrRepr(kid)}: expected 64 hex characters or 32 bytes`);
}

/**
 * kid -> `[alg, raw public key]`, from the vector file's own `witness_keys` shape or from a plain
 * `{kid: publicKeyBytes}` record.
 *
 * `null`/absent means no trust anchor is configured, which is an EMPTY set, not an absent check:
 * an envelope naming a kid nobody trusts is `envelope_unknown_witness`, and that is the honest
 * answer whether the trust set is empty or merely does not contain it.
 *
 * Every row is validated here and a bad one throws, naming its kid. This is the one envelope
 * input that is NOT attacker-supplied — the deployment chose these keys — so a mistake in them is
 * reported to the caller rather than folded into a finding about the bundle. v1 defines Ed25519
 * and no other algorithm, so a row declaring anything else is refused too.
 */
function trustedWitnesses(
  witnessKeys: readonly WitnessKey[] | Record<string, Buffer | string> | null | undefined,
  now: Instant,
): TrustSet {
  const trusted = new Map<string, [string, Buffer]>();
  const expired = new Map<string, string>();
  const seen = new Set<string>();
  if (witnessKeys === null || witnessKeys === undefined) return { trusted, expired };
  const rows: [unknown, unknown][] = Array.isArray(witnessKeys)
    ? witnessKeys.map((k) => [isRecordLike(k) ? k["kid"] : undefined, k])
    : Object.entries(witnessKeys);
  for (const [kid, value] of rows) {
    if (typeof kid !== "string") throw new Error("witness key kid must be a string");
    // One row per kid. The later row used to win, so a row added to expire a key could leave it
    // trusted, and an expired row beside a live one did.
    if (seen.has(kid)) throw new Error(`witness key ${pyStrRepr(kid)}: more than one row names this kid`);
    seen.add(kid);
    let key: unknown = value;
    let notAfter: string | null = null;
    let until: Instant | null = null;
    if (isRecordLike(value)) {
      // Read whole: a row read by projection let a misspelled `notAfter` leave a key that never
      // expired. In the `{kid: row}` form a row may repeat its kid, and must agree with it.
      const unknown = Object.keys(value)
        .filter((m) => !TRUST_ROW_MEMBERS.has(m))
        .sort(compareCodePoints);
      if (unknown.length > 0) {
        throw new Error(
          `witness key ${pyStrRepr(kid)}: the row carries members this build does not evaluate ` +
            `and will not ignore: ${unknown.map(pyStrRepr).join(", ")}`,
        );
      }
      if ("kid" in value && value["kid"] !== kid) {
        throw new Error(
          `witness key ${pyStrRepr(kid)}: its row names a different kid, ${pyRepr(value["kid"] as Json)}`,
        );
      }
      const alg = value["alg"];
      if (alg !== ENVELOPE_ALG) {
        throw new Error(`witness key ${pyStrRepr(kid)}: alg must be '${ENVELOPE_ALG}', got ${pyRepr(alg as Json)}`);
      }
      // Present means checked: `null` is not "no expiry", it is a row that says nothing usable.
      if (value["not_after"] !== undefined) {
        until = rfc3339Utc(value["not_after"]);
        if (until === null) {
          throw new Error(
            `witness key ${pyStrRepr(kid)}: not_after must be an RFC 3339 UTC date-time such as ` +
              `'2026-10-05T00:00:00Z', got ${pyRepr(value["not_after"] as Json)}`,
          );
        }
        notAfter = value["not_after"] as string;
      }
      key = value["public_key_hex"];
    }
    const publicKey = witnessPublicKey(kid, key);
    if (until !== null && atOrBefore(until, now)) {
      // Validated in full, then left out. An expired row neither adds its kid nor removes one
      // that another row trusts; it is remembered so the failure can say the key expired, and
      // when, instead of reading as a key nobody ever configured.
      expired.set(kid, notAfter!);
      continue;
    }
    trusted.set(kid, [ENVELOPE_ALG, publicKey]);
  }
  return { trusted, expired };
}

/**
 * Every row of a trust set checked as the verifier checks it — kid, alg, public key, `not_after` —
 * and an `Error` naming the kid for the first bad one. The CLI runs this when it loads a
 * `--witness-keys` file, so a bad row is reported against that file before any bundle is read.
 * Expiry is not an error: an expired row is a row the verifier leaves out, not a malformed one.
 */
export function validateWitnessKeys(witnessKeys: readonly WitnessKey[]): void {
  trustedWitnesses(witnessKeys, verificationTime(null));
}

/** A trust-set row's members. A row is read whole: anything else in it is refused. */
const TRUST_ROW_MEMBERS: ReadonlySet<string> = new Set(["kid", "alg", "public_key_hex", "not_after"]);

/**
 * The trust set at the verification time: the rows still valid, and the kids whose rows had
 * expired by then.
 */
interface TrustSet {
  /** kid -> `[alg, raw public key]`, for every row still valid at the verification time. */
  trusted: Map<string, [string, Buffer]>;
  /**
   * kid -> the `not_after` of an expired row naming it, exactly as the row wrote it. When several
   * rows for one kid have expired, the last one is named.
   */
  expired: Map<string, string>;
}

/**
 * RFC 3339 `date-time` in UTC: `YYYY-MM-DDTHH:MM:SS`, an optional fraction, and `Z`. RFC 3339
 * allows `t` and `z` in lower case, so they are accepted too. A numeric offset, even `+00:00`, is
 * not: a trust-set row says UTC in the one spelling that cannot be misread as local time. ASCII
 * digits only. The Python implementation accepts exactly this grammar, so a row one of them
 * refuses, both refuse.
 */
const RFC3339_UTC = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?[Zz]$/;

/**
 * A point in time: whole seconds since the epoch, and the fraction's digits, at most six. The
 * fraction is kept to the microsecond and the digits past it are dropped, as Python's `datetime`
 * keeps it, so both implementations compare the same two instants.
 */
interface Instant {
  seconds: number;
  fraction: string;
}

/**
 * `value` as an instant, or `null` when it is not an RFC 3339 UTC date-time. An out-of-range field
 * (month 13, February 30, hour 24, second 60) is `null`: there is no leap second here, as there is
 * none in Python's `datetime`.
 */
function rfc3339Utc(value: unknown): Instant | null {
  const m = typeof value === "string" ? RFC3339_UTC.exec(value) : null;
  if (m !== null) {
    const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [
      number,
      number,
      number,
      number,
      number,
      number,
    ];
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
    if (year >= 1 && days !== undefined && day >= 1 && day <= days && hour <= 23 && minute <= 59 && second <= 59) {
      // `Date.UTC` reads a year below 100 as 19xx; `setUTCFullYear` does not.
      const at = new Date(0);
      at.setUTCFullYear(year, month - 1, day);
      at.setUTCHours(hour, minute, second, 0);
      return { seconds: at.getTime() / 1000, fraction: (m[7] ?? "").slice(0, 6) };
    }
  }
  return null;
}

/**
 * The verification time: `now` when given — a `Date`, or a string in the `not_after` grammar — and
 * the current time otherwise.
 *
 * A number is refused, never read. The Python implementation takes epoch seconds there; a
 * JavaScript epoch counts milliseconds, and a number read in the wrong unit moves the verification
 * time a thousandfold, so this side takes no number at all rather than guess which one it got.
 */
function verificationTime(now: Date | string | null | undefined): Instant {
  if (now === null || now === undefined) return dateInstant(new Date());
  if (now instanceof Date && !Number.isNaN(now.getTime())) return dateInstant(now);
  if (typeof now === "number") {
    throw new Error(
      "now must be a Date or an RFC 3339 UTC date-time such as '2026-10-05T00:00:00Z', not a " +
        "number: a JavaScript epoch counts milliseconds and a Python one seconds",
    );
  }
  const parsed = typeof now === "string" ? rfc3339Utc(now) : null;
  if (parsed === null) {
    throw new Error(
      "now must be a valid Date or an RFC 3339 UTC date-time such as '2026-10-05T00:00:00Z'; got " +
        (now instanceof Date ? "an invalid Date" : pyRepr(now as never)),
    );
  }
  return parsed;
}

function dateInstant(at: Date): Instant {
  const ms = at.getTime();
  const seconds = Math.floor(ms / 1000);
  return { seconds, fraction: String(ms - seconds * 1000).padStart(3, "0") };
}



/** `a` is at or before `b`: whole seconds first, then the fraction digits, padded to one length. */
function atOrBefore(a: Instant, b: Instant): boolean {
  if (a.seconds !== b.seconds) return a.seconds < b.seconds;
  const width = Math.max(a.fraction.length, b.fraction.length);
  return a.fraction.padEnd(width, "0") <= b.fraction.padEnd(width, "0");
}

/**
 * Python's truthiness for a parsed JSON value, read where the Python implementation writes
 * `value or default`: absent, null, false, a zero, "", [] and {} are false.
 */
function pyFalsy(value: Json | undefined): boolean {
  if (value === undefined || value === null || value === false || value === 0 || value === "") return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

/** A plain object (not an array, not null, not a Buffer). */
function isRecordLike(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Uint8Array);
}

/**
 * One `envelopeBytes` element as bytes, or null when it is not bytes at all.
 *
 * Coercing a number would fabricate that many ZERO bytes, turning a caller's mistake into a
 * canonicality finding about the bundle; hex that does not parse is the same mistake in a
 * different shape. Neither is coerced.
 */
function receivedBytes(raw: unknown): Buffer | null {
  if (typeof raw === "string") {
    if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(raw)) return null;
    return Buffer.from(raw, "hex");
  }
  if (raw instanceof Uint8Array) return Buffer.from(raw);
  return null;
}

// A subject `seq` this build looks an entry up by, and an envelope's `v`, must be an integral
// number and never a boolean (`integral`, canonical.ts), as the schema's integer type defines:
// Python's `_is_seq`. `1.0` is 1, and RFC 8785 writes it as 1, so an envelope signed over one
// verifies as if signed over the other. The type check comes first and every use is behind it — in
// Python an unguarded lookup raises on a list or an object and finds the entry at seq 1 for
// `true`, and the two implementations report the same failure for the same bundle. The entries are
// keyed by the same rule (`subjectIndex`), so an entry whose own seq is `true` or `1.5` is covered
// by no envelope.

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
  /**
   * The index in `bundle.entries` of every witness-signed entry -> the `witness.kid` of the
   * envelope that verified for it. By index, not by seq: the index is the entry the subject
   * resolved to, the one `failure_entries` names, so of two entries sharing a seq only the one the
   * witness signed is in it. An entry two envelopes dispute is not.
   */
  witnesses: Record<string, string>;
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
  /**
   * The verification time a trust-set row's `not_after` is compared with: a `Date`, or a string in
   * the `not_after` grammar; never a number, whose unit would be a guess. The current time when
   * absent. A row whose `not_after` is at or before it is left out of the trust set.
   */
  now?: Date | string | null;
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
  trust: TrustSet,
  rawBytes: readonly (Buffer | string | null)[] | null,
): [EnvelopeSummary, FailureLog] {
  const fail = new FailureLog();
  const states: Record<string, EnvelopeState> = {};
  const results: Record<string, Json> = {};
  const witnesses: Record<string, string> = {};
  entries.forEach((e, i) => {
    setOwn(states, stateKey(e, i), PROCESS_ASSERTED);
  });

  // The hash walk is what an envelope's binding member is checked against; a bundle carrying
  // none does not pay for it. Every entry is process-asserted in that case, which is the status
  // quo and exactly what this reports.
  const subjectAt = envelopes.length > 0 ? subjectIndex(entries) : new Map<number, number>();
  const recomputed = envelopes.length > 0 ? recomputedHashes(entries) : [];

  // entry index -> how many envelopes in this array named it, valid or not. `scoreEnvelope` counts
  // an envelope in as soon as its subject names an entry this bundle has.
  const claims = new Map<number, number>();

  envelopes.forEach((envelope, index) => {
    const raw = rawBytes !== null && index < rawBytes.length ? rawBytes[index] ?? null : null;
    const covered = scoreEnvelope(envelope, index, entries, subjectAt, recomputed, trust, raw, fail, claims);
    if (covered === null) return;
    // Where `states` files that entry; `witnesses` files it by the index the subject resolved to.
    const key = stateKey(entries[covered.at]!, covered.at);
    setOwn(states, key, WITNESS_SIGNED);
    setOwn(results, key, covered.result);
    setOwn(witnesses, String(covered.at), covered.kid);
  });

  // The first envelope's result stands in `results` — it is what that witness said, and the
  // duplicate does not erase it — but the STATE falls back, so a contradicted entry never
  // reports witness-signed and the bundle rejects; and it leaves `witnesses`.
  for (const [at, count] of claims) {
    if (count > 1) {
      setOwn(states, stateKey(entries[at]!, at), PROCESS_ASSERTED);
      delete witnesses[String(at)];
    }
  }

  const lines: Record<string, string> = {};
  for (const [seq, state] of Object.entries(states)) {
    setOwn(lines, seq, envelopeLine(state, Object.hasOwn(results, seq) ? results[seq]! : null));
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
    witnesses,
    lines,
    failures: [...fail.messages],
  };
  return [summary, fail];
}

/**
 * `record[key] = value` as an own property, whatever the key. A key is an entry's seq rendered as
 * text, and a bundle chooses its seqs: a plain assignment of `"__proto__"` would reach the
 * prototype setter and record nothing.
 */
function setOwn<T>(record: Record<string, T>, key: string, value: T): void {
  Object.defineProperty(record, key, { value, enumerable: true, configurable: true, writable: true });
}

/** Python `repr` for a member set, so both implementations print the same failure strings. */
function reprList(values: readonly string[]): string {
  return `[${values.map(pyStrRepr).join(", ")}]`;
}

/**
 * One envelope, checked in the order the seven named failures are defined in.
 *
 * Returns the index in `entries` of the entry an envelope that verified covers, and `null` for one
 * that did not. Every failure is positioned on the entry the envelope COVERS, found by
 * `subject.seq` through `subjectIndex` — the locators are checked against that entry, not used to
 * find it.
 *
 * `claims` is the caller's entry index -> count of the envelopes that have named it so far, and
 * this function updates it. An envelope claims its entry as soon as `subject.seq` finds one,
 * BEFORE the rest of the subject is checked, so a second envelope over an entry an earlier one
 * already named is `envelope_duplicate_subject` whether either of them is otherwise sound: the
 * point of the check is that no one can decide what an earlier witness said by appending after
 * it.
 */
function scoreEnvelope(
  envelope: Envelope,
  index: number,
  entries: readonly LedgerEntry[],
  subjectAt: ReadonlyMap<number, number>,
  recomputed: readonly (string | null)[],
  trust: TrustSet,
  raw: Buffer | string | null,
  fail: FailureLog,
  claims: Map<number, number>,
): { at: number; node: Json; result: Json; kid: string } | null {
  const isRecord = (v: unknown): v is Record<string, CJson> =>
    v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof RawNumber);

  const subject: unknown = isRecord(envelope) ? envelope["subject"] : undefined;

  function position(): [Json, Json, LedgerEntry | null] {
    // Every failure is positioned by `subject.seq`, and `subject` is attacker-supplied, so the
    // lookup is guarded: a seq that is not an integer positions nothing, which is honest — it
    // names no entry — and it is never used as a key.
    const s = isRecord(subject) ? integral(subject["seq"]) : null;
    if (s === null) return [null, null, null];
    const at = subjectAt.get(s);
    if (at === undefined) return [s, null, null];
    const entry = entries[at]!;
    return [orNull(entry["seq"]), orNull(entry["node"]), entry];
  }

  function report(reason: string, detail: string): null {
    const [seq, node, entry] = position();
    fail.add(reason, `${reason}: ${detail}`, { seq, node, entry });
    return null;
  }

  if (!isRecord(envelope)) {
    fail.add("envelope_unknown_version", `envelope_unknown_version: envelope #${index} is not a JSON object`);
    return null;
  }

  // (1) version — a `v` or `typ` this build does not know is a DIFFERENT CONTRACT, and nothing
  // further about it can be read safely.
  // The version is read by the seq rule (`integral`): `1.0` is 1, and `true` is not.
  const typ = toPlain(envelope["typ"] as CJson) as Json;
  if (integral(envelope["v"] as CJson) !== ENVELOPE_VERSION || typ !== ENVELOPE_TYP) {
    return report(
      "envelope_unknown_version",
      `envelope v=${reprIntOr(envelope["v"] as CJson)} typ=${pyRepr((envelope["typ"] ?? null) as CJson)}, ` +
        `this build knows v=${ENVELOPE_VERSION} typ='${ENVELOPE_TYP}'`,
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
      // "not an object" rather than the type's name: the two languages spell their type names
      // differently and both implementations report the same failure strings for the same bundle.
      const got = members === null ? "not an object" : reprList(members);
      return report(
        "envelope_unknown_member",
        `${label} member set is ${got}, expected ${reprList(sortedStrings(expected))}`,
      );
    }
  }

  // (3) subject — the event decides the member set; a member ADDED to it is unknown_member, one
  // MISSING is subject_mismatch (a subject that does not say what it covers).
  if (!isRecord(subject)) {
    // No type name, for the same reason as the member-set message above: the two languages spell
    // their type names differently and report the same strings for the same bundle.
    return report("envelope_subject_mismatch", "subject is not a JSON object");
  }
  const event = toPlain(subject["event"]) as Json;
  if (typeof event !== "string") {
    // `event` selects the subject member set, so it is a lookup key as well; in Python an
    // unhashable one raises. Found by the hostile-value suite, not by review.
    return report("envelope_subject_mismatch", "subject event is not a string");
  }
  const expectedMembers = ENVELOPE_SUBJECT_MEMBERS.get(event);
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
  // the entry it finds supplies the hash the subject is checked against. It is also the one
  // subject member used as a KEY, so its type is checked before it is used as one.
  const subjectSeq = integral(subject["seq"]);
  if (subjectSeq === null) {
    return report("envelope_subject_mismatch", "subject seq is not an integer");
  }
  const at = subjectAt.get(subjectSeq);
  if (at === undefined) {
    return report("envelope_subject_mismatch", `no entry at seq ${reprIntOr(subject["seq"])} in this bundle`);
  }
  const entry = entries[at]!;
  // The messages below print an integral seq as its integer, and an entry without one as None.
  const seq = (intOr(entry["seq"]) ?? null) as CJson;

  // (3a') one entry, at most one envelope. Counted here, before anything else about this
  // envelope is judged, so the rule cannot be sidestepped by making the second envelope
  // defective in some other way as well.
  const already = claims.get(at) ?? 0;
  claims.set(at, already + 1);
  if (already > 0) {
    return report(
      "envelope_duplicate_subject",
      `seq ${pyStr(seq)} is already covered by an earlier envelope in this bundle; two ` +
        "observations of one event contradict each other by construction, so this entry is not " +
        "witness-signed",
    );
  }

  const computed = recomputed[at] ?? null;
  const claimed = toPlain(subject["entry_hash"]) as Json;
  if (claimed !== computed) {
    return report(
      "envelope_subject_mismatch",
      `subject entry_hash ${pyRepr(claimed)} != the hash recomputed for seq ${pyStr(seq)} from ` +
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
        `subject ${member}=${pyRepr(stated)} != ${pyRepr(actual)} on the entry at seq ${pyStr(seq)}`,
      );
    }
  }

  // (4) canonicality — an invariant SEPARATE from the signature: the received bytes must equal
  // JCS of what they parse to. It can only be raised where the bytes as received are supplied,
  // because formatting and escaping do not survive a parse.
  let nonCanonical = false;
  if (raw !== null) {
    const received = receivedBytes(raw);
    if (received === null) {
      return report("envelope_non_canonical", "envelope_bytes entry is not hex or bytes");
    }
    let recanonicalized: Buffer;
    try {
      recanonicalized = canonicalBytes(envelope as unknown as CJson);
    } catch (err) {
      // A value JCS cannot represent at all — a non-finite number, an integer outside the
      // binary64 safe range, a lone surrogate. There is no canonical form to compare the
      // received bytes with and none to verify a signature over, so this is the end of it.
      return report("envelope_non_canonical", `the envelope cannot be canonicalized: ${String(err)}`);
    }
    if (!recanonicalized.equals(received)) {
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
  if (typeof kid !== "string") {
    // `kid` names a key, so it is a lookup key here too, and in Python an unhashable one raises.
    return report("envelope_unknown_witness", "witness kid is not a string");
  }
  if (alg !== ENVELOPE_ALG) {
    // v1 defines Ed25519 and nothing else. Without this, `"alg": "none"` on both sides — in the
    // envelope and in a trust-set row — agreed with each other and read as witness-signed.
    return report(
      "envelope_unknown_witness",
      `witness alg=${pyRepr(alg)} is not '${ENVELOPE_ALG}'; envelope v${ENVELOPE_VERSION} ` +
        "defines Ed25519 and no other algorithm",
    );
  }
  const known = trust.trusted.get(kid);
  if (known === undefined) {
    // A kid whose rows have all expired is not in the trust set, so it is the same failure as any
    // other untrusted kid. The message keeps that wording first and then says why, because "not
    // trusted" and "trusted until a date that has passed" call for different fixes.
    const lapsed = trust.expired.get(kid);
    return report(
      "envelope_unknown_witness",
      `witness kid=${pyRepr(kid)} alg=${pyRepr(alg)} is not in the trusted witness keys ` +
        `(${reprList(sortedStrings(trust.trusted.keys()))})` +
        (lapsed === undefined ? "" : `: the key expired at not_after=${pyRepr(lapsed)}`),
    );
  }

  // (6) the signature, over JCS(envelope minus "sig").
  const sigHex = toPlain(envelope["sig"]) as Json;
  if (typeof sigHex !== "string") {
    // A `sig` that is not a string is not a signature. In Python it reached `bytes.fromhex` and
    // raised a TypeError the surrounding `except ValueError` does not catch.
    return report("envelope_bad_signature", "sig is not a hex string");
  }
  const signature = /^[0-9a-fA-F]*$/.test(sigHex) && sigHex.length % 2 === 0
    ? Buffer.from(sigHex, "hex")
    : Buffer.alloc(0);
  let signingInput: Buffer;
  try {
    signingInput = envelopeSigningInput(envelope);
  } catch (err) {
    // Reached only when no `envelopeBytes` were supplied, so step (4) did not run: the envelope
    // holds a value JCS cannot represent and there is nothing to verify OVER.
    return report("envelope_non_canonical", `the envelope cannot be canonicalized: ${String(err)}`);
  }
  let verified = false;
  try {
    verified = new Ed25519Verifier(known[1], kid).verify(signingInput, signature);
  } catch {
    verified = false;
  }
  if (!verified) {
    return report("envelope_bad_signature", `the signature does not verify under the key kid=${pyRepr(kid)} names`);
  }
  if (nonCanonical) return null;
  return { at, node: orNull(entry["node"]), result: toPlain(envelope["observed"]["result"]) as Json, kid };
}

/**
 * Score a bundle's observer envelopes on their own, without the ledger checks.
 *
 * Returns `{ok, ...summary, failure_details, failure_entries}`. `states` maps every entry's seq to
 * `witness-signed` or `process-asserted`; `lines` is the report line for each. `results` maps a
 * covered seq to the verifying envelope's `observed.result`. `witnesses` maps the index in
 * `bundle.entries` of every witness-signed entry to that envelope's `witness.kid`: the entry the
 * subject resolved to, the one `failure_entries` names, so of two entries sharing a seq only the
 * one the witness signed is in it.
 */
export function verifyEnvelopes(
  bundle: Partial<Bundle>,
  options: VerifyEnvelopesOptions = {},
): EnvelopeSummary & { ok: boolean; failure_details: FailureDetail[]; failure_entries: (number | null)[] } {
  const entries = bundle.entries ?? [];
  const [summary, fail] = scoreEnvelopes(
    entries,
    bundle.envelopes ?? [],
    trustedWitnesses(options.witnessKeys ?? null, verificationTime(options.now)),
    options.envelopeBytes ?? null,
  );
  return { ok: fail.length === 0, ...summary, failure_details: fail.details, failure_entries: fail.entryIndices(entries) };
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
      return `adapter[${pyStrRepr(k)}] must be a non-empty string`;
    }
  }
  if (presentButNull(e, "policy")) {
    return "policy is explicitly null (omit it, or give a valid Policy value)";
  }
  if ("policy" in e && !isKnownPolicy(toPlain(e["policy"]))) {
    return `policy ${pyRepr(toPlain(e["policy"]) as Json)} not a known value`;
  }
  err = validHashField(e, "authorized_params_hash");
  if (err) return err;
  return validParamsHashReason(e, "authorized_params_hash");
}

/** Fields that only ever belong on an `allow` entry — illegal on a `deny`, on any schema version. */
const ALLOW_ONLY_FIELDS = [
  "capture",
  "adapter",
  "authorized_params_hash",
  "params_hash_reason",
  "policy",
] as const;

function validateDeny(e: LedgerEntry): string | null {
  const err = validCallId(e);
  if (err) return err;
  const leaked = ALLOW_ONLY_FIELDS.filter((f) => f in e).sort();
  if (leaked.length > 0) {
    return `deny carries allow-only field(s) ${reprList(leaked)}`;
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
        return `receipt[${pyStrRepr(k)}] must be a non-empty string`;
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
/**
 * A `policy` the format defines. Type-checked first: a bundle is untrusted input and can carry
 * any JSON value there (`0`, `""`, `[]`, `{}`), and a bare truthiness or membership test on a
 * non-string is how a made-up marker buys an exemption it was never entitled to.
 */
function isKnownPolicy(value: unknown): boolean {
  return typeof value === "string" && POLICIES.has(value);
}

/**
 * `policy` is checked on EVERY bundle version, because it is what excuses an entry from
 * containment.
 *
 * An `allow` carrying `policy` is not tested for containment: it says the chain never authorized
 * the call, so there is nothing to contain. That exemption is only sound if the value naming it
 * is one the format actually defines. It was validated in `validateAllow`, which runs inside
 * `executionBinding` — and that returns early on a `schemaVersion: 1` bundle. So on a v1 chain
 * ANY non-null value bought the exemption: `"anything"`, `0`, `""`. An out-of-authority action
 * stamped with a made-up policy verified clean and reported `containment: true`, which is the one
 * thing this bundle exists to say honestly.
 *
 * Two rules, both version-independent:
 *
 *   - `policy` may appear ONLY on an `allow`. It answers "how did this allow come to be"; on a
 *     `spawn`, `root` or `outcome` it means nothing and was accepted silently (only `deny` was
 *     checked, by `validateDeny`'s allow-only-field rule).
 *   - its value must be one `reasons.Policy` defines (`unlisted` is the only one in v1).
 *
 * On a v2 bundle `validateAllow`/`validateDeny` already report these two entry shapes and their
 * strings are the published contract, so this check stands down for exactly those cases and
 * covers what they do not reach. No message is ever emitted twice.
 */
function policyFailures(entries: readonly LedgerEntry[], bundleV: Json): FailureLog {
  const failures = new FailureLog();
  for (const e of entries) {
    if (!("policy" in e)) continue;
    const ev = toPlain(e["event"]);
    const position = { seq: orNull(e["seq"]), node: orNull(e["node"]), entry: e };
    if (ev === "allow") {
      if (bundleV === 2) continue; // validateAllow owns this entry's message
      if (!isKnownPolicy(toPlain(e["policy"]))) {
        failures.add(
          "invalid_policy",
          `invalid_policy: seq=${shown(intOr(e["seq"]))} allow carries policy ` +
            `${pyRepr(e["policy"] ?? null)}, not a value this format defines`,
          position,
        );
      }
    } else {
      if (ev === "deny" && bundleV === 2) continue; // validateDeny owns this entry's message
      failures.add(
        "policy_on_non_allow",
        `policy_on_non_allow: seq=${shown(intOr(e["seq"]))} event=${pyRepr(e["event"] ?? null)} ` +
          "carries `policy`, which is an allow-only field",
        position,
      );
    }
  }
  return failures;
}

function v2FieldLeaksOnV1(entries: readonly LedgerEntry[]): FailureLog {
  const failures = new FailureLog();
  for (const e of entries) {
    const leaked = V2_ONLY_FIELDS.filter((f) => f in e).sort();
    if (leaked.length > 0) {
      failures.add(
        "v2_field_on_v1",
        `v2_field_on_v1: seq=${shown(intOr(e["seq"]))} event=${pyRepr(e["event"] ?? null)} ` +
          `carries v2-only field(s) ${reprList(leaked)} on a schema_version=1 entry`,
        { seq: orNull(e["seq"]), node: orNull(e["node"]), entry: e },
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
  // callId -> [event, node, the entry's own seq value as the bundle wrote it]
  const seenCallIds = new Map<string, [string, string | null, CJson]>();
  const allows = new Map<string, LedgerEntry>();
  const outcomes = new Map<string, LedgerEntry>();
  const invalidAllowIds = new Set<string>();
  const nodes = new Set<string>();
  const finalizedNodes = new Set<string>();
  const revokedNodes = new Set<string>();

  for (const e of entries) {
    const ev = toPlain(e["event"]);
    const raw = toPlain(e["node"]) as Json | undefined;
    // A node id is a string; anything else names no node, here as in the Python implementation.
    const node = typeof raw === "string" ? raw : null;
    if (ev === "root") {
      if (node !== null) nodes.add(node);
      const err = validateRoot(e);
      if (err) {
        failures.add("invalid_root", `invalid_root: ${err} (seq ${shown(intOr(e["seq"]))})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
          entry: e,
        });
      }
    } else if (ev === "spawn") {
      if (node !== null) nodes.add(node);
    } else if (ev === "done") {
      if (node !== null) finalizedNodes.add(node);
    } else if (ev === "kill") {
      const killed = new Map<string, CJson | undefined>();
      noteRevoked(e, killed);
      for (const r of killed.keys()) revokedNodes.add(r);
      const err = validateKill(e);
      if (err) {
        failures.add("invalid_kill", `invalid_kill: ${err} (seq ${shown(intOr(e["seq"]))})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
          entry: e,
        });
      }
    }

    if (ev === "allow" || ev === "deny") {
      const cid = toPlain(e["call_id"]) as string | null;
      if (cid !== null && cid !== undefined) {
        const prior = seenCallIds.get(cid);
        if (prior !== undefined) {
          // Positioned on the SECOND sighting: the entry that re-used a call_id is the offending
          // record, the first one having been legitimate when it was written.
          failures.add(
            "duplicate_call_id",
            `duplicate_call_id: call_id ${shown(e["call_id"])} on seq ${shown(intOr(e["seq"]))} (${ev}) already used at seq ` +
              `${shown(intOr(prior[2]))} (${prior[0]})`,
            { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: cid, entry: e },
          );
        } else {
          seenCallIds.set(cid, [ev, node, e["seq"] ?? null]);
        }
      }
      const err = ev === "allow" ? validateAllow(e) : validateDeny(e);
      if (err) {
        failures.add(`invalid_${ev}`, `invalid_${ev}: ${err} (seq ${shown(intOr(e["seq"]))})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
          callId: cid ?? null,
          entry: e,
        });
        if (ev === "allow" && cid !== null && cid !== undefined) invalidAllowIds.add(cid);
        continue;
      }
      if (ev === "allow" && cid !== null && cid !== undefined) allows.set(cid, e);
    } else if (ev === "outcome") {
      const cid = toPlain(e["call_id"]) as string | null;
      const err = validateOutcome(e);
      if (err) {
        failures.add("invalid_outcome", `invalid_outcome: ${err} (seq ${shown(intOr(e["seq"]))})`, {
          seq: orNull(e["seq"]),
          node: orNull(e["node"]),
          callId: cid ?? null,
          entry: e,
        });
        continue;
      }
      if (cid !== null && outcomes.has(cid)) {
        failures.add(
          "duplicate_outcome",
          `duplicate_outcome: call_id ${shown(e["call_id"])} at seq ${shown(intOr(e["seq"]))} (first at seq ` +
            `${shown(intOr(outcomes.get(cid)!["seq"]))})`,
          { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: cid, entry: e },
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
        `outcome_without_allow: call_id ${shown(oc["call_id"])} at seq ${shown(intOr(oc["seq"]))} has no allow in this chain`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid, entry: oc },
      );
      continue;
    }
    const nodeOk = toPlain(allowE["node"]) === toPlain(oc["node"]);
    if (!nodeOk) {
      failures.add(
        "cross_ref",
        `cross_ref: call_id ${shown(oc["call_id"])} allow on node ${pyRepr(allowE["node"] ?? null)} but ` +
          `outcome on node ${pyRepr(oc["node"] ?? null)}`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid, entry: oc },
      );
    }
    const ocSeq = toPlain(oc["seq"]);
    const allowSeq = toPlain(allowE["seq"]);
    const orderOk = typeof ocSeq === "number" && typeof allowSeq === "number" && ocSeq > allowSeq;
    if (!orderOk) {
      failures.add(
        "outcome_before_allow",
        `outcome_before_allow: call_id ${shown(oc["call_id"])} outcome seq ${shown(intOr(oc["seq"]))} not ` +
          `after allow seq ${shown(intOr(allowE["seq"]))}`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid, entry: oc },
      );
    }
    const ah = toPlain(allowE["authorized_params_hash"]);
    const ih = toPlain(oc["invoked_params_hash"]);
    if (ah !== null && ah !== undefined && ih !== null && ih !== undefined && ah !== ih) {
      failures.add(
        "params_mismatch",
        `params_mismatch: call_id ${shown(oc["call_id"])} authorized_params_hash ` +
          `${shown(allowE["authorized_params_hash"])} != invoked_params_hash ${shown(oc["invoked_params_hash"])}`,
        { seq: orNull(oc["seq"]), node: orNull(oc["node"]), callId: cid, entry: oc },
      );
    }
    if (nodeOk && orderOk) boundOk.add(cid);
  }

  // Per-call observation + per-node pending, from valid allows only.
  const perCall: Record<string, "observed" | "unobserved" | "unaccounted"> = {};
  const nodePending = new Map<string | null, string[]>();
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
      const raw = toPlain(allowE["node"]) as Json | undefined;
      const node = typeof raw === "string" ? raw : null;
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
 * The index of the FIRST entry the hash chain does not reproduce at — position only.
 *
 * `AuditLog.verify` stays the authority on WHETHER the chain is broken and on the message this
 * module reports; this walk exists so the structured twin of that message can say WHERE, which
 * the message's own text does not expose in a parseable form. Mirrors `AuditLog.verify`'s walk
 * exactly (same seq/prev_hash/hash order, and the same rule that a seq is an integral number and
 * never a boolean, `integral`). `null` when nothing entry-local is wrong — a consistently
 * re-hashed ledger fails against the signed anchor, not here, and that failure is chain-level.
 */
export function integrityBreak(entries: readonly LedgerEntry[]): number | null {
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
        integral(e["seq"]) !== i ||
        orNull(payload["prev_hash"]) !== prev ||
        hashEntry(prev as string, payload) !== orNull(e["hash"]);
    } catch {
      // An unhashable payload is itself the break, at this entry.
      return i;
    }
    if (broken) return i;
    prev = orNull(e["hash"]);
  }
  return null;
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
  /**
   * In step with `failures` and `failure_details` again: the index in `bundle.entries` of the entry
   * each failure is about, or `null` for a failure about no single entry. Exact where a seq is
   * not, since a forged entry's seq can be missing, null, a boolean or a duplicate; it is what
   * `attenu-guard verify --entries` attributes by.
   */
  failure_entries: (number | null)[];
  nodes: number;
  actions_checked: number;
  /**
   * Allow entries carrying `policy` (reasons.Policy): the call happened but the chain never
   * authorized it, so it is NOT containment-checked and NOT counted in `actions_checked`. The
   * count is reported so a reader can see how much of the run was actually measured.
   */
  ungated: number;
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
  /**
   * The verification time a trust-set row's `not_after` is compared with: a `Date`, or a string in
   * the `not_after` grammar; never a number, whose unit would be a guess. The current time when
   * absent. A row whose `not_after` is at or before it is left out of the trust set, so an envelope
   * naming that kid fails `envelope_unknown_witness`.
   */
  now?: Date | string | null;
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
    ledger_fields: false,
    chain_id: false,
    root: false,
    expected_anchor: "not checked",
    envelopes: "not present",
  };
  const log = new FailureLog();

  // (0) version: the bundle must declare a schema version this build understands, and — when
  // an anchor is present — the anchor must be anchoring THAT version, not a different one. A
  // version is read by the seq rule (`integral`): `2.0` is 2, and `true` is not.
  const rawV = bundle.v as CJson | undefined;
  const bundleV = integral(rawV);
  let versionOk = bundleV !== null && SUPPORTED_BUNDLE_VERSIONS.has(bundleV);
  if (!versionOk) {
    const supported = Array.from(SUPPORTED_BUNDLE_VERSIONS).sort((a, b) => a - b);
    log.add("unsupported_version", `unsupported_version: bundle v=${reprIntOr(rawV)} not in [${supported.join(", ")}]`);
  }
  if (anchorPresent && !sameNumber(anchor["v"], rawV)) {
    versionOk = false;
    log.add(
      "anchor_version_mismatch",
      `anchor_version_mismatch: anchor v=${reprIntOr(anchor["v"])} != bundle v=${reprIntOr(rawV)}`,
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
  if (rootEntry !== undefined && !sameNumber(rootEntry["v"], rawV)) {
    versionOk = false;
    log.add(
      "root_version_mismatch",
      `root_version_mismatch: root v=${reprIntOr(rootEntry["v"])} != bundle v=${reprIntOr(rawV)}`,
      { seq: orNull(rootEntry["seq"]), node: orNull(rootEntry["node"]), entry: rootEntry },
    );
  }
  const mixedEntries = entries.filter((e) => !sameNumber(e["v"], rawV));
  // An entry without `v` is Python's None in the list. Numbers come first in numeric order, then
  // everything else by its repr, compared by code point as Python compares strings, never by locale.
  const mixed = pySetOf(mixedEntries.map((e) => (intOr(e["v"]) ?? null) as CJson)).sort(compareVersions);
  if (mixed.length > 0) {
    versionOk = false;
    // One aggregate message over every offending entry (unchanged); the twin is positioned on
    // the first of them, which is where a reader looks.
    log.add(
      "mixed_entry_versions",
      `mixed_entry_versions: entries declare v in [${mixed.map((v) => pyRepr(v)).join(", ")}], bundle v=${reprIntOr(rawV)}`,
      { seq: orNull(mixedEntries[0]!["seq"]), node: orNull(mixedEntries[0]!["node"]), entry: mixedEntries[0]! },
    );
  }
  checks.version = versionOk;

  // (0b2) every entry must be read WHOLE. `LEDGER_FIELDS` was enforced only on the EXPORT path
  // (`redactionReport`, via `exportBundle({strict: true})`), never on verify, so the verifier read
  // entries by projection: it picked the fields it knows and never looked at the rest. A producer
  // could add `deny_scopes` and `critical` to a `spawn` entry, rehash the chain from genesis as any
  // honest producer does, and `verifyBundle` returned ok=true with zero failures while those fields
  // stayed invisible in `delegationGraph`.
  //
  // That is the same defect as the token-side one this release fixes -- reporting success on input
  // we did not fully read -- but on the offline-verifiable audit trail, which is the thing the
  // bundle exists to be. Envelopes and anchors already read whole; this was the one structure left.
  //
  // Reported as a failure rather than thrown: `verifyBundle` returns a report, and an unknown field
  // is a property of the bundle, not an error in the call.
  //
  // Kept in step with the Python port (`evidence._verify_bundle`, same check, same reason string).
  let unknownOk = true;
  for (const e of entries) {
    const extra = Object.keys(e)
      .filter((f) => !LEDGER_FIELDS.has(f))
      .sort();
    if (extra.length > 0) {
      unknownOk = false;
      log.add(
        "unknown_ledger_fields",
        `unknown_ledger_fields: entry carries fields this verifier does not evaluate and will ` +
          `not ignore: ${extra.map((f) => shown(f)).join(", ")}`,
        { seq: orNull(e["seq"]), node: orNull(e["node"]), entry: e },
      );
    }
  }
  checks.ledger_fields = unknownOk;

  // (0b3) a node id is a string (the schema's `node`). A root, a spawn and an allow are judged by
  // the checks that read their node, below; any other entry that carries a node which is a list,
  // an object, a number or a boolean is reported here, never read by projection and never used as
  // a key. A null node counts as absent.
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    if (ev === "root" || ev === "spawn" || ev === "allow") continue;
    const node = toPlain(e["node"]) as Json | undefined;
    if (node === undefined || node === null || typeof node === "string") continue;
    log.add(
      "invalid_node",
      `invalid_node: seq=${shown(intOr(e["seq"]))} event=${pyRepr((e["event"] ?? null) as CJson)} ` +
        `carries node ${shown(e["node"])}, which is not a string`,
      { seq: orNull(e["seq"]), node: orNull(e["node"]), entry: e },
    );
  }

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
          `expected_head_mismatch: bundle head is (seq=${actualSeq}, hash=${shown(actualHead)}) but the ` +
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
        !sameNumber(ea["v"], rawV)
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
      entry: foreign,
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
    const bad = integrityBreak(entries);
    const badEntry = bad === null ? null : entries[bad]!;
    log.add("integrity", `integrity: ${err}`, {
      seq: badEntry === null ? null : orNull(badEntry["seq"]),
      node: badEntry === null ? null : orNull(badEntry["node"]),
      entry: badEntry,
    });
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

  const { auth, failures: afail } = nodeAuthorities(entries);
  log.extend(afail);

  // (2) monotonicity: every child ⊆ its parent, read in ledger order. Every spawn is checked, and
  // the node it names as `parent` has to be one the root or an EARLIER spawn defined, not revoked
  // by an earlier kill, and not the spawn's own node. Through 0.12.0 a spawn whose parent was
  // absent, null, or named no node in the bundle was skipped, so a child widened past the
  // authority it was really given verified OK; the process being watched writes that field. A
  // node is defined once: a second definition is a failure too, since only one of the two could
  // be read. The Python implementation's same pass, finding for finding.
  let mono = true;
  const definedAt = new Map<string, LedgerEntry>(); // node -> the entry that defined it, as of this point
  const revokedAt = new Map<string, CJson | undefined>(); // node -> the seq of the kill that revoked it
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    if (ev === "kill") {
      noteRevoked(e, revokedAt);
      continue;
    }
    if (ev !== "root" && ev !== "spawn") continue;
    const node = toPlain(e["node"]) as Json | undefined;
    if (typeof node !== "string") continue; // unreadable, reported by nodeAuthorities
    const position = { seq: orNull(e["seq"]), node, entry: e };
    const first = definedAt.get(node);
    if (first !== undefined) {
      mono = false;
      log.add(
        "monotonicity",
        `monotonicity: ${shown(node)} is defined a second time in this bundle (first at seq ${shown(intOr(first["seq"]))})`,
        position,
      );
      continue;
    }
    if (ev === "spawn") {
      const pid = toPlain(e["parent"]) as Json | undefined;
      if (typeof pid !== "string" || !definedAt.has(pid)) {
        mono = false;
        log.add(
          "monotonicity",
          `monotonicity: ${shown(node)} names no parent defined earlier in this bundle (parent ${shown(e["parent"])})`,
          position,
        );
      } else if (revokedAt.has(pid)) {
        mono = false;
        log.add(
          "monotonicity",
          `monotonicity: ${shown(node)} is spawned from ${shown(pid)} after ${shown(pid)} was revoked at seq ` +
            shown(intOr(revokedAt.get(pid))),
          position,
        );
      } else {
        // 0.6.x: the subsumption relation ALONE decides. This used to be gated on a literal,
        // non-wildcard-aware scope difference, which silently accepted a delegation that widened
        // only ttl or a ceiling whenever the child's scopes happened to be literally a subset of
        // the parent's. An unreadable authority on either side is reported by nodeAuthorities
        // and fails this check on its own.
        const child = auth.get(node);
        const p = auth.get(pid);
        if (child !== undefined && p !== undefined && !child.isNarrowerThan(p)) {
          mono = false;
          log.add(
            "monotonicity",
            `monotonicity: ${shown(node)} not ⊆ parent ${shown(pid)} (${monotonicityDetail(child, p)})`,
            position,
          );
        }
      }
    }
    definedAt.set(node, e);
  }
  checks.monotonicity = mono && afail.length === 0;

  // (3) containment: every allowed action's scope within the acting node's authority.
  // An allow carrying `policy` (reasons.Policy) is one the chain never authorized — an adapter
  // running with `allowUnlisted` passed the call through un-gated and recorded that it did. Its
  // `scope` is a label, not a claim of held authority, so testing it for containment would report
  // a violation the entry never asserted. Such entries are counted as UNGATED and reported as
  // their own number instead: a reader sees how much of the run was actually measured, which is
  // the honest answer and never a silent one.
  // Read in ledger order, like monotonicity: an allow is judged against a node defined EARLIER (one
  // defined only later is unknown at that point), and an allow on a node an earlier kill revoked
  // is outside its authority, since a revoked node holds none.
  let contained = true;
  let actions = 0;
  let ungated = 0;
  const known = new Set<string>();
  const killedAt = new Map<string, CJson | undefined>();
  for (const e of entries) {
    const ev = toPlain(e["event"]);
    if (ev === "root" || ev === "spawn") {
      const defined = toPlain(e["node"]);
      if (typeof defined === "string") known.add(defined);
      continue;
    }
    if (ev === "kill") {
      noteRevoked(e, killedAt);
      continue;
    }
    if (ev !== "allow") continue;
    if (isKnownPolicy(toPlain(e["policy"]))) {
      // Only a policy value the format DEFINES buys the exemption. An entry carrying anything
      // else is reported by `policyFailures` and still measured here, so a made-up marker cannot
      // excuse an out-of-authority action.
      ungated += 1;
      continue;
    }
    actions += 1;
    const node = toPlain(e["node"]) as Json | undefined;
    const scope = toPlain(e["scope"]) as string;
    // The Python implementation reads `e.get("context") or {}`, so an absent context and any value
    // Python counts as false (null, false, 0, "", [] or {}) are no context. Any other value that
    // is not an object is not a context the allow could have been checked against, and it does not
    // verify: it is the containment finding below. (Python 0.19.0 raises on it.)
    const rawContext = toPlain(e["context"]) as Json | undefined;
    const noContext = pyFalsy(rawContext);
    const contextIsObject = isRecordLike(rawContext);
    const ctx = (noContext ? {} : rawContext) as Context;
    const a = typeof node === "string" && known.has(node) ? auth.get(node) : undefined;
    if (a === undefined) {
      contained = false;
      log.add("containment", `containment: allow on unknown node ${shown(e["node"])}`, {
        seq: orNull(e["seq"]),
        node: orNull(e["node"]),
        callId: orNull(e["call_id"]),
        entry: e,
      });
      continue;
    }
    if (killedAt.has(node as string)) {
      contained = false;
      log.add(
        "containment",
        `containment: allow of ${pyRepr(e["scope"] ?? null)} on ${shown(e["node"])} after ${shown(e["node"])} was ` +
          `revoked at seq ${shown(intOr(killedAt.get(node as string)))}`,
        { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: orNull(e["call_id"]), entry: e },
      );
      continue;
    }
    // A scope that is not a string is no scope the node can hold. Against a wildcard it threw
    // (`startsWith` on a number or null) out of the verifier; it is this finding either way, as
    // in the Python implementation. A context that is neither absent, nor false to Python, nor an
    // object is this finding too.
    if (typeof scope !== "string" || !(noContext || contextIsObject) || !a.permits(scope, ctx).allowed) {
      contained = false;
      log.add(
        "containment",
        `containment: allow of ${pyRepr(e["scope"] ?? null)} on ${shown(e["node"])} outside its authority ` +
          reprList(Array.from(a.scopes).sort(compareCodePoints)),
        { seq: orNull(e["seq"]), node: orNull(e["node"]), callId: orNull(e["call_id"]), entry: e },
      );
    }
  }
  checks.containment = contained;

  const [eb, ebFailures]: [ExecutionBinding, FailureLog] = versionOk
    ? executionBinding(entries, bundleV)
    : [{ status: "not applicable" }, new FailureLog()];
  if (eb.failures !== undefined && eb.failures.length > 0) log.extend(ebFailures);
  log.extend(policyFailures(entries, bundleV));

  // (4) observer envelopes. Never required — an absent envelope is the status quo and changes
  // nothing — but a PRESENT one has to verify, and a broken one lands in this same list. The
  // per-entry state is reported either way, so a reader sees which hops were covered before
  // reading which one failed.
  const [envelopeSummary, envelopeFailures] = scoreEnvelopes(
    entries,
    bundle.envelopes ?? [],
    trustedWitnesses(options.witnessKeys ?? null, verificationTime(options.now)),
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
    checks.ledger_fields &&
    checks.chain_id &&
    checks.root &&
    log.length === 0;
  return {
    ok,
    checks,
    failures: log.messages,
    failure_details: log.details,
    failure_entries: log.entryIndices(entries),
    nodes: auth.size,
    actions_checked: actions,
    ungated,
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
