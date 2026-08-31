/**
 * test/execution-binding.test.ts — the 0.9.0 execution-binding layer
 * (docs/execution-binding spec, referenced throughout as "spec section N"):
 * callId, capture/adapter, recordOutcome, the pending/complete/kill lifecycle,
 * params_c14n_v1 commitments, and the offline verifier's executionBinding report.
 *
 * Ports tests/test_execution_binding.py from the Python reference implementation
 * one for one (60 cases; see the file's own section markers for the correspondence).
 * Two adaptations, both noted at their test:
 *
 *   - Python patches `os.urandom`; here `node:crypto`'s `randomBytes` is mocked via
 *     `node:test`'s `t.mock.method` — which only sees the SAME module object guard.ts's
 *     `import { randomBytes } from "node:crypto"` reads from if this file imports it with
 *     `import nodeCrypto = require("node:crypto")` (a raw CommonJS require) rather than
 *     `import * as nodeCrypto`, which TS's esModuleInterop wraps in a fresh object whose
 *     properties are un-mockable accessors.
 *   - Python's concurrent-duplicate-outcome test spawns 8 OS threads; JavaScript is
 *     single-threaded, so the equivalent here calls `recordOutcome` for the same callId
 *     repeatedly in a plain loop — deterministic rather than a race, but it still pins
 *     "exactly one wins, every other call throws DuplicateOutcomeError".
 */
import assert from "node:assert/strict";
import test from "node:test";
import nodeCrypto = require("node:crypto");
import { mkdtempSync, unlinkSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Authority } from "../src/authority.js";
import { RowLimit } from "../src/ceilings.js";
import { AuditLog, CommittedAuditError, GENESIS, hashEntry, type LedgerEntry, type Sink } from "../src/audit.js";
import { AuthorityDenied, DuplicateOutcomeError, Guard, type AdapterInfo, type IssueOptions } from "../src/guard.js";
import { BodyState, Capture, CompletionResult, Decision, ReasonCode } from "../src/reasons.js";
import * as paramsMod from "../src/params.js";
import { MAX_SAFE_INTEGER, type CJson } from "../src/canonical.js";
import { anchorFor, exportBundle, verifyBundle } from "../src/evidence.js";
import { HS256TestSigner } from "../src/wire.js";

function v2Root(options: Partial<IssueOptions> = {}): Guard {
  return Guard.issue(
    "orchestrator",
    new Authority({ scopes: ["crm.read", "mail.send"], ceilings: [new RowLimit(100)], ttl: 3600 }),
    { schemaVersion: 2, ...options },
  );
}

function adapterInfo(): AdapterInfo {
  return { module: "test", version: "0", hookPath: "t" };
}

function eventsOf(g: Guard, event: string): LedgerEntry[] {
  return g.auditLog().entries.filter((e) => e["event"] === event);
}

function rehashFrom(entries: LedgerEntry[], fromIdx: number): void {
  let prev = fromIdx === 0 ? GENESIS : (entries[fromIdx - 1]!["hash"] as string);
  for (let i = fromIdx; i < entries.length; i++) {
    const e = entries[i]!;
    e["prev_hash"] = prev;
    const payload: LedgerEntry = {};
    for (const [k, v] of Object.entries(e)) if (k !== "hash") payload[k] = v;
    e["hash"] = hashEntry(prev, payload);
    prev = e["hash"] as string;
  }
}

// =============================================================================================
// callId, the transition, CommittedAuditError.decision
// =============================================================================================

test("a v1 chain never allocates callId or refuses a finalized node", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 })); // schemaVersion: 1, the default
  const d = g.check("crm.read");
  assert.equal(d.callId, null);
  g.complete();
  // v1: complete() never gates check() — informational marker only, unchanged from before 0.9.0
  assert.ok(g.check("crm.read").allowed);
});

test("a v1 chain rejects execution-binding options", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }));
  assert.throws(() => g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() }));
  assert.throws(() => g.check("crm.read", { authorizedParams: { x: 1 } }));
});

test("allow and deny both carry a callId, and they are unique", () => {
  const g = v2Root();
  const allow = g.check("crm.read");
  const deny = g.check("pay.transfer");
  assert.notEqual(allow.callId, null);
  assert.notEqual(deny.callId, null);
  assert.notEqual(allow.callId, deny.callId);
  assert.match(allow.callId!, /^[0-9a-f]{32}$/);
});

test("a finalized v2 node refuses further check calls", () => {
  const g = v2Root();
  g.complete();
  const d = g.check("crm.read");
  assert.equal(d.allowed, false);
  assert.equal(d.reasons[0]!.code, ReasonCode.NODE_FINALIZED);
  assert.notEqual(d.callId, null); // a deny still carries a callId
});

test("callId unavailable is fail-closed and restores meters", (t) => {
  const g = v2Root();
  g.check("crm.read", { context: { rows: 1 } }); // meter now at 1
  const chain = (g as any).chain;
  const before = chain.callsSoFar(g.nodeId, "*");
  t.mock.method(nodeCrypto, "randomBytes", () => {
    throw new Error("no entropy");
  });
  const d = g.check("crm.read", { context: { rows: 1 } });
  assert.equal(d.allowed, false);
  assert.equal(d.reasons[0]!.code, ReasonCode.CALL_ID_UNAVAILABLE);
  const after = chain.callsSoFar(g.nodeId, "*");
  assert.equal(before, after, "meters must be restored on a pre-commit failure");
  // nothing was appended for the failed attempt
  const events = g.auditLog().entries.map((e) => e["event"]);
  assert.equal(events.filter((e) => e === "allow" || e === "deny").length, 1);
});

test("CommittedAuditError carries the entry and the decision", () => {
  class ExplodingSink implements Sink {
    write(_entry: LedgerEntry): void {
      throw new Error("disk full");
    }
  }
  const g = v2Root();
  g.auditLog().sinks = [new ExplodingSink()];
  assert.throws(
    () => g.check("crm.read", { context: { rows: 1 } }),
    (err: unknown) => {
      assert.ok(err instanceof CommittedAuditError);
      const decision = err.decision!;
      assert.ok(decision.allowed);
      assert.notEqual(decision.callId, null);
      assert.equal(err.entry["call_id"], decision.callId);
      // spec: "the guard registers an allowed call as pending before raising"
      const chain = (g as any).chain;
      assert.ok(chain.pendingFor(g.nodeId).includes(decision.callId));
      return true;
    },
  );
});

test("recordDenial also gets a callId on v2", () => {
  const g = v2Root();
  const d = g.recordDenial(ReasonCode.NO_AUTHORITY, "unmapped tool", { tool: "mystery" });
  assert.equal(d.allowed, false);
  assert.notEqual(d.callId, null);
});

test("a post-commit file-write failure is also a CommittedAuditError", () => {
  // A DIFFERENT persistence path than the sink test above: the audit-path file write itself
  // fails (here: the path now names a directory, so appendFileSync raises EISDIR).
  const dir = mkdtempSync(join(tmpdir(), "attenu-post-commit-"));
  const auditPath = join(dir, "ledger.jsonl");
  const g = v2Root({ auditPath });
  unlinkSync(auditPath);
  mkdirSync(auditPath); // put a directory where the ledger file was
  assert.throws(
    () => g.check("crm.read"),
    (err: unknown) => {
      assert.ok(err instanceof CommittedAuditError);
      assert.ok(err.cause instanceof Error);
      assert.ok(err.decision!.allowed);
      return true;
    },
  );
});

test("a retry after CommittedAuditError is a new call with no shared statement", () => {
  class ExplodingSink implements Sink {
    calls = 0;
    write(_entry: LedgerEntry): void {
      this.calls += 1;
      if (this.calls === 1) throw new Error("disk full");
    }
  }
  const g = v2Root();
  g.auditLog().sinks = [new ExplodingSink()];
  let firstCallId: string | null = null;
  assert.throws(() => {
    try {
      g.check("crm.read");
    } catch (exc) {
      if (exc instanceof CommittedAuditError) firstCallId = exc.decision!.callId;
      throw exc;
    }
  }, CommittedAuditError);
  const retry = g.check("crm.read"); // the caller retries the same logical operation
  assert.notEqual(firstCallId, retry.callId);
  const allows = eventsOf(g, "allow");
  assert.equal(allows.length, 2);
  // neither record states they were attempts at one logical operation
  for (const e of allows) {
    assert.equal("retry_of" in e, false);
    assert.equal("attempt" in e, false);
  }
});

// =============================================================================================
// capture / adapter on the allow entry
// =============================================================================================

test("capture requires adapter", () => {
  const g = v2Root();
  assert.throws(() => g.check("crm.read", { capture: Capture.WRAPPER_SYNC }));
});

test("adapter requires all three keys", () => {
  const g = v2Root();
  assert.throws(() =>
    g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: { module: "m" } as unknown as AdapterInfo }),
  );
});

test("an unknown capture value is rejected", () => {
  const g = v2Root();
  assert.throws(() => g.check("crm.read", { capture: "something_else", adapter: adapterInfo() }));
});

test("capture and adapter land on the allow entry only", () => {
  const g = v2Root();
  g.check("crm.read", { capture: Capture.FRAMEWORK_POST_HOOK, adapter: adapterInfo() });
  g.check("pay.transfer", { capture: Capture.FRAMEWORK_POST_HOOK, adapter: adapterInfo() });
  const allow = eventsOf(g, "allow")[0]!;
  const deny = eventsOf(g, "deny")[0]!;
  assert.equal(allow["capture"], Capture.FRAMEWORK_POST_HOOK);
  assert.deepEqual(allow["adapter"], { module: "test", version: "0", hook_path: "t" });
  assert.equal("capture" in deny, false);
  assert.equal("adapter" in deny, false);
});

// =============================================================================================
// pending / complete() / kill's pendingAtKill
// =============================================================================================

test("only allow enters the pending set", () => {
  const g = v2Root();
  const allow = g.check("crm.read");
  const deny = g.check("pay.transfer");
  const chain = (g as any).chain;
  assert.ok(chain.pendingFor(g.nodeId).includes(allow.callId));
  assert.equal(chain.pendingFor(g.nodeId).includes(deny.callId), false);
});

test("complete refuses while pending and reports the callIds", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  const cr = g.complete();
  assert.ok(cr instanceof CompletionResult); // a schemaVersion: 2 chain always gets a CompletionResult
  const cr2 = cr as CompletionResult;
  assert.equal(cr2.completed, false);
  assert.deepEqual(cr2.pendingCallIds, [d.callId]);
  assert.equal(g.isComplete, false);
});

test("complete succeeds once the outcome is recorded", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 5 });
  const cr = g.complete() as CompletionResult;
  assert.equal(cr.completed, true);
  assert.deepEqual(cr.pendingCallIds, []);
});

test("kill snapshots pending without clearing, and a late outcome is accepted", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  g.revoke();
  const killEntry = eventsOf(g, "kill")[0]!;
  assert.deepEqual(killEntry["pending_at_kill"], [d.callId]);
  // not cleared: still pending after the kill
  const chain = (g as any).chain;
  assert.ok(chain.pendingFor(g.nodeId).includes(d.callId));
  // a late true record is accepted
  const entry = g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 3 });
  assert.equal(entry["event"], "outcome");
  assert.equal(chain.pendingFor(g.nodeId).includes(d.callId), false);
});

test("kill with nothing pending still writes an empty list", () => {
  const g = v2Root();
  g.revoke();
  const killEntry = eventsOf(g, "kill")[0]!;
  assert.deepEqual(killEntry["pending_at_kill"], []);
});

test("a v1 kill never carries pendingAtKill", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }));
  g.revoke();
  const killEntry = eventsOf(g, "kill")[0]!;
  assert.equal("pending_at_kill" in killEntry, false);
});

// =============================================================================================
// recordOutcome(): bodyState vocabulary, conditional fields, duplicates
// =============================================================================================

test("a v1 chain refuses recordOutcome", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }));
  assert.throws(() => g.recordOutcome("x".repeat(32), BodyState.RETURNED, { durationMs: 1 }));
});

test("every bodyState and its conditional errorCode", () => {
  for (const state of [BodyState.RETURNED, BodyState.ABANDONED, BodyState.DEFERRED]) {
    const g = v2Root();
    const d = g.check("crm.read");
    const entry = g.recordOutcome(d.callId!, state, { durationMs: 1 });
    assert.equal(entry["body_state"], state);
    assert.equal("error_code" in entry, false);
  }

  const g = v2Root();
  const d = g.check("crm.read");
  const entry = g.recordOutcome(d.callId!, BodyState.RAISED, { errorCode: "ValueError", durationMs: 1 });
  assert.equal(entry["error_code"], "ValueError");
});

test("errorCode is required exactly when raised", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  assert.throws(() => g.recordOutcome(d.callId!, BodyState.RAISED, { durationMs: 1 })); // missing errorCode
  const d2 = g.check("crm.read");
  assert.throws(() =>
    g.recordOutcome(d2.callId!, BodyState.RETURNED, { errorCode: "X", durationMs: 1 }), // illegal here
  );
});

test("an unknown bodyState is rejected", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  assert.throws(() => g.recordOutcome(d.callId!, "executed", { durationMs: 1 }));
});

test("durationMs must be a non-negative integer", () => {
  const g = v2Root();
  for (const bad of [-1, 1.5, true, "1"]) {
    const d = g.check("crm.read");
    assert.throws(() => g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: bad as unknown as number }));
  }
});

test("exactly one outcome per callId", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  assert.throws(() => g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 }), DuplicateOutcomeError);
});

test("repeated duplicate-outcome append: exactly one wins", () => {
  // Python spawns 8 OS threads at the same callId; JavaScript has none, so this calls
  // recordOutcome for the same callId 8 times in a plain loop instead — deterministic rather
  // than a race, but it still pins the invariant: exactly one append succeeds, every other call
  // throws DuplicateOutcomeError, and the ledger carries exactly one outcome event.
  const g = v2Root();
  const d = g.check("crm.read");
  const results: string[] = [];
  for (let i = 0; i < 8; i++) {
    try {
      g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
      results.push("ok");
    } catch (exc) {
      if (exc instanceof DuplicateOutcomeError) results.push("dup");
      else throw exc;
    }
  }
  assert.equal(results.filter((r) => r === "ok").length, 1);
  assert.equal(results.filter((r) => r === "dup").length, 7);
  assert.equal(eventsOf(g, "outcome").length, 1);
});

test("a malformed receipt is rejected", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  assert.throws(() =>
    g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1, receipt: { type: "x" } as any }),
  );
});

test("a receipt is carried verbatim and unverified", () => {
  const g = v2Root();
  const d = g.check("crm.read");
  const receipt = { type: "otel", ref: "span-1", digest: "ab".repeat(32) };
  const entry = g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1, receipt });
  assert.deepEqual(entry["receipt"], receipt);
});

// =============================================================================================
// params_c14n_v1 (docs/execution-binding spec section 4)
// =============================================================================================

test("the safe-integer boundary and one past it", () => {
  const salt = Buffer.alloc(16);
  const [h, reason] = paramsMod.commit({ n: MAX_SAFE_INTEGER }, salt);
  assert.notEqual(h, null);
  assert.equal(reason, null);
  const [h2, reason2] = paramsMod.commit({ n: MAX_SAFE_INTEGER + 1 }, salt);
  assert.equal(h2, null);
  assert.equal(reason2, paramsMod.ParamsHashReason.UNSUPPORTED);
});

test("an integral number beyond the bound is unsupported at the params layer (parity pin)", () => {
  // TS's canonicalBytes ALREADY rejects every unsafe integer, literal or float-shaped alike
  // (JavaScript has one numeric type, unlike Python's separate int/float) — so unlike Python,
  // where this test proves params.py must run its OWN check because canonical.dumps tolerates
  // 1e16, this pins the boundary VALUES the spec names (9e15 accepted, 1e16 rejected) so both
  // runtimes are provably in parity at the layer that matters — the params commitment — even
  // though their general canonicalizers diverge on how they get there (see params.ts's doc
  // comment and canonical.ts's UnsafeIntegerError).
  const salt = Buffer.alloc(16);
  const [hOk, reasonOk] = paramsMod.commit({ n: 9e15 }, salt);
  assert.notEqual(hOk, null);
  assert.equal(reasonOk, null);
  const [h, reason] = paramsMod.commit({ n: 1e16 }, salt);
  assert.equal(h, null);
  assert.equal(reason, paramsMod.ParamsHashReason.UNSUPPORTED);
});

test("an ordinary fractional float within range is fine", () => {
  // Every binary64 double beyond roughly 2**52 in magnitude IS mathematically integral — there
  // is no such thing as "a large non-integral float" to test here; that is exactly why the
  // check is "integral AND out of range", not "out of range" alone.
  const salt = Buffer.alloc(16);
  const [h, reason] = paramsMod.commit({ n: 3.14159 }, salt);
  assert.notEqual(h, null);
  assert.equal(reason, null);
});

test("negative zero hashes identically to positive zero", () => {
  const salt = Buffer.alloc(16);
  const [hPos] = paramsMod.commit({ n: 0.0 }, salt);
  const [hNeg] = paramsMod.commit({ n: -0.0 }, salt);
  assert.equal(hPos, hNeg);
});

test("non-finite numbers are unsupported", () => {
  const salt = Buffer.alloc(16);
  for (const bad of [NaN, Infinity, -Infinity]) {
    const [h, reason] = paramsMod.commit({ n: bad }, salt);
    assert.equal(h, null);
    assert.equal(reason, paramsMod.ParamsHashReason.UNSUPPORTED);
  }
});

test("lone surrogates are unsupported", () => {
  const salt = Buffer.alloc(16);
  const [h, reason] = paramsMod.commit({ s: "\ud800" }, salt);
  assert.equal(h, null);
  assert.equal(reason, paramsMod.ParamsHashReason.UNSUPPORTED);
});

test("an unsupported JavaScript value is unsupported", () => {
  // JavaScript's nearest analogue of Python's `object()`: a non-plain-object value
  // canonicalBytes' closed JSON data model refuses outright.
  const salt = Buffer.alloc(16);
  const [h, reason] = paramsMod.commit({ s: () => undefined } as any, salt);
  assert.equal(h, null);
  assert.equal(reason, paramsMod.ParamsHashReason.UNSUPPORTED);
});

test("raw-salt versus hex-salt hashing", () => {
  const raw = Buffer.from("11".repeat(16), "hex");
  const [h1] = paramsMod.commit({ x: 1 }, raw);
  const [h2] = paramsMod.commit({ x: 1 }, paramsMod.decodeSalt("11".repeat(16)));
  assert.equal(h1, h2);
});

test("decodeSalt rejects the wrong length", () => {
  assert.throws(() => paramsMod.decodeSalt("ab"));
});

test("authorized and invoked hashes are independent, and absence is distinguishable", () => {
  const g = v2Root();
  // deployment opt-out: no hash, no reason field at all
  const d = g.check("crm.read");
  const allow = g.auditLog().entries.find((e) => e["event"] === "allow" && e["call_id"] === d.callId)!;
  assert.equal("authorized_params_hash" in allow, false);
  assert.equal("params_hash_reason" in allow, false);

  // attempted but unsupported: hash absent, reason present
  const d2 = g.check("crm.read", { authorizedParams: { n: 1e16 } });
  const allow2 = g.auditLog().entries.find((e) => e["event"] === "allow" && e["call_id"] === d2.callId)!;
  assert.equal("authorized_params_hash" in allow2, false);
  assert.equal(allow2["params_hash_reason"], "unsupported");

  // matching commitments on both sides
  const d3 = g.check("crm.read", { authorizedParams: { x: 1 } });
  g.recordOutcome(d3.callId!, BodyState.RETURNED, { invokedParams: { x: 1 }, durationMs: 1 });
  const allow3 = g.auditLog().entries.find((e) => e["event"] === "allow" && e["call_id"] === d3.callId)!;
  const outcome3 = g.auditLog().entries.find((e) => e["event"] === "outcome" && e["call_id"] === d3.callId)!;
  assert.equal(allow3["authorized_params_hash"], outcome3["invoked_params_hash"]);

  // a substitution IS visible because both hashes exist
  const d4 = g.check("crm.read", { authorizedParams: { x: 1 } });
  g.recordOutcome(d4.callId!, BodyState.RETURNED, { invokedParams: { x: 2 }, durationMs: 1 });
  const allow4 = g.auditLog().entries.find((e) => e["event"] === "allow" && e["call_id"] === d4.callId)!;
  const outcome4 = g.auditLog().entries.find((e) => e["event"] === "outcome" && e["call_id"] === d4.callId)!;
  assert.notEqual(allow4["authorized_params_hash"], outcome4["invoked_params_hash"]);
});

test("invokedParams unsupported is independent of the authorized side", () => {
  const g = v2Root();
  const d = g.check("crm.read", { authorizedParams: { x: 1 } }); // authorized side: supported
  const entry = g.recordOutcome(d.callId!, BodyState.RETURNED, { invokedParams: { n: 1e16 }, durationMs: 1 });
  assert.equal("invoked_params_hash" in entry, false);
  assert.equal(entry["params_hash_reason"], "unsupported");
  const allow = g.auditLog().entries.find((e) => e["event"] === "allow" && e["call_id"] === d.callId)!;
  assert.ok("authorized_params_hash" in allow); // the allow side is unaffected
});

test("paramsSalt is fixed for the chain and written once on root", () => {
  const g = v2Root();
  const root = g.auditLog().entries[0]!;
  assert.match(root["params_salt"] as string, /^[0-9a-f]{32}$/);
  const child = g.delegate("summarizer", new Authority({ scopes: ["crm.read"], ttl: 60 }), "t");
  assert.equal((g as any).chain, (child as any).chain);
  assert.equal((g as any).chain.paramsSalt, (child as any).chain.paramsSalt);
});

// =============================================================================================
// The offline verifier's executionBinding report (spec section 5)
// =============================================================================================

function bundleFor(guard: Guard, signer: HS256TestSigner) {
  return exportBundle(guard.auditLog(), signer);
}

test("a v1 bundle reports not applicable", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }));
  g.check("crm.read");
  const rep = verifyBundle(bundleFor(g, signer), signer);
  assert.deepEqual(rep.execution_binding, { status: "not applicable" });
});

test("a clean aggregate when every promised call is observed", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  g.complete();
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.aggregate, "clean");
  assert.equal(eb.per_call[d.callId!], "observed");
  assert.equal(eb.per_node_lifecycle[g.nodeId], "finalized");
});

test("an abandoned call is observed and leaves the aggregate clean", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  g.recordOutcome(d.callId!, BodyState.ABANDONED, { durationMs: 1 });
  g.complete();
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.per_call[d.callId!], "observed");
  assert.equal(eb.aggregate, "clean");
});

test("pre_hook_only is unobserved and makes the aggregate incomplete", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read", { capture: Capture.PRE_HOOK_ONLY, adapter: adapterInfo() });
  g.complete();
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.deepEqual(Object.values(eb.per_call), ["unobserved"]);
  assert.equal(eb.aggregate, "incomplete");
});

test("an in-progress node is a snapshot, not a verdict, but still incomplete", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  // never recordOutcome, never complete()
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.per_node_lifecycle[g.nodeId], "in_progress");
  assert.equal(eb.aggregate, "incomplete");
});

test("an unaccounted call in a finalized node is failed", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  // complete() would refuse while pending — reach a finalized node with an unaccounted call only
  // by forging a "done" entry directly on the ledger.
  const entries = g.auditLog().entries.map((e) => ({ ...e }));
  entries.push({
    v: 2,
    c14n: "JCS",
    seq: entries.length,
    ts: 99,
    event: "done",
    chain_id: g.chainId,
    node: g.nodeId,
    agent: "orchestrator",
    prev_hash: entries[entries.length - 1]!["hash"] as string,
  });
  rehashFrom(entries, entries.length - 1);
  const anchor = anchorFor(entries, signer);
  const bundle = { v: 2, c14n: "JCS" as const, chain_id: g.chainId, entries, anchor };
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.per_node_lifecycle[g.nodeId], "finalized");
  assert.equal(eb.aggregate, "failed");
});

test("revoked_with_pending is incomplete", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  g.revoke();
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.per_node_lifecycle[g.nodeId], "revoked_with_pending");
  assert.equal(eb.aggregate, "incomplete");
});

test("a cleanly revoked node with nothing pending does not force incomplete", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  g.revoke();
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.per_node_lifecycle[g.nodeId], "revoked");
  assert.equal(eb.aggregate, "clean");
});

test("outcome without allow", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read");
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  entries.push({
    v: 2,
    c14n: "JCS",
    seq: entries.length,
    ts: 99,
    event: "outcome",
    chain_id: g.chainId,
    node: g.nodeId,
    call_id: "ab".repeat(16),
    body_state: "returned",
    duration_ms: 1,
    prev_hash: entries[entries.length - 1]!["hash"] as string,
  });
  rehashFrom(entries, entries.length - 1);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("outcome_without_allow:")));
  assert.equal(eb.aggregate, "failed");
});

test("a duplicate outcome in the ledger", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read");
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  const dup = { ...entries[entries.length - 1]! };
  dup["seq"] = entries.length;
  dup["prev_hash"] = entries[entries.length - 1]!["hash"] as string;
  const payload: LedgerEntry = {};
  for (const [k, v] of Object.entries(dup)) if (k !== "hash") payload[k] = v;
  dup["hash"] = hashEntry(dup["prev_hash"] as string, payload);
  entries.push(dup);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("duplicate_outcome:")));
});

test("a duplicate callId across allow and deny", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const allowD = g.check("crm.read");
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  const forgedDeny: LedgerEntry = {
    v: 2,
    c14n: "JCS",
    seq: entries.length,
    ts: 99,
    event: "deny",
    chain_id: g.chainId,
    node: g.nodeId,
    scope: "pay.transfer",
    tool: null,
    context: {},
    reason: ReasonCode.SCOPE_NOT_GRANTED,
    reasons: [],
    disposition: "out_of_authority",
    call_id: allowD.callId!,
    prev_hash: entries[entries.length - 1]!["hash"] as string,
  };
  const payload: LedgerEntry = {};
  for (const [k, v] of Object.entries(forgedDeny)) if (k !== "hash") payload[k] = v;
  forgedDeny["hash"] = hashEntry(forgedDeny["prev_hash"] as string, payload);
  entries.push(forgedDeny);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("duplicate_call_id:")));
});

test("outcome before allow", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read");
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  const allowIdx = entries.findIndex((e) => e["event"] === "allow");
  const outcomeIdx = entries.findIndex((e) => e["event"] === "outcome");
  const tmp: CJson = entries[outcomeIdx]!["seq"]!;
  entries[outcomeIdx]!["seq"] = entries[allowIdx]!["seq"]!;
  entries[allowIdx]!["seq"] = tmp;
  // re-chain from scratch so integrity itself still passes and only the binding check is isolated
  entries.sort((a, b) => (a["seq"] as number) - (b["seq"] as number));
  rehashFrom(entries, 0);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("outcome_before_allow:")));
});

test("a cross-ref outcome on a different node", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read");
  const child = g.delegate("summarizer", new Authority({ scopes: ["crm.read"], ttl: 60 }), "t");
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  entries.push({
    v: 2,
    c14n: "JCS",
    seq: entries.length,
    ts: 99,
    event: "outcome",
    chain_id: g.chainId,
    node: child.nodeId,
    call_id: d.callId!,
    body_state: "returned",
    duration_ms: 1,
    prev_hash: entries[entries.length - 1]!["hash"] as string,
  });
  rehashFrom(entries, entries.length - 1);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("cross_ref:")));
});

test("a params mismatch", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read", { authorizedParams: { x: 1 } });
  g.recordOutcome(d.callId!, BodyState.RETURNED, { invokedParams: { x: 2 }, durationMs: 1 });
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("params_mismatch:")));
  assert.equal(eb.aggregate, "failed");
});

test("params_coverage is its own axis, independent of the aggregate", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read"); // no authorizedParams at all -> deployment opted out
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  g.complete(); // finalize the node so the aggregate CAN be clean
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.aggregate, "clean");
  assert.equal(eb.params_coverage, "none");
});

test("mixed entry versions are rejected", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read");
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  entries[1] = { ...entries[1]!, v: 1 };
  // deliberately not re-hashed: tampering the version alone is enough to isolate this check;
  // integrity will also fail, which is fine — we assert the specific failure is present.
  const rep = verifyBundle(bundle, signer);
  assert.ok(rep.failures.some((f) => f.startsWith("mixed_entry_versions:")));
  assert.deepEqual(rep.execution_binding, { status: "not applicable" });
});

test("a root version mismatch", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const bundle = bundleFor(g, signer);
  (bundle as any).v = 1; // bundle claims v1 while the root entry says v2
  const rep = verifyBundle(bundle, signer);
  assert.ok(rep.failures.some((f) => f.startsWith("root_version_mismatch:")));
});

test("an invalid allow with a malformed callId", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  g.check("crm.read");
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  const idx = entries.findIndex((e) => e["event"] === "allow");
  entries[idx]!["call_id"] = "not-hex";
  rehashFrom(entries, idx);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("invalid_allow:")));
});

test("an invalid outcome missing errorCode on raised", () => {
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read");
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  const bundle = bundleFor(g, signer);
  const entries = bundle.entries;
  const idx = entries.findIndex((e) => e["event"] === "outcome");
  entries[idx]!["body_state"] = "raised";
  rehashFrom(entries, idx);
  bundle.anchor = anchorFor(entries, signer);
  const rep = verifyBundle(bundle, signer);
  const eb = rep.execution_binding as any;
  assert.ok(eb.failures.some((f: string) => f.startsWith("invalid_outcome:")));
});

test("verification never consults current authority state", () => {
  // a revocation that happens LATER does not retroactively invalidate an earlier allow's record
  const signer = new HS256TestSigner(Buffer.from("k"), "k");
  const g = v2Root();
  const d = g.check("crm.read", { capture: Capture.WRAPPER_SYNC, adapter: adapterInfo() });
  g.recordOutcome(d.callId!, BodyState.RETURNED, { durationMs: 1 });
  g.revoke(); // after the fact
  const rep = verifyBundle(bundleFor(g, signer), signer);
  const eb = rep.execution_binding as any;
  assert.equal(eb.per_call[d.callId!], "observed");
});
