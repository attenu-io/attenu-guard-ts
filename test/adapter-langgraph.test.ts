/**
 * The LangGraph.js adapter. The wrapping logic is checked against plain
 * callables and stand-in tools — it imports nothing from the framework — and
 * then against a real `ToolNode`, which is skipped when LangGraph is not
 * installed.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  addGuardedNode,
  delegateTo,
  freeze,
  guardNode,
  guardTool,
  guardTools,
  isLangGraphAvailable,
  toolArgs,
  type GraphLike,
  type ToolLike,
} from "../src/adapters/langgraph.js";
import { Authority, AuthorityError } from "../src/authority.js";
import { RowLimit } from "../src/ceilings.js";
import { AuthorityDenied, Guard } from "../src/guard.js";
import { BodyState, Capture, Decision, ReasonCode } from "../src/reasons.js";

function supervisor(): Guard {
  return Guard.issue(
    "supervisor",
    new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(1000)], ttl: 3600 }),
    { chainId: "lg", task: "quarterly review" },
  );
}

/** Same shape as `supervisor`, but on a `schemaVersion: 2` chain — the guard the
 * execution-binding wiring tests below check against. */
function supervisorV2(): Guard {
  return Guard.issue(
    "supervisor",
    new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(1000)], ttl: 3600 }),
    { chainId: "lg2", task: "quarterly review", schemaVersion: 2 },
  );
}

function fakeTool(name: string, fn: (input: any) => any = () => "ok"): ToolLike {
  return { name, description: `the ${name} tool`, schema: { type: "object" }, invoke: fn };
}

test("a guarded node runs on an allow and returns the result unchanged", () => {
  const g = supervisor();
  const node = guardNode(g, "crm.read", (state: { n: number }) => ({ doubled: state.n * 2 }));
  assert.deepEqual(node({ n: 21 }), { doubled: 42 });
  assert.equal(node.guard, g);
  assert.equal(node.toolScope, "crm.read");
});

test("a guarded node never runs its body on a denial", () => {
  const g = supervisor();
  let ran = false;
  const node = guardNode(g, "fs.write", (_state: Record<string, unknown>) => {
    ran = true;
    return "should not happen";
  });
  assert.throws(() => node({}), AuthorityDenied);
  assert.equal(ran, false, "the wrapped body must not execute");
});

test("the context function sees the node's own arguments", () => {
  const g = supervisor();
  const node = guardNode(g, "crm.read", (state: { rows: number }) => state.rows, {
    contextFn: (state: { rows: number }) => ({ rows: state.rows }),
    tool: "crm_query",
  });
  assert.equal(node({ rows: 10 }), 10);
  assert.throws(() => node({ rows: 5_000 }), AuthorityDenied); // over the row ceiling
  const entry = g.auditLog().entries.at(-1)!;
  assert.equal(entry["event"], "deny");
  assert.equal(entry["tool"], "crm_query");
  assert.equal(entry["reason"], ReasonCode.CEILING_EXCEEDED);
});

test("an async node's promise passes through untouched", async () => {
  const g = supervisor();
  const node = guardNode(g, "crm.read", async () => "later");
  assert.equal(await node(), "later");
});

test("addGuardedNode registers the wrapper on a graph", () => {
  const g = supervisor();
  const registered: [string, unknown][] = [];
  const graph: GraphLike = { addNode: (name, action) => registered.push([name, action]) };
  const node = addGuardedNode(graph, "summarize", g, "crm.read", () => "done");
  assert.deepEqual(registered.length, 1);
  assert.equal(registered[0]![0], "summarize");
  assert.equal(registered[0]![1], node);
});

test("a guarded tool keeps the identity ToolNode matches on", () => {
  const g = supervisor();
  const guarded = guardTool(g, fakeTool("crm_query"), { scope: "crm.read" });
  assert.equal(guarded.name, "crm_query");
  assert.equal(guarded.description, "the crm_query tool");
  assert.deepEqual(guarded.schema, { type: "object" });
});

test("a guarded tool authorizes before the tool body runs", () => {
  const g = supervisor();
  let ran = 0;
  const guarded = guardTool(g, fakeTool("crm_delete", () => (ran += 1)), { scope: "fs.write" });
  assert.throws(() => guarded.invoke({ args: {} }), AuthorityDenied);
  assert.equal(ran, 0);

  const allowed = guardTool(g, fakeTool("crm_query", () => (ran += 1)), { scope: "crm.read" });
  allowed.invoke({ args: {} });
  assert.equal(ran, 1);
});

test("a tool call's args reach the context function", () => {
  const g = supervisor();
  const guarded = guardTool(g, fakeTool("crm_query"), {
    scope: "crm.read",
    contextFn: (input) => ({ rows: toolArgs(input)["limit"] as number }),
  });
  guarded.invoke({ name: "crm_query", args: { limit: 5 }, id: "1", type: "tool_call" });
  assert.equal(g.auditLog().entries.at(-1)!["event"], "allow");
  assert.throws(
    () => guarded.invoke({ name: "crm_query", args: { limit: 99_999 }, id: "2", type: "tool_call" }),
    AuthorityDenied,
  );
});

test("toolArgs reads both invoke shapes", () => {
  assert.deepEqual(toolArgs({ name: "t", args: { a: 1 }, id: "x" }), { a: 1 });
  assert.deepEqual(toolArgs({ a: 1 }), { a: 1 });
  assert.deepEqual(toolArgs(null), {});
});

test("onDenied lets the model see the refusal instead of aborting the run", () => {
  const g = supervisor();
  let seen: Decision | null = null;
  const guarded = guardTool(g, fakeTool("wire_money"), {
    scope: "payments.send",
    onDenied: (decision) => {
      seen = decision;
      return `refused: ${decision.explain()}`;
    },
  });
  const result = guarded.invoke({ args: {} });
  assert.match(String(result), /^refused: denied: scope_not_granted/);
  assert.equal((seen as Decision | null)?.allowed, false);
  assert.equal(g.auditLog().entries.at(-1)!["event"], "deny", "the denial is still on the record");
});

test("guardTools maps a whole tool list, defaulting the scope to the tool name", () => {
  const g = supervisor();
  const tools = guardTools(g, [fakeTool("crm_query"), fakeTool("crm_export")], {
    scopes: { crm_query: "crm.read", crm_export: "crm.export" },
  });
  assert.deepEqual(tools.map((t) => t.name), ["crm_query", "crm_export"]);
  tools[0]!.invoke({ args: {} }); // crm.read is inside crm.*
  tools[1]!.invoke({ args: {} }); // crm.export is too
  assert.deepEqual(
    g.auditLog().entries.slice(-2).map((e) => e["event"]),
    ["allow", "allow"],
  );
  // A tool with no mapping falls back to its own name, which is not a held scope.
  const unmapped = guardTools(g, [fakeTool("shell_exec")]);
  assert.throws(() => unmapped[0]!.invoke({ args: {} }), AuthorityDenied);
});

test("the handoff is the delegation moment: the sub-agent gets a narrowed guard", () => {
  const parent = supervisor();
  const researcher = delegateTo(parent, {
    agentId: "researcher",
    request: new Authority({ scopes: ["crm.read", "fs.write"], ceilings: [new RowLimit(50)], ttl: 900 }),
    task: "summarise the pipeline",
  });
  assert.deepEqual([...researcher.authority.scopes], ["crm.read"]); // fs.write was not the parent's to give
  assert.equal((researcher.authority.ceiling("max_rows") as RowLimit).maxRows, 50);
  assert.ok(researcher.isNarrowerThan(parent));

  const tools = guardTools(researcher, [fakeTool("crm_query"), fakeTool("write_file")], {
    scopes: { crm_query: "crm.read", write_file: "fs.write" },
  });
  tools[0]!.invoke({ args: {} });
  assert.throws(() => tools[1]!.invoke({ args: {} }), AuthorityDenied);
});

test("a revoked sub-agent's tools stop working, and it cannot be handed off to again", () => {
  const parent = supervisor();
  const child = delegateTo(parent, {
    agentId: "researcher",
    request: new Authority({ scopes: ["crm.read"], ttl: 900 }),
    task: "research",
  });
  const tool = guardTool(child, fakeTool("crm_query"), { scope: "crm.read" });
  tool.invoke({ args: {} });
  parent.revokeAgent("researcher");
  assert.throws(() => tool.invoke({ args: {} }), AuthorityDenied);
  assert.throws(
    () => delegateTo(parent, { agentId: "researcher", request: new Authority({ scopes: ["crm.read"] }), task: "again" }),
    AuthorityError,
  );
});

test("the adapter loads without LangGraph installed", () => {
  // Nothing above this line touched the framework: the whole suite so far ran
  // against plain callables and stand-in tools.
  assert.equal(typeof guardNode, "function");
  assert.equal(typeof guardTool, "function");
});

test("a guarded tool drops into a real ToolNode", async (t) => {
  if (!(await isLangGraphAvailable())) {
    t.skip("@langchain/langgraph is not installed");
    return;
  }
  // Imported through variables so the suite type-checks with the framework absent.
  const load = (specifier: string) => import(specifier);
  const { ToolNode } = (await load("@langchain/langgraph/prebuilt")) as any;
  const { tool } = (await load("@langchain/core/tools")) as any;
  const { AIMessage } = (await load("@langchain/core/messages")) as any;
  const { z } = (await load("zod")) as any;

  const g = supervisor();
  const calls: number[] = [];
  const crmQuery = tool((input: { limit: number }) => `read ${input.limit} rows`, {
    name: "crm_query",
    description: "Read rows from the CRM.",
    schema: z.object({ limit: z.number() }),
  });
  const wireMoney = tool(() => {
    calls.push(-1);
    return "sent";
  }, {
    name: "wire_money",
    description: "Send a payment.",
    schema: z.object({}),
  });

  const node = new ToolNode(
    guardTools(g, [crmQuery, wireMoney], {
      scopes: { crm_query: "crm.read", wire_money: "payments.send" },
      contexts: { crm_query: (input: any) => ({ rows: toolArgs(input)["limit"] }) },
      onDenied: (decision) => `Denied by attenu-guard: ${decision.explain()}`,
    }),
    { handleToolErrors: false },
  );

  const message = new AIMessage({
    content: "",
    tool_calls: [
      { name: "crm_query", args: { limit: 10 }, id: "a", type: "tool_call" },
      { name: "wire_money", args: {}, id: "b", type: "tool_call" },
    ],
  });
  const out = await node.invoke({ messages: [message] });
  const contents = out.messages.map((m: any) => String(m.content));

  assert.match(contents[0]!, /read 10 rows/);
  assert.match(contents[1]!, /Denied by attenu-guard: denied: scope_not_granted/);
  assert.deepEqual(calls, [], "the unauthorized tool body never ran");

  const events = g.auditLog().entries.slice(1).map((e) => e["event"]);
  assert.deepEqual(events.sort(), ["allow", "deny"]);
});

// =============================================================================================
// 0.9.0: guardNode/guardTool as the reference wiring for recordOutcome — only active when the
// guard's chain is schemaVersion: 2. Mirrors Python's TestExecutionBindingWiring.
// =============================================================================================

test("a sync guarded node records a returned outcome with wrapperSync capture", () => {
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", (state: { rows: number }) => ({ ok: true, rows: state.rows }), {
    contextFn: (state: { rows: number }) => ({ rows: state.rows }),
  });
  const result = node({ rows: 1 });
  assert.deepEqual(result, { ok: true, rows: 1 });
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  assert.equal(allow["capture"], Capture.WRAPPER_SYNC);
  assert.equal((allow["adapter"] as any)?.module, "attenu-guard/adapters/langgraph");
  assert.equal(outcome["call_id"], allow["call_id"]);
  assert.equal(outcome["body_state"], BodyState.RETURNED);
  assert.ok("authorized_params_hash" in allow);
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
});

test("a sync guarded node that throws records a raised outcome with an errorCode", () => {
  const g = supervisorV2();
  const node = guardNode(
    g,
    "crm.read",
    (_state: { rows: number }) => {
      throw new RangeError("boom");
    },
    { contextFn: () => ({ rows: 1 }) },
  );
  assert.throws(() => node({ rows: 1 }), RangeError);
  const outcome = g.auditLog().entries.find((e) => e["event"] === "outcome")!;
  assert.equal(outcome["body_state"], BodyState.RAISED);
  assert.equal(outcome["error_code"], "RangeError");
});

test("a denied guarded-node call never records an outcome", () => {
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", (_state: { rows: number }) => ({ ok: true }), {
    contextFn: (state: { rows: number }) => ({ rows: state.rows }),
  });
  assert.throws(() => node({ rows: 5_000 }), AuthorityDenied); // over supervisorV2's RowLimit(1000)
  assert.deepEqual(g.auditLog().entries.filter((e) => e["event"] === "outcome"), []);
});

test("an async guarded node uses wrapperAsync capture", async () => {
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", async (state: { rows: number }) => ({ ok: true, rows: state.rows }), {
    contextFn: (state: { rows: number }) => ({ rows: state.rows }),
  });
  const result = await node({ rows: 1 });
  assert.deepEqual(result, { ok: true, rows: 1 });
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  assert.equal(allow["capture"], Capture.WRAPPER_ASYNC);
  assert.equal(outcome["body_state"], BodyState.RETURNED);
});

test("an async guarded node that rejects records a raised outcome", async () => {
  const g = supervisorV2();
  const node = guardNode(
    g,
    "crm.read",
    async (_state: { rows: number }) => {
      throw new TypeError("async boom");
    },
    { contextFn: () => ({ rows: 1 }) },
  );
  await assert.rejects(() => node({ rows: 1 }), TypeError);
  const outcome = g.auditLog().entries.find((e) => e["event"] === "outcome")!;
  assert.equal(outcome["body_state"], BodyState.RAISED);
  assert.equal(outcome["error_code"], "TypeError");
});

test("a v1 guard's guarded node gets no callId or outcome", () => {
  const g = supervisor(); // schemaVersion: 1 (the default)
  const node = guardNode(g, "crm.read", (_state: { rows: number }) => ({ ok: true }), {
    contextFn: (state: { rows: number }) => ({ rows: state.rows }),
  });
  node({ rows: 1 });
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  assert.equal("call_id" in allow, false);
  assert.equal("capture" in allow, false);
  assert.deepEqual(entries.filter((e) => e["event"] === "outcome"), []);
});

test("a sync guarded tool's invoke also records an outcome", () => {
  const g = supervisorV2();
  const guarded = guardTool(g, fakeTool("crm_query", (input: any) => `read ${input?.limit ?? 0} rows`), {
    scope: "crm.read",
  });
  const result = guarded.invoke({ limit: 5 });
  assert.equal(result, "read 5 rows");
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  assert.equal(allow["capture"], Capture.WRAPPER_SYNC);
  assert.equal(outcome["body_state"], BodyState.RETURNED);
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
});

test("an async guarded tool's invoke uses wrapperAsync capture and still records", async () => {
  const g = supervisorV2();
  const guarded = guardTool(
    g,
    fakeTool("crm_query", async (input: any) => `read ${input?.limit ?? 0} rows`),
    { scope: "crm.read" },
  );
  const result = await guarded.invoke({ limit: 5 });
  assert.equal(result, "read 5 rows");
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  assert.equal(allow["capture"], Capture.WRAPPER_ASYNC);
  assert.equal(outcome["body_state"], BodyState.RETURNED);
});

test("a denied guarded-tool call with onDenied never records an outcome", () => {
  const g = supervisorV2();
  const guarded = guardTool(g, fakeTool("wire_money"), {
    scope: "payments.send",
    onDenied: (decision) => `refused: ${decision.explain()}`,
  });
  const result = guarded.invoke({});
  assert.match(String(result), /^refused: denied: scope_not_granted/);
  assert.deepEqual(g.auditLog().entries.filter((e) => e["event"] === "outcome"), []);
});

// =============================================================================================
// merge-gate item 3: honest boundary capture — a snapshot taken BEFORE invocation, deferred
// results, and cancellation. "An async callable object" (an instance whose __call__ is async) is
// NOT ported: JavaScript has no equivalent — invocation via `fn(...)` requires `fn` to literally
// be a function, unlike Python where any object can make itself callable via `__call__`, so
// GuardOptions' `fn` type already rules this case out structurally.
// =============================================================================================

test("a callable that mutates its own input does not cause a params mismatch", () => {
  const g = supervisorV2();
  const received: { seen?: unknown } = {};
  const node = guardNode(
    g,
    "crm.read",
    (payload: { original: boolean; mutated?: boolean }, rows: number) => {
      received.seen = { ...payload };
      payload.mutated = true; // mutate the wrapper's own input in place
      return { ok: true };
    },
    { contextFn: (_payload: unknown, rows: number) => ({ rows }) },
  );
  const arg: { original: boolean; mutated?: boolean } = { original: true };
  node(arg, 1);
  assert.deepEqual(received.seen, { original: true }); // the body saw it BEFORE mutation
  assert.equal(arg.mutated, true); // the mutation still happened
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  // both hashes come from the SAME pre-invocation snapshot -- no false mismatch
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
});

test("a generator return value is reported deferred, not returned", () => {
  const g = supervisorV2();
  const node = guardNode(
    g,
    "crm.read",
    function* (): Generator<number> {
      yield 1;
      yield 2;
    },
    { contextFn: () => ({ rows: 1 }) },
  );
  const result = node();
  assert.deepEqual([...(result as Iterable<number>)], [1, 2]); // the generator itself still works
  const outcome = g.auditLog().entries.find((e) => e["event"] === "outcome")!;
  assert.equal(outcome["body_state"], BodyState.DEFERRED);
});

test("async cancellation via AbortController is reported abandoned and still propagates", async () => {
  const g = supervisorV2();
  const node = guardNode(
    g,
    "crm.read",
    async (signal: AbortSignal) => {
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason));
      });
      return { ok: true }; // never reached
    },
    { contextFn: () => ({ rows: 1 }) },
  );
  const controller = new AbortController();
  const promise = node(controller.signal);
  controller.abort();
  await assert.rejects(
    () => promise,
    (err: unknown) => err instanceof Error && err.name === "AbortError",
  );
  const outcome = g.auditLog().entries.find((e) => e["event"] === "outcome")!;
  assert.equal(outcome["body_state"], BodyState.ABANDONED);
  assert.equal("error_code" in outcome, false);
});

test("a v1 guard's guarded async node stays sync and returns an unawaited promise", async () => {
  const g = supervisor(); // schemaVersion: 1 (the default)
  const node = guardNode(g, "crm.read", async (state: { rows: number }) => ({ ok: true, rows: state.rows }), {
    contextFn: (state: { rows: number }) => ({ rows: state.rows }),
  });
  assert.notEqual(node.constructor.name, "AsyncFunction"); // not itself an async function
  const result = node({ rows: 1 });
  assert.ok(result instanceof Promise); // ...that returned an unawaited promise
  assert.deepEqual(await result, { ok: true, rows: 1 });
});

// =================================================================================================
// A parallel adversarial review, TS mirror of the Python batch-2 pass: freeze()'s own aliasing-
// safety invariant when structuredClone cannot itself clone the value being snapshotted, and both
// wrappers' own wiring into it.
// =================================================================================================

test("freeze never aliases a live mutable object, even one it must stringify", () => {
  const mutable: { note: string; mutated?: boolean } = { note: "before" };
  const raw = { args: [mutable, () => {}] }; // the function has no plain-JSON shape to rebuild
  const frozen = freeze(raw) as { args: unknown[] };
  assert.notEqual(frozen.args[0], mutable); // NOT the same reference
  assert.deepEqual(frozen.args[0], { note: "before" }); // captured the pre-mutation shape
  mutable.mutated = true;
  assert.deepEqual(frozen.args[0], { note: "before" }); // unaffected by the later mutation
});

test("freeze never aliases a mutable value's SIBLING that must itself be stringified (the mixed case)", () => {
  // A value with no plain-JSON shape (the function) sits alongside a SEPARATE, otherwise
  // perfectly rebuildable MUTABLE sibling in the same object graph. The sibling must not be
  // silently aliased just because something ELSE in the same structure needed stringifying.
  const sibling: { count: number } = { count: 1 };
  const unclonable = () => {};
  const frozen = freeze({ sibling, unclonable }) as { sibling: unknown };
  assert.notEqual(frozen.sibling, sibling);
  assert.deepEqual(frozen.sibling, { count: 1 });
  sibling.count = 999;
  assert.deepEqual(frozen.sibling, { count: 1 });
});

test("freeze guards a circular reference instead of looping forever", () => {
  const circular: { self?: unknown } = {};
  circular.self = circular;
  const frozen = freeze(circular) as { self: unknown };
  assert.equal(frozen.self, "<circular>");
});

test("freeze does NOT mislabel a DAG's repeated sibling reference as circular", () => {
  // Release-gate correction: an earlier revision of freeze() shared ONE mutable WeakSet across
  // the whole call (added to, never removed), so the SAME object appearing twice as SIBLING
  // values -- not as its own ancestor -- was wrongly reported "<circular>" on its second
  // occurrence. Reproduced directly before fixing: freeze({a: shared, b: shared}) came back
  // {"a": {...}, "b": "<circular>"}. Fixed with a PATH-ACTIVE set (a fresh Set unioned in at
  // each recursive call, never mutated in place or shared across branches).
  const shared = { x: 1 };
  const dag = { a: shared, b: shared };
  const frozen = freeze(dag) as { a: unknown; b: unknown };
  assert.deepEqual(frozen.a, { x: 1 });
  assert.deepEqual(frozen.b, { x: 1 });
  assert.notEqual(frozen.b, "<circular>");
});

test("a guarded node with an unclonable argument still authorizes, runs, and commits a real hash", () => {
  const g = supervisorV2();
  const node = guardNode(
    g,
    "crm.read",
    (payload: { note: string; mutated?: boolean }, _cb: () => void) => {
      payload.mutated = true; // mutate the wrapper's own input in place, same as the existing test above
      return { ok: true };
    },
    { contextFn: () => ({ rows: 1 }) },
  );
  const arg = { note: "before" };
  const result = node(arg, () => {}); // the function is stringified rather than crashing anything
  assert.deepEqual(result, { ok: true });
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  // freeze() sanitizes the unclonable value to a safe string BEFORE it is ever handed to the
  // hash commitment, so -- unlike the pre-fix bare shallow-copy fallback, which left the raw
  // function value in place for the commitment to reject -- a real hash is committed here, not
  // paramsHashReason: "unsupported".
  assert.ok(allow["authorized_params_hash"]);
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
  assert.equal("params_hash_reason" in allow, false);
});

test("a guarded tool with an unclonable argument still authorizes, runs, and commits a real hash", () => {
  const g = supervisorV2();
  const guarded = guardTool(g, fakeTool("crm_query", (input: any) => ({ rows: input.rows })), {
    scope: "crm.read",
    contextFn: (input: any) => ({ rows: toolArgs(input).rows }),
  });
  const result = guarded.invoke({ rows: 5, cb: () => {} }); // the function is stringified rather than crashing anything
  assert.deepEqual(result, { rows: 5 });
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  assert.ok(allow["authorized_params_hash"]);
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
  assert.equal("params_hash_reason" in allow, false);
});

test("freeze keeps a JSON.parse-created own __proto__ key as a data property, not a prototype", () => {
  // Delta review (medium-low, required): the naive `out[k] = v` accumulation loop in an
  // earlier revision of freeze() did not create a data property for the key name
  // "__proto__" -- it set the accumulator's OWN [[Prototype]] instead, via Object.prototype's
  // own __proto__ accessor, so the key silently vanished from the rebuilt object's own
  // enumerable keys. A plain JSON.parse('{"__proto__": {...}}') result genuinely has
  // "__proto__" as an own, enumerable DATA property (JSON has no notion of prototypes), so
  // this is reachable from ordinary untrusted input, not a contrived attack shape.
  const parsed = JSON.parse('{"__proto__": {"polluted": true}, "note": "sibling"}');
  const raw = { data: parsed, cb: () => {} }; // the function has no plain-JSON shape, so it is stringified
  const frozen = freeze(raw) as { data: Record<string, unknown> };
  assert.deepEqual(Object.keys(frozen.data), ["__proto__", "note"]);
  assert.equal(Object.prototype.hasOwnProperty.call(frozen.data, "__proto__"), true);
  assert.deepEqual(frozen.data["__proto__"], { polluted: true });
  assert.equal(Object.getPrototypeOf(frozen.data), Object.prototype); // not polluted
});

test("freeze densifies a sparse array's holes instead of preserving them as holes", () => {
  // Delta review (nit): Array.prototype.map SKIPS a hole rather than visiting it, so a sparse
  // array's hole would survive into the "snapshot" as a hole too, unlike every other absent
  // value freeze() turns into a plain null.
  const sparse = [1, , 3] as unknown[]; // eslint-disable-line no-sparse-arrays
  const frozen = freeze(sparse) as unknown[];
  assert.deepEqual(frozen, [1, null, 3]);
  assert.equal(1 in frozen, true); // a real (densified) element, not a hole
});

// =================================================================================================
// Release-gate finding 2 (CRITICAL) and finding 3 (HIGH): freeze() must run UNCONDITIONALLY on
// every snapshot path, not only when structuredClone throws, and must never invoke a value's own
// protocols (iterators, getters). Each scenario below is verified through the REAL wrapper
// (guardNode/guardTool), not freeze() called directly -- the earlier circular test guarded the
// wrong path: it passed even while the actual wrapper crashed, because structuredClone succeeded
// on a circular input and freeze() was never reached at all.
// =================================================================================================

test("a guarded node with a circular argument does not crash, and commits a real hash", () => {
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", (_payload: unknown) => ({ ok: true }), {
    contextFn: () => ({ rows: 1 }),
  });
  const circular: { note: string; self?: unknown } = { note: "x" };
  circular.self = circular;

  const result = node(circular);

  assert.deepEqual(result, { ok: true });
  const allow = g.auditLog().entries.find((e) => e["event"] === "allow")!;
  assert.ok(allow["authorized_params_hash"]);
  assert.equal("params_hash_reason" in allow, false);
});

test("a guarded node with a sparse array argument densifies it and commits a real hash", () => {
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", (rows: unknown[]) => ({ len: rows.length }), {
    contextFn: () => ({ rows: 1 }),
  });

  const result = node([1, , 3] as unknown[]); // eslint-disable-line no-sparse-arrays

  assert.deepEqual(result, { len: 3 });
  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  // Densified through structuredClone's SUCCESS path (a sparse array clones fine, preserving
  // holes) -- unlike the pre-fix code, where freeze()'s own densification never ran at all here
  // because it was gated behind a structuredClone failure that a sparse array never causes.
  assert.ok(allow["authorized_params_hash"]);
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
  assert.equal("params_hash_reason" in allow, false);
});

test("a guarded node with a hostile custom iterator on its array argument is not fooled by it", () => {
  // structuredClone would have succeeded on this array too (it clones the REAL indexed data,
  // ignoring a custom Symbol.iterator override, since native cloning does not use the iteration
  // protocol either) -- but the OLD freeze() fallback, had it ever been reached, used
  // Array.from/.map, which DOES invoke the iterator. This test pins that the wrapper commits a
  // snapshot of the array's real contents, not whatever a hostile iterator claims they are.
  const g = supervisorV2();
  const seen: unknown[] = [];
  const node = guardNode(
    g,
    "crm.read",
    (arr: number[]) => {
      seen.push([...arr]); // read via a FRESH spread inside the body, independent of freeze()
      return { ok: true };
    },
    { contextFn: () => ({ rows: 1 }) },
  );

  const hostile = [1, 2, 3];
  (hostile as any)[Symbol.iterator] = function* () {
    yield 999; // a hostile override: nothing like the array's real contents
  };

  node(hostile);

  assert.deepEqual(seen[0], [999]); // the body itself DOES see the hostile iterator's lie --
  // that is JavaScript's own semantics for spreading a hostile iterable, not this adapter's
  // concern. What this adapter must get right is its OWN commitment:
  const allow = g.auditLog().entries.find((e) => e["event"] === "allow")!;
  assert.ok(allow["authorized_params_hash"]);
  assert.equal("params_hash_reason" in allow, false);
});

test("a guarded tool with a getter argument never invokes it, and encodes it as an accessor", () => {
  const g = supervisorV2();
  let getterCalls = 0;
  const withGetter: Record<string, unknown> = {};
  Object.defineProperty(withGetter, "secret", {
    get() {
      getterCalls++;
      return "leaked";
    },
    enumerable: true,
  });
  const guarded = guardTool(g, fakeTool("crm_query", () => ({ ok: true })), {
    scope: "crm.read",
    contextFn: () => ({ rows: 1 }),
  });

  guarded.invoke(withGetter);

  // The getter is NEVER invoked across the whole authorize-through-outcome call -- not once,
  // let alone the three observations the old Object.entries-based fallback could produce.
  assert.equal(getterCalls, 0);
  const allow = g.auditLog().entries.find((e) => e["event"] === "allow")!;
  assert.ok(allow["authorized_params_hash"]);
});

test("a guarded node with a SharedArrayBuffer argument never aliases its backing memory", () => {
  // structuredClone "succeeding" on a SharedArrayBuffer produces a DISTINCT wrapper object that
  // shares the SAME underlying memory, by design -- not independence at all. freeze() never
  // calls structuredClone (or anything else) on it; it is stringified like any other value with
  // no plain-JSON shape.
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", (_buf: SharedArrayBuffer) => ({ ok: true }), {
    contextFn: () => ({ rows: 1 }),
  });

  const sab = new SharedArrayBuffer(8);
  node(sab);

  const allow = g.auditLog().entries.find((e) => e["event"] === "allow")!;
  assert.ok(allow["authorized_params_hash"]);
});

test("a guarded node with a JSON.parse-created __proto__ argument commits a real hash", () => {
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", (payload: { rows: number }) => ({ ok: true }), {
    contextFn: (payload: { rows: number }) => ({ rows: payload.rows }),
  });

  const parsed = JSON.parse('{"__proto__": {"polluted": true}, "rows": 1}');
  node(parsed);

  const entries = g.auditLog().entries;
  const allow = entries.find((e) => e["event"] === "allow")!;
  const outcome = entries.find((e) => e["event"] === "outcome")!;
  assert.ok(allow["authorized_params_hash"]);
  assert.equal(allow["authorized_params_hash"], outcome["invoked_params_hash"]);
});

test("a plain async-iterable result (no own .next) is reported deferred, not returned", () => {
  // Release-gate finding 6 (HIGH): isDeferredResult required an own `.next` method on the
  // result itself, matching a self-iterating async generator -- but the JavaScript async-
  // iterable protocol only requires a callable `[Symbol.asyncIterator]()`, which can return a
  // SEPARATE object that has `.next`, without the iterable itself ever having one. Reproduced
  // directly before fixing: this exact shape recorded body_state "returned".
  const g = supervisorV2();
  const node = guardNode(
    g,
    "crm.read",
    () => ({
      [Symbol.asyncIterator]() {
        let i = 0;
        return {
          next: async () => (i++ < 2 ? { done: false, value: i } : { done: true, value: undefined }),
        };
      },
    }),
    { contextFn: () => ({ rows: 1 }) },
  );

  node();

  const outcome = g.auditLog().entries.find((e) => e["event"] === "outcome")!;
  assert.equal(outcome["body_state"], BodyState.DEFERRED);
});

test("a plain array result is NOT misdetected as deferred just because it is iterable", () => {
  // The flip side of the fix above: Array/Set/Map all implement Symbol.iterator too, but their
  // contents are already fully computed -- nothing deferred about returning one. Dropping the
  // own-.next requirement on the SYNC branch (the same way the async branch's requirement was
  // dropped) would have caused exactly this false positive; this test pins that the sync branch
  // was deliberately left alone.
  const g = supervisorV2();
  const node = guardNode(g, "crm.read", () => [1, 2, 3], { contextFn: () => ({ rows: 1 }) });

  node();

  const outcome = g.auditLog().entries.find((e) => e["event"] === "outcome")!;
  assert.equal(outcome["body_state"], BodyState.RETURNED);
});
