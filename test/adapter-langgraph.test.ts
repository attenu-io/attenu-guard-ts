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
