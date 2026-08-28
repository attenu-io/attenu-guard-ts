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
import { Decision, ReasonCode } from "../src/reasons.js";

function supervisor(): Guard {
  return Guard.issue(
    "supervisor",
    new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(1000)], ttl: 3600 }),
    { chainId: "lg", task: "quarterly review" },
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
