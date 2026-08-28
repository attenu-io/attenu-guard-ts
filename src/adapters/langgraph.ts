/**
 * adapters/langgraph.ts — a thin LangGraph.js integration.
 *
 * The adapter is built in two layers, the same shape as the Python one:
 *
 *   1. The AUTHORIZATION-WRAPPING LOGIC is plain TypeScript. It wraps an
 *      arbitrary callable so that every call is authorized through a `Guard`
 *      first, and it does not import, require or reference `@langchain/langgraph`
 *      at all. That is deliberate: a LangGraph node is, by LangGraph's own
 *      convention, just a callable — `(state) => partialState` — so wrapping
 *      "any callable" is enough to wrap a node or a plain tool function alike,
 *      and it keeps the logic testable with no framework installed.
 *
 *   2. The one spot that touches the package itself (`isLangGraphAvailable`)
 *      imports it lazily. `addGuardedNode` takes an already-constructed graph
 *      and only calls `.addNode(name, callable)` on it, so it needs no import
 *      either.
 *
 * ## Which hook this uses, and why
 *
 * The Python adapter wraps node callables. LangGraph.js has no public
 * before-tool-call hook: `ToolNode` resolves the tool itself and invokes it at
 * `dist/prebuilt/tool_node.js:207` (`const output = await tool.invoke(toolCall,
 * runtime)`), inside a `protected runTool`. So this adapter takes the
 * TOOL-WRAPPING form: `guardTool` returns a stand-in for a tool object whose
 * `invoke` authorizes first and calls through only on an allow. The stand-in
 * keeps the original `name`, `description` and `schema`, which is all `ToolNode`
 * looks at when it matches a tool call to a tool, so a wrapped tool drops
 * straight into `new ToolNode([...])` or `createReactAgent({tools})`.
 *
 * A denial throws `AuthorityDenied` — the same error `Guard.enforce` throws —
 * BEFORE the tool body runs, so a poisoned instruction or a runaway plan never
 * reaches the call it is not authorized to make. A graph can catch it around
 * `graph.invoke(...)`, or route around it with LangGraph's own error handling;
 * this adapter does not prescribe which. It guarantees only that the tool body
 * never executes on a denial.
 *
 * ## Delegation
 *
 * Handing work to a sub-agent is the delegation moment. `delegateTo` mints the
 * child `Guard` at the handoff — before the sub-agent's graph is invoked — so
 * the sub-agent's tools are guarded by an authority that is provably a subset of
 * the parent's.
 *
 *     const researcher = delegateTo(supervisor, {
 *       agentId: "researcher",
 *       request: new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(500)], ttl: 900 }),
 *       task: "summarise the Q3 pipeline",
 *     });
 *     const tools = guardTools(researcher, [crmQuery], { scopes: { crm_query: "crm.read" } });
 */

import { AuthorityDenied, type Guard } from "../guard.js";
import type { Authority } from "../authority.js";
import type { Context } from "../ceilings.js";
import type { Decision } from "../reasons.js";

/** Options shared by every guarded wrapper. */
export interface GuardOptions {
  /**
   * Called with the exact arguments the wrapped callable received; returns the
   * context for `guard.check`, e.g. `{rows: 5000, egress: "none"}`. Omitted
   * means an empty context — fine for a scope-only check.
   */
  contextFn?: (...args: any[]) => Context;
  /** The `tool` label recorded on the ledger. Defaults to the callable's name. */
  tool?: string | null;
  /** What the caller knows about why this scope would be absent. */
  disposition?: string | null;
  /** Marks the call as consuming a metered resource. */
  metered?: boolean;
}

/** A callable node, with the guard and scope it was wrapped with attached. */
export type GuardedNode<F extends (...args: any[]) => any> = F & {
  readonly guard: Guard;
  readonly toolScope: string;
  readonly unwrapped: F;
};

/**
 * Wrap a callable so every call is authorized through `guard` first.
 *
 * On call: the context is `contextFn(...args)` if given, else `{}`; then
 * `guard.check(toolScope, {context, tool})`. On a denial this throws
 * `AuthorityDenied` and the wrapped callable is NEVER invoked. Otherwise it
 * calls through with the original arguments and returns the result unchanged —
 * including a promise, which is passed along untouched.
 *
 * Use the Guard for the SPECIFIC agent this callable belongs to, not the
 * orchestrator's broader one, so a denial reflects that node's real, narrowed
 * authority.
 */
export function guardNode<F extends (...args: any[]) => any>(
  guard: Guard,
  toolScope: string,
  fn: F,
  options: GuardOptions = {},
): GuardedNode<F> {
  const resolvedTool = options.tool !== undefined ? options.tool : (fn.name || null);

  const wrapped = function (this: unknown, ...args: any[]) {
    const context: Context = options.contextFn ? options.contextFn(...args) : {};
    const decision = guard.check(toolScope, {
      context,
      tool: resolvedTool,
      disposition: options.disposition ?? null,
      metered: options.metered ?? false,
    });
    if (!decision.allowed) throw new AuthorityDenied(decision);
    return fn.apply(this, args);
  } as GuardedNode<F>;

  Object.defineProperties(wrapped, {
    name: { value: fn.name, configurable: true },
    guard: { value: guard, enumerable: true },
    toolScope: { value: toolScope, enumerable: true },
    unwrapped: { value: fn, enumerable: true },
  });
  return wrapped;
}

/** The minimum a LangGraph.js graph needs to expose for `addGuardedNode`. */
export interface GraphLike {
  addNode(name: string, action: (...args: any[]) => any, ...rest: any[]): unknown;
}

/**
 * Build the guarded wrapper and register it on a graph in one call.
 *
 * `graph` is structurally typed: it only needs `.addNode(name, callable)`,
 * which is `StateGraph`'s real signature — so this helper needs no import of
 * its own and stays testable against a plain stand-in graph.
 */
export function addGuardedNode<F extends (...args: any[]) => any>(
  graph: GraphLike,
  name: string,
  guard: Guard,
  toolScope: string,
  fn: F,
  options: GuardOptions = {},
): GuardedNode<F> {
  const node = guardNode(guard, toolScope, fn, options);
  graph.addNode(name, node);
  return node;
}

/** The shape `ToolNode` requires of a tool: a name and an `invoke`. */
export interface ToolLike {
  name: string;
  invoke(input: any, config?: any): any;
  [key: string]: any;
}

export interface GuardToolOptions extends GuardOptions {
  /** The scope this tool needs. Defaults to the tool's own name. */
  scope?: string;
  /**
   * Called when the guard denies the call, instead of throwing. Return the
   * value the tool should yield — e.g. a `ToolMessage` explaining the refusal,
   * so the model can see the denial and re-plan rather than the run aborting.
   */
  onDenied?: (decision: Decision, input: any) => any;
}

/**
 * Return a stand-in for `tool` whose `invoke` authorizes through `guard` before
 * the tool body runs. Everything else — `name`, `description`, `schema`, any
 * LangChain internals — is forwarded to the original, so `ToolNode` matches and
 * runs it exactly as it would the unwrapped tool.
 *
 * The context function receives the raw invoke arguments. `ToolNode` passes a
 * tool call object, so the arguments the model proposed are at `input.args`;
 * a direct `tool.invoke({...})` passes them at the top level. `toolArgs` below
 * reads either shape.
 */
export function guardTool<T extends ToolLike>(
  guard: Guard,
  tool: T,
  options: GuardToolOptions = {},
): T {
  const scope = options.scope ?? tool.name;
  const label = options.tool !== undefined ? options.tool : tool.name;

  const guardedInvoke = (input: any, config?: any) => {
    const context: Context = options.contextFn ? options.contextFn(input, config) : {};
    const decision = guard.check(scope, {
      context,
      tool: label,
      disposition: options.disposition ?? null,
      metered: options.metered ?? false,
    });
    if (!decision.allowed) {
      if (options.onDenied) return options.onDenied(decision, input);
      throw new AuthorityDenied(decision);
    }
    return tool.invoke(input, config);
  };

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") return guardedInvoke;
      if (prop === ATTENU_GUARD) return guard;
      if (prop === ATTENU_SCOPE) return scope;
      const value: unknown = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? (value as (...a: any[]) => any).bind(target) : value;
    },
  }) as T;
}

/** Marker properties, so a caller can tell a guarded tool from a bare one. */
export const ATTENU_GUARD = "__attenuGuard";
export const ATTENU_SCOPE = "__attenuScope";

export interface GuardToolsOptions extends GuardOptions {
  /** Tool name -> scope. A tool absent from the map uses its own name. */
  scopes?: Record<string, string>;
  /** Tool name -> context function, overriding the shared `contextFn`. */
  contexts?: Record<string, (input: any, config?: any) => Context>;
  onDenied?: (decision: Decision, input: any) => any;
}

/**
 * Guard a whole tool list in one call — what you hand to `new ToolNode([...])`
 * or `createReactAgent({tools})`.
 */
export function guardTools<T extends ToolLike>(
  guard: Guard,
  tools: readonly T[],
  options: GuardToolsOptions = {},
): T[] {
  return tools.map((t) =>
    guardTool(guard, t, {
      scope: options.scopes?.[t.name] ?? t.name,
      contextFn: options.contexts?.[t.name] ?? options.contextFn,
      disposition: options.disposition ?? null,
      metered: options.metered ?? false,
      onDenied: options.onDenied,
    }),
  );
}

/**
 * The arguments a tool call carries, whichever shape `invoke` was handed.
 * `ToolNode` passes `{name, args, id, type}`; a direct call passes the args
 * themselves. Useful inside a `contextFn`.
 */
export function toolArgs(input: any): Record<string, any> {
  if (input !== null && typeof input === "object" && "args" in input && !Array.isArray(input)) {
    const args = (input as { args: unknown }).args;
    if (args !== null && typeof args === "object") return args as Record<string, any>;
  }
  return (input ?? {}) as Record<string, any>;
}

export interface DelegateOptions {
  agentId: string;
  request: Authority;
  task: string;
}

/**
 * Mint the child Guard for a sub-agent handoff. Handing work to a sub-agent IS
 * the delegation moment: call this before the sub-agent's graph is invoked, so
 * its tools are guarded by an authority that is provably a subset of the
 * parent's. A request wider than the parent holds comes back narrowed.
 *
 * Throws `AuthorityError` if the handoff is structurally refused — the parent
 * is revoked or expired, the agent is banned, or the chain's depth or fanout
 * ceiling would be exceeded.
 */
export function delegateTo(parent: Guard, options: DelegateOptions): Guard {
  return parent.delegate(options.agentId, options.request, options.task);
}

/**
 * True iff `@langchain/langgraph` is importable here. The import is lazy and
 * happens only when this is called, so merely importing this adapter — or using
 * `guardNode` / `guardTool` — never requires LangGraph to be installed.
 */
export async function isLangGraphAvailable(): Promise<boolean> {
  const specifier = "@langchain/langgraph";
  try {
    await import(specifier);
    return true;
  } catch {
    return false;
  }
}
