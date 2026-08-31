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
 * ## Execution binding (0.9.0, reference wiring for this adapter)
 *
 * When `guard`'s chain was issued with `schemaVersion: 2` (see `Guard.issue`), `guardNode` also
 * passes `capture`/`adapter`/`authorizedParams` to `check` and calls `guard.recordOutcome` once
 * the wrapped callable finishes — `Capture.WRAPPER_ASYNC` when `fn` is a genuine `async function`
 * (`fn.constructor.name === "AsyncFunction"`, the same test Python's `inspect.iscoroutinefunction`
 * makes), `Capture.WRAPPER_SYNC` otherwise. `authorizedParams`/`invokedParams` are
 * `{args: [...]}` built from exactly what the wrapped callable is called with — JavaScript has no
 * separate `kwargs`, so unlike the Python adapter's `{args, kwargs}` this carries only `args`; a
 * LangGraph.js node in any case receives one state object, not Python's `(*args, **kwargs)`. They
 * are unchanged between the two observations here, since this decorator itself never mutates
 * them; a framework that DOES mutate arguments between authorization and invocation is where a
 * real substitution would become visible. On a `schemaVersion: 1` chain (the default), this
 * adapter behaves exactly as it did before 0.9.0: no `capture`/`authorizedParams`, no
 * `recordOutcome` call. Every other framework adapter is unchanged in this release.
 *
 * ## Adversarial review: the Python batch-1/batch-2 defect classes, checked against this
 * adapter specifically (not assumed absent by analogy)
 *
 * The Python `attenu-guard` adapters went through two rounds of adversarial review that found
 * several defect classes across their (many) framework adapters. This TS package ships exactly
 * ONE adapter surface (this file — verified against `package.json`'s own `exports` map, which
 * declares nothing besides `.` and `./adapters/langgraph`), so each class was checked against
 * THIS adapter specifically, not inherited by assumption:
 *
 * - **Composable middleware / sibling short-circuit or retry** (a sibling wrapper positioned
 *   closer to the tool body than this one, able to fabricate or repeat what it observes) — NOT
 *   APPLICABLE. Verified directly against pinned `@langchain/core@1.2.9` and
 *   `@langchain/langgraph@1.4.13` (installed and grepped, not read off documentation): zero
 *   `"middleware"` hits anywhere near tool invocation in either package, and
 *   `ToolNode.prototype.runTool` (`dist/prebuilt/tool_node.js`) calls `tool.invoke(toolCall,
 *   runtime)` directly — `guardTool`'s `Proxy` IS what gets called, nothing sits between it and
 *   `ToolNode`. Neither framework has a composable per-call hook chain the way LangChain-Python's
 *   `create_agent(middleware=[...])` or AG2's `FunctionTool.register()` do.
 * - **Double authorization via a second, independent gate** (e.g. Python's `claude_sdk`
 *   adapter's `can_use_tool` calling `authorize()` a second time for the same call) — NOT
 *   APPLICABLE. There is no second entry point here: `guardNode`/`guardTool` are each the ONLY
 *   caller-facing wrapper for their call, and there is nothing in either framework analogous to
 *   a second permission callback for a call this adapter already gated.
 * - **Snapshot double-evaluation / narrow-projection commitment** — NOT APPLICABLE in the
 *   double-evaluation shape (`snapshotParams`/`snapshotToolParams` already compute ONE snapshot,
 *   reused unchanged for both `authorizedParams` and `invokedParams`), but a DIFFERENT,
 *   TS-specific gap in the same family was found and fixed — see `freeze()`'s own doc comment
 *   above and the CHANGELOG.
 * - **Correlation-key collision across hooks** (e.g. Python's `claude_sdk` `tool_use_id`
 *   collision) — NOT APPLICABLE. `guard.recordOutcome` is called synchronously inside the same
 *   closure that owns the whole call, from `authorize()`'s own returned `Decision.callId` — no
 *   external pending-map keyed by a framework-supplied correlation id exists to collide on.
 * - **Lazy-result detection gaps** (e.g. Python's `smolagents` adapter missing a coroutine or a
 *   `concurrent.futures.Future`) — `isDeferredResult` catches generators (an object with its own
 *   `.next` AND `[Symbol.iterator]` — "self-iterating", the shape a native generator has, but
 *   deliberately NOT the shape a plain `Array`/`Set`/`Map` has, since those implement
 *   `[Symbol.iterator]` too without an own `.next`, and their contents are already fully
 *   computed), a genuine ASYNC ITERABLE (anything implementing a callable
 *   `[Symbol.asyncIterator]`, self-iterating async generators included — see the RELEASE-GATE
 *   CORRECTION on this function's own body for why this does NOT require an own `.next` the way
 *   the sync branch does), and anything thenable. A plain (non-`async`) function that manually
 *   returns a bare `Promise` is also caught correctly, via the thenable check, in the sync
 *   branch of both wrappers. This is NOT a claim of covering "the whole lazy-result landscape" —
 *   only what this function's own checks actually implement, listed above; a class implementing
 *   some OTHER deferred-consumption protocol this function does not check for would not be
 *   caught.
 * - **Lost-terminal-event / "fires unconditionally" false claims** (e.g. Python's `strands`
 *   adapter's before-hook interrupt paths) — NOT APPLICABLE. There is no external, multi-phase
 *   hook-dispatch loop for an event to be lost across; one wrapper function's own `try`/`catch`
 *   (or `await`ed async path) owns authorize-through-`recordOutcome` for the whole call
 *   synchronously. Structurally this adapter was already closest to Python's own `langgraph.py`
 *   reference wiring, not any of the adapters that needed this class of fix.
 * - **Unbounded correlation cache** (Python's `claude_sdk` `_recentVerdicts`) — NOT APPLICABLE,
 *   for the same reason as the correlation-collision point above: no cache or pending-map exists
 *   in this adapter to bound.
 * - **Wrong dependency declaration** (Python's `semantic-kernel` `protobuf` lesson: check what
 *   the RESOLVED version actually requires, not what is assumed) — checked: `src/` imports only
 *   `@langchain/langgraph` (lazily, in `isLangGraphAvailable()`); it never imports
 *   `@langchain/core` at all (only this file's own tests do, to build fixtures). `package.json`
 *   declares zero `dependencies` and no `peerDependencies` — matching the README's own "zero
 *   runtime dependencies" claim — and both `@langchain/core`/`@langchain/langgraph` are correctly
 *   `devDependencies`-only. Nothing this package's `src/` needs at runtime is undeclared.
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

import { types as nodeUtilTypes } from "node:util";

import { AuthorityDenied, type AdapterInfo, type Guard } from "../guard.js";
import type { Authority } from "../authority.js";
import type { Json } from "../canonical.js";
import type { Context } from "../ceilings.js";
import { BodyState, Capture, type Decision } from "../reasons.js";
import { VERSION } from "../version.js";

// `node:util`'s own Proxy check -- an internal engine-slot test, not a trapped operation (see
// `freeze()`'s doc comment). Aliased for a short, self-explanatory call site.
const isProxy = nodeUtilTypes.isProxy;

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
 * A private, freeze()-only sentinel for "could not be represented as a JSON leaf" — a Proxy, an
 * accessor property, a genuine cycle, a boxed primitive, a TypedArray, a function, or anything
 * else this module does not know how to rebuild as plain JSON. NEVER a JSON-representable
 * value (a string, `null`, …): a second release-gate finding showed a literal string sentinel
 * (`"<accessor>"`) genuinely COLLIDES — a real getter-bearing object and a plain object holding
 * the literal string `"<accessor>"` produced the IDENTICAL `authorizedParamsHash`, an
 * evidence-integrity ambiguity in a supposedly cryptographic commitment (two materially
 * different inputs, one commitment). A fresh, private `Symbol` cannot equal any real call
 * argument, so it cannot collide with one — and it makes the SAME degradation apply uniformly
 * everywhere this function cannot represent something, rather than inventing a new
 * JSON-shaped sentinel (with its own collision risk) per case.
 *
 * Declared as `Json` even though a `Symbol` is not one — a deliberate escape from that type's
 * nominal domain, not an oversight: `canonical.ts`'s own JCS `serialize()` already runtime-checks
 * `typeof` for exactly this reason (its switch handles `"undefined"`/`"bigint"`/`"symbol"`/
 * `"function"` despite `CJson`'s declared type not admitting any of them either), because the
 * type system cannot fully describe this module's actual runtime domain. Once this sentinel
 * reaches `params.ts`'s `commit()` — inside a plain object or array, same as any other frozen
 * leaf — `canonicalBytes` hits that `"symbol"` case, throws `UnsupportedTypeError`, and `commit()`
 * turns that into `paramsHashReason: "unsupported"` for the WHOLE params value, never a partial
 * or per-field one: there is no such thing as "this one nested field is unsupported," only
 * "this whole call's arguments are, or are not, representable."
 *
 * Exported for the same reason `freeze` itself is: not part of this adapter's semantic
 * contract, but its own tests need to assert directly that a given leaf became this exact
 * sentinel (by identity — nothing else can equal it) rather than inferring it indirectly.
 */
export const FREEZE_UNSUPPORTED = Symbol("attenu-guard:freeze-unsupported") as unknown as Json;
const UNSUPPORTED = FREEZE_UNSUPPORTED;

/**
 * A genuinely immutable, fully decoupled rebuild of `value` — the ONE, UNCONDITIONAL sanitizer
 * every snapshot in this adapter goes through. Safe JSON-primitive leaves
 * (`string`/`number`/`boolean`/`null`) pass through verbatim; plain objects and arrays are
 * rebuilt fresh, recursively, by inspecting their REAL own property descriptors directly
 * (`Object.getOwnPropertyDescriptor`), never by invoking anything the value itself controls (a
 * getter, an iterator, a copy protocol, a Proxy trap, a `toString`/`valueOf`/`Symbol.toPrimitive`
 * override); anything this function cannot represent becomes `UNSUPPORTED` (above) — never a
 * string, never the live object.
 *
 * RELEASE-GATE CORRECTION (CRITICAL): this used to run ONLY as a fallback, after
 * `structuredClone` had already been tried and had THROWN — the previous revision of this
 * comment documented that carefully, but never asked whether `structuredClone` SUCCEEDING was
 * itself a sufficient guarantee. It is not, on three counts, each reproduced directly before
 * that fix: (1) a circular object clones successfully — `structuredClone` handles cycles
 * natively — so this function never ran on it at all, and the circularity later reached
 * `params.ts`'s own cycle-guard-less hash walk and crashed with `RangeError`; (2) a sparse
 * array clones successfully too, bypassing this function's own densification; (3) a
 * `SharedArrayBuffer` clones to a DISTINCT wrapper object sharing the SAME underlying memory —
 * a "successful" clone that is not independent at all. Fixed by making this function the ONLY
 * snapshot path, unconditionally — `structuredClone` is not called anywhere in this adapter.
 *
 * A SECOND release-gate pass then found that "pure introspection" was not fully true either —
 * three more code-execution paths, all reproduced directly before this fix:
 *
 *   1. A `Proxy` is not inert under reflection. `Object.getPrototypeOf`, `Object.keys`
 *      (`[[OwnPropertyKeys]]` + a `[[GetOwnProperty]]` per key to check enumerability), and
 *      `Object.getOwnPropertyDescriptor` are each real, user-definable traps — reproduced
 *      directly: walking an ordinary handler-tracked Proxy through the OLD version of this
 *      function fired four separate traps before authorization was ever decided. `Array.isArray`
 *      is worse: called on a REVOKED Proxy, it throws `TypeError` outright (its spec algorithm,
 *      `IsArray`, unwraps `[[ProxyTarget]]`, which does not exist on a revoked handle) —
 *      reproduced directly. Fixed: `require("node:util").types.isProxy(value)` recognizes a
 *      Proxy — live OR revoked — via an internal engine slot, invoking NOTHING (verified
 *      directly: zero trap calls, no throw on a revoked handle either) — checked FIRST, before
 *      `Array.isArray` or any other reflection, and routed straight to `UNSUPPORTED`.
 *   2. The bottom fallback used `String(value)` for anything not a plain object/array — a boxed
 *      primitive (`new Number(...)`) with a hostile `Symbol.toPrimitive`, or a `TypedArray` with
 *      a hostile own `toString`, each ran attacker code exactly once per snapshot, reproduced
 *      directly both ways — BEFORE `Guard.check` had decided allow or deny. The same is true, in
 *      principle, of ANY object-typed exotic value (a function's own `.toString` is just as
 *      overridable) — there is no way to distinguish "safe to stringify" from "hostile" by
 *      inspection alone, so none of them are stringified any more. Fixed: every value that is
 *      not a safe JSON primitive and not a plain object/array — a Proxy, a boxed primitive, a
 *      TypedArray/`ArrayBuffer`/`SharedArrayBuffer`/`DataView`, a `Map`/`Set`/`Date`/`RegExp`, a
 *      function, a `Symbol`, a `BigInt`, anything else — becomes `UNSUPPORTED` (never `String()`,
 *      never any other protocol) — see the confirmed-good note above: stringification itself
 *      was never unsafe as a RESULT (a `SharedArrayBuffer` never retained live memory as a
 *      string), the defect was invoking attacker-controlled code to PRODUCE that string before
 *      authorization ran, and `UNSUPPORTED` avoids that entirely rather than picking a "safer"
 *      string.
 *   3. Any OTHER reflection failure — an exotic value this pass did not specifically anticipate,
 *      still throwing from `Object.getPrototypeOf`/`Object.keys`/`Object.getOwnPropertyDescriptor`
 *      despite the Proxy check above — must degrade the same way, not propagate an exception out
 *      of a snapshot taken before authorization. The whole reflective walk (everything past the
 *      Proxy/primitive fast paths) runs inside one `try`/`catch`; any throw there becomes
 *      `UNSUPPORTED` too.
 *
 * `active` is the PATH-ACTIVE cycle guard: the set of containers on the CURRENT recursion path,
 * passed as a NEW `Set` at each recursive call rather than mutated in place and shared across
 * sibling branches (an earlier revision DID share one mutable `WeakSet` across the whole call,
 * which meant a DAG's repeated reference — the SAME object appearing twice as sibling values,
 * never as its own ancestor — was wrongly flagged on its second occurrence; reproduced directly
 * before that fix too). A genuine cycle's own leaf value is `UNSUPPORTED`, not a literal string
 * `"<circular>"` — audited for the same collision class as `"<accessor>"` below, and it has the
 * identical problem: a self-referential object and a plain object holding the literal string
 * `"<circular>"` would otherwise produce the same commitment. There is no position-based reason
 * a cycle's collision is any less real than an accessor's, so it gets the same fix.
 *
 * The property-descriptor walk ALSO closes a separate, protocol-driven gap: the previous
 * revision used `Array.from`/`.map()` (which invoke `[Symbol.iterator]()` — a hostile array's
 * own override can yield ANYTHING regardless of its real indexed properties; reproduced
 * directly: `[1, , 3]` with a hostile iterator froze as `[999]`) and `Object.entries()` (which
 * reads each property's VALUE directly, invoking a getter if one is defined there — reproduced
 * directly: a getter with a side effect was observed three times across the old clone-attempt/
 * freeze/body sequence, and the committed snapshot was the SECOND of three observations, not the
 * first). `Object.getOwnPropertyDescriptor` and a `.length`-bounded index loop are pure
 * introspection — they never invoke user code — and an accessor property (`.get`/`.set` present)
 * becomes `UNSUPPORTED` rather than read at all: a getter can have arbitrary side effects, throw,
 * or return something different on every call, so there is no single "correct" observation of it
 * to commit, and (release-gate correction) the earlier `"<accessor>"` string sentinel this
 * function used instead genuinely collided — reproduced directly: a real getter-bearing object
 * and a plain object holding the literal string `"<accessor>"` produced the identical
 * `authorizedParamsHash`. Both now degrade the same commitment to `unsupported` via `UNSUPPORTED`
 * (see its own doc comment above), never a JSON-representable stand-in.
 *
 * Exported — not part of this adapter's semantic contract (it is an internal sanitizer, not a
 * feature callers configure), but its own aliasing-safety invariant is worth a direct unit
 * test in isolation, the same way every Python adapter's `_freeze()` is imported directly by
 * its own tests: the audit log never exposes the raw snapshot value it produces (only its
 * hash — see `params.ts`'s own doc comment), so "does this alias a live mutable object" is
 * not otherwise observable from outside this module.
 */
export function freeze(value: unknown, active: ReadonlySet<unknown> = new Set()): Json {
  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean") return value as Json;

  // A Proxy is recognized FIRST, before Array.isArray or ANY reflection -- see this function's
  // own doc comment, point 1. `util.types.isProxy` reads an internal engine slot; it invokes no
  // trap and does not throw even on a revoked Proxy (verified directly), unlike everything below
  // it, which would either fire real traps (a live Proxy) or throw outright (a revoked one).
  if (isProxy(value)) return UNSUPPORTED;

  try {
    if (Array.isArray(value)) {
      if (active.has(value)) return UNSUPPORTED; // a genuine cycle -- see doc comment above
      const withSelf = new Set(active).add(value);
      const out: Json[] = [];
      // Index-by-index via getOwnPropertyDescriptor, not Array.from/.map: those invoke
      // `[Symbol.iterator]()`, which a hostile array can override to yield ANYTHING regardless
      // of what its real indexed properties hold (reproduced directly: `[1, , 3]` with a
      // hostile iterator froze as `[999]`). `.length` and getOwnPropertyDescriptor are pure
      // introspection -- they read the array's REAL own properties without ever calling user
      // code. A hole (no descriptor at that index) is densified to `null`, same as any other
      // absence here.
      for (let i = 0; i < value.length; i++) {
        out.push(freezeDescriptor(Object.getOwnPropertyDescriptor(value, i), withSelf));
      }
      return out;
    }
    if (t === "object") {
      const proto = Object.getPrototypeOf(value);
      if (proto === Object.prototype || proto === null) {
        const obj = value as object;
        if (active.has(obj)) return UNSUPPORTED; // a genuine cycle -- see doc comment above
        const withSelf = new Set(active).add(obj);
        const out: Record<string, Json> = {};
        // Object.keys + getOwnPropertyDescriptor, not Object.entries: Object.entries reads each
        // property's VALUE directly, which invokes a getter if one is defined at that key --
        // reproduced directly: with an unclonable sibling forcing the old fallback, a getter
        // with a side effect was observed three times across the old clone-attempt/freeze/body
        // path, and the committed snapshot was the SECOND of three observations, not the first.
        // Reading the DESCRIPTOR instead never invokes anything; an accessor property
        // (`.get`/`.set` present, no `.value`) becomes `UNSUPPORTED` -- explicitly marked, never
        // executed -- rather than read (see `freezeDescriptor`). `Object.keys` correctly LISTS a
        // literal `"__proto__"` key (a plain `JSON.parse('{"__proto__": {...}}')` result has it
        // as an own, enumerable DATA property, same as any other key) -- the loop below still
        // needs `Object.defineProperty`, not a bracket assignment, to actually WRITE it back
        // safely.
        for (const key of Object.keys(obj)) {
          // Object.defineProperty, NOT `out[key] = ...`: a bracket ASSIGNMENT to the literal key
          // "__proto__" does not create a data property at all -- it invokes Object.prototype's
          // own `__proto__` SETTER, silently changing `out`'s prototype instead and dropping the
          // key from its own enumerable keys entirely. defineProperty always performs a genuine
          // [[DefineOwnProperty]], bypassing that accessor, for "__proto__" exactly like any
          // other key name.
          Object.defineProperty(out, key, {
            value: freezeDescriptor(Object.getOwnPropertyDescriptor(obj, key), withSelf),
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
        return out;
      }
    }
  } catch {
    // A reflection call above threw despite the Proxy check -- an exotic value this pass did
    // not specifically anticipate. Degrade the same way as everything else this function
    // cannot represent; never let a snapshot taken BEFORE authorization propagate an exception.
    return UNSUPPORTED;
  }

  // A boxed primitive (`new Number(...)`/`new String(...)`/`new Boolean(...)`), a TypedArray,
  // `ArrayBuffer`/`SharedArrayBuffer`/`DataView`, a `Map`/`Set`/`Date`/`RegExp`, a function, a
  // `Symbol`, a `BigInt`, or anything else that is not a plain object or array -- never
  // stringified any more (see this function's own doc comment, point 2: a hostile
  // `Symbol.toPrimitive`/`toString`/`valueOf` override runs attacker code before authorization
  // has been decided, reproduced directly for a boxed primitive and a TypedArray) and never the
  // live reference either. `UNSUPPORTED` degrades the whole commitment cleanly instead.
  return UNSUPPORTED;
}

/**
 * Reads ONE property descriptor safely: a data property's `.value` is frozen recursively; an
 * accessor property (`.get`/`.set` present) becomes `UNSUPPORTED` WITHOUT ever calling the
 * getter (a getter can have arbitrary side effects, throw, or return something different on
 * each call — there is no "correct" single observation to commit, and a JSON-representable
 * sentinel string genuinely collided with a real getter-bearing object's commitment — see
 * `UNSUPPORTED`'s own doc comment); a missing descriptor (an array hole, or a key that no
 * longer exists) becomes `null`, the same as any other JSON-shaped absence `freeze` produces
 * elsewhere.
 */
function freezeDescriptor(desc: PropertyDescriptor | undefined, active: ReadonlySet<unknown>): Json {
  if (desc === undefined) return null;
  if (desc.get || desc.set) return UNSUPPORTED;
  return freeze(desc.value, active);
}

/**
 * An IMMUTABLE snapshot of the call's arguments, taken BEFORE the wrapped callable runs and
 * reused for BOTH `authorizedParams` (`check`) and `invokedParams` (`recordOutcome`) — so a
 * callable that mutates its own inputs in place cannot make this adapter observe two different
 * values for what was actually one call's arguments (see the module doc comment's "Execution
 * binding" section; no `kwargs` — JavaScript has no separate keyword-argument bag).
 */
function snapshotParams(args: readonly unknown[]): Json {
  // freeze() unconditionally, not structuredClone-then-fallback: see freeze()'s own doc
  // comment's "RELEASE-GATE CORRECTION" for why a successful structuredClone is not itself a
  // sufficient independence guarantee (circular inputs, sparse arrays, SharedArrayBuffer).
  return freeze({ args: [...args] });
}

/**
 * `true` if `result` is a generator/async-generator/promise-like value whose consumption this
 * wrapper does not itself observe — spec's `deferred`: "the record covers the call, not the
 * eventual exhaustion." A promise counts too (the closest JavaScript analogue of Python's
 * `asyncio.Future`/`concurrent.futures.Future`): the async branch here already `await`s `fn`
 * itself, so a bare promise surfacing as `result` there means `fn` returned ANOTHER promise
 * without awaiting it, which is exactly the same "not actually consumed" situation.
 */
function isDeferredResult(result: unknown): boolean {
  if (result === null || typeof result !== "object") return false;
  const r = result as Record<PropertyKey, unknown>;
  // A native generator object (from `function*`) has BOTH `.next` AND `[Symbol.iterator]`
  // (returning itself) -- "self-iterating". Requiring both here deliberately does NOT match a
  // plain Array/Set/Map: those implement `[Symbol.iterator]` too, but the object ITSELF has no
  // `.next` (only the SEPARATE iterator `arr[Symbol.iterator]()` produces does) -- and an
  // array's contents are already fully computed, nothing deferred about returning one.
  if (typeof r["next"] === "function" && typeof r[Symbol.iterator] === "function") return true;
  // RELEASE-GATE CORRECTION (HIGH): the async branch used to require the SAME "has its own
  // .next" shape, matching a native async generator (self-iterating, same reasoning as above)
  // but missing the more general ASYNC ITERABLE protocol: per spec, `[Symbol.asyncIterator]`
  // being callable is sufficient on its own -- calling it returns a SEPARATE async iterator
  // object that has `.next`, so the ITERABLE itself need not. Reproduced directly before
  // fixing: a plain object implementing only `[Symbol.asyncIterator]()` was recorded
  // `BodyState.RETURNED`, not `DEFERRED`. Unlike the sync case, there is no common JavaScript
  // built-in that implements `Symbol.asyncIterator` over ALREADY-computed values the way a
  // plain Array does for `Symbol.iterator` (Node's own `Readable` streams implement it
  // precisely because their data is NOT all available yet), so checking `Symbol.asyncIterator`
  // alone does not risk the same false-positive class dropping the `.next` requirement here
  // would raise for the sync branch.
  if (typeof r[Symbol.asyncIterator] === "function") return true;
  if (typeof r["then"] === "function") return true;
  return false;
}

function bodyStateFor(result: unknown): string {
  return isDeferredResult(result) ? BodyState.DEFERRED : BodyState.RETURNED;
}

/**
 * `true` for the JavaScript analogue of Python's `asyncio.CancelledError`: an `AbortController`/
 * `AbortSignal`-driven abort, surfaced as a `DOMException`/`Error` named `"AbortError"` — the
 * standard shape Node and the Fetch/Web platform both use. There is no single universal async
 * cancellation exception type in JavaScript the way `asyncio.CancelledError` is in Python, so this
 * is the best-grounded, most widely applicable translation rather than a exact 1:1 port.
 */
function isAbortError(exc: unknown): boolean {
  return exc instanceof Error && exc.name === "AbortError";
}

/** The class/constructor name of a thrown value — JavaScript's nearest analogue of Python's `type(exc).__name__`. */
function errorCodeOf(exc: unknown): string {
  if (exc instanceof Error) return exc.constructor.name || "Error";
  if (exc === null) return "null";
  return typeof exc === "object" ? "object" : typeof exc;
}

function elapsedMs(start: number): number {
  return Math.round(performance.now() - start);
}

/**
 * Wrap a callable so every call is authorized through `guard` first.
 *
 * On call: the context is `contextFn(...args)` if given, else `{}`; then
 * `guard.check(toolScope, {context, tool})`. On a denial this throws
 * `AuthorityDenied` and the wrapped callable is NEVER invoked. Otherwise it
 * calls through with the original arguments and returns the result unchanged —
 * including a promise, which is passed along untouched. On a `schemaVersion: 2`
 * guard, also binds the call's outcome via `guard.recordOutcome` — see the
 * module doc comment's "Execution binding" section.
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
  const isAsyncFn = fn.constructor.name === "AsyncFunction";
  // guard.schemaVersion never changes for a guard's lifetime, so it is safe (and correct: a
  // wrapper's sync-vs-async SHAPE must be fixed at definition time, not per-call) to decide it
  // once, here, at decoration time.
  const v2 = guard.schemaVersion === 2;
  const capture = isAsyncFn ? Capture.WRAPPER_ASYNC : Capture.WRAPPER_SYNC;
  const adapterInfo: AdapterInfo = {
    module: "attenu-guard/adapters/langgraph",
    version: VERSION,
    hookPath: `guardNode:${fn.name || toolScope}`,
  };

  function authorize(args: unknown[], snapshot: Json | null): Decision {
    const context: Context = options.contextFn ? options.contextFn(...args) : {};
    const extra = v2 ? { capture, adapter: adapterInfo, authorizedParams: snapshot ?? undefined } : {};
    const decision = guard.check(toolScope, {
      context,
      tool: resolvedTool,
      disposition: options.disposition ?? null,
      metered: options.metered ?? false,
      ...extra,
    });
    if (!decision.allowed) throw new AuthorityDenied(decision);
    return decision;
  }

  let wrapped: GuardedNode<F>;
  if (isAsyncFn && v2) {
    wrapped = (async function (this: unknown, ...args: any[]) {
      const snapshot = snapshotParams(args);
      const decision = authorize(args, snapshot);
      const start = performance.now();
      try {
        const result = await fn.apply(this, args);
        guard.recordOutcome(decision.callId!, bodyStateFor(result), {
          invokedParams: snapshot,
          durationMs: elapsedMs(start),
        });
        return result;
      } catch (exc) {
        // The wrapper stopped observing while the body may still run — exactly spec's
        // `abandoned`, not `raised`. Still re-thrown: cancellation must propagate normally.
        if (isAbortError(exc)) {
          guard.recordOutcome(decision.callId!, BodyState.ABANDONED, {
            invokedParams: snapshot,
            durationMs: elapsedMs(start),
          });
        } else {
          guard.recordOutcome(decision.callId!, BodyState.RAISED, {
            errorCode: errorCodeOf(exc),
            invokedParams: snapshot,
            durationMs: elapsedMs(start),
          });
        }
        throw exc;
      }
    }) as unknown as GuardedNode<F>;
  } else if (isAsyncFn) {
    // v1 (schemaVersion: 1, the default): EXACTLY the pre-0.9.0 shape — a plain SYNC wrapper
    // that authorizes, then returns fn(...args) UNAWAITED. The caller awaits the returned
    // promise itself, as it always has; `wrapped` is never itself an async function on v1, even
    // when `fn` is.
    wrapped = (function (this: unknown, ...args: any[]) {
      authorize(args, null);
      return fn.apply(this, args);
    }) as unknown as GuardedNode<F>;
  } else {
    wrapped = (function (this: unknown, ...args: any[]) {
      if (!v2) {
        authorize(args, null);
        return fn.apply(this, args);
      }
      const snapshot = snapshotParams(args);
      const decision = authorize(args, snapshot);
      const start = performance.now();
      try {
        const result = fn.apply(this, args);
        guard.recordOutcome(decision.callId!, bodyStateFor(result), {
          invokedParams: snapshot,
          durationMs: elapsedMs(start),
        });
        return result;
      } catch (exc) {
        guard.recordOutcome(decision.callId!, BodyState.RAISED, {
          errorCode: errorCodeOf(exc),
          invokedParams: snapshot,
          durationMs: elapsedMs(start),
        });
        throw exc;
      }
    }) as unknown as GuardedNode<F>;
  }

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
 * reads either shape — and, on a `schemaVersion: 2` guard, feeds a single
 * IMMUTABLE snapshot taken BEFORE `tool.invoke` runs, reused for both
 * `authorizedParams` and `invokedParams`: this adapter's closest analogue of "the
 * exact tool-call JSON object" the execution-binding spec names (see the module
 * doc comment's "Execution binding" section; this is the one construct in this
 * adapter that wraps a tool BODY, so it is the reference wiring for
 * `recordOutcome`, mirroring `guardNode` above).
 */
export function guardTool<T extends ToolLike>(
  guard: Guard,
  tool: T,
  options: GuardToolOptions = {},
): T {
  const scope = options.scope ?? tool.name;
  const label = options.tool !== undefined ? options.tool : tool.name;
  const isAsyncInvoke = tool.invoke.constructor.name === "AsyncFunction";
  // guard.schemaVersion never changes for a guard's lifetime — decided once, at wrap time, same
  // as guardNode.
  const v2 = guard.schemaVersion === 2;
  const capture = isAsyncInvoke ? Capture.WRAPPER_ASYNC : Capture.WRAPPER_SYNC;
  const adapterInfo: AdapterInfo = {
    module: "attenu-guard/adapters/langgraph",
    version: VERSION,
    hookPath: `guardTool:${tool.name}`,
  };

  function snapshotToolParams(input: any): Json {
    // See snapshotParams' own comment above: freeze() unconditionally, never structuredClone.
    return freeze(toolArgs(input));
  }

  function authorize(input: any, config: any, snapshot: Json | null): Decision {
    const context: Context = options.contextFn ? options.contextFn(input, config) : {};
    const extra = v2 ? { capture, adapter: adapterInfo, authorizedParams: snapshot ?? undefined } : {};
    const decision = guard.check(scope, {
      context,
      tool: label,
      disposition: options.disposition ?? null,
      metered: options.metered ?? false,
      ...extra,
    });
    if (!decision.allowed) throw new AuthorityDenied(decision);
    return decision;
  }

  /** `authorize`, but returns `{denied: ...}` instead of throwing when `onDenied` is set. */
  function authorizeOrDenied(
    input: any,
    config: any,
    snapshot: Json | null,
  ): { decision: Decision } | { denied: unknown } {
    try {
      return { decision: authorize(input, config, snapshot) };
    } catch (exc) {
      if (exc instanceof AuthorityDenied && options.onDenied) {
        return { denied: options.onDenied(exc.decision, input) };
      }
      throw exc;
    }
  }

  let guardedInvoke: (input: any, config?: any) => any;
  if (isAsyncInvoke && v2) {
    guardedInvoke = async (input: any, config?: any) => {
      const snapshot = snapshotToolParams(input);
      const outcome = authorizeOrDenied(input, config, snapshot);
      if ("denied" in outcome) return outcome.denied;
      const start = performance.now();
      try {
        const result = await tool.invoke(input, config);
        guard.recordOutcome(outcome.decision.callId!, bodyStateFor(result), {
          invokedParams: snapshot,
          durationMs: elapsedMs(start),
        });
        return result;
      } catch (exc) {
        if (isAbortError(exc)) {
          guard.recordOutcome(outcome.decision.callId!, BodyState.ABANDONED, {
            invokedParams: snapshot,
            durationMs: elapsedMs(start),
          });
        } else {
          guard.recordOutcome(outcome.decision.callId!, BodyState.RAISED, {
            errorCode: errorCodeOf(exc),
            invokedParams: snapshot,
            durationMs: elapsedMs(start),
          });
        }
        throw exc;
      }
    };
  } else if (isAsyncInvoke) {
    // v1: EXACTLY the pre-0.9.0 shape — a plain SYNC function that authorizes, then returns
    // tool.invoke(...) UNAWAITED (the caller — typically ToolNode's own `await` — consumes the
    // returned promise itself, as it always has).
    guardedInvoke = (input: any, config?: any) => {
      const outcome = authorizeOrDenied(input, config, null);
      if ("denied" in outcome) return outcome.denied;
      return tool.invoke(input, config);
    };
  } else {
    guardedInvoke = (input: any, config?: any) => {
      if (!v2) {
        const outcome = authorizeOrDenied(input, config, null);
        if ("denied" in outcome) return outcome.denied;
        return tool.invoke(input, config);
      }
      const snapshot = snapshotToolParams(input);
      const outcome = authorizeOrDenied(input, config, snapshot);
      if ("denied" in outcome) return outcome.denied;
      const start = performance.now();
      try {
        const result = tool.invoke(input, config);
        guard.recordOutcome(outcome.decision.callId!, bodyStateFor(result), {
          invokedParams: snapshot,
          durationMs: elapsedMs(start),
        });
        return result;
      } catch (exc) {
        guard.recordOutcome(outcome.decision.callId!, BodyState.RAISED, {
          errorCode: errorCodeOf(exc),
          invokedParams: snapshot,
          durationMs: elapsedMs(start),
        });
        throw exc;
      }
    };
  }

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
