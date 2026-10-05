/**
 * ceilings.ts — typed, self-narrowing, self-enforcing bounds on an Authority.
 *
 * A `Ceiling` is a small typed object that knows how to (a) check itself against
 * a request context, (b) narrow itself against a sibling ceiling of the same
 * kind, (c) state whether it admits a superset of what another ceiling of its
 * kind admits, and (d) read and write its own wire form. `Authority` never needs
 * to know the semantics of any particular ceiling — it just calls these methods.
 *
 * The property the Internet-Draft's constraint vocabulary demands: "a verifier
 * that encounters an unknown constraint type MUST treat the action as denied
 * (fail-closed), never as unconstrained." That is `ceilingFromWire`: an
 * unrecognised wire constraint becomes an `UnknownCeiling`, whose `permits`
 * always denies. There is no code path by which an unrecognised bound is
 * silently dropped.
 */

import { MAX_SAFE_INTEGER, canonicalJson, compareCodePoints, pyNumber, toPlain, type CJson, type Json } from "./canonical.js";
import { escaped, pyRepr, pyStr, shown, shownText } from "./display.js";
import { Decision, Reason, ReasonCode } from "./reasons.js";

/**
 * Reject a ceiling bound whose magnitude can't survive the signing surface
 * intact. RFC 8785 numbers are binary64: an int past ±(2**53-1) can collide
 * with a neighbouring integer once canonicalized (see
 * `canonical.UnsafeIntegerError`), so a ceiling built from one would silently
 * admit or deny a different value than the one the caller constructed. Fail
 * at construction, not at signing — mirrors `authority.ts`'s scope validator,
 * which also throws `TypeError`.
 */
function validateSafeNumber(key: string, value: number): void {
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new TypeError(
      `${key} value ${value} exceeds the safe integer range ±${MAX_SAFE_INTEGER} for a ` +
        "binary64 signing surface (RFC 8785)",
    );
  }
}

/** A request context: the quantities and attributes a call declares. */
export type Context = Record<string, Json>;

/** The shape every ceiling — built-in or custom — must implement. */
export interface Ceiling {
  /** The dimension being bounded, e.g. "max_rows". Pairs ceilings in `meet`. */
  readonly key: string;
  /** The request-context field this ceiling reads, when it differs from `key`. */
  readonly ctxField?: string;
  /** Caller-chosen context field for the generic membership/prefix ceilings. */
  readonly field?: string | null;
  /** Set on a ceiling that bounds a consumed quantity the caller must declare. */
  readonly metered?: boolean;

  /**
   * Does this ceiling admit the given request context? A context that does not
   * mention this ceiling's dimension is not asserting anything here, and is
   * permitted.
   */
  permits(ctx: Context): Decision;

  /**
   * The more restrictive of `this` and `other` (same key). Must satisfy:
   * the result's admitted set is a subset of both inputs'. That is what makes
   * `Authority.meet` sound.
   */
  narrow(other: Ceiling): Ceiling;

  /** True iff `this` admits a superset of what `other` admits. */
  subsumes(other: Ceiling): boolean;

  /** The wire form, per the Internet-Draft's Constraint Vocabulary. */
  toWire(): Record<string, Json>;

  /** Human-readable rendering, for dashboards and parent-vs-child diffs. */
  describe?(): string;

  /** Scoped ceilings only: does this bound bite a request for `scope`? */
  appliesToScope?(scope: string | null | undefined): boolean;

  /** Scoped ceilings only: the pattern this ceiling meters against, or "*". */
  readonly meterKey?: string;
}

// Ordered enum for egress: index 0 is the strictest. A value outside this
// vocabulary is treated as maximally permissive-requested (worst case), so a
// garbage or unknown egress value fails closed rather than silently passing.
const EGRESS_ORDER = ["none", "internal", "any"] as const;

function egressRankOf(value: unknown): number {
  const i = (EGRESS_ORDER as readonly unknown[]).indexOf(value);
  return i === -1 ? EGRESS_ORDER.length : i;
}

/**
 * The request-context field a ceiling reads. Prefers an explicit `ctxField`,
 * then the caller-keyed `field`, then the ceiling's own `key`.
 */
export function ctxFieldOf(ceiling: Ceiling): string {
  if (ceiling.ctxField) return ceiling.ctxField;
  if (ceiling.field) return ceiling.field;
  return ceiling.key;
}

/**
 * Uniform human-readable rendering of any ceiling. Never parsed back. A ceiling without its own
 * `describe`, such as one this build does not define, prints as the Python implementation prints
 * it: its key as the wire carried it, `=`, and its wire form as Python prints a dict.
 */
export function describe(ceiling: Ceiling): string {
  if (typeof ceiling.describe === "function") return ceiling.describe();
  return `${pyStr(wireKeyOf(ceiling))}=${pyRepr(ceiling.toWire())}`;
}

/**
 * A ceiling's key as the wire carried it, which is what a finding names. A ceiling this build does
 * not define keeps whatever its key was, null included, where its `key` property is text: the
 * Python implementation prints a null key as `None`.
 */
export function wireKeyOf(ceiling: Ceiling): CJson {
  return ceiling instanceof UnknownCeiling ? (ceiling.raw["key"] ?? null) : ceiling.key;
}

/**
 * A ceiling as a verifier finding prints it: `describe`'s text, with every value the bundle supplied
 * printed through `shown` (display.ts), so the finding stays on one line.
 *
 * `describe` itself is left alone, so dashboards and `Authority.describe()` print a region called
 * "São Paulo" as it is, and for values in the bare set the two agree character for character. A
 * ceiling this build does not define prints the Python implementation's description of it — its key,
 * `=`, and the wire object as Python prints a dict — as it is when that is printable ASCII, spaces
 * included, and as escaped JSON otherwise. Same text as the Python implementation's finding.
 */
export function describeInFinding(ceiling: Ceiling): string {
  // A bound the wire supplied: a number prints as `describe` prints it; anything else is shown.
  const bound = (v: unknown): string => (typeof v === "number" ? pyNumber(v) : shown(v as CJson));
  const members = (values: Iterable<Json>): string =>
    sortByStr(values)
      .map((v) => shownText(strOf(v), v))
      .join(", ");
  // By exact class, as the Python implementation matches by exact type: a subclass of a built-in
  // describes itself, and is printed the way any other ceiling this build does not define is.
  const kind = (ceiling as object).constructor;
  if (kind === RowLimit) return `${shown(ceiling.key)}<=${bound((ceiling as RowLimit).maxRows)}`;
  if (kind === SpendCap) return `${shown(ceiling.key)}<=${bound((ceiling as SpendCap).maxSpend)}`;
  if (kind === CallLimit) return `${shown(ceiling.key)}<=${bound((ceiling as CallLimit).maxCalls)}`;
  if (kind === EgressRank) return `${shown(ceiling.key)}<=${shown((ceiling as EgressRank).level)}`;
  if (kind === Allow) return `${shown(ceiling.key)} in [${members((ceiling as Allow).oneOf)}]`;
  if (kind === Deny) return `${shown(ceiling.key)} not in [${members((ceiling as Deny).notOneOf)}]`;
  if (kind === Prefix) return `${shown(ceiling.key)} startswith ${shown((ceiling as Prefix).prefix)}`;
  const text = describe(ceiling);
  return /^[ -~]*$/.test(text) ? text : escaped(text);
}

/**
 * A METERED ceiling bounds a consumed quantity the caller must declare (rows
 * read, spend, calls) — by convention its key starts with "max_". Rank and
 * membership ceilings are not metered: omitting them from a context means "not
 * asserting anything here", not "consuming an undeclared amount".
 */
export function isMetered(ceiling: Ceiling): boolean {
  return Boolean(ceiling.metered) || String(ceiling.key).startsWith("max_");
}

/**
 * What a refusal calls a `one_of` / `not_one_of` that is not a list of members, or `null` for one
 * that is: a JSON array, or in-process any other iterable of members (a Set).
 *
 * The draft defines both as an array. null used to become the empty list, a string its
 * characters, and an object threw a TypeError in its own words. Each is malformed now, as in the
 * Python implementation: a token carrying one is refused as malformed, and a bundle reports the
 * authority unreadable.
 */
function notAnArray(values: unknown): string | null {
  if (values === null) return "null";
  if (typeof values === "boolean") return "a boolean";
  if (typeof values === "number") return "a number";
  if (typeof values === "string") return "a string";
  if (Array.isArray(values)) return null;
  if (values instanceof Map) return "an object";
  if (typeof values === "object" && typeof (values as Iterable<Json>)[Symbol.iterator] === "function") return null;
  if (typeof values === "object") return "an object";
  return "a value that is not an array";
}

/**
 * `values` as the members of an `Allow` or a `Deny`. Throws a TypeError naming the list and the
 * key when `values` is not a list of members (`notAnArray`); the Python implementation raises
 * ValueError with the same text.
 */
function memberList(key: string, listName: string, values: unknown): Iterable<Json> {
  const kind = notAnArray(values);
  if (kind !== null) throw new TypeError(`${listName} of constraint ${pyRepr(key)} is ${kind}, not an array`);
  return values as Iterable<Json>;
}

/**
 * What a refusal calls a request value that an `Allow` or a `Deny` cannot compare with its
 * members, or `null` for a JSON scalar: a string, a number or a boolean. (null never gets here: it
 * asserts nothing.)
 *
 * No member is an array, an object or a value outside JSON, so no such value can equal one. An
 * allow-list refuses it as a non-member. A deny-list must refuse it too: waving `["rm"]` through
 * because it is not the string "rm" would fail open. The Python implementation uses the same words.
 */
function notAScalar(value: unknown): string | null {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return null;
  if (Array.isArray(value)) return "an array";
  if (value !== null && typeof value === "object") return "an object";
  return "a value that is not JSON";
}

/**
 * Why an `Allow` or a `Deny` refused `value`. `kind` is `notAScalar(value)`: a value the list could
 * compare carries no message, as before; one it could not compare says so.
 */
function outside(key: string, listName: string, members: Iterable<Json>, value: Json, kind: string | null): Reason {
  return new Reason(ReasonCode.CEILING_EXCEEDED, {
    constraint: key,
    limit: sortByStr(members),
    requested: value,
    message: kind === null ? "" : `${kind} cannot be compared with ${listName} members; refused`,
  });
}

/**
 * The context's own value for `field`, or `undefined`. A plain object inherits `constructor`,
 * `toString` and the rest from Object.prototype, and a field named like one of them is absent unless
 * the context holds it, as `ctx.get(field)` reads it in the Python implementation.
 */
function ownValue(ctx: Context, field: string): Json | undefined {
  return Object.prototype.hasOwnProperty.call(ctx, field) ? ctx[field] : undefined;
}

function sortByStr(values: Iterable<Json>): Json[] {
  return Array.from(values).sort((a, b) => compareCodePoints(strOf(a), strOf(b)));
}

function strOf(value: Json): string {
  if (typeof value === "number") return pyNumber(value);
  if (value === null) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

// =========================================================================
// Built-in ceilings — fixed-key numeric and enum caps. For these four the wire
// "key" IS the type discriminator, so the registry can route on "key" alone.
// =========================================================================

/** Per-call cap on rows read or returned. Context field: "rows". */
export class RowLimit implements Ceiling {
  readonly key = "max_rows";
  readonly ctxField = "rows";
  constructor(readonly maxRows: number) {
    validateSafeNumber("max_rows", maxRows);
  }

  permits(ctx: Context): Decision {
    const n = ctx["rows"];
    if (n === undefined || n === null || (n as number) <= this.maxRows) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.maxRows,
        requested: n,
      }),
    );
  }

  describe(): string {
    return `${this.key}<=${pyNumber(this.maxRows)}`;
  }

  narrow(other: Ceiling): RowLimit {
    return new RowLimit(Math.min(this.maxRows, (other as RowLimit).maxRows));
  }

  subsumes(other: Ceiling): boolean {
    return this.maxRows >= (other as RowLimit).maxRows;
  }

  toWire(): Record<string, Json> {
    return { key: this.key, max: this.maxRows };
  }

  static fromWire(d: Record<string, Json>): RowLimit {
    return new RowLimit(d["max"] as number);
  }
}

/** Per-call cap on spend, currency-agnostic. Context field: "spend". */
export class SpendCap implements Ceiling {
  readonly key = "max_spend";
  readonly ctxField = "spend";
  constructor(readonly maxSpend: number) {
    validateSafeNumber("max_spend", maxSpend);
  }

  permits(ctx: Context): Decision {
    const n = ctx["spend"];
    if (n === undefined || n === null || (n as number) <= this.maxSpend) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.maxSpend,
        requested: n,
      }),
    );
  }

  describe(): string {
    return `${this.key}<=${pyNumber(this.maxSpend)}`;
  }

  narrow(other: Ceiling): SpendCap {
    return new SpendCap(Math.min(this.maxSpend, (other as SpendCap).maxSpend));
  }

  subsumes(other: Ceiling): boolean {
    return this.maxSpend >= (other as SpendCap).maxSpend;
  }

  toWire(): Record<string, Json> {
    return { key: this.key, max: this.maxSpend };
  }

  static fromWire(d: Record<string, Json>): SpendCap {
    return new SpendCap(d["max"] as number);
  }
}

/**
 * Cap on a call COUNT. Context field: "calls" — the running count including
 * this call.
 *
 * `appliesTo` makes the ceiling SCOPED: it only bites requests for that scope
 * (wildcards as in scopes: "fs.write", "web.*"). A scoped limit is its own
 * dimension — `key` becomes `max_calls[<appliesTo>]` — so an unscoped and a
 * scoped limit coexist in one Authority and pair independently.
 *
 * `Guard.check` supplies `calls` itself, per (node, pattern), when the caller
 * does not; an explicit `calls` in the context still wins.
 */
export class CallLimit implements Ceiling {
  readonly key: string;
  readonly ctxField: string;

  constructor(
    readonly maxCalls: number,
    readonly appliesTo: string | null = null,
  ) {
    validateSafeNumber("max_calls", maxCalls);
    this.key = appliesTo ? `max_calls[${appliesTo}]` : "max_calls";
    this.ctxField = appliesTo ? `calls[${appliesTo}]` : "calls";
  }

  /** What this ceiling counts: the pattern it applies to, or every call. */
  get meterKey(): string {
    return this.appliesTo ?? "*";
  }

  appliesToScope(scope: string | null | undefined): boolean {
    if (!this.appliesTo || scope === null || scope === undefined) return true;
    const held = this.appliesTo;
    return held === scope || (held.endsWith(".*") && String(scope).startsWith(held.slice(0, -1)));
  }

  permits(ctx: Context): Decision {
    if (!this.appliesToScope(ctx["_scope"] as string | undefined)) return Decision.allow();
    const n = ctx[this.ctxField];
    if (n === undefined || n === null || (n as number) <= this.maxCalls) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.maxCalls,
        requested: n,
      }),
    );
  }

  describe(): string {
    return `${this.key}<=${pyNumber(this.maxCalls)}`;
  }

  narrow(other: Ceiling): CallLimit {
    return new CallLimit(Math.min(this.maxCalls, (other as CallLimit).maxCalls), this.appliesTo);
  }

  subsumes(other: Ceiling): boolean {
    return this.maxCalls >= (other as CallLimit).maxCalls;
  }

  toWire(): Record<string, Json> {
    if (!this.appliesTo) return { key: this.key, max: this.maxCalls };
    return { key: this.key, type: "max_calls", max: this.maxCalls, applies_to: this.appliesTo };
  }

  static fromWire(d: Record<string, Json>): CallLimit {
    return new CallLimit(d["max"] as number, (d["applies_to"] as string | undefined) ?? null);
  }
}

/** Ordered-enum egress ceiling: none < internal < any. Context field: "egress". */
export class EgressRank implements Ceiling {
  readonly key = "egress";
  readonly ctxField = "egress";
  constructor(readonly level: string) {}

  permits(ctx: Context): Decision {
    const val = ctx["egress"];
    if (val === undefined || val === null || egressRankOf(val) <= egressRankOf(this.level)) {
      return Decision.allow();
    }
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.level,
        requested: val,
      }),
    );
  }

  describe(): string {
    return `${this.key}<=${this.level}`;
  }

  narrow(other: Ceiling): EgressRank {
    const o = other as EgressRank;
    return new EgressRank(egressRankOf(this.level) <= egressRankOf(o.level) ? this.level : o.level);
  }

  subsumes(other: Ceiling): boolean {
    return egressRankOf(this.level) >= egressRankOf((other as EgressRank).level);
  }

  toWire(): Record<string, Json> {
    return { key: this.key, rank: this.level };
  }

  static fromWire(d: Record<string, Json>): EgressRank {
    return new EgressRank(d["rank"] as string);
  }
}

// =========================================================================
// Built-in ceilings — generic, caller-keyed set membership and prefix bounds.
// `key` here IS a caller choice, so it cannot double as the wire discriminator;
// these carry an explicit "type" on the wire.
// =========================================================================

/**
 * Membership allow-list: the context value MUST be one of `oneOf`. A member is its JSON type plus
 * its value, as a Set holds it: `[1]` admits 1 and refuses `true` and `"1"`. A context value that
 * is not a JSON scalar is refused (`notAScalar`).
 */
export class Allow implements Ceiling {
  readonly oneOf: ReadonlySet<Json>;
  constructor(
    readonly key: string,
    oneOf: Iterable<Json>,
    readonly field: string | null = null,
  ) {
    this.oneOf = new Set(memberList(key, "one_of", oneOf));
  }

  private ctxKey(): string {
    return this.field ?? this.key;
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, this.ctxKey());
    if (val === undefined || val === null) return Decision.allow();
    const kind = notAScalar(val);
    if (kind === null && this.oneOf.has(val)) return Decision.allow();
    return Decision.deny(outside(this.key, "one_of", this.oneOf, val, kind));
  }

  describe(): string {
    return `${this.key} in [${sortByStr(this.oneOf).map(strOf).join(", ")}]`;
  }

  narrow(other: Ceiling): Allow {
    const o = other as Allow;
    return new Allow(this.key, Array.from(this.oneOf).filter((v) => o.oneOf.has(v)), this.field);
  }

  subsumes(other: Ceiling): boolean {
    return Array.from((other as Allow).oneOf).every((v) => this.oneOf.has(v));
  }

  toWire(): Record<string, Json> {
    const d: Record<string, Json> = { key: this.key, type: "allow", one_of: sortByStr(this.oneOf) };
    if (this.field !== null && this.field !== this.key) d["field"] = this.field;
    return d;
  }

  static fromWire(d: Record<string, Json>): Allow {
    // Absent is the empty list; anything present but not an array is refused by the constructor.
    return new Allow(
      d["key"] as string,
      d["one_of"] === undefined ? [] : (d["one_of"] as Json[]),
      (d["field"] as string | undefined) ?? null,
    );
  }
}

/**
 * Membership deny-list: the context value MUST NOT be one of `notOneOf`. A member is its JSON type
 * plus its value, as a Set holds it: `[1]` refuses 1 and not `true` or `"1"`. A context value that
 * is not a JSON scalar is refused as well (`notAScalar`): a deny-list never waves through a value it
 * cannot compare.
 */
export class Deny implements Ceiling {
  readonly notOneOf: ReadonlySet<Json>;
  constructor(
    readonly key: string,
    notOneOf: Iterable<Json>,
    readonly field: string | null = null,
  ) {
    this.notOneOf = new Set(memberList(key, "not_one_of", notOneOf));
  }

  private ctxKey(): string {
    return this.field ?? this.key;
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, this.ctxKey());
    if (val === undefined || val === null) return Decision.allow();
    const kind = notAScalar(val);
    if (kind === null && !this.notOneOf.has(val)) return Decision.allow();
    return Decision.deny(outside(this.key, "not_one_of", this.notOneOf, val, kind));
  }

  describe(): string {
    return `${this.key} not in [${sortByStr(this.notOneOf).map(strOf).join(", ")}]`;
  }

  narrow(other: Ceiling): Deny {
    const o = other as Deny;
    return new Deny(this.key, [...this.notOneOf, ...o.notOneOf], this.field);
  }

  subsumes(other: Ceiling): boolean {
    // `this` admits a superset of `other`'s admitted set iff it forbids a
    // subset of what `other` forbids.
    return Array.from(this.notOneOf).every((v) => (other as Deny).notOneOf.has(v));
  }

  toWire(): Record<string, Json> {
    const d: Record<string, Json> = {
      key: this.key,
      type: "deny",
      not_one_of: sortByStr(this.notOneOf),
    };
    if (this.field !== null && this.field !== this.key) d["field"] = this.field;
    return d;
  }

  static fromWire(d: Record<string, Json>): Deny {
    // Absent is the empty list; anything present but not an array is refused by the constructor.
    return new Deny(
      d["key"] as string,
      d["not_one_of"] === undefined ? [] : (d["not_one_of"] as Json[]),
      (d["field"] as string | undefined) ?? null,
    );
  }
}

/** String-prefix bound: the context value MUST start with `prefix`. */
export class Prefix implements Ceiling {
  constructor(
    readonly key: string,
    readonly prefix: string,
    readonly field: string | null = null,
  ) {}

  private ctxKey(): string {
    return this.field ?? this.key;
  }

  permits(ctx: Context): Decision {
    const val = ctx[this.ctxKey()];
    if (val === undefined || val === null || String(val).startsWith(this.prefix)) {
      return Decision.allow();
    }
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.prefix,
        requested: val,
      }),
    );
  }

  describe(): string {
    return `${this.key} startswith ${this.prefix}`;
  }

  narrow(other: Ceiling): Prefix {
    const o = other as Prefix;
    // If one prefix is a prefix of the other, the longer (more specific) one
    // admits the subset and is the sound meet.
    if (this.prefix.startsWith(o.prefix)) return this;
    if (o.prefix.startsWith(this.prefix)) return o;
    // Incomparable prefixes (e.g. "eu-" and "us-"): no real value can start
    // with both, so the sound meet admits nothing. That is encoded as a prefix
    // containing a NUL byte, which cannot be a genuine prefix of any realistic
    // context string — so `permits` soundly denies every real request rather
    // than picking one side and silently admitting values the other rejected.
    return new Prefix(this.key, `${this.prefix}\u0000${o.prefix}`, this.field);
  }

  subsumes(other: Ceiling): boolean {
    return (other as Prefix).prefix.startsWith(this.prefix);
  }

  toWire(): Record<string, Json> {
    const d: Record<string, Json> = { key: this.key, type: "prefix", prefix: this.prefix };
    if (this.field !== null && this.field !== this.key) d["field"] = this.field;
    return d;
  }

  static fromWire(d: Record<string, Json>): Prefix {
    return new Prefix(
      d["key"] as string,
      d["prefix"] as string,
      (d["field"] as string | undefined) ?? null,
    );
  }
}

// =========================================================================
// Registry — the extension seam. Maps a wire discriminator ("type" if present,
// else "key") to the class that rebuilds itself from that wire shape.
// Fail-closed: an unrecognised discriminator resolves to a ceiling that denies.
// =========================================================================

export interface CeilingClass {
  fromWire(d: Record<string, Json>): Ceiling;
}

const REGISTRY = new Map<string, CeilingClass>();

/**
 * Register a ceiling class's `fromWire` under a wire discriminator.
 * Re-registering replaces the previous mapping — callers may shadow a built-in
 * deliberately, but should do so knowingly.
 */
export function registerCeiling(key: string, cls: CeilingClass): void {
  REGISTRY.set(key, cls);
}

/**
 * Fail-closed placeholder for a wire constraint this build does not recognise.
 *
 * `permits` always denies. `narrow` stays an unknown ceiling, so it can never
 * resolve to something more permissive than "deny everything". `subsumes` is
 * true only against an identical unknown ceiling — just enough reflexivity for
 * `isNarrowerThan(self)`. Identical means the same RFC 8785 bytes, which is
 * equality as JSON: `true` is not 1, `1.0` is 1, and key order is no difference
 * at any depth; a value RFC 8785 cannot write is identical to nothing. `toWire`
 * preserves the original bytes losslessly, so a chain that merely forwards
 * constraints can still do so.
 */
export class UnknownCeiling implements Ceiling {
  readonly key: string;
  constructor(
    key: Json,
    readonly raw: Record<string, Json> = {},
  ) {
    this.key = key === null || key === undefined ? "" : String(key);
  }

  permits(_ctx: Context): Decision {
    // In the Python implementation's words, and with the key as the wire carried it (null, a
    // number), so a deny entry is the same bytes from both implementations.
    const key = wireKeyOf(this);
    return Decision.deny(
      new Reason(ReasonCode.UNKNOWN_CONSTRAINT, {
        constraint: key as string | null,
        message: `unrecognised constraint type for key=${pyRepr(key)}; fail-closed`,
      }),
    );
  }

  narrow(_other: Ceiling): UnknownCeiling {
    return this;
  }

  subsumes(other: Ceiling): boolean {
    // Compared as RFC 8785 bytes, as the Python implementation compares them. JSON text with only
    // the top-level keys sorted told `{"v":{"a":1,"b":2}}` from `{"v":{"b":2,"a":1}}` (attenu-ops#110).
    if (!(other instanceof UnknownCeiling)) return false;
    try {
      return canonicalJson(other.raw) === canonicalJson(this.raw);
    } catch {
      return false;
    }
  }

  toWire(): Record<string, Json> {
    return { ...this.raw };
  }

  static fromWire(d: Record<string, Json>): UnknownCeiling {
    return new UnknownCeiling(d["key"] ?? null, { ...d });
  }
}

/**
 * Reconstruct a Ceiling from its wire form. Routes on "type" when present (it
 * disambiguates the generic ceilings), else on "key". An unrecognised
 * discriminator fails closed via `UnknownCeiling`.
 */
export function ceilingFromWire(wire: CJson): Ceiling {
  const d = toPlain<Record<string, Json>>(wire);
  const discriminator = d["type"] ?? d["key"];
  const cls = typeof discriminator === "string" ? REGISTRY.get(discriminator) : undefined;
  if (cls === undefined) return UnknownCeiling.fromWire(d);
  return cls.fromWire(d);
}

registerCeiling("max_rows", RowLimit);
registerCeiling("max_spend", SpendCap);
registerCeiling("max_calls", CallLimit);
registerCeiling("egress", EgressRank);
registerCeiling("allow", Allow);
registerCeiling("deny", Deny);
registerCeiling("prefix", Prefix);
