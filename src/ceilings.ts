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

import {
  MAX_SAFE_INTEGER, RawNumber, canonicalJson, compareCodePoints, pyNumber, toPlain, type CJson, type Json,
} from "./canonical.js";
import { escaped, pyRepr, pyStr, pyStrRepr, shown, shownText } from "./display.js";
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

/**
 * The scope grammar the draft defines: lowercase dot-separated segments, `*` only as the whole last
 * segment. `Authority` validates its scopes against it, and a scoped `CallLimit`'s `appliesTo`
 * follows it too.
 */
export const SCOPE_RE = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*\.(?:[a-z][a-z0-9_-]*|\*)$/;

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

/** The JSON kinds a ceiling compares, as `jsonKind` names them. */
const NUMBER = ["a number"];
const STRING = ["a string"];
const SCALAR = ["a string", "a number", "a boolean"];

/**
 * `value`'s JSON type as a refusal names it: null, a boolean, a number, a string, an array or an
 * object, or "a value that is not JSON" for anything else passed in-process (a bigint). A number
 * this library's `parseJson` read, a `RawNumber`, is a number. The Python implementation names the
 * same values the same way.
 */
function jsonKind(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return "a boolean";
  if (typeof value === "number" || value instanceof RawNumber) return "a number";
  if (typeof value === "string") return "a string";
  if (Array.isArray(value)) return "an array";
  if (typeof value === "object") return "an object";
  return "a value that is not JSON";
}

/** `value`, or the number it holds when `parseJson` read it as a `RawNumber`. */
function plain(value: unknown): unknown {
  return value instanceof RawNumber ? value.value : value;
}

/**
 * `jsonKind(value)` when a ceiling that compares `accepted` cannot compare `value`, or `null`.
 *
 * Every built-in ceiling refuses such a request value rather than coercing it (attenu-ops#110):
 * `"50"`, `[50]` and `true` passed a row cap through `<=`, `["/tmp/x"]` passed the prefix "/tmp/" as
 * the text "/tmp/x", and `true` passed the prefix "t" as "true".
 */
function wrongKind(value: unknown, accepted: readonly string[]): string | null {
  const kind = jsonKind(value);
  return accepted.includes(kind) ? null : kind;
}

/**
 * A denial's message: none when the value had the right type, as before; for one of the wrong type,
 * `<kind> cannot be compared with <against>; refused`, one wording per ceiling kind, and the Python
 * implementation's too.
 */
function refusal(kind: string | null, against: string): string {
  return kind === null ? "" : `${kind} cannot be compared with ${against}; refused`;
}

/**
 * The error for a constraint member of the wrong type, `<member> of constraint <key> is <kind>, not
 * <expected>`, with the key as Python's repr prints it: the Python implementation's text, where it
 * raises ValueError. A member the constraint does not carry is `absent`.
 *
 * A bound of the wrong type is malformed (attenu-ops#110), on every path: the draft makes "max" a
 * number and "prefix" a string, an egress rank outside none < internal < any ranked above "any" and
 * admitted every request, and a `field` or `applies_to` that is not a string named a different
 * context field in each implementation. A token carrying one is refused as malformed, and a bundle
 * reports the authority unreadable.
 */
function malformed(key: unknown, member: string, value: unknown, expected: string, shownAs?: string): TypeError {
  const kind = value === undefined ? "absent" : (shownAs ?? jsonKind(value));
  return new TypeError(`${member} of constraint ${pyRepr(key as CJson)} is ${kind}, not ${expected}`);
}

/**
 * A constraint's key is a string: it names the dimension ceilings pair by and, unless `field` says
 * otherwise, the context field the ceiling reads. A number, null or a boolean key was read as
 * String(key) here, so 5 and "5" were one dimension, and an absent key loaded and read the field
 * "undefined"; the Python implementation read a field no JSON context carries. Every constraint is
 * refused without one, an unknown type included, in the Python implementation's words.
 */
function checkKey(key: unknown): void {
  if (typeof key !== "string") {
    throw new TypeError(`key of a constraint is ${key === undefined ? "absent" : jsonKind(key)}, not a string`);
  }
}

/** A `max` is a JSON number. */
function checkMax(key: string, value: unknown): void {
  if (value === undefined || jsonKind(value) !== "a number") throw malformed(key, "max", value, "a number");
}

/** A `prefix`, `field` or `applies_to` is a string; `field` and `applies_to` may be null, unset. */
function checkString(key: unknown, member: string, value: unknown, optional = false): void {
  if (optional && (value === null || value === undefined)) return;
  if (typeof value !== "string") throw malformed(key, member, value, "a string");
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
 * Python's `type(a) is type(b)`: whether two ceilings are of one class. Ceilings pair by key, and
 * two of different classes under one key are not comparable: neither narrows the other, so an
 * authority holding one is not narrower than an authority holding the other (attenu-ops#110).
 */
export function sameType(a: Ceiling, b: Ceiling): boolean {
  return Object.getPrototypeOf(a) === Object.getPrototypeOf(b);
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
 * "São Paulo" as it is, and for values in the bare set the two agree character for character, except
 * that an allow-list's or a deny-list's string members are printed through Python's repr, quoted, so
 * the string "1" and the number 1 read differently. A ceiling this build does not define prints the
 * Python implementation's description of it — its key, `=`, and the wire object as Python prints a
 * dict — as it is when that is printable ASCII, spaces included, and as escaped JSON otherwise. Same
 * text as the Python implementation's finding.
 */
export function describeInFinding(ceiling: Ceiling): string {
  // A bound the wire supplied: a number prints as `describe` prints it; anything else is shown.
  const bound = (v: unknown): string => (typeof v === "number" ? pyNumber(v) : shown(v as CJson));
  // The typed members in wire order, as `describe` lists them, except that a string member is printed
  // through Python's repr, quoted and escaped, so a finding tells the string "1" from the number 1
  // (attenu-ops#110). Every other member's text is bare.
  const members = (values: Iterable<Json>): string =>
    sortByStr(values)
      .map((v) => (typeof v === "string" ? pyStrRepr(v) : shownText(strOf(v), v)))
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
 * characters, and an object threw a TypeError in its own words; an absent list read as an empty
 * one, so an absent deny-list bounded nothing. Each is malformed now, as in the Python
 * implementation: a token carrying one is refused as malformed, and a bundle reports the authority
 * unreadable.
 */
function notAnArray(values: unknown): string | null {
  if (values === undefined) return "absent";
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
 * `values` as the members of an `Allow` or a `Deny`, a number `parseJson` read as the number it
 * holds. Throws a TypeError naming the list and the key when `values` is not a list of members
 * (`notAnArray`); the Python implementation raises ValueError with the same text.
 */
function memberList(key: string, listName: string, values: unknown): Json[] {
  const kind = notAnArray(values);
  if (kind !== null) throw new TypeError(`${listName} of constraint ${pyRepr(key)} is ${kind}, not an array`);
  return Array.from(values as Iterable<unknown>, (v) => plain(v) as Json);
}

/**
 * The context's own value for `field`, or `undefined`. A plain object inherits `constructor`,
 * `toString` and the rest from Object.prototype, and a field named like one of them is absent unless
 * the context holds it, as `ctx.get(field)` reads it in the Python implementation.
 */
export function ownValue(ctx: Context, field: string): Json | undefined {
  return Object.prototype.hasOwnProperty.call(ctx, field) ? ctx[field] : undefined;
}

/**
 * Where two members print alike ("1" and 1), JSON type decides their order: null, boolean, number,
 * string, then anything else.
 */
function kindRank(value: Json): number {
  if (value === null) return 0;
  if (typeof value === "boolean") return 1;
  if (typeof value === "number") return 2;
  if (typeof value === "string") return 3;
  return 4;
}

/**
 * `values` as the wire form, a denial's `limit` and `describe()` list them: sorted by `strOf`, then
 * by JSON type (`kindRank`). That is a total order on distinct members, so an equal member set
 * re-emits the same bytes whatever order it arrived in, in both implementations; ties used to keep
 * their arrival order.
 */
function sortByStr(values: Iterable<Json>): Json[] {
  return Array.from(values).sort((a, b) => compareCodePoints(strOf(a), strOf(b)) || kindRank(a) - kindRank(b));
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
  readonly maxRows: number;
  constructor(maxRows: number) {
    checkMax("max_rows", maxRows);
    this.maxRows = plain(maxRows) as number;
    validateSafeNumber("max_rows", this.maxRows);
  }

  permits(ctx: Context): Decision {
    const n = ownValue(ctx, "rows");
    if (n === undefined || n === null) return Decision.allow();
    const kind = wrongKind(n, NUMBER);
    if (kind === null && (plain(n) as number) <= this.maxRows) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.maxRows,
        requested: n,
        message: refusal(kind, "a maximum"),
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
    return sameType(this, other) && this.maxRows >= (other as RowLimit).maxRows;
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
  readonly maxSpend: number;
  constructor(maxSpend: number) {
    checkMax("max_spend", maxSpend);
    this.maxSpend = plain(maxSpend) as number;
    validateSafeNumber("max_spend", this.maxSpend);
  }

  permits(ctx: Context): Decision {
    const n = ownValue(ctx, "spend");
    if (n === undefined || n === null) return Decision.allow();
    const kind = wrongKind(n, NUMBER);
    if (kind === null && (plain(n) as number) <= this.maxSpend) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.maxSpend,
        requested: n,
        message: refusal(kind, "a maximum"),
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
    return sameType(this, other) && this.maxSpend >= (other as SpendCap).maxSpend;
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
  readonly maxCalls: number;

  constructor(
    maxCalls: number,
    readonly appliesTo: string | null = null,
  ) {
    checkString("max_calls", "applies_to", appliesTo, true);
    // A pattern no scope matches ("*", "crm", "CRM.READ") applied to no call, so the limit bounded
    // nothing. It follows the scope grammar: an exact scope, or a terminal `.*` wildcard.
    if (appliesTo !== null && appliesTo !== undefined && !SCOPE_RE.test(appliesTo)) {
      throw malformed("max_calls", "applies_to", appliesTo, "a scope", pyRepr(appliesTo));
    }
    this.key = appliesTo ? `max_calls[${appliesTo}]` : "max_calls";
    checkMax(this.key, maxCalls);
    this.maxCalls = plain(maxCalls) as number;
    validateSafeNumber("max_calls", this.maxCalls);
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
    if (!this.appliesToScope(ownValue(ctx, "_scope") as string | undefined)) return Decision.allow();
    const n = ownValue(ctx, this.ctxField);
    if (n === undefined || n === null) return Decision.allow();
    const kind = wrongKind(n, NUMBER);
    if (kind === null && (plain(n) as number) <= this.maxCalls) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.maxCalls,
        requested: n,
        message: refusal(kind, "a maximum"),
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
    return sameType(this, other) && this.maxCalls >= (other as CallLimit).maxCalls;
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
  constructor(readonly level: string) {
    // A rank outside the vocabulary ranked above "any", so the ceiling admitted every request.
    if (typeof level !== "string" || !(EGRESS_ORDER as readonly string[]).includes(level)) {
      throw malformed("egress", "rank", level, "'none', 'internal' or 'any'",
        typeof level === "string" ? pyRepr(level) : undefined);
    }
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, "egress");
    if (val === undefined || val === null) return Decision.allow();
    const kind = wrongKind(val, STRING);
    if (kind === null && egressRankOf(val) <= egressRankOf(this.level)) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.level,
        requested: val,
        message: refusal(kind, "an egress rank"),
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
    return sameType(this, other) && egressRankOf(this.level) >= egressRankOf((other as EgressRank).level);
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
 * is not a JSON scalar is refused (`wrongKind`).
 */
export class Allow implements Ceiling {
  readonly oneOf: ReadonlySet<Json>;
  constructor(
    readonly key: string,
    oneOf: Iterable<Json>,
    readonly field: string | null = null,
  ) {
    checkKey(key);
    this.oneOf = new Set(memberList(key, "one_of", oneOf));
    checkString(key, "field", field, true);
  }

  private ctxKey(): string {
    return this.field ?? this.key;
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, this.ctxKey());
    if (val === undefined || val === null) return Decision.allow();
    const kind = wrongKind(val, SCALAR);
    if (kind === null && this.oneOf.has(plain(val) as Json)) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: sortByStr(this.oneOf),
        requested: val,
        message: refusal(kind, "one_of members"),
      }),
    );
  }

  describe(): string {
    return `${this.key} in [${sortByStr(this.oneOf).map(strOf).join(", ")}]`;
  }

  narrow(other: Ceiling): Allow {
    const o = other as Allow;
    return new Allow(this.key, Array.from(this.oneOf).filter((v) => o.oneOf.has(v)), this.field);
  }

  subsumes(other: Ceiling): boolean {
    return sameType(this, other) && Array.from((other as Allow).oneOf).every((v) => this.oneOf.has(v));
  }

  toWire(): Record<string, Json> {
    const d: Record<string, Json> = { key: this.key, type: "allow", one_of: sortByStr(this.oneOf) };
    if (this.field !== null && this.field !== this.key) d["field"] = this.field;
    return d;
  }

  static fromWire(d: Record<string, Json>): Allow {
    // Anything but an array, an absent one_of included, is refused by the constructor.
    return new Allow(d["key"] as string, d["one_of"] as Json[], (d["field"] as string | undefined) ?? null);
  }
}

/**
 * Membership deny-list: the context value MUST NOT be one of `notOneOf`. A member is its JSON type
 * plus its value, as a Set holds it: `[1]` refuses 1 and not `true` or `"1"`. A context value that
 * is not a JSON scalar is refused as well (`wrongKind`): a deny-list never waves through a value it
 * cannot compare, since waving `["rm"]` through because it is not the string "rm" would fail open.
 */
export class Deny implements Ceiling {
  readonly notOneOf: ReadonlySet<Json>;
  constructor(
    readonly key: string,
    notOneOf: Iterable<Json>,
    readonly field: string | null = null,
  ) {
    checkKey(key);
    this.notOneOf = new Set(memberList(key, "not_one_of", notOneOf));
    checkString(key, "field", field, true);
  }

  private ctxKey(): string {
    return this.field ?? this.key;
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, this.ctxKey());
    if (val === undefined || val === null) return Decision.allow();
    const kind = wrongKind(val, SCALAR);
    if (kind === null && !this.notOneOf.has(plain(val) as Json)) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: sortByStr(this.notOneOf),
        requested: val,
        message: refusal(kind, "not_one_of members"),
      }),
    );
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
    return sameType(this, other) && Array.from(this.notOneOf).every((v) => (other as Deny).notOneOf.has(v));
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
    // Anything but an array, an absent not_one_of included, is refused by the constructor.
    return new Deny(d["key"] as string, d["not_one_of"] as Json[], (d["field"] as string | undefined) ?? null);
  }
}

/** String-prefix bound: the context value MUST start with `prefix`. */
export class Prefix implements Ceiling {
  constructor(
    readonly key: string,
    readonly prefix: string,
    readonly field: string | null = null,
  ) {
    checkKey(key);
    checkString(key, "prefix", prefix);
    checkString(key, "field", field, true);
  }

  private ctxKey(): string {
    return this.field ?? this.key;
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, this.ctxKey());
    if (val === undefined || val === null) return Decision.allow();
    const kind = wrongKind(val, STRING);
    if (kind === null && (val as string).startsWith(this.prefix)) return Decision.allow();
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.prefix,
        requested: val,
        message: refusal(kind, "a prefix"),
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
    return sameType(this, other) && (other as Prefix).prefix.startsWith(this.prefix);
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
 *
 * A constraint is a JSON object with a string `key`, and a `type` that, when present, is a string;
 * anything else is malformed (attenu-ops#110), in the Python implementation's words too: `a
 * constraint is a string, not an object`, `type of constraint 'max_rows' is null, not a string`.
 * A constraint that is not an object loaded as an unknown constraint here, null aside, and a null
 * `type` was read as absent, so the constraint was routed by its key: `{"key": "allow", "type":
 * null, ...}` loaded as an allow-list, where the Python implementation loaded an unknown constraint.
 */
export function ceilingFromWire(wire: CJson): Ceiling {
  const d = toPlain<Record<string, Json>>(wire);
  if (d === null || typeof d !== "object" || Array.isArray(d)) {
    throw new TypeError(`a constraint is ${jsonKind(d)}, not an object`);
  }
  checkKey(d["key"]);
  const type = d["type"];
  if (type !== undefined && typeof type !== "string") throw malformed(d["key"], "type", type, "a string");
  const discriminator = type ?? d["key"];
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
