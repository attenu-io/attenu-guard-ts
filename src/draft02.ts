/**
 * draft02.ts — the rules draft-asor-wimse-agent-delegation-chain-02 adds, as one module.
 *
 * The -01 rules stay where they are (ceilings.ts, authority.ts, wire.ts) and stay the DEFAULT:
 * every existing caller, adapter, test and the twenty published -01 vectors verify exactly as
 * before. The -02 rules are opted into by a profile selector — `new Authority({..., profile:
 * "02"})`, `Authority.fromWire(wire, "02")`, `load(tokens, signer, { draft: "02" })` — and this
 * module holds what differs:
 *
 *   - the three-form scope grammar (Section 4.1): literal, wildcard, and opaque scopes, classified
 *     by their bytes alone in that order, with the covering relation per form;
 *   - the constraint vocabulary of Section 4.2 as generic, key-addressed ceilings: `max`, `min`,
 *     `max_lifetime`, `max_subtree`, and `rank` with its `order` member;
 *   - the constraint-object rules: closed members, one typed value, one constraint per
 *     (key, type), unknown types fail closed;
 *   - the measurement-scope rule of step 8: a cumulative constraint (`max_lifetime`,
 *     `max_subtree`) is satisfied only where the running total it is measured over is held, so a
 *     request context that carries no total for it DENIES, never passes.
 *
 * Request-context fields read by the generic ceilings (so that a chain minted from the library's
 * own fixed-key ceilings keeps reading the same context after a -02 round trip):
 *
 *     key            per-action field   lifetime total     subtree total
 *     max_rows       rows               rows_total         rows_subtree_total
 *     max_spend      spend              spend_total        spend_subtree_total
 *     max_calls      calls              calls              calls_subtree_total
 *     max_calls[P]   calls[P]           calls[P]           calls[P]_subtree_total
 *     egress         egress             -                  -
 *     anything else  <key>              <key>_total        <key>_subtree_total
 *
 * `max_calls` is the one key whose per-action field IS the running total: the library has always
 * metered call counts as "the count including this call" under `calls`, and the guard fills that
 * field itself (`Guard.autoMeter`), so a -02 `max_lifetime` on `max_calls` reads `calls` and is
 * held by the guard. Every other cumulative total is supplied by the component that holds it, or
 * the constraint denies.
 *
 * Known limitation (fail-closed): under the "02" profile a legacy fixed-key ceiling and the generic
 * ceiling of the same -02 type on the same key (`RowLimit(5)` and `Max("max_rows", 5)`, `EgressRank`
 * and `Rank("egress", ...)`, `CallLimit` and `MaxLifetime("max_calls", ...)`) share the (key, type)
 * pair but are different classes, so neither subsumes nor narrows the other: `isNarrowerThan` is
 * false and a delegation across them is refused as `not_narrower` even where the values narrow.
 * That is a false deny, never a false allow. It arises only when the two forms are mixed in one
 * process, for example a guard built from legacy ceilings delegating to a request built from
 * `Authority.fromWire(..., "02")`; build both sides from the same form. The forms are not
 * normalised into one in this release.
 *
 * Kept in step with the Python reference implementation (`attenu_guard.draft02`): the same
 * classification, the same pairing, the same wire shapes and the same refusals, in the same words.
 */

import { canonicalJson, compareCodePoints, pyNumber, toPlain, type CJson, type Json } from "./canonical.js";
import {
  Allow,
  Deny,
  NUMBER,
  Prefix,
  STRING,
  UnknownCeiling,
  checkKey,
  jsonKind,
  malformed,
  ownValue,
  plain,
  refusal,
  validateSafeNumber,
  wrongKind,
  type Ceiling,
  type CeilingClass,
  type Context,
} from "./ceilings.js";
import { pyRepr, pyStrRepr } from "./display.js";
import { Decision, Reason, ReasonCode } from "./reasons.js";

export const PROFILE_01 = "01";
export const PROFILE_02 = "02";
export const PROFILES = [PROFILE_01, PROFILE_02] as const;

/** The revision of the Internet-Draft an authority or a token follows. */
export type Profile = (typeof PROFILES)[number];

/** `profile`, when it names a known revision; a TypeError otherwise, in the Python port's words. */
export function checkProfile(profile: unknown): Profile {
  if (!(PROFILES as readonly unknown[]).includes(profile)) {
    throw new TypeError(
      `unknown draft profile ${pyRepr((profile ?? null) as CJson)}; expected one of ('01', '02')`,
    );
  }
  return profile as Profile;
}

// =========================================================================
// Scope grammar — Section 4.1 of the -02
// =========================================================================

/** literal-scope  = segment "." segment *("." segment) */
const LITERAL_RE = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$/;
/** wildcard-scope = segment *("." segment) ".*" */
const WILDCARD_RE = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*\.\*$/;
/** opaque-scope   = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )   ; RFC 6749 scope-token minus "*" */
const OPAQUE_RE = /^[\x21\x23-\x29\x2B-\x5B\x5D-\x7E]+$/;

export const LITERAL = "literal";
export const WILDCARD = "wildcard";
export const OPAQUE = "opaque";
export type ScopeForm = typeof LITERAL | typeof WILDCARD | typeof OPAQUE;

/**
 * The form of `scope` under the -02 grammar, by its bytes alone and in the draft's order: literal,
 * then wildcard, then opaque; `null` when it matches none of the three (so it is invalid and the
 * token carrying it is malformed). No case folding at any step.
 */
export function classifyScope(scope: unknown): ScopeForm | null {
  if (typeof scope !== "string") return null;
  if (LITERAL_RE.test(scope)) return LITERAL;
  if (WILDCARD_RE.test(scope)) return WILDCARD;
  if (OPAQUE_RE.test(scope)) return OPAQUE;
  return null;
}

export function validateScope(scope: unknown): asserts scope is string {
  if (classifyScope(scope) === null) {
    throw new TypeError(
      `invalid scope ${pyRepr((scope ?? null) as CJson)}: not a literal scope, a wildcard scope, or an opaque ` +
        "scope (RFC 6749 scope-token without '*'); '*' is permitted only as the complete " +
        "final segment after a dot",
    );
  }
}

/**
 * The -02 covering relation. A literal covers only an identical literal; a wildcard covers any
 * literal or wildcard that begins with its value minus the final `*` (the dot retained); an opaque
 * scope covers only a byte-identical opaque scope, and no wildcard covers an opaque scope. Each
 * side is classified by its own bytes, so `drive.*` does not cover `drive.Read`: the uppercase R
 * makes the child opaque.
 */
export function scopeCovers(held: string, requested: string): boolean {
  const heldForm = classifyScope(held);
  const reqForm = classifyScope(requested);
  if (heldForm === null || reqForm === null) return false;
  if (heldForm === WILDCARD) {
    return (reqForm === LITERAL || reqForm === WILDCARD) && requested.startsWith(held.slice(0, -1));
  }
  return held === requested;
}

// =========================================================================
// Generic ceilings — the -02 constraint vocabulary, addressed by key
// =========================================================================

/** The -02 constraint types this build implements, by their wire member name. */
export const CONSTRAINT_TYPES = [
  "max", "min", "max_lifetime", "max_subtree", "one_of", "not_one_of", "prefix", "rank",
] as const;
export const CUMULATIVE_TYPES = ["max_lifetime", "max_subtree"] as const;

/** The context field a key's PER-ACTION value is read from (see the module doc comment). */
const LEGACY_FIELDS: Readonly<Record<string, string>> = { max_rows: "rows", max_spend: "spend", max_calls: "calls" };

function perActionField(key: string): string {
  if (Object.prototype.hasOwnProperty.call(LEGACY_FIELDS, key)) return LEGACY_FIELDS[key]!;
  if (key.startsWith("max_calls[")) return "calls" + key.slice("max_calls".length);
  return key;
}

function lifetimeField(key: string): string {
  const base = perActionField(key);
  if (base === "calls" || base.startsWith("calls[")) return base; // the guard's own meter IS the running total
  return base + "_total";
}

function subtreeField(key: string): string {
  return perActionField(key) + "_subtree_total";
}

function checkNumber(key: string, member: string, value: unknown): void {
  if (value === undefined || jsonKind(value) !== "a number") throw malformed(key, member, value, "a number");
  validateSafeNumber(key, plain(value) as number);
}

/** Python's `type(a) is type(b)`, for the narrowing relations below. */
function sameClass(a: object, b: object): boolean {
  return Object.getPrototypeOf(a) === Object.getPrototypeOf(b);
}

function numberDenial(key: string, limit: number, n: Json, kind: string | null, against: string): Decision {
  return Decision.deny(
    new Reason(ReasonCode.CEILING_EXCEEDED, { constraint: key, limit, requested: n, message: refusal(kind, against) }),
  );
}

/**
 * Per-action numeric ceiling (`max`): the quantity in ONE authorized action MUST NOT exceed
 * `value`. Nothing in this type aggregates across actions, tokens, siblings or a subtree.
 */
export class Max implements Ceiling {
  readonly key: string;
  readonly value: number;
  readonly metered = true;

  constructor(key: string, value: number) {
    checkKey(key);
    // A per-action cap on a COUNT caps nothing (every action is one call), and it is exactly what a
    // -01 producer emits as a call cap. This library meters `max_calls` as a running count, so
    // under the -02 a count bound is `max_lifetime` or `max_subtree`; a `max` on that key is
    // refused, in-process and at load (library profile restriction, not a rule of the draft, which
    // reserves no key names).
    if (key === "max_calls" || key.startsWith("max_calls[")) {
      throw new TypeError(
        `a per-action 'max' on the count key ${pyRepr(key)} bounds nothing; use max_lifetime or max_subtree for a call count`,
      );
    }
    checkNumber(key, "max", value);
    this.key = key;
    this.value = plain(value) as number;
  }

  get draftType(): string {
    return "max";
  }

  get ctxField(): string {
    return perActionField(this.key);
  }

  permits(ctx: Context): Decision {
    const n = ownValue(ctx, this.ctxField);
    if (n === undefined || n === null) return Decision.allow();
    const kind = wrongKind(n, NUMBER);
    if (kind === null && (plain(n) as number) <= this.value) return Decision.allow();
    return numberDenial(this.key, this.value, n, kind, "a maximum");
  }

  describe(): string {
    return `${this.key}<=${pyNumber(this.value)}`;
  }

  narrow(other: Ceiling): Max {
    return new Max(this.key, Math.min(this.value, (other as Max).value));
  }

  subsumes(other: Ceiling): boolean {
    return sameClass(other, this) && other.key === this.key && this.value >= (other as Max).value;
  }

  toWire(): Record<string, Json> {
    return { key: this.key, max: this.value };
  }

  static fromWire(d: Record<string, Json>): Max {
    return new Max(d["key"] as string, d["max"] as number);
  }
}

/**
 * Per-action numeric floor (`min`): the quantity MUST NOT be less than `value`. A child tightens a
 * floor UPWARD, so narrowing takes the larger value.
 */
export class Min implements Ceiling {
  readonly key: string;
  readonly value: number;

  constructor(key: string, value: number) {
    checkKey(key);
    checkNumber(key, "min", value);
    this.key = key;
    this.value = plain(value) as number;
  }

  get draftType(): string {
    return "min";
  }

  get ctxField(): string {
    return perActionField(this.key);
  }

  permits(ctx: Context): Decision {
    const n = ownValue(ctx, this.ctxField);
    if (n === undefined || n === null) return Decision.allow();
    const kind = wrongKind(n, NUMBER);
    if (kind === null && (plain(n) as number) >= this.value) return Decision.allow();
    return numberDenial(this.key, this.value, n, kind, "a minimum");
  }

  describe(): string {
    return `${this.key}>=${pyNumber(this.value)}`;
  }

  narrow(other: Ceiling): Min {
    return new Min(this.key, Math.max(this.value, (other as Min).value));
  }

  subsumes(other: Ceiling): boolean {
    return sameClass(other, this) && other.key === this.key && this.value <= (other as Min).value;
  }

  toWire(): Record<string, Json> {
    return { key: this.key, min: this.value };
  }

  static fromWire(d: Record<string, Json>): Min {
    return new Min(d["key"] as string, d["min"] as number);
  }
}

/**
 * Shared behaviour of the two cumulative types. `permits` reads the RUNNING TOTAL from the context
 * field named by `ctxField`; a context that carries no total is a component that does not hold it,
 * and step 8 of the -02 says such a component MUST deny.
 */
abstract class Cumulative implements Ceiling {
  readonly key: string;
  readonly value: number;
  readonly metered = true;
  abstract readonly draftType: string;
  abstract readonly ctxField: string;

  constructor(key: string, value: number, member: string) {
    checkKey(key);
    checkNumber(key, member, value);
    this.key = key;
    this.value = plain(value) as number;
  }

  /**
   * What a `max_calls` lifetime bound counts, for `Guard.autoMeter`: the scope pattern in
   * `max_calls[<pattern>]`, or "*" for every call of the node.
   */
  get meterKey(): string {
    if (this.key.startsWith("max_calls[") && this.key.endsWith("]")) return this.key.slice("max_calls[".length, -1);
    return "*";
  }

  appliesToScope(scope: string | null | undefined): boolean {
    const pattern = this.meterKey;
    if (pattern === "*" || scope === null || scope === undefined) return true;
    return scopeCovers(pattern, scope) || pattern === scope;
  }

  permits(ctx: Context): Decision {
    if (this.key.startsWith("max_calls") && !this.appliesToScope(ownValue(ctx, "_scope") as string | undefined)) {
      return Decision.allow();
    }
    const n = ownValue(ctx, this.ctxField);
    if (n === undefined || n === null) {
      return Decision.deny(
        new Reason(ReasonCode.CEILING_EXCEEDED, {
          constraint: this.key,
          limit: this.value,
          requested: null,
          message:
            `no running total for ${pyStrRepr(this.ctxField)} is held here; a cumulative ` +
            "constraint is checked only where its total is held; refused",
        }),
      );
    }
    const kind = wrongKind(n, NUMBER);
    if (kind === null && (plain(n) as number) <= this.value) return Decision.allow();
    return numberDenial(this.key, this.value, n, kind, "a maximum");
  }

  describe(): string {
    return `${this.key}<=${pyNumber(this.value)} (${this.draftType})`;
  }

  abstract narrow(other: Ceiling): Ceiling;

  subsumes(other: Ceiling): boolean {
    return sameClass(other, this) && other.key === this.key && this.value >= (other as Cumulative).value;
  }

  toWire(): Record<string, Json> {
    return { key: this.key, [this.draftType]: this.value };
  }
}

/**
 * `max_lifetime`: the SUM of the quantity over every action authorized under the token carrying it
 * (its `jti`) MUST NOT exceed `value`. Read from the lifetime-total field.
 */
export class MaxLifetime extends Cumulative {
  constructor(key: string, value: number) {
    super(key, value, "max_lifetime");
  }

  get draftType(): string {
    return "max_lifetime";
  }

  get ctxField(): string {
    return lifetimeField(this.key);
  }

  narrow(other: Ceiling): MaxLifetime {
    return new MaxLifetime(this.key, Math.min(this.value, (other as MaxLifetime).value));
  }

  static fromWire(d: Record<string, Json>): MaxLifetime {
    return new MaxLifetime(d["key"] as string, d["max_lifetime"] as number);
  }
}

/**
 * `max_subtree`: the SUM over the token and every token descended from it MUST NOT exceed `value`.
 * The total spans tokens, so it is held by accounting outside any one chain (Section 9.4 of the
 * -02); a context carrying none denies.
 */
export class MaxSubtree extends Cumulative {
  constructor(key: string, value: number) {
    super(key, value, "max_subtree");
  }

  get draftType(): string {
    return "max_subtree";
  }

  get ctxField(): string {
    return subtreeField(this.key);
  }

  narrow(other: Ceiling): MaxSubtree {
    return new MaxSubtree(this.key, Math.min(this.value, (other as MaxSubtree).value));
  }

  static fromWire(d: Record<string, Json>): MaxSubtree {
    return new MaxSubtree(d["key"] as string, d["max_subtree"] as number);
  }
}

function checkOrder(key: string, order: unknown): readonly string[] {
  if (order === undefined || !Array.isArray(order)) throw malformed(key, "order", order, "an array");
  if (order.length < 2 || order.some((o) => typeof o !== "string") || new Set(order).size !== order.length) {
    throw new TypeError(`order of constraint ${pyRepr(key)} must list two or more distinct strings`);
  }
  return Object.freeze([...(order as string[])]);
}

function sameOrder(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * `rank` with its `order`: `order` lists an enumeration from least to most permissive and travels
 * with the constraint, so a verifier needs no registry entry per key. The request value MUST be a
 * member of `order` at a position not above `rank`'s; a value outside `order` is refused. A child's
 * `order` MUST be identical to its parent's, element for element.
 */
export class Rank implements Ceiling {
  readonly key: string;
  readonly rank: string;
  readonly order: readonly string[];

  constructor(key: string, rank: string, order: readonly string[]) {
    checkKey(key);
    this.key = key;
    this.order = checkOrder(key, order);
    if (typeof rank !== "string" || !this.order.includes(rank)) {
      throw malformed(key, "rank", rank, "a member of order", typeof rank === "string" ? pyRepr(rank) : undefined);
    }
    this.rank = rank;
  }

  get draftType(): string {
    return "rank";
  }

  get ctxField(): string {
    return perActionField(this.key);
  }

  private index(value: string): number {
    return this.order.indexOf(value);
  }

  permits(ctx: Context): Decision {
    const val = ownValue(ctx, this.ctxField);
    if (val === undefined || val === null) return Decision.allow();
    const kind = wrongKind(val, STRING);
    if (kind === null && this.order.includes(val as string) && this.index(val as string) <= this.index(this.rank)) {
      return Decision.allow();
    }
    return Decision.deny(
      new Reason(ReasonCode.CEILING_EXCEEDED, {
        constraint: this.key,
        limit: this.rank,
        requested: val,
        message: refusal(kind, "a rank"),
      }),
    );
  }

  describe(): string {
    return `${this.key}<=${this.rank} in [${this.order.join(", ")}]`;
  }

  narrow(other: Ceiling): Rank {
    const o = other as Rank;
    if (!sameOrder(o.order, this.order)) {
      throw new TypeError(`rank orderings differ on ${pyRepr(this.key)}; neither narrows the other`);
    }
    const stricter = this.index(this.rank) <= this.index(o.rank) ? this.rank : o.rank;
    return new Rank(this.key, stricter, this.order);
  }

  subsumes(other: Ceiling): boolean {
    if (!sameClass(other, this) || other.key !== this.key) return false;
    const o = other as Rank;
    return sameOrder(o.order, this.order) && this.index(o.rank) <= this.index(this.rank);
  }

  toWire(): Record<string, Json> {
    return { key: this.key, rank: this.rank, order: [...this.order] };
  }

  static fromWire(d: Record<string, Json>): Rank {
    return new Rank(d["key"] as string, d["rank"] as string, d["order"] as unknown as string[]);
  }
}

// =========================================================================
// Constraint objects on the -02 wire
// =========================================================================

const GENERIC = new Map<string, CeilingClass>([
  ["max", Max],
  ["min", Min],
  ["max_lifetime", MaxLifetime],
  ["max_subtree", MaxSubtree],
  ["rank", Rank],
  ["one_of", Allow],
  ["not_one_of", Deny],
  ["prefix", Prefix],
]);
/** Members a type's definition adds beside "key" and the type member itself. */
const EXTRA_MEMBERS: Readonly<Record<string, readonly string[]>> = { rank: ["order"] };

/** Python's `str()` of a tuple of strings, so (key, type) pairs sort as the Python port's do. */
function pyTupleStr(items: readonly string[]): string {
  return `(${items.map(pyStrRepr).join(", ")}${items.length === 1 ? "," : ""})`;
}

/**
 * The -02 type of a ceiling (the wire member name that carries its value), used to pair constraints
 * by (key, type). The library's ceilings declare it (`draftType`); an unknown constraint pairs by
 * the set of members it carries, so two unknown constraints of different shapes are two
 * constraints. Returned as text: for an unknown constraint, the Python port's tuple as Python
 * prints it, so the (key, type) order is the same order in both implementations.
 */
export function draftTypeOf(ceiling: Ceiling): string {
  const t = ceiling.draftType;
  if (t !== undefined && t !== null) return t;
  if (ceiling instanceof UnknownCeiling) {
    const members = Object.keys(ceiling.raw).filter((k) => k !== "key").sort(compareCodePoints);
    return pyTupleStr(["unknown", ...members]);
  }
  return (ceiling as object).constructor.name;
}

/** The members an unknown constraint pairs by, after "unknown"; `null` for any other ceiling. */
function unknownShape(ceiling: Ceiling): string[] | null {
  if (ceiling.draftType !== undefined && ceiling.draftType !== null) return null;
  if (!(ceiling instanceof UnknownCeiling)) return null;
  return ["unknown", ...Object.keys(ceiling.raw).filter((k) => k !== "key").sort(compareCodePoints)];
}

/** `draftTypeOf(ceiling)` as Python's `repr` prints the Python port's value: a quoted string, or a tuple. */
export function draftTypeRepr(ceiling: Ceiling): string {
  const shape = unknownShape(ceiling);
  return shape === null ? pyStrRepr(draftTypeOf(ceiling)) : pyTupleStr(shape);
}

/** `draftTypeOf(ceiling)` as JSON, as the Python port's value lands in a ledger: a string, or an array. */
export function draftTypeJson(ceiling: Ceiling): Json {
  return unknownShape(ceiling) ?? draftTypeOf(ceiling);
}

function isPlainObject(value: unknown): value is Record<string, Json> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * One -02 constraint object -> a ceiling. The object is closed: `key`, exactly one type member, and
 * the members that type adds (`order` for `rank`). Anything else is malformed. A single member this
 * build does not implement is an unknown constraint, kept whole and failing closed (unknown types
 * deny every action and subsume only an identical one).
 */
export function ceilingFromWire02(wire: CJson): Ceiling {
  const d = toPlain<Json>(wire);
  if (!isPlainObject(d)) throw new TypeError(`a constraint is ${jsonKind(d)}, not an object`);
  checkKey(d["key"]);
  const key = d["key"] as string;
  const members = Object.keys(d).filter((m) => m !== "key");
  const known = members.filter((m) => GENERIC.has(m));
  if (known.length > 1) {
    throw new TypeError(
      `constraint ${pyRepr(key)} carries ${known.length} typed values (${[...known].sort(compareCodePoints).join(", ")}); ` +
        "a constraint carries exactly one",
    );
  }
  if (known.length === 0) {
    if (members.length === 1) return UnknownCeiling.fromWire(d); // one unimplemented type: fail closed, not malformed
    throw new TypeError(
      `constraint ${pyRepr(key)} carries no typed value this build implements and ` +
        `${members.length} other members; a constraint carries exactly one typed value`,
    );
  }
  const ctype = known[0]!;
  const allowed = new Set(["key", ctype, ...(EXTRA_MEMBERS[ctype] ?? [])]);
  const extra = Object.keys(d).filter((m) => !allowed.has(m)).sort(compareCodePoints);
  if (extra.length > 0) {
    throw new TypeError(
      `constraint ${pyRepr(key)} of type ${pyStrRepr(ctype)} carries members this type does not ` +
        `define: ${extra.map(pyStrRepr).join(", ")}; a constraint object is closed`,
    );
  }
  return GENERIC.get(ctype)!.fromWire(d);
}

/**
 * The -02 wire form of any ceiling: the generic and legacy classes that know their -02 shape emit
 * it; the library's membership and prefix ceilings drop their `type` discriminator, which the -02's
 * closed constraint object does not admit; an unknown constraint re-emits its bytes. A `field` that
 * differs from the key cannot be expressed on the -02 wire and is refused.
 */
export function ceilingToWire02(c: Ceiling): Record<string, Json> {
  const w: Record<string, Json> = typeof c.toWire02 === "function" ? c.toWire02() : { ...c.toWire() };
  if (c instanceof UnknownCeiling) return w;
  delete w["type"];
  if (Object.prototype.hasOwnProperty.call(w, "field")) {
    if (w["field"] !== w["key"]) {
      throw new TypeError(
        `constraint ${pyRepr(c.key)} reads context field ${pyRepr(w["field"] ?? null)}, which the ` +
          "-02 wire cannot express; the key names the field there",
      );
    }
    delete w["field"];
  }
  return w;
}

/** The -02 Section 3 rule: an integer whose magnitude exceeds 2^53-1 is malformed. */
export function checkIntegerSafe(value: unknown): void {
  if (typeof value === "number" && Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new TypeError(`integer ${value} exceeds the safe range for a binary64 signing surface`);
  }
}

/** Two unknown constraints are identical when their RFC 8785 bytes are. */
export function isIdenticalUnknown(a: UnknownCeiling, b: UnknownCeiling): boolean {
  try {
    return canonicalJson(a.raw) === canonicalJson(b.raw);
  } catch {
    return false;
  }
}
