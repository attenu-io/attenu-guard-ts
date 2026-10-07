/**
 * Authority — the core value object.
 *
 * An Authority is an immutable capability: a set of scopes plus typed `Ceiling`
 * bounds and a TTL. The single most important operation is `meet`: the greatest
 * authority that is within BOTH a parent's authority and a requested one. A
 * child of a delegation can never hold more than the meet — attenuation is a
 * lattice operation, enforced in code, not a convention.
 *
 * The guarantee everything else rests on:
 *
 *     meet(parent, requested) <= parent   for ALL requested.
 *
 * There is no code path by which a derived child authority can exceed its
 * parent. That is what makes model-proposed authority safe to accept: the
 * proposal is only ever an input to `meet`, and `meet` can only shrink.
 *
 * `isNarrowerThan` is exactly the wire protocol's subsumption relation
 * (draft-asor-wimse-agent-delegation-chain-01), so a chain that verifies offline
 * is one the library would have permitted, and the reverse.
 */

import { compareCodePoints, sortedStrings, toPlain, type CJson, type Json } from "./canonical.js";
import { pyRepr, pyStrRepr } from "./display.js";
import {
  SCOPE_RE,
  UnknownCeiling,
  ceilingFromWire,
  ctxFieldOf,
  describe as describeCeiling,
  jsonKind,
  sameType,
  type Ceiling,
  type Context,
} from "./ceilings.js";
import { Decision, Reason, ReasonCode } from "./reasons.js";
import {
  CUMULATIVE_TYPES,
  PROFILE_01,
  PROFILE_02,
  ceilingFromWire02,
  ceilingToWire02,
  checkProfile,
  draftTypeJson,
  draftTypeOf,
  draftTypeRepr,
  scopeCovers as scopeCovers02,
  validateScope as validateScope02,
  type Profile,
} from "./draft02.js";

/**
 * Raised for STRUCTURAL failures — bad input or invalid chain state, such as
 * delegating from a revoked or expired node, or a depth/fanout overflow.
 * Deliberately distinct from a policy denial: a denial is a normal outcome,
 * expressed as a `Decision`. A structural error means the caller did something
 * invalid; a denial means the caller asked for something the authority model
 * legitimately refuses.
 */
export class AuthorityError extends Error {
  readonly reason: string;
  readonly detail: Record<string, Json>;

  constructor(message: string, reason: string, detail: Record<string, Json> = {}) {
    super(message);
    this.name = "AuthorityError";
    this.reason = reason;
    this.detail = detail;
  }
}

/**
 * `ceilingFromWire`, but refusing a constraint we would only partly read.
 *
 * The test is a MEMBER difference, not value equality. Parse the constraint,
 * re-emit it, and refuse if the input carried a member the re-emission does not
 * -- that member is one this build did not read. That was live and silent:
 *
 *     {"key":"max_rows","max":100,"min":9999}  ->  {"key":"max_rows","max":100}
 *
 * byte-identical to a constraint that never carried a floor. `min` is a
 * first-class type in the draft's constraint vocabulary ("the value MUST NOT be
 * less than it"), so this dropped a signed, spec-defined, *restricting* term.
 * The draft allows one typed value per object, which makes two malformed -- it
 * must be refused, never silently resolved to whichever one this build happens
 * to read first.
 *
 * Comparing whole VALUES instead was tried and reverted before release: it
 * could not tell "we ignored a member" from "we normalised a value", and
 * several built-ins legitimately normalise (`Allow` emits its `one_of` sorted
 * and holds it as a set; `toWire` omits `field` when it equals `key`). RFC 8785
 * canonicalises object member ORDER and never reorders array elements, and the
 * draft puts no ordering or uniqueness requirement on `one_of` -- so
 * `["us-west", "us-east"]` is a conformant constraint from a third-party
 * issuer, and value equality called it malformed. On a release whose whole
 * subject is reading tokens correctly, refusing correct tokens is the worse
 * failure.
 *
 * An unrecognised constraint TYPE is deliberately not caught here:
 * `UnknownCeiling` preserves its whole object, so nothing looks dropped, and it
 * still routes to the fail-closed path the draft requires. Rejecting those here
 * would turn a deny into a parse error and lose that distinction.
 *
 * Kept in step with the Python port (`authority._ceiling_from_wire_whole`).
 */
function ceilingFromWireWhole(c: CJson): Ceiling {
  const ceiling = ceilingFromWire(c);
  const input = toPlain<Record<string, Json>>(c);
  if (input !== undefined && input !== null && typeof input === "object") {
    const emitted = toPlain<Record<string, Json>>(ceiling.toWire()) ?? {};
    // `key` is the one member whose VALUE is load-bearing: subsumption pairs
    // ceilings by it, so a rewritten key is a different dimension, not a
    // cosmetic difference. `CallLimit` rewrites it ("max_calls" ->
    // "max_calls[fs.write]" when `applies_to` is present), which the member test
    // cannot see because the member set is unchanged. Checked on its own rather
    // than by returning to whole-value equality, which broke conformant tokens a
    // revision ago.
    // The values in these messages are the bundle's, and the messages reach `attenu-guard verify`
    // output inside "unreadable authority (...)". So they print through Python's `repr`, as the
    // Python port prints them: quoted, every non-printable character escaped, one line.
    if (emitted["key"] !== input["key"]) {
      throw new AuthorityError(
        `constraint ${pyRepr(input)} names dimension ${pyRepr(input["key"] ?? null)} ` +
          `but this build reads it as ${pyRepr(emitted["key"] ?? null)}; refusing rather ` +
          "than silently changing which dimension is bounded",
        "malformed_constraint",
      );
    }
    const dropped = Object.keys(input)
      // The emission's OWN members: `k in emitted` found `constructor`, `toString` and the rest of
      // Object.prototype on every plain object, so a member named like one was ignored, where the
      // Python implementation refuses it (attenu-ops#110).
      .filter((k) => !Object.prototype.hasOwnProperty.call(emitted, k))
      // `field` is read and then not re-emitted when it equals `key`, because at
      // that point it is redundant. Absent from the emission does not mean
      // unread, so exempt it only on EVIDENCE that this ceiling parsed it: the
      // attribute the constructor actually populated. `ctxFieldOf` is not that
      // evidence -- it falls back to a hardcoded `ctxField` and then to `key`,
      // so it returns the input's value by coincidence for the metered built-ins
      // (which never read `field` at all) and unconditionally for a custom
      // ceiling deriving `ctxField` from its own input.
      .filter((k) => !(k === "field" && (ceiling as { field?: unknown }).field === input["field"]))
      .sort(compareCodePoints);
    if (dropped.length > 0) {
      throw new AuthorityError(
        `constraint ${pyRepr(input)} carries members this build does not ` +
          `evaluate and will not ignore: ${dropped.map(pyStrRepr).join(", ")}`,
        "malformed_constraint",
      );
    }
  }
  return ceiling;
}

export interface PermitsOptions {
  /**
   * The running totals the caller holds for this authority's cumulative -02 constraints, keyed by
   * total field (`spend_total`, `calls_subtree_total`). The only source of a total under the -02.
   */
  totals?: Context | null;
}

export interface AuthorityInit {
  scopes?: Iterable<string>;
  ceilings?: Iterable<Ceiling>;
  /** Seconds this authority remains valid from issuance; `null` is unbounded. */
  ttl?: number | null;
  /**
   * Which revision of the Internet-Draft this authority follows: "01" (the default, and every
   * pre-existing caller) or "02" (draft02.ts: three-form scope grammar, generic constraint types,
   * one constraint per (key, type)). The profile is not on the wire; `load(..., { draft })` and
   * `Authority.fromWire(wire, profile)` set it.
   */
  profile?: Profile;
}

/** The wire form of an Authority. */
export interface AuthorityWire {
  scopes: string[];
  constraints: Record<string, Json>[];
  ttl: number | null;
  // A wire form is a JSON object, so it can be handed straight to
  // `canonicalJson`, `Authority.fromWire`, or a ledger field.
  [key: string]: CJson;
}

/**
 * Validate the agent_delegation scope grammar defined by the I-D: the -01's two forms by default,
 * the -02's three forms (literal, wildcard, opaque) under profile "02".
 */
function validateScope(scope: unknown, profile: Profile = PROFILE_01): asserts scope is string {
  if (profile === PROFILE_02) {
    validateScope02(scope);
    return;
  }
  if (typeof scope !== "string" || !SCOPE_RE.test(scope)) {
    throw new TypeError(
      `invalid scope ${pyRepr((scope ?? null) as CJson)}: expected lowercase dot-separated segments; ` +
        "'*' is permitted only as the complete final segment after a dot",
    );
  }
}

export class Authority {
  /**
   * Lowercase, dot-separated permission strings, e.g. `crm.read`. A terminal
   * prefix wildcard such as `crm.*` covers every depth below the dotted `crm.`
   * boundary, but not bare `crm` or the adjacent namespace `crmx.read`. A child
   * requesting `crm.read` under a parent holding `crm.*` is allowed; the reverse
   * is not. Bare or non-terminal `*` is invalid.
   */
  readonly scopes: ReadonlySet<string>;

  /**
   * One ceiling per `key` (a second one under the same key throws a TypeError),
   * sorted by key for a deterministic wire form and integrity seal. A dimension
   * with no ceiling is unbounded on that dimension unless a parent in the chain
   * bounds it — attenuation can only add or tighten bounds, never remove one.
   */
  readonly ceilings: readonly Ceiling[];

  /** Seconds from issuance. `null` is unbounded (discouraged). */
  readonly ttl: number | null;

  /** The revision of the Internet-Draft this authority follows (`AuthorityInit.profile`). */
  readonly profile: Profile;

  constructor(init: AuthorityInit = {}) {
    this.profile = checkProfile(init.profile ?? PROFILE_01);
    const scopes = new Set(init.scopes ?? []);
    for (const scope of scopes) validateScope(scope, this.profile);
    this.scopes = scopes;
    const byKey = new Map<string, Ceiling>();
    for (const c of init.ceilings ?? []) {
      // One constraint per key, on every path (attenu-ops#110): the last one won, silently, so
      // [allow region in [us], deny region not in [rm]] kept only the deny-list. Under the -02
      // the unit is (key, type), so a `min` and a `max` on one quantity form a range, while two
      // `max` on one key are still malformed (draft -02 Section 4.2).
      const k = this.pairKey(c);
      if (byKey.has(k)) {
        if (this.profile === PROFILE_02) {
          throw new TypeError(
            `two constraints share the key ${pyRepr(c.key as CJson)} and the type ` +
              `${draftTypeRepr(c)}; an authority holds one per (key, type)`,
          );
        }
        throw new TypeError(`two constraints share the key ${pyRepr(c.key as CJson)}; an authority holds one per key`);
      }
      byKey.set(k, c);
    }
    this.ceilings = this.sortedKeys(byKey.keys()).map((k) => byKey.get(k)!);
    this.ttl = init.ttl ?? null;
  }

  /**
   * What two constraints are paired by in `meet` and `isNarrowerThan`: the key (-01), or the
   * (key, type) pair (-02), encoded as one string.
   */
  private pairKey(c: Ceiling): string {
    if (this.profile === PROFILE_02) return JSON.stringify([String(c.key), draftTypeOf(c)]);
    return String(c.key);
  }

  /**
   * Deterministic wire order of pairing keys. The -01 order (plain string sort) is unchanged; the
   * -02's (key, type) pairs sort by key, then type.
   */
  private sortedKeys(keys: Iterable<string>): string[] {
    if (this.profile === PROFILE_02) {
      return Array.from(keys).sort((a, b) => {
        const [ak, at] = JSON.parse(a) as [string, string];
        const [bk, bt] = JSON.parse(b) as [string, string];
        return compareCodePoints(ak, bk) || compareCodePoints(at, bt);
      });
    }
    return Array.from(keys).sort(compareCodePoints);
  }

  private byKey(): Map<string, Ceiling> {
    const m = new Map<string, Ceiling>();
    for (const c of this.ceilings) m.set(this.pairKey(c), c);
    return m;
  }

  /**
   * The ceiling bound to `key`, or `undefined`. Under the -02 a key may carry several constraints
   * of different types; this returns the first in wire order, and `ceilingsFor(key)` returns them
   * all.
   */
  ceiling(key: string): Ceiling | undefined {
    return this.ceilings.find((c) => c.key === key);
  }

  /** Every ceiling bound to `key`, in wire order. */
  ceilingsFor(key: string): Ceiling[] {
    return this.ceilings.filter((c) => c.key === key);
  }

  // ---- scope helpers ----------------------------------------------------

  /** Exact match, or a terminal `x.*` prefix at the retained dot boundary. */
  static scopeCovers(held: string, requested: string): boolean {
    if (held === requested) return true;
    if (held.endsWith(".*")) return requested.startsWith(held.slice(0, -1)); // keep the dot
    return false;
  }

  /** The covering relation of this authority's profile: `scopeCovers` (-01) or draft02's. */
  private covers(held: string, requested: string): boolean {
    if (this.profile === PROFILE_02) return scopeCovers02(held, requested);
    return Authority.scopeCovers(held, requested);
  }

  coversScope(requested: string): boolean {
    for (const held of this.scopes) {
      if (this.covers(held, requested)) return true;
    }
    return false;
  }

  // ---- the lattice ------------------------------------------------------

  /**
   * The greatest authority within BOTH `this` and `other` — the attenuation.
   * This is the only way a child authority is constructed, with `this` the
   * parent and `other` the request. It is commutative and can only ever shrink
   * relative to either input, except in one case, by design (attenu-ops#110):
   * a constraint this build does not define on the parent's side passes down,
   * so the child inherits it, and it denies every action; one in the request
   * under a parent's ceiling of another type is refused with an AuthorityError
   * (reason `not_narrower`), as two different ceiling types under one key are.
   * So `parent.meet(request)` and `request.meet(parent)` differ there.
   */
  meet(other: Authority): Authority {
    if (other.profile !== this.profile) {
      // A request under another revision's rules has no common narrowing with this authority:
      // refused as a delegation, so Guard.delegate records spawn_denied.
      throw new AuthorityError(
        `cannot meet an authority of profile ${pyStrRepr(this.profile)} with one of profile ${pyStrRepr(other.profile)}`,
        "not_narrower",
        { profile: other.profile },
      );
    }
    // Scopes: keep a requested scope only if this side covers it, and keep this
    // side's own concrete scopes that the other covers. The net effect is a
    // wildcard-aware intersection, never larger than either side's coverage.
    const merged = new Set<string>();
    for (const s of other.scopes) if (this.coversScope(s)) merged.add(s);
    for (const s of this.scopes) if (other.coversScope(s)) merged.add(s);

    // Remove only REDUNDANT scopes: one covered by a broader wildcard that is
    // also present. This keeps the broadest legitimately-granted authority and
    // only trims duplicates, so a wildcard granted by both sides survives.
    const wildcards = Array.from(merged).filter((s) => s.endsWith(".*"));
    const pruned = new Set(
      Array.from(merged).filter(
        (s) => !wildcards.some((w) => w !== s && this.covers(w, s)),
      ),
    );

    // Ceilings: union of keys. Where BOTH sides bound a key, narrow it; where
    // only one side bounds it, carry that bound through unchanged. A ceiling
    // therefore only ever appears or tightens across a meet, never disappears —
    // exactly the property `isNarrowerThan` checks.
    const mine = this.byKey();
    const theirs = other.byKey();
    const keys = this.sortedKeys(new Set([...mine.keys(), ...theirs.keys()]));
    const ceilings: Ceiling[] = [];
    for (const k of keys) {
      const a = mine.get(k);
      const b = theirs.get(k);
      if (a !== undefined && b !== undefined && !sameType(a, b)) {
        // Two ceiling types under one key have no common narrowing, so the delegation is refused
        // as not narrower, and `Guard.delegate` records it as `spawn_denied` (attenu-ops#110). One
        // exception: this side's constraint this build does not define, which denies every action,
        // is kept, so the child inherits it, as 0.13.0 delegated from a parent holding one. A
        // request carrying one under this side's other ceiling is refused: the child would not be
        // narrower (`isNarrowerThan`).
        if (a instanceof UnknownCeiling) {
          ceilings.push(a);
          continue;
        }
        // The constraint as the Python port names it: the key (-01), or the (key, type) pair (-02).
        const named = this.profile === PROFILE_02 ? `(${pyStrRepr(String(a.key))}, ${draftTypeRepr(a)})` : pyRepr(k);
        throw new AuthorityError(
          `constraint ${named} has a different ceiling type on each side; neither narrows the other`,
          "not_narrower",
          { constraint: this.profile === PROFILE_02 ? [String(a.key), draftTypeJson(a)] : k },
        );
      }
      if (a !== undefined && b !== undefined) {
        try {
          ceilings.push(a.narrow(b));
        } catch (e) {
          // A -02 rank whose ordering differs from the request's: no common narrowing. The Python
          // port catches its ValueError here, which this port throws as a TypeError.
          if (!(e instanceof TypeError)) throw e;
          throw new AuthorityError(e.message, "not_narrower", { constraint: a.key });
        }
      } else {
        ceilings.push((a ?? b)!);
      }
    }

    const ttls = [this.ttl, other.ttl].filter((t): t is number => t !== null);
    const ttl = ttls.length > 0 ? Math.min(...ttls) : null;

    return new Authority({ scopes: pruned, ceilings, ttl, profile: this.profile });
  }

  /**
   * `this <= other`: is `this` provably no more powerful than `other` in every
   * dimension? True iff:
   *
   *   1. every scope of `this` is covered by `other` (wildcard-aware);
   *   2. for every ceiling in `other` there is a ceiling of the same key in
   *      `this` that `other`'s ceiling subsumes. A ceiling present in `other`
   *      and ABSENT here means `this` is unbounded on that dimension, i.e. more
   *      powerful, so the relation is false. This holds for any ceiling key,
   *      including ones outside the built-in registry, which is what makes the
   *      relation sound for custom ceilings too;
   *   3. `this.ttl` is not null and (`other.ttl` is null or `this.ttl <= other.ttl`).
   *
   * This is exactly the wire subsumption relation: the library relation and the
   * token relation are the same relation.
   */
  isNarrowerThan(other: Authority): boolean {
    if (other.profile !== this.profile) return false;
    for (const s of this.scopes) {
      if (!other.coversScope(s)) return false;
    }
    const mine = this.byKey();
    for (const [k, otherCeiling] of other.byKey()) {
      const selfCeiling = mine.get(k);
      if (selfCeiling === undefined) return false; // unbounded here where other bounds
      // Two ceiling types under one key are not comparable, so not narrower (a custom ceiling's
      // subsumes() need not handle another type).
      if (!sameType(selfCeiling, otherCeiling) || !otherCeiling.subsumes(selfCeiling)) return false;
    }
    if (other.ttl !== null) {
      if (this.ttl === null || this.ttl > other.ttl) return false;
    }
    return true;
  }

  // ---- policy evaluation ------------------------------------------------

  /**
   * Is `scope` permitted under this authority, given a request context such as
   * `{rows: 5000, egress: "none"}`?
   *
   * Checks scope coverage AND every ceiling this authority holds, collecting
   * every failing reason — not just the first — so a single evaluation can
   * explain everything wrong with a request. A ceiling whose context field is
   * absent is not asserting anything on this call and is treated as satisfied.
   *
   * `options.totals` is the TRUSTED channel for the running totals a cumulative -02 constraint
   * (`max_lifetime`, `max_subtree`) is measured over: the component holding a total supplies it
   * here, keyed by the ceiling's total field (`spend_total`, `spend_subtree_total`, ...). Under
   * the -02 profile the held total fields (`totalFields`) are dropped from `ctx` before
   * evaluation, as `_scope` is: the context is what an adapter fills from the tool call's own
   * arguments, and a total the caller asserts about itself is the attenu-ops#110 defect class.
   */
  permits(scope: string, ctx: Context | null = null, options: PermitsOptions = {}): Decision {
    const context = this.effectiveContext(ctx, options.totals ?? null);
    const reasons: Reason[] = [];

    if (!this.coversScope(scope)) {
      reasons.push(
        new Reason(ReasonCode.SCOPE_NOT_GRANTED, {
          requested: scope,
          message: `scope '${scope}' not covered by held scopes [${sortedStrings(this.scopes)
            .map((s) => `'${s}'`)
            .join(", ")}]`,
        }),
      );
    }

    // Reserved key so scoped ceilings can tell whether they apply. Always the scope being checked: a
    // `_scope` in the caller's context is ignored, so it can move no call off its own meter or onto
    // another (attenu-ops#110).
    const cctx: Context = { ...context };
    cctx["_scope"] = scope;
    for (const c of this.ceilings) {
      const decision = c.permits(cctx);
      if (decision.allowed) continue;
      // A denial with no reason still denies: an empty list read as an allow, so a custom ceiling's
      // bare `Decision.deny([])` let every call through (attenu-ops#110).
      if (decision.reasons.length > 0) reasons.push(...decision.reasons);
      else reasons.push(new Reason(ReasonCode.CEILING_EXCEEDED, { constraint: c.key, message: "denied without a reason" }));
    }

    return reasons.length > 0 ? Decision.deny(reasons) : Decision.allow();
  }

  /**
   * The context fields the cumulative constraints this authority HOLDS read their running total
   * from (`calls`, `spend_total`, `spend_subtree_total`, ...). Only these are stripped from a
   * caller's context and only these may be supplied through `totals`; an ordinary constraint keyed
   * `order_total` keeps reading its own field.
   */
  totalFields(): Set<string> {
    return new Set(
      this.ceilings
        .filter((c) => (CUMULATIVE_TYPES as readonly string[]).includes(draftTypeOf(c)))
        .map((c) => ctxFieldOf(c)),
    );
  }

  /**
   * The context an evaluation reads: the caller's context with the held total fields removed
   * under the -02 profile, then the trusted `totals` applied. `totals` may name only held total
   * fields; anything else is a TypeError, so a misuse is loud rather than a silent overwrite.
   * `Guard` builds its strict-metering check from this same function, so the two never read
   * different contexts.
   */
  effectiveContext(ctx: Context | null, totals: Context | null = null): Context {
    const held = this.totalFields();
    let context: Context = { ...(ctx ?? {}) };
    if (this.profile === PROFILE_02) {
      context = Object.fromEntries(Object.entries(context).filter(([k]) => !held.has(k)));
    }
    if (totals) {
      const stray = Object.keys(totals).filter((k) => !held.has(k)).sort(compareCodePoints);
      if (stray.length > 0) {
        throw new TypeError(
          `totals names fields no held cumulative constraint reads: [${stray.map(pyStrRepr).join(", ")}]; ` +
            `held total fields are [${[...held].sort(compareCodePoints).map(pyStrRepr).join(", ")}]`,
        );
      }
      Object.assign(context, totals);
    }
    return context;
  }

  withTtl(ttl: number | null): Authority {
    return new Authority({ scopes: this.scopes, ceilings: this.ceilings, ttl, profile: this.profile });
  }

  // ---- wire form --------------------------------------------------------

  /**
   * The authority's wire form under its own profile: the -01 constraint shapes by default; under
   * "02", every constraint in its -02 shape (`ceilingToWire02`). The profile itself is not written:
   * it is a property of the token format around it.
   */
  toWire(): AuthorityWire {
    return {
      scopes: sortedStrings(this.scopes),
      constraints:
        this.profile === PROFILE_02 ? this.ceilings.map((c) => ceilingToWire02(c)) : this.ceilings.map((c) => c.toWire()),
      ttl: this.ttl,
    };
  }

  static fromWire(wire: CJson, profile: Profile = PROFILE_01): Authority {
    const d = toPlain<Record<string, Json>>(wire) ?? {};
    // Read the authority object WHOLE, for the same reason the constraint inside
    // it is read whole. The token path is safe only by accident --
    // `authorityFromPayload` builds this object itself after checking the
    // detail's members -- but the BUNDLE path hands us the raw untrusted object
    // straight out of a ledger entry (`evidence`, the `authority` and `granted`
    // members). Without this, `verifyBundle` reported success on an authority it
    // had read by projection: a `granted` carrying `deny_scopes` verified clean
    // with `checks.ledger_fields` true, because that check only covers an
    // entry's TOP-LEVEL keys. Kept in step with the Python port.
    const unknownAuthorityMembers = Object.keys(d)
      .filter((k) => k !== "scopes" && k !== "constraints" && k !== "ttl")
      .sort(compareCodePoints);
    if (unknownAuthorityMembers.length > 0) {
      // Through Python's `repr`, as the Python port prints it: this message reaches
      // `attenu-guard verify` output, and a member name is the bundle's.
      throw new AuthorityError(
        `authority ${pyRepr(d)} carries members this build does not evaluate ` +
          `and will not ignore: ${unknownAuthorityMembers.map(pyStrRepr).join(", ")}`,
        "malformed_authority",
      );
    }
    const scopes = (d["scopes"] as string[] | undefined) ?? [];
    // An absent list is empty. A null one is empty under the -01 as it always was here, and is
    // refused under the -02 as the Python port refuses it on both.
    const listed = d["constraints"];
    const constraints = (listed === undefined || (listed === null && profile === PROFILE_01) ? [] : listed) as
      Record<string, Json>[];
    if (!Array.isArray(constraints)) {
      throw new TypeError(`constraints is ${jsonKind(constraints)}, not an array`);
    }
    const ttl = d["ttl"];
    return new Authority({
      scopes,
      ceilings: constraints.map((c) => (profile === PROFILE_02 ? ceilingFromWire02(c) : ceilingFromWireWhole(c))),
      ttl: typeof ttl === "number" ? ttl : null,
      profile,
    });
  }

  /** A stable, human-readable one-liner. */
  describe(): string {
    const scopes = sortedStrings(this.scopes).join(", ");
    const cs = this.ceilings.map((c) => describeCeiling(c)).sort(compareCodePoints).join(", ");
    return `scopes=[${scopes}] ceilings=[${cs}] ttl=${this.ttl}`;
  }

  toString(): string {
    const tail = this.profile === PROFILE_01 ? "" : ` profile=${this.profile}`;
    return `Authority(${this.describe()}${tail})`;
  }
}
