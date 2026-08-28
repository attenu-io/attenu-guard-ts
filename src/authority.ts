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
 * (draft-asor-wimse-agent-delegation-chain-00), so a chain that verifies offline
 * is one the library would have permitted, and the reverse.
 */

import { compareCodePoints, sortedStrings, toPlain, type CJson, type Json } from "./canonical.js";
import { ceilingFromWire, describe as describeCeiling, type Ceiling, type Context } from "./ceilings.js";
import { Decision, Reason, ReasonCode } from "./reasons.js";

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

export interface AuthorityInit {
  scopes?: Iterable<string>;
  ceilings?: Iterable<Ceiling>;
  /** Seconds this authority remains valid from issuance; `null` is unbounded. */
  ttl?: number | null;
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

export class Authority {
  /**
   * Permission strings, e.g. `crm.read`. Scopes support one level of prefix
   * wildcard: `crm.*` covers `crm.read` and `crm.write`. A child requesting
   * `crm.read` under a parent holding `crm.*` is allowed; the reverse is not.
   */
  readonly scopes: ReadonlySet<string>;

  /**
   * At most one ceiling per `key` (last one wins), sorted by key for a
   * deterministic wire form and integrity seal. A dimension with no ceiling is
   * unbounded on that dimension unless a parent in the chain bounds it —
   * attenuation can only add or tighten bounds, never remove one.
   */
  readonly ceilings: readonly Ceiling[];

  /** Seconds from issuance. `null` is unbounded (discouraged). */
  readonly ttl: number | null;

  constructor(init: AuthorityInit = {}) {
    this.scopes = new Set(init.scopes ?? []);
    const byKey = new Map<string, Ceiling>();
    for (const c of init.ceilings ?? []) byKey.set(String(c.key), c);
    this.ceilings = Array.from(byKey.keys())
      .sort(compareCodePoints)
      .map((k) => byKey.get(k)!);
    this.ttl = init.ttl ?? null;
  }

  private byKey(): Map<string, Ceiling> {
    const m = new Map<string, Ceiling>();
    for (const c of this.ceilings) m.set(String(c.key), c);
    return m;
  }

  /** The ceiling bound to `key`, or `undefined`. */
  ceiling(key: string): Ceiling | undefined {
    return this.byKey().get(key);
  }

  // ---- scope helpers ----------------------------------------------------

  /** Does a held scope cover a requested scope? Supports one `x.*` wildcard. */
  static scopeCovers(held: string, requested: string): boolean {
    if (held === requested) return true;
    if (held.endsWith(".*")) return requested.startsWith(held.slice(0, -1)); // keep the dot
    return false;
  }

  coversScope(requested: string): boolean {
    for (const held of this.scopes) {
      if (Authority.scopeCovers(held, requested)) return true;
    }
    return false;
  }

  // ---- the lattice ------------------------------------------------------

  /**
   * The greatest authority within BOTH `this` and `other` — the attenuation.
   * This is the only way a child authority is constructed. It is commutative
   * and can only ever shrink relative to either input.
   */
  meet(other: Authority): Authority {
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
        (s) => !wildcards.some((w) => w !== s && Authority.scopeCovers(w, s)),
      ),
    );

    // Ceilings: union of keys. Where BOTH sides bound a key, narrow it; where
    // only one side bounds it, carry that bound through unchanged. A ceiling
    // therefore only ever appears or tightens across a meet, never disappears —
    // exactly the property `isNarrowerThan` checks.
    const mine = this.byKey();
    const theirs = other.byKey();
    const keys = Array.from(new Set([...mine.keys(), ...theirs.keys()])).sort(compareCodePoints);
    const ceilings: Ceiling[] = [];
    for (const k of keys) {
      const a = mine.get(k);
      const b = theirs.get(k);
      ceilings.push(a !== undefined && b !== undefined ? a.narrow(b) : (a ?? b)!);
    }

    const ttls = [this.ttl, other.ttl].filter((t): t is number => t !== null);
    const ttl = ttls.length > 0 ? Math.min(...ttls) : null;

    return new Authority({ scopes: pruned, ceilings, ttl });
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
    for (const s of this.scopes) {
      if (!other.coversScope(s)) return false;
    }
    const mine = this.byKey();
    for (const [k, otherCeiling] of other.byKey()) {
      const selfCeiling = mine.get(k);
      if (selfCeiling === undefined) return false; // unbounded here where other bounds
      if (!otherCeiling.subsumes(selfCeiling)) return false;
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
   */
  permits(scope: string, ctx: Context | null = null): Decision {
    const context: Context = ctx ?? {};
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

    // Reserved key so scoped ceilings can tell whether they apply.
    const cctx: Context = { ...context };
    if (!("_scope" in cctx)) cctx["_scope"] = scope;
    for (const c of this.ceilings) {
      const decision = c.permits(cctx);
      if (!decision.allowed) reasons.push(...decision.reasons);
    }

    return reasons.length > 0 ? Decision.deny(reasons) : Decision.allow();
  }

  withTtl(ttl: number): Authority {
    return new Authority({ scopes: this.scopes, ceilings: this.ceilings, ttl });
  }

  // ---- wire form --------------------------------------------------------

  toWire(): AuthorityWire {
    return {
      scopes: sortedStrings(this.scopes),
      constraints: this.ceilings.map((c) => c.toWire()),
      ttl: this.ttl,
    };
  }

  static fromWire(wire: CJson): Authority {
    const d = toPlain<Record<string, Json>>(wire) ?? {};
    const scopes = (d["scopes"] as string[] | undefined) ?? [];
    const constraints = (d["constraints"] as Record<string, Json>[] | undefined) ?? [];
    const ttl = d["ttl"];
    return new Authority({
      scopes,
      ceilings: constraints.map((c) => ceilingFromWire(c)),
      ttl: typeof ttl === "number" ? ttl : null,
    });
  }

  /** A stable, human-readable one-liner. */
  describe(): string {
    const scopes = sortedStrings(this.scopes).join(", ");
    const cs = this.ceilings.map((c) => describeCeiling(c)).sort(compareCodePoints).join(", ");
    return `scopes=[${scopes}] ceilings=[${cs}] ttl=${this.ttl}`;
  }

  toString(): string {
    return `Authority(${this.describe()})`;
  }
}
