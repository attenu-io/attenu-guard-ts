/**
 * The -02 profile of `Authority` (draft-asor-wimse-agent-delegation-chain-02, Sections 4.1 to
 * 4.3): the three-form scope grammar, the generic constraint vocabulary, one constraint per
 * (key, type), rank with its ordering on the wire, the cumulative types, and the guarantee the
 * whole library rests on, restated for the new profile: the meet never widens.
 *
 * The default profile is "01" and is asserted unchanged here, so that no existing caller, adapter
 * or published vector changes behaviour. Case for case, the Python reference implementation's
 * tests/test_draft02_authority.py.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Authority, AuthorityError } from "../src/authority.js";
import { Allow, CallLimit, Deny, EgressRank, Prefix, RowLimit, SpendCap, UnknownCeiling, type Ceiling } from "../src/ceilings.js";
import type { Json } from "../src/canonical.js";
import * as d from "../src/draft02.js";
import { Guard } from "../src/guard.js";

const ORDER = ["none", "internal", "any"];

function A02(scopes: Iterable<string>, ceilings: Ceiling[] = [], ttl: number | null = 100): Authority {
  return new Authority({ scopes, ceilings, ttl, profile: "02" });
}

// ---- scope grammar ----------------------------------------------------------

test("-02 scopes: classification by bytes, in the draft's order", () => {
  assert.equal(d.classifyScope("crm.read"), "literal");
  assert.equal(d.classifyScope("crm.*"), "wildcard");
  assert.equal(d.classifyScope("crm.x.*"), "wildcard");
  for (const opaque of ["User.Read", "openid", "repo:status", "https://graph.example/.default", "a"]) {
    assert.equal(d.classifyScope(opaque), "opaque", opaque);
  }
  for (const invalid of ["*", "crm.re*", "crm.*.read", "User.*", "", "a b", "crm.readé", 5, null]) {
    assert.equal(d.classifyScope(invalid), null, String(invalid));
  }
});

test("-02 scopes: a trailing newline matches none of the three forms", () => {
  // JavaScript's `$` is end of input; Python's `re.match(...$)` also matches before a final "\n".
  for (const s of ["crm.read\n", "crm.*\n", "User.Read\n"]) assert.equal(d.classifyScope(s), null, JSON.stringify(s));
});

test("-02 scopes: the covering relation", () => {
  assert.ok(d.scopeCovers("crm.*", "crm.read"));
  assert.ok(d.scopeCovers("crm.*", "crm.x.y.z"));
  assert.ok(d.scopeCovers("crm.*", "crm.x.*")); // a narrower wildcard under its prefix
  assert.equal(d.scopeCovers("crm.*", "crm"), false);
  assert.equal(d.scopeCovers("crm.*", "crmx.read"), false);
  assert.ok(d.scopeCovers("crm.read", "crm.read"));
  assert.equal(d.scopeCovers("crm.read", "crm.*"), false);
  // Kieran Sweeney's three cases, from the list thread of 2026-10-06/07.
  assert.equal(d.scopeCovers("drive.*", "drive.Read"), false, "a wildcard never covers an opaque scope");
  assert.equal(d.scopeCovers("drive.Read", "drive.*"), false, "an opaque scope never covers a wildcard");
  assert.ok(d.scopeCovers("repo:status", "repo:status"), "opaque covers byte-identical only");
  assert.equal(d.scopeCovers("User.Read", "user.read"), false, "no case folding");
});

test("-02 scopes: a provider string shaped like a literal is a literal", () => {
  assert.equal(d.classifyScope("payment.release"), "literal");
  assert.ok(d.scopeCovers("payment.*", "payment.release"));
});

test("-02 scopes: the default profile is unchanged", () => {
  assert.throws(() => new Authority({ scopes: ["User.Read"] }), TypeError);
  assert.ok(new Authority({ scopes: ["drive.*"] }).coversScope("drive.read"));
  const a02 = A02(["User.Read", "repo:status"]);
  assert.ok(a02.coversScope("User.Read"));
  assert.equal(a02.coversScope("user.read"), false);
  assert.throws(() => A02(["User.*"]), TypeError);
});

// ---- one constraint per (key, type) ----------------------------------------

test("-02: a min and a max on one key form a range", () => {
  const a = A02(["hr.read"], [new d.Min("tenure_years", 2), new d.Max("tenure_years", 10)]);
  assert.equal(a.ceilingsFor("tenure_years").length, 2);
  assert.ok(a.permits("hr.read", { tenure_years: 5 }).allowed);
  assert.equal(a.permits("hr.read", { tenure_years: 1 }).allowed, false);
  assert.equal(a.permits("hr.read", { tenure_years: 11 }).allowed, false);
});

test("-02: two of one type on one key are malformed", () => {
  assert.throws(() => A02(["a.b"], [new d.Max("rows", 1), new d.Max("rows", 2)]), /one per \(key, type\)/);
  // legacy and generic are both `max`
  assert.throws(() => A02(["a.b"], [new RowLimit(1), new d.Max("max_rows", 2)]), TypeError);
});

test("-02: an allow-list and a deny-list on one key are both evaluated", () => {
  const a = A02(["a.b"], [new Allow("region", ["us", "eu"]), new Deny("region", ["eu"])]);
  assert.ok(a.permits("a.b", { region: "us" }).allowed);
  assert.equal(a.permits("a.b", { region: "eu" }).allowed, false);
  assert.equal(a.permits("a.b", { region: "jp" }).allowed, false);
});

test("-02: the default profile still refuses two per key", () => {
  assert.throws(
    () => new Authority({ scopes: ["a.b"], ceilings: [new Allow("region", ["us"]), new Deny("region", ["rm"])] }),
    /one per key/,
  );
});

test("-02: narrowing pairs by key and type", () => {
  const parent = A02(["a.b"], [new d.Min("t", 2), new d.Max("t", 10)]);
  assert.ok(A02(["a.b"], [new d.Min("t", 3), new d.Max("t", 9)]).isNarrowerThan(parent));
  assert.equal(A02(["a.b"], [new d.Min("t", 1), new d.Max("t", 9)]).isNarrowerThan(parent), false);
  assert.equal(A02(["a.b"], [new d.Max("t", 9)]).isNarrowerThan(parent), false, "the floor is dropped");
  const child = parent.meet(A02(["a.b"], [new d.Min("t", 5), new d.Max("t", 20)]));
  assert.deepEqual(child.toWire().constraints, [{ key: "t", max: 10 }, { key: "t", min: 5 }]);
});

test("-02: a duplicate unknown constraint is named by its member tuple, as Python prints it", () => {
  const u = () => new UnknownCeiling("quota", { key: "quota", units: 5 });
  assert.throws(() => A02(["a.b"], [u(), u()]), {
    message: "two constraints share the key 'quota' and the type ('unknown', 'units'); an authority holds one per (key, type)",
  });
  assert.equal(d.draftTypeOf(u()), "('unknown', 'units')");
});

// ---- no inference across types ---------------------------------------------

test("-02: a lifetime bound does not satisfy a per-action bound", () => {
  const parent = A02(["a.b"], [new d.Max("spend", 100)]);
  assert.equal(A02(["a.b"], [new d.MaxLifetime("spend", 50)]).isNarrowerThan(parent), false);
  assert.equal(A02(["a.b"], [new d.Max("spend", 50)]).isNarrowerThan(A02(["a.b"], [new d.MaxLifetime("spend", 100)])), false);
  assert.ok(
    A02(["a.b"], [new d.Max("spend", 50), new d.MaxLifetime("spend", 40)]).isNarrowerThan(
      A02(["a.b"], [new d.Max("spend", 100), new d.MaxLifetime("spend", 400)]),
    ),
  );
});

// ---- cumulative constraints deny without a total ---------------------------

test("-02: a lifetime bound with no running total denies", () => {
  const a = A02(["a.b"], [new d.MaxLifetime("spend", 100)]);
  const decision = a.permits("a.b", { spend: 10 });
  assert.equal(decision.allowed, false);
  assert.match(decision.reasons[0]!.message, /no running total/);
  assert.equal(
    decision.reasons[0]!.message,
    "no running total for 'spend_total' is held here; a cumulative constraint is checked only where its total is held; refused",
  );
  assert.ok(a.permits("a.b", { spend_total: 90 }).allowed);
  assert.equal(a.permits("a.b", { spend_total: 101 }).allowed, false);
});

test("-02: a subtree bound reads its own total", () => {
  const a = A02(["a.b"], [new d.MaxSubtree("spend", 100)]);
  assert.equal(a.permits("a.b", { spend_total: 1 }).allowed, false);
  assert.ok(a.permits("a.b", { spend_subtree_total: 100 }).allowed);
});

test("-02: a per-action max still asserts nothing when absent", () => {
  assert.ok(A02(["a.b"], [new d.Max("spend", 100)]).permits("a.b", {}).allowed);
});

test("-02: the guard's call meter feeds a lifetime call bound", () => {
  const root = Guard.issue("root", A02(["crm.read"], [new CallLimit(2)], 60), { maxDepth: 2 });
  assert.ok(root.check("crm.read").allowed);
  assert.ok(root.check("crm.read").allowed);
  assert.equal(root.check("crm.read").allowed, false);
  // The same bound after a -02 wire round trip is the generic type, reading the same field.
  const generic = Authority.fromWire(root.authority.toWire(), "02");
  assert.ok(generic.ceilings[0] instanceof d.MaxLifetime);
  assert.equal(generic.ceilings[0]!.ctxField, "calls");
  assert.ok(generic.permits("crm.read", { calls: 2 }).allowed);
  assert.equal(generic.permits("crm.read", { calls: 3 }).allowed, false);
  assert.equal(generic.permits("crm.read", {}).allowed, false, "no total held: deny");
});

test("-02: a guard holding the generic lifetime call bound meters it too", () => {
  const generic = Authority.fromWire(A02(["crm.read"], [new CallLimit(1, "crm.*")], 60).toWire(), "02");
  const root = Guard.issue("root", generic, { maxDepth: 2 });
  assert.ok(root.check("crm.read").allowed);
  assert.equal(root.check("crm.read").allowed, false);
});

// ---- rank with its ordering --------------------------------------------------

test("-02 rank: the ordering travels on the wire", () => {
  assert.deepEqual(new EgressRank("internal").toWire02(), { key: "egress", rank: "internal", order: ORDER });
  const a = Authority.fromWire({ scopes: ["a.b"], constraints: [new EgressRank("internal").toWire02()], ttl: 10 }, "02");
  assert.ok(a.ceilings[0] instanceof d.Rank);
  assert.ok(a.permits("a.b", { egress: "none" }).allowed);
  assert.equal(a.permits("a.b", { egress: "any" }).allowed, false);
  assert.equal(a.permits("a.b", { egress: "everywhere" }).allowed, false, "a value outside order is refused");
});

test("-02 rank: a child must carry the parent's ordering", () => {
  const parent = A02(["a.b"], [new d.Rank("egress", "internal", ORDER)]);
  assert.ok(A02(["a.b"], [new d.Rank("egress", "none", ORDER)]).isNarrowerThan(parent));
  assert.equal(A02(["a.b"], [new d.Rank("egress", "any", ORDER)]).isNarrowerThan(parent), false);
  assert.equal(A02(["a.b"], [new d.Rank("egress", "none", ["none", "any"])]).isNarrowerThan(parent), false);
  assert.throws(
    () => parent.meet(A02(["a.b"], [new d.Rank("egress", "none", ["none", "any"])])),
    (e: unknown) => e instanceof AuthorityError && e.reason === "not_narrower",
  );
});

test("-02 rank: malformed ranks", () => {
  assert.throws(() => new d.Rank("egress", "none", ["none"]), TypeError); // fewer than two members
  assert.throws(() => new d.Rank("egress", "none", ["none", "none"]), TypeError); // not distinct
  assert.throws(() => new d.Rank("egress", "high", ORDER), TypeError); // rank not a member
  assert.throws(() => d.ceilingFromWire02({ key: "egress", rank: "none" }), TypeError); // the -01 shape lacks order
});

// ---- closed constraint objects ----------------------------------------------

test("-02 constraints: closed members", () => {
  const bad: Record<string, Json>[] = [
    { key: "x", max: 1, note: "n" },
    { key: "x", max: 1, min: 0 },
    { key: "x", one_of: ["a"], type: "allow" },
    { key: "x", one_of: ["a"], field: "y" },
    { key: "x", max_lifetime: 5, applies_to: "a.b" },
    { key: "x" },
    { key: "x", foo: 1, bar: 2 },
  ];
  for (const c of bad) assert.throws(() => d.ceilingFromWire02(c), TypeError, JSON.stringify(c));
});

test("-02 constraints: one unknown type fails closed rather than malformed", () => {
  const c = d.ceilingFromWire02({ key: "x", quota: 5 });
  assert.ok(c instanceof UnknownCeiling);
  assert.equal(c.permits({ x: 1 }).allowed, false);
});

test("-02 constraints: the library ceilings emit closed objects", () => {
  const a = A02(["a.b"], [
    new Allow("region", ["us"]), new Deny("tool", ["rm"]), new Prefix("path", "/tmp/"),
    new RowLimit(5), new SpendCap(2.5), new CallLimit(3, "a.*"), new EgressRank("none"),
  ]);
  for (const c of a.toWire().constraints) {
    assert.equal("type" in c, false);
    assert.equal("field" in c, false);
    assert.equal("applies_to" in c, false);
    d.ceilingFromWire02(c); // round-trips through the -02 parser
  }
  assert.ok(a.toWire().constraints.some((c) => JSON.stringify(c) === JSON.stringify({ key: "max_calls[a.*]", max_lifetime: 3 })));
  assert.throws(() => A02(["a.b"], [new Allow("region", ["us"], "geo")]).toWire(), TypeError);
});

test("-02 constraints: the default profile wire form is unchanged", () => {
  assert.deepEqual(new Authority({ scopes: ["a.b"], ceilings: [new CallLimit(3)] }).toWire().constraints, [{ key: "max_calls", max: 3 }]);
  assert.deepEqual(new Authority({ scopes: ["a.b"], ceilings: [new EgressRank("none")] }).toWire().constraints, [{ key: "egress", rank: "none" }]);
});

test("-02 constraints: a null constraint list is refused under -02 and empty under -01, as before", () => {
  assert.throws(() => Authority.fromWire({ scopes: ["a.b"], constraints: null, ttl: 1 }, "02"), { message: "constraints is null, not an array" });
  assert.equal(Authority.fromWire({ scopes: ["a.b"], constraints: null, ttl: 1 }).ceilings.length, 0);
  assert.throws(() => Authority.fromWire({ scopes: ["a.b"], constraints: "x", ttl: 1 }), { message: "constraints is a string, not an array" });
});

// ---- profiles do not mix -----------------------------------------------------

test("-02: meet refuses and narrower is false across profiles", () => {
  const a01 = new Authority({ scopes: ["a.b"], ceilings: [new RowLimit(1)], ttl: 10 });
  const a02 = A02(["a.b"], [new RowLimit(1)], 10);
  assert.equal(a01.isNarrowerThan(a02), false);
  assert.equal(a02.isNarrowerThan(a01), false);
  assert.throws(() => a01.meet(a02), TypeError);
  assert.throws(() => new Authority({ scopes: ["a.b"], profile: "03" as never }), TypeError);
});

test("-02: profile survives withTtl, meet and the wire round trip", () => {
  const a = A02(["a.b"], [new RowLimit(5)], 10);
  assert.equal(a.withTtl(5).profile, "02");
  assert.equal(a.meet(a).profile, "02");
  assert.equal(Authority.fromWire(a.toWire(), "02").profile, "02");
  assert.equal(new Authority().profile, "01");
  assert.equal(Authority.fromWire(new Authority().toWire()).profile, "01");
});

// =========================================================================
// Property trials: under the -02 profile the meet never widens
// =========================================================================

const LITERALS = ["crm.read", "crm.write", "crm.export", "mail.send", "files.read", "pay.transfer"];
const WILDS = ["crm.*", "mail.*", "files.*"];
const OPAQUES = ["User.Read", "repo:status", "openid", "user.read"];

/** A small seeded PRNG (mulberry32), so a failing trial reproduces. */
class Rng {
  constructor(private s: number) {}
  next(): number {
    this.s = (this.s + 0x6d2b79f5) | 0;
    let t = Math.imul(this.s ^ (this.s >>> 15), 1 | this.s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  int(lo: number, hi: number): number {
    return lo + Math.floor(this.next() * (hi - lo + 1));
  }
  choice<T>(xs: readonly T[]): T {
    return xs[this.int(0, xs.length - 1)]!;
  }
  sample<T>(xs: readonly T[], k: number): T[] {
    const pool = [...xs];
    const out: T[] = [];
    for (let i = 0; i < k; i++) out.push(pool.splice(this.int(0, pool.length - 1), 1)[0]!);
    return out;
  }
}

function rndAuthority(rng: Rng): Authority {
  const all = [...LITERALS, ...WILDS, ...OPAQUES];
  const scopes = new Set(rng.sample(all, rng.int(0, 6)));
  const regions = ["us", "eu", "jp", "br"];
  const pool: (() => Ceiling)[] = [
    () => new RowLimit(rng.int(0, 1000)),
    () => new d.Max("max_rows", rng.int(0, 1000)),
    () => new d.Min("max_rows", rng.int(0, 1000)),
    () => new d.MaxLifetime("max_spend", rng.int(0, 1000)),
    () => new d.MaxSubtree("max_spend", rng.int(0, 1000)),
    () => new SpendCap(rng.int(0, 1000)),
    () => new d.Rank("egress", rng.choice(ORDER), ORDER),
    () => new d.Rank("tier", rng.choice(["t1", "t2", "t3"]), ["t1", "t2", "t3"]),
    () => new Allow("region", rng.sample(regions, rng.int(0, 4))),
    () => new Deny("region", rng.sample(regions, rng.int(0, 4))),
    // Prefixes drawn from one chain so every pair is comparable: the meet of two incomparable
    // prefixes is the library's "admits nothing" NUL encoding, which `Prefix.subsumes` does not
    // recognise as narrower (a -01 property, unchanged here).
    () => new Prefix("path", rng.choice(["/", "/tmp", "/tmp/a"])),
  ];
  const ceilings: Ceiling[] = [];
  const seen = new Set<string>();
  for (const make of rng.sample(pool, rng.int(0, pool.length))) {
    const c = make();
    const k = JSON.stringify([c.key, d.draftTypeOf(c)]);
    if (seen.has(k)) continue;
    seen.add(k);
    ceilings.push(c);
  }
  return new Authority({ scopes, ceilings, ttl: rng.int(1, 7200), profile: "02" });
}

test("-02 property: the meet is narrower than both inputs (2000 trials)", () => {
  const rng = new Rng(20261007);
  let met = 0;
  for (let i = 0; i < 2000; i++) {
    const p = rndAuthority(rng);
    const r = rndAuthority(rng);
    let c: Authority;
    try {
      c = p.meet(r);
    } catch (e) {
      // Only a rank whose ordering differs, or two types under a key the library cannot narrow,
      // refuse a meet; both are recorded as not_narrower.
      assert.ok(e instanceof AuthorityError && e.reason === "not_narrower", `${p} ${r} ${String(e)}`);
      continue;
    }
    met++;
    assert.ok(c.isNarrowerThan(p), `${p} ${r} ${c}`);
    assert.ok(c.isNarrowerThan(r), `${p} ${r} ${c}`);
    assert.ok(c.isNarrowerThan(c));
  }
  assert.ok(met > 500, `only ${met} trials produced a meet`);
});

test("-02 property: a meet survives a wire round trip as narrower (500 trials)", () => {
  const rng = new Rng(7);
  for (let i = 0; i < 500; i++) {
    const p = rndAuthority(rng);
    const r = rndAuthority(rng);
    let c: Authority;
    try {
      c = p.meet(r);
    } catch (e) {
      if (e instanceof AuthorityError) continue;
      throw e;
    }
    const p2 = Authority.fromWire(p.toWire(), "02");
    const c2 = Authority.fromWire(c.toWire(), "02");
    assert.ok(c2.isNarrowerThan(p2), `${p} ${c}`);
    assert.deepEqual(c2.toWire(), c.toWire());
  }
});

test("-02 property: a random widening is caught (500 trials)", () => {
  const rng = new Rng(99);
  let caught = 0;
  for (let i = 0; i < 500; i++) {
    const p = rndAuthority(rng);
    const wider = new Authority({
      scopes: [...p.scopes, rng.choice([...LITERALS, ...OPAQUES])],
      ceilings: p.ceilings,
      ttl: p.ttl,
      profile: "02",
    });
    const added = [...wider.scopes].filter((s) => !p.scopes.has(s));
    if (added.length > 0 && !added.some((s) => p.coversScope(s))) {
      assert.equal(wider.isNarrowerThan(p), false);
      caught++;
    }
  }
  assert.ok(caught > 100, `only ${caught} widenings were tried`);
});
