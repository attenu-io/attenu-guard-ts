/**
 * Core enforcement: issue, delegate, check, enforce, revoke — and the structural
 * ceilings a single-agent policy model cannot express.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Authority, AuthorityError } from "../src/authority.js";
import { CallLimit, EgressRank, RowLimit, SpendCap } from "../src/ceilings.js";
import { ManualClock } from "../src/chain.js";
import { AuthorityDenied, Guard } from "../src/guard.js";
import { Disposition, Reason, ReasonCode } from "../src/reasons.js";
import { StrikePolicy } from "../src/strikes.js";
import { toPlain } from "../src/canonical.js";

function root(overrides: Parameters<typeof Guard.issue>[2] = {}): Guard {
  return Guard.issue(
    "orchestrator",
    new Authority({
      scopes: ["crm.*", "mail.send"],
      ceilings: [new RowLimit(100_000), new EgressRank("any")],
      ttl: 3600,
    }),
    { chainId: "t", task: "root task", ...overrides },
  );
}

test("issue records the root and its authority", () => {
  const g = root();
  assert.equal(g.agentId, "orchestrator");
  assert.equal(g.chainId, "t");
  assert.equal(g.nodeId, "t:n0");
  const entries = g.auditLog().entries;
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!["event"], "root");
  assert.deepEqual(toPlain(entries[0]!["authority"]), g.authority.toWire());
});

test("delegate narrows and never widens", () => {
  const g = root();
  const child = g.delegate(
    "reader",
    new Authority({ scopes: ["crm.read", "fs.write"], ceilings: [new RowLimit(1e9)], ttl: 99_999 }),
    "read",
  );
  assert.deepEqual([...child.authority.scopes], ["crm.read"]);
  assert.equal((child.authority.ceiling("max_rows") as RowLimit).maxRows, 100_000);
  assert.equal(child.authority.ttl, 3600);
  assert.ok(child.isNarrowerThan(g));
  assert.ok(child.isDescendantOf(g));
  assert.ok(!g.isDescendantOf(child));

  const spawn = g.auditLog().entries.find((e) => e["event"] === "spawn")!;
  assert.equal(spawn["parent"], g.nodeId);
  assert.equal(spawn["node"], child.nodeId);
  assert.equal(spawn["agent"], "reader");
});

test("check allows within authority and denies outside it", () => {
  const g = root();
  const reader = g.delegate(
    "reader",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(500)], ttl: 60 }),
    "read",
  );
  assert.ok(reader.check("crm.read", { context: { rows: 10 } }).allowed);

  const overRows = reader.check("crm.read", { context: { rows: 501 } });
  assert.equal(overRows.allowed, false);
  assert.equal(overRows.reasons[0]!.code, ReasonCode.CEILING_EXCEEDED);
  assert.equal(overRows.determiningNode, reader.nodeId);

  const notHeld = reader.check("crm.export");
  assert.equal(notHeld.allowed, false);
  assert.equal(notHeld.reasons[0]!.code, ReasonCode.SCOPE_NOT_GRANTED);
  assert.match(notHeld.explain(), /^denied: scope_not_granted/);
});

test("every violated reason is collected, not just the first", () => {
  const g = Guard.issue(
    "a",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(10), new SpendCap(1)], ttl: 60 }),
    { chainId: "t" },
  );
  const d = g.check("crm.write", { context: { rows: 100, spend: 50 } });
  assert.deepEqual(d.reasons.map((r) => r.code).sort(), [
    "ceiling_exceeded",
    "ceiling_exceeded",
    "scope_not_granted",
  ]);
});

test("enforce throws AuthorityDenied carrying the decision", () => {
  const g = root();
  const reader = g.delegate("reader", new Authority({ scopes: ["crm.read"], ttl: 60 }), "read");
  reader.enforce("crm.read");
  assert.throws(
    () => reader.enforce("crm.export"),
    (err: unknown) => {
      assert.ok(err instanceof AuthorityDenied);
      assert.equal(err.decision.reasons[0]!.code, ReasonCode.SCOPE_NOT_GRANTED);
      return true;
    },
  );
});

test("wouldAllow evaluates without writing to the ledger", () => {
  const g = root();
  const before = g.auditLog().length;
  assert.ok(g.wouldAllow("crm.read").allowed);
  assert.ok(!g.wouldAllow("fs.write").allowed);
  assert.equal(g.auditLog().length, before);
});

test("revoke cascades to the whole subtree", () => {
  const g = root();
  const a = g.delegate("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), "a");
  const b = a.delegate("b", new Authority({ scopes: ["crm.read"], ttl: 60 }), "b");
  const c = b.delegate("c", new Authority({ scopes: ["crm.read"], ttl: 60 }), "c");

  const revoked = g.revoke(a.nodeId);
  assert.deepEqual(revoked.sort(), [a.nodeId, b.nodeId, c.nodeId].sort());
  for (const node of [a, b, c]) {
    assert.ok(node.isRevoked);
    const d = node.check("crm.read");
    assert.equal(d.allowed, false);
    assert.equal(d.reasons[0]!.code, ReasonCode.REVOKED);
  }
  assert.ok(g.check("crm.read").allowed, "the root is untouched");
  assert.throws(() => a.delegate("d", new Authority({ scopes: ["crm.read"] }), "d"), AuthorityError);
});

test("revokeAgent bans the principal, so a re-handoff cannot mint fresh authority", () => {
  const g = root();
  const rogue = g.delegate("rogue", new Authority({ scopes: ["crm.read"], ttl: 60 }), "work");
  g.revokeAgent("rogue");
  assert.ok(rogue.isRevoked);
  assert.equal(g.wouldDelegate("rogue").allowed, false);
  assert.throws(
    () => g.delegate("rogue", new Authority({ scopes: ["crm.read"], ttl: 60 }), "again"),
    (err: unknown) => err instanceof AuthorityError && err.reason === "agent_banned",
  );
  const denied = g.auditLog().entries.find((e) => e["event"] === "spawn_denied")!;
  assert.equal(denied["reason"], "agent_banned");
});

test("an elapsed ttl stops authorizing", () => {
  const clock = new ManualClock(0);
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 10 }), { chainId: "t", clock });
  assert.ok(g.check("crm.read").allowed);
  clock.advance(11);
  assert.ok(g.isExpired);
  const d = g.check("crm.read");
  assert.equal(d.allowed, false);
  assert.equal(d.reasons[0]!.code, ReasonCode.EXPIRED);
  assert.throws(
    () => g.delegate("b", new Authority({ scopes: ["crm.read"] }), "b"),
    (err: unknown) => err instanceof AuthorityError && err.reason === "ttl_expired",
  );
});

test("the chain depth ceiling holds", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["test.x"], ttl: 60 }), { chainId: "t", maxDepth: 2 });
  const one = g.delegate("b", new Authority({ scopes: ["test.x"], ttl: 60 }), "b");
  const two = one.delegate("c", new Authority({ scopes: ["test.x"], ttl: 60 }), "c");
  assert.equal(two.wouldDelegate("d").allowed, false);
  assert.throws(
    () => two.delegate("d", new Authority({ scopes: ["test.x"], ttl: 60 }), "d"),
    (err: unknown) => err instanceof AuthorityError && err.reason === "max_depth",
  );
});

test("the chain fanout ceiling holds", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["test.x"], ttl: 60 }), { chainId: "t", maxFanout: 2 });
  g.delegate("b", new Authority({ scopes: ["test.x"], ttl: 60 }), "b");
  g.delegate("c", new Authority({ scopes: ["test.x"], ttl: 60 }), "c");
  assert.throws(
    () => g.delegate("d", new Authority({ scopes: ["test.x"], ttl: 60 }), "d"),
    (err: unknown) => err instanceof AuthorityError && err.reason === "max_fanout",
  );
});

test("wouldDelegate is a pure dry-run: it consumes no fanout", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["test.x"], ttl: 60 }), { chainId: "t", maxFanout: 1 });
  const before = g.auditLog().length;
  assert.ok(g.wouldDelegate("b").allowed);
  assert.ok(g.wouldDelegate("b").allowed);
  assert.equal(g.auditLog().length, before);
  g.delegate("b", new Authority({ scopes: ["test.x"], ttl: 60 }), "b"); // the one slot
  assert.equal(g.wouldDelegate("c").allowed, false);
});

test("call limits meter themselves per node and pattern", () => {
  const g = Guard.issue(
    "a",
    new Authority({
      scopes: ["web.search", "web.fetch"],
      ceilings: [new CallLimit(2, "web.fetch")],
      ttl: 60,
    }),
    { chainId: "t" },
  );
  assert.ok(g.check("web.fetch").allowed);
  assert.ok(g.check("web.fetch").allowed);
  const third = g.check("web.fetch");
  assert.equal(third.allowed, false);
  assert.equal(third.reasons[0]!.constraint, "max_calls[web.fetch]");
  // A scope the ceiling does not apply to is unaffected.
  assert.ok(g.check("web.search").allowed);
  assert.ok(g.check("web.search").allowed);
  assert.ok(g.check("web.search").allowed);
});

test("a denial does not consume the call meter", () => {
  const g = Guard.issue(
    "a",
    new Authority({ scopes: ["web.fetch"], ceilings: [new CallLimit(1), new RowLimit(10)], ttl: 60 }),
    { chainId: "t" },
  );
  assert.equal(g.check("web.fetch", { context: { rows: 999 } }).allowed, false); // row ceiling
  assert.ok(g.check("web.fetch", { context: { rows: 1 } }).allowed, "the meter was not spent");
});

test("strict metering refuses a call that omits a held metered dimension", () => {
  const g = Guard.issue(
    "a",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(10), new EgressRank("any")], ttl: 60 }),
    { chainId: "t", strictMetering: true },
  );
  // A partial context is still refused: egress is declared, rows is not.
  const partial = g.check("crm.read", { context: { egress: "none" }, metered: true });
  assert.equal(partial.allowed, false);
  assert.equal(partial.reasons[0]!.code, ReasonCode.UNMETERED);
  assert.ok(g.check("crm.read", { context: { rows: 1, egress: "none" }, metered: true }).allowed);
  // Unmetered calls are unaffected.
  assert.ok(g.check("crm.read").allowed);
});

test("a strike policy revokes a node that keeps probing the same wall", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), {
    chainId: "t",
    strikes: new StrikePolicy({ n: 3 }),
  });
  g.check("crm.export");
  g.check("crm.export");
  assert.ok(!g.isRevoked);
  g.check("crm.export");
  assert.ok(g.isRevoked, "three strikes revokes the node");
  const kill = g.auditLog().entries.find((e) => e["event"] === "kill")!;
  assert.equal(kill["reason"], "strike_policy");
  assert.equal(toPlain(kill["strikes"]), 3);
  assert.equal(kill["mode"], "same_scope");
});

test("a deny records its disposition; an allow never does", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), { chainId: "t" });
  g.check("crm.read");
  g.check("crm.export"); // unexplained: the library states its own truth
  g.check("fs.write", { disposition: Disposition.HELD_PENDING_GRANT });
  const [allow, plain, stated] = g.auditLog().entries.slice(1);
  assert.equal(allow!["event"], "allow");
  assert.equal(allow!["disposition"], undefined);
  assert.equal(plain!["disposition"], Disposition.OUT_OF_AUTHORITY);
  assert.equal(stated!["disposition"], Disposition.HELD_PENDING_GRANT);
  assert.throws(() => g.check("x", { disposition: "invented" }), /unknown disposition/);
});

test("recordDenial puts an adapter-level refusal on the same trail", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), { chainId: "t" });
  const d = g.recordDenial(ReasonCode.NO_AUTHORITY, "no permissions declared for this tool", {
    tool: "mystery_tool",
    disposition: Disposition.UNRESOLVED,
  });
  assert.equal(d.allowed, false);
  const entry = g.auditLog().entries.at(-1)!;
  assert.equal(entry["event"], "deny");
  assert.equal(entry["reason"], ReasonCode.NO_AUTHORITY);
  assert.equal(entry["scope"], "mystery_tool"); // defaults to the tool label
  assert.equal(entry["disposition"], Disposition.UNRESOLVED);
  // A Reason object is accepted too.
  g.recordDenial(new Reason(ReasonCode.INTEGRITY, { message: "bad" }), "", { scope: "s" });
  assert.equal(g.auditLog().entries.at(-1)!["reason"], ReasonCode.INTEGRITY);
});

test("complete is an idempotent lifecycle marker that never changes authority", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), { chainId: "t" });
  assert.equal(g.isComplete, false);
  // v1 chain (the default): complete() returns a plain boolean, byte-and-type identical to
  // every release before 0.9.0 — CompletionResult only appears on a schemaVersion: 2 chain.
  assert.equal(g.complete(), true);
  assert.equal(g.complete(), false);
  assert.equal(g.isComplete, true);
  assert.ok(g.check("crm.read").allowed, "completion does not revoke");
  assert.equal(g.auditLog().entries.filter((e) => e["event"] === "done").length, 1);
});

test("tampering with node authority in memory is caught by the seal", () => {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), { chainId: "t" });
  const node = (g as any).node as { authority: Authority };
  node.authority = new Authority({ scopes: ["crm.*", "fs.write"], ttl: 99_999 });
  const d = g.check("fs.write");
  assert.equal(d.allowed, false);
  assert.equal(d.reasons[0]!.code, ReasonCode.INTEGRITY);
});

test("the graph reports the live delegation tree", () => {
  const g = root();
  const child = g.delegate("reader", new Authority({ scopes: ["crm.read"], ttl: 60 }), "read");
  const graph = g.graph() as { chain_id: string; nodes: any[] };
  assert.equal(graph.chain_id, "t");
  assert.equal(graph.nodes.length, 2);
  assert.equal(graph.nodes[1].parent, g.nodeId);
  assert.equal(graph.nodes[1].id, child.nodeId);
  assert.equal(graph.nodes[1].depth, 1);
});
