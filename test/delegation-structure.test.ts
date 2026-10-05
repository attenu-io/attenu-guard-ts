/**
 * The delegation structure is read in ledger order, and nothing skips the checks.
 *
 * Through 0.12.0 a spawn whose `parent` was absent, null, or named no node in the bundle was never
 * checked for monotonicity, so a child widened past its parent verified OK; the process being
 * watched writes that field. Every spawn's parent must now be a string naming a node the root or
 * an earlier spawn defined, not revoked by an earlier kill and not the spawn's own node; a node is
 * defined once; an allow is judged against a node defined earlier and not revoked; and a node id
 * that is not a string is a finding, never an exception. Every expected string is the Python
 * implementation's for the same bundle (attenu-guard 27b1e35, tests/test_bundle_vectors.py).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { GENESIS, hashEntry, type LedgerEntry } from "../src/audit.js";
import { Authority } from "../src/authority.js";
import type { CJson } from "../src/canonical.js";
import { exportBundle, verifyBundle, type Bundle, type VerifyReport } from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { HS256TestSigner } from "../src/wire.js";
import { REPO_ROOT, fixtureJson } from "./helpers.js";

const BIN = resolve(REPO_ROOT, "bin", "attenu-guard.js");
const SIGNER = new HS256TestSigner(Buffer.from("k"), "k");
const WIDENED = "admin.delete";

type Mutable = Record<string, CJson> & { entries: LedgerEntry[] };

/** A copy of the corpus's valid_bundle_v2: a root vectors:n0 and a spawn vectors:n1 at index 1. */
function validBundle(): Mutable {
  const cases = (fixtureJson("vectors/bundles/bundle_vectors_v1.json") as { cases: { name: string; bundle: Bundle }[] })
    .cases;
  return JSON.parse(JSON.stringify(cases.find((c) => c.name === "valid_bundle_v2")!.bundle)) as Mutable;
}

/** `bundle` re-hashed from genesis as a forger would, its anchor dropped, then verified. */
function verify(bundle: Mutable): VerifyReport {
  let prev = GENESIS;
  for (const e of bundle.entries) {
    e["prev_hash"] = prev;
    delete e["hash"];
    e["hash"] = hashEntry(prev, e);
    prev = e["hash"] as string;
  }
  delete bundle["anchor"];
  return verifyBundle(bundle as unknown as Bundle, null);
}

function monotonicity(report: VerifyReport): string[] {
  return report.failures.filter((f) => f.startsWith("monotonicity"));
}

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** valid_bundle_v2 with the spawn granted a scope the root does not hold, its parent set by `setParent`. */
function widened(setParent: (spawn: LedgerEntry) => void): Mutable {
  const bundle = validBundle();
  const spawn = bundle.entries[1]!;
  assert.deepEqual([spawn["event"], spawn["node"], spawn["parent"]], ["spawn", "vectors:n1", "vectors:n0"]);
  const granted = spawn["granted"] as Record<string, CJson>;
  granted["scopes"] = [...new Set([...(granted["scopes"] as string[]), WIDENED])].sort();
  setParent(spawn);
  return bundle;
}

/** root t:n0 -> t:n1 (-> t:n2), each holding crm.read, and an allow by the deepest. */
function chain(depth: number): { root: Guard; leaf: Guard } {
  const root = Guard.issue("root", new Authority({ scopes: ["crm.read"], ttl: 600 }), { chainId: "t" });
  let guard = root;
  for (let i = 0; i < depth - 1; i++) {
    guard = guard.delegate(`agent${i}`, new Authority({ scopes: ["crm.read"], ttl: 600 }), "t");
  }
  assert.ok(guard.check("crm.read").allowed);
  return { root, leaf: guard };
}

function bundleOf(root: Guard): Mutable {
  return copy(exportBundle(root.auditLog().entries, SIGNER)) as unknown as Mutable;
}

function setParent(value: CJson): (spawn: LedgerEntry) => void {
  return (spawn) => void (spawn["parent"] = value);
}

test("a widened child fails whatever its parent field says", () => {
  const stated = "names no parent defined earlier in this bundle";
  const cases: [string, (spawn: LedgerEntry) => void, string][] = [
    [
      "intact",
      () => undefined,
      "monotonicity: vectors:n1 not ⊆ parent vectors:n0 (child scopes ['admin.delete', 'crm.read'] not held by parent)",
    ],
    ["absent", (spawn) => void delete spawn["parent"], `monotonicity: vectors:n1 ${stated} (parent None)`],
    ["null", setParent(null), `monotonicity: vectors:n1 ${stated} (parent None)`],
    ["unknown", setParent("vectors:n9"), `monotonicity: vectors:n1 ${stated} (parent vectors:n9)`],
    ["empty", setParent(""), `monotonicity: vectors:n1 ${stated} (parent "")`],
    ["its own node", setParent("vectors:n1"), `monotonicity: vectors:n1 ${stated} (parent vectors:n1)`],
    ["a number", setParent(5), `monotonicity: vectors:n1 ${stated} (parent 5)`],
    ["a boolean", setParent(true), `monotonicity: vectors:n1 ${stated} (parent True)`],
    ["a list", setParent(["vectors:n0"]), `monotonicity: vectors:n1 ${stated} (parent ['vectors:n0'])`],
    ["an object", setParent({ node: "vectors:n0" }), `monotonicity: vectors:n1 ${stated} (parent {"node":"vectors:n0"})`],
  ];
  for (const [label, edit, message] of cases) {
    const report = verify(widened(edit));
    assert.equal(report.ok, false, label);
    assert.equal(report.checks.monotonicity, false, label);
    assert.deepEqual(monotonicity(report), [message], label);
    assert.equal(report.failure_entries[report.failures.indexOf(message)], 1, `${label}: the spawn, by index`);
  }
});

test("a parent defined only later is no parent", () => {
  const { root } = chain(3);
  const bundle = bundleOf(root);
  assert.deepEqual(
    bundle.entries.slice(0, 3).map((e) => [e["node"], e["parent"] ?? null]),
    [["t:n0", null], ["t:n1", "t:n0"], ["t:n2", "t:n1"]],
  );
  bundle.entries[1]!["parent"] = "t:n2";
  assert.deepEqual(monotonicity(verify(bundle)), [
    "monotonicity: t:n1 names no parent defined earlier in this bundle (parent t:n2)",
  ]);
});

test("a cycle of widened nodes fails without any missing parent", () => {
  // X's parent is Y and Y's parent is X, both granted admin.delete, so each is ⊆ the other and
  // neither is compared with the root, which holds only crm.read. No parent is missing, and this
  // verified OK with an allow on admin.delete. A parent defined by an EARLIER entry breaks it.
  const { root } = chain(3);
  const bundle = bundleOf(root);
  const [x, y, allow] = [bundle.entries[1]!, bundle.entries[2]!, bundle.entries[3]!];
  assert.deepEqual([x["node"], x["parent"], y["node"], y["parent"], allow["event"]], ["t:n1", "t:n0", "t:n2", "t:n1", "allow"]);
  const grant = { ...(x["granted"] as Record<string, CJson>), scopes: [WIDENED, "crm.read"] };
  x["parent"] = "t:n2";
  x["granted"] = grant;
  y["granted"] = copy(grant);
  allow["scope"] = WIDENED;
  const report = verify(bundle);
  assert.equal(report.ok, false);
  assert.deepEqual(report.failures, ["monotonicity: t:n1 names no parent defined earlier in this bundle (parent t:n2)"]);
  assert.deepEqual(report.failure_entries, [1]);
});

test("a node is defined once", () => {
  // The second definition of t:n1, widened and from the root, would have been the only one read;
  // a spawn reusing the root's own node is the same defect.
  const { root } = chain(2);
  const bundle = bundleOf(root);
  const n = bundle.entries.length;
  const spawn = bundle.entries[1]!;
  const again = { ...copy(spawn), seq: n, granted: { ...(spawn["granted"] as Record<string, CJson>), scopes: ["crm.read", WIDENED] } };
  const reroot = { ...copy(spawn), node: "t:n0", seq: n + 1 };
  bundle.entries.push(again, reroot);
  assert.deepEqual(monotonicity(verify(bundle)), [
    "monotonicity: t:n1 is defined a second time in this bundle (first at seq 1)",
    "monotonicity: t:n0 is defined a second time in this bundle (first at seq 0)",
  ]);
});

test("a spawn from a revoked parent fails", () => {
  const { root, leaf } = chain(2);
  root.revoke(leaf.nodeId);
  const bundle = bundleOf(root);
  const killSeq = bundle.entries.find((e) => e["event"] === "kill")!["seq"];
  bundle.entries.push({ ...copy(bundle.entries[1]!), node: "t:n2", parent: "t:n1", seq: bundle.entries.length });
  assert.deepEqual(monotonicity(verify(bundle)), [
    `monotonicity: t:n2 is spawned from t:n1 after t:n1 was revoked at seq ${String(killSeq)}`,
  ]);
});

test("an allow on a revoked node fails containment", () => {
  const { root, leaf } = chain(2);
  root.revoke(leaf.nodeId);
  const bundle = bundleOf(root);
  const allow = bundle.entries.find((e) => e["event"] === "allow")!;
  const killSeq = bundle.entries.find((e) => e["event"] === "kill")!["seq"];
  bundle.entries.push({ ...copy(allow), seq: bundle.entries.length });
  const report = verify(bundle);
  assert.deepEqual(report.failures, [
    `containment: allow of 'crm.read' on t:n1 after t:n1 was revoked at seq ${String(killSeq)}`,
  ]);
  assert.deepEqual(report.failure_entries, [bundle.entries.length - 1]);
});

test("an allow before its node is defined is on an unknown node", () => {
  const { root } = chain(2);
  const bundle = bundleOf(root);
  const entries = bundle.entries;
  assert.deepEqual(entries.slice(0, 3).map((e) => e["event"]), ["root", "spawn", "allow"]);
  [entries[1], entries[2]] = [entries[2]!, entries[1]!];
  entries.forEach((e, i) => void (e["seq"] = i));
  const report = verify(bundle);
  assert.deepEqual(report.failures, ["containment: allow on unknown node t:n1"]);
  assert.deepEqual(report.failure_entries, [1]);
});

test("a context that is not an object fails containment", () => {
  const { root } = chain(1);
  const bundle = bundleOf(root);
  bundle.entries[1]!["context"] = [1];
  assert.deepEqual(verify(bundle).failures, [
    "containment: allow of 'crm.read' on t:n0 outside its authority ['crm.read']",
  ]);
});

test("a node that is not a string is a finding and never an exception", () => {
  const expected: Record<string, string> = { root: "unreadable_authority", spawn: "unreadable_granted", allow: "containment" };
  for (const bad of [[1], { a: 1 }, 5, true] as CJson[]) {
    for (const event of ["root", "spawn", "allow", "deny", "done", "outcome"]) {
      const label = `${event} ${JSON.stringify(bad)}`;
      const bundle = validBundle();
      const at = bundle.entries.findIndex((e) => e["event"] === event);
      bundle.entries[at]!["node"] = bad;
      const report = verify(bundle);
      assert.equal(report.ok, false, label);
      assert.ok(report.failure_details.some((d) => d.reason === (expected[event] ?? "invalid_node")), label);
      assert.ok(report.failure_entries.includes(at), label);
    }
  }
  // A kill naming nodes that are not strings revokes nothing and throws nothing.
  const { root, leaf } = chain(2);
  root.revoke(leaf.nodeId);
  const bundle = bundleOf(root);
  bundle.entries.find((e) => e["event"] === "kill")!["revoked"] = [[1], { a: 1 }, 5];
  assert.equal(verify(bundle).ok, true);
});

test("the exact strings for a node that is not a string", () => {
  let bundle = validBundle();
  bundle.entries[0]!["node"] = [1];
  assert.ok(verify(bundle).failures.includes("root [1]: unreadable authority (node is not a string)"));
  bundle = validBundle();
  bundle.entries[1]!["node"] = { a: 1 };
  assert.ok(verify(bundle).failures.includes('spawn {"a":1}: unreadable granted (node is not a string)'));
  bundle = validBundle();
  const denyAt = bundle.entries.findIndex((e) => e["event"] === "deny");
  bundle.entries[denyAt]!["node"] = 5;
  assert.ok(
    verify(bundle).failures.includes(`invalid_node: seq=${denyAt} event='deny' carries node 5, which is not a string`),
  );
  // An absent root node is the same finding, where it was "root None: unreadable authority ('node')".
  bundle = validBundle();
  delete bundle.entries[0]!["node"];
  assert.ok(verify(bundle).failures.includes("root None: unreadable authority (node is not a string)"));
});

test("fuzz: a widened child never verifies OK, whatever its parent says", () => {
  // Deterministic: one seed, and every draw is a parent value a ledger writer could put there,
  // including well-formed node ids, the child's own id and nodes that do not exist.
  let state = 20261005;
  const next = (): number => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)]!;
  const pool: (CJson | "DELETE")[] = [
    null, true, false, 0, 1, -1, 1.5, "", " ", "vectors:n0", "vectors:n1", "vectors:n2", "vectors:n9",
    "VECTORS:N0", "vectors:n0 ", ["vectors:n0"], [], { node: "vectors:n0" }, {}, String.fromCharCode(0),
    "vectors:n0\n", "DELETE",
  ];
  for (let trial = 0; trial < 400; trial++) {
    const draw = next() < 0.5
      ? pick(pool)
      : Array.from({ length: Math.floor(next() * 13) }, () => pick("vectors:n0129*.".split(""))).join("");
    const report = verify(widened((spawn) => {
      if (draw === "DELETE") delete spawn["parent"];
      else spawn["parent"] = copy(draw);
    }));
    const label = `trial ${trial}: ${JSON.stringify(draw)}`;
    assert.equal(report.ok, false, label);
    assert.equal(report.checks.monotonicity, false, label);
  }
});

// ---- the CLI ------------------------------------------------------------------------------------

function cli(bundle: Mutable, ...args: string[]): { status: number; stdout: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "attenu-delegation-"));
  try {
    const file = join(dir, "bundle.json");
    verify(bundle); // re-hash in place and drop the anchor
    writeFileSync(file, JSON.stringify(bundle));
    const r = spawnSync(process.execPath, [BIN, "verify", file, ...args], { encoding: "utf8" });
    return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the CLI: a widened child with its parent removed fails, on its own line", () => {
  // 0.12.0 printed OK for this bundle.
  const bundle = validBundle();
  (bundle.entries[1]!["granted"] as Record<string, CJson>)["scopes"] = ["admin.delete", "crm.read"];
  delete bundle.entries[1]!["parent"];
  const { status, stdout, stderr } = cli(bundle, "--entries");
  assert.equal(stderr, "");
  assert.equal(status, 2);
  assert.ok(
    stdout.includes("\n  - monotonicity: vectors:n1 names no parent defined earlier in this bundle (parent None)\nFAILED\n"),
    stdout,
  );
  assert.ok(stdout.includes("\n  seq=1 event=spawn node=vectors:n1 state=process-asserted failed=monotonicity\n"), stdout);
});

test("the CLI: a node that is not a string is a finding, not a stack trace", () => {
  const bundle = validBundle();
  bundle.entries[0]!["node"] = [1];
  const { status, stdout, stderr } = cli(bundle, "--entries");
  assert.equal(stderr, "");
  assert.equal(status, 2);
  assert.ok(stdout.includes("\n  - root [1]: unreadable authority (node is not a string)\n"), stdout);
  assert.ok(stdout.includes("\n  seq=0 event=root node=[1] state=process-asserted failed=unreadable_authority\n"), stdout);
});

test("the CLI: the summary line ends ungated=N when allows passed through un-gated, and only then", () => {
  // An allow marked `policy: "unlisted"` is excused from containment by design, so actions_checked
  // does not count it, and a reader could not tell it was there.
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 600 }), { chainId: "t" });
  assert.ok(g.check("crm.read").allowed);
  g.recordPassthrough("shell.exec");
  g.recordPassthrough("admin.delete"); // outside the node's authority, and not measured
  const dir = mkdtempSync(join(tmpdir(), "attenu-ungated-"));
  try {
    const file = join(dir, "bundle.json");
    writeFileSync(file, JSON.stringify(exportBundle(g.auditLog().entries, SIGNER)));
    const key = Buffer.from("k").toString("hex");
    const summary =
      "integrity=True monotonicity=True containment=True anchor=verified nodes=1 actions_checked=1 ungated=2";
    const plain = spawnSync(process.execPath, [BIN, "verify", file, "--hs256-key", key], { encoding: "utf8" });
    assert.deepEqual([plain.status, plain.stdout], [0, `${summary}\nOK\n`]);
    const entries = spawnSync(process.execPath, [BIN, "verify", file, "--hs256-key", key, "--entries"], { encoding: "utf8" });
    assert.equal(entries.status, 0);
    assert.ok(entries.stdout.startsWith(`${summary}\nOK\nentries:\n`), entries.stdout);
    assert.equal(entries.stdout.trimEnd().split("\n").length, 3 + 4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
