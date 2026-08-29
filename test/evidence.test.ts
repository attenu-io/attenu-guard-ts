/**
 * The offline verifier. Every bundle Python exported — clean and tampered, HS256
 * and Ed25519 — must produce the report Python produces, check for check and
 * failure string for failure string.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { RowLimit } from "../src/ceilings.js";
import {
  EvidenceLeakError,
  delegationGraph,
  denials,
  exportBundle,
  parseBundle,
  redactionReport,
  verifyBundle,
  type Bundle,
} from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { Ed25519Signer, Ed25519Verifier, HS256TestSigner, type Signer } from "../src/wire.js";
import { META, fixtureText } from "./helpers.js";

interface ExpectedReport {
  ok: boolean;
  checks: Record<string, unknown>;
  failures: string[];
  nodes: number;
  actions_checked: number;
  chain_id: string;
}

const expected = JSON.parse(fixtureText("expected_reports.json")) as Record<
  string,
  { with_key: ExpectedReport; without_key: ExpectedReport }
>;

const hs256 = new HS256TestSigner(Buffer.from(META.hs256_secret_hex, "hex"), META.hs256_kid);
const ed25519 = new Ed25519Verifier(Buffer.from(META.ed25519_public_hex, "hex"), META.ed25519_kid);

function signerFor(name: string): Signer {
  return name.includes("ed25519") ? ed25519 : hs256;
}

function bundleFor(name: string): Bundle {
  return parseBundle(fixtureText(`${name}.bundle.json`));
}

const NAMES = Object.keys(expected);

test("the fixture set covers a clean bundle and every tamper mode", () => {
  for (const required of [
    "clean_hs256",
    "clean_ed25519",
    "redacted_hs256",
    "tampered_hs256",
    "dropped_hs256",
    "reordered_hs256",
    "bad_anchor_hs256",
    "widened_hs256",
    "uncontained_hs256",
  ]) {
    assert.ok(NAMES.includes(required), `fixture ${required} is present`);
  }
});

for (const name of NAMES) {
  test(`verifyBundle(${name}) matches Python, with the key`, () => {
    const report = verifyBundle(bundleFor(name), signerFor(name));
    const want = expected[name]!.with_key;
    assert.deepEqual(report.checks, want.checks);
    assert.deepEqual(report.failures, want.failures);
    assert.equal(report.ok, want.ok);
    assert.equal(report.nodes, want.nodes);
    assert.equal(report.actions_checked, want.actions_checked);
    assert.equal(report.chain_id, want.chain_id);
  });

  test(`verifyBundle(${name}) matches Python, without the key`, () => {
    const report = verifyBundle(bundleFor(name), null);
    const want = expected[name]!.without_key;
    assert.deepEqual(report.checks, want.checks);
    assert.deepEqual(report.failures, want.failures);
    assert.equal(report.ok, want.ok);
  });
}

test("each tamper mode fails its own check, independently", () => {
  assert.equal(verifyBundle(bundleFor("tampered_hs256"), hs256).checks.integrity, false);
  assert.equal(verifyBundle(bundleFor("widened_hs256"), hs256).checks.monotonicity, false);
  // A widened ledger is honestly recorded: the chain and anchor both hold.
  assert.equal(verifyBundle(bundleFor("widened_hs256"), hs256).checks.integrity, true);
  assert.equal(verifyBundle(bundleFor("uncontained_hs256"), hs256).checks.containment, false);
  assert.equal(verifyBundle(bundleFor("uncontained_hs256"), hs256).checks.integrity, true);
  assert.equal(verifyBundle(bundleFor("bad_anchor_hs256"), hs256).checks.anchor, "FAILED");
});

test("the wrong key does not verify a clean anchor", () => {
  const wrong = new HS256TestSigner(Buffer.from("00", "hex"), META.hs256_kid);
  assert.equal(verifyBundle(bundleFor("clean_hs256"), wrong).checks.anchor, "FAILED");
});

test("an Ed25519 anchor verifies from the public half alone", () => {
  const report = verifyBundle(bundleFor("clean_ed25519"), ed25519);
  assert.equal(report.checks.anchor, "verified");
  assert.equal(report.ok, true);
  // And a different key does not.
  const other = new Ed25519Verifier(Ed25519Signer.generate().publicBytesRaw());
  assert.equal(verifyBundle(bundleFor("clean_ed25519"), other).checks.anchor, "FAILED");
});

test("the delegation graph reads the chain from the bundle alone", () => {
  const graph = delegationGraph(bundleFor("clean_hs256"));
  assert.equal(graph.chain_id, "fixtures");
  assert.equal(Object.keys(graph.nodes).length, 3);
  assert.equal(graph.edges.length, 2);
  const nodes = Object.values(graph.nodes);
  assert.deepEqual(
    nodes.map((n) => n.agent).sort(),
    ["analyst", "orchestrator", "reader"],
  );
  const reader = nodes.find((n) => n.agent === "reader")!;
  assert.equal(reader.allows, 1);
  assert.equal(reader.denies, 1);
  assert.equal(reader.revoked, true); // the fixture run revokes the reader subtree
  const analyst = nodes.find((n) => n.agent === "analyst")!;
  assert.equal(analyst.complete, true);
  assert.deepEqual(analyst.scopes, ["crm.read"]);
});

test("denials fold into the rows a decisions queue renders", () => {
  const rows = denials(bundleFor("clean_hs256"));
  assert.equal(rows.length, 2);
  assert.deepEqual(
    rows.map((r) => [r.scope, r.reason, r.disposition]),
    [
      ["crm.read", "ceiling_exceeded", null],
      ["crm.export", "scope_not_granted", "out_of_authority"],
    ],
  );
  assert.ok(rows[0]!.first_seq < rows[1]!.first_seq);
});

test("a bundle this library exports verifies here and reports no leak", () => {
  const guard = Guard.issue(
    "orchestrator",
    new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(1000)], ttl: 3600 }),
    { chainId: "ts", task: "quarterly review" },
  );
  const reader = guard.delegate(
    "reader",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(10)], ttl: 60 }),
    "read the pipeline",
  );
  reader.check("crm.read", { context: { rows: 5 } });
  reader.check("crm.write", { context: {} });

  const bundle = exportBundle(guard.auditLog(), hs256);
  const report = verifyBundle(bundle, hs256);
  assert.equal(report.ok, true);
  assert.deepEqual(report.checks, {
    integrity: true,
    monotonicity: true,
    containment: true,
    anchor: "verified",
  });
  assert.equal(bundle.redaction.ok, true);
  assert.equal(bundle.anchor.verified, true);
});

test("redaction removes the prompt text and the bundle still verifies", () => {
  const bundle = parseBundle(fixtureText("redacted_hs256.bundle.json"));
  const tasks = bundle.entries
    .map((e) => e["task"])
    .filter((t): t is string => typeof t === "string");
  assert.ok(tasks.length > 0);
  for (const t of tasks) assert.match(t, /^redacted:len=\d+:h=[0-9a-f]{12}$/);
  assert.equal(verifyBundle(bundle, hs256).ok, true);
});

test("strict export refuses to carry a field outside the allow-list", () => {
  const guard = Guard.issue("a", new Authority({ scopes: ["test.x"], ttl: 60 }), { chainId: "leak" });
  const entries = guard.auditLog().entries;
  entries[0]!["raw_tool_args"] = { password: "hunter2" };
  const report = redactionReport(entries);
  assert.equal(report.ok, false);
  assert.equal(report.violations[0]!.field, "raw_tool_args");
  assert.throws(() => exportBundle(entries, hs256, { strict: true }), EvidenceLeakError);
  // Without strict it exports, but the report says so.
  assert.equal(exportBundle(entries, hs256).redaction.ok, false);
});

test("a context allow-list catches an unvetted context key", () => {
  const guard = Guard.issue("a", new Authority({ scopes: ["test.x"], ttl: 60 }), { chainId: "ctx" });
  guard.check("test.x", { context: { rows: 1, customer_email: "someone@example.com" } });
  const report = redactionReport(guard.auditLog().entries, ["rows", "_scope"]);
  assert.equal(report.ok, false);
  assert.equal(report.violations[0]!.context_key, "customer_email");
});

test("an empty ledger anchors to a seq of -1", () => {
  const bundle = exportBundle([], hs256);
  assert.equal(bundle.anchor.seq, -1);
  assert.equal(bundle.anchor.head, "GENESIS");
  assert.equal(verifyBundle(bundle, hs256).ok, true);
});
