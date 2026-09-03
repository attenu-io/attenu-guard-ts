/**
 * test/bundle-vectors.test.ts — the bundle-level interop vectors
 * (`test/fixtures/vectors/bundles/bundle_vectors_v1.json`) and the structured-failure contract
 * they are scored against (`verifyBundle`'s `failure_details`).
 *
 * The wire vectors next door pin what a delegation TOKEN means; these pin what the LEDGER of a
 * run has to satisfy — the hash chain reproduces and matches a signed anchor, every delegation is
 * a subset of its parent, every allowed scope was inside the acting node's authority, and (schema
 * v2) every tool call binds to exactly one correctly-ordered outcome on the same node, with the
 * arguments that were authorized. That is the check an auditor runs on a published ledger with no
 * engine, no service and no vendor in the loop, so it is the check a second implementation has to
 * be scored on.
 *
 * The file is copied VERBATIM from attenu-guard (Python)'s
 * `tests/vectors/bundles/bundle_vectors_v1.json`, where `tests/vectors/generate_bundles.py` is its
 * single writer and `tests/test_bundle_vectors.py` self-checks it against that build's own
 * `verify_bundle()`. Copying the bytes rather than rebuilding them is the point: a second
 * generator would be a second source of truth. `tools/gen_fixtures.py` re-copies it from the
 * INSTALLED Python package once a release ships it, and CI's fixture-drift check fails on any
 * difference — the same discipline the wire vectors are held to.
 *
 * Ports the two halves of Python's `tests/test_bundle_vectors.py`:
 *
 *   1. every committed case scores exactly as it declares — accepting cases accept with no
 *      failures, rejecting cases reject with every declared {reason, seq, node} reported AT that
 *      position;
 *   2. `failures` and `failure_details` cannot drift apart: same length, same order, one
 *      structured twin per string, at every failure site in `src/evidence.ts` — including the
 *      sites no committed vector exercises.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { AuditLog, GENESIS, hashEntry, type LedgerEntry } from "../src/audit.js";
import { RowLimit } from "../src/ceilings.js";
import type { CJson, Json } from "../src/canonical.js";
import {
  anchorFor,
  exportBundle,
  verifyBundle,
  type Bundle,
  type FailureDetail,
  type VerifyBundleOptions,
} from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { BodyState, Capture } from "../src/reasons.js";
import { HS256TestSigner } from "../src/wire.js";
import { FIXTURES, REPO_ROOT, fixtureJson } from "./helpers.js";

const VECTOR_FILE = "vectors/bundles/bundle_vectors_v1.json";

interface ExpectedFailure {
  reason: string;
  seq: Json;
  node: Json;
}

interface VectorCase {
  name: string;
  description: string;
  signer: { alg: string; kid: string; secret_hex: string };
  bundle: Bundle;
  expect: "accept" | "reject";
  expect_failures: ExpectedFailure[];
}

interface VectorFile {
  /** The compatibility contract. Does not move when cases are appended. */
  version: string;
  /** The additive counter. Moves with each appended case; what a report should name. */
  revision: string;
  description: string;
  cases: VectorCase[];
}

const DOCUMENT = fixtureJson<VectorFile>(VECTOR_FILE);

/**
 * The two failure strings that predate this contract and name a NODE before their colon rather
 * than a reason token. Their `reason` is stated by `evidence.ts` instead of being the text before
 * the colon; every other failure follows the rule.
 */
const REASON_NOT_IN_MESSAGE = new Set(["unreadable_authority", "unreadable_granted"]);

function signerFor(c: VectorCase): HS256TestSigner {
  assert.equal(c.signer.alg, "HS256", "these vectors are HS256; the verifier must be told so");
  return new HS256TestSigner(Buffer.from(c.signer.secret_hex, "hex"), c.signer.kid);
}

/** `{reason, seq, node}` for every reported failure — what `expect_failures` is matched against. */
function positions(details: readonly FailureDetail[]): ExpectedFailure[] {
  return details.map((d) => ({ reason: d.reason, seq: d.seq, node: d.node }));
}

function includesPosition(reported: ExpectedFailure[], expected: ExpectedFailure): boolean {
  return reported.some(
    (r) => r.reason === expected.reason && r.seq === expected.seq && r.node === expected.node,
  );
}

// =============================================================================================
// The committed vectors
// =============================================================================================

test("the vector file declares its version and every expected case, in order", () => {
  // `version` is the compatibility contract and does not move when cases are appended — an
  // implementation that scored bundle_vectors_v1 still scores it. `revision` is the additive
  // counter that does move. Cases are appended, never inserted: a position is stable for life.
  assert.equal(DOCUMENT.version, "bundle_vectors_v1");
  assert.equal(DOCUMENT.revision, "bundle_vectors_v1.1");
  assert.deepEqual(
    DOCUMENT.cases.map((c) => c.name),
    [
      "valid_bundle_v2",
      "reject_params_mismatch",
      "reject_outcome_without_allow",
      "reject_outcome_before_allow",
      "reject_duplicate_outcome",
      "reject_duplicate_call_id",
      "reject_rehashed_chain",
      "reject_tampered_entry",
      // revision v1.1 — the delegation checks no rejecting case covered. The last two add no
      // scope at all: a verifier comparing scope sets alone accepts both and reports nothing.
      "reject_widened_scope",
      "reject_uncontained_allow",
      "reject_increased_ttl",
      "reject_loosened_ceiling",
    ],
  );
});

test("every case is a complete v2 bundle with execution binding", () => {
  for (const c of DOCUMENT.cases) {
    const bundle = c.bundle;
    assert.equal(bundle.v, 2, c.name);
    assert.ok((bundle.anchor as Record<string, CJson>)["sig"], c.name);
    const events = bundle.entries.map((e) => e["event"]);
    for (const required of ["root", "spawn", "allow", "deny", "outcome", "done"]) {
      assert.ok(events.includes(required as CJson), `${c.name}: no ${required} entry`);
    }
    const allow = bundle.entries.find((e) => e["event"] === "allow")!;
    for (const field of ["call_id", "capture", "adapter", "authorized_params_hash"]) {
      assert.ok(field in allow, `${c.name}: allow missing ${field}`);
    }
    const outcome = bundle.entries.find((e) => e["event"] === "outcome")!;
    for (const field of ["call_id", "body_state", "invoked_params_hash"]) {
      assert.ok(field in outcome, `${c.name}: outcome missing ${field}`);
    }
    assert.ok(c.description.trim(), c.name);
  }
});

test("accepting cases verify with no failures", () => {
  for (const c of DOCUMENT.cases) {
    if (c.expect !== "accept") continue;
    const report = verifyBundle(c.bundle, signerFor(c));
    assert.ok(report.ok, `${c.name}: ${JSON.stringify(report.failures)}`);
    assert.deepEqual(report.failures, []);
    assert.deepEqual(report.failure_details, []);
    assert.deepEqual(c.expect_failures, []);
  }
});

test("every rejecting case reports each declared failure at its declared position", () => {
  for (const c of DOCUMENT.cases) {
    if (c.expect !== "reject") continue;
    const report = verifyBundle(c.bundle, signerFor(c));
    assert.equal(report.ok, false, c.name);
    assert.ok(c.expect_failures.length > 0, `${c.name}: a rejecting case must declare a failure`);
    const reported = positions(report.failure_details);
    for (const expected of c.expect_failures) {
      assert.ok(
        includesPosition(reported, expected),
        `${c.name}: ${JSON.stringify(expected)} not in ${JSON.stringify(reported)}`,
      );
    }
  }
});

test("every case scores exactly as it declares, accept or reject", () => {
  for (const c of DOCUMENT.cases) {
    const report = verifyBundle(c.bundle, signerFor(c));
    assert.equal(report.ok ? "accept" : "reject", c.expect, `${c.name}: ${c.description}`);
  }
});

test("the declared minimal set is minimal — every declared reason is genuinely reported", () => {
  // A declared failure must be one this verifier actually reports for THAT bundle, not a hopeful
  // entry no implementation could satisfy.
  for (const c of DOCUMENT.cases) {
    const report = verifyBundle(c.bundle, signerFor(c));
    const reasons = new Set(report.failure_details.map((d) => d.reason));
    for (const expected of c.expect_failures) {
      assert.ok(reasons.has(expected.reason), `${c.name}: ${expected.reason} not in ${[...reasons].join(", ")}`);
    }
  }
});

test("a signerless verification still reports the entry-local failures at their positions", () => {
  // Without the anchor key the hash chain, monotonicity and containment are still checked. The
  // case whose only failure IS the anchor is the exception, and is excluded here by construction.
  for (const c of DOCUMENT.cases) {
    const anchorOnly = c.expect_failures.every((f) => f.reason === "integrity(anchor)");
    if (c.expect !== "reject" || anchorOnly) continue;
    const reported = positions(verifyBundle(c.bundle, null).failure_details);
    for (const expected of c.expect_failures) {
      if (expected.reason === "integrity(anchor)") continue;
      assert.ok(includesPosition(reported, expected), `${c.name}: ${JSON.stringify(expected)}`);
    }
  }
});

test("the vendored copy is the file the fixtures directory documents, read as raw bytes", () => {
  // Read through the same path an auditor would, not the parsed object: a file that fails to be
  // copied, or is copied with a rewritten serialisation, fails here.
  const raw = readFileSync(resolve(FIXTURES, "vectors", "bundles", "bundle_vectors_v1.json"), "utf8");
  assert.equal(JSON.parse(raw).version, "bundle_vectors_v1");
  assert.equal(JSON.parse(raw).revision, "bundle_vectors_v1.1");
  assert.equal(JSON.parse(raw).cases.length, 12);
  assert.ok(raw.endsWith("\n"), "the Python writer terminates the file with a newline");
});

// =============================================================================================
// failures <-> failure_details: the structured twin, at every failure site
// =============================================================================================

const TWIN_SIGNER = new HS256TestSigner(Buffer.from("k", "utf8"), "k");

/**
 * A small v2 chain with a root, a delegation, an allow+outcome on each node, a deny, and both
 * nodes finalized — the shape every mutation below starts from. Mirrors Python's `_v2_bundle`.
 */
function v2Bundle(): Bundle {
  const root = Guard.issue(
    "orchestrator",
    new Authority({ scopes: ["crm.*", "mail.send"], ceilings: [new RowLimit(100)], ttl: 3600 }),
    { chainId: "t", schemaVersion: 2 },
  );
  const child = root.delegate(
    "summarizer",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(50)], ttl: 900 }),
    "summarize",
  );
  const adapter = { module: "m", version: "1", hookPath: "h" };
  const d1 = root.check("mail.send", { authorizedParams: { to: "a" }, capture: Capture.WRAPPER_SYNC, adapter });
  root.recordOutcome(d1.callId!, BodyState.RETURNED, { invokedParams: { to: "a" }, durationMs: 1 });
  const d2 = child.check("crm.read", { authorizedParams: { q: 1 }, capture: Capture.WRAPPER_SYNC, adapter });
  child.check("crm.export");
  child.recordOutcome(d2.callId!, BodyState.RETURNED, { invokedParams: { q: 1 }, durationMs: 2 });
  child.complete();
  root.complete();
  return exportBundle(root.auditLog(), TWIN_SIGNER);
}

function v1Bundle(): Bundle {
  const g = Guard.issue("a", new Authority({ scopes: ["crm.read"], ttl: 60 }), { chainId: "t" });
  g.check("crm.read");
  return exportBundle(g.auditLog(), TWIN_SIGNER);
}

const BASE = v2Bundle();

function clone(bundle: Bundle): Bundle {
  return JSON.parse(JSON.stringify(bundle)) as Bundle;
}

function indexOf(bundle: Bundle, event: string, occurrence = 0): number {
  let seen = -1;
  for (let i = 0; i < bundle.entries.length; i++) {
    if (bundle.entries[i]!["event"] === event) {
      seen += 1;
      if (seen === occurrence) return i;
    }
  }
  throw new Error(`no ${event} entry #${occurrence} in this bundle`);
}

function rehash(bundle: Bundle): void {
  let prev = GENESIS;
  for (const e of bundle.entries) {
    e["prev_hash"] = prev;
    const payload: LedgerEntry = {};
    for (const [k, v] of Object.entries(e)) if (k !== "hash") payload[k] = v;
    e["hash"] = hashEntry(prev, payload);
    prev = e["hash"] as string;
  }
}

function reanchor(bundle: Bundle): void {
  const anchor = anchorFor(bundle.entries, TWIN_SIGNER, 0);
  anchor.verified = AuditLog.verifyAnchor(bundle.entries, anchor as Record<string, CJson>, TWIN_SIGNER)[0];
  bundle.anchor = anchor;
}

interface Site {
  name: string;
  bundle: Bundle;
  options: VerifyBundleOptions;
  reasons: string[];
}

function broken(
  mutate: (b: Bundle) => void,
  options: { rehash?: boolean; reanchor?: boolean } = {},
): Bundle {
  const bundle = clone(BASE);
  mutate(bundle);
  if (options.rehash) rehash(bundle);
  if (options.reanchor) reanchor(bundle);
  return bundle;
}

function killBundle(): Bundle {
  const root = Guard.issue("orchestrator", new Authority({ scopes: ["crm.read"], ttl: 3600 }), {
    chainId: "t",
    schemaVersion: 2,
  });
  const child = root.delegate("summarizer", new Authority({ scopes: ["crm.read"], ttl: 900 }), "t");
  root.revoke(child.nodeId);
  return exportBundle(root.auditLog(), TWIN_SIGNER);
}

/** One mutation per failure site in `src/evidence.ts`, with the reasons it must produce. */
function sites(): Site[] {
  const setEntry = (index: number, field: string, value: CJson) => (b: Bundle) => {
    b.entries[index]![field] = value;
  };
  const dropEntryField = (index: number, field: string) => (b: Bundle) => {
    delete b.entries[index]![field];
  };

  const allowI = indexOf(BASE, "allow");
  const outcomeI = indexOf(BASE, "outcome");
  const denyI = indexOf(BASE, "deny");
  const spawnI = indexOf(BASE, "spawn");
  const childAllowI = indexOf(BASE, "allow", 1);
  const childNode = BASE.entries[spawnI]!["node"] as CJson;

  const kill = killBundle();
  const killBroken = clone(kill);
  killBroken.entries[indexOf(kill, "kill")]!["pending_at_kill"] = "nope";

  const v1 = v1Bundle();
  const v1Leak = clone(v1);
  v1Leak.entries[v1Leak.entries.length - 1]!["call_id"] = "ab".repeat(16);

  return [
    {
      name: "unsupported_version",
      bundle: broken((b) => {
        b.v = 3;
        (b.anchor as Record<string, CJson>)["v"] = 3;
      }),
      options: {},
      reasons: ["unsupported_version"],
    },
    {
      name: "anchor_version_mismatch",
      bundle: broken((b) => {
        (b.anchor as Record<string, CJson>)["v"] = 1;
      }),
      options: {},
      reasons: ["anchor_version_mismatch"],
    },
    { name: "missing_root", bundle: broken((b) => void b.entries.shift()), options: {}, reasons: ["missing_root"] },
    {
      name: "root_version_mismatch",
      bundle: broken(setEntry(0, "v", 1)),
      options: {},
      reasons: ["root_version_mismatch", "mixed_entry_versions"],
    },
    {
      name: "mixed_entry_versions",
      bundle: broken(setEntry(allowI, "v", 1)),
      options: {},
      reasons: ["mixed_entry_versions"],
    },
    {
      name: "expected_head_mismatch",
      bundle: BASE,
      options: { expectedHead: [99, "ff".repeat(32)] },
      reasons: ["expected_head_mismatch"],
    },
    {
      name: "expected_anchor_mismatch",
      bundle: BASE,
      options: { expectedAnchor: { seq: 99, head: "ff".repeat(32), chain_id: "t", v: 2 } },
      reasons: ["expected_anchor_mismatch"],
    },
    {
      name: "chain_id_mismatch(entry)",
      bundle: broken(setEntry(allowI, "chain_id", "other")),
      options: {},
      reasons: ["chain_id_mismatch"],
    },
    {
      name: "chain_id_mismatch(anchor)",
      bundle: broken((b) => {
        (b.anchor as Record<string, CJson>)["chain_id"] = "other";
      }),
      options: {},
      reasons: ["chain_id_mismatch"],
    },
    {
      name: "integrity",
      bundle: broken(setEntry(outcomeI, "duration_ms", 99)),
      options: {},
      reasons: ["integrity", "integrity(anchor)"],
    },
    {
      name: "integrity(anchor)",
      bundle: broken(setEntry(outcomeI, "duration_ms", 99), { rehash: true }),
      options: {},
      reasons: ["integrity(anchor)"],
    },
    // Python's equivalent site corrupts `authority`/`granted` to the STRING "not-an-authority".
    // That value reaches `unreadable_authority` in Python (`str.get` raises) but NOT in
    // TypeScript: `Authority.fromWire` runs its argument through `toPlain` and then indexes it,
    // so a string, a number or null all read as an authority holding nothing, and verification
    // fails later as `containment`/`monotonicity` instead of naming the unreadable record. That
    // divergence lives in `authority.ts`, not here. `{scopes: 5}` is a corruption BOTH
    // implementations refuse (Python `frozenset(5)`, TypeScript a non-iterable spread), so it is
    // what pins these two sites until the two `fromWire` implementations agree.
    {
      name: "unreadable_authority",
      bundle: broken(setEntry(0, "authority", { scopes: 5 }), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["unreadable_authority"],
    },
    {
      name: "unreadable_granted",
      bundle: broken(setEntry(spawnI, "granted", { scopes: 5 }), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["unreadable_granted"],
    },
    {
      name: "monotonicity",
      bundle: broken(
        (b) => {
          (b.entries[spawnI]!["granted"] as Record<string, CJson>)["scopes"] = ["crm.read", "pay.transfer"];
        },
        { rehash: true, reanchor: true },
      ),
      options: {},
      reasons: ["monotonicity"],
    },
    {
      name: "containment",
      bundle: broken(setEntry(childAllowI, "scope", "pay.transfer"), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["containment"],
    },
    {
      name: "containment(unknown node)",
      bundle: broken(setEntry(childAllowI, "node", "t:n99"), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["containment"],
    },
    {
      name: "invalid_root",
      bundle: broken(dropEntryField(0, "params_salt"), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["invalid_root"],
    },
    { name: "invalid_kill", bundle: killBroken, options: {}, reasons: ["invalid_kill"] },
    {
      name: "invalid_allow",
      bundle: broken(dropEntryField(allowI, "capture"), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["invalid_allow"],
    },
    {
      name: "invalid_deny",
      bundle: broken(setEntry(denyI, "capture", Capture.WRAPPER_SYNC), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["invalid_deny"],
    },
    {
      name: "invalid_outcome",
      bundle: broken(setEntry(outcomeI, "duration_ms", -1), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["invalid_outcome"],
    },
    {
      name: "duplicate_call_id",
      bundle: broken(
        (b) => {
          b.entries[denyI]!["call_id"] = b.entries[allowI]!["call_id"]!;
        },
        { rehash: true, reanchor: true },
      ),
      options: {},
      reasons: ["duplicate_call_id"],
    },
    {
      name: "duplicate_outcome",
      bundle: broken(
        (b) => {
          b.entries.splice(outcomeI + 1, 0, JSON.parse(JSON.stringify(b.entries[outcomeI])) as LedgerEntry);
        },
        { rehash: true, reanchor: true },
      ),
      options: {},
      reasons: ["duplicate_outcome"],
    },
    {
      name: "outcome_without_allow",
      bundle: broken(setEntry(outcomeI, "call_id", "cd".repeat(16)), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["outcome_without_allow"],
    },
    {
      name: "cross_ref",
      bundle: broken(setEntry(outcomeI, "node", childNode), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["cross_ref"],
    },
    {
      name: "params_mismatch",
      bundle: broken(setEntry(outcomeI, "invoked_params_hash", "ab".repeat(32)), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["params_mismatch"],
    },
    { name: "v2_field_on_v1", bundle: v1Leak, options: {}, reasons: ["v2_field_on_v1"] },
  ];
}

test("every failure site produces exactly one twin per string", () => {
  for (const site of sites()) {
    const report = verifyBundle(site.bundle, TWIN_SIGNER, site.options);
    const { failures, failure_details: details } = report;
    assert.ok(failures.length > 0, `${site.name}: expected this mutation to fail verification`);
    assert.equal(details.length, failures.length, `${site.name}: the two lists must stay in step`);
    for (let i = 0; i < failures.length; i++) {
      const detail = details[i]!;
      assert.deepEqual(Object.keys(detail).sort(), ["call_id", "detail", "node", "reason", "seq"]);
      assert.equal(detail.detail, failures[i], `${site.name}: twin ${i} does not carry its own string`);
      assert.equal(typeof detail.reason, "string");
      assert.ok(detail.reason.length > 0);
    }
    const reasons = new Set(details.map((d) => d.reason));
    for (const expected of site.reasons) {
      assert.ok(reasons.has(expected), `${site.name}: reported ${[...reasons].sort().join(", ")}`);
    }
  }
});

test("the reason is the token before the colon, with the two documented exceptions", () => {
  const seenExceptions = new Set<string>();
  for (const site of sites()) {
    const report = verifyBundle(site.bundle, TWIN_SIGNER, site.options);
    for (const detail of report.failure_details) {
      if (REASON_NOT_IN_MESSAGE.has(detail.reason)) {
        seenExceptions.add(detail.reason);
        continue;
      }
      assert.equal(detail.reason, detail.detail.split(":", 1)[0], `${site.name}: ${detail.detail}`);
    }
  }
  assert.deepEqual(
    [...seenExceptions].sort(),
    [...REASON_NOT_IN_MESSAGE].sort(),
    "the documented exceptions must both still be reachable",
  );
});

test("a positioned failure names a real entry", () => {
  for (const site of sites()) {
    const report = verifyBundle(site.bundle, TWIN_SIGNER, site.options);
    const seqs = new Set(site.bundle.entries.map((e) => e["seq"] as Json));
    const nodes = new Set(site.bundle.entries.map((e) => e["node"] as Json));
    for (const detail of report.failure_details) {
      if (detail.seq !== null) assert.ok(seqs.has(detail.seq), `${site.name}: seq ${String(detail.seq)}`);
      if (detail.node !== null) assert.ok(nodes.has(detail.node), `${site.name}: node ${String(detail.node)}`);
    }
  }
});

test("a clean bundle reports neither list", () => {
  const report = verifyBundle(BASE, TWIN_SIGNER);
  assert.ok(report.ok, JSON.stringify(report.failures));
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.failure_details, []);
});

test("a v1 bundle keeps its historical execution_binding shape", () => {
  // The structured twins ride ALONGSIDE the executionBinding sub-report, never inside it: that
  // sub-report's published shape is unchanged.
  const report = verifyBundle(v1Bundle(), TWIN_SIGNER);
  assert.deepEqual(report.execution_binding, { status: "not applicable" });
  assert.deepEqual(report.failure_details, []);
});

test("no failure list is appended to directly", () => {
  // Anti-drift: `FailureLog.add` is the only way a failure enters either list, so a new check
  // cannot add a message without its twin. This trap is what keeps that true.
  const source = readFileSync(resolve(REPO_ROOT, "src", "evidence.ts"), "utf8");
  for (const forbidden of ["failures.push(", "log.push("]) {
    assert.ok(
      !source.includes(forbidden),
      `use FailureLog.add(reason, detail, position) instead of ${forbidden}`,
    );
  }
});

// =============================================================================================
// Monotonicity across EVERY dimension of the lattice, not just scopes
// =============================================================================================
//
// A delegation widens if it grows on ANY dimension `Authority.isNarrowerThan` compares: scopes,
// ceilings, or ttl. Through 0.6.0 the bundle verifier's monotonicity check was gated on a
// literal, non-wildcard-aware scope difference, so a child that only outlived its parent or only
// raised a ceiling was reported ONLY when its scopes happened not to be literally a subset.
// Every widening bundle below verified clean before that gate was removed, and the misdirected
// case reported a scope message for a ttl violation. Mirrors Python's
// `TestMonotonicityDimensions`, message for message.

const MONO_PARENT = () =>
  new Authority({ scopes: ["crm.read", "mail.send"], ceilings: [new RowLimit(100)], ttl: 3600 });

interface GrantedWire {
  scopes: string[];
  constraints: Array<Record<string, Json>>;
  ttl: number | null;
}

function granted(
  overrides: { scopes?: string[]; maxRows?: number | null; ttl?: number | null } = {},
): GrantedWire {
  const maxRows = overrides.maxRows === undefined ? 50 : overrides.maxRows;
  return {
    scopes: overrides.scopes ?? ["crm.read"],
    constraints: maxRows === null ? [] : [{ key: "max_rows", max: maxRows }],
    ttl: overrides.ttl === undefined ? 900 : overrides.ttl,
  };
}

/**
 * An honest two-node v2 chain with the spawn's `granted` replaced wholesale, the chain re-hashed
 * and a fresh anchor signed over it. That detour is the only way to get an unsound delegation
 * into a ledger: `Guard.delegate` refuses to create one, which is why this is a verifier test.
 */
function monoBundle(grantedWire: GrantedWire, parent?: Authority): Bundle {
  const root = Guard.issue("orchestrator", parent ?? MONO_PARENT(), {
    chainId: "t",
    schemaVersion: 2,
  });
  const child = root.delegate(
    "summarizer",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(50)], ttl: 900 }),
    "summarize",
  );
  child.complete();
  root.complete();
  const bundle = exportBundle(root.auditLog(), TWIN_SIGNER);
  bundle.entries[indexOf(bundle, "spawn")]!["granted"] = grantedWire as unknown as CJson;
  rehash(bundle);
  reanchor(bundle);
  return bundle;
}

function assertWidens(grantedWire: GrantedWire, expectedDetail: string, parent?: Authority): void {
  const bundle = monoBundle(grantedWire, parent);
  const spawn = bundle.entries[indexOf(bundle, "spawn")]!;
  const node = spawn["node"] as string;
  const pid = spawn["parent"] as string;
  const report = verifyBundle(bundle, TWIN_SIGNER);
  assert.equal(report.ok, false, "a widening delegation must not verify");
  assert.equal(report.checks.monotonicity, false);
  // Integrity stays green: the chain was re-hashed and re-anchored, so monotonicity is the only
  // thing wrong and the failure cannot be an artifact of a broken ledger.
  assert.equal(report.checks.integrity, true);
  assert.deepEqual(report.failures, [
    `monotonicity: ${node} not ⊆ parent ${pid} (${expectedDetail})`,
  ]);
  assert.deepEqual(
    report.failure_details.map((d) => [d.reason, d.seq, d.node]),
    [["monotonicity", 1, node]],
  );
}

test("a child that outlives its parent is not narrower", () => {
  assertWidens(granted({ ttl: 7200 }), "ttl 7200 > parent 3600");
});

test("a child with a looser ceiling is not narrower", () => {
  assertWidens(granted({ maxRows: 250 }), "ceiling max_rows<=250 looser than parent max_rows<=100");
});

test("a child unbounded where its parent bounds is not narrower", () => {
  // Dropping a ceiling is not attenuation: no ceiling means unbounded on that dimension, which
  // is MORE authority than the parent held, not less.
  assertWidens(granted({ maxRows: null }), "ceiling max_rows unbounded, parent holds max_rows<=100");
});

test("a child that never expires under a parent that does is not narrower", () => {
  assertWidens(granted({ ttl: null }), "ttl unbounded, parent 3600");
});

test("a ttl widening under a wildcard parent names ttl, not scopes", () => {
  // The misdirected case. {crm.read} is covered by a parent holding {crm.*} but is NOT literally
  // in its scope set, so the old gate fired and printed a scope message for a violation that was
  // entirely about ttl.
  assertWidens(
    granted({ ttl: 7200 }),
    "ttl 7200 > parent 3600",
    new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(100)], ttl: 3600 }),
  );
});

test("the scope widening message is unchanged", () => {
  assertWidens(
    granted({ scopes: ["crm.read", "pay.transfer"] }),
    "child scopes ['pay.transfer'] not held by parent",
  );
});

test("a scope widening under a wildcard parent keeps its historical wording", () => {
  // The published string lists the LITERAL set difference, so a scope the parent covers by
  // wildcard appears in it alongside the one it does not. Unchanged on purpose: it is the
  // wording the released vectors and two independent verifiers already score.
  assertWidens(
    granted({ scopes: ["crm.read", "pay.transfer"] }),
    "child scopes ['crm.read', 'pay.transfer'] not held by parent",
    new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(100)], ttl: 3600 }),
  );
});

test("an honestly narrower child still verifies", () => {
  // The other half of the fix: removing the gate must not make a sound delegation fail.
  const report = verifyBundle(monoBundle(granted({ maxRows: 10, ttl: 60 })), TWIN_SIGNER);
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  assert.deepEqual(report.failures, []);
});

test("an identical regrant still verifies", () => {
  // The boundary of the relation: equal is narrower-or-equal, so a child granted exactly what
  // its parent holds is sound and must not be reported.
  const report = verifyBundle(
    monoBundle({
      scopes: ["crm.read", "mail.send"],
      constraints: [{ key: "max_rows", max: 100 }],
      ttl: 3600,
    }),
    TWIN_SIGNER,
  );
  assert.equal(report.ok, true, JSON.stringify(report.failures));
});

test("the first failing dimension is the one reported", () => {
  // Ceilings are compared before ttl, matching Authority.isNarrowerThan, so a child that widens
  // both names the ceiling. One message per unsound delegation, as before.
  assertWidens(
    granted({ maxRows: 250, ttl: 7200 }),
    "ceiling max_rows<=250 looser than parent max_rows<=100",
  );
});
