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
  LEDGER_EVENTS,
  LEDGER_EVENTS_V1,
  LEDGER_FIELDS,
  anchorFor,
  delegationGraph,
  denials,
  envelopeSigningInput,
  envelopeSubject,
  exportBundle,
  integrityBreak,
  parseBundle,
  redactionReport,
  signEnvelope,
  stateKey,
  verifyBundle,
  verifyEnvelopes,
  type Bundle,
  type FailureDetail,
  type VerifyBundleOptions,
  type VerifyReport,
} from "../src/evidence.js";
import * as api from "../src/index.js";
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
  /**
   * OPTIONAL, revision v1.3: named counters from the verifier's own report that a conformant
   * implementation reproduces exactly. It exists for a rule accept/reject cannot distinguish —
   * an un-gated allow is neither a containment pass nor a failure, so the only way a case can
   * pin it is by the number reported. A case without it asserts nothing about counters.
   */
  expect_report?: Record<string, number>;
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
  assert.equal(DOCUMENT.revision, "bundle_vectors_v1.4");
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
      // revision v1.2 — the literal-subset base and the four rows that can fail ONLY on ttl or a
      // ceiling. The two v1.1 rows above are also rejected, for a scope reason, by a verifier
      // that compares scope lists literally and skips both dimensions (0.11.0 / 0.6.0 did).
      "valid_bundle_v2_literal",
      "reject_increased_ttl_literal",
      "reject_loosened_ceiling_literal",
      "reject_null_ttl_literal",
      "reject_omitted_ceiling_literal",
      // revision v1.3 — the un-gated allow. An accepting row whose whole content is a report
      // counter: `policy: "unlisted"` says the chain never authorized the call, so containment
      // must not test it and must not drop it either.
      "valid_bundle_v2_ungated_allow",
      // v1.4: the two rows that pin the policy rule an implementer could get wrong.
      "reject_unknown_policy_value",
      "reject_policy_on_spawn",
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

test("a case declaring expect_report reproduces those counters exactly", () => {
  // The counters are the only thing an accept/reject verdict cannot express. A case that declares
  // them must reproduce every one; a case that declares none asserts nothing here.
  let declared = 0;
  for (const c of DOCUMENT.cases) {
    if (c.expect_report === undefined) continue;
    declared += 1;
    const report = verifyBundle(c.bundle, signerFor(c)) as unknown as Record<string, unknown>;
    for (const [counter, expected] of Object.entries(c.expect_report)) {
      assert.equal(report[counter], expected, `${c.name}: report.${counter}`);
    }
  }
  assert.ok(declared > 0, "revision v1.3 ships at least one case declaring expect_report");
});

test("an un-gated allow is counted, not contained and not ignored", () => {
  // The rule the v1.3 row exists for, asserted against the shape of the entry rather than the
  // counters alone: the policy-marked allow's scope is OUTSIDE the acting node's authority, so a
  // verifier that ran it through containment would reject an honest bundle.
  const c = DOCUMENT.cases.find((x) => x.name === "valid_bundle_v2_ungated_allow");
  assert.ok(c, "valid_bundle_v2_ungated_allow is present");
  const marked = (c!.bundle.entries ?? []).filter((e) => "policy" in e);
  assert.equal(marked.length, 1);
  assert.equal(marked[0]!["event"], "allow");
  assert.equal(marked[0]!["policy"], "unlisted");
  const report = verifyBundle(c!.bundle, signerFor(c!));
  assert.ok(report.ok, JSON.stringify(report.failures));
  assert.equal(report.ungated, 1);
  assert.equal(report.actions_checked, 2);
});

test("policy is allow-only: a deny carrying it is an invalid v2 entry", () => {
  const c = DOCUMENT.cases.find((x) => x.name === "valid_bundle_v2_ungated_allow")!;
  const bundle = JSON.parse(JSON.stringify(c.bundle)) as Bundle;
  const deny = (bundle.entries ?? []).find((e) => e["event"] === "deny");
  assert.ok(deny, "the case has a deny to mark");
  (deny as Record<string, unknown>)["policy"] = "unlisted";
  const report = verifyBundle(bundle, signerFor(c));
  assert.equal(report.ok, false);
  assert.ok(
    report.failure_details.some((d) => d.reason === "invalid_deny"),
    JSON.stringify(report.failures),
  );
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
  assert.equal(JSON.parse(raw).revision, "bundle_vectors_v1.4");
  assert.equal(JSON.parse(raw).cases.length, 20);
  assert.ok(raw.endsWith("\n"), "the Python writer terminates the file with a newline");
});

test("the literal base differs from valid_bundle_v2 in the root authority only", () => {
  const byName = new Map(DOCUMENT.cases.map((c) => [c.name, c]));
  const a = byName.get("valid_bundle_v2")!.bundle.entries;
  const b = byName.get("valid_bundle_v2_literal")!.bundle.entries;
  assert.equal(a.length, b.length);
  const strip = (e: Record<string, CJson>) => {
    const { hash: _h, prev_hash: _p, ...rest } = e;
    return JSON.stringify(rest);
  };
  const differing = a.map((e, i) => (strip(e) !== strip(b[i]!) ? i : -1)).filter((i) => i >= 0);
  assert.deepEqual(differing, [0]);
  assert.deepEqual((a[0]!["authority"] as Record<string, CJson>)["scopes"], ["crm.*", "mail.send"]);
  assert.deepEqual((b[0]!["authority"] as Record<string, CJson>)["scopes"], ["crm.read", "mail.send"]);
  assert.deepEqual(a[1]!["granted"], b[1]!["granted"]);
});

test("the literal rows show no scope difference to a literal comparison", () => {
  // What revision v1.2 exists for. A verifier that compares scope LISTS and never looks at ttl or
  // ceilings rejects the two v1.1 rows anyway, for a scope reason at the declared position:
  // crm.read is not literally in {crm.*, mail.send}. It passes them without checking the
  // dimension they are about. On the four v1.2 rows that comparison finds nothing, so only a
  // ttl or ceiling check can produce the required failure.
  const byName = new Map(DOCUMENT.cases.map((c) => [c.name, c]));
  const literalWidening = (name: string): string[] => {
    const es = byName.get(name)!.bundle.entries;
    const parent = new Set((es[0]!["authority"] as Record<string, CJson>)["scopes"] as string[]);
    const child = (es[1]!["granted"] as Record<string, CJson>)["scopes"] as string[];
    return child.filter((s) => !parent.has(s)).sort();
  };
  for (const name of ["reject_increased_ttl", "reject_loosened_ceiling"]) {
    assert.deepEqual(literalWidening(name), ["crm.read"], name);
  }
  const base = byName.get("valid_bundle_v2_literal")!.bundle.entries[1]!["granted"] as Record<string, CJson>;
  for (const name of [
    "reject_increased_ttl_literal",
    "reject_loosened_ceiling_literal",
    "reject_null_ttl_literal",
    "reject_omitted_ceiling_literal",
  ]) {
    assert.deepEqual(literalWidening(name), [], name);
    const granted = byName.get(name)!.bundle.entries[1]!["granted"] as Record<string, CJson>;
    assert.deepEqual(granted["scopes"], base["scopes"], name);
    assert.ok(
      JSON.stringify(granted["ttl"]) !== JSON.stringify(base["ttl"]) ||
        JSON.stringify(granted["constraints"]) !== JSON.stringify(base["constraints"]),
      `${name}: only ttl or constraints may differ from the base`,
    );
  }
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
  const doneI = indexOf(BASE, "done");
  const childAllowI = indexOf(BASE, "allow", 1);
  const childNode = BASE.entries[spawnI]!["node"] as CJson;

  const kill = killBundle();
  const killBroken = clone(kill);
  killBroken.entries[indexOf(kill, "kill")]!["pending_at_kill"] = "nope";

  const v1 = v1Bundle();
  const v1Leak = clone(v1);
  v1Leak.entries[v1Leak.entries.length - 1]!["call_id"] = "ab".repeat(16);

  // `policy` is checked on EVERY version, so its two sites are reached on a v1 bundle, where
  // execution binding (which owns the v2 message) never runs.
  const v1BogusPolicy = clone(v1);
  v1BogusPolicy.entries[indexOf(v1, "allow")]!["policy"] = "totally-made-up";
  const v1PolicyOnRoot = clone(v1);
  v1PolicyOnRoot.entries[0]!["policy"] = "unlisted";

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
      name: "invalid_policy",
      bundle: v1BogusPolicy,
      options: {},
      reasons: ["invalid_policy", "integrity", "integrity(anchor)"],
    },
    {
      name: "policy_on_non_allow",
      bundle: v1PolicyOnRoot,
      options: {},
      reasons: ["policy_on_non_allow", "integrity", "integrity(anchor)"],
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
    {
      name: "unknown_ledger_event",
      bundle: broken(setEntry(doneI, "event", "frobnicate"), { rehash: true, reanchor: true }),
      options: {},
      reasons: ["unknown_ledger_event"],
    },
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

// =============================================================================================
// Every entry is a JSON object, and its event one its chain's version defines
// =============================================================================================
//
// The schema (`schema/agent-audit.schema.json` in the Python distribution) closes the ledger
// `event` set, and the verifier did not enforce it: `valid_bundle_v2` with a `done` renamed
// `frobnicate` or `""`, re-chained and re-anchored, verified ok; an `allow` renamed was read by no
// check, containment included; and a bare `outcome` on a schemaVersion 1 chain verified, though
// the schema makes `outcome` v2-only. An entry that is not a JSON object, or an `entries` that is
// not an array, threw out of `verifyBundle` instead of reporting. Both entry-level names are
// XuebinMa's (A2A #1575).
//
// Every expected string here is the Python implementation's, asserted byte for byte by its
// tests/test_bundle_vectors.py (`TestEntryShapeAndEventNames`), for the same mutation of the same
// bundle.

const UNKNOWN_EVENT =
  "unknown_ledger_event: entry carries an event this verifier does not evaluate and will not ignore: ";

const VALID_V2_CASE = DOCUMENT.cases.find((c) => c.name === "valid_bundle_v2")!;
const VALID_V2_SIGNER = signerFor(VALID_V2_CASE);

function validV2(): Bundle {
  return clone(VALID_V2_CASE.bundle);
}

/** valid_bundle_v2 with `edit(entries)` applied, re-chained and re-anchored, so integrity is not what fails. */
function rechained(edit: (entries: LedgerEntry[]) => void): Bundle {
  const bundle = validV2();
  edit(bundle.entries);
  rehash(bundle);
  const anchor = anchorFor(bundle.entries, VALID_V2_SIGNER, 0);
  anchor.verified = AuditLog.verifyAnchor(bundle.entries, anchor as Record<string, CJson>, VALID_V2_SIGNER)[0];
  bundle.anchor = anchor;
  return bundle;
}

function verifyV2(bundle: unknown, options: VerifyBundleOptions = {}): VerifyReport {
  return verifyBundle(bundle as Bundle, VALID_V2_SIGNER, options);
}

function assertTwins(report: VerifyReport): void {
  assert.equal(report.failure_details.length, report.failures.length);
  assert.equal(report.failure_entries.length, report.failures.length);
  report.failures.forEach((message, i) => {
    assert.equal(report.failure_details[i]!.detail, message);
    assert.equal(report.failure_details[i]!.reason, message.split(":", 1)[0]);
  });
}

test("LEDGER_EVENTS is the schema's event enum, and version 1 has every name but outcome", () => {
  // No copy of the schema ships in this repository. The Python implementation's
  // `test_ledger_events_are_the_schema_enum_per_version` pins these same sets against it.
  assert.deepEqual([...LEDGER_EVENTS].sort(), [
    "allow", "deny", "done", "kill", "outcome", "root", "spawn", "spawn_denied",
  ]);
  assert.deepEqual([...LEDGER_EVENTS_V1].sort(), [
    "allow", "deny", "done", "kill", "root", "spawn", "spawn_denied",
  ]);
  assert.equal(api.LEDGER_EVENTS, LEDGER_EVENTS);
  assert.equal(api.LEDGER_EVENTS_V1, LEDGER_EVENTS_V1);
});

test("LEDGER_FIELDS is the schema's property set", () => {
  // The Python implementation's `test_the_schema_names_exactly_the_ledger_fields` pins this same
  // set against the schema's properties.
  assert.deepEqual([...LEDGER_FIELDS].sort(), [
    "adapter", "agent", "authority", "authorized_params_hash", "body_state", "c14n", "call_id",
    "capture", "chain_id", "context", "detail", "disposition", "duration_ms", "error_code", "event",
    "granted", "hash", "invoked_params_hash", "mode", "node", "params_hash_reason", "params_salt",
    "parent", "pending_at_kill", "policy", "prev_hash", "reason", "reasons", "receipt", "requested",
    "revoked", "scope", "seq", "strikes", "target", "task", "tool", "ts", "v",
  ]);
});

test("an event outside the eight fails at its entry", () => {
  // Printed by the display rule, as unknown_ledger_fields prints a field name.
  const cases: [string, string][] = [
    ["frobnicate", "frobnicate"], ["", '""'], ["Done", "Done"], ["done ", '"done\\u0020"'],
    ["spawn-denied", "spawn-denied"], ["5", "5"], ["None", "None"],
  ];
  for (const [value, shown] of cases) {
    const report = verifyV2(rechained((entries) => void (entries[7]!["event"] = value)));
    const message = UNKNOWN_EVENT + shown;
    assert.equal(report.ok, false, value);
    assert.equal(report.checks.ledger_fields, false, value);
    assert.equal(report.checks.integrity, true, value);
    assert.deepEqual(report.failures, [message]);
    assert.deepEqual(report.failure_details, [
      { reason: "unknown_ledger_event", seq: 7, node: "vectors:n1", call_id: null, detail: message },
    ]);
    assert.deepEqual(report.failure_entries, [7]);
  }
});

test("an event that is not a string fails at its entry", () => {
  // Said to be no string, so the number 5 and null read differently from the strings "5" and
  // "None" above. An absent event reads as None, as an absent seq does.
  const cases: [string, (e: LedgerEntry) => void, string][] = [
    ["absent", (e) => void delete e["event"], "None"],
    ["null", (e) => void (e["event"] = null), "None"],
    ["number", (e) => void (e["event"] = 5), "5"],
    ["boolean", (e) => void (e["event"] = true), "True"],
    ["array", (e) => void (e["event"] = ["done"]), "['done']"],
    ["object", (e) => void (e["event"] = { name: "done" }), '{"name":"done"}'],
  ];
  for (const [label, edit, shown] of cases) {
    const report = verifyV2(rechained((entries) => edit(entries[7]!)));
    const message = `${UNKNOWN_EVENT}${shown}, which is not a string`;
    assert.equal(report.ok, false, label);
    assert.equal(report.checks.ledger_fields, false, label);
    assert.deepEqual(report.failures, [message], label);
    assert.deepEqual(report.failure_details, [
      { reason: "unknown_ledger_event", seq: 7, node: "vectors:n1", call_id: null, detail: message },
    ]);
    assert.deepEqual(report.failure_entries, [7], label);
  }
});

test("an allow renamed is reported, not skipped", () => {
  // Before, the only failure was the outcome it orphaned: the renamed entry itself was read by no
  // check, containment included.
  const report = verifyV2(rechained((entries) => void (entries[2]!["event"] = "frobnicate")));
  assert.equal(report.ok, false);
  assert.deepEqual(report.failures, [
    UNKNOWN_EVENT + "frobnicate",
    "outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain",
  ]);
  assert.deepEqual(report.failure_entries, [2, 3]);
  assertTwins(report);
});

test("a bare outcome on a schemaVersion 1 chain fails at its entry", () => {
  // `outcome` is v2-only. A bare one carries no v2-only field, so v2_field_on_v1 does not see it
  // either, and this bundle verified.
  const bundle = v1Bundle();
  const last = bundle.entries[bundle.entries.length - 1]!;
  bundle.entries.push({
    v: 1,
    c14n: last["c14n"]!,
    seq: (last["seq"] as number) + 1,
    ts: last["ts"]!,
    event: "outcome",
    chain_id: last["chain_id"]!,
    node: last["node"]!,
  });
  rehash(bundle);
  reanchor(bundle);
  const report = verifyBundle(bundle, TWIN_SIGNER);
  const message = UNKNOWN_EVENT + "outcome, a v2-only event on a schema_version=1 chain";
  assert.equal(report.ok, false);
  assert.deepEqual(report.failures, [message]);
  assert.deepEqual(report.failure_details, [
    { reason: "unknown_ledger_event", seq: 2, node: "t:n0", call_id: null, detail: message },
  ]);
  assert.deepEqual(report.failure_entries, [2]);
  // The other seven are version 1's own.
  assert.equal(verifyBundle(v1Bundle(), TWIN_SIGNER).ok, true);
});

test("each defect on one entry is reported", () => {
  const report = verifyV2(
    rechained((entries) => {
      entries[7]!["event"] = "frobnicate";
      entries[7]!["critical"] = true;
    }),
  );
  assert.deepEqual(report.failures, [
    UNKNOWN_EVENT + "frobnicate",
    "unknown_ledger_fields: entry carries fields this verifier does not evaluate and will not ignore: critical",
  ]);
  assert.deepEqual(report.failure_entries, [7, 7]);
  assertTwins(report);
});

test("every event the schema names still verifies", () => {
  // The control: the eight names are read, and nothing above fires on a clean bundle.
  const report = verifyV2(validV2());
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  assert.equal(report.checks.ledger_fields, true);
});

test("an entry that is not an object is reported, never thrown", () => {
  // Chain-level, since it has no seq or node; its index is in the message, and `failure_entries`
  // names it. Nothing else reads it, so it is reported once; the hash chain breaks there, which is
  // the one consequence. Not re-chained: such an entry has no hash to re-chain.
  const cases: [unknown, string][] = [
    ["x", "a string"], [null, "null"], [[], "an array"], [["root"], "an array"], [5, "a number"],
    [1.5, "a number"], [true, "a boolean"],
  ];
  for (const [value, kind] of cases) {
    const bundle = validV2();
    bundle.entries[7] = value as LedgerEntry;
    const report = verifyV2(bundle);
    const label = JSON.stringify(value);
    assert.equal(report.ok, false, label);
    assert.equal(report.checks.ledger_fields, false, label);
    assert.equal(report.checks.integrity, false, label);
    assert.equal(report.checks.version, true, label);
    assert.equal(report.checks.chain_id, true, label);
    assert.deepEqual(report.failures, [
      `invalid_ledger_entry: entries[7] is ${kind}, not an object`,
      "integrity: seq gap at 7 (got None)",
      "integrity(anchor): seq gap at 7 (got None)",
    ], label);
    assert.deepEqual(
      report.failure_details.map((d) => [d.reason, d.seq, d.node, d.call_id]),
      [
        ["invalid_ledger_entry", null, null, null],
        ["integrity", null, null, null],
        ["integrity(anchor)", null, null, null],
      ],
      label,
    );
    assert.deepEqual(report.failure_entries, [7, 7, null], label);
    assertTwins(report);
  }
});

test("a number entry read by parseBundle is a number, not an object", () => {
  // `parseBundle` keeps every number's literal as a RawNumber, which is an object to `typeof`.
  const bundle = validV2() as unknown as Record<string, unknown>;
  (bundle["entries"] as unknown[])[7] = 5;
  const report = verifyV2(parseBundle(JSON.stringify(bundle)));
  assert.equal(report.failures[0], "invalid_ledger_entry: entries[7] is a number, not an object");
});

test("two entries that are not objects are each positioned", () => {
  // By index, never by the value: two nulls are two entries.
  const bundle = validV2();
  bundle.entries[3] = null as unknown as LedgerEntry;
  bundle.entries[7] = null as unknown as LedgerEntry;
  const report = verifyV2(bundle);
  assert.deepEqual(report.failures, [
    "invalid_ledger_entry: entries[3] is null, not an object",
    "invalid_ledger_entry: entries[7] is null, not an object",
    "integrity: seq gap at 3 (got None)",
    "integrity(anchor): seq gap at 3 (got None)",
  ]);
  assert.deepEqual(report.failure_entries, [3, 7, 3, null]);
});

test("an expected head past an entry that is not an object is reported", () => {
  const bundle = validV2();
  const head = bundle.entries[8]!["hash"] as string;
  bundle.entries[8] = null as unknown as LedgerEntry;
  const report = verifyV2(bundle, { expectedHead: [8, head] });
  assert.ok(
    report.failures.includes(
      `expected_head_mismatch: bundle head is (seq=8, hash=None) but the independently retained expected head is (seq=8, hash=${head})`,
    ),
    JSON.stringify(report.failures),
  );
  assert.equal(report.ok, false);
});

test("entries that is not an array is reported, never thrown", () => {
  const cases: [unknown, string][] = [
    ["x", "a string"], ["", "a string"], [{}, "an object"], [{ "0": {} }, "an object"],
    [5, "a number"], [0, "a number"], [false, "a boolean"],
  ];
  for (const [value, kind] of cases) {
    const bundle = validV2() as unknown as Record<string, unknown>;
    bundle["entries"] = value;
    const report = verifyV2(bundle);
    const message = `invalid_bundle: entries is ${kind}, not an array`;
    const label = JSON.stringify(value);
    assert.deepEqual(report.failures, [message], label);
    assert.deepEqual(report.failure_details, [
      { reason: "invalid_bundle", seq: null, node: null, call_id: null, detail: message },
    ]);
    assert.deepEqual(report.failure_entries, [null], label);
    assert.equal(report.ok, false, label);
    assert.deepEqual(report.checks, {
      integrity: false,
      monotonicity: false,
      containment: false,
      anchor: "not checked",
      version: false,
      ledger_fields: false,
      chain_id: false,
      root: false,
      expected_anchor: "not checked",
      envelopes: "not checked",
    });
    assert.deepEqual([report.nodes, report.actions_checked, report.ungated], [0, 0, 0]);
    assert.equal(report.chain_id, "vectors");
    assert.deepEqual(report.execution_binding, { status: "not applicable" });
    assert.equal(report.envelopes.status, "not checked");
    assert.equal(report.verified_against, "bundle_anchor");
  }
});

test("absent or null entries are still an empty ledger", () => {
  const cases: [string, (b: Record<string, unknown>) => void][] = [
    ["absent", (b) => void delete b["entries"]],
    ["null", (b) => void (b["entries"] = null)],
    ["empty", (b) => void (b["entries"] = [])],
  ];
  for (const [label, edit] of cases) {
    const bundle = validV2() as unknown as Record<string, unknown>;
    edit(bundle);
    assert.deepEqual(
      verifyBundle(bundle as unknown as Bundle).failures,
      ["missing_root: bundle has 0 root event(s), expected exactly 1"],
      label,
    );
  }
});

test("a bundle that is not an object is reported, never thrown", () => {
  const cases: [unknown, string][] = [
    [[], "an array"], ["x", "a string"], [null, "null"], [5, "a number"], [true, "a boolean"],
  ];
  for (const [value, kind] of cases) {
    const report = verifyV2(value);
    const label = JSON.stringify(value);
    assert.deepEqual(report.failures, [`invalid_bundle: the bundle is ${kind}, not an object`], label);
    assert.deepEqual(report.failure_entries, [null], label);
    assert.equal(report.ok, false, label);
    assert.equal(report.chain_id, null, label);
    assertTwins(report);
  }
});

// =============================================================================================
// Hostile bundle content is reported or skipped by every public reader, never thrown
// =============================================================================================
//
// `verifyBundle`'s 0.8.0 note says it never throws. It threw on `envelopes` that were not an
// array, and read an `anchor` that was not an object by projection (a string's characters as its
// members). `delegationGraph`, `denials`, `verifyEnvelopes` and `redactionReport` threw on a
// bundle, its entries, or an entry that was not what the format says, and `stateKey` and
// `integrityBreak` on one that was not an object or an array. Every public reader now reports
// what it cannot read, by its own convention, or skips it; the signing helpers throw their
// documented Error, and `exportBundle` and `anchorFor`, which sign, refuse such input by name. The
// Python implementation's tests/test_bundle_vectors.py (`TestHostileBundleContent`) asserts the
// same strings and shapes.

/** One value of each JSON kind, and the empty ones Python counts as false. */
const KINDS: unknown[] = [null, true, 0, 1.5, "", "x", [], ["x"], {}, { a: 1 }];

const FIELD_CASES: [string, (es: LedgerEntry[]) => void, [string, Json, Json, number | null][]][] = [
  ["v=[] at 4", (es) => void (es[4]!["v"] = []), [["mixed_entry_versions: entries declare v in [[]], bundle v=2", 4, "vectors:n1", 4]]],
  [
    "v={'a': 1} at 4, v=[] at 6",
    (es) => {
      es[4]!["v"] = { a: 1 };
      es[6]!["v"] = [];
    },
    [["mixed_entry_versions: entries declare v in [[], {'a': 1}], bundle v=2", 4, "vectors:n1", 4]],
  ],
  [
    "seq=[] at 4",
    (es) => void (es[4]!["seq"] = []),
    [
      ["integrity: seq gap at 4 (got [])", [], "vectors:n1", 4],
      ["integrity(anchor): seq gap at 4 (got [])", null, null, null],
      ["outcome_before_allow: call_id 15d42567717e39b8ff1881a14ec42f96 outcome seq 6 not after allow seq []", 6, "vectors:n1", 6],
    ],
  ],
  [
    "seq='x' at 3",
    (es) => void (es[3]!["seq"] = "x"),
    [
      ["integrity: seq gap at 3 (got x)", "x", "vectors:n0", 3],
      ["integrity(anchor): seq gap at 3 (got x)", null, null, null],
      ["outcome_before_allow: call_id eb099aeb221783e1442261f15df4fb35 outcome seq x not after allow seq 2", "x", "vectors:n0", 3],
    ],
  ],
  [
    "seq=true at 2",
    (es) => void (es[2]!["seq"] = true),
    [
      ["integrity: seq gap at 2 (got True)", true, "vectors:n0", 2],
      ["integrity(anchor): seq gap at 2 (got True)", null, null, null],
      ["outcome_before_allow: call_id eb099aeb221783e1442261f15df4fb35 outcome seq 3 not after allow seq True", 3, "vectors:n0", 3],
    ],
  ],
  [
    "call_id=[] at 2",
    (es) => void (es[2]!["call_id"] = []),
    [
      ["invalid_allow: call_id missing or malformed ([]) (seq 2)", 2, "vectors:n0", 2],
      ["outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain", 3, "vectors:n0", 3],
    ],
  ],
  [
    "capture={} at 2",
    (es) => void (es[2]!["capture"] = {}),
    [
      ["invalid_allow: capture {} not a known value (seq 2)", 2, "vectors:n0", 2],
      ["outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain", 3, "vectors:n0", 3],
    ],
  ],
  [
    "params_hash_reason=[] at 2",
    (es) => {
      delete es[2]!["authorized_params_hash"];
      es[2]!["params_hash_reason"] = [];
    },
    [
      ["invalid_allow: params_hash_reason [] not a known value (seq 2)", 2, "vectors:n0", 2],
      ["outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain", 3, "vectors:n0", 3],
    ],
  ],
  ["body_state=[] at 3", (es) => void (es[3]!["body_state"] = []), [["invalid_outcome: body_state [] not a known value (seq 3)", 3, "vectors:n0", 3]]],
  [
    "call_id=5 at 2 and 5",
    (es) => {
      es[2]!["call_id"] = 5;
      es[5]!["call_id"] = 5;
    },
    [
      ["invalid_allow: call_id missing or malformed (5) (seq 2)", 2, "vectors:n0", 2],
      ["duplicate_call_id: call_id 5 on seq 5 (deny) already used at seq 2 (allow)", 5, "vectors:n1", 5],
      ["invalid_deny: call_id missing or malformed (5) (seq 5)", 5, "vectors:n1", 5],
      ["outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain", 3, "vectors:n0", 3],
    ],
  ],
];

function hostile(edit: (b: Record<string, unknown>) => void): Bundle {
  const bundle = validV2() as unknown as Record<string, unknown>;
  edit(bundle);
  return bundle as unknown as Bundle;
}

test("an anchor that is not an object is an invalid bundle", () => {
  const cases: [unknown, string][] = [
    ["x", "a string"], ["", "a string"], [5, "a number"], [0, "a number"], [true, "a boolean"],
    [false, "a boolean"], [[], "an array"], [["x"], "an array"],
  ];
  for (const [value, kind] of cases) {
    for (const signer of [null, VALID_V2_SIGNER]) {
      const report = verifyBundle(hostile((b) => void (b["anchor"] = value)), signer);
      assert.deepEqual(report.failures, [`invalid_bundle: anchor is ${kind}, not an object`], JSON.stringify(value));
      assert.deepEqual(report.failure_entries, [null]);
      assert.equal(report.ok, false);
    }
  }
  // null is an absent anchor, as before
  assert.equal(verifyBundle(hostile((b) => void (b["anchor"] = null))).ok, true);
});

test("envelopes that are not an array are an invalid bundle", () => {
  const cases: [unknown, string][] = [["x", "a string"], [5, "a number"], [true, "a boolean"], [{}, "an object"], [{ v: 1 }, "an object"]];
  for (const [value, kind] of cases) {
    const report = verifyV2(hostile((b) => void (b["envelopes"] = value)));
    assert.deepEqual(report.failures, [`invalid_bundle: envelopes is ${kind}, not an array`], JSON.stringify(value));
    assert.equal(report.checks.envelopes, "not checked");
  }
  // null is no envelope, as before
  const report = verifyV2(hostile((b) => void (b["envelopes"] = null)));
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  assert.equal(report.checks.envelopes, "verified");
});

test("each unreadable member is reported", () => {
  const report = verifyV2(
    hostile((b) => {
      b["entries"] = "x";
      b["anchor"] = 5;
      b["envelopes"] = {};
    }),
  );
  assert.deepEqual(report.failures, [
    "invalid_bundle: entries is a string, not an array",
    "invalid_bundle: anchor is a number, not an object",
    "invalid_bundle: envelopes is an object, not an array",
  ]);
  assert.deepEqual(report.failure_entries, [null, null, null]);
});

test("field values the Python implementation hashed or compared report as they do here", () => {
  for (const [label, edit, expected] of FIELD_CASES) {
    const report = verifyBundle(parseBundle(JSON.stringify(rechained(edit))), VALID_V2_SIGNER);
    assert.deepEqual(
      report.failures.map((m, k) => [m, report.failure_details[k]!.seq, report.failure_details[k]!.node, report.failure_entries[k]]),
      expected,
      label,
    );
  }
});

test("a value RFC 8785 cannot write is a hash mismatch, never a throw", () => {
  // The parser refuses NaN, Infinity and a lone surrogate; a caller can still hand one over, and
  // no hash reproduces over it. The Python implementation, whose json reads all three, reports
  // them the same way.
  for (const value of [NaN, Infinity, String.fromCharCode(0xd800)]) {
    const bundle = validV2();
    bundle.entries[3]!["error_code"] = value as CJson;
    const report = verifyV2(bundle);
    assert.ok(report.failures.includes("integrity: hash mismatch at seq 3"), String(value));
    assert.ok(report.failures.includes("integrity(anchor): hash mismatch at seq 3"), String(value));
    assert.deepEqual(AuditLog.verify(bundle.entries), [false, "hash mismatch at seq 3"]);
  }
  const bundle = validV2();
  (bundle.anchor as unknown as Record<string, CJson>)["ts"] = NaN;
  assert.deepEqual(AuditLog.verifyAnchor(bundle.entries, bundle.anchor as unknown as Record<string, CJson>, VALID_V2_SIGNER), [
    false,
    "anchor signature invalid",
  ]);
});

test("the graph and denials skip what they cannot read", () => {
  for (const value of [null, "x", 5, true, [], ["x"]] as unknown[]) {
    assert.deepEqual(delegationGraph(value as Bundle), { chain_id: null, nodes: {}, edges: [] }, JSON.stringify(value));
    assert.deepEqual(denials(value as Bundle), []);
  }
  for (const value of ["x", 5, true, {}, { "0": {} }]) {
    const bundle = hostile((b) => void (b["entries"] = value));
    assert.deepEqual(delegationGraph(bundle), { chain_id: "vectors", nodes: {}, edges: [] }, JSON.stringify(value));
    assert.deepEqual(denials(bundle), []);
  }
  // An entry that is not an object names no node and folds into no row.
  let bundle = validV2();
  bundle.entries[5] = null as unknown as LedgerEntry; // the one deny
  assert.equal(delegationGraph(bundle).nodes["vectors:n1"]!.denies, 0);
  assert.deepEqual(denials(bundle), []);
  bundle = validV2();
  bundle.entries[1] = "x" as unknown as LedgerEntry; // the spawn: vectors:n1 is never defined
  const graph = delegationGraph(bundle);
  assert.deepEqual([Object.keys(graph.nodes).sort(), graph.edges], [["vectors:n0"], []]);
  assert.equal(denials(bundle)[0]!.agent, null);
});

test("the graph and denials read values of any kind", () => {
  let bundle = validV2();
  bundle.entries[5]!["disposition"] = ["x"];
  assert.deepEqual(delegationGraph(bundle).nodes["vectors:n1"]!.denials_by_disposition, { "['x']": 1 });
  assert.deepEqual(denials(bundle)[0]!.disposition, ["x"]);
  // Read as Python reads `disposition or reason`: an empty disposition names none.
  for (const empty of ["", 0, []]) {
    bundle = validV2();
    bundle.entries[5]!["disposition"] = empty as CJson;
    assert.deepEqual(delegationGraph(bundle).nodes["vectors:n1"]!.denials_by_disposition, { scope_not_granted: 1 }, JSON.stringify(empty));
  }
  bundle = validV2();
  const deny = bundle.entries[5]!;
  deny["node"] = { id: "n1" };
  deny["scope"] = ["a", "b"];
  deny["tool"] = { t: 1 };
  const twin = JSON.parse(JSON.stringify(deny)) as LedgerEntry;
  twin["seq"] = "z";
  bundle.entries.splice(6, 0, twin);
  assert.equal(delegationGraph(bundle).nodes["vectors:n1"]!.denies, 0);
  assert.deepEqual(
    denials(bundle).map((r) => [r.node, r.agent, r.scope, r.tool, r.count, r.first_seq, r.last_seq]),
    [[{ id: "n1" }, null, ["a", "b"], { t: 1 }, 2, 5, "z"]],
  );
  // Rows are in the order each first occurs, whatever their seqs are.
  bundle = validV2();
  const later = JSON.parse(JSON.stringify(bundle.entries[5])) as LedgerEntry;
  later["scope"] = "crm.delete";
  later["seq"] = "a";
  bundle.entries.splice(6, 0, later);
  bundle.entries[5]!["seq"] = 9;
  assert.deepEqual(denials(bundle).map((r) => r.scope), ["crm.export", "crm.delete"]);
  // A parent that is not a string names no node, so it is no edge.
  bundle = validV2();
  bundle.entries[1]!["parent"] = 5;
  assert.deepEqual(delegationGraph(bundle).edges, []);
});

test("verifyEnvelopes reports a bundle it cannot read", () => {
  assert.deepEqual(verifyEnvelopes(null as unknown as Bundle), {
    ok: false,
    status: "not checked",
    count: 0,
    witness_signed: [],
    states: {},
    results: {},
    witnesses: {},
    lines: {},
    failures: ["invalid_bundle: the bundle is null, not an object"],
    failure_details: [
      { reason: "invalid_bundle", seq: null, node: null, call_id: null, detail: "invalid_bundle: the bundle is null, not an object" },
    ],
    failure_entries: [null],
  });
  for (const [member, value, message] of [
    ["entries", 5, "invalid_bundle: entries is a number, not an array"],
    ["envelopes", "x", "invalid_bundle: envelopes is a string, not an array"],
  ] as [string, unknown, string][]) {
    const report = verifyEnvelopes(hostile((b) => void (b[member] = value)));
    assert.deepEqual([report.ok, report.failures], [false, [message]]);
  }
  assert.equal(verifyEnvelopes(hostile((b) => void (b["anchor"] = 5))).ok, true); // not read here
  const bundle = validV2();
  bundle.entries[7] = null as unknown as LedgerEntry; // an entry with no members: filed by its index
  const report = verifyEnvelopes(bundle);
  assert.equal(report.ok, true);
  assert.equal(report.states["7"], "process-asserted");
});

test("an entry whose seq is a boolean keeps its own state", () => {
  // The Python implementation's dict took `true` for 1, so two entries shared one state there;
  // both now file a seq by its JSON text.
  const bundle = rechained((es) => void (es[0]!["seq"] = true));
  for (const report of [verifyEnvelopes(bundle), verifyBundle(bundle, VALID_V2_SIGNER).envelopes]) {
    assert.equal(Object.keys(report.states).length, 9);
    assert.deepEqual([report.states["true"], report.states["1"]], ["process-asserted", "process-asserted"]);
  }
});

test("redactionReport reports what it cannot read", () => {
  for (const [value, kind] of [["x", "a string"], [null, "null"], [{}, "an object"]] as [unknown, string][]) {
    assert.deepEqual(redactionReport(value as LedgerEntry[]), {
      ok: false,
      violations: [{ event_index: null, event: null, entries: kind }],
    });
  }
  let entries = validV2().entries;
  entries[3] = ["x"] as unknown as LedgerEntry;
  entries[7] = null as unknown as LedgerEntry;
  assert.deepEqual(redactionReport(entries), {
    ok: false,
    violations: [
      { event_index: 3, event: null, entry: "an array" },
      { event_index: 7, event: null, entry: "null" },
    ],
  });
  const contexts: [unknown, unknown[]][] = [
    ["x", [{ event_index: 2, event: "allow", context: "a string" }]],
    [["rows", ["x"]], [{ event_index: 2, event: "allow", context: "an array" }]],
    [[], []],
    [null, []],
  ];
  for (const [context, violations] of contexts) {
    entries = validV2().entries;
    entries[2]!["context"] = context as CJson;
    assert.deepEqual(redactionReport(entries, ["rows"]), { ok: violations.length === 0, violations }, JSON.stringify(context));
  }
});

test("the signing helpers throw their documented Error", () => {
  const seed = Buffer.from([...Array(32).keys()]);
  const observed = { at: "t", method: "m" };
  const calls: [() => unknown, string][] = [
    [() => envelopeSubject("x" as unknown as LedgerEntry[], 1), "entries is a string, not an array"],
    [() => envelopeSubject(null as unknown as LedgerEntry[], 1), "entries is null, not an array"],
    [() => signEnvelope(5 as unknown as LedgerEntry[], 1, seed, "w", observed), "entries is a number, not an array"],
    [() => envelopeSigningInput(null as unknown as Record<string, CJson>), "an envelope is null, not an object"],
    [() => envelopeSigningInput(["x"] as unknown as Record<string, CJson>), "an envelope is an array, not an object"],
  ];
  for (const [call, message] of calls) {
    assert.throws(call, (err: Error) => err.constructor === Error && err.message === message, message);
  }
  // An entry that is not an object has no event, so v1 defines no subject for it.
  assert.throws(
    () => envelopeSubject([null, null] as unknown as LedgerEntry[], 1),
    (err: Error) => err.constructor === Error && /defines no subject for event/.test(err.message),
  );
});

test("exportBundle and anchorFor refuse entries they cannot sign, by name", () => {
  for (const [value, message] of [
    ["x", "entries is a string, not an array"],
    [null, "entries is null, not an array"],
    [[{}, null], "entries[1] is null, not an object"],
    [[{}, ["x"]], "entries[1] is an array, not an object"],
  ] as [unknown, string][]) {
    for (const call of [() => exportBundle(value as LedgerEntry[], TWIN_SIGNER), () => anchorFor(value as LedgerEntry[], TWIN_SIGNER)]) {
      assert.throws(call, (err: Error) => err instanceof TypeError && err.message === message, message);
    }
  }
});

test("AuditLog reports entries that are not an array", () => {
  const anchor = validV2().anchor as Record<string, CJson>;
  for (const [value, kind] of [[null, "null"], ["x", "a string"], [5, "a number"], [{}, "an object"]] as [unknown, string][]) {
    const expected = [false, `entries is ${kind}, not an array`];
    assert.deepEqual(AuditLog.verify(value as LedgerEntry[]), expected);
    assert.deepEqual(AuditLog.verifyAnchor(value as LedgerEntry[], anchor, VALID_V2_SIGNER), expected);
  }
  for (const value of [null, "x", 5, []] as unknown[]) {
    assert.equal(AuditLog.verifyAnchor(validV2().entries, value as Record<string, CJson>, VALID_V2_SIGNER)[0], false);
  }
});

test("stateKey and integrityBreak read an entry, or entries, of any kind", () => {
  assert.equal(stateKey(null as unknown as LedgerEntry, 7), "7");
  assert.equal(stateKey("x" as unknown as LedgerEntry, 3), "3");
  assert.equal(stateKey({ seq: [1, [2]] }, 0), "[1,[2]]");
  assert.equal(stateKey({ seq: { a: 1 } }, 0), '{"a":1}');
  assert.equal(stateKey({ seq: 4 }, 0), "4");
  assert.equal(integrityBreak("x" as unknown as LedgerEntry[]), null);
  assert.equal(integrityBreak(null as unknown as LedgerEntry[]), null);
});

test("no public reader throws on a value of any kind anywhere", () => {
  const readers: Record<string, (b: unknown) => unknown> = {
    verifyBundle: (b) => verifyBundle(b as Bundle),
    "verifyBundle(key)": (b) => verifyBundle(b as Bundle, VALID_V2_SIGNER),
    "verifyBundle(head)": (b) => verifyBundle(b as Bundle, VALID_V2_SIGNER, { expectedHead: [8, "f".repeat(64)] }),
    delegationGraph: (b) => delegationGraph(b as Bundle),
    denials: (b) => denials(b as Bundle),
    verifyEnvelopes: (b) => verifyEnvelopes(b as Bundle),
    redactionReport: (b) => redactionReport(entriesOf(b) as LedgerEntry[], ["rows"]),
    "AuditLog.verify": (b) => AuditLog.verify(entriesOf(b) as LedgerEntry[]),
    stateKey: (b) => (Array.isArray(entriesOf(b)) ? (entriesOf(b) as LedgerEntry[]) : []).map((e, i) => stateKey(e, i)),
    integrityBreak: (b) => integrityBreak(entriesOf(b) as LedgerEntry[]),
  };
  function entriesOf(b: unknown): unknown {
    return b !== null && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>)["entries"] : b;
  }
  const bundles: unknown[] = [];
  for (const value of KINDS) {
    bundles.push(value);
    for (const member of ["entries", "anchor", "envelopes", "v", "chain_id"]) {
      bundles.push(hostile((b) => void (b[member] = JSON.parse(JSON.stringify(value)))));
    }
    for (let i = 0; i < 9; i++) {
      if (value !== null && typeof value === "object" && !Array.isArray(value)) continue;
      const bundle = validV2();
      bundle.entries[i] = JSON.parse(JSON.stringify(value)) as LedgerEntry;
      bundles.push(bundle);
    }
    for (const i of [0, 1, 2, 3, 5, 7]) {
      // root, spawn, allow, outcome, deny, done
      for (const field of [...LEDGER_FIELDS].sort()) {
        bundles.push(parseBundle(JSON.stringify(rechained((es) => void (es[i]![field] = JSON.parse(JSON.stringify(value)) as CJson)))));
      }
    }
  }
  for (const bundle of bundles) {
    for (const [name, read] of Object.entries(readers)) {
      try {
        read(bundle);
      } catch (err) {
        assert.fail(`${name} threw ${(err as Error).name}: ${(err as Error).message} on ${JSON.stringify(bundle).slice(0, 200)}`);
      }
    }
  }
});
