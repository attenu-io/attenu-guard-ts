/**
 * Failure strings the TypeScript verifier used to print differently from the Python one.
 *
 * Each case mutates one committed bundle the way a hostile or broken producer might, re-hashes the
 * chain so the deeper checks run, and asserts the failure list. Every expected string was produced
 * by the Python implementation from the same mutation of the same bundle: an absent `v` or `seq` is
 * Python's None, not `undefined` or `null`; a list or a member name prints as Python's repr, not as
 * JSON; and `v2_field_on_v1` uses Python's wording. Found by running both CLIs over mutated bundles.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { GENESIS, hashEntry, type LedgerEntry } from "../src/audit.js";
import { verifyBundle, type Bundle, type WitnessKey } from "../src/evidence.js";
import { fixtureJson, fixtureText } from "./helpers.js";

/** The Python implementation's `verify_bundle(...)["failures"]` for each mutation below. */
const PYTHON: Record<string, string[]> = {
  "root_without_v": [
    "root_version_mismatch: root v=None != bundle v=2",
    "mixed_entry_versions: entries declare v in [None], bundle v=2"
  ],
  "v2_field_on_v1": [
    "v2_field_on_v1: seq=3 event='allow' carries v2-only field(s) ['call_id'] on a schema_version=1 entry"
  ],
  "deny_with_capture": [
    "invalid_deny: deny carries allow-only field(s) ['capture'] (seq 5)"
  ],
  "adapter_without_module": [
    "invalid_allow: adapter['module'] must be a non-empty string (seq 2)",
    "outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain"
  ],
  "receipt_without_type": [
    "invalid_outcome: receipt['type'] must be a non-empty string (seq 3)"
  ],
  "entry_without_seq": [
    "integrity: seq gap at 1 (got None)",
    "envelope_subject_mismatch: subject entry_hash '5339c1271ede46a2b783871e7e65e4f0018e8f141f30ef760e8d3e6b0f31bb8d' != the hash recomputed for seq None from this bundle (None)"
  ],
  "authority_member_newline": [
    "root vectors:n0: unreadable authority (authority {'constraints': [{'key': 'max_rows', 'max': 100000}], 'scopes': ['crm.*', 'mail.send'], 'ttl': 3600, 'x\\nOK': 1} carries members this build does not evaluate and will not ignore: 'x\\nOK')",
    "containment: allow on unknown node vectors:n0"
  ],
  "constraint_member_newline": [
    "spawn vectors:n1: unreadable granted (constraint {'key': 'max_rows', 'max': 5000, 'y\\nOK': 1} carries members this build does not evaluate and will not ignore: 'y\\nOK')",
    "containment: allow on unknown node vectors:n1"
  ],
  "authority_scope_u2028": [
    "root vectors:n0: unreadable authority (invalid scope 'crm.\\u2028x': expected lowercase dot-separated segments; '*' is permitted only as the complete final segment after a dot)",
    "containment: allow on unknown node vectors:n0"
  ],
  "constraint_dimension_rewritten": [
    "spawn vectors:n1: unreadable granted (constraint {'key': 'max_calls', 'max': 5, 'applies_to': 'fs.write\\x85\\x1b[2K'} names dimension 'max_calls' but this build reads it as 'max_calls[fs.write\\x85\\x1b[2K]'; refusing rather than silently changing which dimension is bounded)",
    "containment: allow on unknown node vectors:n1"
  ]
};

const VALID_V2 = (fixtureJson("vectors/bundles/bundle_vectors_v1.json") as { cases: { name: string; bundle: Bundle }[] })
  .cases.find((c) => c.name === "valid_bundle_v2")!.bundle;
const CLEAN_V1 = JSON.parse(fixtureText("clean_hs256.bundle.json")) as Bundle;
const ENVELOPED = (fixtureJson("vectors/envelopes/envelope_vectors_v1.json") as {
  cases: { name: string; bundle: Bundle; witness_keys: WitnessKey[] }[];
}).cases.find((c) => c.name === "valid_spawn_envelope")!;

/** `seed` with `mutate` applied to a copy of its entries and the chain re-hashed from genesis. */
function mutated(seed: Bundle, mutate: (entries: LedgerEntry[]) => void): Bundle {
  const bundle = JSON.parse(JSON.stringify(seed)) as Bundle;
  mutate(bundle.entries);
  let prev = GENESIS;
  for (const e of bundle.entries) {
    e["prev_hash"] = prev;
    delete e["hash"];
    e["hash"] = hashEntry(prev, e);
    prev = e["hash"] as string;
  }
  return bundle;
}

function authorityOf(entry: LedgerEntry, member: "authority" | "granted"): Record<string, unknown> {
  return entry[member] as unknown as Record<string, unknown>;
}

function first(entries: LedgerEntry[], event: string): LedgerEntry {
  return entries.find((e) => e["event"] === event)!;
}

const CASES: [string, Bundle, WitnessKey[] | null][] = [
  ["root_without_v", mutated(VALID_V2, (es) => void delete es[0]!["v"]), null],
  ["v2_field_on_v1", mutated(CLEAN_V1, (es) => void (es[3]!["call_id"] = "x")), null],
  ["deny_with_capture", mutated(VALID_V2, (es) => void (first(es, "deny")["capture"] = "pre_hook_only")), null],
  [
    "adapter_without_module",
    mutated(VALID_V2, (es) => void ((first(es, "allow")["adapter"] as Record<string, string>)["module"] = "")),
    null,
  ],
  [
    "receipt_without_type",
    mutated(VALID_V2, (es) => void (first(es, "outcome")["receipt"] = { type: "", ref: "r", digest: "0".repeat(64) })),
    null,
  ],
  ["entry_without_seq", mutated(ENVELOPED.bundle, (es) => void delete es[1]!["seq"]), ENVELOPED.witness_keys],
  // The messages inside "unreadable authority (...)" carry the bundle's member names, scopes and
  // values. Python prints them through repr; JSON spelling here left U+2028, DEL and C1 characters
  // raw, and a member name joined bare could end the line.
  ["authority_member_newline", mutated(VALID_V2, (es) => void (authorityOf(es[0]!, "authority")["x\nOK"] = 1)), null],
  [
    "constraint_member_newline",
    mutated(VALID_V2, (es) => void ((authorityOf(es[1]!, "granted")["constraints"] as Record<string, unknown>[])[0]!["y\nOK"] = 1)),
    null,
  ],
  [
    "authority_scope_u2028",
    mutated(VALID_V2, (es) => void ((authorityOf(es[0]!, "authority")["scopes"] as string[])[0] = "crm.\u2028x")),
    null,
  ],
  [
    "constraint_dimension_rewritten",
    mutated(VALID_V2, (es) =>
      void (authorityOf(es[1]!, "granted")["constraints"] as unknown[]).push({
        key: "max_calls",
        max: 5,
        applies_to: "fs.write\u0085\u001b[2K",
      }),
    ),
    null,
  ],
];

for (const [name, bundle, witnessKeys] of CASES) {
  test(`${name}: the failure strings are the Python implementation's`, () => {
    assert.deepEqual(verifyBundle(bundle, null, { witnessKeys }).failures, PYTHON[name]);
  });
}
