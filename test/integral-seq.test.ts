/**
 * A `seq` or `v` is an integral number that is not a boolean, as the schema's integer type defines
 * (JSON Schema 2020-12): `1.0` is 1 and `-0` is 0, and RFC 8785 writes both as the integer, so an
 * honest envelope or anchor still verifies over them with no re-signing. A boolean, a string, and a
 * number that is fractional or not finite are not integers. A message prints an integral `seq` or
 * `v` as its integer.
 *
 * Each case mutates a committed bundle the way a producer might, re-hashes the chain where an entry
 * changed, and asserts the failures, the `seq` of each `failure_details` entry and
 * `failure_entries`. Every expected value was produced by the Python implementation from the same
 * mutation of the same bundle. A number written with a fraction or an exponent is a `RawNumber`
 * here, as the strict parser reads it from a file.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { GENESIS, hashEntry, type LedgerEntry } from "../src/audit.js";
import { RawNumber, intOr, integral, type CJson } from "../src/canonical.js";
import { verifyBundle, type Bundle, type WitnessKey } from "../src/evidence.js";
import { fixtureJson } from "./helpers.js";

interface Expected {
  failures: string[];
  seqs: (number | null)[];
  entries: (number | null)[];
}

/** The Python implementation's `verify_bundle(...)` for each mutation below. */
const PYTHON: Record<string, Expected> = {
  "bundle_v_two_float": {
    "failures": [],
    "seqs": [],
    "entries": []
  },
  "bundle_v_true": {
    "failures": [
      "unsupported_version: bundle v=True not in [1, 2]",
      "anchor_version_mismatch: anchor v=2 != bundle v=True",
      "root_version_mismatch: root v=2 != bundle v=True",
      "mixed_entry_versions: entries declare v in [2], bundle v=True"
    ],
    "seqs": [
      null,
      null,
      0,
      0
    ],
    "entries": [
      null,
      null,
      0,
      0
    ]
  },
  "bundle_v_three_float": {
    "failures": [
      "unsupported_version: bundle v=3 not in [1, 2]",
      "anchor_version_mismatch: anchor v=2 != bundle v=3",
      "root_version_mismatch: root v=2 != bundle v=3",
      "mixed_entry_versions: entries declare v in [2], bundle v=3"
    ],
    "seqs": [
      null,
      null,
      0,
      0
    ],
    "entries": [
      null,
      null,
      0,
      0
    ]
  },
  "anchor_v_two_float": {
    "failures": [],
    "seqs": [],
    "entries": []
  },
  "root_v_true": {
    "failures": [
      "root_version_mismatch: root v=True != bundle v=2",
      "mixed_entry_versions: entries declare v in [True], bundle v=2"
    ],
    "seqs": [
      0,
      0
    ],
    "entries": [
      0,
      0
    ]
  },
  "entry_versions_mixed": {
    "failures": [
      "root_version_mismatch: root v=None != bundle v=2",
      "mixed_entry_versions: entries declare v in [1.5, 3, 'x', None, True], bundle v=2"
    ],
    "seqs": [
      0,
      0
    ],
    "entries": [
      0,
      0
    ]
  },
  "bundle_v_list": {
    "failures": [
      "unsupported_version: bundle v=[2] not in [1, 2]"
    ],
    "seqs": [
      null
    ],
    "entries": [
      null
    ]
  },
  "allow_seq_two_float": {
    "failures": [
      "invalid_allow: capture is required on every v2 allow (seq 2)",
      "outcome_without_allow: call_id eb099aeb221783e1442261f15df4fb35 at seq 3 has no allow in this chain"
    ],
    "seqs": [
      2,
      3
    ],
    "entries": [
      2,
      3
    ]
  },
  "subject_seq_nine_float": {
    "failures": [
      "envelope_subject_mismatch: no entry at seq 9 in this bundle"
    ],
    "seqs": [
      9
    ],
    "entries": [
      null
    ]
  },
  "subject_seq_one_and_a_half": {
    "failures": [
      "envelope_subject_mismatch: subject seq is not an integer"
    ],
    "seqs": [
      null
    ],
    "entries": [
      null
    ]
  },
  "envelope_v_two_float": {
    "failures": [
      "envelope_unknown_version: envelope v=2 typ='delegation-event-observation', this build knows v=1 typ='delegation-event-observation'"
    ],
    "seqs": [
      1
    ],
    "entries": [
      1
    ]
  },
  "envelope_v_one_and_a_half": {
    "failures": [
      "envelope_unknown_version: envelope v=1.5 typ='delegation-event-observation', this build knows v=1 typ='delegation-event-observation'"
    ],
    "seqs": [
      1
    ],
    "entries": [
      1
    ]
  },
  "envelope_v_true": {
    "failures": [
      "envelope_unknown_version: envelope v=True typ='delegation-event-observation', this build knows v=1 typ='delegation-event-observation'"
    ],
    "seqs": [
      1
    ],
    "entries": [
      1
    ]
  },
  "envelope_v_one_float": {
    "failures": [],
    "seqs": [],
    "entries": []
  },
  "subject_seq_one_float": {
    "failures": [],
    "seqs": [],
    "entries": []
  },
  "entry_seq_one_float": {
    "failures": [],
    "seqs": [],
    "entries": []
  }
};

type Mutable = Record<string, CJson> & { entries: LedgerEntry[] };

const VALID_V2 = (fixtureJson("vectors/bundles/bundle_vectors_v1.json") as { cases: { name: string; bundle: Bundle }[] })
  .cases.find((c) => c.name === "valid_bundle_v2")!.bundle;
const ENVELOPED = (fixtureJson("vectors/envelopes/envelope_vectors_v1.json") as {
  cases: { name: string; bundle: Bundle; witness_keys: WitnessKey[] }[];
}).cases.find((c) => c.name === "valid_spawn_envelope")!;

/** A number as the strict parser reads `text` from a file: its value, with its literal kept. */
function written(text: string): RawNumber {
  return new RawNumber(text, Number(text));
}

function record(value: CJson | undefined): Record<string, CJson> {
  return value as Record<string, CJson>;
}

/** `seed` with `mutate` applied to a copy, the chain re-hashed from genesis when `rehash` is set. */
function mutated(seed: Bundle, mutate: (bundle: Mutable) => void, rehash: boolean): Bundle {
  const bundle = JSON.parse(JSON.stringify(seed)) as Mutable;
  mutate(bundle);
  if (rehash) {
    let prev = GENESIS;
    for (const e of bundle.entries) {
      e["prev_hash"] = prev;
      delete e["hash"];
      e["hash"] = hashEntry(prev, e);
      prev = e["hash"] as string;
    }
  }
  return bundle as unknown as Bundle;
}

function envelopeOf(bundle: Mutable): Record<string, CJson> {
  return record((bundle["envelopes"] as CJson[])[0]);
}

const CASES: [string, Bundle, WitnessKey[] | null][] = [
  ["bundle_v_two_float", mutated(VALID_V2, (b) => void (b["v"] = written("2.0")), false), null],
  ["bundle_v_true", mutated(VALID_V2, (b) => void (b["v"] = true), false), null],
  ["bundle_v_three_float", mutated(VALID_V2, (b) => void (b["v"] = written("3.0")), false), null],
  ["anchor_v_two_float", mutated(VALID_V2, (b) => void (record(b["anchor"])["v"] = written("2.0")), false), null],
  ["root_v_true", mutated(VALID_V2, (b) => void (b.entries[0]!["v"] = true), true), null],
  [
    "entry_versions_mixed",
    mutated(
      VALID_V2,
      (b) => {
        const es = b.entries;
        delete es[0]!["v"];
        es[1]!["v"] = "x";
        es[2]!["v"] = true;
        es[3]!["v"] = written("1.5");
        es[4]!["v"] = written("3.0");
        es[5]!["v"] = 1;
        es[6]!["v"] = true;
      },
      true,
    ),
    null,
  ],
  [
    "bundle_v_list",
    mutated(
      VALID_V2,
      (b) => {
        b["v"] = [2];
        record(b["anchor"])["v"] = [2];
        for (const e of b.entries) e["v"] = [2];
      },
      true,
    ),
    null,
  ],
  [
    "allow_seq_two_float",
    mutated(
      VALID_V2,
      (b) => {
        b.entries[2]!["seq"] = written("2.0");
        delete b.entries[2]!["capture"];
      },
      true,
    ),
    null,
  ],
  [
    "subject_seq_nine_float",
    mutated(ENVELOPED.bundle, (b) => void (record(envelopeOf(b)["subject"])["seq"] = written("9.0")), false),
    ENVELOPED.witness_keys,
  ],
  [
    "subject_seq_one_and_a_half",
    mutated(ENVELOPED.bundle, (b) => void (record(envelopeOf(b)["subject"])["seq"] = written("1.5")), false),
    ENVELOPED.witness_keys,
  ],
  ["envelope_v_two_float", mutated(ENVELOPED.bundle, (b) => void (envelopeOf(b)["v"] = written("2.0")), false), ENVELOPED.witness_keys],
  ["envelope_v_one_and_a_half", mutated(ENVELOPED.bundle, (b) => void (envelopeOf(b)["v"] = written("1.5")), false), ENVELOPED.witness_keys],
  ["envelope_v_true", mutated(ENVELOPED.bundle, (b) => void (envelopeOf(b)["v"] = true), false), ENVELOPED.witness_keys],
  ["envelope_v_one_float", mutated(ENVELOPED.bundle, (b) => void (envelopeOf(b)["v"] = written("1.0")), false), ENVELOPED.witness_keys],
  [
    "subject_seq_one_float",
    mutated(ENVELOPED.bundle, (b) => void (record(envelopeOf(b)["subject"])["seq"] = written("1.0")), false),
    ENVELOPED.witness_keys,
  ],
  ["entry_seq_one_float", mutated(ENVELOPED.bundle, (b) => void (b.entries[1]!["seq"] = written("1.0")), true), ENVELOPED.witness_keys],
];

test("every case has the Python implementation's expectation, and every expectation a case", () => {
  assert.deepEqual(CASES.map(([name]) => name).sort(), Object.keys(PYTHON).sort());
});

for (const [name, bundle, witnessKeys] of CASES) {
  test(`${name}: the failures, their seqs and their entries are the Python implementation's`, () => {
    const report = verifyBundle(bundle, null, { witnessKeys });
    const expected = PYTHON[name]!;
    assert.deepEqual(report.failures, expected.failures);
    assert.deepEqual(
      report.failure_details.map((d) => d.seq),
      expected.seqs,
    );
    assert.deepEqual(report.failure_entries, expected.entries);
  });
}

test("an entry or a subject written 1.0 is the entry at seq 1, and witness-signed", () => {
  for (const name of ["entry_seq_one_float", "subject_seq_one_float", "envelope_v_one_float"]) {
    const [, bundle, witnessKeys] = CASES.find(([n]) => n === name)!;
    const report = verifyBundle(bundle, null, { witnessKeys });
    assert.equal(report.ok, true, name);
    assert.deepEqual(report.envelopes.witnesses, { 1: "witness-interop-v1" }, name);
    assert.equal(report.envelopes.states["1"], "witness-signed", name);
  }
});

test("integral reads an integral number as that integer, and nothing else", () => {
  assert.equal(integral(written("1.0")), 1);
  assert.equal(integral(written("1e2")), 100);
  assert.equal(integral(7), 7);
  assert.ok(Object.is(integral(written("-0.0")), 0), "-0.0 is 0");
  assert.ok(Object.is(integral(written("-0")), 0), "-0 is 0");
  const others: (CJson | undefined)[] = [
    true,
    false,
    "1",
    null,
    undefined,
    written("1.5"),
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    [1],
    { v: 1 },
  ];
  for (const value of others) assert.equal(integral(value), null, String(value));
});

test("intOr gives the integer only inside the I-JSON safe range, and anything else unchanged", () => {
  assert.equal(intOr(written("2.0")), 2);
  assert.equal(intOr(written("9007199254740991.0")), 9007199254740991);
  for (const text of ["9007199254740992.0", "1e20", "-9007199254740992"]) {
    const value = written(text);
    assert.equal(intOr(value), value, text);
  }
  for (const value of [true, "1", null, undefined, written("1.5")] as (CJson | undefined)[]) {
    assert.equal(intOr(value), value, String(value));
  }
});
