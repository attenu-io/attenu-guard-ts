/**
 * CLI parity cases recorded from the PYTHON CLI (`tools/gen_fixtures.py`, `test/fixtures/parity/`).
 *
 * Each case is a `verify` run the two implementations must print identically: the stdout and the
 * exit code the Python CLI gave for the same arguments on the same files, run from inside that
 * directory so every path it prints is relative. The cases cover what a reader of one CLI must be
 * able to trust the other on: `--entries` attributing a failure to an entry whose seq is missing,
 * null, a boolean or a string; a seq or `v` written `1.0`, `2.0`, `3.0`, `9.0` or `-0.0`, which
 * both read as the integer it equals and print as one, and one written `1.5` or `true`, which
 * neither reads as an integer; an anchor `seq` or `v` past 2^53, whose signature no longer
 * verifies, and an entry carrying an integer past 2^53, a hash mismatch there; an allow scope or
 * an anchor sig that is not a string, each the existing finding; a widened child whatever its
 * parent field says, a cycle, a node defined twice, a spawn from and an allow on a revoked node, an
 * allow before its node, and nodes that are not strings, none of which may verify OK; the ungated
 * count on the summary line; versions of every type, listed in one order; two entries
 * sharing a seq with the witness's signature on the later copy, which alone reads witness-signed;
 * an envelope naming seq 1 that binds an entry whose seq is `true`, which no envelope covers; a
 * trust row past its `not_after`; a row carrying a member it does not define (`notAfter`); a kid
 * named twice; and a node name carrying line breaks, which must not add a line to either CLI's
 * output.
 *
 * The generator writes these only when the installed Python has that verifier, so CI's fixture
 * drift check compares them once its pinned release does, and until then this test holds the
 * TypeScript CLI to the recorded bytes.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

import { REPO_ROOT, fixturePath, fixtureText } from "./helpers.js";

interface Case {
  args: string[];
  stdout: string;
  exit: number;
}

const BIN = resolve(REPO_ROOT, "bin", "attenu-guard.js");
const DIR = fixturePath("parity");
const CASES = JSON.parse(fixtureText("parity/cli.json")) as Record<string, Case>;

test("the parity set covers every case the release gate names", () => {
  for (const name of [
    "bool_seq",
    "bool_seq_ledger",
    "float_seq",
    "float_seq_ledger",
    "seq_frac_ledger",
    "seq_two_ledger",
    "seq_negzero_ledger",
    "subject_seq_nine",
    "envelope_v_two",
    "bundle_v_true",
    "bundle_v_three",
    "versions_mixed",
    "anchor_seq_huge",
    "anchor_v_huge",
    "anchor_seq_int_huge",
    "anchor_int_huge_badsig",
    "entry_int_huge",
    "entry_int_huge_keyed",
    "entry_int_huge_ledger",
    "scope_int",
    "scope_null",
    "scope_bool",
    "scope_float",
    "scope_list",
    "scope_object",
    "anchor_sig_null",
    "anchor_sig_int",
    "anchor_sig_list",
    "widened_orphan",
    "widened_parent_list",
    "widened_parent_self",
    "widened_cycle",
    "node_defined_twice",
    "spawn_after_kill",
    "allow_after_kill",
    "allow_before_node",
    "root_node_list",
    "root_node_absent",
    "deny_node_int",
    "ungated",
    "ungated_entries",
    "subject_seq_float",
    "envelope_v_float",
    "string_seq",
    "seq_removed",
    "seq_null",
    "duplicate_seq_later_signed",
    "bool_seq_signed",
    "expired_row",
    "unknown_member_row",
    "duplicate_kid",
    "forged_allow",
    "forged_node_newline",
    "forged_node_newline_entries",
  ]) {
    assert.ok(name in CASES, name);
  }
});

for (const [name, c] of Object.entries(CASES)) {
  test(`${name}: the TypeScript CLI prints what the Python CLI printed`, () => {
    const r = spawnSync(process.execPath, [BIN, ...c.args], { cwd: DIR, encoding: "utf8" });
    assert.equal(r.error, undefined);
    assert.equal(r.stdout, c.stdout);
    assert.equal(r.status, c.exit);
    assert.equal(r.stderr, "");
  });
}
