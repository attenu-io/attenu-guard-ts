/**
 * CLI parity cases recorded from the PYTHON CLI (`tools/gen_fixtures.py`, `test/fixtures/parity/`).
 *
 * Each case is a `verify` run the two implementations must print identically: the stdout and the
 * exit code the Python CLI gave for the same arguments on the same files, run from inside that
 * directory so every path it prints is relative. The cases cover what a reader of one CLI must be
 * able to trust the other on: `--entries` attributing a failure to an entry whose seq is missing,
 * null, a boolean, a string or written `1.0`; a seq written `1.0` in a ledger and in an envelope
 * subject, which Python reads as a float and refuses; an envelope whose `v` is `1.0`; a trust row
 * past its `not_after`; a row carrying a member it does not define (`notAfter`); a kid named twice.
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
    "subject_seq_float",
    "envelope_v_float",
    "string_seq",
    "seq_removed",
    "seq_null",
    "expired_row",
    "unknown_member_row",
    "duplicate_kid",
    "forged_allow",
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
