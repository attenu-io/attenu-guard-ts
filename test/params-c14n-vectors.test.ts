/**
 * test/params-c14n-vectors.test.ts — consumes test/fixtures/params_c14n_v1.json, the
 * language-neutral parity vector file for params_c14n_v1 (docs/execution-binding spec section 4).
 *
 * Copied verbatim from attenu-guard (Python)'s tests/vectors/params_c14n/params_c14n_v1.json
 * (generated there by tests/vectors/params_c14n/generate_params_c14n.py, self-checked against
 * that build's attenu_guard.params.commit() by tests/test_params_c14n_vectors.py). This mirrors
 * that Python test file's structure: every case is verified against THIS build's
 * src/params.ts's commit(), so a hash produced here for the same params+salt is byte-for-byte
 * what Python produced — the "9e15 accepted / 1e16 rejected" boundary named in the build brief is
 * one case among the eleven, not a hand-picked pair, and the file is the single source of truth
 * for both runtimes rather than two independently hand-written vectors that could quietly drift
 * apart.
 *
 * No generator/drift-check test here (unlike Python's test_committed_file_matches_what_the_
 * generator_produces_now): there is no TypeScript vector generator, and none is warranted — this
 * file is a straight copy of the Python-committed vectors, consumed read-only.
 */
import assert from "node:assert/strict";
import test from "node:test";

import * as paramsMod from "../src/params.js";
import { fixtureJson } from "./helpers.js";

interface VectorCase {
  name: string;
  description: string;
  params: unknown;
  salt_hex: string;
  expect: "hash" | "unsupported";
  hash_hex?: string;
}

interface VectorFile {
  algorithm: string;
  cases: VectorCase[];
}

const data = fixtureJson<VectorFile>("params_c14n_v1.json");

test("every params_c14n_v1 vector case matches this build's commit()", () => {
  assert.equal(data.algorithm, "params_c14n_v1");
  assert.ok(data.cases.length > 0);
  for (const c of data.cases) {
    const rawSalt = paramsMod.decodeSalt(c.salt_hex);
    const [hashHex, reason] = paramsMod.commit(c.params as any, rawSalt);
    if (c.expect === "hash") {
      assert.equal(reason, null, `case ${c.name}`);
      assert.equal(hashHex, c.hash_hex, `case ${c.name}`);
    } else {
      assert.equal(hashHex, null, `case ${c.name}`);
      assert.equal(reason, paramsMod.ParamsHashReason.UNSUPPORTED, `case ${c.name}`);
    }
  }
});

test("negative zero matches positive zero in the vector file", () => {
  const byName = new Map(data.cases.map((c) => [c.name, c]));
  assert.equal(byName.get("positive_zero_accept")!.hash_hex, byName.get("negative_zero_accept")!.hash_hex);
});

test("different salts diverge for identical params in the vector file", () => {
  const byName = new Map(data.cases.map((c) => [c.name, c]));
  const a = byName.get("salt_a_accept")!;
  const b = byName.get("salt_b_accept")!;
  assert.deepEqual(a.params, b.params);
  assert.notEqual(a.salt_hex, b.salt_hex);
  assert.notEqual(a.hash_hex, b.hash_hex);
});

test("a malformed salt length is rejected", () => {
  for (const bad of ["", "ab", "gg".repeat(16), "00".repeat(15), "00".repeat(17)]) {
    assert.throws(() => paramsMod.decodeSalt(bad), `salt_hex=${JSON.stringify(bad)}`);
  }
});
