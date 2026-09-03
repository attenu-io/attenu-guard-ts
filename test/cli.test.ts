/**
 * The `attenu-guard verify` command. Its output lines and exit codes must match
 * the Python CLI's for the same file, so either implementation can stand in for
 * the other in a script.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import test from "node:test";
import { join, resolve } from "node:path";

import { META, REPO_ROOT, fixturePath, fixtureText } from "./helpers.js";

const BIN = resolve(REPO_ROOT, "bin", "attenu-guard.js");

function run(args: string[]): { stdout: string; status: number } {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined);
  return { stdout: r.stdout, status: r.status ?? -1 };
}

function keyArgs(name: string): string[] {
  return name.includes("ed25519")
    ? ["--pubkey", META.ed25519_public_hex]
    : ["--hs256-key", META.hs256_secret_hex];
}

for (const [name, expected] of Object.entries(META.cli)) {
  test(`verify ${name}.bundle.json with the key matches the Python CLI`, () => {
    const file = fixturePath(`${name}.bundle.json`);
    const { stdout, status } = run(["verify", file, ...keyArgs(name)]);
    const lines = stdout.trimEnd().split("\n");
    assert.equal(lines[0], expected.with_key.line);
    assert.equal(lines.at(-1), expected.with_key.status);
    assert.equal(status, expected.with_key.exit);
  });

  test(`verify ${name}.bundle.json without a key matches the Python CLI`, () => {
    const file = fixturePath(`${name}.bundle.json`);
    const { stdout, status } = run(["verify", file]);
    const lines = stdout.trimEnd().split("\n");
    assert.equal(lines[0], expected.without_key.line);
    assert.equal(lines.at(-1), expected.without_key.status);
    assert.equal(status, expected.without_key.exit);
  });
}

test("verify prints the failure lines a bundle earned", () => {
  const { stdout } = run([
    "verify",
    fixturePath("widened_hs256.bundle.json"),
    "--hs256-key",
    META.hs256_secret_hex,
  ]);
  assert.match(stdout, /monotonicity: n1 not ⊆ parent n0/);
  assert.match(stdout, /^ {2}- /m);
});

test("verify checks a plain .jsonl ledger", () => {
  const { stdout, status } = run(["verify", fixturePath("ledger.jsonl")]);
  assert.equal(stdout.trimEnd(), META.ledger.cli_status);
  assert.equal(status, 0);
});

test("a tampered ledger exits 2 and names the break", () => {
  const { stdout, status } = run(["verify", fixturePath("tampered_ledger.jsonl")]);
  assert.match(stdout, /^TAMPERED — hash mismatch at seq \d+$/m);
  assert.equal(status, 2);
});

test("no arguments prints usage and exits 1", () => {
  const bare = run([]);
  assert.match(bare.stdout, /attenu-guard verify/);
  assert.equal(bare.status, 1);
  const unknown = run(["frobnicate", "x"]);
  assert.equal(unknown.status, 1);
});

test("--help, -h and verify --help print usage and exit 0", () => {
  for (const args of [["--help"], ["-h"], ["verify", "--help"]]) {
    const { stdout, status } = run(args);
    assert.match(stdout, /attenu-guard verify/);
    assert.equal(status, 0, `${JSON.stringify(args)} exited ${status}`);
  }
});

// ---- observer envelopes: --witness-keys -----------------------------------------------------

/**
 * A one-envelope bundle and the trust set for it, written into a fresh temp directory. Built
 * from the vendored vector corpus, so the bundle here is the same one every implementation
 * scores rather than a shape invented for this test.
 */
function envelopeBundleFiles(): { dir: string; bundle: string; keys: string; caseFile: string } {
  const doc = JSON.parse(fixtureText("vectors/envelopes/envelope_vectors_v1.json")) as {
    cases: { name: string; bundle: unknown; witness_keys: unknown }[];
  };
  const c = doc.cases.find((x) => x.name === "valid_spawn_envelope")!;
  const dir = mkdtempSync(join(tmpdir(), "attenu-cli-"));
  const bundle = join(dir, "envelopes.bundle.json");
  const keys = join(dir, "witness_keys.json");
  const caseFile = join(dir, "case.json");
  writeFileSync(bundle, JSON.stringify(c.bundle));
  writeFileSync(keys, JSON.stringify(c.witness_keys));
  writeFileSync(caseFile, JSON.stringify(c));
  return { dir, bundle, keys, caseFile };
}

test("a bundle with envelopes verifies when the trust set is given", () => {
  const files = envelopeBundleFiles();
  try {
    const { stdout, status } = run(["verify", files.bundle, "--witness-keys", files.keys]);
    assert.equal(status, 0, stdout);
    assert.equal(stdout.trimEnd().split("\n").at(-1), "OK");
    assert.doesNotMatch(stdout, /hint:/);
  } finally {
    rmSync(files.dir, { recursive: true, force: true });
  }
});

test("a bundle with envelopes and no trust set fails and names the flag", () => {
  // The defect: every bundle carrying an envelope failed here with no way to pass keys. The
  // failure is still correct — an unknown key is not a trusted one — so it stands, and the
  // output says which flag makes the run meaningful.
  const files = envelopeBundleFiles();
  try {
    const { stdout, status } = run(["verify", files.bundle]);
    assert.equal(status, 2);
    assert.match(stdout, /envelope_unknown_witness/);
    assert.match(stdout, /^hint: pass --witness-keys FILE to supply the trusted witness keys$/m);
    assert.equal(stdout.trimEnd().split("\n").at(-1), "FAILED");
  } finally {
    rmSync(files.dir, { recursive: true, force: true });
  }
});

test("no hint on a bundle that carries no envelopes", () => {
  const { stdout, status } = run(["verify", fixturePath("clean_hs256.bundle.json")]);
  assert.equal(status, 0);
  assert.doesNotMatch(stdout, /hint:/);
});

test("the trust set may be given as a whole vector case", () => {
  const files = envelopeBundleFiles();
  try {
    const { stdout, status } = run(["verify", files.bundle, "--witness-keys", files.caseFile]);
    assert.equal(status, 0, stdout);
  } finally {
    rmSync(files.dir, { recursive: true, force: true });
  }
});
