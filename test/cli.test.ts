/**
 * The `attenu-guard verify` command. Its output lines and exit codes must match
 * the Python CLI's for the same file, so either implementation can stand in for
 * the other in a script.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import test from "node:test";
import { join, resolve } from "node:path";

import { AuditLog, hashEntry, type LedgerEntry } from "../src/audit.js";
import { Authority } from "../src/authority.js";
import { Allow } from "../src/ceilings.js";
import { exportBundle, parseBundle, signEnvelope, verifyBundle, type Bundle, type WitnessKey } from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { Ed25519Signer, HS256TestSigner } from "../src/wire.js";
import { META, REPO_ROOT, fixturePath, fixtureText } from "./helpers.js";

const BIN = resolve(REPO_ROOT, "bin", "attenu-guard.js");

function run(args: string[]): { stdout: string; status: number; stderr: string } {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined);
  return { stdout: r.stdout, status: r.status ?? -1, stderr: r.stderr };
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

test("--help lists --entries in the Python CLI's words", () => {
  const { stdout } = run(["--help"]);
  assert.match(stdout, /\[--witness-keys FILE\] \[--entries\]/);
  for (const line of [
    "--entries adds one line per entry: its envelope state and the checks that failed on it;",
    'a line is key=value tokens split by single spaces, the key before the first "=",',
    'and a value never contains a space; one that starts with " is a JSON string)',
  ]) {
    assert.ok(stdout.includes(line), line);
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

// A ledger with no entries has nothing to verify; reporting it OK would be a fail-open. The
// line and the exit code match the Python CLI's for the same file.
for (const [label, content] of [
  ["a 0-byte ledger", ""],
  ["a blank-lines-only ledger", "\n\n  \n"],
] as const) {
  test(`verify on ${label} prints EMPTY and exits 2, like the Python CLI`, () => {
    const dir = mkdtempSync(join(tmpdir(), "attenu-empty-"));
    try {
      const file = join(dir, "log.jsonl");
      writeFileSync(file, content);
      const { stdout, status } = run(["verify", file]);
      assert.equal(stdout, "EMPTY — no events to verify\n");
      assert.equal(status, 2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test("verify on a bundle with zero entries fails (missing_root)", () => {
  const bundle = JSON.parse(fixtureText("clean_hs256.bundle.json")) as Record<string, unknown>;
  bundle["entries"] = [];
  const dir = mkdtempSync(join(tmpdir(), "attenu-empty-bundle-"));
  try {
    const file = join(dir, "empty.bundle.json");
    writeFileSync(file, JSON.stringify(bundle));
    const { stdout, status } = run(["verify", file]);
    assert.match(stdout, /missing_root/);
    assert.equal(stdout.trimEnd().split("\n").at(-1), "FAILED");
    assert.equal(status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- --entries: one line per ledger entry (attenu-io/attenu-guard#23) --------------------------

/** The test witness's Ed25519 seed. Fixed, so every run signs the same bytes. */
const WITNESS_SEED = Buffer.alloc(32, 7);
const WITNESS_KID = "witness-custody";
const WITNESS_PUBLIC_HEX = Ed25519Signer.fromPrivateBytes(WITNESS_SEED, WITNESS_KID)
  .publicBytesRaw()
  .toString("hex");
const ANCHOR = new HS256TestSigner(Buffer.from(META.hs256_secret_hex, "hex"), META.hs256_kid);

/**
 * The shape of the separated-custody run of 2026-09-30: a supervisor delegates `docs.write` to a
 * brief-writer, which is then allowed `docs.write` and denied `web.search`. The ledger is v1 with
 * a logical clock, so its bytes, and every line printed from it, are the same on every run.
 */
function custodyRun(chainId = "custody"): LedgerEntry[] {
  const root = Guard.issue(
    "supervisor",
    new Authority({ scopes: ["docs.write", "web.search"], ttl: 3600 }),
    { chainId },
  );
  const writer = root.delegate("brief-writer", new Authority({ scopes: ["docs.write"], ttl: 600 }), "write the brief");
  assert.ok(writer.check("docs.write", { tool: "docs" }).allowed);
  assert.ok(!writer.check("web.search", { tool: "search" }).allowed);
  return root.auditLog().entries.map((e) => ({ ...e }));
}

/**
 * That run's boundary case: the process appends an allow for the scope it was just denied, in
 * chain order (prev_hash on the real head, hash recomputed), and the witness signs it because it
 * arrives in order. The chain, the anchor and the envelope all verify. Containment is the check
 * that catches it.
 */
function withForgedAllow(entries: LedgerEntry[]): LedgerEntry[] {
  const head = entries[entries.length - 1]!;
  const template = entries.find((e) => e["event"] === "allow")!;
  const forged: LedgerEntry = {
    ...template,
    seq: entries.length,
    ts: entries.length + 1,
    scope: "web.search",
    tool: "search",
    prev_hash: head["hash"]!,
  };
  delete forged["hash"];
  forged["hash"] = hashEntry(head["hash"] as string, forged);
  return [...entries, forged];
}

/** An anchored bundle with a witness envelope over each of `signed`. */
function writeBundle(dir: string, name: string, entries: LedgerEntry[], signed: number[]): string {
  const envelopes = signed.map((seq) =>
    signEnvelope(entries, seq, WITNESS_SEED, WITNESS_KID, {
      result: "indeterminate",
      at: "2026-09-30T12:00:00Z",
      method: "ledger-tail",
    }),
  );
  const file = join(dir, name);
  writeFileSync(file, JSON.stringify(exportBundle(entries, ANCHOR, { envelopes }), null, 1));
  return file;
}

/** A `--witness-keys` file trusting the test witness, with `not_after` on its row when given. */
function writeWitnessKeys(dir: string, notAfter?: string): string {
  const row: Record<string, string> = { kid: WITNESS_KID, alg: "EdDSA", public_key_hex: WITNESS_PUBLIC_HEX };
  if (notAfter !== undefined) row["not_after"] = notAfter;
  const file = join(dir, `witness_keys${notAfter === undefined ? "" : "_not_after"}.json`);
  writeFileSync(file, JSON.stringify([row]));
  return file;
}

function inTempDir(body: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "attenu-entries-"));
  try {
    body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("--entries lists every entry of a witness-signed bundle with its state", () => {
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "clean.bundle.json", custodyRun(), [1, 2]);
    const keys = writeWitnessKeys(dir);
    const { stdout, status } = run([
      "verify", bundle, "--hs256-key", META.hs256_secret_hex, "--witness-keys", keys, "--entries",
    ]);
    assert.equal(
      stdout,
      [
        "integrity=True monotonicity=True containment=True anchor=verified nodes=2 actions_checked=1",
        "OK",
        "entries:",
        "  seq=0 event=root node=custody:n0 state=process-asserted",
        "  seq=1 event=spawn node=custody:n1 state=witness-signed observed=indeterminate witness=witness-custody",
        "  seq=2 event=allow node=custody:n1 scope=docs.write state=witness-signed observed=indeterminate witness=witness-custody",
        "  seq=3 event=deny node=custody:n1 scope=web.search state=process-asserted",
        "",
      ].join("\n"),
    );
    assert.equal(status, 0);
  });
});

test("a forged allow appended in chain order is witness-signed, and fails containment on that entry only", () => {
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "forged.bundle.json", withForgedAllow(custodyRun()), [1, 2, 4]);
    const keys = writeWitnessKeys(dir);
    const { stdout, status } = run([
      "verify", bundle, "--hs256-key", META.hs256_secret_hex, "--witness-keys", keys, "--entries",
    ]);
    assert.equal(
      stdout,
      [
        "integrity=True monotonicity=True containment=False anchor=verified nodes=2 actions_checked=2",
        "  - containment: allow of 'web.search' on custody:n1 outside its authority ['docs.write']",
        "FAILED",
        "entries:",
        "  seq=0 event=root node=custody:n0 state=process-asserted",
        "  seq=1 event=spawn node=custody:n1 state=witness-signed observed=indeterminate witness=witness-custody",
        "  seq=2 event=allow node=custody:n1 scope=docs.write state=witness-signed observed=indeterminate witness=witness-custody",
        "  seq=3 event=deny node=custody:n1 scope=web.search state=process-asserted",
        "  seq=4 event=allow node=custody:n1 scope=web.search state=witness-signed observed=indeterminate witness=witness-custody failed=containment",
        "",
      ].join("\n"),
    );
    assert.equal(stdout.match(/failed=/g)?.length, 1, "containment lands on the forged entry and nowhere else");
    assert.equal(status, 2);
  });
});

test("--entries names every check that failed on an entry, and leaves a chain-level finding out", () => {
  // No --witness-keys: both envelopes fail envelope_unknown_witness, each at the entry it covers.
  // The wrong anchor key fails integrity(anchor), which commits to the whole ledger and carries
  // no seq: it stays in the bundle-level output and lands on no entry.
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "forged.bundle.json", withForgedAllow(custodyRun()), [2, 4]);
    const { stdout, status } = run(["verify", bundle, "--hs256-key", "00".repeat(32), "--entries"]);
    assert.match(stdout, /^ {2}- integrity\(anchor\): anchor signature invalid$/m);
    const listed = stdout.slice(stdout.indexOf("entries:\n"));
    assert.equal(
      listed,
      [
        "entries:",
        "  seq=0 event=root node=custody:n0 state=process-asserted",
        "  seq=1 event=spawn node=custody:n1 state=process-asserted",
        "  seq=2 event=allow node=custody:n1 scope=docs.write state=process-asserted failed=envelope_unknown_witness",
        "  seq=3 event=deny node=custody:n1 scope=web.search state=process-asserted",
        "  seq=4 event=allow node=custody:n1 scope=web.search state=process-asserted failed=containment,envelope_unknown_witness",
        "",
      ].join("\n"),
    );
    assert.equal(status, 2);
  });
});

test("--entries on a plain ledger prints seq, event, node and scope, and no envelope state", () => {
  const { stdout, status } = run(["verify", fixturePath("ledger.jsonl"), "--entries"]);
  assert.equal(
    stdout,
    [
      "OK",
      "entries:",
      "  seq=0 event=root node=fixtures:n0",
      "  seq=1 event=spawn node=fixtures:n1",
      "  seq=2 event=spawn node=fixtures:n2",
      "  seq=3 event=allow node=fixtures:n1 scope=crm.read",
      "  seq=4 event=allow node=fixtures:n2 scope=crm.read",
      "  seq=5 event=deny node=fixtures:n2 scope=crm.read",
      "  seq=6 event=deny node=fixtures:n1 scope=crm.export",
      "  seq=7 event=done node=fixtures:n2",
      "  seq=8 event=kill",
      "",
    ].join("\n"),
  );
  assert.equal(status, 0);
});

test("--entries on a tampered ledger marks the entry the chain breaks at", () => {
  const { stdout, status } = run(["verify", fixturePath("tampered_ledger.jsonl"), "--entries"]);
  const lines = stdout.trimEnd().split("\n");
  assert.equal(lines[0], "TAMPERED — hash mismatch at seq 5");
  assert.deepEqual(
    lines.filter((line) => line.includes("failed=")),
    ["  seq=5 event=allow node=fixtures:n2 scope=crm.read failed=integrity"],
  );
  assert.equal(lines.length, 2 + 9);
  assert.equal(status, 2);
});

test("--entries prints a value that could forge a line as escaped JSON, never as it is", () => {
  // A ledger is attacker-supplied. Printed as it is, this `scope` would end its own line and print
  // a clean-looking `seq=9` after it. A value is printed bare only when it is printable ASCII with
  // no space, `"` or `\`; anything else is compact JSON with non-ASCII escaped and spaces as
  // \u0020, so it never contains whitespace. The rule and the bytes are the Python CLI's.
  inTempDir((dir) => {
    const file = join(dir, "hostile.jsonl");
    const rows = [
      '{"seq":0,"event":"root","node":"n0"}',
      '{"seq":1,"event":"allow","node":"n 1","scope":"crm.read\\n  seq=9 event=allow node=n0 scope=x"}',
      '{"seq":2,"event":"allow","node":"n0","scope":"r\u00e9sum\u00e9 \ud83d\ude00"}',
      '{"seq":3.0,"event":"deny","node":"n0","scope":"say \\"hi\\" \\\\ bye"}',
      '{"seq":4,"event":true,"node":["a",1,null],"scope":{"k":"v w"}}',
      '{"seq":5,"event":"allow","node":"","scope":"a=b,c"}',
    ];
    writeFileSync(file, `${rows.join("\n")}\n`);
    const { stdout } = run(["verify", file, "--entries"]);
    assert.deepEqual(stdout.split("\n").slice(1), [
      "entries:",
      "  seq=0 event=root node=n0 failed=integrity",
      String.raw`  seq=1 event=allow node="n\u00201" scope="crm.read\n\u0020\u0020seq=9\u0020event=allow\u0020node=n0\u0020scope=x"`,
      String.raw`  seq=2 event=allow node=n0 scope="r\u00e9sum\u00e9\u0020\ud83d\ude00"`,
      String.raw`  seq=3.0 event=deny node=n0 scope="say\u0020\"hi\"\u0020\\\u0020bye"`,
      String.raw`  seq=4 event=true node=["a",1,null] scope={"k":"v\u0020w"}`,
      `  seq=5 event=allow node="" scope=a=b,c`,
      "",
    ]);
    assert.equal(stdout.split("\n").filter((line) => line.startsWith("  seq=")).length, 6, "six entries, six lines");
  });
});

test("--entries on an empty ledger prints the header and no entry lines", () => {
  inTempDir((dir) => {
    const file = join(dir, "log.jsonl");
    writeFileSync(file, "");
    const { stdout, status } = run(["verify", file, "--entries"]);
    assert.equal(stdout, "EMPTY — no events to verify\nentries:\n");
    assert.equal(status, 2);
  });
});

test("--entries only appends: without it the output is unchanged, and the exit code never moves", () => {
  inTempDir((dir) => {
    const clean = writeBundle(dir, "clean.bundle.json", custodyRun(), [1, 2]);
    const forged = writeBundle(dir, "forged.bundle.json", withForgedAllow(custodyRun()), [1, 2, 4]);
    const keys = writeWitnessKeys(dir);
    const cases: string[][] = [
      [clean, "--witness-keys", keys],
      [forged, "--hs256-key", META.hs256_secret_hex, "--witness-keys", keys],
      [forged],
      [fixturePath("ledger.jsonl")],
      [fixturePath("tampered_ledger.jsonl")],
      ...Object.keys(META.cli).flatMap((name) => [
        [fixturePath(`${name}.bundle.json`)],
        [fixturePath(`${name}.bundle.json`), ...keyArgs(name)],
      ]),
    ];
    for (const args of cases) {
      const plain = run(["verify", ...args]);
      const listed = run(["verify", ...args, "--entries"]);
      const flagFirst = run(["verify", "--entries", ...args]);
      assert.ok(listed.stdout.startsWith(plain.stdout), `${args.join(" ")}: the output without --entries is a prefix`);
      assert.match(listed.stdout.slice(plain.stdout.length), /^entries:\n/);
      assert.equal(listed.status, plain.status, `${args.join(" ")}: the exit code is unchanged`);
      assert.equal(flagFirst.stdout, listed.stdout, "the flag may come before the path");
    }
  });
});

// ---- not_after on a --witness-keys row (attenu-io/attenu-guard#22) -----------------------------

test("verify honours not_after on a --witness-keys row", () => {
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "clean.bundle.json", custodyRun(), [1, 2]);

    const current = run(["verify", bundle, "--witness-keys", writeWitnessKeys(dir, "9999-12-31T23:59:59Z")]);
    assert.equal(current.stdout.trimEnd().split("\n").at(-1), "OK");
    assert.equal(current.status, 0);

    const expired = run(["verify", bundle, "--witness-keys", writeWitnessKeys(dir, "2000-01-01T00:00:00Z"), "--entries"]);
    const line =
      "  - envelope_unknown_witness: witness kid='witness-custody' alg='EdDSA' is not in the trusted " +
      "witness keys ([]): the key expired at not_after='2000-01-01T00:00:00Z'";
    assert.deepEqual(
      expired.stdout.split("\n").filter((l) => l.startsWith("  - ")),
      [line, line],
    );
    assert.doesNotMatch(expired.stdout, /hint:/, "a trust set was given; it is the row that expired");
    assert.match(expired.stdout, /^ {2}seq=1 event=spawn node=custody:n1 state=process-asserted failed=envelope_unknown_witness$/m);
    assert.equal(expired.status, 2);
  });
});

// ---- a bundle value cannot add a line to the default output ----------------------------------

test("a forged node name cannot add a line to the default output", () => {
  // Printed raw, this node name turns the containment finding into three lines, the middle one
  // reading `OK`, above the real FAILED. The Python CLI prints the same three lines.
  inTempDir((dir) => {
    const chainId = "run\nOK\nx";
    const bundle = writeBundle(dir, "forged.bundle.json", withForgedAllow(custodyRun(chainId)), [1, 2, 4]);
    const args = ["verify", bundle, "--hs256-key", META.hs256_secret_hex, "--witness-keys", writeWitnessKeys(dir)];
    const { stdout, status } = run(args);
    assert.equal(status, 2);
    assert.deepEqual(stdout.split("\n"), [
      "integrity=True monotonicity=True containment=False anchor=verified nodes=2 actions_checked=2",
      String.raw`  - containment: allow of 'web.search' on "run\nOK\nx:n1" outside its authority ['docs.write']`,
      "FAILED",
      "",
    ]);
    const token = stdout.split("\n")[1]!.split(" on ")[1]!.split(" outside")[0]!;
    assert.equal(JSON.parse(token), `${chainId}:n1`, "the escaped form reads back as the node");
    // --entries adds exactly the header and one line per entry, nothing more.
    assert.equal(run([...args, "--entries"]).stdout.trimEnd().split("\n").length, 3 + 1 + 5);
  });
});

test("a ceiling value cannot add a line to a monotonicity finding", () => {
  // A spawn the process wrote itself, granting a looser region allow-list than the parent holds,
  // with one region carrying a line break. The ceiling description prints it.
  inTempDir((dir) => {
    const root = Guard.issue(
      "root",
      new Authority({ scopes: ["docs.write"], ceilings: [new Allow("region", ["us"])] }),
      { chainId: "mono" },
    );
    const ledger = root.auditLog();
    const wider = new Authority({ scopes: ["docs.write"], ceilings: [new Allow("region", ["us", "eu\nOK"])] });
    ledger.append("spawn", 1, {
      chain_id: "mono",
      node: "mono:n1",
      parent: ledger.entries[0]!["node"]!,
      agent: "child",
      task: "t",
      granted: wider.toWire() as never,
    });
    const signer = new HS256TestSigner(Buffer.from("mono"), "mono");
    const file = join(dir, "mono.bundle.json");
    writeFileSync(file, JSON.stringify(exportBundle(ledger, signer)));
    const { stdout, status } = run(["verify", file, "--hs256-key", Buffer.from("mono").toString("hex")]);
    assert.equal(status, 2);
    assert.deepEqual(stdout.split("\n"), [
      "integrity=True monotonicity=False containment=True anchor=verified nodes=2 actions_checked=0",
      String.raw`  - monotonicity: mono:n1 not ⊆ parent mono:n0 (ceiling region in ["eu\nOK", us] looser than parent region in [us])`,
      "FAILED",
      "",
    ]);
  });
});

test("a forged seq cannot add a line to a plain ledger's verdict", () => {
  inTempDir((dir) => {
    const file = join(dir, "l.jsonl");
    Guard.issue("a", new Authority({ scopes: ["x.read"] }), { auditPath: file });
    const rows = readFileSync(file, "utf8").trimEnd().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    rows[0]!["seq"] = "0\nOK";
    writeFileSync(file, rows.map((r) => `${JSON.stringify(r)}\n`).join(""));
    const { stdout, status } = run(["verify", file]);
    assert.equal(stdout, String.raw`TAMPERED — seq gap at 0 (got "0\nOK")` + "\n");
    assert.equal(status, 2);
  });
});

// ---- --entries reads a state only for the entry it belongs to -----------------------------------

test("--entries never shows a forged string seq as witness-signed", () => {
  // The verifier keys its per-entry record by the seq rendered as text, so "1" shared a key with
  // seq 1 and printed that entry's witness, and "__proto__" printed `state={}`. An envelope subject's
  // seq is an integer, so an entry whose seq is not a number is process-asserted by construction.
  const doc = JSON.parse(fixtureText("vectors/envelopes/envelope_vectors_v1.json")) as {
    cases: { name: string; bundle: { entries: LedgerEntry[] }; witness_keys: unknown }[];
  };
  const c = doc.cases.find((x) => x.name === "valid_spawn_envelope")!;
  const entries = c.bundle.entries.map((e) => ({ ...e }));
  for (const seq of ["1", "__proto__"]) {
    const head = entries[entries.length - 1]!;
    const forged: LedgerEntry = { ...entries[1]!, seq, node: "vectors:evil", prev_hash: head["hash"]! };
    delete forged["hash"];
    forged["hash"] = hashEntry(head["hash"] as string, forged);
    entries.push(forged);
  }
  inTempDir((dir) => {
    const bundle = join(dir, "forged.bundle.json");
    const keys = join(dir, "keys.json");
    writeFileSync(bundle, JSON.stringify({ ...c.bundle, entries }));
    writeFileSync(keys, JSON.stringify(c.witness_keys));
    const { stdout } = run(["verify", bundle, "--witness-keys", keys, "--entries"]);
    const lines = stdout.split("\n");
    assert.ok(lines.includes("  seq=1 event=spawn node=vectors:n1 state=witness-signed observed=matched witness=witness-interop-v1"), stdout);
    assert.ok(lines.includes("  seq=1 event=spawn node=vectors:evil state=process-asserted failed=integrity"), stdout);
    assert.ok(lines.includes("  seq=__proto__ event=spawn node=vectors:evil state=process-asserted"), stdout);
    assert.doesNotMatch(stdout, /state=\{\}/);
    assert.equal(lines.filter((l) => l.includes("witness=")).length, 1, "only the real seq 1 is witness-signed");
  });
});

// ---- --entries attributes a failure to its entry by index, never by seq ---------------------------

/** The forged-allow bundle with `edit` applied to its entries, re-hashed, the anchor dropped. */
function forgedWith(edit: (entries: LedgerEntry[]) => void): Record<string, unknown> {
  const entries = withForgedAllow(custodyRun());
  const envelopes = [1, 2, 4].map((seq) =>
    signEnvelope(entries, seq, WITNESS_SEED, WITNESS_KID, {
      result: "indeterminate",
      at: "2026-09-30T12:00:00Z",
      method: "ledger-tail",
    }),
  );
  const bundle = exportBundle(entries, ANCHOR, { envelopes }) as unknown as Record<string, unknown>;
  const edited = (bundle["entries"] as LedgerEntry[]).map((e) => ({ ...e }));
  edit(edited);
  rehash(edited);
  bundle["entries"] = edited;
  delete bundle["anchor"];
  return bundle;
}

function rehash(entries: LedgerEntry[]): void {
  let prev = "0".repeat(64);
  for (const e of entries) {
    e["prev_hash"] = prev;
    delete e["hash"];
    e["hash"] = hashEntry(prev, e);
    prev = e["hash"] as string;
  }
}

/** `verify --entries` on `bundle`, trusting the test witness: exit code, stdout, entry lines. */
function entriesOf(dir: string, bundle: unknown): { status: number; stdout: string; lines: string[] } {
  const file = join(dir, "bundle.json");
  writeFileSync(file, JSON.stringify(bundle));
  const { stdout, status } = run(["verify", file, "--witness-keys", writeWitnessKeys(dir), "--entries"]);
  return { status, stdout, lines: stdout.split("entries:\n")[1]!.trimEnd().split("\n") };
}

test("an entry without a seq prints seq=null and keeps its failures", () => {
  // Findings about this entry carried no seq, were taken for chain-level ones, and the forged
  // allow printed a clean line under a FAILED verdict.
  const variants: [string, (es: LedgerEntry[]) => void, string][] = [
    // The envelope over seq 4 still finds this entry (its index stands in for the missing seq),
    // and its entry_hash no longer matches.
    ["seq removed", (es) => void delete es[4]!["seq"], "integrity,containment,envelope_subject_mismatch"],
    // A null seq finds nothing, so that envelope failure is about no entry.
    ["seq null", (es) => void (es[4]!["seq"] = null), "integrity,containment"],
  ];
  inTempDir((dir) => {
    for (const [label, edit, failed] of variants) {
      const { status, stdout, lines } = entriesOf(dir, forgedWith(edit));
      assert.equal(status, 2, label);
      assert.ok(stdout.includes("integrity: seq gap at 4 (got None)"), label);
      assert.equal(lines[4], `  seq=null event=allow node=custody:n1 scope=web.search state=process-asserted failed=${failed}`, label);
      assert.deepEqual(lines.filter((l) => l.includes("failed=")), [lines[4]], label);
    }
  });
});

test("a boolean seq breaks the chain at its own entry", () => {
  inTempDir((dir) => {
    const bundle = forgedWith((es) => void (es[1]!["seq"] = true));
    bundle["envelopes"] = [];
    const { status, stdout, lines } = entriesOf(dir, bundle);
    assert.equal(status, 2);
    assert.ok(stdout.includes("integrity=False"));
    assert.ok(stdout.includes("  - integrity: seq gap at 1 (got True)\n"));
    assert.equal(lines[1], "  seq=true event=spawn node=custody:n1 state=process-asserted failed=integrity");
    assert.ok(lines[4]!.endsWith(" failed=containment"), lines[4]);
  });
});

test("a string seq is a seq gap about its own entry", () => {
  inTempDir((dir) => {
    const { status, stdout, lines } = entriesOf(dir, forgedWith((es) => void (es[4]!["seq"] = "4")));
    assert.equal(status, 2);
    assert.ok(stdout.includes("integrity: seq gap at 4 (got 4)"));
    assert.ok(lines[4]!.endsWith(" failed=integrity,containment"), lines[4]);
    assert.deepEqual(lines.filter((l) => l.includes("failed=")), [lines[4]]);
  });
});

test("two entries sharing a seq are told apart", () => {
  // A forged allow inserted after the real one at seq 4, on the same node, with its own call_id.
  // Matching failures by seq and node could not tell the two apart.
  const doc = JSON.parse(fixtureText("vectors/envelopes/envelope_vectors_v1.json")) as {
    cases: { name: string; bundle: Record<string, unknown> & { entries: LedgerEntry[] } }[];
  };
  const bundle = JSON.parse(JSON.stringify(doc.cases.find((c) => c.name === "absent_envelope")!.bundle)) as Record<
    string,
    unknown
  > & { entries: LedgerEntry[] };
  const entries = bundle.entries;
  assert.deepEqual([entries[4]!["seq"], entries[4]!["event"]], [4, "allow"]);
  entries.splice(5, 0, { ...entries[4]!, scope: "crm.export", call_id: "ab".repeat(16) });
  rehash(entries);
  delete bundle["anchor"];
  inTempDir((dir) => {
    const { status, lines } = entriesOf(dir, bundle);
    assert.equal(status, 2);
    assert.ok(lines[4]!.startsWith("  seq=4 event=allow node=vectors:n1 scope=crm.read "), lines[4]);
    assert.ok(lines[5]!.startsWith("  seq=4 event=allow node=vectors:n1 scope=crm.export "), lines[5]);
    assert.ok(!lines[4]!.includes("failed="), lines[4]);
    assert.ok(lines[5]!.endsWith(" failed=integrity,containment"), lines[5]);
  });
});

test("a reason twice on one entry is listed once, and failure_entries names the entry", () => {
  const doc = JSON.parse(fixtureText("vectors/envelopes/envelope_vectors_v1.json")) as {
    cases: { name: string; bundle: Bundle; witness_keys: WitnessKey[] }[];
  };
  const c = doc.cases.find((x) => x.name === "valid_spawn_envelope")!;
  const bundle = JSON.parse(JSON.stringify(c.bundle)) as Bundle;
  const envelope = bundle.envelopes![0]!;
  bundle.envelopes = [envelope, structuredClone(envelope), structuredClone(envelope)];
  const report = verifyBundle(bundle, null, { witnessKeys: c.witness_keys });
  assert.deepEqual(report.failure_details.map((d) => d.reason), ["envelope_duplicate_subject", "envelope_duplicate_subject"]);
  assert.deepEqual(report.failure_entries, [1, 1]);
  inTempDir((dir) => {
    const file = join(dir, "dup.json");
    const keys = join(dir, "vector-keys.json");
    writeFileSync(file, JSON.stringify(bundle));
    writeFileSync(keys, JSON.stringify(c.witness_keys));
    const { stdout, status } = run(["verify", file, "--witness-keys", keys, "--entries"]);
    assert.equal(status, 2);
    assert.ok(
      stdout.includes("\n  seq=1 event=spawn node=vectors:n1 state=process-asserted failed=envelope_duplicate_subject\n"),
      stdout,
    );
  });
});

test("a seq that is not an integer is a gap in the ledger itself", () => {
  // `1.0` is a float to the Python implementation and `true` its bool, so neither is seq 1 there;
  // here a parsed ledger keeps each literal, and the same seqs are the same gap.
  inTempDir((dir) => {
    const file = join(dir, "l.jsonl");
    const root = Guard.issue("a", new Authority({ scopes: ["x.read"] }), { chainId: "c" });
    root.delegate("b", new Authority({ scopes: ["x.read"] }), "t");
    const clean = root.auditLog().entries.map((e) => JSON.stringify(e));
    for (const [bad, printed] of [["true", "True"], ["1.0", "1.0"], ['"1"', "1"]] as const) {
      // Re-hashed as a forger would; JCS writes 1.0 as 1, so that literal keeps the old hash.
      const entries = clean.map((line) => JSON.parse(line) as LedgerEntry);
      entries[1]!["seq"] = bad === "1.0" ? 1 : (JSON.parse(bad) as LedgerEntry[string]);
      rehash(entries);
      const lines = entries.map((e) => JSON.stringify(e));
      if (bad === "1.0") lines[1] = lines[1]!.replace('"seq":1,', '"seq":1.0,');
      writeFileSync(file, `${lines.join("\n")}\n`);
      assert.deepEqual(AuditLog.verify(AuditLog.parseLines(`${lines.join("\n")}\n`)), [false, `seq gap at 1 (got ${printed})`], bad);
      const { stdout, status } = run(["verify", file, "--entries"]);
      assert.equal(status, 2, bad);
      assert.ok(stdout.startsWith(`TAMPERED — seq gap at 1 (got ${printed})\n`), stdout);
      assert.ok(stdout.split("\n")[3]!.endsWith(" failed=integrity"), stdout);
    }
  });
});

test("an envelope subject seq or an envelope v written 1.0 is refused, as Python refuses a float", () => {
  // JCS writes 1.0 as 1, so nothing else about the bundle changes; the lexeme is the case. A plain
  // JSON parse cannot tell 1.0 from 1, and this build reads the literal it kept.
  const doc = JSON.parse(fixtureText("vectors/envelopes/envelope_vectors_v1.json")) as {
    cases: { name: string; bundle: unknown; witness_keys: unknown }[];
  };
  const c = doc.cases.find((x) => x.name === "valid_spawn_envelope")!;
  const text = JSON.stringify(c.bundle);
  assert.equal(text.split('"node":"vectors:n1","seq":1}').length, 2, "one subject names seq 1");
  assert.equal(text.split('"v":1,"witness"').length, 2, "one envelope declares v 1");
  inTempDir((dir) => {
    const keys = join(dir, "keys.json");
    writeFileSync(keys, JSON.stringify(c.witness_keys));
    const cases: [string, string, string][] = [
      ["subject seq", text.replace('"node":"vectors:n1","seq":1}', '"node":"vectors:n1","seq":1.0}'), "  - envelope_subject_mismatch: subject seq is not an integer"],
      ["envelope v", text.replace('"v":1,"witness"', '"v":1.0,"witness"'), "  - envelope_unknown_version: envelope v=1.0 typ='delegation-event-observation', this build knows v=1 typ='delegation-event-observation'"],
    ];
    for (const [label, bundleText, line] of cases) {
      assert.notEqual(bundleText, text, label);
      const report = verifyBundle(parseBundle(bundleText), null, { witnessKeys: c.witness_keys as WitnessKey[] });
      assert.equal(report.ok, false, label);
      const file = join(dir, "bundle.json");
      writeFileSync(file, bundleText);
      const { stdout, status } = run(["verify", file, "--witness-keys", keys]);
      assert.equal(status, 2, label);
      assert.ok(stdout.split("\n").includes(line), `${label}:\n${stdout}`);
    }
  });
});

// ---- a file this build cannot parse is one line, exit 1 -------------------------------------------

test("a bundle the strict parser refuses is one line naming the file and the reason, exit 1", () => {
  inTempDir((dir) => {
    const file = join(dir, "bundle.json");
    const cases: [string, string][] = [
      ['{"v":2,"entries":[],"entries":[]}', 'duplicate JSON object member "entries"'],
      ['{"v":2,"entries":[{"seq":1e400}]}', "non-finite numbers are not permitted"],
      ['{"v":2,"entries":[{"node":"\\ud800"}]}', "lone UTF-16 surrogates are not permitted"],
      // The parser quotes the member it refused; a separator in it is escaped, never printed raw.
      ['{"entries":[],"a\\u2028b":1,"a\\u2028b":2}', 'duplicate JSON object member "a\\u2028b"'],
      ["{not json", "line 1: expected an object key at position 1"],
      ['{"seq":0}\n{bad\n', "line 2: expected an object key at position 1"],
    ];
    for (const [content, reason] of cases) {
      writeFileSync(file, content);
      const { stdout, stderr, status } = run(["verify", file]);
      assert.deepEqual([status, stdout, stderr], [1, `cannot parse ${file}: ${reason}\n`, ""], content);
      assert.equal(run(["verify", file, "--entries"]).stdout, `cannot parse ${file}: ${reason}\n`, content);
    }
  });
});

// ---- a malformed trust file is one line naming the file and the kid, exit 2 ---------------------

function badRow(fields: Record<string, unknown>): unknown[] {
  return [{ kid: WITNESS_KID, alg: "EdDSA", public_key_hex: WITNESS_PUBLIC_HEX, ...fields }];
}

test("a bad --witness-keys row is one line naming the file and the kid, exit 2", () => {
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "clean.bundle.json", custodyRun(), [1, 2]);
    const keys = join(dir, "keys.json");
    const cases: [unknown, string][] = [
      [badRow({ not_after: "2026-10-05" }),
        `witness key '${WITNESS_KID}': not_after must be an RFC 3339 UTC date-time such as '2026-10-05T00:00:00Z', got '2026-10-05'`],
      [badRow({ not_after: null }),
        `witness key '${WITNESS_KID}': not_after must be an RFC 3339 UTC date-time such as '2026-10-05T00:00:00Z', got None`],
      [badRow({ public_key_hex: "zz".repeat(32) }), `witness key '${WITNESS_KID}': public_key_hex is not hexadecimal`],
      [badRow({ alg: "none" }), `witness key '${WITNESS_KID}': alg must be 'EdDSA', got 'none'`],
      [[{ alg: "EdDSA" }], "witness key kid must be a string"],
    ];
    for (const [rows, reason] of cases) {
      writeFileSync(keys, JSON.stringify(rows));
      const { stdout, stderr, status } = run(["verify", bundle, "--witness-keys", keys]);
      assert.deepEqual([status, stdout, stderr], [2, `cannot use --witness-keys ${keys}: ${reason}\n`, ""], reason);
    }
  });
});

test("a --witness-keys file that is not a trust set says so in one line, exit 2", () => {
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "clean.bundle.json", custodyRun(), [1, 2]);
    const keys = join(dir, "keys.json");
    const valid = JSON.stringify(badRow({}));
    const cases: [string | Buffer, string][] = [
      ["{not json", "the file is not valid JSON"],
      ["", "the file is not valid JSON"],
      // JSON is UTF-8 text: bytes that are not UTF-8 are not JSON, and a byte-order mark is not JSON.
      [Buffer.from([0x5b, 0xff, 0x5d]), "the file is not valid JSON"],
      [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(valid)]), "the file is not valid JSON"],
      [JSON.stringify({ kid: WITNESS_KID }),
        "expected a JSON array of {kid, alg, public_key_hex} rows, or a vector case carrying one as witness_keys"],
    ];
    for (const [content, reason] of cases) {
      writeFileSync(keys, content);
      const { stdout, status } = run(["verify", bundle, "--witness-keys", keys]);
      assert.deepEqual([status, stdout], [2, `cannot use --witness-keys ${keys}: ${reason}\n`], reason);
    }
  });
});

test("a file that cannot be read is a usage error naming it, exit 1", () => {
  inTempDir((dir) => {
    const bundle = writeBundle(dir, "clean.bundle.json", custodyRun(), [1, 2]);
    const missing = join(dir, "no-such-keys.json");
    assert.deepEqual(
      [run(["verify", bundle, "--witness-keys", missing]).status, run(["verify", bundle, "--witness-keys", missing]).stdout],
      [1, `cannot read ${missing}: No such file or directory\n`],
    );
    const absent = join(dir, "no-such-bundle.json");
    const missingBundle = run(["verify", absent]);
    assert.deepEqual([missingBundle.status, missingBundle.stdout, missingBundle.stderr], [1, `cannot read ${absent}: No such file or directory\n`, ""]);
    const directory = run(["verify", dir]);
    assert.deepEqual([directory.status, directory.stdout], [1, `cannot read ${dir}: Is a directory\n`]);
  });
});
