/**
 * The hash-chained ledger. Entry hashes must match Python's for identical
 * content, a Python-written ledger must verify here, and every way of editing
 * the record must be caught.
 */

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AuditLog, GENESIS, hashEntry, chainIdOf } from "../src/audit.js";
import { Authority } from "../src/authority.js";
import { RowLimit } from "../src/ceilings.js";
import { Guard } from "../src/guard.js";
import { parseJson, pyJsonDumps, toPlain } from "../src/canonical.js";
import { HS256TestSigner } from "../src/wire.js";
import { META, fixtureJson, fixtureText } from "./helpers.js";

interface HashVector {
  prev_hash: string;
  payload: Record<string, any>;
  expected_hash: string;
}

test("entry hashes match Python's, byte for byte", () => {
  const vectors = fixtureJson<HashVector[]>("hash_vectors.json");
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    assert.equal(hashEntry(v.prev_hash, v.payload), v.expected_hash, JSON.stringify(v.payload));
  }
});

test("a ledger written by Python verifies here", () => {
  const entries = AuditLog.parseLines(fixtureText("ledger.jsonl"));
  assert.equal(entries.length, META.ledger.entries);
  const [ok, reason] = AuditLog.verify(entries);
  assert.equal(ok, META.ledger.verify_ok);
  assert.equal(reason, META.ledger.verify_reason);
});

test("editing an entry breaks the chain", () => {
  const entries = AuditLog.parseLines(fixtureText("ledger.jsonl"));
  const denyIndex = entries.findIndex((e) => toPlain(e["event"]) === "deny");
  assert.ok(denyIndex >= 0, "the fixture run contains a denial");
  entries[denyIndex]!["event"] = "allow";
  const [ok, reason] = AuditLog.verify(entries);
  assert.equal(ok, false);
  assert.equal(reason, `hash mismatch at seq ${denyIndex}`);
});

test("removing an entry leaves a seq gap", () => {
  const entries = AuditLog.parseLines(fixtureText("ledger.jsonl"));
  entries.splice(3, 1);
  const [ok, reason] = AuditLog.verify(entries);
  assert.equal(ok, false);
  assert.equal(reason, "seq gap at 3 (got 4)");
});

test("reordering two entries is caught", () => {
  const entries = AuditLog.parseLines(fixtureText("ledger.jsonl"));
  const [a, b] = [entries[2]!, entries[3]!];
  entries[2] = b;
  entries[3] = a;
  const [ok] = AuditLog.verify(entries);
  assert.equal(ok, false);
});

test("an empty log has a GENESIS head and verifies", () => {
  const log = new AuditLog();
  assert.deepEqual(log.head(), [-1, GENESIS]);
  assert.deepEqual(AuditLog.verify(log.entries), [true, null]);
  assert.equal(log.length, 0);
});

test("a log this library writes verifies, and its head advances", () => {
  const log = new AuditLog();
  log.append("root", 1, { chain_id: "c", node: "n0", agent: "a" });
  log.append("allow", 2, { chain_id: "c", node: "n0", scope: "crm.read", context: {} });
  assert.equal(log.length, 2);
  assert.deepEqual(AuditLog.verify(log.entries), [true, null]);
  const [seq, head] = log.head();
  assert.equal(seq, 1);
  assert.equal(head, log.entries[1]!["hash"]);
  assert.equal(chainIdOf(log.entries), "c");
  assert.deepEqual([...log].length, 2);
});

test("the on-disk ledger uses the same line format Python writes", () => {
  const dir = mkdtempSync(join(tmpdir(), "attenu-audit-"));
  try {
    const path = join(dir, "nested", "audit.jsonl");
    const log = new AuditLog({ path });
    log.append("root", 1, { chain_id: "c", node: "n0", agent: "orchestrator", task: "café 😀" });
    log.append("allow", 2, { chain_id: "c", node: "n0", scope: "crm.read", context: { rows: 5 } });
    const lines = readFileSync(path, "utf8").trimEnd().split("\n");
    assert.equal(lines.length, 2);
    for (let i = 0; i < lines.length; i++) {
      // Python writes `json.dumps(payload, sort_keys=True)` — default separators.
      assert.equal(lines[i], pyJsonDumps(log.entries[i]!));
      assert.deepEqual(toPlain(parseJson(lines[i]!)), toPlain(log.entries[i]!));
    }
    assert.deepEqual(AuditLog.verify(AuditLog.load(path)), [true, null]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("sinks receive every entry", () => {
  const seen: string[] = [];
  const log = new AuditLog({ sinks: [{ write: (e) => seen.push(String(e["event"])) }] });
  log.append("root", 1, {});
  log.append("allow", 2, {});
  assert.deepEqual(seen, ["root", "allow"]);
});

test("an anchor commits to the head and catches a consistent rewrite", () => {
  const signer = new HS256TestSigner(Buffer.from(META.hs256_secret_hex, "hex"), META.hs256_kid);
  const guard = Guard.issue("orchestrator", new Authority({ scopes: ["crm.*"], ceilings: [new RowLimit(10)], ttl: 60 }), {
    chainId: "anchor-test",
  });
  guard.check("crm.read", { context: { rows: 1 } });
  const log = guard.auditLog();
  const anchor = log.anchor(signer, 7);
  assert.equal(anchor.kid, META.hs256_kid);
  assert.deepEqual(AuditLog.verifyAnchor(log.entries, anchor as any, signer), [true, null]);

  // A full, internally consistent rewrite: re-hash the whole chain after editing.
  const rewritten = log.entries.map((e) => ({ ...e }));
  rewritten[1]!["scope"] = "crm.write";
  let prev = GENESIS;
  for (const e of rewritten) {
    e["prev_hash"] = prev;
    const payload: Record<string, any> = {};
    for (const [k, v] of Object.entries(e)) if (k !== "hash") payload[k] = v;
    e["hash"] = hashEntry(prev, payload);
    prev = e["hash"] as string;
  }
  // The chain alone cannot tell — that is the whole point of the anchor.
  assert.deepEqual(AuditLog.verify(rewritten), [true, null]);
  const [ok, reason] = AuditLog.verifyAnchor(rewritten, anchor as any, signer);
  assert.equal(ok, false);
  assert.equal(reason, "anchor head does not match the ledger head (ledger rewritten?)");
});

test("a non-hex or invalid anchor signature is refused", () => {
  const signer = new HS256TestSigner(Buffer.from("00ff", "hex"), "k");
  const log = new AuditLog();
  log.append("root", 1, { chain_id: "c", node: "n0" });
  const anchor = log.anchor(signer, 0) as Record<string, any>;
  assert.deepEqual(AuditLog.verifyAnchor(log.entries, { ...anchor, sig: "zz" }, signer), [
    false,
    "anchor signature not hex",
  ]);
  assert.deepEqual(AuditLog.verifyAnchor(log.entries, { ...anchor, sig: "00" }, signer), [
    false,
    "anchor signature invalid",
  ]);
});
