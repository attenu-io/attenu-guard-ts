import assert from "node:assert/strict";
import test from "node:test";

import { AuditLog } from "../src/audit.js";
import { exportBundle, verifyBundle } from "../src/evidence.js";
import { HS256TestSigner } from "../src/wire.js";

const signer = new HS256TestSigner(Buffer.from("jcs-surface-test"), "jcs-test");

test("ledger entries, anchors, and bundles declare JCS", () => {
  const log = new AuditLog();
  const entry = log.append("root", 0, { chain_id: "jcs", node: "root" });
  assert.equal(entry["c14n"], "JCS");
  const anchor = log.anchor(signer);
  assert.equal(anchor.c14n, "JCS");
  const bundle = exportBundle(log, signer);
  assert.equal(bundle.c14n, "JCS");
  assert.equal(bundle.anchor.c14n, "JCS");
  assert.equal(verifyBundle(bundle, signer).ok, true);
});

test("unmarked ledgers, anchors, and bundles fail closed", () => {
  const log = new AuditLog();
  log.append("root", 0, { chain_id: "jcs", node: "root" });
  const bundle = exportBundle(log, signer) as any;

  const unmarkedEntry = structuredClone(bundle);
  delete unmarkedEntry.entries[0].c14n;
  assert.equal(AuditLog.verify(unmarkedEntry.entries)[0], false);

  const unmarkedAnchor = structuredClone(bundle);
  delete unmarkedAnchor.anchor.c14n;
  assert.equal(AuditLog.verifyAnchor(unmarkedAnchor.entries, unmarkedAnchor.anchor, signer)[0], false);

  const unmarkedBundle = structuredClone(bundle);
  delete unmarkedBundle.c14n;
  const report = verifyBundle(unmarkedBundle, signer);
  assert.equal(report.ok, false);
  assert.ok(report.failures.some((failure) => failure.includes("canonicalization")));
});
