import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBytes } from "../src/canonical.js";
import { AuditLog, GENESIS, hashEntry } from "../src/audit.js";
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

test("c14n is informational on ledger, anchor, and bundle verification", () => {
  const log = new AuditLog();
  const original = log.append("root", 0, { chain_id: "jcs", node: "root" });

  for (const marker of [undefined, "private-label-v2"] as const) {
    const entry: any = structuredClone(original);
    delete entry.c14n;
    delete entry.hash;
    if (marker !== undefined) entry.c14n = marker;
    entry.hash = hashEntry(GENESIS, entry);
    assert.deepEqual(AuditLog.verify([entry]), [true, null]);

    const body: any = {
      v: 1,
      chain_id: "jcs",
      seq: 0,
      head: entry.hash,
      ts: 0,
    };
    if (marker !== undefined) body.c14n = marker;
    const anchor: any = {
      ...body,
      kid: signer.kid,
      sig: signer.sign(canonicalBytes(body)).toString("hex"),
    };
    assert.deepEqual(AuditLog.verifyAnchor([entry], anchor, signer), [true, null]);

    const bundle: any = {
      v: 1,
      chain_id: "jcs",
      entries: [entry],
      anchor,
    };
    if (marker !== undefined) bundle.c14n = marker;
    const report = verifyBundle(bundle, signer);
    assert.equal(report.ok, true, report.failures.join("; "));
  }
});
