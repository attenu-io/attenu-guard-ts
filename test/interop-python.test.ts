/**
 * The reverse direction: a ledger and a bundle produced HERE, verified by the
 * Python CLI.
 *
 * The fixture-driven tests prove Python → TypeScript. This proves TypeScript →
 * Python, which is the half a shared canonical serialiser can still get wrong in
 * one direction only (a number written as `1e-5` where Python would write
 * `1e-05`, say).
 *
 * It runs when a Python `attenu-guard` CLI is reachable, and skips otherwise —
 * so CI without a Python toolchain stays green. Point it at one with:
 *
 *     ATTENU_GUARD_PY=/path/to/venv/bin/attenu-guard npm test
 *
 * With no variable set it tries `attenu-guard` on PATH.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Authority } from "../src/authority.js";
import { Allow, CallLimit, EgressRank, Prefix, RowLimit, SpendCap } from "../src/ceilings.js";
import { exportBundle } from "../src/evidence.js";
import { Guard } from "../src/guard.js";
import { Ed25519Signer, HS256TestSigner } from "../src/wire.js";
import { META } from "./helpers.js";

const PY_CLI = process.env["ATTENU_GUARD_PY"] ?? "attenu-guard";

function pythonCliAvailable(): boolean {
  const r = spawnSync(PY_CLI, ["verify"], { encoding: "utf8" });
  return r.error === undefined;
}

function runPython(args: string[]): { stdout: string; status: number } {
  const r = spawnSync(PY_CLI, args, { encoding: "utf8" });
  assert.equal(r.error, undefined, `could not run ${PY_CLI}`);
  return { stdout: r.stdout, status: r.status ?? -1 };
}

/** A run that exercises every ceiling type, unicode, and both outcomes. */
function buildRun(auditPath: string | null): Guard {
  const root = Guard.issue(
    "orchestrator",
    new Authority({
      scopes: ["crm.*", "db.query", "web.fetch"],
      ceilings: [
        new RowLimit(100_000),
        new EgressRank("any"),
        new SpendCap(12.5),
        new CallLimit(4, "web.fetch"),
        new Allow("region", ["eu-west", "eu-north"]),
        new Prefix("path", "/srv/data/"),
      ],
      ttl: 3600,
    }),
    { chainId: "ts-interop", task: "quarterly review · résumé 😀", auditPath },
  );
  const reader = root.delegate(
    "reader",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(5_000), new SpendCap(0.5)], ttl: 900 }),
    "summarise the pipeline",
  );
  const analyst = reader.delegate(
    "analyst",
    new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(500)], ttl: 600 }),
    "top accounts",
  );
  reader.check("crm.read", { context: { rows: 4_200, spend: 0.25 }, tool: "crm_query" });
  analyst.check("crm.read", { context: { rows: 120 }, tool: "crm_query" });
  analyst.check("crm.read", { context: { rows: 9_000 }, tool: "crm_query" }); // row ceiling
  reader.check("crm.export", { context: { egress: "any" }, tool: "crm_export" }); // not held
  root.check("db.query", { context: { region: "eu-west", path: "/srv/data/x" }, tool: "db" });
  root.check("web.fetch", { tool: "fetch" });
  analyst.complete();
  root.revoke(reader.nodeId);
  return root;
}

test("a ledger and bundle written here verify with the Python CLI", (t) => {
  if (!pythonCliAvailable()) {
    t.skip(`no Python attenu-guard CLI (set ATTENU_GUARD_PY); tried '${PY_CLI}'`);
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), "attenu-interop-"));
  try {
    const ledgerPath = join(dir, "audit.jsonl");
    const root = buildRun(ledgerPath);

    // 1. The .jsonl ledger, checked by the Python chain verifier.
    const ledger = runPython(["verify", ledgerPath]);
    assert.equal(ledger.stdout.trimEnd(), "OK", "Python must accept our ledger");
    assert.equal(ledger.status, 0);

    // 2. A bundle anchored with the HMAC test signer.
    const hs = new HS256TestSigner(Buffer.from(META.hs256_secret_hex, "hex"), META.hs256_kid);
    const hsPath = join(dir, "hs256.bundle.json");
    writeFileSync(hsPath, JSON.stringify(exportBundle(root.auditLog(), hs), null, 1));
    const hsRun = runPython(["verify", hsPath, "--hs256-key", META.hs256_secret_hex]);
    assert.equal(
      hsRun.stdout.split("\n")[0],
      "integrity=True monotonicity=True containment=True anchor=verified nodes=3 actions_checked=4",
    );
    assert.equal(hsRun.stdout.trimEnd().split("\n").at(-1), "OK");
    assert.equal(hsRun.status, 0);

    // 3. A bundle anchored with a real Ed25519 key, verified from the public half.
    const ed = Ed25519Signer.fromPrivateBytes(
      Buffer.from(META.ed25519_private_hex, "hex"),
      META.ed25519_kid,
    );
    const edPath = join(dir, "ed25519.bundle.json");
    writeFileSync(edPath, JSON.stringify(exportBundle(root.auditLog(), ed), null, 1));
    const edRun = runPython(["verify", edPath, "--pubkey", ed.publicBytesRaw().toString("hex")]);
    assert.match(edRun.stdout, /anchor=verified/);
    assert.equal(edRun.stdout.trimEnd().split("\n").at(-1), "OK");
    assert.equal(edRun.status, 0);

    // 4. Python must reject a bundle we deliberately broke, not wave it through.
    const bundle = exportBundle(root.auditLog(), hs);
    const deny = bundle.entries.find((e) => e["event"] === "deny");
    assert.ok(deny, "the run recorded a denial");
    deny!["event"] = "allow";
    const brokenPath = join(dir, "broken.bundle.json");
    writeFileSync(brokenPath, JSON.stringify(bundle, null, 1));
    const broken = runPython(["verify", brokenPath, "--hs256-key", META.hs256_secret_hex]);
    assert.match(broken.stdout, /integrity=False/);
    assert.equal(broken.stdout.trimEnd().split("\n").at(-1), "FAILED");
    assert.equal(broken.status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("our Ed25519 signatures verify against a key Python generated", () => {
  // The fixture public key was exported by the Python signer; signing the same
  // bytes here and verifying there is covered above. This checks the key
  // material itself round-trips through the raw byte forms.
  const ed = Ed25519Signer.fromPrivateBytes(
    Buffer.from(META.ed25519_private_hex, "hex"),
    META.ed25519_kid,
  );
  assert.equal(ed.publicBytesRaw().toString("hex"), META.ed25519_public_hex);
  assert.equal(ed.privateBytesRaw().toString("hex"), META.ed25519_private_hex);
  const sig = ed.sign(Buffer.from("attenu", "utf8"));
  assert.equal(sig.length, 64);
  assert.ok(ed.verify(Buffer.from("attenu", "utf8"), sig));
  assert.ok(!ed.verify(Buffer.from("attenv", "utf8"), sig));
});
