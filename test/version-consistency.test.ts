/**
 * Release-gate finding 4 (HIGH): three separate places each carry the package's version, and
 * nothing checked they agreed. Found genuinely disagreeing across all three at once:
 * `package.json` said `0.4.0`, `package-lock.json`'s root `version` said `0.3.1` (stale from
 * before the 0.4.0 bump — `npm install` never re-synced it), and `src/version.ts`'s exported
 * `VERSION` — the constant `guard.ts` and `adapters/langgraph.ts` both attribute every v2
 * ledger entry's `adapter.version` field with — said `0.3.0`. The existing release workflow
 * (`.github/workflows/release.yml`) only ever checks the pushed tag against `package.json`; it
 * would have published while the shipped ledger attribution was still wrong. This test closes
 * that gap on every CI run, not only at release time: `package.json`, `package-lock.json`'s
 * root `version`, and the exported `VERSION` must always agree.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { VERSION } from "../src/version.js";
import { REPO_ROOT } from "./helpers.js";

function readJson(relativePath: string): any {
  return JSON.parse(readFileSync(resolve(REPO_ROOT, relativePath), "utf8"));
}

test("package.json, package-lock.json's root version, and the exported VERSION all agree", () => {
  const pkg = readJson("package.json");
  const lock = readJson("package-lock.json");

  assert.equal(
    typeof pkg.version, "string",
    "package.json must declare a version",
  );
  assert.equal(
    lock.version, pkg.version,
    `package-lock.json's root "version" (${lock.version}) must match package.json's (${pkg.version})`,
  );
  // lockfileVersion 3's root package entry, keyed by "", carries its own copy of the version --
  // both are checked, not just the top-level field, since the two have drifted independently
  // before.
  assert.equal(
    lock.packages?.[""]?.version, pkg.version,
    `package-lock.json's packages[""].version (${lock.packages?.[""]?.version}) must match ` +
    `package.json's (${pkg.version})`,
  );
  assert.equal(
    VERSION, pkg.version,
    `src/version.ts's exported VERSION (${VERSION}) must match package.json's (${pkg.version}) ` +
    `-- every v2 chain's ledger entries attribute their "adapter.version" field with this ` +
    `constant (guard.ts's bare check() default, and both adapters/langgraph.ts wrappers), so a ` +
    `stale VERSION silently misreports it in the audit trail, not merely in package metadata.`,
  );
});
