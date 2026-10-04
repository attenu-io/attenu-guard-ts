/**
 * No value from a bundle can add a line to `attenu-guard verify` output.
 *
 * A property, not an example. Each committed bundle below is mutated at every place a value can
 * sit — an entry's members at any depth, a member's NAME, a scope, a constraint's members and
 * values, an authority's members, an envelope's members — by text carrying a line break, a
 * separator, a terminal escape or a format character, and the chain is re-hashed so every check
 * runs. Every failure the verifier reports must then be one line of printable text: what Python's
 * `repr` and the escaped-JSON rule (display.ts) guarantee. The CLI prints each failure on a line of
 * its own, so this is the claim the README makes, checked on the strings it rests on; a sample of
 * the bundles also goes through the CLI itself, `--entries` included, and its line count is checked.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { GENESIS, hashEntry, type LedgerEntry } from "../src/audit.js";
import { verifyBundle, type Bundle, type WitnessKey } from "../src/evidence.js";
import { REPO_ROOT, fixtureJson, fixtureText } from "./helpers.js";

/** Characters Python's `repr` escapes: Other and Separator, the space aside. */
const NOT_ONE_PRINTABLE_LINE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]|(?! )\p{Zs}/u;

/** Text that ends a line, starts one, moves the cursor, or hides itself in a terminal. */
const HOSTILE = [
  "a\nOK",
  "OK\n  - forged",
  "a\rOK",
  "a\u2028b",
  "a\u0085b",
  "\u001b[2K",
  "a\u200bb",
  "a\u00a0b",
];

interface Seed {
  name: string;
  bundle: Bundle;
  witnessKeys: WitnessKey[] | null;
}

const ENVELOPED = (fixtureJson("vectors/envelopes/envelope_vectors_v1.json") as {
  cases: { name: string; bundle: Bundle; witness_keys: WitnessKey[] }[];
}).cases.find((c) => c.name === "valid_spawn_envelope")!;

const SEEDS: Seed[] = [
  {
    name: "valid_bundle_v2",
    bundle: (fixtureJson("vectors/bundles/bundle_vectors_v1.json") as { cases: { name: string; bundle: Bundle }[] })
      .cases.find((c) => c.name === "valid_bundle_v2")!.bundle,
    witnessKeys: null,
  },
  { name: "clean_hs256", bundle: JSON.parse(fixtureText("clean_hs256.bundle.json")) as Bundle, witnessKeys: null },
  { name: "valid_spawn_envelope", bundle: ENVELOPED.bundle, witnessKeys: ENVELOPED.witness_keys },
];

type Slot = { path: string; container: Record<string, unknown> | unknown[]; key: string | number };

/** Every place inside `value` a value sits, depth first. */
function slots(value: unknown, path: string, out: Slot[] = []): Slot[] {
  if (Array.isArray(value)) {
    value.forEach((item, i) => {
      out.push({ path: `${path}[${i}]`, container: value, key: i });
      slots(item, `${path}[${i}]`, out);
    });
  } else if (value !== null && typeof value === "object") {
    for (const [k, item] of Object.entries(value)) {
      if (k === "hash" || k === "prev_hash") continue;
      out.push({ path: `${path}.${k}`, container: value as Record<string, unknown>, key: k });
      slots(item, `${path}.${k}`, out);
    }
  }
  return out;
}

/** Every object inside `value`, where a hostile member NAME can be added. */
function objects(value: unknown, path: string, out: [string, Record<string, unknown>][] = []) {
  if (Array.isArray(value)) value.forEach((item, i) => objects(item, `${path}[${i}]`, out));
  else if (value !== null && typeof value === "object") {
    out.push([path, value as Record<string, unknown>]);
    for (const [k, item] of Object.entries(value)) objects(item, `${path}.${k}`, out);
  }
  return out;
}

function rehash(bundle: Bundle): void {
  let prev = GENESIS;
  for (const e of bundle.entries) {
    e["prev_hash"] = prev;
    delete e["hash"];
    e["hash"] = hashEntry(prev, e);
    prev = e["hash"] as string;
  }
}

/** Each mutation of `seed`: one hostile value in one place, or one hostile member name. */
function* mutations(seed: Seed): Generator<[string, Bundle]> {
  const probe = JSON.parse(JSON.stringify(seed.bundle)) as Bundle;
  const where: { path: string; apply: (b: Bundle, text: string) => void }[] = [];
  const locate = (b: Bundle, path: string): unknown =>
    path.split(/(?=[.[])/).filter((step) => step !== "").reduce<unknown>((at, step) => {
      if (step.startsWith("[")) return (at as unknown[])[Number(step.slice(1, -1))];
      return (at as Record<string, unknown>)[step.slice(1)];
    }, b);
  for (const s of slots({ entries: probe.entries, envelopes: probe.envelopes ?? [] }, "")) {
    if (s.path === ".entries" || s.path === ".envelopes") continue; // the containers themselves
    const parent = s.path.slice(0, s.path.length - (typeof s.key === "number" ? `[${s.key}]` : `.${s.key}`).length);
    where.push({
      path: s.path,
      apply: (b, text) => {
        const container = locate(b, parent) as Record<string | number, unknown>;
        container[s.key] = text;
      },
    });
  }
  for (const [path] of objects({ entries: probe.entries, envelopes: probe.envelopes ?? [] }, "")) {
    if (path === "") continue; // the wrapper above, not a bundle object
    where.push({
      path: `${path}.<name>`,
      apply: (b, text) => {
        (locate(b, path) as Record<string, unknown>)[text] = 1;
      },
    });
  }
  for (const w of where) {
    for (const text of HOSTILE) {
      const bundle = JSON.parse(JSON.stringify(seed.bundle)) as Bundle;
      w.apply(bundle, text);
      try {
        rehash(bundle);
      } catch {
        continue; // a value JCS cannot hash: no chain to re-link, and nothing new to report
      }
      yield [`${seed.name} ${w.path} = ${JSON.stringify(text)}`, bundle];
    }
  }
}

test("every failure a hostile bundle earns is one line of printable text", () => {
  let runs = 0;
  let failures = 0;
  let escapedSeen = 0;
  for (const seed of SEEDS) {
    for (const [label, bundle] of mutations(seed)) {
      const report = verifyBundle(bundle, null, { witnessKeys: seed.witnessKeys });
      runs += 1;
      for (const failure of report.failures) {
        failures += 1;
        if (failure.includes("\\n") || failure.includes("\\u2028") || failure.includes("\\x1b")) escapedSeen += 1;
        assert.doesNotMatch(failure, NOT_ONE_PRINTABLE_LINE, `${label}: ${JSON.stringify(failure)}`);
      }
    }
  }
  // The property is only as good as its reach: the mutations must have produced findings that
  // carry the hostile text, escaped.
  assert.ok(runs > 2000, `${runs} bundles`);
  assert.ok(failures > runs / 2, `${failures} failures over ${runs} bundles`);
  assert.ok(escapedSeen > 500, `${escapedSeen} failures carried an escaped hostile value`);
});

test("the CLI prints exactly one line per finding and per entry for hostile bundles", () => {
  const bin = resolve(REPO_ROOT, "bin", "attenu-guard.js");
  const dir = mkdtempSync(join(tmpdir(), "attenu-one-line-"));
  try {
    let checked = 0;
    for (const seed of SEEDS) {
      const all = Array.from(mutations(seed));
      // A spread sample: every 97th mutation of each seed.
      for (let i = 0; i < all.length; i += 97) {
        const [label, bundle] = all[i]!;
        const file = join(dir, `b${checked}.json`);
        writeFileSync(file, JSON.stringify(bundle));
        const keys = join(dir, "keys.json");
        const args = ["verify", file, "--entries"];
        if (seed.witnessKeys !== null) {
          writeFileSync(keys, JSON.stringify(seed.witnessKeys));
          args.push("--witness-keys", keys);
        }
        const r = spawnSync(process.execPath, [bin, ...args], { encoding: "utf8" });
        const report = verifyBundle(bundle, null, { witnessKeys: seed.witnessKeys });
        const hint = (bundle.envelopes?.length ?? 0) > 0 && seed.witnessKeys === null ? 1 : 0;
        const expected = 1 + report.failures.length + hint + 1 + 1 + bundle.entries.length;
        assert.equal(r.stdout.split("\n").length - 1, expected, `${label}:\n${r.stdout}`);
        assert.doesNotMatch(r.stdout.replace(/\n/g, ""), NOT_ONE_PRINTABLE_LINE, label);
        checked += 1;
      }
    }
    assert.ok(checked >= 20, `${checked} CLI runs`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
