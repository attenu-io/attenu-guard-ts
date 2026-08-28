/** Shared fixture loading for the test suite. */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * The fixtures directory. Resolved from the package root, which is where `npm
 * test` runs, with a fallback relative to the compiled test file so the suite
 * also works when invoked from elsewhere.
 */
export const FIXTURES = (() => {
  const fromCwd = resolve(process.cwd(), "test", "fixtures");
  try {
    readFileSync(resolve(fromCwd, "meta.json"));
    return fromCwd;
  } catch {
    return resolve(__dirname, "..", "..", "test", "fixtures");
  }
})();

export const REPO_ROOT = resolve(FIXTURES, "..", "..");

export function fixturePath(name: string): string {
  return resolve(FIXTURES, name);
}

export function fixtureText(name: string): string {
  return readFileSync(fixturePath(name), "utf8");
}

export function fixtureJson<T = any>(name: string): T {
  return JSON.parse(fixtureText(name)) as T;
}

export interface Meta {
  hs256_secret_hex: string;
  hs256_kid: string;
  ed25519_private_hex: string;
  ed25519_public_hex: string;
  ed25519_kid: string;
  ledger: { entries: number; verify_ok: boolean; verify_reason: string | null; cli_status: string };
  cli: Record<string, Record<"with_key" | "without_key", { line: string; status: string; exit: number }>>;
}

export const META: Meta = fixtureJson<Meta>("meta.json");

/** The bundle fixtures, and which key verifies each one's anchor. */
export const BUNDLE_NAMES = Object.keys(META.cli);

export function bundleFile(name: string): string {
  return `${name}.bundle.json`;
}
