/**
 * attenu-guard — command-line tool.
 *
 *   attenu-guard verify <log.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
 *                                                 [--witness-keys FILE]
 *
 * A `.jsonl` audit log is checked for hash-chain integrity. A bundle (the
 * output of `exportBundle`, or of the Python library's `export_bundle`) is
 * checked for integrity, monotonicity (child ⊆ parent) and containment from the
 * bundle alone; the signed anchor is verified when a key is given and reported
 * as "not checked" otherwise. `--witness-keys FILE` supplies the trusted witness
 * keys for a bundle carrying observer envelopes; without it every envelope fails
 * `envelope_unknown_witness`, and the output says which flag to pass.
 *
 * Exit codes: 0 = ok, 2 = a check failed, 1 = usage. The output lines match the
 * Python CLI's, so either implementation can stand in for the other in a script.
 */

import { readFileSync } from "node:fs";

import { AuditLog } from "./audit.js";
import { parseBundle, verifyBundle, type Bundle, type WitnessKey } from "./evidence.js";
import { Ed25519Verifier, HS256TestSigner, type Signer } from "./wire.js";

const USAGE = `attenu-guard — command-line tool.

  attenu-guard verify <log.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
                                                [--witness-keys FILE]
                                     verify a hash-chained audit log, or an evidence bundle
                                     (integrity · child ⊆ parent · containment;
                                      --hs256-key/--pubkey checks the anchor;
                                      --witness-keys FILE supplies the trusted observer-envelope keys)
`;

/**
 * The trust set for a bundle's observer envelopes, read from `--witness-keys FILE`.
 *
 * The file is the `witness_keys` array the interop vectors carry — `[{kid, alg,
 * public_key_hex}]` — or one whole vector case, in which case its `witness_keys` member is used.
 * Without a trust set every envelope in a bundle fails `envelope_unknown_witness`, which is
 * correct (an unknown key is not a trusted one) and useless as a default, so this is how a bundle
 * carrying envelopes is verified from the command line.
 */
function readWitnessKeys(path: string): readonly WitnessKey[] {
  let parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) && "witness_keys" in parsed) {
    parsed = (parsed as Record<string, unknown>)["witness_keys"];
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`${path}: expected a list of {kid, alg, public_key_hex}, got ${typeof parsed}`);
  }
  return parsed as readonly WitnessKey[];
}

/** Render a boolean the way Python does, so the two CLIs print the same line. */
function py(value: boolean): string {
  return value ? "True" : "False";
}

function verify(args: string[]): number {
  let path: string | null = null;
  let keyHex: string | null = null;
  let pubHex: string | null = null;
  let kid: string | null = null;
  let witnessPath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--hs256-key") keyHex = args[++i] ?? null;
    else if (a === "--pubkey") pubHex = args[++i] ?? null;
    else if (a === "--kid") kid = args[++i] ?? null;
    else if (a === "--witness-keys") witnessPath = args[++i] ?? null;
    else if (path === null) path = a;
  }
  if (path === null) {
    process.stdout.write(USAGE);
    return 1;
  }

  const text = readFileSync(path, "utf8");
  let bundle: Bundle | null = null;
  try {
    // A bundle is ONE JSON object; a ledger is JSON Lines.
    const parsed = parseBundle(text) as unknown;
    bundle =
      parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) && "entries" in parsed
        ? (parsed as Bundle)
        : null;
  } catch {
    bundle = null;
  }

  if (bundle !== null) {
    const anchorKid = (bundle.anchor?.["kid"] as string | undefined) ?? undefined;
    let signer: Signer | null = null;
    if (keyHex) signer = new HS256TestSigner(Buffer.from(keyHex, "hex"), kid ?? anchorKid ?? "k1");
    else if (pubHex) {
      signer = new Ed25519Verifier(Buffer.from(pubHex, "hex"), kid ?? anchorKid ?? "k1");
    }
    const witnessKeys = witnessPath === null ? null : readWitnessKeys(witnessPath);
    const rep = verifyBundle(bundle, signer, { witnessKeys });
    const c = rep.checks;
    process.stdout.write(
      `integrity=${py(c.integrity)} monotonicity=${py(c.monotonicity)} ` +
        `containment=${py(c.containment)} anchor=${c.anchor} ` +
        `nodes=${rep.nodes} actions_checked=${rep.actions_checked}\n`,
    );
    for (const f of rep.failures) process.stdout.write(`  - ${f}\n`);
    // A bundle carrying envelopes and no trust set fails every one of them, correctly and
    // unhelpfully: the keys are the caller's to supply and nothing in the bundle can stand in
    // for them. The failure stands; the line says how to make the run meaningful.
    if ((bundle.envelopes?.length ?? 0) > 0 && witnessKeys === null) {
      process.stdout.write("hint: pass --witness-keys FILE to supply the trusted witness keys\n");
    }
    process.stdout.write(rep.ok ? "OK\n" : "FAILED\n");
    return rep.ok ? 0 : 2;
  }

  const entries = AuditLog.parseLines(text);
  const [ok, reason] = AuditLog.verify(entries);
  process.stdout.write(ok ? "OK\n" : `TAMPERED — ${reason}\n`);
  return ok ? 0 : 2;
}

export function main(argv: string[] = process.argv.slice(2)): number {
  if (argv.length === 0) {
    process.stdout.write(USAGE);
    return 1;
  }
  const [cmd, ...rest] = argv;
  if (cmd === "-h" || cmd === "--help" || rest.some((a) => a === "-h" || a === "--help")) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (cmd === "verify" && rest.length > 0) return verify(rest);
  process.stdout.write(USAGE);
  return 1;
}
