/**
 * attenu-guard — command-line tool.
 *
 *   attenu-guard verify <log.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
 *                                                 [--witness-keys FILE] [--entries]
 *
 * A `.jsonl` audit log is checked for hash-chain integrity. A bundle (the
 * output of `exportBundle`, or of the Python library's `export_bundle`) is
 * checked for integrity, monotonicity (child ⊆ parent) and containment from the
 * bundle alone; the signed anchor is verified when a key is given and reported
 * as "not checked" otherwise. `--witness-keys FILE` supplies the trusted witness
 * keys for a bundle carrying observer envelopes; without it every envelope fails
 * `envelope_unknown_witness`, and the output says which flag to pass. A trust-set row may carry
 * `not_after`; a row expired at the time of the run is not trusted. A trust file that is not one
 * (not JSON, not an array of rows, or a row the verifier refuses) is one line naming the file and,
 * for a bad row, the kid.
 *
 * `--entries` prints, after everything else, `entries:` and one line per ledger entry: its seq,
 * event, node and scope; on a bundle, its envelope state, with the observed result and the
 * witness's kid when that state is witness-signed; and the checks that failed on that entry.
 * Without the flag the output is unchanged.
 *
 * A ledger with zero events is reported EMPTY, not OK.
 *
 * Exit codes: 0 = ok, 2 = a check failed, there was nothing to check, or the trust file is
 * malformed, 1 = usage (a missing argument, or a file that cannot be read).
 * The output lines match the Python CLI's, so either implementation can stand in
 * for the other in a script.
 */

import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

import { AuditLog, type LedgerEntry } from "./audit.js";
import { toPlain, type CJson, type Json } from "./canonical.js";
import { BARE, escaped, integerText } from "./display.js";
import {
  WITNESS_SIGNED,
  integrityPosition,
  parseBundle,
  validateWitnessKeys,
  verifyBundle,
  type Bundle,
  type FailureDetail,
  type VerifyReport,
  type WitnessKey,
} from "./evidence.js";
import { Ed25519Verifier, HS256TestSigner, type Signer } from "./wire.js";

/** The Python CLI prints the same line for the same file. */
const EMPTY = "EMPTY — no events to verify";

const USAGE = `attenu-guard — command-line tool.

  attenu-guard verify <log.jsonl | bundle.json> [--hs256-key HEX | --pubkey HEX] [--kid KID]
                                                [--witness-keys FILE]
                                     verify a hash-chained audit log, or an evidence bundle
                                     (integrity · child ⊆ parent · containment;
                                      --hs256-key/--pubkey checks the anchor;
                                      --witness-keys FILE supplies the trusted observer-envelope keys)
`;

/** A `--witness-keys` file that was read and is not a trust set. The message says why. */
class NotATrustSet extends Error {}

/**
 * The trust set for a bundle's observer envelopes, read from `--witness-keys FILE`.
 *
 * The file is the `witness_keys` array the interop vectors carry — `[{kid, alg,
 * public_key_hex}]`, each row optionally with `not_after` — or one whole vector case, in which case
 * its `witness_keys` member is used. Without a trust set every envelope in a bundle fails
 * `envelope_unknown_witness`, which is correct (an unknown key is not a trusted one) and useless as
 * a default, so this is how a bundle carrying envelopes is verified from the command line.
 *
 * Every row is validated here, by the same checks the verifier runs, so a bad row is reported
 * against this file before any bundle is read. Throws the file system's error when the file cannot
 * be read, and `NotATrustSet` when it is not a trust set: not JSON (JSON is UTF-8 text, so bytes
 * that are not UTF-8 are not JSON either), not an array of rows, or a row the verifier refuses,
 * whose message names the kid. The messages are the Python CLI's, word for word.
 */
function readWitnessKeys(path: string): readonly WitnessKey[] {
  const bytes = readFileSync(path);
  let parsed: unknown;
  try {
    // `ignoreBOM` keeps a byte-order mark in the text, where JSON.parse refuses it as Python does.
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    throw new NotATrustSet("the file is not valid JSON");
  }
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) && "witness_keys" in parsed) {
    parsed = (parsed as Record<string, unknown>)["witness_keys"];
  }
  if (!Array.isArray(parsed)) {
    throw new NotATrustSet(
      "expected a JSON array of {kid, alg, public_key_hex} rows, or a vector case carrying one as witness_keys",
    );
  }
  try {
    validateWitnessKeys(parsed as readonly WitnessKey[]);
  } catch (err) {
    throw new NotATrustSet((err as Error).message);
  }
  return parsed as readonly WitnessKey[];
}

/**
 * The C library's text for the file-system errors a path argument meets — what Python prints as
 * `strerror` — so `cannot read FILE: REASON` reads the same from both CLIs. `null` for an error
 * that is not a file-system one. A code outside this table prints Node's own message, which is
 * worded differently.
 */
function readFailure(err: unknown): string | null {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code !== "string") return null;
  return STRERROR[code] ?? (err as Error).message;
}

const STRERROR: Readonly<Record<string, string>> = {
  ENOENT: "No such file or directory",
  EACCES: "Permission denied",
  EISDIR: "Is a directory",
  ENOTDIR: "Not a directory",
  ELOOP: "Too many levels of symbolic links",
  ENAMETOOLONG: "File name too long",
  EPERM: "Operation not permitted",
  EMFILE: "Too many open files",
  EINVAL: "Invalid argument",
  EIO: "Input/output error",
};

/** Render a boolean the way Python does, so the two CLIs print the same line. */
function py(value: boolean): string {
  return value ? "True" : "False";
}

/** A ledger field as a plain JSON value, `null` when the entry does not carry it. */
function field(e: LedgerEntry, name: string): Json {
  const plain = toPlain(e[name]);
  return plain === undefined ? null : plain;
}

/** A seq as an index key, or `null` for an object or array seq, which is compared whole instead. */
function seqKey(seq: Json): string | null {
  return typeof seq === "number" || typeof seq === "string" || typeof seq === "boolean" ? JSON.stringify(seq) : null;
}

/**
 * Entry index -> the checks that failed on that entry: the `reason` of every finding positioned on
 * it, each once, in the order the verifier reported them.
 *
 * A finding lands on every entry whose own seq equals the finding's seq, and whose node and call_id
 * equal the finding's wherever the finding carries them. In a ledger whose seqs are unique that is
 * one entry. A finding with no seq is about no single entry (a version, root, anchor or chain-id
 * failure, or an envelope whose subject names no entry), and stays in the bundle-level output
 * only. Entries are indexed by seq first, so a long ledger with a finding on every entry is not a
 * quadratic walk.
 */
function failedByEntry(entries: readonly LedgerEntry[], findings: readonly FailureDetail[]): Map<number, string[]> {
  const bySeq = new Map<string, number[]>();
  entries.forEach((e, i) => {
    const key = seqKey(field(e, "seq"));
    if (key === null) return;
    const list = bySeq.get(key);
    if (list === undefined) bySeq.set(key, [i]);
    else list.push(i);
  });
  const failed = new Map<number, string[]>();
  for (const f of findings) {
    if (f.seq === null) continue;
    const key = seqKey(f.seq);
    const candidates =
      key !== null
        ? (bySeq.get(key) ?? [])
        : entries.flatMap((e, i) => (isDeepStrictEqual(field(e, "seq"), f.seq) ? [i] : []));
    for (const i of candidates) {
      const e = entries[i]!;
      if (f.node !== null && !isDeepStrictEqual(f.node, field(e, "node"))) continue;
      if (f.call_id !== null && !isDeepStrictEqual(f.call_id, field(e, "call_id"))) continue;
      const reasons = failed.get(i) ?? [];
      if (!reasons.includes(f.reason)) reasons.push(f.reason);
      failed.set(i, reasons);
    }
  }
  return failed;
}

/**
 * One value on an `--entries` line, byte for byte what the Python CLI prints.
 *
 * The values come from the bundle, which is attacker-supplied, and a line is only worth reading if
 * no value can end it early or start a forged one: a `scope` carrying a newline and a clean-looking
 * second line would otherwise print a fake entry with the real entry's `failed=` attached to it. So
 * a value is printed as it is only when it is printable ASCII with no space, `"` or `\`, and an
 * integer in decimal. Anything else is printed in the `escaped` JSON form (display.ts), which holds
 * no whitespace and which a JSON parser reads back.
 */
function entryValue(value: CJson): string {
  if (typeof value === "string" && BARE.test(value)) return value;
  return integerText(value) ?? escaped(value);
}

/** One `--entries` line: `key=value` pairs in a fixed order, a key with no value left out. */
function entryLine(pairs: readonly (readonly [string, CJson | undefined])[]): string {
  const shown: string[] = [];
  for (const [key, value] of pairs) {
    if (value !== null && value !== undefined) shown.push(`${key}=${entryValue(value)}`);
  }
  return `  ${shown.join(" ")}`;
}

/**
 * A bundle's entries with the state the verifier computed for each. `observed` and `witness` are
 * printed only on a witness-signed entry: an entry that fell back to process-asserted carries no
 * observation the reader may rely on.
 */
function bundleEntryLines(entries: readonly LedgerEntry[], rep: VerifyReport): string[] {
  const failed = failedByEntry(entries, rep.failure_details);
  return entries.map((e, i) => {
    // The key the verifier filed this entry's state under.
    const key = String(field(e, "seq") ?? i);
    const state = rep.envelopes.states[key] ?? null;
    const signed = state === WITNESS_SIGNED;
    return entryLine([
      ["seq", e["seq"]],
      ["event", e["event"]],
      ["node", e["node"]],
      ["scope", e["scope"]],
      ["state", state],
      ["observed", signed ? rep.envelopes.results[key] : null],
      ["witness", signed ? rep.envelopes.witnesses[key] : null],
      ["failed", failed.get(i)?.join(",") ?? null],
    ]);
  });
}

/** A plain ledger's entries. A plain ledger carries no envelopes, so there is no state to print. */
function ledgerEntryLines(entries: readonly LedgerEntry[], findings: readonly FailureDetail[]): string[] {
  const failed = failedByEntry(entries, findings);
  return entries.map((e, i) =>
    entryLine([
      ["seq", e["seq"]],
      ["event", e["event"]],
      ["node", e["node"]],
      ["scope", e["scope"]],
      ["failed", failed.get(i)?.join(",") ?? null],
    ]),
  );
}

function writeEntries(lines: readonly string[]): void {
  process.stdout.write(`entries:\n${lines.map((line) => `${line}\n`).join("")}`);
}

function verify(args: string[]): number {
  let path: string | null = null;
  let keyHex: string | null = null;
  let pubHex: string | null = null;
  let kid: string | null = null;
  let witnessPath: string | null = null;
  let listEntries = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--hs256-key") keyHex = args[++i] ?? null;
    else if (a === "--pubkey") pubHex = args[++i] ?? null;
    else if (a === "--kid") kid = args[++i] ?? null;
    else if (a === "--witness-keys") witnessPath = args[++i] ?? null;
    else if (a === "--entries") listEntries = true;
    else if (path === null) path = a;
  }
  if (path === null) {
    process.stdout.write(USAGE);
    return 1;
  }

  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    // A wrong path is a usage error, not a stack trace.
    const reason = readFailure(err);
    if (reason === null) throw err;
    process.stdout.write(`cannot read ${path}: ${reason}\n`);
    return 1;
  }
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
    let witnessKeys: readonly WitnessKey[] | null = null;
    if (witnessPath) {
      try {
        witnessKeys = readWitnessKeys(witnessPath);
      } catch (err) {
        // Read, and not a trust set: one line, naming the file and, for a bad row, the kid.
        if (err instanceof NotATrustSet) {
          process.stdout.write(`cannot use --witness-keys ${witnessPath}: ${err.message}\n`);
          return 2;
        }
        // Unreadable, as for the bundle path above.
        const reason = readFailure(err);
        if (reason === null) throw err;
        process.stdout.write(`cannot read ${witnessPath}: ${reason}\n`);
        return 1;
      }
    }
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
    if (listEntries) writeEntries(bundleEntryLines(bundle.entries ?? [], rep));
    return rep.ok ? 0 : 2;
  }

  const entries = AuditLog.parseLines(text);
  if (entries.length === 0) {
    // A ledger with no entries has nothing to verify. Reporting it OK would be a fail-open: a
    // truncated or never-written file would pass the same check as a clean chain.
    process.stdout.write(`${EMPTY}\n`);
    if (listEntries) writeEntries([]);
    return 2;
  }
  const [ok, reason] = AuditLog.verify(entries);
  process.stdout.write(ok ? "OK\n" : `TAMPERED — ${reason}\n`);
  if (listEntries) {
    // A plain ledger has one check, the hash chain. When it breaks, it is positioned with the
    // same walk the bundle verifier uses for its `integrity` finding.
    const findings: FailureDetail[] = [];
    if (!ok) {
      const [seq, node] = integrityPosition(entries);
      findings.push({ reason: "integrity", seq, node, call_id: null, detail: `integrity: ${reason}` });
    }
    writeEntries(ledgerEntryLines(entries, findings));
  }
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
