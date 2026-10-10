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

import { AuditLog, isLedgerObject, type LedgerEntry } from "./audit.js";
import { intOr, parseJson, type CJson } from "./canonical.js";
import { BARE, escaped, integerText, oneLine } from "./display.js";
import {
  PROCESS_ASSERTED,
  WITNESS_SIGNED,
  integrityBreak,
  parseBundle,
  stateKey,
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
                                                [--witness-keys FILE] [--entries]
                                     verify a hash-chained audit log, or an evidence bundle
                                     (integrity · child ⊆ parent · containment;
                                      --hs256-key/--pubkey checks the anchor;
                                      --witness-keys FILE supplies the trusted observer-envelope keys;
                                      --entries adds one line per entry: its envelope state and the checks that failed on it;
                                      a line is key=value tokens split by single spaces, the key before the first "=",
                                      and a value never contains a space; one that starts with " is a JSON string)
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

/**
 * Entry index -> the checks that failed on that entry: the `reason` of every failure about it,
 * each once, in the order the verifier reported them.
 *
 * `failureEntries` is the verifier's own record of the entry each failure is about, by index
 * (`VerifyReport.failure_entries`), so a failure lands on its entry even when that entry's seq is
 * missing, null, a boolean, a string or another entry's. A failure about no single entry (a
 * version, root, anchor or chain-id failure, or an envelope whose subject names no entry) is in
 * the bundle-level output already and lands on no line.
 */
function failedByEntry(
  failureEntries: readonly (number | null)[],
  details: readonly FailureDetail[],
): Map<number, string[]> {
  const failed = new Map<number, string[]>();
  failureEntries.forEach((index, k) => {
    if (index === null) return;
    const reason = details[k]!.reason;
    const reasons = failed.get(index) ?? [];
    if (!reasons.includes(reason)) reasons.push(reason);
    failed.set(index, reasons);
  });
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

/**
 * One `--entries` line: two spaces, then `key=value` tokens separated by single spaces, in a fixed
 * order. `seq` is always printed, as the integer when it is integral (`1.0` prints 1, as the
 * verifier reads it), and as `seq=null` for an entry that has none: an entry without a seq is
 * exactly the entry a reader must see. Any other key with no value is left out.
 *
 * How a line parses: no token contains whitespace; the key is the text before the token's first
 * `=`, and keys never contain one, though a value may (`scope=failed=containment` is the scope
 * "failed=containment"); a value that starts with `"` is a JSON string, and any other value is
 * printed as it is.
 *
 * An entry that is not a JSON object has no member to print, so its line is `seq=null` and what the
 * verifier said about it, as for any entry without those members.
 */
function entryLine(raw: LedgerEntry, rest: readonly (readonly [string, CJson | undefined])[]): string {
  const e: LedgerEntry = isLedgerObject(raw) ? raw : {};
  const tokens = [`seq=${entryValue((intOr(e["seq"]) ?? null) as CJson)}`];
  const pairs: (readonly [string, CJson | undefined])[] = [
    ["event", e["event"]],
    ["node", e["node"]],
    ["scope", e["scope"]],
    ...rest,
  ];
  for (const [key, value] of pairs) {
    if (value !== null && value !== undefined) tokens.push(`${key}=${entryValue(value)}`);
  }
  return `  ${tokens.join(" ")}`;
}

/**
 * A bundle's entries with the state the verifier computed for each, read by index: an entry is
 * witness-signed exactly when `envelopes.witnesses` holds its index, which is the entry the
 * verifier resolved an envelope to, so of two entries sharing a seq only the one the witness signed
 * reads witness-signed. `observed` and `witness` are printed only on such an entry: they are what
 * its envelope says, and an entry that is process-asserted carries no observation the reader may
 * rely on.
 */
function bundleEntryLines(entries: readonly LedgerEntry[], rep: VerifyReport): string[] {
  const failed = failedByEntry(rep.failure_entries, rep.failure_details);
  const { results, witnesses } = rep.envelopes;
  return entries.map((e, i) => {
    const kid = Object.hasOwn(witnesses, String(i)) ? witnesses[String(i)]! : null;
    // `results` is keyed the way `states` is (`stateKey`), and for a covered entry the result filed
    // there is its own envelope's.
    const key = stateKey(isLedgerObject(e) ? e : {}, i);
    return entryLine(e, [
      ["state", kid === null ? PROCESS_ASSERTED : WITNESS_SIGNED],
      ["observed", kid !== null && Object.hasOwn(results, key) ? results[key]! : null],
      ["witness", kid],
      ["failed", failed.get(i)?.join(",") ?? null],
    ]);
  });
}

/** A plain ledger's entries. A plain ledger carries no envelopes, so there is no state to print. */
function ledgerEntryLines(
  entries: readonly LedgerEntry[],
  failureEntries: readonly (number | null)[],
  details: readonly FailureDetail[],
): string[] {
  const failed = failedByEntry(failureEntries, details);
  return entries.map((e, i) => entryLine(e, [["failed", failed.get(i)?.join(",") ?? null]]));
}

/** One JSON object with an `entries` member: what `exportBundle` writes. */
function isBundleShaped(value: unknown): boolean {
  return value !== null && typeof value === "object" && !Array.isArray(value) && "entries" in value;
}

/**
 * Why a file that is neither a bundle nor a ledger could not be read, in one line.
 *
 * A file that is ONE JSON object with `entries`, read by JavaScript's lenient parser, is a bundle
 * the strict one refused — a duplicate member, a number past the double range, a lone surrogate —
 * and that refusal is the reason. Anything else was read as JSON Lines, and the reason is the first
 * line that does not parse. A parser's message can quote the input, so it goes through `oneLine`.
 */
function unparsable(text: string, bundleError: unknown, ledgerError: unknown): string {
  if (bundleError !== null) {
    let lenient: unknown = null;
    try {
      lenient = JSON.parse(text);
    } catch {
      lenient = null;
    }
    if (isBundleShaped(lenient)) return oneLine((bundleError as Error).message);
  }
  const lines = text.split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    if (lines[n]!.trim() === "") continue;
    try {
      parseJson(lines[n]!);
    } catch (err) {
      return `line ${n + 1}: ${oneLine((err as Error).message)}`;
    }
  }
  return oneLine((ledgerError as Error).message);
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
  let bundleError: unknown = null;
  try {
    // A bundle is ONE JSON object; a ledger is JSON Lines.
    const parsed = parseBundle(text) as unknown;
    bundle = isBundleShaped(parsed) ? (parsed as Bundle) : null;
  } catch (err) {
    bundle = null;
    bundleError = err;
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
    // An allow marked `policy: "unlisted"` passed through un-gated and is excused from containment,
    // so `actions_checked` does not count it. Say how many there were, only when there were any:
    // every other bundle prints this line exactly as it always has.
    const ungated = rep.ungated > 0 ? ` ungated=${rep.ungated}` : "";
    process.stdout.write(
      `integrity=${py(c.integrity)} monotonicity=${py(c.monotonicity)} ` +
        `containment=${py(c.containment)} anchor=${c.anchor} ` +
        `nodes=${rep.nodes} actions_checked=${rep.actions_checked}${ungated}\n`,
    );
    for (const f of rep.failures) process.stdout.write(`  - ${f}\n`);
    // A bundle carrying envelopes and no trust set fails every one of them, correctly and
    // unhelpfully: the keys are the caller's to supply and nothing in the bundle can stand in
    // for them. The failure stands; the line says how to make the run meaningful.
    // Only over envelopes this verifier read: an `envelopes` that is not an array is reported
    // (`invalid_bundle`), and no trust set would change that.
    if (Array.isArray(bundle.envelopes) && bundle.envelopes.length > 0 && witnessKeys === null) {
      process.stdout.write("hint: pass --witness-keys FILE to supply the trusted witness keys\n");
    }
    process.stdout.write(rep.ok ? "OK\n" : "FAILED\n");
    // `entries` that are not an array list nothing: the verifier read none of them.
    if (listEntries) writeEntries(bundleEntryLines(Array.isArray(bundle.entries) ? bundle.entries : [], rep));
    return rep.ok ? 0 : 2;
  }

  let entries: LedgerEntry[];
  try {
    entries = AuditLog.parseLines(text);
  } catch (err) {
    // Neither a bundle nor a ledger this build reads: one line, not a stack trace. Exit 1, as the
    // Python CLI exits on a file it cannot parse.
    process.stdout.write(`cannot parse ${path}: ${unparsable(text, bundleError, err)}\n`);
    return 1;
  }
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
    // A plain ledger has one check, the hash chain, and its failure is about the entry a bundle's
    // integrity failure is about: the first one the chain does not reproduce at.
    const at: (number | null)[] = [];
    const details: FailureDetail[] = [];
    if (!ok) {
      at.push(integrityBreak(entries));
      details.push({ reason: "integrity", seq: null, node: null, call_id: null, detail: `integrity: ${reason}` });
    }
    writeEntries(ledgerEntryLines(entries, at, details));
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
