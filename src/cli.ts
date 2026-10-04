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
 * `not_after`; a row expired at the time of the run is not trusted.
 *
 * `--entries` prints, after everything else, `entries:` and one line per ledger entry: its seq,
 * event, node and scope; on a bundle, its envelope state, with the observed result and the
 * witness's kid when that state is witness-signed; and the checks that failed on that entry.
 * Without the flag the output is unchanged.
 *
 * A ledger with zero events is reported EMPTY, not OK.
 *
 * Exit codes: 0 = ok, 2 = a check failed or there was nothing to check, 1 = usage.
 * The output lines match the Python CLI's, so either implementation can stand in
 * for the other in a script.
 */

import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

import { AuditLog, type LedgerEntry } from "./audit.js";
import { RawNumber, toPlain, type CJson, type Json } from "./canonical.js";
import {
  WITNESS_SIGNED,
  integrityPosition,
  parseBundle,
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

/** A value printed as it is on an `--entries` line: printable ASCII other than space, `"` and `\`. */
const BARE_VALUE = /^[!#-\[\]-~]+$/;

/**
 * One value on an `--entries` line, byte for byte what the Python CLI prints.
 *
 * The values come from the bundle, which is attacker-supplied, and a line is only worth reading if
 * no value can end it early or start a forged one: a `scope` carrying a newline and a clean-looking
 * second line would otherwise print a fake entry with the real entry's `failed=` attached to it. So
 * a value is printed as it is only when it is printable ASCII with no space, `"` or `\`, and an
 * integer in decimal. Anything else is printed as JSON, with every character outside printable
 * ASCII escaped as \uXXXX and every space as \u0020, so it never contains whitespace and a JSON
 * parser gives the value back.
 */
function entryValue(value: CJson): string {
  if (typeof value === "string" && BARE_VALUE.test(value)) return value;
  return integerText(value) ?? pyJson(value).replace(/ /g, "\\u0020");
}

/**
 * A number Python's `json` reads as an `int`, in decimal, or `null` for anything else. A parsed
 * bundle keeps every number's literal, so `1` and `1.0` stay as distinct as they are in Python. A
 * number that has lost its literal (a report value) is read as an integer when it is integral.
 */
function integerText(value: CJson): string | null {
  if (value instanceof RawNumber) {
    return /^-?(?:0|[1-9][0-9]*)$/.test(value.raw) ? BigInt(value.raw).toString() : null;
  }
  if (typeof value === "number" && Number.isInteger(value)) return BigInt(value).toString();
  return null;
}

/** Python's `json.dumps(value, ensure_ascii=True, separators=(",", ":"))`. */
function pyJson(value: CJson): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return pyJsonString(value);
  const integer = integerText(value);
  if (integer !== null) return integer;
  if (value instanceof RawNumber) return pyFloat(value.value);
  if (typeof value === "number") return pyFloat(value);
  if (Array.isArray(value)) return `[${value.map(pyJson).join(",")}]`;
  return `{${Object.entries(value)
    .map(([key, member]) => `${pyJsonString(key)}:${pyJson(member)}`)
    .join(",")}}`;
}

/**
 * A JSON string as Python's `json` writes it with `ensure_ascii`: printable ASCII as it is, the
 * five short escapes, and every other UTF-16 unit as a lowercase \uXXXX. A character beyond the
 * BMP is already a surrogate pair in a JavaScript string, and Python writes it as the same pair.
 */
function pyJsonString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const unit = s.charCodeAt(i);
    if (unit === 0x22) out += '\\"';
    else if (unit === 0x5c) out += "\\\\";
    else if (unit === 0x0a) out += "\\n";
    else if (unit === 0x0d) out += "\\r";
    else if (unit === 0x09) out += "\\t";
    else if (unit === 0x08) out += "\\b";
    else if (unit === 0x0c) out += "\\f";
    else if (unit >= 0x20 && unit <= 0x7e) out += s[i];
    else out += `\\u${unit.toString(16).padStart(4, "0")}`;
  }
  return `${out}"`;
}

/**
 * Python's `repr` of a float, which `json` writes: the shortest digits that read back as the same
 * number, in positional form from 1e-4 up to below 1e16 with `.0` on an integral value, and in
 * exponent form, with a two-digit exponent at least, outside that range.
 */
function pyFloat(n: number): string {
  if (Number.isNaN(n)) return "NaN";
  if (n === Infinity) return "Infinity";
  if (n === -Infinity) return "-Infinity";
  if (n === 0) return Object.is(n, -0) ? "-0.0" : "0.0";
  const m = /^(-?)([0-9])(?:\.([0-9]+))?e([+-][0-9]+)$/.exec(n.toExponential())!;
  const sign = m[1]!;
  const digits = m[2]! + (m[3] ?? "");
  const exponent = Number(m[4]);
  if (exponent < -4 || exponent >= 16) {
    const mantissa = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    return `${sign}${mantissa}e${exponent < 0 ? "-" : "+"}${String(Math.abs(exponent)).padStart(2, "0")}`;
  }
  if (exponent < 0) return `${sign}0.${"0".repeat(-exponent - 1)}${digits}`;
  const whole = digits.slice(0, exponent + 1).padEnd(exponent + 1, "0");
  const fraction = digits.slice(exponent + 1);
  return `${sign}${whole}.${fraction === "" ? "0" : fraction}`;
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
