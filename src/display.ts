/**
 * display.ts — how a value from a ledger, a bundle or a trust file is printed into a line of text.
 *
 * A ledger, a bundle and the envelopes beside it are untrusted input, and their values reach a
 * terminal through the verifier's finding messages, `attenu-guard verify`, and `--entries`. A value
 * that carries a line break can end the line it is printed on and start a forged one: a node named
 * "n1\nOK" would print a line reading `OK` under a failed verification. Two rules cover every place
 * such a value is printed, and both are the Python implementation's, byte for byte:
 *
 *   - a value printed bare goes through `shown`: as its text when that text is printable ASCII
 *     0x21-0x7E other than `"` and `\`, so clean input prints exactly as it always has, and as its
 *     `escaped` JSON form otherwise, which holds no whitespace and no line break;
 *   - a value printed the way Python's `repr` prints it goes through `pyRepr`, which quotes and
 *     escapes a string exactly as `repr` does. Python's `{x!r}` needs no other rule, so neither
 *     does this.
 */

import { RawNumber, type CJson } from "./canonical.js";

/** The bare form: printable ASCII 0x21-0x7E without `"` (0x22) or `\` (0x5C). */
export const BARE = /^[!#-\[\]-~]+$/;

/**
 * Python's `repr` of a `str`: single quotes unless the text holds a `'` and no `"`, the quote and
 * the backslash escaped, `\t` `\n` `\r` by name, any other control character or DEL as `\xHH`, and
 * a non-ASCII character as it is when Python counts it printable, as `\xHH`, `\uHHHH` or
 * `\UHHHHHHHH` when it does not. Lower-case hex throughout, as CPython writes it.
 */
export function pyStrRepr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  // By code point: a surrogate pair is one character to Python, and a lone surrogate is one too.
  for (const ch of s) out += ch === quote || ch === "\\" ? `\\${ch}` : reprChar(ch);
  return out + quote;
}

/**
 * `text` with every character Python's `repr` would escape written as that escape, and nothing
 * else changed: no quotes added, no backslash doubled. For a parser's message, which can quote a
 * fragment of the input it refused: one line, always.
 */
export function oneLine(text: string): string {
  let out = "";
  for (const ch of text) out += reprChar(ch);
  return out;
}

/** One character as Python's `repr` writes it inside a string, the quote and backslash aside. */
function reprChar(ch: string): string {
  const cp = ch.codePointAt(0)!;
  if (ch === "\t") return "\\t";
  if (ch === "\n") return "\\n";
  if (ch === "\r") return "\\r";
  if (cp < 0x20 || cp === 0x7f) return `\\x${hex(cp, 2)}`;
  if (cp < 0x7f || !NOT_PRINTABLE.test(ch)) return ch;
  if (cp <= 0xff) return `\\x${hex(cp, 2)}`;
  if (cp <= 0xffff) return `\\u${hex(cp, 4)}`;
  return `\\U${hex(cp, 8)}`;
}

/**
 * What Python's `str.isprintable` is false for, outside ASCII: the Unicode categories "Other"
 * (Cc, Cf, Cs, Co, Cn) and "Separator" (Zl, Zp, Zs). The space is the one exception, and it is
 * ASCII, which `pyStrRepr` decides before it asks.
 */
const NOT_PRINTABLE = /^[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]$/u;

function hex(n: number, width: number): string {
  return n.toString(16).padStart(width, "0");
}

/**
 * Python-style `repr` for the value types a finding message carries. A number that kept its
 * literal prints as Python prints what `json` reads from it (`1` an int, `1.0` a float). A number
 * that has lost its literal prints as an integer when it is integral, and otherwise as Python's
 * repr of the float, `1e-05` where JavaScript writes 0.00001.
 */
export function pyRepr(value: CJson): string {
  if (value === null) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  if (value instanceof RawNumber) return integerText(value) ?? pyFloat(value.value);
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : pyFloat(value);
  if (typeof value === "string") return pyStrRepr(value);
  // Containers reach here only on hostile input — a member that is a list or an object where the
  // contract wants a scalar. Rendered the way Python's repr renders them.
  if (Array.isArray(value)) return `[${value.map(pyRepr).join(", ")}]`;
  if (typeof value === "object") {
    return `{${Object.entries(value)
      .map(([k, v]) => `${pyStrRepr(k)}: ${pyRepr(v)}`)
      .join(", ")}}`;
  }
  return JSON.stringify(value);
}

/**
 * Python's `str()` where a message interpolates a value bare (`{x}`) rather than through `repr`
 * (`{x!r}`): the same rendering for every type except a string, which `str` leaves unquoted.
 */
export function pyStr(value: CJson): string {
  return typeof value === "string" ? value : pyRepr(value);
}

/**
 * `value` as a finding message prints it bare: its text (Python's `str`) when that text is bare,
 * its `escaped` JSON form otherwise. Clean values print exactly as they always have. An absent
 * value is Python's `None`.
 */
export function shown(value: CJson | undefined): string {
  const v = value === undefined ? null : value;
  return shownText(pyStr(v), v);
}

/**
 * `shown`, for a caller that already holds the text Python's `str` gives for `value` (a ceiling
 * renders its numbers the way Python renders a float): the text when it is bare, `value`'s
 * `escaped` form otherwise.
 */
export function shownText(text: string, value: CJson): string {
  return BARE.test(text) ? text : escaped(value);
}

/**
 * `value` as whitespace-free, ASCII-only JSON: Python's
 * `json.dumps(value, ensure_ascii=True, separators=(",", ":"))`, with every space then written as
 * `\u0020`. Inside a string that is `\"` and `\\`, the short escapes `\n` `\t` `\r` `\b` `\f`, and
 * a lower-case `\uXXXX` for every other UTF-16 unit outside printable ASCII. That form holds no
 * whitespace and no line break, and a JSON parser gives the value back.
 */
export function escaped(value: CJson): string {
  return pyJson(value).replace(/ /g, "\\u0020");
}

/**
 * A number Python's `json` reads as an `int`, in decimal, or `null` for anything else. A parsed
 * bundle keeps every number's literal, so `1` and `1.0` stay as distinct as they are in Python. A
 * number that has lost its literal is read as an integer when it is integral.
 */
export function integerText(value: CJson): string | null {
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
    else out += `\\u${hex(unit, 4)}`;
  }
  return `${out}"`;
}

/**
 * Python's `repr` of a float, which `json` writes: the shortest digits that read back as the same
 * number, in positional form from 1e-4 up to below 1e16 with `.0` on an integral value, and in
 * exponent form, with a two-digit exponent at least, outside that range.
 */
export function pyFloat(n: number): string {
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
