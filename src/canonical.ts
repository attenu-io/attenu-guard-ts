/**
 * canonical.ts — byte-exact interoperability with the Python implementation.
 *
 * Every hash, seal and signature in Attenu is taken over a canonical JSON
 * serialisation. The Python library produces those bytes with
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, whose defaults
 * include `ensure_ascii=True`. `JSON.stringify` differs from that in three
 * ways that would each silently break cross-language verification:
 *
 *   1. key order — `JSON.stringify` preserves insertion order, Python sorts;
 *   2. non-ASCII — Python escapes every code point above U+007E as `\uXXXX`
 *      (astral characters as a surrogate pair), `JSON.stringify` emits them raw;
 *   3. numbers — Python distinguishes `int` from `float` (`100` vs `100.0`) and
 *      switches to exponential notation at different magnitudes than JavaScript
 *      (`1e-05` where `String()` gives `0.00001`).
 *
 * (1) and (2) are handled by `canonicalJson` below. (3) cannot be solved by a
 * serialiser alone, because a JavaScript `number` has forgotten whether the
 * document said `100` or `100.0`. So a document that is going to be re-hashed —
 * a ledger or a bundle produced elsewhere — is read with `parseJson`, which
 * keeps each number's original literal alongside its value as a `RawNumber`.
 * `canonicalJson` re-emits that literal verbatim, so a Python-written entry
 * hashes to the byte-identical digest here. Values created in this library are
 * plain numbers, and `pyNumber` formats them the way Python's `json` would, so
 * the reverse direction round-trips too.
 */

/** A number as it was written in the source document, plus its parsed value. */
export class RawNumber {
  constructor(
    readonly raw: string,
    readonly value: number,
  ) {}
  valueOf(): number {
    return this.value;
  }
  toJSON(): number {
    return this.value;
  }
}

/** A JSON value that may still carry original number literals. */
export type CJson =
  | null
  | boolean
  | number
  | string
  | RawNumber
  | CJson[]
  | { [key: string]: CJson };

/** A plain JSON value — what the rest of the library works with. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Compare two strings by Unicode code point, as Python's `sorted` does. */
export function compareCodePoints(a: string, b: string): number {
  const ca = Array.from(a);
  const cb = Array.from(b);
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    const x = ca[i]!.codePointAt(0)!;
    const y = cb[i]!.codePointAt(0)!;
    if (x !== y) return x < y ? -1 : 1;
  }
  return ca.length - cb.length;
}

/** Sort strings by code point (Python's `sorted(list_of_str)`). */
export function sortedStrings(values: Iterable<string>): string[] {
  return Array.from(values).sort(compareCodePoints);
}

/**
 * Format a number the way Python's `json.dumps` would.
 *
 * Integral values are emitted without a decimal point, matching a Python `int`.
 * A TypeScript number cannot record that it was meant to be the float `100.0`,
 * so such a value serialises as `100`; Python reads that back as an `int` and
 * re-emits `100`, which keeps the chain verifiable in both directions. Values
 * with a fractional part follow CPython's `repr`: shortest round-tripping
 * digits, exponential notation when the decimal exponent is below -4 or at
 * least 16, a two-digit signed exponent, and always a decimal point otherwise.
 */
export function pyNumber(n: number): string {
  if (Number.isNaN(n)) return "NaN";
  if (!Number.isFinite(n)) return n > 0 ? "Infinity" : "-Infinity";
  if (Object.is(n, -0)) return "-0.0";
  if (Number.isInteger(n) && Math.abs(n) < 1e21) return n.toFixed(0);
  return pyFloatRepr(n);
}

function pyFloatRepr(n: number): string {
  // `toExponential()` with no argument yields the shortest digit string that
  // uniquely identifies the value — the same "shortest round-trip" digits
  // CPython's repr produces. Only the layout around them differs.
  const parsed = /^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(n.toExponential());
  if (!parsed) return String(n); // unreachable for a finite double
  const sign = parsed[1]!;
  const digits = parsed[2]! + (parsed[3] ?? "");
  const exp = parseInt(parsed[4]!, 10);

  if (exp < -4 || exp >= 16) {
    const mantissa = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const expSign = exp < 0 ? "-" : "+";
    return `${sign}${mantissa}e${expSign}${String(Math.abs(exp)).padStart(2, "0")}`;
  }
  if (exp >= 0) {
    const body =
      digits.length > exp + 1
        ? `${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`
        : `${digits.padEnd(exp + 1, "0")}.0`;
    return sign + body;
  }
  return `${sign}0.${"0".repeat(-exp - 1)}${digits}`;
}

/** Escape a string the way Python's `json.dumps(ensure_ascii=True)` does. */
export function pyString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    const code = s.charCodeAt(i);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x09) out += "\\t";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0d) out += "\\r";
    else if (code < 0x20 || code > 0x7e) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/**
 * Serialise to the exact bytes Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))` produces:
 * sorted keys, no incidental whitespace, ASCII-escaped strings.
 *
 * Object entries whose value is `undefined` are omitted, matching a Python dict
 * that simply never held the key. `null` is kept — it is a value.
 */
export function canonicalJson(value: CJson | undefined): string {
  return pyJsonDumps(value, ",", ":");
}

/**
 * Serialise with sorted keys and ASCII escaping, choosing the separators.
 *
 * `canonicalJson` uses the compact `(",", ":")` pair every hash is taken over.
 * The `.jsonl` ledger on disk is written with Python's DEFAULT separators
 * (`", "` and `": "`), so a line read back by either language re-serialises to
 * the same bytes its writer produced.
 */
export function pyJsonDumps(
  value: CJson | undefined,
  itemSeparator = ", ",
  keySeparator = ": ",
): string {
  if (value === null || value === undefined) return "null";
  if (value instanceof RawNumber) return value.raw;
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return pyNumber(value);
    case "string":
      return pyString(value);
  }
  if (Array.isArray(value)) {
    return (
      "[" + value.map((v) => pyJsonDumps(v, itemSeparator, keySeparator)).join(itemSeparator) + "]"
    );
  }
  const keys = sortedStrings(Object.keys(value).filter((k) => value[k] !== undefined));
  return (
    "{" +
    keys
      .map((k) => `${pyString(k)}${keySeparator}${pyJsonDumps(value[k]!, itemSeparator, keySeparator)}`)
      .join(itemSeparator) +
    "}"
  );
}

/** The canonical bytes — what every hash, seal and signature is taken over. */
export function canonicalBytes(value: CJson | undefined): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

/** Strip `RawNumber` wrappers, yielding ordinary JavaScript values. */
export function toPlain<T = Json>(value: CJson | undefined): T {
  if (value instanceof RawNumber) return value.value as unknown as T;
  if (Array.isArray(value)) return value.map((v) => toPlain(v)) as unknown as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, Json> = {};
    for (const [k, v] of Object.entries(value)) out[k] = toPlain(v);
    return out as unknown as T;
  }
  return value as unknown as T;
}

/**
 * Parse JSON, keeping every number's original literal.
 *
 * `JSON.parse` is not used: it discards the literal, and with it the ability to
 * reproduce the bytes the writer hashed. Objects preserve their key order for
 * readability; canonical serialisation sorts them anyway.
 */
export function parseJson(text: string): CJson {
  const p = new Parser(text);
  p.skipWhitespace();
  const value = p.parseValue();
  p.skipWhitespace();
  if (!p.atEnd()) p.fail("unexpected trailing data");
  return value;
}

const NUMBER_RE = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;

class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  atEnd(): boolean {
    return this.i >= this.s.length;
  }

  fail(message: string): never {
    throw new SyntaxError(`${message} at position ${this.i}`);
  }

  skipWhitespace(): void {
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else break;
    }
  }

  parseValue(): CJson {
    if (this.atEnd()) this.fail("unexpected end of input");
    const c = this.s[this.i]!;
    if (c === "{") return this.parseObject();
    if (c === "[") return this.parseArray();
    if (c === '"') return this.parseString();
    if (this.s.startsWith("true", this.i)) return (this.i += 4), true;
    if (this.s.startsWith("false", this.i)) return (this.i += 5), false;
    if (this.s.startsWith("null", this.i)) return (this.i += 4), null;
    return this.parseNumber();
  }

  private parseObject(): { [key: string]: CJson } {
    this.i++; // {
    const out: { [key: string]: CJson } = {};
    this.skipWhitespace();
    if (this.s[this.i] === "}") return this.i++, out;
    for (;;) {
      this.skipWhitespace();
      if (this.s[this.i] !== '"') this.fail("expected an object key");
      const key = this.parseString();
      this.skipWhitespace();
      if (this.s[this.i] !== ":") this.fail("expected ':'");
      this.i++;
      this.skipWhitespace();
      out[key] = this.parseValue();
      this.skipWhitespace();
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "}") return this.i++, out;
      this.fail("expected ',' or '}'");
    }
  }

  private parseArray(): CJson[] {
    this.i++; // [
    const out: CJson[] = [];
    this.skipWhitespace();
    if (this.s[this.i] === "]") return this.i++, out;
    for (;;) {
      this.skipWhitespace();
      out.push(this.parseValue());
      this.skipWhitespace();
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        continue;
      }
      if (c === "]") return this.i++, out;
      this.fail("expected ',' or ']'");
    }
  }

  private parseString(): string {
    this.i++; // opening quote
    let out = "";
    for (;;) {
      if (this.atEnd()) this.fail("unterminated string");
      const c = this.s[this.i]!;
      if (c === '"') return this.i++, out;
      if (c !== "\\") {
        out += c;
        this.i++;
        continue;
      }
      this.i++;
      const esc = this.s[this.i];
      this.i++;
      switch (esc) {
        case '"':
          out += '"';
          break;
        case "\\":
          out += "\\";
          break;
        case "/":
          out += "/";
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const hex = this.s.slice(this.i, this.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          this.i += 4;
          break;
        }
        default:
          this.fail("bad escape");
      }
    }
  }

  private parseNumber(): RawNumber {
    const m = NUMBER_RE.exec(this.s.slice(this.i));
    if (!m) this.fail("expected a value");
    const raw = m[0];
    this.i += raw.length;
    return new RawNumber(raw, Number(raw));
  }
}
