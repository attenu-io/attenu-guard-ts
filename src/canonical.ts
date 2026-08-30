/** RFC 8785 JSON Canonicalization Scheme (JCS), with no runtime dependencies. */

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class NonFiniteNumberError extends CanonicalizationError {}
export class LoneSurrogateError extends CanonicalizationError {}
export class UnsupportedTypeError extends CanonicalizationError {}

/**
 * An integer's magnitude exceeds what binary64 can represent exactly.
 *
 * RFC 8785 numbers ARE IEEE 754 doubles: every JCS number, integer or not, is
 * rendered from a `number`, which JavaScript already stores as a double — so
 * an integer past ±(2**53-1) may already have collided with its neighbour
 * before canonicalization ever runs (`9007199254740992 === 9007199254740993`
 * is `true`). Unlike Python, JS has no separate arbitrary-precision integer
 * type to fall back on, so the only safe rule is the same one: reject rather
 * than silently render a value that may not be the one the caller meant.
 */
export class UnsafeIntegerError extends CanonicalizationError {}

/**
 * The largest (and, negated, the smallest) integer magnitude a binary64
 * double represents exactly. Every integer strictly beyond this range raises
 * `UnsafeIntegerError` instead of being canonicalized.
 */
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER; // 9007199254740991
const MAX_SAFE_INTEGER_BIGINT = 9007199254740991n;

function checkSafeInteger(value: number): void {
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new UnsafeIntegerError(
      `integer ${value} exceeds the safe range ±${MAX_SAFE_INTEGER} for a binary64 ` +
        "signing surface (RFC 8785 numbers are IEEE 754 doubles)",
    );
  }
}

/**
 * Does `raw` look like a bare decimal integer literal (no `.`, `e`, or `E`)?
 * Only such literals can carry MORE precision than the double they parse
 * into, so only they need checking against the original text rather than the
 * already-rounded value.
 */
function isIntegerLiteralText(raw: string): boolean {
  return /^-?\d+$/.test(raw);
}

/**
 * Check a parsed number's ORIGINAL source text, before the double it parsed
 * into (which may already have silently rounded two different literals to the
 * same value) is used for anything.
 */
function checkSafeIntegerLiteral(raw: string): void {
  if (!isIntegerLiteralText(raw)) return;
  const n = BigInt(raw);
  const magnitude = n < 0n ? -n : n;
  if (magnitude > MAX_SAFE_INTEGER_BIGINT) {
    throw new UnsafeIntegerError(
      `integer ${raw} exceeds the safe range ±${MAX_SAFE_INTEGER} for a binary64 ` +
        "signing surface (RFC 8785 numbers are IEEE 754 doubles)",
    );
  }
}

/** Raised while parsing when an object repeats a member name. */
export class DuplicateMemberError extends SyntaxError {
  constructor(readonly member: string) {
    super(`duplicate JSON object member ${JSON.stringify(member)}`);
    this.name = "DuplicateMemberError";
  }
}

/** A parsed JSON number, retaining its source spelling for syntax-sensitive checks. */
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

export type CJson =
  | null
  | boolean
  | number
  | string
  | RawNumber
  | CJson[]
  | { [key: string]: CJson };

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** Compare by Unicode code point for semantic lists that mirror Python `sorted`. */
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

export function sortedStrings(values: Iterable<string>): string[] {
  return Array.from(values).sort(compareCodePoints);
}

/** Python-style numeric display used only in human-readable ceiling descriptions. */
export function pyNumber(n: number): string {
  if (Number.isNaN(n)) return "NaN";
  if (!Number.isFinite(n)) return n > 0 ? "Infinity" : "-Infinity";
  if (Object.is(n, -0)) return "-0.0";
  if (Number.isInteger(n) && Math.abs(n) < 1e21) return n.toFixed(0);
  const parsed = /^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(n.toExponential());
  if (!parsed) return String(n);
  const sign = parsed[1]!;
  const digits = parsed[2]! + (parsed[3] ?? "");
  const exp = parseInt(parsed[4]!, 10);
  if (exp < -4 || exp >= 16) {
    const mantissa = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    return `${sign}${mantissa}e${exp < 0 ? "-" : "+"}${String(Math.abs(exp)).padStart(2, "0")}`;
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

function validateUnicode(value: string): void {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new LoneSurrogateError("lone UTF-16 surrogates are not permitted");
      }
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new LoneSurrogateError("lone UTF-16 surrogates are not permitted");
    }
  }
}

function jcsString(value: string): string {
  validateUnicode(value);
  return JSON.stringify(value);
}

function jcsNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new NonFiniteNumberError("non-finite numbers are not permitted");
  }
  checkSafeInteger(value);
  return JSON.stringify(value);
}

function unsupported(value: unknown): never {
  const kind = value === null ? "null" : typeof value;
  throw new UnsupportedTypeError(`not a supported JSON value: ${kind}`);
}

function serialize(value: unknown, active: WeakSet<object>): string {
  if (value === null) return "null";
  if (value instanceof RawNumber) {
    // Check the ORIGINAL text first: `Number(raw)` may already have rounded
    // two different out-of-range literals to the identical double, so the
    // rounded `.value` alone cannot always be trusted to catch what the wire
    // actually said.
    checkSafeIntegerLiteral(value.raw);
    return jcsNumber(value.value);
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return jcsNumber(value);
    case "string":
      return jcsString(value);
    case "undefined":
    case "bigint":
    case "symbol":
    case "function":
      return unsupported(value);
  }

  if (active.has(value)) throw new UnsupportedTypeError("cyclic JSON values are not permitted");
  active.add(value);
  try {
    if (Array.isArray(value)) {
      const own = Reflect.ownKeys(value);
      for (const key of own) {
        if (key === "length") continue;
        if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= value.length) {
          throw new UnsupportedTypeError("JSON arrays may not carry extra properties");
        }
      }
      const items: string[] = [];
      for (let i = 0; i < value.length; i++) {
        if (!Object.prototype.hasOwnProperty.call(value, i)) {
          throw new UnsupportedTypeError("sparse JSON arrays are not permitted");
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, String(i))!;
        if (!descriptor.enumerable || !("value" in descriptor)) {
          throw new UnsupportedTypeError("JSON arrays may contain only enumerable data elements");
        }
        items.push(serialize(descriptor.value, active));
      }
      return `[${items.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new UnsupportedTypeError("only plain JSON objects are permitted");
    }
    const symbols = Object.getOwnPropertySymbols(value);
    if (symbols.length > 0) throw new UnsupportedTypeError("JSON object member names must be strings");
    const keys = Object.getOwnPropertyNames(value);
    const members = new Map<string, unknown>();
    for (const key of keys) {
      validateUnicode(key);
      const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
      if (!descriptor.enumerable || !("value" in descriptor)) {
        throw new UnsupportedTypeError("JSON objects may contain only enumerable data properties");
      }
      members.set(key, descriptor.value);
    }
    // RFC 8785 sorts property names by their raw UTF-16 code units. JavaScript's
    // default string ordering is exactly that ordering.
    keys.sort();
    return `{${keys
      .map((key) => `${jcsString(key)}:${serialize(members.get(key), active)}`)
      .join(",")}}`;
  } finally {
    active.delete(value);
  }
}

/** Return an RFC 8785 canonical JSON string. */
export function canonicalJson(value: CJson | undefined): string {
  return serialize(value, new WeakSet<object>());
}

/** The canonical UTF-8 bytes used by every hash, seal, and signature. */
export function canonicalBytes(value: CJson | undefined): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

/** Strip `RawNumber` wrappers, yielding ordinary JavaScript values. */
export function toPlain<T = Json>(value: CJson | undefined): T {
  if (value instanceof RawNumber) return value.value as unknown as T;
  if (Array.isArray(value)) return value.map((item) => toPlain(item)) as unknown as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, Json> = {};
    for (const [key, item] of Object.entries(value)) {
      Object.defineProperty(out, key, {
        value: toPlain(item),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return out as unknown as T;
  }
  return value as unknown as T;
}

/** Parse JSON without losing number spellings, while rejecting duplicates. */
export function parseJson(text: string): CJson {
  const parser = new Parser(text);
  parser.skipWhitespace();
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.atEnd()) parser.fail("unexpected trailing data");
  return value;
}

const NUMBER_RE = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;

class Parser {
  private i = 0;
  constructor(private readonly source: string) {}

  atEnd(): boolean {
    return this.i >= this.source.length;
  }

  fail(message: string): never {
    throw new SyntaxError(`${message} at position ${this.i}`);
  }

  skipWhitespace(): void {
    while (this.i < this.source.length && /[\t\n\r ]/.test(this.source[this.i]!)) this.i++;
  }

  parseValue(): CJson {
    if (this.atEnd()) this.fail("unexpected end of input");
    const char = this.source[this.i]!;
    if (char === "{") return this.parseObject();
    if (char === "[") return this.parseArray();
    if (char === '"') return this.parseString();
    if (this.source.startsWith("true", this.i)) return (this.i += 4), true;
    if (this.source.startsWith("false", this.i)) return (this.i += 5), false;
    if (this.source.startsWith("null", this.i)) return (this.i += 4), null;
    if (
      this.source.startsWith("NaN", this.i) ||
      this.source.startsWith("Infinity", this.i) ||
      this.source.startsWith("-Infinity", this.i)
    ) {
      throw new NonFiniteNumberError("non-finite numbers are not permitted");
    }
    return this.parseNumber();
  }

  private parseObject(): { [key: string]: CJson } {
    this.i++;
    const out = Object.create(null) as Record<string, CJson>;
    this.skipWhitespace();
    if (this.source[this.i] === "}") return this.i++, out;
    for (;;) {
      this.skipWhitespace();
      if (this.source[this.i] !== '"') this.fail("expected an object key");
      const key = this.parseString();
      if (Object.prototype.hasOwnProperty.call(out, key)) throw new DuplicateMemberError(key);
      this.skipWhitespace();
      if (this.source[this.i] !== ":") this.fail("expected ':'");
      this.i++;
      this.skipWhitespace();
      out[key] = this.parseValue();
      this.skipWhitespace();
      const char = this.source[this.i];
      if (char === ",") {
        this.i++;
        continue;
      }
      if (char === "}") return this.i++, out;
      this.fail("expected ',' or '}'");
    }
  }

  private parseArray(): CJson[] {
    this.i++;
    const out: CJson[] = [];
    this.skipWhitespace();
    if (this.source[this.i] === "]") return this.i++, out;
    for (;;) {
      this.skipWhitespace();
      out.push(this.parseValue());
      this.skipWhitespace();
      const char = this.source[this.i];
      if (char === ",") {
        this.i++;
        continue;
      }
      if (char === "]") return this.i++, out;
      this.fail("expected ',' or ']'");
    }
  }

  private parseString(): string {
    this.i++;
    let out = "";
    for (;;) {
      if (this.atEnd()) this.fail("unterminated string");
      const char = this.source[this.i]!;
      if (char === '"') {
        this.i++;
        validateUnicode(out);
        return out;
      }
      if (char.charCodeAt(0) < 0x20) this.fail("unescaped control character");
      if (char !== "\\") {
        out += char;
        this.i++;
        continue;
      }
      this.i++;
      const escape = this.source[this.i];
      this.i++;
      switch (escape) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const hex = this.source.slice(this.i, this.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          this.i += 4;
          break;
        }
        default: this.fail("bad escape");
      }
    }
  }

  private parseNumber(): RawNumber {
    const match = NUMBER_RE.exec(this.source.slice(this.i));
    if (!match) this.fail("expected a value");
    const raw = match[0];
    this.i += raw.length;
    const value = Number(raw);
    if (!Number.isFinite(value)) {
      throw new NonFiniteNumberError("non-finite numbers are not permitted");
    }
    return new RawNumber(raw, value);
  }
}
