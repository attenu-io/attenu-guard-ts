/**
 * attenu-guard — enforced authority attenuation for multi-agent AI systems.
 *
 * A sub-agent's authority can never exceed its parent's, chains have hard
 * ceilings, and any subtree can be revoked in one call — enforced in code, with
 * a hash-chained audit log anyone can verify offline.
 *
 *     import { Authority, Guard, RowLimit, EgressRank } from "attenu-guard";
 *
 *     const orchestrator = Guard.issue("orchestrator", new Authority({
 *       scopes: ["crm.*", "mail.send"],
 *       ceilings: [new RowLimit(100_000), new EgressRank("any")],
 *       ttl: 3600,
 *     }));
 *
 *     const summarizer = orchestrator.delegate("summarizer", new Authority({
 *       scopes: ["crm.read"],
 *       ceilings: [new RowLimit(5_000), new EgressRank("none")],
 *       ttl: 900,
 *     }), "summarise the Q3 pipeline");
 *
 *     const decision = summarizer.check("crm.read", { context: { rows: 4200 } });
 *     if (!decision.allowed) console.log(decision.explain());
 *
 *     summarizer.enforce("crm.export", { context: { egress: "any" } }); // throws
 *
 * The ledger and the evidence bundle use the same wire format as the Python
 * library, verified by cross-language fixtures — a bundle exported by either
 * one verifies with the other.
 */

export { Authority, AuthorityError } from "./authority.js";
export type { AuthorityInit, AuthorityWire } from "./authority.js";

export { Guard, AuthorityDenied, DuplicateOutcomeError } from "./guard.js";
export type {
  AdapterInfo,
  CheckOptions,
  IssueOptions,
  ReceiptInfo,
  RecordDenialOptions,
  RecordOutcomeOptions,
} from "./guard.js";

export {
  BODY_STATES,
  CAPTURES,
  DISPOSITIONS,
  BodyState,
  Capture,
  CompletionResult,
  Decision,
  Disposition,
  Reason,
  ReasonCode,
} from "./reasons.js";
export type {
  BodyStateValue,
  CaptureValue,
  DispositionValue,
  ReasonCodeValue,
  ReasonInit,
} from "./reasons.js";

export { PARAMS_C14N_VERSION, PARAMS_HASH_REASONS, ParamsHashReason, SALT_HEX_LEN, decodeSalt } from "./params.js";
export type { ParamsHashReasonValue } from "./params.js";
export { commit as commitParams } from "./params.js";

export {
  Allow,
  CallLimit,
  Deny,
  EgressRank,
  Prefix,
  RowLimit,
  SpendCap,
  UnknownCeiling,
  ceilingFromWire,
  ctxFieldOf,
  describe,
  isMetered,
  registerCeiling,
} from "./ceilings.js";
export type { Ceiling, CeilingClass, Context } from "./ceilings.js";

export { AuditLog, CommittedAuditError, GENESIS, SCHEMA_VERSION, chainIdOf, hashEntry } from "./audit.js";
export type { Anchor, AuditLogInit, LedgerEntry, Sink } from "./audit.js";

export { Chain, ManualClock, MonotonicClock } from "./chain.js";
export type { Clock, ChainInit, Node } from "./chain.js";

export { StrikePolicy } from "./strikes.js";
export type { StrikeMode, StrikePolicyInit } from "./strikes.js";

export {
  ENVELOPE_ALG,
  ENVELOPE_FAILURES,
  ENVELOPE_MEMBERS,
  ENVELOPE_RESULTS,
  ENVELOPE_SUBJECT_MEMBERS,
  ENVELOPE_TYP,
  ENVELOPE_VERSION,
  EvidenceLeakError,
  LEDGER_FIELDS,
  PROCESS_ASSERTED,
  SUPPORTED_BUNDLE_VERSIONS,
  WITNESS_SIGNED,
  anchorFor,
  delegationGraph,
  denials,
  envelopeSigningInput,
  envelopeSubject,
  exportBundle,
  parseBundle,
  redactionReport,
  signEnvelope,
  verifyBundle,
  verifyEnvelopes,
} from "./evidence.js";
export type {
  Bundle,
  DelegationGraph,
  DenialRow,
  Envelope,
  EnvelopeResult,
  EnvelopeState,
  EnvelopeSummary,
  ExecutionBinding,
  ExportOptions,
  FailureDetail,
  GraphNode,
  Observation,
  RedactionReport,
  RedactionViolation,
  VerifyBundleOptions,
  VerifyChecks,
  VerifyEnvelopesOptions,
  VerifyReport,
  WitnessKey,
} from "./evidence.js";

export {
  Ed25519Signer,
  Ed25519Verifier,
  HS256TestSigner,
  VerifiedChain,
  WireError,
  WireReasonCode,
  b64urlDecode,
  b64urlEncode,
  load,
} from "./wire.js";
export type { LoadOptions, Signer, WireReasonCodeValue } from "./wire.js";

export {
  CanonicalizationError,
  DuplicateMemberError,
  LoneSurrogateError,
  MAX_SAFE_INTEGER,
  NonFiniteNumberError,
  RawNumber,
  UnsafeIntegerError,
  UnsupportedTypeError,
  canonicalBytes,
  canonicalJson,
  compareCodePoints,
  parseJson,
  pyNumber,
  sortedStrings,
  toPlain,
} from "./canonical.js";
export type { CJson, Json } from "./canonical.js";

export { VERSION } from "./version.js";
