# attenu-guard (TypeScript)

Permissions for multi-agent systems, enforced at the point of the call.

A sub-agent holds a subset of what its parent holds. Every tool call is checked
against the calling agent's own permissions, every handoff narrows them, and
every decision lands in a hash-chained log that anyone can verify offline —
without this library, its authors, or a network.

This is the TypeScript implementation. It writes the same ledger and the same
evidence bundle as the [Python library](https://github.com/attenu-io/attenu-guard),
and reads either one's output.

- Zero runtime dependencies — Node's own `crypto`, nothing else
- ESM and CommonJS builds, types included
- Node 20 and above (the LangGraph.js adapter depends on `langsmith`, which needs the global WebCrypto that Node 19 introduced; Node 18 is end-of-life)

## Install

```
npm install attenu-guard
```

## Verify a run you did not produce

You have a bundle exported from an agent run, and the public half of the key
that anchored it. You do not need an account, a network, or the system that
produced it.

```
npx attenu-guard verify run.bundle.json --pubkey <hex>
```

```
integrity=True monotonicity=True containment=True anchor=verified nodes=3 actions_checked=2
OK
```

Three things were checked from the file alone:

- **integrity** — every entry hashes to the next, and the head matches the signed
  anchor. Nothing was inserted, removed, or rewritten afterwards.
- **monotonicity** — every delegated agent's permissions are a subset of its
  parent's, all the way down.
- **containment** — every allowed action fell inside what the acting agent held
  at the time.

Those are different findings. A broken chain says the record was edited. A
broken monotonicity check says the record is honest and the delegation was not —
which points at a different person. The same checks are available in code:

```ts
import { parseBundle, verifyBundle, Ed25519Verifier } from "attenu-guard";
import { readFileSync } from "node:fs";

const bundle = parseBundle(readFileSync("run.bundle.json", "utf8"));
const report = verifyBundle(bundle, new Ed25519Verifier(Buffer.from(pubkeyHex, "hex")));

report.ok;       // false if any check failed
report.checks;   // { integrity, monotonicity, containment, anchor }
report.failures; // one line per finding
```

Pass `null` instead of a key and the chain, subset and containment checks still
run; the anchor is reported as `not checked`, and `ok` then means *consistent*
rather than *verified* — a consistent full rewrite by someone holding the signing
key cannot be excluded without the key.

> **Want to try this before wiring it in?** The repo ships a sample: from a clone,
> `npx attenu-guard@latest verify test/fixtures/clean_ed25519.bundle.json --pubkey d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
> prints the same `anchor=verified` / `OK` result shown above. For the three-bundle
> version — clean, tampered, widened, each a different kind of failure — see the
> [Python library's walkthrough](https://github.com/attenu-io/attenu-guard/blob/main/examples/verify/README.md).

## Guard a delegation chain

```ts
import { Authority, Guard, RowLimit, EgressRank } from "attenu-guard";

const orchestrator = Guard.issue("orchestrator", new Authority({
  scopes: ["crm.*", "mail.send"],
  ceilings: [new RowLimit(100_000), new EgressRank("any")],
  ttl: 3600,
}));

// The handoff is where permissions narrow. A request wider than the parent
// holds comes back narrowed — `fs.write` was never the orchestrator's to give.
const summarizer = orchestrator.delegate("summarizer", new Authority({
  scopes: ["crm.read", "fs.write"],
  ceilings: [new RowLimit(5_000), new EgressRank("none")],
  ttl: 900,
}), "summarise the Q3 pipeline");

summarizer.authority.scopes;            // Set { "crm.read" }
summarizer.isNarrowerThan(orchestrator); // true, by construction

const decision = summarizer.check("crm.read", { context: { rows: 4200 } });
if (!decision.allowed) console.log(decision.explain());

summarizer.enforce("crm.export", { context: { egress: "any" } }); // throws AuthorityDenied
```

`check` returns a `Decision` and never throws — a denial is an outcome to reason
about, not a bug. `enforce` throws `AuthorityDenied` where a denial should stop
the caller. `wouldAllow` runs the same evaluation and writes nothing, so a
planner can ask without leaving a record of an attempt.

Beyond scopes, a chain has ceilings no single-agent permission model expresses:
row and spend caps, an ordered egress rank, per-scope call limits that meter
themselves, membership and prefix bounds, a TTL, and depth and fanout limits on
the tree. `revoke` cascades to a whole subtree; `revokeAgent` bans a principal
chain-wide, so a framework that hands off to it again cannot mint it fresh
permissions. A constraint type this build does not recognise denies rather than
going unenforced.

Export the evidence when the run is done:

```ts
import { exportBundle, Ed25519Signer } from "attenu-guard";

const signer = Ed25519Signer.generate();
const bundle = exportBundle(orchestrator.auditLog(), signer);
// Publish the bundle; distribute signer.publicBytesRaw() out of band.
```

## LangGraph.js

```ts
import { ToolNode } from "@langchain/langgraph/prebuilt";
import { delegateTo, guardTools, toolArgs } from "attenu-guard/adapters/langgraph";

const researcher = delegateTo(supervisor, {
  agentId: "researcher",
  request: new Authority({ scopes: ["crm.read"], ceilings: [new RowLimit(500)], ttl: 900 }),
  task: "summarise the pipeline",
});

const node = new ToolNode(guardTools(researcher, [crmQuery, wireMoney], {
  scopes: { crm_query: "crm.read", wire_money: "payments.send" },
  contexts: { crm_query: (input) => ({ rows: toolArgs(input).limit }) },
  onDenied: (decision) => `Denied by attenu-guard: ${decision.explain()}`,
}));
```

`wire_money` is refused: the researcher does not hold `payments.send`, and the
supervisor could not have granted it either. The tool body never runs. With
`onDenied` the model sees the refusal and can re-plan; leave it out and the call
throws `AuthorityDenied` instead.

**Which hook this uses.** LangGraph.js exposes no public before-tool-call hook —
`ToolNode` resolves the tool itself and calls `tool.invoke(toolCall, runtime)`
inside a `protected runTool`. So the adapter takes the tool-wrapping form:
`guardTool` returns a stand-in whose `invoke` authorizes first and forwards
everything else — `name`, `description`, `schema` — to the original, which is
all `ToolNode` matches on. `guardNode` wraps any node callable the same way, and
`addGuardedNode` registers one on a graph. LangGraph is never imported by the
adapter; it is a devDependency here, used to test against the real `ToolNode`.

## Cross-language interoperability

Same bundle format as the Python library, verified by cross-language fixtures.
`tools/gen_fixtures.py` generates `test/fixtures/` from the Python package —
canonical-form vectors, entry-hash vectors, `meet` and subsumption cases, a raw
ledger, and one bundle per tamper mode with the report Python produces for each.
The suite reproduces all of it, and a separate test writes a ledger and bundle
here and has the Python CLI verify them, so both directions are covered.

Versions 0.2 and later use [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) for every
signed or hashed JSON surface: Delegation Tokens, ledger entries, anchors and
evidence bundles. Tokens, ledger entries, anchors and bundles emit
`"c14n":"JCS"` as an informational label. Verifiers enforce JCS from canonical
bytes and hashes regardless of that label. Duplicate object members, non-finite
numbers, lone UTF-16 surrogates and non-canonical spellings are rejected instead
of being normalized after verification.

This is the only supported format. There is no 0.1 compatibility reader or
dual-signing mode. The 19 committed interop vectors include the separating cases
for number spelling, raw Unicode, UTF-16 member ordering, large integers,
duplicates, non-finite values and an unmarked canonical header.

`test/fixtures/vectors/bundles/bundle_vectors_v1.json` is the second, bundle-level
suite: whole evidence bundles for `verifyBundle`, the check an auditor runs on a
published ledger with no engine and no vendor in the loop. The token vectors pin
what a delegation token means; these pin what the LEDGER of a run has to satisfy.
A bundle verifier reports a LIST of failures rather than one reject reason, so
each rejecting case declares the minimal set of `{reason, seq, node}` that MUST
appear, at that exact position. A conformant verifier may report more, never
fewer and never elsewhere. `verifyBundle` returns those positions as
`failure_details`, the structured twin of `failures`: one
`{reason, seq, node, call_id, detail}` entry per string, in the same order.

`test/fixtures/vectors/envelopes/envelope_vectors_v1.json` is the third suite:
observer envelopes. An envelope is a witness's Ed25519 signature over the
IDENTITY of one committed ledger entry — `chain_id`, `node`, `seq`,
`entry_hash`, `event`, and `call_id` on an allow — carried beside the ledger in
a bundle's top-level `envelopes` array. It answers the one question the other
two suites cannot: was this delegation event signed by something outside the
process that wrote it? An envelope is never required, and a bundle without them
verifies exactly as before with every entry reporting `process-asserted`. A
present one has to verify, and a broken one lands in the same failure list under
one of seven named reasons. Pass the trust set as
`verifyBundle(bundle, signer, { witnessKeys })`, or `attenu-guard verify
--witness-keys FILE` from the command line; whose signatures count is yours to
decide, so the keys come from you and never from the bundle. The report carries
the per-entry state, the result and the report line — `witness-signed
(matched)`, and so on — for every entry, so a reader sees which hops were
covered before reading which one failed.

One entry, at most one envelope. A second envelope naming a `subject.seq` an
earlier one in the same array already named is `envelope_duplicate_subject` at
the covered entry, and that entry reports `process-asserted`: two observations
of one event contradict each other by construction, and an entry whose coverage
is disputed must not read as clean.

## What it does not do

- It does not decide what permissions a task needs. You state them; this library
  enforces that a child never exceeds its parent and records what happened.
- It does not sandbox anything. A tool called around the guard is not guarded.
- The in-process integrity seal catches bugs and casual mutation, not code
  running in the same process. Tamper-evidence comes from the signed bundle.
- `HS256TestSigner` is for tests and local development. It is symmetric, so
  anyone who can verify can also forge. Use `Ed25519Signer` in production.

## Development

```
npm install
npm run build
npm test
```

`npm test` builds first. The Python-CLI interoperability test skips unless a
Python `attenu-guard` is reachable:

```
ATTENU_GUARD_PY=path/to/venv/bin/attenu-guard npm test
```

Regenerate the fixtures with `npm run fixtures` (needs the Python package and
`cryptography` importable).

Publishing runs on a `v*` tag through npm trusted publishing, which needs a
one-time trusted-publisher configuration on the npm side for this package.

## Licence

Apache-2.0. Security reports: see [SECURITY.md](SECURITY.md).
