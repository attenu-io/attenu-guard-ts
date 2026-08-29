"""Generate the cross-language fixtures under `test/fixtures/` FROM the Python library.

The TypeScript tests read these and must reproduce them byte for byte. That is what
makes "byte-compatible with the Python implementation" a claim with a check behind it
rather than an assertion.

    python3 tools/gen_fixtures.py

Requires the Python `attenu-guard` package (>=0.7.1, which ships the JCS interop vectors this
script copies) and `cryptography`, for the Ed25519 anchor, importable in the running
interpreter. Deterministic: the Ed25519 key, the HMAC secret
and every timestamp are fixed, so re-running produces identical files.

What lands in `test/fixtures/`:

  canonical_vectors.json   documents written by Python's json, with the compact
                           canonical form each must serialise back to
  hash_vectors.json        {prev_hash, payload, expected_hash} triples covering unicode,
                           floats, nesting and empty values
  delegation_cases.json    {parent, request, expected_child} — the meet, as wire forms
  subsumption_cases.json   {a, b, expected} — is_narrower_than over the same wire forms
  permits_cases.json       {authority, scope, context, expected} — policy evaluation
  ledger.jsonl             a raw hash-chained ledger, as Python writes it to disk
  *.bundle.json            clean (HS256 and Ed25519 anchors) plus one file per tamper
  expected_reports.json    what Python's verify_bundle returns for each bundle
  meta.json                the keys, and the CLI lines Python prints for each file
  vectors/*.json           the Internet-Draft's delegation-chain interop vectors, copied
                           verbatim from the installed package: one chain that must verify
                           with each accepted or rejected outcome declared
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from attenu_guard import (
    Allow,
    AuditLog,
    Authority,
    CallLimit,
    Deny,
    EgressRank,
    Guard,
    Prefix,
    RowLimit,
    SpendCap,
    evidence,
)
from attenu_guard.audit import _canonical, _hash
from attenu_guard.wire import Ed25519Signer, HS256TestSigner

try:
    from attenu_guard import vectors as attenu_vectors
except ImportError as e:  # pragma: no cover - a too-old attenu-guard
    raise SystemExit(
        "The installed attenu-guard does not ship the delegation-chain interop vectors "
        "(attenu_guard.vectors), which this script copies rather than regenerating.\n"
        "Upgrade with:  pip install --upgrade 'attenu-guard>=0.7'"
    ) from e

_JCS_VECTOR_NAMES = {
    "valid_jcs_integral_float.json",
    "valid_jcs_exponent_form.json",
    "valid_jcs_non_ascii.json",
    "valid_jcs_utf16_key_order.json",
    "valid_jcs_big_integer.json",
    "reject_non_finite.json",
    "reject_duplicate_member.json",
    "valid_jcs_unmarked_header.json",
}
_missing_jcs = _JCS_VECTOR_NAMES.difference(attenu_vectors.VECTOR_NAMES)
if _missing_jcs:
    raise SystemExit(
        "The installed attenu-guard predates the RFC 8785 JCS vector set.\n"
        "Upgrade with:  pip install --upgrade 'attenu-guard>=0.7.1'"
    )

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "test" / "fixtures"

HS256_SECRET = bytes.fromhex("73616d706c652d6b6579")  # "sample-key"
HS256_KID = "sample"
# A fixed Ed25519 private key so the fixtures are reproducible. It signs nothing but
# these test files; it is published here on purpose.
ED25519_SECRET = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
ED25519_KID = "fixture-ed25519"


def write(name: str, payload) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=1, sort_keys=True)
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)  # `name` may name a subdirectory
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    print(f"  {name}")


# ---------------------------------------------------------------- canonical form


def canonical_vectors() -> list[dict]:
    """Documents whose canonical bytes the TypeScript serialiser must reproduce.

    `source` is deliberately written with Python's spaced default separators so a reader
    has to parse and canonicalize it rather than pattern-match the text. The expected
    value is the compact RFC 8785 representation.
    """
    values = [
        {},
        [],
        {"b": 1, "a": 2, "C": 3, "_": 4},
        {"unicode": "café", "emoji": "😀", "cjk": "監査", "combining": "é"},
        {"control": "\x00\x1f\x7f", "escapes": '\t\n\r\\"', "solidus": "a/b"},
        {"ints": [0, -0, 1, -1, 100, 10**15, 10**16, 10**20]},
        {"floats": [100.0, 0.1, 2.5, 1 / 3, -0.0, 1e-5, 1e-7, 1e16, 1e21, 1.5e17]},
        {"null": None, "true": True, "false": False},
        {"nested": {"z": [1, {"y": "x"}], "a": {"b": {"c": []}}}},
        {"key with spaces": 1, "key\twith\ttabs": 2, "ключ": 3},
    ]
    return [
        {
            "source": json.dumps(v, sort_keys=True),
            "canonical": _canonical(v).decode("utf-8"),
        }
        for v in values
    ]


def hash_vectors() -> list[dict]:
    """`{prev_hash, payload, expected_hash}` — the entry hash, in isolation."""
    genesis = "0" * 64
    payloads = [
        {"v": 1, "seq": 0, "ts": 1, "event": "root", "prev_hash": genesis},
        {
            "v": 1,
            "seq": 3,
            "ts": "2026-08-28T10:00:00Z",
            "event": "allow",
            "scope": "crm.read",
            "tool": None,
            "context": {"rows": 4200, "spend": 0.5, "egress": "none"},
            "prev_hash": "a" * 64,
        },
        {
            "v": 1,
            "seq": 7,
            "ts": 12,
            "event": "deny",
            "scope": "crm.export",
            "task": "résumé the pipeline 😀",
            "reasons": [
                {
                    "code": "scope_not_granted",
                    "constraint": None,
                    "limit": None,
                    "requested": "crm.export",
                    "message": "scope 'crm.export' not covered",
                }
            ],
            "prev_hash": "f" * 64,
        },
        {"v": 1, "seq": 0, "ts": 0, "event": "empty", "context": {}, "prev_hash": genesis},
    ]
    out = []
    for p in payloads:
        prev = p["prev_hash"]
        out.append({"prev_hash": prev, "payload": p, "expected_hash": _hash(prev, p)})
    return out


# ---------------------------------------------------------------- the lattice


def authorities() -> dict[str, Authority]:
    return {
        "broad": Authority(
            scopes={"crm.*", "mail.send"},
            ceilings=[RowLimit(100_000), EgressRank("any"), SpendCap(50.0)],
            ttl=3600,
        ),
        "reader": Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000)], ttl=900),
        "wider_request": Authority(
            scopes={"crm.read", "crm.export", "fs.write"},
            ceilings=[RowLimit(1_000_000)],
            ttl=7200,
        ),
        "wildcard_both": Authority(scopes={"crm.*"}, ceilings=[], ttl=None),
        "scoped_calls": Authority(
            scopes={"web.search", "web.fetch"},
            ceilings=[CallLimit(10), CallLimit(3, "web.fetch")],
            ttl=600,
        ),
        "membership": Authority(
            scopes={"db.query"},
            ceilings=[
                Allow("region", {"eu-west", "eu-north"}),
                Deny("table", {"salaries"}),
                Prefix("path", "/srv/data/"),
            ],
            ttl=300,
        ),
        "membership_other": Authority(
            scopes={"db.query"},
            ceilings=[
                Allow("region", {"eu-west", "us-east"}),
                Deny("table", {"tokens"}),
                Prefix("path", "/srv/"),
            ],
            ttl=1200,
        ),
        "incomparable_prefix": Authority(
            scopes={"db.query"}, ceilings=[Prefix("path", "/var/log/")], ttl=300
        ),
        "unknown_ceiling": Authority.from_wire(
            {
                "scopes": ["widget.spin"],
                "constraints": [{"key": "max_widgets", "type": "widgets", "max": 4}],
                "ttl": 60,
            }
        ),
        "empty": Authority(),
    }


def delegation_cases() -> list[dict]:
    a = authorities()
    pairs = [
        ("broad", "reader"),
        ("broad", "wider_request"),
        ("reader", "broad"),
        ("wildcard_both", "wildcard_both"),
        ("broad", "wildcard_both"),
        ("scoped_calls", "scoped_calls"),
        ("membership", "membership_other"),
        ("membership", "incomparable_prefix"),
        ("unknown_ceiling", "unknown_ceiling"),
        ("empty", "broad"),
        ("broad", "empty"),
    ]
    out = []
    for parent, request in pairs:
        child = a[parent].meet(a[request])
        out.append(
            {
                "name": f"{parent} meet {request}",
                "parent": a[parent].to_wire(),
                "request": a[request].to_wire(),
                "expected_child": child.to_wire(),
                "child_narrower_than_parent": child.is_narrower_than(a[parent]),
            }
        )
    return out


def subsumption_cases() -> list[dict]:
    a = authorities()
    names = sorted(a)
    return [
        {"a": a[x].to_wire(), "b": a[y].to_wire(), "name": f"{x} <= {y}",
         "expected": a[x].is_narrower_than(a[y])}
        for x in names
        for y in names
    ]


def permits_cases() -> list[dict]:
    a = authorities()
    probes = [
        ("broad", "crm.read", {"rows": 10}),
        ("broad", "crm.read", {"rows": 999_999}),
        ("broad", "fs.write", {}),
        ("reader", "crm.read", {"rows": 5_000}),
        ("reader", "crm.read", {"rows": 5_001}),
        ("reader", "crm.export", {}),
        ("scoped_calls", "web.fetch", {"calls[web.fetch]": 4}),
        ("scoped_calls", "web.fetch", {"calls[web.fetch]": 3}),
        ("scoped_calls", "web.search", {"calls": 11}),
        ("membership", "db.query", {"region": "eu-west", "table": "orders", "path": "/srv/data/x"}),
        ("membership", "db.query", {"region": "us-east"}),
        ("membership", "db.query", {"table": "salaries"}),
        ("membership", "db.query", {"path": "/etc/passwd"}),
        ("membership", "db.query", {}),
        ("unknown_ceiling", "widget.spin", {}),
        ("empty", "anything", {}),
    ]
    out = []
    for name, scope, ctx in probes:
        d = a[name].permits(scope, ctx)
        out.append(
            {
                "name": f"{name}.permits({scope!r}, {ctx!r})",
                "authority": a[name].to_wire(),
                "scope": scope,
                "context": ctx,
                "expected": {
                    "allowed": d.allowed,
                    "codes": sorted(r.code for r in d.reasons),
                },
            }
        )
    return out


# ---------------------------------------------------------------- ledgers and bundles


def build_run() -> Guard:
    """A small but complete run: a root, two levels of delegation, allows, denials,
    a completion and a revocation."""
    root = Guard.issue(
        "orchestrator",
        Authority(
            scopes={"crm.*", "mail.send"},
            ceilings=[RowLimit(100_000), EgressRank("any")],
            ttl=3600,
        ),
        task="quarterly review",
        chain_id="fixtures",
    )
    reader = root.delegate(
        "reader",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900),
        task="summarise the pipeline · résumé 😀",
    )
    analyst = reader.delegate(
        "analyst",
        Authority(scopes={"crm.read"}, ceilings=[RowLimit(500)], ttl=600),
        task="top accounts",
    )
    reader.check("crm.read", context={"rows": 4_200}, tool="crm_query")
    analyst.check("crm.read", context={"rows": 120}, tool="crm_query")
    analyst.check("crm.read", context={"rows": 9_000}, tool="crm_query")  # row ceiling
    reader.check("crm.export", context={"egress": "any"}, tool="crm_export")  # not held
    analyst.complete()
    root.revoke(reader.node_id)
    return root


def tampered(bundle: dict) -> dict:
    """The classic rewrite: a denial edited into an allow after the fact."""
    b = copy.deepcopy(bundle)
    next(e for e in b["entries"] if e["event"] == "deny")["event"] = "allow"
    return b


def dropped(bundle: dict) -> dict:
    """An entry removed — the seq gap is the evidence."""
    b = copy.deepcopy(bundle)
    del b["entries"][2]
    return b


def reordered(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["entries"][2], b["entries"][3] = b["entries"][3], b["entries"][2]
    return b


def bad_anchor(bundle: dict) -> dict:
    """The ledger is intact; the anchor signature is not."""
    b = copy.deepcopy(bundle)
    sig = b["anchor"]["sig"]
    b["anchor"]["sig"] = ("f" if sig[0] != "f" else "0") + sig[1:]
    return b


def widened(signer) -> dict:
    """A ledger an insider holding the key could produce: every hash and the anchor are
    valid, but a child was granted more than its parent held."""
    log = AuditLog(None)
    parent = Authority(scopes={"crm.read"}, ceilings=[RowLimit(5_000), EgressRank("none")], ttl=900)
    child = Authority(scopes={"crm.read", "crm.export"}, ceilings=[EgressRank("any")], ttl=900)
    log.append("root", 1, chain_id="fixtures", node="n0", agent="orchestrator",
               authority=parent.to_wire())
    log.append("spawn", 2, chain_id="fixtures", node="n1", parent="n0", agent="exporter",
               granted=child.to_wire())
    log.append("allow", 3, chain_id="fixtures", node="n1", scope="crm.export",
               tool="crm_export", context={"egress": "any"})
    return evidence.export_bundle(log, signer)


def uncontained(signer) -> dict:
    """An honest-looking ledger in which an ALLOW records a scope the acting node
    never held — the containment check is what catches it."""
    log = AuditLog(None)
    held = Authority(scopes={"crm.read"}, ceilings=[RowLimit(100)], ttl=900)
    log.append("root", 1, chain_id="fixtures", node="n0", agent="reader",
               authority=held.to_wire())
    log.append("allow", 2, chain_id="fixtures", node="n0", scope="crm.read",
               tool="crm_query", context={"rows": 5_000})
    return evidence.export_bundle(log, signer)


def report_of(bundle: dict, signer) -> dict:
    rep = evidence.verify_bundle(bundle, signer)
    return {
        "ok": rep["ok"],
        "checks": rep["checks"],
        "failures": rep["failures"],
        "nodes": rep["nodes"],
        "actions_checked": rep["actions_checked"],
        "chain_id": rep["chain_id"],
    }


def cli_line(rep: dict) -> str:
    c = rep["checks"]
    return (
        f"integrity={c['integrity']} monotonicity={c['monotonicity']} "
        f"containment={c['containment']} anchor={c['anchor']} "
        f"nodes={rep['nodes']} actions_checked={rep['actions_checked']}"
    )


# ------------------------------------------------- delegation-chain interop vectors


def chain_vectors() -> dict[str, str]:
    """The Internet-Draft's interop vectors, copied VERBATIM out of the installed
    `attenu_guard` package — raw bytes, not re-serialised.

    Accepted and adversarial Delegation Chains, each declaring its required outcome.
    They are generated by the Python repository's
    `tests/vectors/generate.py`, which is their only writer, and ship as package data
    precisely so a consumer in another language does not need that repository. Copying
    the bytes rather than rebuilding them is the point: a second generator would be a
    second source of truth, and the descriptions and the tokens would drift apart at
    different rates.
    """
    return {
        name: attenu_vectors.read_vector_bytes(name).decode("utf-8")
        for name in attenu_vectors.VECTOR_NAMES
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"writing fixtures to {OUT.relative_to(ROOT)}/")

    write("canonical_vectors.json", canonical_vectors())
    write("hash_vectors.json", hash_vectors())
    write("delegation_cases.json", delegation_cases())
    write("subsumption_cases.json", subsumption_cases())
    write("permits_cases.json", permits_cases())

    hs = HS256TestSigner(HS256_SECRET, kid=HS256_KID)
    ed = Ed25519Signer.from_private_bytes(ED25519_SECRET, kid=ED25519_KID)

    # A JCS ledger exactly as Python writes it to disk (one canonical JSON object per line).
    root = build_run()
    entries = root.audit_log().entries
    write("ledger.jsonl", "".join(_canonical(e).decode("utf-8") + "\n" for e in entries))

    # The same ledger with one denial edited into an allow — the hash mismatch names the seq.
    edited = copy.deepcopy(entries)
    next(e for e in edited if e["event"] == "deny")["event"] = "allow"
    write("tampered_ledger.jsonl", "".join(_canonical(e).decode("utf-8") + "\n" for e in edited))
    t_ok, t_reason = AuditLog.verify(edited)
    assert not t_ok, "the tampered ledger must fail"

    clean_hs = evidence.export_bundle(root.audit_log(), hs)
    clean_ed = evidence.export_bundle(root.audit_log(), ed)
    redacted = evidence.export_bundle(root.audit_log(), hs, redact_task=True)

    bundles = {
        "clean_hs256": (clean_hs, hs),
        "clean_ed25519": (clean_ed, ed),
        "redacted_hs256": (redacted, hs),
        "tampered_hs256": (tampered(clean_hs), hs),
        "dropped_hs256": (dropped(clean_hs), hs),
        "reordered_hs256": (reordered(clean_hs), hs),
        "bad_anchor_hs256": (bad_anchor(clean_hs), hs),
        "widened_hs256": (widened(hs), hs),
        "uncontained_hs256": (uncontained(hs), hs),
    }

    reports: dict[str, dict] = {}
    cli: dict[str, dict] = {}
    for name, (bundle, signer) in bundles.items():
        write(f"{name}.bundle.json", bundle)
        with_key = report_of(bundle, signer)
        without_key = report_of(bundle, None)
        reports[name] = {"with_key": with_key, "without_key": without_key}
        cli[name] = {
            "with_key": {"line": cli_line(with_key), "status": "OK" if with_key["ok"] else "FAILED",
                         "exit": 0 if with_key["ok"] else 2},
            "without_key": {"line": cli_line(without_key),
                            "status": "OK" if without_key["ok"] else "FAILED",
                            "exit": 0 if without_key["ok"] else 2},
        }

    write("expected_reports.json", reports)

    # Verbatim: `write` passes a string through untouched, so these land
    # byte-identical to the canonical files, descriptions and all.
    vectors = chain_vectors()
    for filename, text in vectors.items():
        write(f"vectors/{filename}", text)

    ok, reason = AuditLog.verify(entries)
    write(
        "meta.json",
        {
            "hs256_secret_hex": HS256_SECRET.hex(),
            "hs256_kid": HS256_KID,
            "ed25519_private_hex": ED25519_SECRET.hex(),
            "ed25519_public_hex": ed.public_bytes_raw().hex(),
            "ed25519_kid": ED25519_KID,
            "ledger": {
                "entries": len(entries),
                "verify_ok": ok,
                "verify_reason": reason,
                "cli_status": "OK" if ok else f"TAMPERED — {reason}",
            },
            "tampered_ledger": {
                "verify_reason": t_reason,
                "cli_status": f"TAMPERED — {t_reason}",
            },
            "cli": cli,
            "generated_by": "tools/gen_fixtures.py",
        },
    )
    print(f"done · {len(entries)} ledger entries · {len(bundles)} bundles "
          f"· {len(vectors)} chain vectors")


if __name__ == "__main__":
    main()
