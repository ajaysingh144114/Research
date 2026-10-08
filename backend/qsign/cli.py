"""Command line: create keys, sign a file, verify a file. Works fully offline.

    qsign keygen --dir keys
    qsign sign contract.pdf --name "A. Singh" --email a@example.com --jurisdiction IN
    qsign verify contract.pdf contract.pdf.qsig.json

Operators (whoever runs the AWS deployment) manage subscriptions with:

    qsign plan show acme
    qsign plan set acme --plan business --until 2027-12-31
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .bundle import JURISDICTIONS, build_manifest, hash_document, sign_manifest, verify_bundle
from .signers import generate_local_keys, signers_from_env


def _keygen(args) -> int:
    for path in generate_local_keys(args.dir):
        print(f"wrote {path}")
    print("Keep these files private. Anyone holding them can sign as you.")
    return 0


def _sign(args) -> int:
    if args.kms:
        os.environ["QSIGN_MODE"] = "kms"
    else:
        os.environ.setdefault("QSIGN_LOCAL_KEY_DIR", args.keys)
    doc = Path(args.file)
    with doc.open("rb") as fh:
        digests = hash_document(fh)
    manifest = build_manifest(
        document={"name": doc.name, **digests},
        signer={"name": args.name, "email": args.email, "verified_by": "self-declared (cli)"},
        reason=args.reason,
        location=args.location,
        jurisdiction=args.jurisdiction,
    )
    bundle = sign_manifest(manifest, signers_from_env())
    out = Path(args.out or f"{doc}.qsig.json")
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"signed {doc.name} -> {out}")
    return 0


def _verify(args) -> int:
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    with open(args.file, "rb") as fh:
        digests = hash_document(fh)
    trusted = args.trust or None
    report = verify_bundle(bundle, document_digests=digests, trusted_fingerprints=trusted)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        m = report["manifest"]
        print("VALID" if report["valid"] else "NOT VALID")
        for s in report["signatures"]:
            print(f"  {s['alg']:<20} {'ok' if s['valid'] else 'FAILED'}  key {str(s['key_fingerprint'])[:16]}")
        if report["valid"]:
            signer = m.get("signer", {})
            print(f"  signed by {signer.get('name')} <{signer.get('email')}> at {m.get('signed_at')}")
        if trusted is not None:
            print(f"  keys trusted: {'yes' if report['trusted_keys'] else 'NO'}")
        for err in report["errors"]:
            print(f"  error: {err}")
    ok = report["valid"] and (trusted is None or report["trusted_keys"])
    return 0 if ok else 1


def _plan_show(args) -> int:
    from .plans import plan_store_from_env, status

    sub = plan_store_from_env().get(args.org)
    if not sub:
        print(f"{args.org}: no plan yet (a trial starts when a member first signs in)")
        return 1
    print(json.dumps(status(sub), indent=2))
    return 0


def _plan_set(args) -> int:
    from .audit import audit_from_env
    from .plans import plan_store_from_env, set_plan, status

    until = datetime.strptime(args.until, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
    sub = set_plan(plan_store_from_env(), args.org, args.plan, until)
    audit_from_env().event("plan.changed", org_id=args.org, actor="operator", plan=args.plan,
                           expires_at=sub["expires_at"])
    print(json.dumps(status(sub), indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="qsign", description="Quantum-safe hybrid e-signatures")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="create local ML-DSA-65 + ECDSA P-384 keys")
    k.add_argument("--dir", default="keys")
    k.set_defaults(func=_keygen)

    s = sub.add_parser("sign", help="sign a file")
    s.add_argument("file")
    s.add_argument("--name", required=True)
    s.add_argument("--email", required=True)
    s.add_argument("--reason", default="")
    s.add_argument("--location", default="")
    s.add_argument("--jurisdiction", default="OTHER", choices=sorted(JURISDICTIONS))
    s.add_argument("--keys", default="keys", help="local key directory")
    s.add_argument("--kms", action="store_true", help="sign with AWS KMS keys from QSIGN_KMS_* env vars")
    s.add_argument("--out")
    s.set_defaults(func=_sign)

    v = sub.add_parser("verify", help="verify a file against its .qsig.json bundle")
    v.add_argument("file")
    v.add_argument("bundle")
    v.add_argument("--trust", action="append", metavar="FINGERPRINT", help="trusted key fingerprint (repeatable)")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_verify)

    pl = sub.add_parser("plan", help="show or change an organisation's subscription (operators)")
    plsub = pl.add_subparsers(dest="plan_cmd", required=True)
    ps = plsub.add_parser("show")
    ps.add_argument("org")
    ps.set_defaults(func=_plan_show)
    pt = plsub.add_parser("set")
    pt.add_argument("org")
    pt.add_argument("--plan", required=True, choices=["trial", "business", "enterprise"])
    pt.add_argument("--until", required=True, metavar="YYYY-MM-DD", help="last day of the paid period")
    pt.set_defaults(func=_plan_set)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
