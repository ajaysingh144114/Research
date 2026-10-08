# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Justivia Legal Ventures LLP
"""QSign Verifier: check a QSign signature or evidence pack, free and offline.

This one file is all you need. It does not contact QSign or AWS, so courts,
auditors and the other party to a contract can check a signature without an
account and without trusting the service that made it.

    pip install "cryptography>=48"
    python qsign_verify.py contract.pdf contract.pdf.qsig.json
    python qsign_verify.py contract.pdf evidence.json --trust <key fingerprint>

Exit code 0 means valid (and, with --trust, made with the trusted keys).

A signature is valid only if every signature in it verifies AND at least one
of them is post-quantum (ML-DSA). An evidence pack is valid only if its
completion seal and every signer's signature verify and all fit together.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

__version__ = "1.0.0"
BUNDLE_FORMAT = "qsign/1"
EVIDENCE_FORMAT = "qsign-evidence/1"

_MLDSA = {
    "ML-DSA-44": mldsa.MLDSA44PublicKey,
    "ML-DSA-65": mldsa.MLDSA65PublicKey,
    "ML-DSA-87": mldsa.MLDSA87PublicKey,
}
_CLASSICAL = {"ECDSA-P384-SHA384"}


def canonical(obj) -> bytes:
    """The exact bytes that were signed: JSON with sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(public_key_der: bytes) -> str:
    return hashlib.sha256(public_key_der).hexdigest()


def hash_document(path) -> dict:
    sha2, sha3 = hashlib.sha512(), hashlib.sha3_512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha2.update(chunk)
            sha3.update(chunk)
    return {"sha512": sha2.hexdigest(), "sha3_512": sha3.hexdigest()}


def _verify_one(alg: str, public_key_der: bytes, message: bytes, signature: bytes) -> bool:
    key = serialization.load_der_public_key(public_key_der)
    try:
        if alg in _MLDSA:
            if not isinstance(key, _MLDSA[alg]):
                return False
            key.verify(signature, message)  # pure ML-DSA (FIPS 204), empty context, as AWS KMS signs
        elif alg in _CLASSICAL:
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
                return False
            key.verify(signature, message, ec.ECDSA(hashes.SHA384()))
        else:
            raise ValueError(f"unsupported algorithm {alg!r}")
    except InvalidSignature:
        return False
    return True


def verify_bundle(bundle: dict, *, document_digests: dict | None = None, trusted_fingerprints=None) -> dict:
    errors: list[str] = []
    results = []
    if bundle.get("format") != BUNDLE_FORMAT:
        errors.append(f"unknown bundle format {bundle.get('format')!r}")
    manifest = bundle.get("manifest") or {}
    message = canonical(manifest)
    sigs = bundle.get("signatures") or []
    if not sigs:
        errors.append("bundle has no signatures")
    for sig in sigs:
        alg = sig.get("alg")
        entry = {"alg": alg, "key_id": sig.get("key_id"), "key_fingerprint": None, "valid": False}
        try:
            pub = base64.b64decode(sig["public_key"], validate=True)
            entry["key_fingerprint"] = fingerprint(pub)
            if sig.get("key_fingerprint") and sig["key_fingerprint"] != entry["key_fingerprint"]:
                raise ValueError("key fingerprint does not match public key")
            entry["valid"] = _verify_one(alg, pub, message, base64.b64decode(sig["signature"], validate=True))
        except Exception as exc:  # malformed input must never pass
            entry["error"] = str(exc)
        if not entry["valid"]:
            errors.append(f"{alg} signature is not valid")
        results.append(entry)
    if sigs and not any(r["valid"] and r["alg"] in _MLDSA for r in results):
        errors.append("no valid post-quantum signature")

    document_match = None
    if document_digests is not None:
        signed = manifest.get("document") or {}
        document_match = bool(signed.get("sha512")) and bool(document_digests.get("sha512"))
        for algo in ("sha512", "sha3_512"):
            if signed.get(algo) and document_digests.get(algo) and signed[algo] != str(document_digests[algo]).lower():
                document_match = False
        if not document_match:
            errors.append("document does not match the signed hash (it was changed or is a different file)")

    trusted = None
    if trusted_fingerprints is not None:
        allowed = set(trusted_fingerprints)
        trusted = bool(results) and all(r["key_fingerprint"] in allowed for r in results)
    return {"valid": not errors, "errors": errors, "document_match": document_match,
            "trusted_keys": trusted, "signatures": results, "manifest": manifest}


def _bundle_digest(bundle: dict) -> str:
    return hashlib.sha256(canonical(bundle)).hexdigest()


def verify_evidence(evidence: dict, *, document_digests: dict | None = None, trusted_fingerprints=None) -> dict:
    errors: list[str] = []
    if evidence.get("format") != EVIDENCE_FORMAT:
        return {"valid": False, "errors": ["not a QSign evidence pack"], "signers": [], "trusted_keys": None}
    env = evidence.get("envelope") or {}
    seal = evidence.get("seal") or {}
    seal_report = verify_bundle(seal, trusted_fingerprints=trusted_fingerprints)
    if not seal_report["valid"]:
        errors.append("completion seal is not valid")
    sealed = seal.get("manifest") or {}
    if sealed.get("type") != "envelope-completion" or sealed.get("envelope_id") != env.get("id"):
        errors.append("seal does not belong to this envelope")
    if (sealed.get("document") or {}).get("sha512") != (env.get("document") or {}).get("sha512"):
        errors.append("seal covers a different document")

    sealed_signers = {s.get("order"): s for s in sealed.get("signers") or []}
    trusted_all = seal_report["trusted_keys"]
    signers = []
    for s in env.get("signers") or []:
        bundle = s.get("bundle") or {}
        rep = verify_bundle(bundle, document_digests=document_digests, trusted_fingerprints=trusted_fingerprints)
        m = rep["manifest"]
        ok = rep["valid"]
        expected = sealed_signers.get(s.get("order"))
        if not expected or expected.get("bundle_sha256") != _bundle_digest(bundle):
            ok = False
            errors.append(f"signature {s.get('order')} is not the one that was sealed")
        if (m.get("envelope") or {}).get("id") != env.get("id"):
            ok = False
            errors.append(f"signature {s.get('order')} belongs to a different envelope")
        if (m.get("signer") or {}).get("email") != s.get("email"):
            ok = False
            errors.append(f"signature {s.get('order')} was made by someone else")
        errors.extend(f"signer {s.get('order')}: {e}" for e in rep["errors"])
        if trusted_all is not None:
            trusted_all = trusted_all and bool(rep["trusted_keys"])
        signer = m.get("signer") or {}
        signers.append({"order": s.get("order"), "email": signer.get("email"), "name": signer.get("name"),
                        "signed_at": m.get("signed_at"), "identity": signer.get("verified_by"), "valid": ok})
    if len(signers) != len(sealed_signers):
        errors.append("number of signatures does not match the seal")
    return {"valid": not errors, "errors": errors, "trusted_keys": trusted_all, "title": env.get("title"),
            "completed_at": sealed.get("completed_at"), "signers": signers}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="qsign_verify", description="Verify a QSign signature or evidence pack offline.")
    p.add_argument("document", help="the signed document")
    p.add_argument("signature", help="the .qsig.json signature file or the evidence pack (.json)")
    p.add_argument("--trust", action="append", metavar="FINGERPRINT",
                   help="key fingerprint published by the signing organisation (repeatable)")
    p.add_argument("--json", action="store_true", help="print the full report as JSON")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    data = json.loads(Path(args.signature).read_text(encoding="utf-8"))
    digests = hash_document(args.document)
    trusted = args.trust or None
    if data.get("format") == EVIDENCE_FORMAT:
        report = verify_evidence(data, document_digests=digests, trusted_fingerprints=trusted)
    else:
        report = verify_bundle(data, document_digests=digests, trusted_fingerprints=trusted)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("VALID" if report["valid"] else "NOT VALID")
        if "signers" in report:
            print(f"  envelope: {report.get('title')}  completed {report.get('completed_at')}")
            for s in report["signers"]:
                print(f"  {s['order']}. {s['name']} <{s['email']}> at {s['signed_at']}  {'ok' if s['valid'] else 'FAILED'}")
        else:
            for s in report["signatures"]:
                print(f"  {s['alg']:<20} {'ok' if s['valid'] else 'FAILED'}  key {str(s['key_fingerprint'])[:16]}")
            signer = report["manifest"].get("signer", {})
            if report["valid"]:
                print(f"  signed by {signer.get('name')} <{signer.get('email')}> at {report['manifest'].get('signed_at')}")
        if trusted is not None:
            print(f"  keys trusted: {'yes' if report['trusted_keys'] else 'NO'}")
        for err in report["errors"]:
            print(f"  error: {err}")
    return 0 if report["valid"] and (trusted is None or report["trusted_keys"]) else 1


if __name__ == "__main__":
    sys.exit(main())
