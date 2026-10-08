"""Signature bundles: what gets signed, and how a bundle is checked.

A bundle (`*.qsig.json`) is a detached signature. It holds a small *manifest*
(the document's hashes plus who signed, when and why) and one signature per
algorithm over the canonical bytes of that manifest. The document itself is
never embedded, so it can stay private.

Hybrid policy: a bundle is valid only if every signature in it verifies AND at
least one is post-quantum. A forger would have to break both ML-DSA and ECDSA.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import BinaryIO, Iterable

from . import BUNDLE_FORMAT
from .algorithms import ALGORITHMS, fingerprint, is_post_quantum, verify
from .signers import Signer

JURISDICTIONS = {"US", "IN", "EU", "OTHER"}
DEFAULT_INTENT = "I have reviewed this document and I intend to sign it electronically."


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def canonical(obj) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_document(stream: BinaryIO) -> dict:
    """SHA-512 and SHA3-512 of a document, read in chunks."""
    sha2, sha3, size = hashlib.sha512(), hashlib.sha3_512(), 0
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        sha2.update(chunk)
        sha3.update(chunk)
        size += len(chunk)
    return {"size": size, "sha512": sha2.hexdigest(), "sha3_512": sha3.hexdigest()}


def build_manifest(
    *,
    document: dict,
    signer: dict,
    reason: str = "",
    location: str = "",
    jurisdiction: str = "OTHER",
    intent: str = DEFAULT_INTENT,
    signed_at: datetime | None = None,
    envelope: dict | None = None,
) -> dict:
    if jurisdiction not in JURISDICTIONS:
        raise ValueError(f"jurisdiction must be one of {sorted(JURISDICTIONS)}")
    sha512 = str(document.get("sha512", "")).lower()
    if len(sha512) != 128 or any(c not in "0123456789abcdef" for c in sha512):
        raise ValueError("document.sha512 must be a 128-character hex digest")
    doc = {"name": str(document.get("name", ""))[:255], "sha512": sha512}
    if document.get("size") is not None:
        doc["size"] = int(document["size"])
    if document.get("sha3_512"):
        doc["sha3_512"] = str(document["sha3_512"]).lower()
    when = (signed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest = {
        "format": BUNDLE_FORMAT,
        "document": doc,
        "signer": {k: str(v) for k, v in signer.items()},
        "intent": intent,
        "reason": reason[:500],
        "location": location[:200],
        "jurisdiction": jurisdiction,
        "signed_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if envelope:
        manifest["envelope"] = envelope
    return manifest


def sign_manifest(manifest: dict, signers: Iterable[Signer]) -> dict:
    signers = list(signers)
    if not any(is_post_quantum(s.alg) for s in signers):
        raise ValueError("at least one post-quantum signer is required")
    message = canonical(manifest)
    signatures = []
    for s in signers:
        pub = s.public_key_der()
        signatures.append(
            {
                "alg": s.alg,
                "key_id": s.key_id,
                "public_key": b64(pub),
                "key_fingerprint": fingerprint(pub),
                "signature": b64(s.sign(message)),
            }
        )
    return {"format": BUNDLE_FORMAT, "manifest": manifest, "signatures": signatures}


def verify_bundle(
    bundle: dict,
    *,
    document_digests: dict | None = None,
    trusted_fingerprints: Iterable[str] | None = None,
) -> dict:
    """Check a bundle. Returns a report; `report["valid"]` is the overall answer.

    document_digests: hashes of the document in hand (from `hash_document`, or at
        least {"sha512": ...}). If omitted, only the signatures are checked.
    trusted_fingerprints: key fingerprints you trust. If given, `trusted` says
        whether every signing key is one of them.
    """
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
            if alg not in ALGORITHMS:
                raise ValueError(f"unsupported algorithm {alg!r}")
            pub = unb64(sig["public_key"])
            entry["key_fingerprint"] = fingerprint(pub)
            if sig.get("key_fingerprint") and sig["key_fingerprint"] != entry["key_fingerprint"]:
                raise ValueError("key fingerprint does not match public key")
            entry["valid"] = verify(alg, pub, message, unb64(sig["signature"]))
        except Exception as exc:  # malformed input must never pass
            entry["error"] = str(exc)
        if not entry["valid"]:
            errors.append(f"{alg} signature is not valid")
        results.append(entry)

    if sigs and not any(r["valid"] and is_post_quantum(r["alg"]) for r in results if r["alg"] in ALGORITHMS):
        errors.append("no valid post-quantum signature")

    document_match = None
    if document_digests is not None:
        signed_doc = manifest.get("document") or {}
        if not signed_doc.get("sha512"):
            errors.append("manifest has no document hash")
            document_match = False
        else:
            document_match = True
            for algo in ("sha512", "sha3_512"):
                if signed_doc.get(algo) and document_digests.get(algo):
                    if signed_doc[algo] != str(document_digests[algo]).lower():
                        document_match = False
            if not document_digests.get("sha512"):
                document_match = False
            if not document_match:
                errors.append("document does not match the signed hash (it was changed or is a different file)")

    trusted = None
    if trusted_fingerprints is not None:
        allowed = set(trusted_fingerprints)
        trusted = bool(results) and all(r["key_fingerprint"] in allowed for r in results)

    return {
        "valid": not errors,
        "errors": errors,
        "document_match": document_match,
        "trusted_keys": trusted,
        "signatures": results,
        "manifest": manifest,
    }
