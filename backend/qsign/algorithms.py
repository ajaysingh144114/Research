"""Signature algorithms supported by QSign and how to verify them offline.

Every algorithm here verifies with the open-source `cryptography` library, so
anyone can check a QSign signature without AWS and without trusting this service.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

# alg name -> (KMS SigningAlgorithm, is post-quantum)
ALGORITHMS = {
    "ML-DSA-44": ("ML_DSA_SHAKE_256", True),
    "ML-DSA-65": ("ML_DSA_SHAKE_256", True),
    "ML-DSA-87": ("ML_DSA_SHAKE_256", True),
    "ECDSA-P384-SHA384": ("ECDSA_SHA_384", False),
}

_MLDSA_TYPES = {
    "ML-DSA-44": mldsa.MLDSA44PublicKey,
    "ML-DSA-65": mldsa.MLDSA65PublicKey,
    "ML-DSA-87": mldsa.MLDSA87PublicKey,
}


def is_post_quantum(alg: str) -> bool:
    return ALGORITHMS[alg][1]


def fingerprint(public_key_der: bytes) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, the key's stable identity."""
    return hashlib.sha256(public_key_der).hexdigest()


def verify(alg: str, public_key_der: bytes, message: bytes, signature: bytes) -> bool:
    """Return True only if `signature` is a valid `alg` signature over `message`."""
    if alg not in ALGORITHMS:
        raise ValueError(f"unsupported algorithm {alg!r}")
    key = serialization.load_der_public_key(public_key_der)
    try:
        if alg in _MLDSA_TYPES:
            if not isinstance(key, _MLDSA_TYPES[alg]):
                return False
            # Pure ML-DSA (FIPS 204) with an empty context, which is what AWS KMS uses.
            key.verify(signature, message)
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp384r1":
                return False
            key.verify(signature, message, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        return False
    return True
