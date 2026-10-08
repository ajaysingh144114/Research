"""Signing back ends.

`KmsSigner` keeps private keys inside AWS KMS hardware security modules (FIPS 140-3
Level 3); the key never leaves AWS. `LocalSigner` uses PEM files on disk and is
meant for development, tests and offline use.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

from .algorithms import ALGORITHMS

# KMS signs RAW messages up to 4096 bytes; QSign only ever signs a small manifest.
KMS_RAW_LIMIT = 4096


class Signer(Protocol):
    alg: str
    key_id: str

    def public_key_der(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


class KmsSigner:
    def __init__(self, kms_client, key_id: str, alg: str):
        if alg not in ALGORITHMS:
            raise ValueError(f"unsupported algorithm {alg!r}")
        self._kms = kms_client
        self.key_id = key_id
        self.alg = alg
        self._public_key: bytes | None = None

    def public_key_der(self) -> bytes:
        if self._public_key is None:
            self._public_key = self._kms.get_public_key(KeyId=self.key_id)["PublicKey"]
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        if len(message) > KMS_RAW_LIMIT:
            raise ValueError(f"message is {len(message)} bytes; KMS RAW limit is {KMS_RAW_LIMIT}")
        resp = self._kms.sign(
            KeyId=self.key_id,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm=ALGORITHMS[self.alg][0],
        )
        return resp["Signature"]


class LocalSigner:
    def __init__(self, private_key, alg: str, key_id: str):
        self._key = private_key
        self.alg = alg
        self.key_id = key_id

    def public_key_der(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, message: bytes) -> bytes:
        if self.alg.startswith("ML-DSA"):
            return self._key.sign(message)
        return self._key.sign(message, ec.ECDSA(hashes.SHA384()))


LOCAL_KEY_FILES = {"ML-DSA-65": "mldsa65.pem", "ECDSA-P384-SHA384": "ecdsa_p384.pem"}


def generate_local_keys(directory: str | Path) -> list[Path]:
    """Create a fresh ML-DSA-65 + ECDSA P-384 key pair set for local signing."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    keys = {
        "ML-DSA-65": mldsa.MLDSA65PrivateKey.generate(),
        "ECDSA-P384-SHA384": ec.generate_private_key(ec.SECP384R1()),
    }
    written = []
    for alg, key in keys.items():
        path = directory / LOCAL_KEY_FILES[alg]
        if path.exists():
            raise FileExistsError(f"{path} already exists; refusing to overwrite a signing key")
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        written.append(path)
    return written


def load_local_signers(directory: str | Path) -> list[Signer]:
    directory = Path(directory)
    signers: list[Signer] = []
    for alg, name in LOCAL_KEY_FILES.items():
        key = serialization.load_pem_private_key((directory / name).read_bytes(), password=None)
        signers.append(LocalSigner(key, alg, key_id=f"local:{name}"))
    return signers


def signers_from_env() -> list[Signer]:
    """Build the signer set from environment variables.

    QSIGN_MODE=kms   -> QSIGN_KMS_MLDSA_KEY_ID and QSIGN_KMS_ECDSA_KEY_ID (AWS), and
                        QSIGN_MLDSA_ALG = ML-DSA-65 (default) or ML-DSA-87 (NSA CNSA 2.0)
    QSIGN_MODE=local -> QSIGN_LOCAL_KEY_DIR (default ./keys)
    """
    mode = os.environ.get("QSIGN_MODE", "local")
    if mode == "kms":
        import boto3

        kms = boto3.client("kms")
        pq_alg = os.environ.get("QSIGN_MLDSA_ALG", "ML-DSA-65")
        if pq_alg not in ("ML-DSA-65", "ML-DSA-87"):
            raise ValueError("QSIGN_MLDSA_ALG must be ML-DSA-65 or ML-DSA-87")
        return [
            KmsSigner(kms, os.environ["QSIGN_KMS_MLDSA_KEY_ID"], pq_alg),
            KmsSigner(kms, os.environ["QSIGN_KMS_ECDSA_KEY_ID"], "ECDSA-P384-SHA384"),
        ]
    if mode == "local":
        return load_local_signers(os.environ.get("QSIGN_LOCAL_KEY_DIR", "keys"))
    raise ValueError(f"QSIGN_MODE must be 'kms' or 'local', not {mode!r}")
