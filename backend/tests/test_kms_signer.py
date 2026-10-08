"""KmsSigner talks to KMS exactly as AWS documents for ML-DSA and ECDSA keys."""

import pytest

from qsign.bundle import build_manifest, sign_manifest, verify_bundle
from qsign.signers import KmsSigner, generate_local_keys, load_local_signers


class FakeKms:
    """Stands in for boto3's KMS client, backed by local keys."""

    def __init__(self, local_signers):
        self.keys = {f"arn:aws:kms:ap-south-1:111122223333:key/{s.alg}": s for s in local_signers}
        self.calls = []

    def get_public_key(self, KeyId):
        return {"PublicKey": self.keys[KeyId].public_key_der()}

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.calls.append((KeyId, MessageType, SigningAlgorithm, len(Message)))
        return {"Signature": self.keys[KeyId].sign(Message)}


@pytest.fixture()
def kms(tmp_path):
    generate_local_keys(tmp_path)
    return FakeKms(load_local_signers(tmp_path))


def test_kms_hybrid_signature_verifies(kms):
    signers = [KmsSigner(kms, key_id, key_id.rsplit("/", 1)[1]) for key_id in kms.keys]
    manifest = build_manifest(document={"sha512": "b" * 128}, signer={"email": "s@example.com"}, jurisdiction="US")
    bundle = sign_manifest(manifest, signers)
    assert verify_bundle(bundle)["valid"]
    algs = {call[2] for call in kms.calls}
    assert algs == {"ML_DSA_SHAKE_256", "ECDSA_SHA_384"}
    assert all(call[1] == "RAW" and call[3] <= 4096 for call in kms.calls)


def test_kms_refuses_oversized_message(kms):
    key_id = next(iter(kms.keys))
    with pytest.raises(ValueError):
        KmsSigner(kms, key_id, "ML-DSA-65").sign(b"x" * 5000)
