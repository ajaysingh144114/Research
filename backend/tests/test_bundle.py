import copy
import io
import json

import pytest

from qsign.bundle import b64, build_manifest, hash_document, sign_manifest, unb64, verify_bundle
from qsign.signers import generate_local_keys, load_local_signers

DOC = b"%PDF-1.7 sample contract between two parties\n" * 100


@pytest.fixture()
def signers(tmp_path):
    generate_local_keys(tmp_path)
    return load_local_signers(tmp_path)


def make_bundle(signers, doc=DOC):
    digests = hash_document(io.BytesIO(doc))
    manifest = build_manifest(
        document={"name": "contract.pdf", **digests},
        signer={"name": "Test Signer", "email": "t@example.com"},
        reason="approve",
        jurisdiction="IN",
    )
    return sign_manifest(manifest, signers), digests


def test_round_trip_valid(signers):
    bundle, digests = make_bundle(signers)
    report = verify_bundle(bundle, document_digests=digests)
    assert report["valid"], report["errors"]
    assert report["document_match"] is True
    assert [s["alg"] for s in report["signatures"]] == ["ML-DSA-65", "ECDSA-P384-SHA384"]


def test_bundle_survives_json_round_trip(signers):
    bundle, digests = make_bundle(signers)
    again = json.loads(json.dumps(bundle, indent=2))
    assert verify_bundle(again, document_digests=digests)["valid"]


def test_changed_document_is_rejected(signers):
    bundle, _ = make_bundle(signers)
    other = hash_document(io.BytesIO(DOC + b"x"))
    report = verify_bundle(bundle, document_digests=other)
    assert not report["valid"]
    assert report["document_match"] is False


def test_edited_manifest_is_rejected(signers):
    bundle, digests = make_bundle(signers)
    forged = copy.deepcopy(bundle)
    forged["manifest"]["signer"]["email"] = "attacker@example.com"
    assert not verify_bundle(forged, document_digests=digests)["valid"]


def test_one_broken_signature_fails_the_hybrid(signers):
    bundle, digests = make_bundle(signers)
    for i in range(2):
        forged = copy.deepcopy(bundle)
        sig = bytearray(unb64(forged["signatures"][i]["signature"]))
        sig[10] ^= 0x01
        forged["signatures"][i]["signature"] = b64(bytes(sig))
        assert not verify_bundle(forged, document_digests=digests)["valid"]


def test_classical_only_bundle_is_rejected(signers):
    bundle, digests = make_bundle(signers)
    bundle["signatures"] = [s for s in bundle["signatures"] if s["alg"].startswith("ECDSA")]
    report = verify_bundle(bundle, document_digests=digests)
    assert not report["valid"]
    assert "no valid post-quantum signature" in report["errors"]


def test_signing_requires_post_quantum_signer(signers):
    manifest = build_manifest(document={"sha512": "a" * 128}, signer={"email": "x@y"})
    with pytest.raises(ValueError):
        sign_manifest(manifest, [s for s in signers if s.alg.startswith("ECDSA")])


def test_swapped_public_key_is_rejected(signers, tmp_path):
    bundle, digests = make_bundle(signers)
    other_dir = tmp_path / "other"
    generate_local_keys(other_dir)
    other = load_local_signers(other_dir)
    bundle["signatures"][0]["public_key"] = b64(other[0].public_key_der())
    bundle["signatures"][0].pop("key_fingerprint")
    assert not verify_bundle(bundle, document_digests=digests)["valid"]


def test_trusted_fingerprints(signers):
    bundle, digests = make_bundle(signers)
    fps = [s["key_fingerprint"] for s in bundle["signatures"]]
    assert verify_bundle(bundle, trusted_fingerprints=fps)["trusted_keys"] is True
    assert verify_bundle(bundle, trusted_fingerprints=fps[:1])["trusted_keys"] is False


def test_garbage_input_never_validates():
    assert not verify_bundle({})["valid"]
    bad = {"format": "qsign/1", "manifest": {}, "signatures": [{"alg": "ML-DSA-65", "public_key": "!!", "signature": ""}]}
    assert not verify_bundle(bad)["valid"]


def test_manifest_rejects_bad_hash_and_jurisdiction():
    with pytest.raises(ValueError):
        build_manifest(document={"sha512": "zz"}, signer={})
    with pytest.raises(ValueError):
        build_manifest(document={"sha512": "a" * 128}, signer={}, jurisdiction="MARS")


def test_keygen_refuses_to_overwrite(tmp_path):
    generate_local_keys(tmp_path)
    with pytest.raises(FileExistsError):
        generate_local_keys(tmp_path)
    assert oct((tmp_path / "mldsa65.pem").stat().st_mode & 0o777) == "0o600"
