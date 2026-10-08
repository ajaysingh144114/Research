from qsign.cli import main


def test_cli_keygen_sign_verify(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("QSIGN_MODE", raising=False)
    monkeypatch.setenv("QSIGN_LOCAL_KEY_DIR", str(tmp_path / "keys"))
    doc = tmp_path / "deed.txt"
    doc.write_bytes(b"sale deed")
    assert main(["keygen", "--dir", str(tmp_path / "keys")]) == 0
    assert main(["sign", str(doc), "--name", "A", "--email", "a@b.c", "--jurisdiction", "IN"]) == 0
    assert main(["verify", str(doc), f"{doc}.qsig.json"]) == 0
    doc.write_bytes(b"sale deed (edited)")
    assert main(["verify", str(doc), f"{doc}.qsig.json"]) == 1
    assert "NOT VALID" in capsys.readouterr().out
