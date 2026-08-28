from pathlib import Path

import pytest

from intraseal.core import AuthenticationError, decrypt_file, encrypt_file, inspect_file, sha256_file


def test_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "board-report.pdf"
    sealed = tmp_path / "board-report.pdf.seal"
    restored = tmp_path / "restored.pdf"
    source.write_bytes((b"confidential\x00data\n" * 10000) + b"end")

    encrypt_file(source, sealed, "correct horse battery staple")
    decrypt_file(sealed, restored, "correct horse battery staple")

    assert restored.read_bytes() == source.read_bytes()
    assert sha256_file(restored) == sha256_file(source)


def test_wrong_passphrase_does_not_leave_plaintext(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    sealed = tmp_path / "source.bin.seal"
    restored = tmp_path / "restored.bin"
    source.write_bytes(b"sensitive")
    encrypt_file(source, sealed, "first-passphrase")

    with pytest.raises(AuthenticationError):
        decrypt_file(sealed, restored, "wrong-passphrase")

    assert not restored.exists()


def test_modified_ciphertext_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    sealed = tmp_path / "source.bin.seal"
    restored = tmp_path / "restored.bin"
    source.write_bytes(b"classified material" * 100)
    encrypt_file(source, sealed, "strong-passphrase")

    data = bytearray(sealed.read_bytes())
    data[len(data) // 2] ^= 0x01
    sealed.write_bytes(data)

    with pytest.raises(AuthenticationError):
        decrypt_file(sealed, restored, "strong-passphrase")

    assert not restored.exists()


def test_inspect_reports_envelope_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    sealed = tmp_path / "source.txt.seal"
    source.write_text("private notes", encoding="utf-8")
    encrypt_file(source, sealed, "inspection-passphrase")

    info = inspect_file(sealed)

    assert info.version == 1
    assert info.cipher == "AES-256-GCM"
    assert info.kdf.startswith("scrypt")
    assert info.payload_bytes == source.stat().st_size
