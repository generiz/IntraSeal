from __future__ import annotations

import hashlib
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"INTRASEAL"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024
HEADER = struct.Struct(">9sB16s12s")


class IntraSealError(Exception):
    pass


class FormatError(IntraSealError):
    pass


class AuthenticationError(IntraSealError):
    pass


@dataclass(frozen=True)
class EnvelopeInfo:
    version: int
    cipher: str
    kdf: str
    payload_bytes: int


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise IntraSealError("passphrase cannot be empty")
    return Scrypt(salt=salt, length=KEY_SIZE, n=2**15, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def _header_bytes(salt: bytes, nonce: bytes) -> bytes:
    return HEADER.pack(MAGIC, VERSION, salt, nonce)


def _read_header(handle) -> tuple[bytes, int, bytes, bytes]:
    raw = handle.read(HEADER.size)
    if len(raw) != HEADER.size:
        raise FormatError("file is too small to be an IntraSeal envelope")
    magic, version, salt, nonce = HEADER.unpack(raw)
    if magic != MAGIC:
        raise FormatError("invalid IntraSeal magic")
    if version != VERSION:
        raise FormatError(f"unsupported IntraSeal version: {version}")
    return raw, version, salt, nonce


def _temporary_path(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(fd)
    return Path(name)


def _prepare_destination(destination: Path, force: bool) -> None:
    if destination.exists() and not force:
        raise FileExistsError(f"destination already exists: {destination}")


def encrypt_file(source: Path, destination: Path, passphrase: str, force: bool = False) -> None:
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    if source == destination:
        raise IntraSealError("source and destination must be different files")
    _prepare_destination(destination, force)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = _header_bytes(salt, nonce)
    key = _derive_key(passphrase, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    temporary = _temporary_path(destination)

    try:
        with source.open("rb") as src, temporary.open("wb") as dst:
            dst.write(header)
            while chunk := src.read(CHUNK_SIZE):
                dst.write(encryptor.update(chunk))
            dst.write(encryptor.finalize())
            dst.write(encryptor.tag)
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def decrypt_file(source: Path, destination: Path, passphrase: str, force: bool = False) -> None:
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    if source == destination:
        raise IntraSealError("source and destination must be different files")
    _prepare_destination(destination, force)

    total_size = source.stat().st_size
    minimum_size = HEADER.size + TAG_SIZE
    if total_size < minimum_size:
        raise FormatError("file is too small to contain an authenticated envelope")

    temporary = _temporary_path(destination)

    try:
        with source.open("rb") as src:
            header, _, salt, nonce = _read_header(src)
            src.seek(-TAG_SIZE, os.SEEK_END)
            tag = src.read(TAG_SIZE)
            ciphertext_size = total_size - HEADER.size - TAG_SIZE
            src.seek(HEADER.size)
            key = _derive_key(passphrase, salt)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(header)

            with temporary.open("wb") as dst:
                remaining = ciphertext_size
                while remaining:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise FormatError("truncated ciphertext")
                    remaining -= len(chunk)
                    dst.write(decryptor.update(chunk))
                dst.write(decryptor.finalize())

        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    except InvalidTag as exc:
        temporary.unlink(missing_ok=True)
        raise AuthenticationError("authentication failed: wrong passphrase or modified data") from exc
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def inspect_file(source: Path) -> EnvelopeInfo:
    source = source.expanduser().resolve()
    total_size = source.stat().st_size
    if total_size < HEADER.size + TAG_SIZE:
        raise FormatError("file is too small to contain an authenticated envelope")
    with source.open("rb") as handle:
        _, version, _, _ = _read_header(handle)
    return EnvelopeInfo(
        version=version,
        cipher="AES-256-GCM",
        kdf="scrypt N=32768 r=8 p=1",
        payload_bytes=total_size - HEADER.size - TAG_SIZE,
    )


def sha256_file(source: Path) -> str:
    digest = hashlib.sha256()
    with source.expanduser().resolve().open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()
