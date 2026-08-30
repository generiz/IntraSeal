# IntraSeal

IntraSeal is a small command-line utility for creating authenticated encrypted file envelopes. It is intended for local handling of files where confidentiality and tamper detection matter.

**Status:** utility. It is not a key-management platform, document vault, identity system or enterprise encryption product.

The project does not implement cryptographic primitives itself. It uses Python's `cryptography` package for AES-256-GCM and scrypt.

## What it does

- AES-256-GCM authenticated encryption
- scrypt passphrase derivation with a random 128-bit salt
- fresh 96-bit nonce for every envelope
- streaming I/O for large files
- authenticated header data
- atomic output replacement
- failed authentication does not leave plaintext output behind
- hidden terminal passphrase prompt
- envelope inspection without exposing secrets
- SHA-256 file hashing

## Install

```bash
python -m pip install -e .
```

Development install:

```bash
python -m pip install -e ".[dev]"
pytest
```

## Usage

Encrypt:

```bash
intraseal encrypt financial-report.pdf
```

Decrypt:

```bash
intraseal decrypt financial-report.pdf.seal
```

Inspect non-secret envelope parameters:

```bash
intraseal inspect financial-report.pdf.seal
```

Hash a file:

```bash
intraseal hash financial-report.pdf
```

Use `-o` to select an output path. Use `--force` only when replacing an existing destination is intentional.

## Envelope format

Version 1 uses a fixed binary header followed by ciphertext and a 128-bit GCM authentication tag.

| Field | Size |
| --- | ---: |
| Magic | 9 bytes |
| Version | 1 byte |
| Salt | 16 bytes |
| Nonce | 12 bytes |
| Ciphertext | variable |
| GCM tag | 16 bytes |

The complete header is authenticated as additional data. Original filenames, timestamps and paths are not embedded in the envelope.

## Threat model

IntraSeal protects file contents against offline disclosure when an attacker obtains the encrypted file but not the passphrase. It also detects modifications to the authenticated envelope.

It does **not** protect plaintext while it is open on a compromised endpoint. It does not provide key escrow, identity management, hardware-backed keys, secure deletion, recovery services or protection against weak passphrases.

For organizational use, passphrase policy, backup and key lifecycle controls must be handled outside this tool.

## Repository layout

```text
src/intraseal/core.py   envelope format, KDF and authenticated encryption
src/intraseal/cli.py    command-line interface
tests/test_core.py      round-trip, tamper and authentication tests
.github/workflows/      cross-platform CI
```

## License

MIT
