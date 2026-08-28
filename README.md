# IntraSeal

IntraSeal is a small command-line tool for creating authenticated encrypted file envelopes. It is designed for local handling of sensitive documents where confidentiality and tamper detection matter more than platform-specific integration.

The tool does not implement cryptographic primitives itself. It uses `cryptography` for AES-256-GCM and scrypt.

## Security properties

- AES-256-GCM authenticated encryption
- scrypt passphrase derivation with a random 128-bit salt
- fresh 96-bit nonce for every envelope
- streaming I/O for large files
- header authentication through GCM additional authenticated data
- atomic output replacement
- failed authentication does not leave plaintext output behind
- passphrases are requested through a hidden terminal prompt rather than command-line arguments

## Install

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
pytest
```

## Usage

Encrypt a file:

```bash
intraseal encrypt financial-report.pdf
```

The default output is `financial-report.pdf.seal`.

Decrypt it:

```bash
intraseal decrypt financial-report.pdf.seal
```

Inspect the non-secret envelope parameters:

```bash
intraseal inspect financial-report.pdf.seal
```

Calculate a SHA-256 digest:

```bash
intraseal hash financial-report.pdf
```

Use `-o` to select an output path and `--force` only when replacing an existing destination is intentional.

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

IntraSeal protects file contents against offline disclosure when the attacker obtains the encrypted file but not the passphrase. It also detects changes to the authenticated envelope.

It does not protect a file while plaintext is open on a compromised endpoint. It does not provide key escrow, identity management, secure deletion, hardware-backed key storage or protection against a weak passphrase.

For organizational deployments, passphrase policy and key lifecycle controls should be handled outside the tool.

## Security lab

`labs/veil-link` contains Veil Link, a Rust peer-to-peer encrypted terminal channel built on `Noise_XX_25519_ChaChaPoly_BLAKE2s`. It uses ephemeral X25519 key agreement, ChaCha20-Poly1305 authenticated encryption, peer fingerprint verification and identity pinning.

Veil Link is intentionally separate from the file-envelope code so its transport and trust model can be reviewed independently.

## Repository layout

```text
src/intraseal/core.py          envelope format, KDF and authenticated encryption
src/intraseal/cli.py           command-line interface
tests/test_core.py             round-trip, tamper and authentication tests
labs/veil-link/                Noise-based secure communications prototype
.github/workflows/             Python and Rust CI
```

## License

MIT
