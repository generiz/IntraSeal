from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .core import AuthenticationError, IntraSealError, decrypt_file, encrypt_file, inspect_file, sha256_file


def _passphrase(confirm: bool) -> str:
    first = getpass.getpass("Passphrase: ")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise IntraSealError("passphrases do not match")
    return first


def _encrypt(args: argparse.Namespace) -> None:
    source = Path(args.source)
    destination = Path(args.output) if args.output else source.with_name(source.name + ".seal")
    encrypt_file(source, destination, _passphrase(confirm=True), force=args.force)
    print(destination)


def _decrypt(args: argparse.Namespace) -> None:
    source = Path(args.source)
    if args.output:
        destination = Path(args.output)
    elif source.suffix == ".seal":
        destination = source.with_suffix("")
    else:
        destination = source.with_name(source.name + ".plain")
    decrypt_file(source, destination, _passphrase(confirm=False), force=args.force)
    print(destination)


def _inspect(args: argparse.Namespace) -> None:
    info = inspect_file(Path(args.source))
    print(f"version: {info.version}")
    print(f"cipher: {info.cipher}")
    print(f"kdf: {info.kdf}")
    print(f"payload_bytes: {info.payload_bytes}")


def _hash(args: argparse.Namespace) -> None:
    print(sha256_file(Path(args.source)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="intraseal")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt = subparsers.add_parser("encrypt")
    encrypt.add_argument("source")
    encrypt.add_argument("-o", "--output")
    encrypt.add_argument("--force", action="store_true")
    encrypt.set_defaults(func=_encrypt)

    decrypt = subparsers.add_parser("decrypt")
    decrypt.add_argument("source")
    decrypt.add_argument("-o", "--output")
    decrypt.add_argument("--force", action="store_true")
    decrypt.set_defaults(func=_decrypt)

    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("source")
    inspect.set_defaults(func=_inspect)

    hash_command = subparsers.add_parser("hash")
    hash_command.add_argument("source")
    hash_command.set_defaults(func=_hash)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
        return 0
    except AuthenticationError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (IntraSealError, FileExistsError, FileNotFoundError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
