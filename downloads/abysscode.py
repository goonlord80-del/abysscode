#!/usr/bin/env python3
"""
ABYSSCODE — custom text/binary encoding format with authenticated encryption.

Install:
    py -m pip install cryptography

Generate a key:
    py abysscode.py keygen
    py abysscode.py keygen --out abyss.key

Encode a file:
    py abysscode.py encode message.txt message.aby --key-file abyss.key

Decode it:
    py abysscode.py decode message.aby recovered.txt --key-file abyss.key

Encode/decode using a passphrase (derived securely with scrypt):
    py abysscode.py encode message.txt message.aby --passphrase
    py abysscode.py decode message.aby recovered.txt --passphrase

Notes:
- This is a custom container/encoding format, not a new cryptographic primitive.
- Security comes from AES-256-GCM and scrypt via the `cryptography` package.
- Keep your key/passphrase safe. If lost, encrypted files cannot be recovered.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import secrets
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    print("Missing dependency. Install it with: py -m pip install cryptography", file=sys.stderr)
    raise SystemExit(2)

MAGIC = b"ABYSS\x01"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# A shuffled, non-Base64 alphabet. The encoded output uses only these symbols.
ALPHABET = "JMg75pWqTlFQjy8xNEfwHDioakbGI6LPKz3cCRSOY0mv94trXBeZAU21uVhdn/s+"
# Ensure the alphabet is exactly 64 unique characters.
if len(ALPHABET) != 64 or len(set(ALPHABET)) != 64:
    raise RuntimeError("Internal alphabet must contain exactly 64 unique characters.")

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ENC_TABLE = str.maketrans(B64_ALPHABET, ALPHABET)
DEC_TABLE = str.maketrans(ALPHABET, B64_ALPHABET)


def abyss_encode(raw: bytes) -> str:
    """Encode bytes into the custom ABYSSCODE alphabet."""
    return base64.b64encode(raw).decode("ascii").translate(ENC_TABLE).rstrip("=")


def abyss_decode(text: str) -> bytes:
    """Decode custom-alphabet text back to bytes."""
    cleaned = "".join(text.split())
    if any(ch not in ALPHABET for ch in cleaned):
        raise ValueError("Input contains characters that are not valid ABYSSCODE symbols.")
    standard = cleaned.translate(DEC_TABLE)
    standard += "=" * ((4 - len(standard) % 4) % 4)
    try:
        return base64.b64decode(standard, validate=True)
    except Exception as exc:
        raise ValueError("Malformed ABYSSCODE payload.") from exc


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("Passphrase cannot be empty.")
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def load_key_file(path: str) -> bytes:
    key = Path(path).read_bytes().strip()
    # Key files contain 64 ASCII hex characters.
    try:
        decoded = bytes.fromhex(key.decode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid key file. Generate one with the keygen command.") from exc
    if len(decoded) != KEY_LEN:
        raise ValueError("Key file must contain a 32-byte (64 hex-character) key.")
    return decoded


def get_encrypt_key(args, salt: bytes) -> bytes:
    if args.passphrase:
        first = getpass.getpass("Passphrase: ")
        if args.command == "encode":
            confirm = getpass.getpass("Confirm passphrase: ")
            if first != confirm:
                raise ValueError("Passphrases do not match.")
        return derive_key(first, salt)
    if not args.key_file:
        raise ValueError("Supply --key-file or use --passphrase.")
    return load_key_file(args.key_file)


def command_keygen(args) -> None:
    key = secrets.token_bytes(KEY_LEN).hex() + "\n"
    if args.out:
        target = Path(args.out)
        target.write_text(key, encoding="ascii")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        print(f"Key written to {target}. Keep it private and make a backup.")
    else:
        print(key, end="")
        print("Store this key securely; anyone who has it can decrypt your files.", file=sys.stderr)


def command_encode(args) -> None:
    source = Path(args.input).read_bytes()
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = get_encrypt_key(args, salt)
    # Header is authenticated as associated data, so tampering is detected.
    header = MAGIC + (b"P" if args.passphrase else b"K") + salt + nonce
    ciphertext = AESGCM(key).encrypt(nonce, source, header)
    encoded = abyss_encode(header + ciphertext)
    Path(args.output).write_text("ABYSSCODE:" + encoded + "\n", encoding="ascii")
    print(f"Encoded and encrypted {len(source)} bytes -> {args.output}")


def command_decode(args) -> None:
    text = Path(args.input).read_text(encoding="ascii")
    if not text.startswith("ABYSSCODE:"):
        raise ValueError("Missing ABYSSCODE header.")
    blob = abyss_decode(text[len("ABYSSCODE:"):])
    min_len = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + 16  # GCM tag
    if len(blob) < min_len:
        raise ValueError("Payload is too short or corrupted.")
    if not blob.startswith(MAGIC):
        raise ValueError("Unknown ABYSSCODE version.")
    mode = blob[len(MAGIC):len(MAGIC) + 1]
    offset = len(MAGIC) + 1
    salt = blob[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    header = blob[:offset]
    ciphertext = blob[offset:]

    if mode == b"P":
        if not args.passphrase:
            raise ValueError("This file uses a passphrase. Add --passphrase.")
        key = get_encrypt_key(args, salt)
    elif mode == b"K":
        if args.passphrase:
            raise ValueError("This file uses a key file, not a passphrase.")
        if not args.key_file:
            raise ValueError("Supply --key-file for this file.")
        key = load_key_file(args.key_file)
    else:
        raise ValueError("Unknown key mode.")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong key/passphrase or modified file.") from exc
    Path(args.output).write_bytes(plaintext)
    print(f"Verified and decoded {len(plaintext)} bytes -> {args.output}")


def build_parser():
    parser = argparse.ArgumentParser(description="ABYSSCODE custom encoding + authenticated encryption")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate a random 256-bit key")
    keygen.add_argument("--out", help="Write key to a file instead of printing it")
    keygen.set_defaults(func=command_keygen)

    for name, help_text in (
        ("encode", "Encrypt and encode a file"),
        ("decode", "Decode and decrypt a file"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("input", help="Input file")
        p.add_argument("output", help="Output file")
        p.add_argument("--key-file", help="Path to a key generated by keygen")
        p.add_argument("--passphrase", action="store_true", help="Use a passphrase with scrypt")
        p.set_defaults(func=command_encode if name == "encode" else command_decode)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
