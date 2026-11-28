"""Credentials are encrypted at rest with Fernet (AES-128-CBC with an HMAC). A vault holds one or more keys: the first encrypts,
every key can decrypt, so a key can be rotated without losing what was written under the old one."""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


class VaultError(Exception):
    pass


def generate_key() -> str:
    return Fernet.generate_key().decode()


def load_or_create_key(path: str | Path) -> str:
    """Read the key file, or create it readable by its owner only. The key is never printed or logged."""
    p = Path(path)
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = generate_key()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key)
    return key


class CredentialVault:
    def __init__(self, keys: list[str] | str):
        if isinstance(keys, str):
            keys = [k for k in (x.strip() for x in keys.split(",")) if k]
        if not keys:
            raise VaultError("no encryption key is configured")
        try:
            self._multi = MultiFernet([Fernet(k.encode() if isinstance(k, str) else k) for k in keys])
        except (ValueError, TypeError) as exc:
            raise VaultError("an encryption key is not a valid Fernet key") from exc

    def encrypt(self, plaintext: str) -> str:
        return self._multi.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._multi.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise VaultError("a stored credential cannot be decrypted with the configured key") from exc

    def rotate(self, token: str) -> str:
        """Re-encrypt a stored value under the first key."""
        try:
            return self._multi.rotate(token.encode("ascii")).decode("ascii")
        except InvalidToken as exc:
            raise VaultError("a stored credential cannot be decrypted with the configured keys") from exc
