#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secrets management via Windows Credential Manager (keyring) and Fernet encryption."""

import base64
import logging
import secrets
from typing import Optional

logger = logging.getLogger("LUMENOS_SANDBOX")

_SERVICE_NAME = "lumenos_sandbox"

# Fernet requires a 32-byte URL-safe base64-encoded key.
_FERNET_PREFIX = b"AAAA"


def _fernet_available() -> bool:
    try:
        from cryptography.fernet import Fernet  # noqa: F401
        return True
    except ImportError:
        return False


def _b64url_encode(raw: bytes) -> str:
    """URL-safe base64 encode (no padding, Fernet-compatible)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode (restores padding)."""
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


class SecretManager:
    """Facade over Windows Credential Manager (keyring) and Fernet encryption.

    - ``store_secret`` / ``get_secret`` / ``delete_secret`` use the OS
      credential store so secrets never appear in plaintext on disk.
    - ``encrypt`` / ``decrypt`` use Fernet symmetric encryption for fields
      that must be persisted in SQLite (e.g. signing keys).
    - ``generate_key`` produces a fresh 32-byte random key suitable for
      both credential storage and Fernet.
    """

    def __init__(self, service_name: str = _SERVICE_NAME):
        self.service_name = service_name

    # -- OS credential store (keyring) ----------------------------------

    def store_secret(self, name: str, value: str) -> None:
        """Store a secret in Windows Credential Manager via keyring."""
        import keyring

        keyring.set_password(self.service_name, name, value)
        logger.debug("Secret stored: %s/%s", self.service_name, name)

    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve a secret from Windows Credential Manager. Returns None if absent."""
        import keyring

        value = keyring.get_password(self.service_name, name)
        if value is None:
            logger.debug("Secret not found: %s/%s", self.service_name, name)
        return value

    def delete_secret(self, name: str) -> bool:
        """Remove a secret from Windows Credential Manager. Returns True if deleted."""
        import keyring

        try:
            keyring.delete_password(self.service_name, name)
            logger.debug("Secret deleted: %s/%s", self.service_name, name)
            return True
        except keyring.errors.PasswordDeleteError:
            logger.debug("Secret not found for deletion: %s/%s", self.service_name, name)
            return False

    # -- Key generation -------------------------------------------------

    def generate_key(self) -> str:
        """Generate a random 32-byte key, returned as a hex string."""
        return secrets.token_hex(32)

    # -- Fernet encryption ----------------------------------------------

    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """Encrypt *plaintext* with a hex-encoded Fernet key.

        Returns a URL-safe base64 ciphertext string.
        Raises ``ImportError`` if the ``cryptography`` package is not installed.
        """
        from cryptography.fernet import Fernet

        fernet_key = _b64url_encode(bytes.fromhex(key))
        return Fernet(fernet_key).encrypt(plaintext.encode()).decode("ascii")

    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        """Decrypt a Fernet ciphertext string with a hex-encoded key."""
        from cryptography.fernet import Fernet

        fernet_key = _b64url_encode(bytes.fromhex(key))
        return Fernet(fernet_key).decrypt(ciphertext.encode()).decode("ascii")
