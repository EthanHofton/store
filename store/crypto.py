"""Encryption and decryption utilities for stored secrets.

Encryption scheme
-----------------
1. A random 16-byte salt is generated for each value that is encrypted.
2. The caller-supplied password is stretched with PBKDF2-HMAC-SHA256
   (480 000 iterations — OWASP 2023 recommendation) to produce a 32-byte
   key, which is base64url-encoded to satisfy the Fernet key format.
3. The plaintext is encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
4. The persisted blob is ``base64url(salt || fernet_token)`` so that the
   salt can be recovered at decryption time without a separate DB column.
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Number of PBKDF2 iterations — increase over time as hardware gets faster.
_PBKDF2_ITERATIONS: int = 480_000
# Salt size in bytes.
_SALT_SIZE: int = 16


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible 32-byte key from *password* and *salt*.

    The raw PBKDF2-HMAC-SHA256 digest is base64url-encoded so that it can
    be passed directly to :class:`cryptography.fernet.Fernet`.

    Args:
        password: The caller-supplied encryption password (arbitrary length).
        salt:     A random byte string used to prevent pre-computation
                  attacks.  Must be the same value that was used during
                  encryption when deriving the key for decryption.

    Returns:
        A 44-byte, URL-safe base64-encoded key suitable for use with Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt(plaintext: str, password: str) -> str:
    """Encrypt *plaintext* with *password* and return a portable blob.

    A fresh random salt is generated on every call so that the same
    plaintext encrypted with the same password produces a different blob
    each time.

    Args:
        plaintext: The secret string to encrypt.
        password:  The encryption password chosen by the user.

    Returns:
        A base64url-encoded string of the form ``base64url(salt || token)``
        that is safe to store in a text column.
    """
    salt = os.urandom(_SALT_SIZE)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return base64.urlsafe_b64encode(salt + token).decode("ascii")


def decrypt(blob: str, password: str) -> str:
    """Decrypt a blob produced by :func:`encrypt`.

    Args:
        blob:     The base64url-encoded ``salt || token`` string returned by
                  :func:`encrypt`.
        password: The encryption password chosen by the user.

    Returns:
        The original plaintext string.

    Raises:
        cryptography.fernet.InvalidToken: If *password* is wrong or the blob
            has been corrupted.
        ValueError: If the blob is too short to contain a valid salt prefix.
    """
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    if len(raw) <= _SALT_SIZE:
        raise ValueError("Encrypted blob is too short — data may be corrupted.")
    salt, token = raw[:_SALT_SIZE], raw[_SALT_SIZE:]
    key = derive_key(password, salt)
    return Fernet(key).decrypt(token).decode("utf-8")
