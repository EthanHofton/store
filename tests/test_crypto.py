"""Unit tests for store.crypto."""

import base64

import pytest
from cryptography.fernet import InvalidToken

from store.crypto import _SALT_SIZE, decrypt, derive_key, encrypt


class TestDeriveKey:
    """Tests for :func:`store.crypto.derive_key`."""

    def test_returns_bytes(self):
        """derive_key should return bytes."""
        key = derive_key("password", b"0123456789abcdef")
        assert isinstance(key, bytes)

    def test_correct_length_for_fernet(self):
        """Derived key must be 44 bytes (32 raw bytes, base64url-encoded)."""
        key = derive_key("password", b"0123456789abcdef")
        # Fernet expects a URL-safe base64-encoded 32-byte key → 44 chars.
        assert len(key) == 44

    def test_same_inputs_produce_same_key(self):
        """Derivation must be deterministic for the same password and salt."""
        salt = b"abcdefghijklmnop"
        assert derive_key("pw", salt) == derive_key("pw", salt)

    def test_different_salts_produce_different_keys(self):
        """Different salts must yield different keys."""
        key1 = derive_key("pw", b"aaaaaaaaaaaaaaaa")
        key2 = derive_key("pw", b"bbbbbbbbbbbbbbbb")
        assert key1 != key2

    def test_different_passwords_produce_different_keys(self):
        """Different passwords must yield different keys."""
        salt = b"0123456789abcdef"
        assert derive_key("password1", salt) != derive_key("password2", salt)


class TestEncrypt:
    """Tests for :func:`store.crypto.encrypt`."""

    def test_returns_string(self):
        """encrypt should return a str."""
        result = encrypt("secret", "password")
        assert isinstance(result, str)

    def test_output_is_base64url(self):
        """Output must be valid URL-safe base64."""
        result = encrypt("secret", "password")
        # Should not raise.
        base64.urlsafe_b64decode(result.encode("ascii"))

    def test_blob_contains_salt_prefix(self):
        """Decoded blob must be at least SALT_SIZE bytes longer than an empty token."""
        result = encrypt("", "password")
        raw = base64.urlsafe_b64decode(result.encode("ascii"))
        assert len(raw) > _SALT_SIZE

    def test_same_plaintext_produces_different_blobs(self):
        """Fresh random salt means two calls yield different ciphertexts."""
        b1 = encrypt("secret", "password")
        b2 = encrypt("secret", "password")
        assert b1 != b2

    def test_empty_plaintext(self):
        """Encrypting an empty string should succeed."""
        blob = encrypt("", "password")
        assert isinstance(blob, str)


class TestDecrypt:
    """Tests for :func:`store.crypto.decrypt`."""

    def test_roundtrip(self):
        """encrypt then decrypt must recover the original plaintext."""
        plaintext = "super secret value"
        blob = encrypt(plaintext, "my-password")
        assert decrypt(blob, "my-password") == plaintext

    def test_unicode_roundtrip(self):
        """Non-ASCII plaintext must survive the roundtrip."""
        plaintext = "パスワード 🔑"
        blob = encrypt(plaintext, "pw")
        assert decrypt(blob, "pw") == plaintext

    def test_wrong_password_raises(self):
        """Decrypting with the wrong password must raise InvalidToken."""
        blob = encrypt("secret", "correct-password")
        with pytest.raises(InvalidToken):
            decrypt(blob, "wrong-password")

    def test_corrupted_blob_raises(self):
        """A truncated / corrupted blob must raise an exception."""
        blob = encrypt("secret", "pw")
        # Corrupt the blob by truncating it.
        corrupted = blob[: len(blob) // 2]
        with pytest.raises(Exception):
            decrypt(corrupted, "pw")

    def test_too_short_blob_raises_value_error(self):
        """A blob shorter than the salt prefix must raise ValueError."""
        # Encode fewer than _SALT_SIZE bytes.
        tiny = base64.urlsafe_b64encode(b"tooshort").decode("ascii")
        with pytest.raises(ValueError, match="too short"):
            decrypt(tiny, "pw")

    def test_empty_plaintext_roundtrip(self):
        """An empty plaintext should survive the roundtrip."""
        blob = encrypt("", "pw")
        assert decrypt(blob, "pw") == ""
