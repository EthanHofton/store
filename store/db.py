"""SQLite persistence layer for the store secret manager.

The database is located at ``~/.store/store.sqlite`` by default.  The path
can be overridden via the ``STORE_DB_PATH`` environment variable, which is
primarily useful for testing.

Schema
------
``store`` table:

==========  =======  =====================================================
Column      Type     Description
==========  =======  =====================================================
key         TEXT PK  The lookup key supplied by the user.
value       TEXT     The (possibly encrypted) value.
encrypted   INTEGER  1 if *value* is an encrypted blob, 0 otherwise.
==========  =======  =====================================================
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional, Tuple

# Default DB path; overridable via env var for tests.
_DEFAULT_DB_PATH = Path.home() / ".store" / "store.sqlite"


def _resolve_db_path() -> Path:
    """Return the active database path, honouring ``STORE_DB_PATH`` if set."""
    override = os.environ.get("STORE_DB_PATH")
    return Path(override) if override else _DEFAULT_DB_PATH


class Database:
    """Context-manager wrapper around the store SQLite database.

    Usage::

        with Database() as db:
            db.store("api_key", "s3cr3t")
            value, encrypted = db.retrieve("api_key")

    Args:
        db_path: Path to the SQLite file.  Defaults to
            ``~/.store/store.sqlite`` (or ``STORE_DB_PATH`` env var).
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path: Path = db_path if db_path is not None else _resolve_db_path()
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "Database":
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create the ``store`` table if it does not already exist."""
        assert self._conn is not None
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS store (
                key       TEXT    PRIMARY KEY,
                value     TEXT    NOT NULL,
                encrypted INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(self, key: str, value: str, *, encrypted: bool = False) -> None:
        """Insert or replace a key-value pair.

        If *key* already exists its value and encryption flag are updated
        (upsert semantics).

        Args:
            key:       Lookup key.
            value:     Plaintext or encrypted blob to persist.
            encrypted: ``True`` if *value* is an encrypted blob produced by
                       :func:`store.crypto.encrypt`.
        """
        assert self._conn is not None
        self._conn.execute(
            "INSERT OR REPLACE INTO store (key, value, encrypted) VALUES (?, ?, ?)",
            (key, value, int(encrypted)),
        )
        self._conn.commit()

    def retrieve(self, key: str) -> Optional[Tuple[str, bool]]:
        """Fetch the value associated with *key*.

        Args:
            key: The lookup key to query.

        Returns:
            A ``(value, encrypted)`` tuple, or ``None`` if the key does not
            exist.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT value, encrypted FROM store WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return row[0], bool(row[1])

    def update(self, key: str, value: str, *, encrypted: bool = False) -> bool:
        """Update the value of an existing key.

        Unlike :meth:`store`, this method will not create the key if it does
        not already exist.

        Args:
            key:       Lookup key that must already exist.
            value:     New plaintext or encrypted blob.
            encrypted: ``True`` if *value* is an encrypted blob produced by
                       :func:`store.crypto.encrypt`.  This replaces the
                       previous encryption flag regardless of its prior value.

        Returns:
            ``True`` if the row was updated, ``False`` if the key did not
            exist.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "UPDATE store SET value = ?, encrypted = ? WHERE key = ?",
            (value, int(encrypted), key),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def rename(self, old_key: str, new_key: str) -> bool:
        """Rename *old_key* to *new_key*, preserving the value and encryption flag.

        Args:
            old_key: The existing key to rename.
            new_key: The desired new key name.

        Returns:
            ``True`` if the rename succeeded, ``False`` if *old_key* does not
            exist.

        Raises:
            ValueError: If *new_key* already exists.
        """
        assert self._conn is not None
        if self.retrieve(new_key) is not None:
            raise ValueError(f"Key '{new_key}' already exists.")
        cursor = self._conn.execute(
            "UPDATE store SET key = ? WHERE key = ?", (new_key, old_key)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def delete(self, key: str) -> bool:
        """Delete the entry for *key*.

        Args:
            key: The lookup key to remove.

        Returns:
            ``True`` if a row was deleted, ``False`` if the key did not exist.
        """
        assert self._conn is not None
        cursor = self._conn.execute("DELETE FROM store WHERE key = ?", (key,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_keys(self) -> list[str]:
        """Return all stored keys in alphabetical order.

        Returns:
            A list of key strings, possibly empty.
        """
        assert self._conn is not None
        cursor = self._conn.execute("SELECT key FROM store ORDER BY key")
        return [row[0] for row in cursor.fetchall()]

    def list_entries(self) -> list[tuple[str, bool]]:
        """Return all stored ``(key, encrypted)`` pairs in alphabetical order.

        Returns:
            A list of ``(key, encrypted)`` tuples, possibly empty.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT key, encrypted FROM store ORDER BY key"
        )
        return [(row[0], bool(row[1])) for row in cursor.fetchall()]
