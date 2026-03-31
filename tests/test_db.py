"""Unit tests for store.db."""

from pathlib import Path

import pytest

from store.db import Database


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    """Return an open Database backed by a temporary file."""
    instance = Database(db_path=tmp_path / "test_store.sqlite")
    with instance as opened:
        yield opened


class TestSchema:
    """Tests that verify the schema is created correctly."""

    def test_db_file_is_created(self, tmp_path: Path):
        """Entering the context manager must create the SQLite file."""
        db_path = tmp_path / "sub" / "store.sqlite"
        with Database(db_path=db_path):
            assert db_path.exists()

    def test_parent_directories_are_created(self, tmp_path: Path):
        """Missing parent directories must be created automatically."""
        db_path = tmp_path / "a" / "b" / "c" / "store.sqlite"
        with Database(db_path=db_path):
            assert db_path.parent.is_dir()


class TestStore:
    """Tests for :meth:`store.db.Database.store`."""

    def test_store_and_retrieve_plaintext(self, db: Database):
        """A stored plaintext value must be retrievable."""
        db.store("key1", "value1")
        result = db.retrieve("key1")
        assert result == ("value1", False)

    def test_store_and_retrieve_encrypted(self, db: Database):
        """A stored encrypted blob must be retrievable with encrypted=True."""
        db.store("secret", "blob==", encrypted=True)
        result = db.retrieve("secret")
        assert result == ("blob==", True)

    def test_upsert_overwrites_value(self, db: Database):
        """Storing the same key twice must update the existing row."""
        db.store("key", "old_value")
        db.store("key", "new_value")
        value, _ = db.retrieve("key")
        assert value == "new_value"

    def test_upsert_can_change_encrypted_flag(self, db: Database):
        """Re-storing a key must also update the encrypted flag."""
        db.store("key", "plaintext", encrypted=False)
        db.store("key", "blob==", encrypted=True)
        _, is_encrypted = db.retrieve("key")
        assert is_encrypted is True

    def test_store_empty_string(self, db: Database):
        """Storing an empty string must succeed."""
        db.store("empty", "")
        assert db.retrieve("empty") == ("", False)

    def test_special_characters_in_key(self, db: Database):
        """Keys with special characters must be stored and retrieved correctly."""
        db.store("my/key:with.special-chars", "val")
        assert db.retrieve("my/key:with.special-chars") == ("val", False)


class TestRetrieve:
    """Tests for :meth:`store.db.Database.retrieve`."""

    def test_missing_key_returns_none(self, db: Database):
        """Retrieving a non-existent key must return None."""
        assert db.retrieve("does_not_exist") is None

    def test_returns_tuple(self, db: Database):
        """retrieve must return a two-element tuple."""
        db.store("k", "v")
        result = db.retrieve("k")
        assert isinstance(result, tuple)
        assert len(result) == 2


class TestUpdate:
    """Tests for :meth:`store.db.Database.update`."""

    def test_update_existing_key(self, db: Database):
        """update must return True and persist the new value."""
        db.store("k", "old")
        assert db.update("k", "new") is True
        assert db.retrieve("k") == ("new", False)

    def test_update_missing_key_returns_false(self, db: Database):
        """update must return False when the key does not exist."""
        assert db.update("ghost", "value") is False

    def test_update_missing_key_does_not_create_entry(self, db: Database):
        """update must not create a new row when the key is absent."""
        db.update("ghost", "value")
        assert db.retrieve("ghost") is None

    def test_update_sets_encrypted_flag(self, db: Database):
        """update must overwrite the encrypted flag with the new value."""
        db.store("k", "plain", encrypted=False)
        db.update("k", "blob==", encrypted=True)
        assert db.retrieve("k") == ("blob==", True)

    def test_update_clears_encrypted_flag(self, db: Database):
        """update without --encrypt must clear a previously set encrypted flag."""
        db.store("k", "blob==", encrypted=True)
        db.update("k", "plain", encrypted=False)
        assert db.retrieve("k") == ("plain", False)

    def test_update_does_not_affect_other_keys(self, db: Database):
        """Updating one key must leave other keys unchanged."""
        db.store("a", "1")
        db.store("b", "2")
        db.update("a", "new")
        assert db.retrieve("b") == ("2", False)


class TestRename:
    """Tests for :meth:`store.db.Database.rename`."""

    def test_rename_existing_key(self, db: Database):
        """rename must return True and the new key must hold the original value."""
        db.store("old", "val")
        assert db.rename("old", "new") is True
        assert db.retrieve("new") == ("val", False)

    def test_rename_removes_old_key(self, db: Database):
        """After rename, the old key must no longer exist."""
        db.store("old", "val")
        db.rename("old", "new")
        assert db.retrieve("old") is None

    def test_rename_preserves_encrypted_flag(self, db: Database):
        """rename must carry the encrypted flag over to the new key."""
        db.store("old", "blob==", encrypted=True)
        db.rename("old", "new")
        assert db.retrieve("new") == ("blob==", True)

    def test_rename_missing_key_returns_false(self, db: Database):
        """rename must return False when old_key does not exist."""
        assert db.rename("ghost", "new") is False

    def test_rename_to_existing_key_raises(self, db: Database):
        """rename must raise ValueError when new_key already exists."""
        db.store("a", "1")
        db.store("b", "2")
        with pytest.raises(ValueError, match="already exists"):
            db.rename("a", "b")

    def test_rename_does_not_affect_other_keys(self, db: Database):
        """rename must leave unrelated entries unchanged."""
        db.store("a", "1")
        db.store("b", "2")
        db.rename("a", "c")
        assert db.retrieve("b") == ("2", False)


class TestDelete:
    """Tests for :meth:`store.db.Database.delete`."""

    def test_delete_existing_key(self, db: Database):
        """Deleting an existing key must return True and remove the entry."""
        db.store("k", "v")
        assert db.delete("k") is True
        assert db.retrieve("k") is None

    def test_delete_missing_key_returns_false(self, db: Database):
        """Deleting a non-existent key must return False."""
        assert db.delete("ghost") is False

    def test_delete_does_not_affect_other_keys(self, db: Database):
        """Deleting one key must leave other keys intact."""
        db.store("a", "1")
        db.store("b", "2")
        db.delete("a")
        assert db.retrieve("b") == ("2", False)


class TestListKeys:
    """Tests for :meth:`store.db.Database.list_keys`."""

    def test_empty_database(self, db: Database):
        """list_keys on an empty database must return an empty list."""
        assert db.list_keys() == []

    def test_returns_all_keys(self, db: Database):
        """list_keys must return every stored key."""
        db.store("beta", "2")
        db.store("alpha", "1")
        db.store("gamma", "3")
        assert db.list_keys() == ["alpha", "beta", "gamma"]

    def test_alphabetical_order(self, db: Database):
        """list_keys must return keys sorted alphabetically."""
        for key in ("z", "a", "m"):
            db.store(key, "v")
        assert db.list_keys() == ["a", "m", "z"]

    def test_deleted_key_not_listed(self, db: Database):
        """A deleted key must not appear in list_keys."""
        db.store("k", "v")
        db.delete("k")
        assert "k" not in db.list_keys()


class TestListEntries:
    """Tests for :meth:`store.db.Database.list_entries`."""

    def test_empty_database(self, db: Database):
        """list_entries on an empty database must return an empty list."""
        assert db.list_entries() == []

    def test_returns_all_entries(self, db: Database):
        """list_entries must return every stored (key, encrypted) pair."""
        db.store("beta", "2", encrypted=False)
        db.store("alpha", "1", encrypted=True)
        assert db.list_entries() == [("alpha", True), ("beta", False)]

    def test_alphabetical_order(self, db: Database):
        """list_entries must return entries sorted alphabetically by key."""
        for key in ("z", "a", "m"):
            db.store(key, "v")
        keys = [k for k, _ in db.list_entries()]
        assert keys == ["a", "m", "z"]

    def test_encrypted_flag_preserved(self, db: Database):
        """list_entries must faithfully report the encrypted flag for each entry."""
        db.store("plain", "v", encrypted=False)
        db.store("secret", "blob", encrypted=True)
        entries = dict(db.list_entries())
        assert entries["plain"] is False
        assert entries["secret"] is True

    def test_deleted_key_not_listed(self, db: Database):
        """A deleted key must not appear in list_entries."""
        db.store("k", "v")
        db.delete("k")
        assert all(k != "k" for k, _ in db.list_entries())


class TestContextManager:
    """Tests for Database context manager behaviour."""

    def test_connection_closed_after_exit(self, tmp_path: Path):
        """The connection must be closed after the context manager exits."""
        db_path = tmp_path / "store.sqlite"
        instance = Database(db_path=db_path)
        with instance:
            pass
        assert instance._conn is None

    def test_reentrant_usage(self, tmp_path: Path):
        """Database can be opened twice sequentially."""
        db_path = tmp_path / "store.sqlite"
        with Database(db_path=db_path) as db:
            db.store("k", "v")
        with Database(db_path=db_path) as db:
            assert db.retrieve("k") == ("v", False)
