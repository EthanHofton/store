"""Unit tests for tab completion of stored keys.

Completion is tested by driving :class:`click.shell_completion.ShellComplete`
directly, which exercises the full Click completion pipeline without needing a
real shell.  The ``STORE_DB_PATH`` environment variable is pointed at a
temporary database for every test.
"""

from pathlib import Path

import pytest
from click.shell_completion import ShellComplete

from store.cli import _complete_keys, cli
from store.db import Database


@pytest.fixture()
def db_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Temporary database with a handful of known keys."""
    db_path = tmp_path / "store.sqlite"
    monkeypatch.setenv("STORE_DB_PATH", str(db_path))
    with Database(db_path=db_path) as db:
        db.store("github_token", "v")
        db.store("github_secret", "v", encrypted=True)
        db.store("db_password", "v")
    return db_path


def _completions(args: list[str], incomplete: str) -> list[str]:
    """Return completion values for *args* + *incomplete* via Click's pipeline."""
    sc = ShellComplete(cli, {}, "store", "_STORE_COMPLETE")
    return [c.value for c in sc.get_completions(args, incomplete)]


# ---------------------------------------------------------------------------
# _complete_keys unit tests
# ---------------------------------------------------------------------------


class TestCompleteKeysFunction:
    """Tests for the :func:`store.cli._complete_keys` helper directly."""

    def test_returns_all_keys_for_empty_incomplete(self, db_env: Path):
        """An empty incomplete string must return every stored key."""
        items = _complete_keys(None, None, "")
        values = [c.value for c in items]
        assert sorted(values) == ["db_password", "github_secret", "github_token"]

    def test_filters_by_prefix(self, db_env: Path):
        """Only keys that start with *incomplete* must be returned."""
        items = _complete_keys(None, None, "github")
        values = [c.value for c in items]
        assert sorted(values) == ["github_secret", "github_token"]
        assert "db_password" not in values

    def test_exact_match(self, db_env: Path):
        """A fully-typed key must still be returned as a completion."""
        items = _complete_keys(None, None, "db_password")
        assert len(items) == 1
        assert items[0].value == "db_password"

    def test_no_match_returns_empty(self, db_env: Path):
        """A prefix that matches nothing must return an empty list."""
        assert _complete_keys(None, None, "zzz") == []

    def test_empty_database_returns_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Completion against an empty database must return an empty list."""
        monkeypatch.setenv("STORE_DB_PATH", str(tmp_path / "empty.sqlite"))
        assert _complete_keys(None, None, "") == []

    def test_unreachable_db_returns_empty(self, monkeypatch: pytest.MonkeyPatch):
        """An error reaching the database must be swallowed and return empty."""
        monkeypatch.setenv("STORE_DB_PATH", "/nonexistent/path/store.sqlite")
        # Should not raise — completion failures must never crash the shell.
        assert _complete_keys(None, None, "") == []


# ---------------------------------------------------------------------------
# End-to-end completion pipeline tests
# ---------------------------------------------------------------------------


class TestCompletionPipeline:
    """Tests that drive Click's full completion pipeline per command."""

    def test_get_completes_all_keys(self, db_env: Path):
        """``store get <TAB>`` must suggest all stored keys."""
        values = _completions(["get"], "")
        assert sorted(values) == ["db_password", "github_secret", "github_token"]

    def test_get_filters_by_prefix(self, db_env: Path):
        """``store get github<TAB>`` must suggest only keys starting with 'github'."""
        values = _completions(["get"], "github")
        assert sorted(values) == ["github_secret", "github_token"]

    def test_keep_does_not_complete_keys(self, db_env: Path):
        """``store keep <TAB>`` must not suggest existing keys (free-form new key)."""
        values = _completions(["keep"], "")
        assert values == []

    def test_update_completes_keys(self, db_env: Path):
        """``store update <TAB>`` must suggest stored keys."""
        values = _completions(["update"], "")
        assert "github_token" in values

    def test_delete_completes_keys(self, db_env: Path):
        """``store delete <TAB>`` must suggest stored keys."""
        values = _completions(["delete"], "")
        assert "db_password" in values

    def test_rename_old_key_completes_keys(self, db_env: Path):
        """``store rename <TAB>`` must suggest stored keys for the first argument."""
        values = _completions(["rename"], "")
        assert "github_token" in values

    def test_rename_new_key_no_completion(self, db_env: Path):
        """``store rename github_token <TAB>`` must not suggest keys for the new name."""
        values = _completions(["rename", "github_token"], "")
        assert values == []
