"""Unit tests for store.cli.

All tests use Click's :class:`~click.testing.CliRunner` so that no real
database is created.  The ``STORE_DB_PATH`` environment variable is pointed at
a temporary file for every test that touches the database.
"""

import re
from importlib.metadata import version
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.fernet import InvalidToken

from store.cli import cli
from store.crypto import encrypt


@pytest.fixture()
def runner():
    """Return a Click test runner."""
    return CliRunner()


# ---------------------------------------------------------------------------
# `store --version` tests
# ---------------------------------------------------------------------------


class TestVersionOption:
    """Tests for the ``--version`` flag."""

    def test_version_exits_zero(self, runner: CliRunner):
        """--version must exit 0."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    def test_version_output_contains_version(self, runner: CliRunner):
        """--version output must include the installed package version."""
        result = runner.invoke(cli, ["--version"])
        assert version("store") in result.output

    def test_version_output_contains_prog_name(self, runner: CliRunner):
        """--version output must include the program name."""
        result = runner.invoke(cli, ["--version"])
        assert "store" in result.output.lower()


@pytest.fixture()
def db_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point STORE_DB_PATH at a temp file and return the path."""
    db_path = tmp_path / "store.sqlite"
    monkeypatch.setenv("STORE_DB_PATH", str(db_path))
    return db_path


# ---------------------------------------------------------------------------
# `store keep` tests
# ---------------------------------------------------------------------------


class TestKeepCommand:
    """Tests for the ``store keep`` command."""

    def test_keep_plaintext(self, runner: CliRunner, db_env: Path):
        """Storing a plaintext value must exit 0 and confirm the key name."""
        result = runner.invoke(cli, ["keep", "api_key", "abc123"])
        assert result.exit_code == 0
        assert "api_key" in result.output

    def test_keep_creates_db_file(self, runner: CliRunner, db_env: Path):
        """Running keep must create the SQLite file."""
        runner.invoke(cli, ["keep", "k", "v"])
        assert db_env.exists()

    def test_keep_encrypted(self, runner: CliRunner, db_env: Path):
        """Storing with --encrypt must succeed when passwords match."""
        result = runner.invoke(
            cli,
            ["keep", "secret", "mysecretvalue", "--encrypt"],
            input="password\npassword\n",
        )
        assert result.exit_code == 0
        assert "secret" in result.output

    def test_keep_encrypted_empty_password(self, runner: CliRunner, db_env: Path):
        """An empty string is a valid encryption password — keep and get must roundtrip."""
        runner.invoke(
            cli,
            ["keep", "k", "secret", "--encrypt"],
            input="\n\n",  # empty password, empty confirmation
        )
        result = runner.invoke(cli, ["get", "k"], input="\n")
        assert result.exit_code == 0
        assert result.output.splitlines()[-1] == "secret"

    def test_keep_encrypted_password_mismatch(self, runner: CliRunner, db_env: Path):
        """Storing with --encrypt must fail when the confirmation password differs."""
        result = runner.invoke(
            cli,
            ["keep", "secret", "value", "--encrypt"],
            input="password1\npassword2\n",
        )
        assert result.exit_code != 0

    def test_keep_upsert(self, runner: CliRunner, db_env: Path):
        """Calling keep twice with the same key must overwrite the old value."""
        runner.invoke(cli, ["keep", "k", "first"])
        runner.invoke(cli, ["keep", "k", "second"])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "second"

    def test_keep_requires_key_and_value(self, runner: CliRunner, db_env: Path):
        """keep must fail when neither VALUE nor --from-file is provided."""
        result = runner.invoke(cli, ["keep", "only_key"])
        assert result.exit_code != 0

    def test_keep_from_file(self, runner: CliRunner, db_env: Path, tmp_path: Path):
        """--from-file must read the file contents as the stored value."""
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file_contents")
        runner.invoke(cli, ["keep", "k", "--from-file", str(secret_file)])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "file_contents"

    def test_keep_from_file_strips_trailing_newline(
        self, runner: CliRunner, db_env: Path, tmp_path: Path
    ):
        """Trailing newlines added by text editors must be stripped."""
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("api_key_value\n")
        runner.invoke(cli, ["keep", "k", "--from-file", str(secret_file)])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "api_key_value"

    def test_keep_from_file_short_flag(self, runner: CliRunner, db_env: Path, tmp_path: Path):
        """-f short flag must behave identically to --from-file."""
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("short_flag_value")
        runner.invoke(cli, ["keep", "k", "-f", str(secret_file)])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "short_flag_value"

    def test_keep_from_file_with_encrypt(self, runner: CliRunner, db_env: Path, tmp_path: Path):
        """--from-file combined with --encrypt must encrypt the file contents."""
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file_secret")
        runner.invoke(
            cli,
            ["keep", "k", "--from-file", str(secret_file), "--encrypt"],
            input="pw\npw\n",
        )
        result = runner.invoke(cli, ["get", "k"], input="pw\n")
        assert result.exit_code == 0
        assert result.output.splitlines()[-1] == "file_secret"

    def test_keep_from_file_missing_file_exits_nonzero(
        self, runner: CliRunner, db_env: Path
    ):
        """--from-file must exit non-zero when the file does not exist."""
        result = runner.invoke(cli, ["keep", "k", "--from-file", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_keep_value_and_from_file_mutually_exclusive(
        self, runner: CliRunner, db_env: Path, tmp_path: Path
    ):
        """Providing both VALUE and --from-file must exit non-zero."""
        f = tmp_path / "f.txt"
        f.write_text("x")
        result = runner.invoke(cli, ["keep", "k", "value", "--from-file", str(f)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# `store get` tests
# ---------------------------------------------------------------------------


class TestGetCommand:
    """Tests for the ``store get`` command."""

    def test_get_plaintext(self, runner: CliRunner, db_env: Path):
        """get must print the stored plaintext value to stdout."""
        runner.invoke(cli, ["keep", "token", "abc123"])
        result = runner.invoke(cli, ["get", "token"])
        assert result.exit_code == 0
        assert result.output.strip() == "abc123"

    def test_get_missing_key_exits_nonzero(self, runner: CliRunner, db_env: Path):
        """get for a non-existent key must exit with a non-zero code."""
        result = runner.invoke(cli, ["get", "does_not_exist"])
        assert result.exit_code != 0

    def test_get_missing_key_error_message(self, runner: CliRunner, db_env: Path):
        """get for a non-existent key must print an error message containing the key."""
        result = runner.invoke(cli, ["get", "ghost"])
        assert "ghost" in result.output

    def test_get_encrypted_correct_password(self, runner: CliRunner, db_env: Path):
        """get must decrypt and print the plaintext when the password is correct."""
        runner.invoke(
            cli,
            ["keep", "pw_key", "topsecret", "--encrypt"],
            input="hunter2\nhunter2\n",
        )
        result = runner.invoke(cli, ["get", "pw_key"], input="hunter2\n")
        assert result.exit_code == 0
        # Output includes the password prompt; the last line is the decrypted value.
        assert result.output.splitlines()[-1] == "topsecret"

    def test_get_encrypted_wrong_password_exits_nonzero(
        self, runner: CliRunner, db_env: Path
    ):
        """get must exit non-zero when the decryption password is wrong."""
        runner.invoke(
            cli,
            ["keep", "pw_key", "topsecret", "--encrypt"],
            input="correct\ncorrect\n",
        )
        result = runner.invoke(cli, ["get", "pw_key"], input="wrong\n")
        assert result.exit_code != 0

    def test_get_encrypted_wrong_password_error_message(
        self, runner: CliRunner, db_env: Path
    ):
        """get must report a decryption error message for a wrong password."""
        runner.invoke(
            cli,
            ["keep", "pw_key", "value", "--encrypt"],
            input="correct\ncorrect\n",
        )
        result = runner.invoke(cli, ["get", "pw_key"], input="wrong\n")
        combined = result.output.lower()
        assert "wrong password" in combined or "error" in combined

    def test_get_output_ends_with_newline(self, runner: CliRunner, db_env: Path):
        """get output must be terminated by a newline for shell compatibility."""
        runner.invoke(cli, ["keep", "k", "v"])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.endswith("\n")

    def test_get_requires_key_argument(self, runner: CliRunner, db_env: Path):
        """get must fail when no key argument is supplied."""
        result = runner.invoke(cli, ["get"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# `store update` tests
# ---------------------------------------------------------------------------


class TestUpdateCommand:
    """Tests for the ``store update`` command."""

    def test_update_existing_key(self, runner: CliRunner, db_env: Path):
        """update must exit 0 and confirm the key name."""
        runner.invoke(cli, ["keep", "k", "old"])
        result = runner.invoke(cli, ["update", "k", "new"])
        assert result.exit_code == 0
        assert "k" in result.output

    def test_update_changes_value(self, runner: CliRunner, db_env: Path):
        """After update, get must return the new value."""
        runner.invoke(cli, ["keep", "k", "old"])
        runner.invoke(cli, ["update", "k", "new"])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "new"

    def test_update_missing_key_exits_nonzero(self, runner: CliRunner, db_env: Path):
        """update must exit non-zero when the key does not exist."""
        result = runner.invoke(cli, ["update", "ghost", "value"])
        assert result.exit_code != 0

    def test_update_missing_key_error_message(self, runner: CliRunner, db_env: Path):
        """update must include the key name in the error output."""
        result = runner.invoke(cli, ["update", "ghost", "value"])
        assert "ghost" in result.output

    def test_update_with_encrypt(self, runner: CliRunner, db_env: Path):
        """update --encrypt must store the new value encrypted."""
        runner.invoke(cli, ["keep", "k", "plain"])
        runner.invoke(cli, ["update", "k", "secret", "--encrypt"], input="pw\npw\n")
        result = runner.invoke(cli, ["get", "k"], input="pw\n")
        assert result.exit_code == 0
        assert result.output.splitlines()[-1] == "secret"

    def test_update_removes_encryption(self, runner: CliRunner, db_env: Path):
        """update without --encrypt must store plaintext even if key was encrypted."""
        runner.invoke(cli, ["keep", "k", "secret", "--encrypt"], input="pw\npw\n")
        runner.invoke(cli, ["update", "k", "nowplain"])
        result = runner.invoke(cli, ["get", "k"])
        assert result.exit_code == 0
        assert result.output.strip() == "nowplain"

    def test_update_wrong_password_after_re_encrypt(self, runner: CliRunner, db_env: Path):
        """A new encryption password from update must be required for decryption."""
        runner.invoke(cli, ["keep", "k", "v", "--encrypt"], input="oldpw\noldpw\n")
        runner.invoke(cli, ["update", "k", "v2", "--encrypt"], input="newpw\nnewpw\n")
        result = runner.invoke(cli, ["get", "k"], input="oldpw\n")
        assert result.exit_code != 0

    def test_update_requires_key_and_value(self, runner: CliRunner, db_env: Path):
        """update must fail when neither VALUE nor --from-file is provided."""
        result = runner.invoke(cli, ["update", "only_key"])
        assert result.exit_code != 0

    def test_update_from_file(self, runner: CliRunner, db_env: Path, tmp_path: Path):
        """--from-file must read the file contents as the updated value."""
        runner.invoke(cli, ["keep", "k", "old"])
        f = tmp_path / "new.txt"
        f.write_text("new_from_file")
        runner.invoke(cli, ["update", "k", "--from-file", str(f)])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "new_from_file"

    def test_update_from_file_strips_trailing_newline(
        self, runner: CliRunner, db_env: Path, tmp_path: Path
    ):
        """Trailing newlines must be stripped when reading from a file."""
        runner.invoke(cli, ["keep", "k", "old"])
        f = tmp_path / "new.txt"
        f.write_text("new_value\n")
        runner.invoke(cli, ["update", "k", "--from-file", str(f)])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "new_value"

    def test_update_from_file_short_flag(
        self, runner: CliRunner, db_env: Path, tmp_path: Path
    ):
        """-f short flag must behave identically to --from-file on update."""
        runner.invoke(cli, ["keep", "k", "old"])
        f = tmp_path / "new.txt"
        f.write_text("short_flag")
        runner.invoke(cli, ["update", "k", "-f", str(f)])
        result = runner.invoke(cli, ["get", "k"])
        assert result.output.strip() == "short_flag"

    def test_update_from_file_with_encrypt(
        self, runner: CliRunner, db_env: Path, tmp_path: Path
    ):
        """--from-file combined with --encrypt must encrypt the file contents."""
        runner.invoke(cli, ["keep", "k", "old"])
        f = tmp_path / "secret.txt"
        f.write_text("file_secret")
        runner.invoke(cli, ["update", "k", "--from-file", str(f), "--encrypt"], input="pw\npw\n")
        result = runner.invoke(cli, ["get", "k"], input="pw\n")
        assert result.exit_code == 0
        assert result.output.splitlines()[-1] == "file_secret"

    def test_update_value_and_from_file_mutually_exclusive(
        self, runner: CliRunner, db_env: Path, tmp_path: Path
    ):
        """Providing both VALUE and --from-file must exit non-zero."""
        runner.invoke(cli, ["keep", "k", "old"])
        f = tmp_path / "f.txt"
        f.write_text("x")
        result = runner.invoke(cli, ["update", "k", "value", "--from-file", str(f)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# `store list` tests
# ---------------------------------------------------------------------------

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI colour codes from *text* for plain-text assertions."""
    return _ANSI_ESCAPE.sub("", text)


class TestListCommand:
    """Tests for the ``store list`` command."""

    def test_list_empty_database(self, runner: CliRunner, db_env: Path):
        """list on an empty database must exit 0 and note no entries."""
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "no entries" in _strip_ansi(result.output).lower()

    def test_list_shows_all_keys(self, runner: CliRunner, db_env: Path):
        """list must show every stored key."""
        runner.invoke(cli, ["keep", "alpha", "1"])
        runner.invoke(cli, ["keep", "beta", "2"])
        plain = _strip_ansi(result := runner.invoke(cli, ["list"])).output if False else _strip_ansi(runner.invoke(cli, ["list"]).output)
        assert "alpha" in plain
        assert "beta" in plain

    def test_list_shows_enc_badge_for_encrypted(self, runner: CliRunner, db_env: Path):
        """list must show the [enc] badge next to an encrypted key."""
        runner.invoke(cli, ["keep", "secret", "v", "--encrypt"], input="pw\npw\n")
        plain = _strip_ansi(runner.invoke(cli, ["list"]).output)
        assert "[enc]" in plain

    def test_list_shows_plain_badge_for_plaintext(self, runner: CliRunner, db_env: Path):
        """list must show the [plain] badge next to a plaintext key."""
        runner.invoke(cli, ["keep", "plain_key", "v"])
        plain = _strip_ansi(runner.invoke(cli, ["list"]).output)
        assert "[plain]" in plain

    def test_list_shows_summary(self, runner: CliRunner, db_env: Path):
        """list must print a summary line with entry and encryption counts."""
        runner.invoke(cli, ["keep", "a", "1"])
        runner.invoke(cli, ["keep", "b", "2", "--encrypt"], input="pw\npw\n")
        plain = _strip_ansi(runner.invoke(cli, ["list"]).output)
        assert "2 entries" in plain
        assert "1 encrypted" in plain

    def test_list_exits_zero(self, runner: CliRunner, db_env: Path):
        """list must exit 0."""
        runner.invoke(cli, ["keep", "k", "v"])
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0

    # --encrypted filter

    def test_list_encrypted_filter(self, runner: CliRunner, db_env: Path):
        """--encrypted must show only encrypted keys."""
        runner.invoke(cli, ["keep", "plain_key", "v"])
        runner.invoke(cli, ["keep", "secret_key", "v", "--encrypt"], input="pw\npw\n")
        plain = _strip_ansi(runner.invoke(cli, ["list", "--encrypted"]).output)
        assert "secret_key" in plain
        assert "plain_key" not in plain

    def test_list_encrypted_empty(self, runner: CliRunner, db_env: Path):
        """--encrypted on a database with no encrypted entries reports no entries."""
        runner.invoke(cli, ["keep", "k", "v"])
        plain = _strip_ansi(runner.invoke(cli, ["list", "--encrypted"]).output)
        assert "no entries" in plain.lower()

    # --unencrypted filter

    def test_list_unencrypted_filter(self, runner: CliRunner, db_env: Path):
        """--unencrypted must show only plaintext keys."""
        runner.invoke(cli, ["keep", "plain_key", "v"])
        runner.invoke(cli, ["keep", "secret_key", "v", "--encrypt"], input="pw\npw\n")
        plain = _strip_ansi(runner.invoke(cli, ["list", "--unencrypted"]).output)
        assert "plain_key" in plain
        assert "secret_key" not in plain

    # --search filter

    def test_list_search_matches(self, runner: CliRunner, db_env: Path):
        """--search must show only keys containing the search term."""
        runner.invoke(cli, ["keep", "github_token", "v"])
        runner.invoke(cli, ["keep", "db_password", "v"])
        plain = _strip_ansi(runner.invoke(cli, ["list", "--search", "github"]).output)
        assert "github_token" in plain
        assert "db_password" not in plain

    def test_list_search_case_insensitive(self, runner: CliRunner, db_env: Path):
        """--search must match regardless of case."""
        runner.invoke(cli, ["keep", "GitHub_Token", "v"])
        plain = _strip_ansi(runner.invoke(cli, ["list", "--search", "github"]).output)
        assert "GitHub_Token" in plain

    def test_list_search_no_matches(self, runner: CliRunner, db_env: Path):
        """--search with no matches must report no entries."""
        runner.invoke(cli, ["keep", "k", "v"])
        plain = _strip_ansi(runner.invoke(cli, ["list", "--search", "zzz"]).output)
        assert "no entries" in plain.lower()

    def test_list_search_combined_with_encrypted(self, runner: CliRunner, db_env: Path):
        """--search combined with --encrypted must apply both filters."""
        runner.invoke(cli, ["keep", "github_token", "v"])
        runner.invoke(cli, ["keep", "github_secret", "v", "--encrypt"], input="pw\npw\n")
        plain = _strip_ansi(
            runner.invoke(cli, ["list", "--encrypted", "--search", "github"]).output
        )
        assert "github_secret" in plain
        assert "github_token" not in plain

    # mutual exclusion

    def test_list_encrypted_and_unencrypted_mutually_exclusive(
        self, runner: CliRunner, db_env: Path
    ):
        """--encrypted and --unencrypted together must exit non-zero."""
        result = runner.invoke(cli, ["list", "--encrypted", "--unencrypted"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# `store rename` tests
# ---------------------------------------------------------------------------


class TestRenameCommand:
    """Tests for the ``store rename`` command."""

    def test_rename_existing_key(self, runner: CliRunner, db_env: Path):
        """rename must exit 0 and confirm the old and new key names."""
        runner.invoke(cli, ["keep", "old", "v"])
        result = runner.invoke(cli, ["rename", "old", "new"])
        assert result.exit_code == 0
        assert "old" in result.output
        assert "new" in result.output

    def test_rename_new_key_retrievable(self, runner: CliRunner, db_env: Path):
        """After rename, the value must be retrievable under the new key."""
        runner.invoke(cli, ["keep", "old", "myvalue"])
        runner.invoke(cli, ["rename", "old", "new"])
        result = runner.invoke(cli, ["get", "new"])
        assert result.exit_code == 0
        assert result.output.strip() == "myvalue"

    def test_rename_old_key_gone(self, runner: CliRunner, db_env: Path):
        """After rename, the old key must no longer exist."""
        runner.invoke(cli, ["keep", "old", "v"])
        runner.invoke(cli, ["rename", "old", "new"])
        result = runner.invoke(cli, ["get", "old"])
        assert result.exit_code != 0

    def test_rename_preserves_encryption(self, runner: CliRunner, db_env: Path):
        """rename must preserve the encrypted flag — decryption must still work."""
        runner.invoke(cli, ["keep", "old", "secret", "--encrypt"], input="pw\npw\n")
        runner.invoke(cli, ["rename", "old", "new"])
        result = runner.invoke(cli, ["get", "new"], input="pw\n")
        assert result.exit_code == 0
        assert result.output.splitlines()[-1] == "secret"

    def test_rename_missing_key_exits_nonzero(self, runner: CliRunner, db_env: Path):
        """rename must exit non-zero when old_key does not exist."""
        result = runner.invoke(cli, ["rename", "ghost", "new"])
        assert result.exit_code != 0

    def test_rename_missing_key_error_message(self, runner: CliRunner, db_env: Path):
        """rename must include the missing key name in the error output."""
        result = runner.invoke(cli, ["rename", "ghost", "new"])
        assert "ghost" in result.output

    def test_rename_to_existing_key_exits_nonzero(self, runner: CliRunner, db_env: Path):
        """rename must exit non-zero when new_key already exists."""
        runner.invoke(cli, ["keep", "a", "1"])
        runner.invoke(cli, ["keep", "b", "2"])
        result = runner.invoke(cli, ["rename", "a", "b"])
        assert result.exit_code != 0

    def test_rename_to_existing_key_error_message(self, runner: CliRunner, db_env: Path):
        """rename must mention the conflicting key in the error output."""
        runner.invoke(cli, ["keep", "a", "1"])
        runner.invoke(cli, ["keep", "b", "2"])
        result = runner.invoke(cli, ["rename", "a", "b"])
        assert "b" in result.output

    def test_rename_requires_two_arguments(self, runner: CliRunner, db_env: Path):
        """rename must fail when either argument is missing."""
        result = runner.invoke(cli, ["rename", "only_one"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# `store delete` tests
# ---------------------------------------------------------------------------


class TestDeleteCommand:
    """Tests for the ``store delete`` command."""

    def test_delete_existing_key(self, runner: CliRunner, db_env: Path):
        """delete must exit 0 and confirm deletion for an existing key."""
        runner.invoke(cli, ["keep", "k", "v"])
        result = runner.invoke(cli, ["delete", "k"])
        assert result.exit_code == 0
        assert "k" in result.output

    def test_delete_removes_key(self, runner: CliRunner, db_env: Path):
        """After deletion, get must report the key as not found."""
        runner.invoke(cli, ["keep", "k", "v"])
        runner.invoke(cli, ["delete", "k"])
        result = runner.invoke(cli, ["get", "k"])
        assert result.exit_code != 0

    def test_delete_missing_key_exits_nonzero(self, runner: CliRunner, db_env: Path):
        """delete must exit non-zero when the key does not exist."""
        result = runner.invoke(cli, ["delete", "ghost"])
        assert result.exit_code != 0

    def test_delete_missing_key_error_message(self, runner: CliRunner, db_env: Path):
        """delete must include the key name in the error output."""
        result = runner.invoke(cli, ["delete", "ghost"])
        assert "ghost" in result.output

    def test_delete_does_not_affect_other_keys(self, runner: CliRunner, db_env: Path):
        """Deleting one key must leave other keys retrievable."""
        runner.invoke(cli, ["keep", "a", "1"])
        runner.invoke(cli, ["keep", "b", "2"])
        runner.invoke(cli, ["delete", "a"])
        result = runner.invoke(cli, ["get", "b"])
        assert result.exit_code == 0
        assert result.output.strip() == "b: \n2" or "2" in result.output

    def test_delete_requires_key_argument(self, runner: CliRunner, db_env: Path):
        """delete must fail when no key argument is supplied."""
        result = runner.invoke(cli, ["delete"])
        assert result.exit_code != 0
