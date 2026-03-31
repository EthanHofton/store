"""Command-line interface for the store secret manager.

Commands
--------
``store keep <key> <value> [--encrypt]``
``store keep <key> -f <file> [--encrypt]``
    Persist a key-value pair.  The value may be a positional argument or
    read from a file with ``-f``/``--from-file``.  Pass ``--encrypt`` to
    be prompted for a password; the value will be encrypted before storage.

``store get <key>``
    Retrieve a value.  If the stored entry is encrypted the user is
    prompted for the decryption password.

``store list [--encrypted] [--unencrypted] [--search TERM]``
    List all stored keys with an indicator for encrypted entries.
    Optional flags filter by encryption status or key substring.

``store delete <key>``
    Remove a key-value pair from the database.

``store rename <old_key> <new_key>``
    Rename a key, preserving its value and encryption status.

``store update <key> <value> [--encrypt]``
``store update <key> -f <file> [--encrypt]``
    Update the value of an existing key.  Fails if the key does not exist.
    The encryption flag is set from the current call, overriding the
    previous setting.
"""

import getpass
import sys
from importlib.metadata import PackageNotFoundError, version

import click
from click.shell_completion import CompletionItem
from cryptography.fernet import InvalidToken

from store.crypto import decrypt, encrypt
from store.db import Database


def _complete_keys(
    ctx: click.Context, param: click.Parameter, incomplete: str
) -> list[CompletionItem]:
    """Return stored keys that start with *incomplete* for shell tab completion.

    Args:
        ctx:        The current Click context (unused).
        param:      The parameter being completed (unused).
        incomplete: The partially-typed string the user has entered so far.

    Returns:
        A list of :class:`~click.shell_completion.CompletionItem` whose values
        begin with *incomplete* (case-sensitive).
    """
    try:
        with Database() as db:
            keys = db.list_keys()
    except Exception:
        return []
    return [CompletionItem(k) for k in keys if k.startswith(incomplete)]


def _prompt_password(prompt: str, *, confirm: bool = False) -> str:
    """Prompt for a password, allowing empty strings.

    :func:`click.prompt` with ``hide_input=True`` rejects empty input
    internally.  This helper bypasses that restriction by using
    :func:`getpass.getpass` on real terminals and reading directly from
    ``sys.stdin`` when input is redirected (e.g. during tests).

    Args:
        prompt:  The prompt label shown to the user (without trailing colon).
        confirm: When ``True``, prompt a second time and raise
                 :class:`click.UsageError` if the two values differ.

    Returns:
        The password string entered by the user (may be empty).

    Raises:
        click.UsageError: If *confirm* is ``True`` and the two entries differ.
    """
    def _read(label: str) -> str:
        click.echo(f"{label}: ", nl=False, err=True)
        if sys.stdin.isatty():
            password = getpass.getpass(prompt="")
        else:
            password = sys.stdin.readline().rstrip("\n")
            click.echo("", err=True)  # echo the newline the terminal would show
        return password

    password = _read(prompt)
    if confirm:
        confirmation = _read("Confirm password")
        if password != confirmation:
            raise click.UsageError("Passwords do not match.")
    return password

try:
    _version = version("store")
except PackageNotFoundError:
    _version = "unknown"


@click.group()
@click.version_option(version=_version, prog_name="store")
def cli() -> None:
    """Store — a simple secret manager."""


@cli.command("keep")
@click.argument("key")
@click.argument("value", default=None, required=False)
@click.option(
    "-f",
    "--from-file",
    "from_file",
    type=click.Path(exists=True, readable=True, dir_okay=False),
    default=None,
    help="Read the value from FILE instead of the VALUE argument.",
)
@click.option(
    "--encrypt",
    "do_encrypt",
    is_flag=True,
    default=False,
    help="Encrypt the value before storing it.",
)
def keep(key: str, value: str | None, from_file: str | None, do_encrypt: bool) -> None:
    """Store KEY with VALUE.

    VALUE may be supplied as a positional argument or read from a file with
    ``-f``/``--from-file``.  Exactly one of the two must be provided.

    If --encrypt is supplied you will be prompted for a password twice
    (confirmation).  The value is encrypted with that password before it is
    written to the database.

    \b
    Examples
    --------
        store keep github_token ghp_abc123
        store keep db_password s3cr3t --encrypt
        store keep tls_cert -f /etc/ssl/certs/server.pem
        store keep private_key -f ~/.ssh/id_rsa --encrypt
    """
    if (value is None) == (from_file is None):
        raise click.UsageError("Provide either VALUE or --from-file, not both (or neither).")

    if from_file is not None:
        value = click.open_file(from_file).read().rstrip("\n")

    if do_encrypt:
        password = _prompt_password("Encryption password", confirm=True)
        value = encrypt(value, password)

    with Database() as db:
        db.store(key, value, encrypted=do_encrypt)

    click.echo(f"Stored '{key}'.")


@cli.command("get")
@click.argument("key")
def get(key: str) -> None:
    """Retrieve the value for KEY.

    If the entry was stored with --encrypt you will be prompted for the
    decryption password.  The decrypted value is written to stdout so that
    it can be captured by shell scripts.

    \b
    Examples
    --------
        store get github_token
        value=$(store get db_password)
    """
    with Database() as db:
        result = db.retrieve(key)

    if result is None:
        click.echo(f"Error: key '{key}' not found.", err=True)
        sys.exit(1)

    value, is_encrypted = result

    if is_encrypted:
        password = _prompt_password("Decryption password")
        try:
            value = decrypt(value, password)
        except (InvalidToken, ValueError):
            click.echo("Error: wrong password or corrupted data.", err=True)
            sys.exit(1)

    click.echo(value)


@cli.command("update")
@click.argument("key")
@click.argument("value", default=None, required=False)
@click.option(
    "-f",
    "--from-file",
    "from_file",
    type=click.Path(exists=True, readable=True, dir_okay=False),
    default=None,
    help="Read the new value from FILE instead of the VALUE argument.",
)
@click.option(
    "--encrypt",
    "do_encrypt",
    is_flag=True,
    default=False,
    help="Encrypt the new value before storing it.",
)
def update(key: str, value: str | None, from_file: str | None, do_encrypt: bool) -> None:
    """Update KEY with a new VALUE.

    VALUE may be supplied as a positional argument or read from a file with
    ``-f``/``--from-file``.  Exactly one of the two must be provided.

    The key must already exist.  The encryption flag is determined entirely
    by the current call — passing ``--encrypt`` encrypts the new value,
    omitting it stores it as plaintext, regardless of how the entry was
    originally stored.

    \b
    Examples
    --------
        store update github_token ghp_newtoken
        store update db_password n3ws3cr3t --encrypt
        store update tls_cert -f /etc/ssl/certs/server.pem
    """
    if (value is None) == (from_file is None):
        raise click.UsageError("Provide either VALUE or --from-file, not both (or neither).")

    if from_file is not None:
        value = click.open_file(from_file).read().rstrip("\n")

    if do_encrypt:
        password = _prompt_password("Encryption password", confirm=True)
        value = encrypt(value, password)

    with Database() as db:
        updated = db.update(key, value, encrypted=do_encrypt)

    if not updated:
        click.echo(f"Error: key '{key}' not found.", err=True)
        sys.exit(1)

    click.echo(f"Updated '{key}'.")


@cli.command("list")
@click.option(
    "--encrypted",
    "show_encrypted",
    is_flag=True,
    default=False,
    help="Show only encrypted entries.",
)
@click.option(
    "--unencrypted",
    "show_unencrypted",
    is_flag=True,
    default=False,
    help="Show only plaintext entries.",
)
@click.option(
    "--search",
    "search_term",
    default=None,
    metavar="TERM",
    help="Filter keys containing TERM (case-insensitive substring match).",
)
def list_keys(show_encrypted: bool, show_unencrypted: bool, search_term: str | None) -> None:
    """List all stored keys.

    Each key is shown with a coloured lock indicator:

    \b
      🔒  encrypted entry
      🔓  plaintext entry

    Outputs a summary line with the total count at the end.

    \b
    Examples
    --------
        store list
        store list --encrypted
        store list --unencrypted
        store list --search github
        store list --encrypted --search prod
    """
    if show_encrypted and show_unencrypted:
        click.echo("Error: --encrypted and --unencrypted are mutually exclusive.", err=True)
        sys.exit(1)

    with Database() as db:
        entries = db.list_entries()

    if show_encrypted:
        entries = [(k, e) for k, e in entries if e]
    elif show_unencrypted:
        entries = [(k, e) for k, e in entries if not e]

    if search_term is not None:
        term = search_term.lower()
        entries = [(k, e) for k, e in entries if term in k.lower()]

    if not entries:
        click.echo(click.style("No entries found.", fg="yellow"))
        return

    col_width = max(len(key) for key, _ in entries)
    for key, encrypted in entries:
        key_text = click.style(key.ljust(col_width), fg="cyan")
        if encrypted:
            badge = click.style(" [enc]", fg="yellow", bold=True)
        else:
            badge = click.style(" [plain]", fg="green", dim=True)
        click.echo(f"  {key_text}{badge}")

    total = len(entries)
    encrypted_count = sum(1 for _, enc in entries if enc)
    summary = click.style(
        f"\n{total} {'entry' if total == 1 else 'entries'}"
        f" ({encrypted_count} encrypted)",
        dim=True,
    )
    click.echo(summary)


@cli.command("delete")
@click.argument("key")
def delete(key: str) -> None:
    """Delete the entry for KEY.

    Exits with a non-zero status code if the key does not exist.

    \b
    Examples
    --------
        store delete github_token
    """
    with Database() as db:
        removed = db.delete(key)

    if not removed:
        click.echo(f"Error: key '{key}' not found.", err=True)
        sys.exit(1)

    click.echo(f"Deleted '{key}'.")


@cli.command("rename")
@click.argument("old_key")
@click.argument("new_key")
def rename(old_key: str, new_key: str) -> None:
    """Rename OLD_KEY to NEW_KEY.

    The value and encryption status are preserved.  Fails if OLD_KEY does
    not exist or NEW_KEY already exists.

    \b
    Examples
    --------
        store rename github_token gh_token
    """
    try:
        with Database() as db:
            renamed = db.rename(old_key, new_key)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if not renamed:
        click.echo(f"Error: key '{old_key}' not found.", err=True)
        sys.exit(1)

    click.echo(f"Renamed '{old_key}' to '{new_key}'.")
