# store

A lightweight CLI secret manager with optional encryption. Store, retrieve, and manage key-value pairs from the terminal, backed by a local SQLite database.

## Features

- Store plaintext or encrypted key-value pairs
- AES-128-CBC encryption via [Fernet](https://cryptography.io/en/latest/fernet/) with PBKDF2-HMAC-SHA256 key derivation
- Per-value random salts — no two encrypted blobs are identical even for the same value
- Shell tab completion for stored keys
- Read values from files with `--from-file`
- Filter and search stored keys

## Setup

**Requirements:** Python 3.10+, [Poetry](https://python-poetry.org/)

```bash
git clone <repo>
cd store
poetry install
```

The `store` command is registered as a Poetry entry point and available immediately after install.

## Usage

```
store [command] [options]
```

### Commands

#### `keep` — store a new value
```bash
store keep <key> <value>
store keep <key> <value> --encrypt          # prompt for encryption password
store keep <key> -f /path/to/file           # read value from a file
```

#### `get` — retrieve a value
```bash
store get <key>                             # prints value; prompts for password if encrypted
```

#### `update` — update an existing value
```bash
store update <key> <new_value>
store update <key> <new_value> --encrypt
store update <key> -f /path/to/file
```

#### `delete` — remove a key
```bash
store delete <key>
```

#### `rename` — rename a key (preserves value and encryption status)
```bash
store rename <old_key> <new_key>
```

#### `list` — list all keys
```bash
store list                                  # all keys with encryption status
store list --encrypted                      # only encrypted keys
store list --unencrypted                    # only plaintext keys
store list --search foo                     # keys matching a substring
```

### Shell completion

Tab completion is supported for stored key names. To enable it, add the following to your shell config.

**zsh / oh-my-zsh** — add to `~/.zshrc`:
```zsh
eval "$(_STORE_COMPLETE=zsh_source store)"
```

Then reload your shell (`source ~/.zshrc` or open a new terminal).

### Configuration

| Variable | Default | Description |
|---|---|---|
| `STORE_DB_PATH` | `~/.store/store.sqlite` | Override the database file path |

## Architecture

```
store/
├── cli.py       # Click commands — user interaction and dispatch
├── crypto.py    # Encrypt/decrypt with Fernet + PBKDF2
└── db.py        # SQLite persistence layer
```

The three layers are strictly separated:

**`cli.py`** handles all user interaction — argument parsing, password prompts, coloured output, and tab completion. It calls into `crypto` and `db` but neither of those know about each other.

**`crypto.py`** is stateless. `encrypt(plaintext, password)` returns a base64url blob that embeds a fresh 16-byte random salt. `decrypt(blob, password)` extracts the salt and recovers the plaintext. Nothing is persisted here.

**`db.py`** manages a SQLite database with a single `store` table (`key`, `value`, `encrypted`). It uses WAL journal mode and exposes a context-manager interface. The database path is resolved at open time so it can be overridden in tests via `STORE_DB_PATH`.

### Encryption scheme

```
password + random_salt  →  PBKDF2-HMAC-SHA256 (480 000 iterations)  →  32-byte key
32-byte key  →  Fernet (AES-128-CBC + HMAC-SHA256)  →  ciphertext
stored blob  =  base64url(salt || fernet_token)
```

The salt travels with the ciphertext so only the password is needed to decrypt. No keys or salts are stored separately.

### Data flow

```
store keep api_key s3cr3t --encrypt
  └─ cli.keep()
       ├─ prompts for password
       ├─ crypto.encrypt(plaintext, password)  →  encrypted blob
       └─ db.store(key, blob, encrypted=True)  →  SQLite

store get api_key
  └─ cli.get()
       ├─ db.retrieve(key)  →  (blob, encrypted=True)
       ├─ prompts for password
       └─ crypto.decrypt(blob, password)  →  prints plaintext
```

## Development

```bash
# Run tests
poetry run pytest

# Run with coverage
poetry run pytest --cov
```

Tests use a `STORE_DB_PATH` temporary file fixture so they never touch `~/.store/store.sqlite`.
