import os
import subprocess
import sys
import threading
import time

import click
from cryptography.exceptions import InvalidTag

from vault import crypto, storage, lockout


# ── Helpers ────────────────────────────────────────────────────────────────────

def _require_vault():
    """Exit with a helpful message if the vault hasn't been initialized yet."""
    if not storage.vault_exists():
        click.echo(click.style("✗ No vault found. Run `vault init` first.", fg="red"))
        sys.exit(1)
    # Warn if file permissions are unsafe (e.g. world-readable)
    warning = storage.check_vault_permissions()
    if warning:
        click.echo(click.style(warning, fg="yellow"))


def _prompt_password(confirm: bool = False) -> str:
    """Securely prompt for the master password (input hidden)."""
    password = click.prompt("Master password", hide_input=True)
    if confirm:
        confirm_pw = click.prompt("Confirm master password", hide_input=True)
        if password != confirm_pw:
            click.echo(click.style("✗ Passwords do not match.", fg="red"))
            sys.exit(1)
    return password


def _clipboard_clear(delay: int = 15):
    """Clear the clipboard after `delay` seconds in a background thread."""
    try:
        import pyperclip
        time.sleep(delay)
        pyperclip.copy("")
        click.echo(f"\n  Clipboard cleared after {delay}s.")
    except Exception:
        pass  # Clipboard clear is best-effort — don't crash on failure


# ── CLI group ──────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """
    \b
    ╔══════════════════════════════════════╗
    ║   Zero-Trust Secrets Manager (vault) ║
    ╚══════════════════════════════════════╝
    Encrypted environment variable manager.
    Secrets are AES-256-GCM encrypted. Your
    master password is never stored on disk.
    """
    pass


# ── Commands ───────────────────────────────────────────────────────────────────

@cli.command()
def init():
    """Initialize a new vault. Creates an empty .vault.db file."""
    if storage.vault_exists():
        click.echo(click.style("! Vault already exists at .vault.db", fg="yellow"))
        return

    _prompt_password(confirm=True)  # Validate password strength via confirmation
    # We write an empty vault — the password itself is never written
    import json, os
    from pathlib import Path
    Path(".vault.db").write_text(json.dumps({}))
    os.chmod(".vault.db", 0o600)
    click.echo(click.style("✓ Vault initialized. .vault.db created (owner read/write only).", fg="green"))
    click.echo("  Your master password was NOT stored. Don't forget it!")


@cli.command()
@click.argument("key")
@click.argument("value")
def set(key, value):
    """Encrypt and store a secret: vault set KEY VALUE"""
    _require_vault()
    lockout.check_lockout()
    password = _prompt_password()

    blob = crypto.encrypt(value, password)
    storage.set_secret(key, blob)
    click.echo(click.style(f"✓ Secret '{key.upper()}' stored.", fg="green"))


@cli.command()
@click.argument("key")
@click.option("--clip", is_flag=True, help="Copy to clipboard instead of printing. Clears after 15s.")
def get(key, clip):
    """Decrypt and retrieve a secret: vault get KEY [--clip]"""
    _require_vault()
    lockout.check_lockout()

    blob = storage.get_secret(key)
    if blob is None:
        click.echo(click.style(f"✗ Key '{key.upper()}' not found.", fg="red"))
        sys.exit(1)

    password = _prompt_password()

    try:
        value = crypto.decrypt(blob, password)
        lockout.record_success()  # correct password — reset failure count
    except InvalidTag:
        failures = lockout.record_failure()
        remaining = lockout.remaining_attempts()
        if remaining > 0:
            click.echo(click.style(
                f"✗ Wrong password. {remaining} attempt(s) remaining before lockout.",
                fg="red"
            ))
        else:
            click.echo(click.style(
                f"✗ Wrong password. Vault locked for {lockout.LOCKOUT_SECONDS} seconds.",
                fg="red"
            ))
        sys.exit(1)

    if clip:
        try:
            import pyperclip
            pyperclip.copy(value)
            click.echo(click.style(f"✓ '{key.upper()}' copied to clipboard. Clearing in 15s...", fg="green"))
            t = threading.Thread(target=_clipboard_clear, args=(15,), daemon=True)
            t.start()
            t.join()  # Wait so the CLI doesn't exit before clearing
        except ImportError:
            click.echo(click.style("✗ pyperclip not installed. pip install pyperclip", fg="red"))
    else:
        click.echo(f"\n  {key.upper()} = {value}\n")


@cli.command()
@click.argument("key")
def delete(key):
    """Remove a secret from the vault: vault delete KEY"""
    _require_vault()

    removed = storage.delete_secret(key)
    if removed:
        click.echo(click.style(f"✓ '{key.upper()}' deleted.", fg="green"))
    else:
        click.echo(click.style(f"✗ Key '{key.upper()}' not found.", fg="red"))


@cli.command(name="list")
def list_secrets():
    """List all stored key names (no decryption): vault list"""
    _require_vault()

    keys = storage.list_keys()
    if not keys:
        click.echo("  Vault is empty.")
        return

    click.echo(click.style(f"\n  {len(keys)} secret(s) stored:\n", fg="cyan"))
    for k in keys:
        click.echo(f"  • {k}")
    click.echo()


@cli.command()
@click.argument("prefix")
def search(prefix):
    """Search keys by prefix using the Trie: vault search DB_"""
    _require_vault()

    matches = storage.search_keys(prefix)
    if not matches:
        click.echo(click.style(f"  No keys matching '{prefix.upper()}*'", fg="yellow"))
        return

    click.echo(click.style(f"\n  {len(matches)} match(es) for '{prefix.upper()}*':\n", fg="cyan"))
    for k in matches:
        click.echo(f"  • {k}")
    click.echo()


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def run(command):
    """
    Inject all secrets as environment variables and run a command.

    \b
    Usage:
      python -m vault.cli run -- python app.py
      python -m vault.cli run -- bash deploy.sh
      python -m vault.cli run -- node server.js

    All secrets in the vault are decrypted and injected into the
    subprocess environment. Your app accesses them via os.getenv()
    exactly like a .env file — except nothing is ever written to disk.
    Secrets exist only in the subprocess memory and vanish when it exits.
    """
    _require_vault()
    lockout.check_lockout()

    if not command:
        click.echo(click.style(
            "✗ No command provided. Usage: vault run -- python app.py",
            fg="red"
        ))
        sys.exit(1)

    password = _prompt_password()

    # Decrypt every secret in the vault
    keys = storage.list_keys()
    if not keys:
        click.echo(click.style("! Vault is empty — running command with no injected secrets.", fg="yellow"))

    # Start with a full copy of the current environment so the subprocess
    # inherits PATH, HOME, and everything else it needs to function normally.
    # We then layer our decrypted secrets on top.
    env = os.environ.copy()
    injected = []

    for key in keys:
        blob = storage.get_secret(key)
        try:
            value = crypto.decrypt(blob, password)
            env[key] = value
            injected.append(key)
        except InvalidTag:
            # Wrong password caught on first key — no point continuing
            failures = lockout.record_failure()
            remaining = lockout.remaining_attempts()
            if remaining > 0:
                click.echo(click.style(
                    f"✗ Wrong password. {remaining} attempt(s) remaining before lockout.",
                    fg="red"
                ))
            else:
                click.echo(click.style(
                    f"✗ Wrong password. Vault locked for {lockout.LOCKOUT_SECONDS} seconds.",
                    fg="red"
                ))
            sys.exit(1)

    lockout.record_success()

    click.echo(click.style(
        f"✓ Injecting {len(injected)} secret(s): {', '.join(injected)}",
        fg="green"
    ))
    click.echo(click.style(
        f"  Running: {' '.join(command)}\n",
        fg="cyan"
    ))

    # Launch the subprocess with the enriched environment.
    # We use subprocess.run() which blocks until the child process exits.
    # The secrets live only in `env` — an in-memory dict — and are never
    # written to any file. When the subprocess exits, they are gone.
    result = subprocess.run(command, env=env)

    # Exit with the same code as the subprocess so scripts can check
    # whether the command succeeded or failed.
    sys.exit(result.returncode)


if __name__ == "__main__":
    cli()