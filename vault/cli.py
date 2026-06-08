import sys
import threading
import time

import click
from cryptography.exceptions import InvalidTag

from vault import crypto, storage, lockout

def _require_vault():

    if not storage.vault_exists():
        click.echo(click.style("✗ No vault found. Run `vault init` first.", fg="red"))
        sys.exit(1)
    warning = storage.check_vault_permissions()
    if warning:
        click.echo(click.style(warning, fg="yellow"))


def _prompt_password(confirm: bool = False) -> str:
    password = click.prompt("Master password", hide_input=True)
    if confirm:
        confirm_pw = click.prompt("Confirm master password", hide_input=True)
        if password != confirm_pw:
            click.echo(click.style("✗ Passwords do not match.", fg="red"))
            sys.exit(1)
    return password


def _clipboard_clear(delay: int = 15):
    try:
        import pyperclip
        time.sleep(delay)
        pyperclip.copy("")
        click.echo(f"\n  Clipboard cleared after {delay}s.")
    except Exception:
        pass


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

@cli.command()
def init():
    if storage.vault_exists():
        click.echo(click.style("! Vault already exists at .vault.db", fg="yellow"))
        return

    _prompt_password(confirm=True)
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
        lockout.record_success() 
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
            t.join()  
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


if __name__ == "__main__":
    cli()