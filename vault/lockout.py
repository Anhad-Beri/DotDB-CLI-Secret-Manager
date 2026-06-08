import json
import os
import time
from pathlib import Path

LOCK_FILE = Path(".vault.lock")
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60


def _read_lock() -> dict:
    """Read the lock file. Returns empty dict if it doesn't exist."""
    if not LOCK_FILE.exists():
        return {}
    try:
        with open(LOCK_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_lock(data: dict) -> None:
    """Write the lock file with owner-only permissions."""
    with open(LOCK_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(LOCK_FILE, 0o600)


def _delete_lock() -> None:
    """Remove the lock file entirely (called on successful login)."""
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()


def check_lockout() -> None:

    state = _read_lock()
    failures = state.get("failures", 0)
    locked_at = state.get("locked_at")

    if failures >= MAX_FAILURES and locked_at is not None:
        elapsed = time.time() - locked_at
        remaining = LOCKOUT_SECONDS - elapsed

        if remaining > 0:
            raise SystemExit(
                f"\n  ✗ Vault locked after {MAX_FAILURES} failed attempts.\n"
                f"    Try again in {int(remaining) + 1} seconds.\n"
            )
        else:
            _delete_lock()


def record_failure() -> int:
    state = _read_lock()
    failures = state.get("failures", 0) + 1
    new_state = {"failures": failures}

    if failures >= MAX_FAILURES:
        new_state["locked_at"] = state.get("locked_at") or time.time()

    _write_lock(new_state)
    return failures


def record_success() -> None:
    _delete_lock()


def remaining_attempts() -> int:
    state = _read_lock()
    failures = state.get("failures", 0)
    return max(0, MAX_FAILURES - failures)