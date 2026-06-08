"""
Tests for the lockout module.

Key challenge: lockout.py uses hardcoded Path(".vault.lock").
We monkey-patch lockout.LOCK_FILE in each test to redirect it
to a tmp_path so tests never touch the real filesystem.
"""

import json
import time
import pytest
import vault.lockout as lockout_mod


@pytest.fixture(autouse=True)
def redirect_lock_file(tmp_path, monkeypatch):
    """
    Redirect LOCK_FILE to a temp directory for every test automatically.

    autouse=True means this fixture runs for every test in this file
    without needing to declare it as a parameter — keeps test signatures clean.

    monkeypatch is pytest's built-in way to temporarily replace module-level
    variables. It automatically restores the original value after each test.
    """
    monkeypatch.setattr(lockout_mod, "LOCK_FILE", tmp_path / ".vault.lock")


# ── record_failure ─────────────────────────────────────────────────────────────

def test_first_failure_returns_one():
    count = lockout_mod.record_failure()
    assert count == 1


def test_failures_accumulate():
    lockout_mod.record_failure()
    lockout_mod.record_failure()
    count = lockout_mod.record_failure()
    assert count == 3


def test_failure_writes_lock_file():
    lockout_mod.record_failure()
    assert lockout_mod.LOCK_FILE.exists()


def test_locked_at_set_only_on_threshold():
    """
    locked_at should only appear in the file once failures hit MAX_FAILURES.
    Before that threshold, the key must not exist — otherwise the lockout
    window would start too early.
    """
    for _ in range(lockout_mod.MAX_FAILURES - 1):
        lockout_mod.record_failure()

    state = json.loads(lockout_mod.LOCK_FILE.read_text())
    assert "locked_at" not in state  # not locked yet

    lockout_mod.record_failure()  # this one hits the threshold

    state = json.loads(lockout_mod.LOCK_FILE.read_text())
    assert "locked_at" in state


def test_locked_at_not_reset_by_subsequent_failures():
    """
    If the user keeps entering wrong passwords after lockout,
    locked_at must stay the same — otherwise the 60s window resets
    and the lockout never actually expires.
    """
    for _ in range(lockout_mod.MAX_FAILURES):
        lockout_mod.record_failure()

    state_after_lockout = json.loads(lockout_mod.LOCK_FILE.read_text())
    original_locked_at = state_after_lockout["locked_at"]

    # One more failure — should NOT change locked_at
    lockout_mod.record_failure()

    state_after_extra = json.loads(lockout_mod.LOCK_FILE.read_text())
    assert state_after_extra["locked_at"] == original_locked_at


# ── record_success ─────────────────────────────────────────────────────────────

def test_success_deletes_lock_file():
    lockout_mod.record_failure()
    lockout_mod.record_success()
    assert not lockout_mod.LOCK_FILE.exists()


def test_success_with_no_prior_failures_is_safe():
    """record_success with no lock file should not raise."""
    lockout_mod.record_success()  # must not throw


# ── check_lockout ──────────────────────────────────────────────────────────────

def test_no_lockout_with_zero_failures():
    """check_lockout should be silent when no failures have been recorded."""
    lockout_mod.check_lockout()  # must not raise


def test_no_lockout_below_threshold():
    for _ in range(lockout_mod.MAX_FAILURES - 1):
        lockout_mod.record_failure()
    lockout_mod.check_lockout()  # must not raise — still under threshold


def test_lockout_raises_after_max_failures():
    for _ in range(lockout_mod.MAX_FAILURES):
        lockout_mod.record_failure()
    with pytest.raises(SystemExit):
        lockout_mod.check_lockout()


def test_lockout_clears_after_window_expires(monkeypatch):
    """
    After LOCKOUT_SECONDS have elapsed, check_lockout should reset
    the state and allow entry again.

    We fake an old locked_at timestamp by patching time.time() to
    return a value far in the future, making the elapsed time appear
    greater than LOCKOUT_SECONDS.
    """
    for _ in range(lockout_mod.MAX_FAILURES):
        lockout_mod.record_failure()

    # Make time appear to have advanced past the lockout window
    future_time = time.time() + lockout_mod.LOCKOUT_SECONDS + 10
    monkeypatch.setattr(lockout_mod.time, "time", lambda: future_time)

    lockout_mod.check_lockout()  # must not raise — window has expired
    assert not lockout_mod.LOCK_FILE.exists()  # lock file should be cleaned up


# ── remaining_attempts ─────────────────────────────────────────────────────────

def test_remaining_attempts_starts_at_max():
    assert lockout_mod.remaining_attempts() == lockout_mod.MAX_FAILURES


def test_remaining_attempts_decrements():
    lockout_mod.record_failure()
    lockout_mod.record_failure()
    assert lockout_mod.remaining_attempts() == lockout_mod.MAX_FAILURES - 2


def test_remaining_attempts_never_goes_negative():
    for _ in range(lockout_mod.MAX_FAILURES + 5):
        lockout_mod.record_failure()
    assert lockout_mod.remaining_attempts() == 0
