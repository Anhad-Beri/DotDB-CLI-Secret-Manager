import os
import pytest
from click.testing import CliRunner
from vault.cli import cli
from vault import crypto, storage as storage_mod


@pytest.fixture(autouse=True)
def redirect_vault(tmp_path, monkeypatch):
    """Redirect vault file and lock file to temp directory."""
    import vault.lockout as lockout_mod
    monkeypatch.setattr(storage_mod, "VAULT_FILE", tmp_path / ".vault.db")
    monkeypatch.setattr(lockout_mod, "LOCK_FILE", tmp_path / ".vault.lock")


@pytest.fixture
def runner():
    """Click's test runner — simulates terminal input/output."""
    return CliRunner()


@pytest.fixture
def vault_with_secrets(tmp_path):

    password = "testpass"
    storage_mod.VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)

    import json
    storage_mod.VAULT_FILE.write_text(json.dumps({}))

    blob1 = crypto.encrypt("hunter2", password)
    blob2 = crypto.encrypt("localhost", password)
    storage_mod.set_secret("DB_PASSWORD", blob1)
    storage_mod.set_secret("DB_HOST", blob2)
    return password


def test_run_injects_secrets_into_subprocess(runner, vault_with_secrets, tmp_path):
   
    password = vault_with_secrets
    output_file = tmp_path / "result.txt"

    result = runner.invoke(
        cli,
        [
            "run", "--",
            "python", "-c",
            f"import os; open(r'{output_file}', 'w').write(os.getenv('DB_PASSWORD', 'NOT_FOUND'))"
        ],
        input=password + "\n"
    )

    assert result.exit_code == 0
    assert output_file.exists(), "Subprocess did not run — output file not created"
    assert output_file.read_text() == "hunter2"


def test_run_exits_with_subprocess_return_code(runner, vault_with_secrets):
    
    password = vault_with_secrets
    result = runner.invoke(
        cli,
        ["run", "--", "python", "-c", "import sys; sys.exit(42)"],
        input=password + "\n"
    )
    assert result.exit_code == 42


def test_run_fails_with_no_command(runner, vault_with_secrets):
    password = vault_with_secrets
    result = runner.invoke(cli, ["run"], input=password + "\n")
    assert result.exit_code == 1
    assert "No command provided" in result.output


def test_run_wrong_password(runner, vault_with_secrets):
    result = runner.invoke(
        cli,
        ["run", "--", "python", "-c", "print('hello')"],
        input="wrongpassword\n"
    )
    assert result.exit_code == 1
    assert "Wrong password" in result.output


def test_run_empty_vault_still_runs_command(runner, tmp_path):
    
    import json
    storage_mod.VAULT_FILE.write_text(json.dumps({}))

    runner_obj = CliRunner()
    result = runner_obj.invoke(
        cli,
        ["run", "--", "python", "-c", "print('ran successfully')"],
        input="anypassword\n"
    )
    assert "ran successfully" in result.output