"""Smoke test: proves the package installs, imports and the CLI runs."""

import pytest

from netsentinel import __version__
from netsentinel.cli import main


def test_version_is_set():
    assert __version__ == "0.0.1"


def test_cli_runs_without_arguments(capsys):
    assert main([]) == 0
    assert "netsentinel 0.0.1" in capsys.readouterr().out


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "netsentinel 0.0.1" in capsys.readouterr().out
