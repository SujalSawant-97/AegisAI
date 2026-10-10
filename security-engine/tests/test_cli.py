import argparse
import json
import pytest

from app.main import _cmd_scan
from tests.test_app import TestApp


def test_cli_scan_all_scanners(capsys):
    with TestApp() as app:
        args = argparse.Namespace(
            target=app.base_url,
            scanners="all",
            auth_token="valid-secret-token",
            low_priv_token="user-token",
        )
        exit_code = _cmd_scan(args)

    assert exit_code == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["status"] == "completed"
    assert "findings" in output
    assert "scanner_errors" in output
    assert len(output["scanner_errors"]) == 0


def test_cli_scan_specific_scanners(capsys):
    with TestApp() as app:
        args = argparse.Namespace(
            target=app.base_url,
            scanners="headers,cors,sqli,xss",
            auth_token=None,
            low_priv_token=None,
        )
        exit_code = _cmd_scan(args)

    assert exit_code == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["status"] == "completed"
