from types import SimpleNamespace

import pytest

from ai_shield.cli import _result_status


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        (SimpleNamespace(degraded=True, blocked=True, action="block"), "DEGRADED"),
        (SimpleNamespace(degraded=False, blocked=True, action="block"), "BLOCKED"),
        (SimpleNamespace(degraded=False, blocked=False, action="alert"), "ALERT"),
        (SimpleNamespace(degraded=False, blocked=False, action="log"), "LOGGED"),
        (SimpleNamespace(degraded=False, blocked=False, action="pass"), "PASSED"),
    ],
)
def test_cli_never_labels_alert_or_degraded_inspection_as_pass(verdict, expected):
    assert _result_status(verdict) == expected
