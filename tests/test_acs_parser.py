from pathlib import Path

from arm_soc_sbsa.acs.checks import CHECKS
from arm_soc_sbsa.acs.runner import run_checks
from arm_soc_sbsa.boot.mock import run_mock_boot
from arm_soc_sbsa.tables.acpi import build_all, parse_table

SAMPLE = Path(__file__).parent.parent / "samples" / "sample_uart.log"


def test_check_count_at_least_100():
    assert len(CHECKS) >= 100
    assert len({c.id for c in CHECKS}) == len(CHECKS)


def test_mock_log_passes_regression():
    infos = [parse_table(b) for b in build_all().values()]
    report = run_checks(run_mock_boot().uart_text, suite="all", table_infos=infos)
    assert report.failed == 0, [r for r in report.results if r.status == "FAIL"][:5]
    assert report.passed >= 100


def test_sample_uart_log_parses():
    assert SAMPLE.exists()
    infos = [parse_table(b) for b in build_all().values()]
    report = run_checks(SAMPLE.read_text(), suite="sbsa", table_infos=infos)
    assert report.passed > 50


def test_empty_log_skips():
    report = run_checks("", suite="sbsa")
    assert report.skipped == report.total


def test_partial_log_fails_missing():
    report = run_checks("BL1: Booting BL2\n", suite="sbsa")
    assert report.failed > 0
