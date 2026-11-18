import pytest

from arm_soc_sbsa.boot.mock import BootStateMachine, Milestone, run_mock_boot, MILESTONES


def test_full_boot_order():
    r = run_mock_boot()
    assert r.success
    assert r.milestones == MILESTONES
    assert "BOOT_COMPLETE" in r.uart_text


def test_illegal_transition_rejected():
    sm = BootStateMachine()
    with pytest.raises(ValueError):
        sm.advance(Milestone.DXE)


def test_injected_failure():
    with pytest.raises(RuntimeError):
        run_mock_boot(fail_at=Milestone.BL2)
