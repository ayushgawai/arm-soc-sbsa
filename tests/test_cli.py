import json

from arm_soc_sbsa.cli import main


def test_cli_tables_and_bench(tmp_path, capsys):
    assert main(["tables", "gen", "--out-dir", str(tmp_path / "t")]) == 0
    assert (tmp_path / "t" / "MADT.dat").exists()
    assert main(["tables", "validate", "--out-dir", str(tmp_path / "t")]) == 0
    assert main(["bench"]) == 0


def test_cli_boot_mock(tmp_path):
    assert main(["boot-run", "--mode", "mock", "--out", str(tmp_path / "o")]) == 0
    assert "BOOT_COMPLETE" in (tmp_path / "o" / "uart.log").read_text()


def test_cli_acs_json(tmp_path):
    out = tmp_path / "r.json"
    assert main(["acs", "run", "--suite", "sbsa", "--report", "json", "--out", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["total"] > 50 and data["failed"] == 0


def test_cli_redfish_snapshot(capsys):
    assert main(["redfish", "snapshot"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["system"]["PowerState"] == "On"
