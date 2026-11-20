"""Integration test: synthetic PCAP files -> full pipeline -> expected detections."""

import pytest

from netsentinel.cli import main
from netsentinel.evaluation import evaluate
from netsentinel.scenarios import write_scenarios


@pytest.fixture(scope="module")
def scenario_dir(tmp_path_factory):
    folder = tmp_path_factory.mktemp("scenarios")
    write_scenarios(folder)
    return folder


def test_evaluation_results(scenario_dir):
    result = evaluate(scenario_dir)
    by_name = {row["scenario"]: row for row in result["scenarios"]}
    for name in [
        "normal_browsing.pcap",
        "port_scan_connect.pcap",
        "port_scan_syn.pcap",
        "udp_flood.pcap",
        "bulk_download.pcap",
        "repeated_failed_connections.pcap",
    ]:
        assert by_name[name]["result"] == "PASS", by_name[name]
    # Documented false negative: a slow scan stays under the 60 s window threshold.
    assert by_name["slow_port_scan.pcap"]["FN"] == ["NS-001"]
    assert result["totals"] == {"TP": 4, "FP": 0, "FN": 1}


def test_slow_scan_is_caught_with_a_longer_window(scenario_dir, tmp_path):
    rules = tmp_path / "rules.toml"
    rules.write_text("[port_scan]\nwindow_seconds = 300\n")
    from netsentinel.detection import load_config

    result = evaluate(scenario_dir, load_config(rules))
    slow = next(r for r in result["scenarios"] if r["scenario"] == "slow_port_scan.pcap")
    assert slow["result"] == "PASS"


def test_cli_shows_alerts(scenario_dir, capsys):
    assert main(["analyze", str(scenario_dir / "port_scan_connect.pcap")]) == 0
    out = capsys.readouterr().out
    assert "NS-001 Port scan indicator" in out
    assert "200 distinct ports" in out


def test_cli_rejects_bad_rules_file(scenario_dir, tmp_path, capsys):
    rules = tmp_path / "bad.toml"
    rules.write_text("[nope]\n")
    assert main(["analyze", str(scenario_dir / "udp_flood.pcap"), "--rules", str(rules)]) == 2
    assert "Unknown section" in capsys.readouterr().err
