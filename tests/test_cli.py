import json

from netsentinel.cli import main


def test_analyze_prints_report(sample_pcap, capsys):
    assert main(["analyze", str(sample_pcap)]) == 0
    out = capsys.readouterr().out
    assert "Packets     : 8" in out
    assert "example.com" in out
    assert "Flows       : 4" in out


def test_analyze_writes_json(sample_pcap, tmp_path):
    out_file = tmp_path / "report.json"
    assert main(["analyze", str(sample_pcap), "--json", str(out_file)]) == 0
    report = json.loads(out_file.read_text(encoding="utf-8"))
    assert report["summary"]["packet_count"] == 8
    assert report["flows"]["flow_count"] == 4


def test_analyze_bad_file_returns_error_code(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"garbage")
    assert main(["analyze", str(bad)]) == 2
    assert "Not a valid" in capsys.readouterr().err
