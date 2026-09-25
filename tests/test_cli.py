import json

from app import cli


def test_cli_text_analysis_prints_json(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["nexvision-qr-shield", "--text", "https://example.com"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["payload_type"]


def test_cli_reports_missing_file_without_traceback(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("sys.argv", ["nexvision-qr-shield", "--file", str(tmp_path / "missing.png")])
    assert cli.main() == 2
    assert capsys.readouterr().err.startswith("error:")


def test_cli_reports_unreadable_image_without_traceback(monkeypatch, capsys, tmp_path):
    bogus = tmp_path / "not-an-image.png"
    bogus.write_bytes(b"plain text, not an image")
    monkeypatch.setattr("sys.argv", ["nexvision-qr-shield", "--file", str(bogus)])
    assert cli.main() == 2
    assert "Unsupported or invalid image" in capsys.readouterr().err
