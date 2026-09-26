import json

from typer.testing import CliRunner

from emergent_kali.cli import app
from emergent_kali.engine import Engine
from emergent_kali.model import MockModel
from emergent_kali.models import LAB

runner = CliRunner()
ARGS = ["scan", "--mock", "--authorization", "I own this lab.", "--allowlist", LAB]


def test_scan_jsonl_and_saved_reports(tmp_path, monkeypatch):
    monkeypatch.setenv("EMERG_DATA_DIR", str(tmp_path))
    result = runner.invoke(app, [*ARGS, "--jsonl"])
    assert result.exit_code == 2, result.output
    events = [json.loads(line) for line in result.output.splitlines()]
    assert events[-1]["data"]["state"] == "completed"
    run_id = events[0]["run_id"]
    assert run_id in runner.invoke(app, ["runs"]).output
    assert "Public directory index" in runner.invoke(app, ["show", run_id]).output
    report = runner.invoke(app, ["report", run_id, "--format", "sarif"])
    assert report.exit_code == 0, report.output
    assert (tmp_path / "runs" / run_id / "report.sarif").exists()


def test_cli_no_findings_exit_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("EMERG_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(
        "emergent_kali.cli.Engine", lambda *args, **kwargs: Engine(*args, model=MockModel(False), **kwargs)
    )
    result = runner.invoke(app, ARGS)
    assert result.exit_code == 0, result.output


def test_cli_refuses_missing_authorization_or_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("EMERG_DATA_DIR", str(tmp_path))
    for args in [["scan", "--mock"], [*ARGS, "--target", "http://example.com"]]:
        result = runner.invoke(app, args)
        assert result.exit_code == 1, result.output
    assert not (tmp_path / "emerg.db").exists()


def test_cli_model_failure_is_operational(tmp_path, monkeypatch):
    monkeypatch.setenv("EMERG_DATA_DIR", str(tmp_path))

    class BadModel:
        async def respond(self, *_):
            raise RuntimeError("The model is unavailable.")

    monkeypatch.setattr(
        "emergent_kali.cli.Engine", lambda *args, **kwargs: Engine(*args, model=BadModel(), **kwargs)
    )
    result = runner.invoke(app, ARGS)
    assert result.exit_code == 1
    assert '"state": "failed"' in result.output


def test_cli_syntax_errors_do_not_use_finding_exit_code():
    for args in [["scan", "--unknown-option"], ["scan", "--time-limit", "wrong"]]:
        result = runner.invoke(app, args)
        assert result.exit_code == 1, result.output
    result = runner.invoke(app, ["scan", "--jsonl", "--unknown-option"])
    assert result.exit_code == 1
    assert json.loads(result.output)["kind"] == "error"
