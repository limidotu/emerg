import csv
import io
import json

import pytest

from emergent_kali.engine import Engine
from emergent_kali.redaction import redact
from emergent_kali.reports import export_report, render_report, report_data


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer supersecret",
        '{"password": "supersecret"}',
        "https://user:supersecret@example.com",
        "?api_key=supersecret&x=1",
        "token: supersecret",
        "Cookie: session=supersecret",
        "Bearer supersecret",
        "access_token=supersecret",
    ],
)
def test_redaction(text):
    assert "supersecret" not in redact(text)


def test_environment_secret_and_terminal_escape_redaction(monkeypatch):
    monkeypatch.setenv("EMERG_MODEL_API_KEY", "configured-secret")
    assert redact("error configured-secret \x1b[31mred\x1b[0m") == "error [REDACTED] red"
    assert redact({"nested": {"apiKey": "secret"}})["nested"]["apiKey"] == "[REDACTED]"


def test_json_secret_assignment_stays_valid():
    raw = (
        '{"password":{"type":"string","example":"pass1"},'
        '"secret":["hidden-value"],'
        '"note":"Password is not correct for the given username."}'
    )
    cleaned = redact(raw)
    parsed = json.loads(cleaned)
    assert "pass1" not in cleaned
    assert "hidden-value" not in cleaned
    assert parsed["password"] == "[REDACTED]"
    assert parsed["secret"] == "[REDACTED]"
    assert "correct for the given username." in parsed["note"]


async def test_all_report_formats_and_artifacts(store, config, tmp_path):
    engine = Engine(store, config)
    assert await engine.run() == 2
    data = report_data(store, engine.run_id)
    for format in ["markdown", "json", "csv", "sarif"]:
        destination = export_report(store, engine.run_id, format, tmp_path / ("report." + format))
        text = destination.read_text(encoding="utf-8")
        assert "Public directory index" in text
        assert "Disable directory indexes" in text
        assert data["findings"][0]["evidence"][0]["evidence_id"] in text
    assert len(store.execute("SELECT * FROM artifacts")) == 4
    sarif = json.loads(render_report(data, "sarif"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert len(list(csv.DictReader(io.StringIO(render_report(data, "csv"))))) == 1


async def test_reports_exclude_unvalidated_findings(store, config):
    engine = Engine(store, config)
    await engine.run()
    store.execute("UPDATE findings SET validated=0 WHERE run_id=?", (engine.run_id,))
    data = report_data(store, engine.run_id)
    assert data["findings"] == [] and data["evidence"] == {}
