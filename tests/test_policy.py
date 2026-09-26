import json

import pytest
from pydantic import ValidationError

from emergent_kali.models import LAB, Limits, RunConfig, ToolArgs
from emergent_kali.runner_runtime import Gate, check_url, command


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://juice-shop:3000.evil/",
        "http://juice-shop:3000@evil/",
        "http://127.0.0.1:3000",
        "http://juice-shop:3000/#x",
        "http://juice-shop:3000/\n-H header",
        "file:///etc/passwd",
        "http://juice-shop:3000\\@evil",
        "http://JUICE-SHOP:3000",
        "http://juice-shop:3000:80",
        "-o/tmp/file",
    ],
)
def test_scope_rejects_aliases_and_external_urls(url):
    with pytest.raises(ValueError):
        check_url(url)


@pytest.mark.parametrize(
    "updates",
    [
        {"authorization": "        "},
        {"allowlist": []},
        {"allowlist": ["*"]},
        {"allowlist": [LAB + "/"]},
        {"target": "http://example.com"},
    ],
)
def test_explicit_authorization_and_exact_scope(updates):
    data = {"authorization": "I own this lab.", "allowlist": [LAB], **updates}
    with pytest.raises(ValidationError):
        RunConfig(**data)


@pytest.mark.parametrize(
    "tool",
    [
        "http_probe",
        "port_scan",
        "crawl",
        "content_discovery",
        "template_scan",
        "sql_check",
        "form_check",
    ],
)
def test_fixed_commands(tool):
    url = LAB + ("/rest/products/search?q=apple" if tool == "sql_check" else "/")
    argv = command(tool, ToolArgs(url=url).model_dump(), Limits().model_dump())
    assert argv[0] in {"curl", "nmap", "python3", "nuclei", "sqlmap"}
    assert not any(item in argv for item in ["sh", "bash", "--os-shell", "--dump", "--tamper"])
    if tool == "sql_check":
        assert "--technique=BE" in argv and "--risk=1" in argv


@pytest.mark.parametrize(
    "tool,args",
    [
        ("shell", {"url": LAB}),
        ("http_probe", {"url": LAB, "flags": "-o file"}),
        ("port_scan", {"url": LAB, "ports": [22]}),
        ("content_discovery", {"url": LAB, "paths": ["//evil"]}),
        ("sql_check", {"url": LAB + "/login?q=1"}),
        ("sql_check", {"url": LAB + "/rest/products/search?x=1"}),
    ],
)
def test_command_policy(tool, args):
    with pytest.raises(ValueError):
        command(tool, args, Limits().model_dump())


def test_form_check_skips_the_proxy():
    argv = command("form_check", {"url": LAB}, Limits().model_dump())
    assert argv == ["python3", "/opt/emerg/runtime.py", "direct-form"]
    assert "8765" not in argv


def test_one_named_service_replaces_the_default_lab(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    assert check_url("http://vampi:5000/users/v1") == "http://vampi:5000/users/v1"
    with pytest.raises(ValueError):
        check_url(LAB)
    argv = command(
        "port_scan",
        {"url": "http://vampi:5000/", "ports": [5000]},
        Limits().model_dump(),
    )
    assert argv[-2:] == ["5000", "vampi"]
    with pytest.raises(ValidationError):
        RunConfig(
            target=LAB,
            authorization="I am authorized to test this local lab.",
            allowlist=[LAB],
        )


def test_lab_url_rejects_a_dotted_host(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://evil.example:80")
    with pytest.raises(ValueError):
        check_url("http://evil.example:80/")


def test_shell_metacharacters_are_only_url_data():
    argv = command("http_probe", {"url": LAB + "/?q=;whoami"}, Limits().model_dump())
    assert argv[-2:] == ["--", LAB + "/?q=;whoami"]


def test_global_request_budget_and_rate_survive_commands(tmp_path, monkeypatch):
    from emergent_kali import runner_runtime

    current = [100.0]
    sleeps = []
    monkeypatch.setattr(runner_runtime.time, "time", lambda: current[0])

    def sleep(seconds):
        sleeps.append(seconds)
        current[0] += seconds

    monkeypatch.setattr(runner_runtime.time, "sleep", sleep)
    limits = Limits(requests=2, requests_per_second=2).model_dump()
    Gate(limits, tmp_path).reserve()
    gate = Gate(limits, tmp_path)
    gate.reserve()
    assert sleeps == [0.5]
    with pytest.raises(ValueError, match="request limit"):
        Gate(limits, tmp_path).reserve()
    assert json.loads((tmp_path / "request-budget.json").read_text())["count"] == 2
