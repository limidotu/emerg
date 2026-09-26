import json
import sys

import httpx
import pytest

from emergent_kali import docker, doctor, model
from emergent_kali.docker import DockerRunner, process
from emergent_kali.model import ModelConfig, OpenAIModel


def test_system_text_names_the_authorized_lab():
    assert "Juice Shop" not in model.SYSTEM
    assert "/rest/products/search" not in model.SYSTEM
    assert "http://juice-shop:3000" in model.SYSTEM
    assert "authorized lab" in model.SYSTEM


async def test_compatible_model_request_schema_and_redaction(monkeypatch):
    real_client = httpx.AsyncClient
    captured = []

    def handle(request):
        captured.append(request)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": '{"kind":"stop","reason":"Done."}'}}]}
        )

    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    adapter = OpenAIModel(ModelConfig("http://localhost:11434/v1", "test-model", "api-secret"))
    result = await adapter.respond("coordinator", {"password": "do-not-send"})
    assert json.loads(result)["kind"] == "stop"
    request = captured[0]
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer api-secret"
    payload = json.loads(request.content)
    assert "JSON schema" in payload["messages"][0]["content"]
    assert "do-not-send" not in payload["messages"][1]["content"]
    assert payload["response_format"] == {"type": "json_object"}
    assert "thinking" not in payload


async def test_nvidia_request_disables_thinking(monkeypatch):
    real_client = httpx.AsyncClient
    captured = []
    seen = {}

    def handle(request):
        captured.append(request)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": '{"kind":"stop","reason":"Done."}'}}]}
        )

    def client(**kwargs):
        seen.update(kwargs)
        return real_client(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(model.httpx, "AsyncClient", client)
    adapter = OpenAIModel(
        ModelConfig("https://integrate.api.nvidia.com/v1", "deepseek-ai/deepseek-v4.1-flash", "api-secret")
    )
    await adapter.respond("coordinator", {})
    payload = json.loads(captured[0].content)
    assert payload["thinking"] == {"type": "disabled"}
    assert payload["stream"] is True
    assert payload["response_format"] == {"type": "json_object"}
    assert seen["timeout"].read == 180.0


async def test_provider_failure_does_not_leak_body(monkeypatch):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(401, text="credentials: private-value")
            ),
            **kwargs,
        ),
    )
    with pytest.raises(RuntimeError) as exc:
        await OpenAIModel(ModelConfig("http://localhost/v1", "test", "")).respond("report", {})
    assert str(exc.value) == "The model request failed with HTTP 401."
    assert "private-value" not in str(exc.value)


async def test_timeout_is_one_attempt_and_does_not_leak_the_url(monkeypatch):
    real_client = httpx.AsyncClient
    calls = []

    def handle(request):
        calls.append(request)
        raise httpx.ReadTimeout("https://integrate.api.nvidia.com/v1 secret-token", request=request)

    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    with pytest.raises(RuntimeError) as exc:
        await OpenAIModel(ModelConfig("http://localhost/v1", "test", "")).respond("coordinator", {})
    assert str(exc.value) == "The model request exceeded the time limit."
    assert "secret-token" not in str(exc.value)
    assert "nvidia" not in str(exc.value)
    assert len(calls) == 1


async def test_empty_model_text_names_the_cause(monkeypatch):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"choices": [{"message": {"content": None}}]})
            ),
            **kwargs,
        ),
    )
    with pytest.raises(RuntimeError) as exc:
        await OpenAIModel(ModelConfig("http://localhost/v1", "test", "")).respond("report", {})
    assert str(exc.value) == "The model response had no text."


async def test_streamed_tokens_join_into_one_json_object(monkeypatch):
    real_client = httpx.AsyncClient
    body = "\n".join(
        [
            "data: " + json.dumps({"choices": [{"delta": {"content": '{"kind":'}}]}),
            "data: " + json.dumps({"choices": [{"delta": {"content": '"stop"}'}}]}),
            "data: [DONE]",
            "",
        ]
    )
    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, text=body)),
            **kwargs,
        ),
    )
    result = await OpenAIModel(ModelConfig("http://localhost/v1", "test", "")).respond("coordinator", {})
    assert json.loads(result) == {"kind": "stop"}


async def test_reasoning_text_is_used_when_content_is_empty(monkeypatch):
    real_client = httpx.AsyncClient
    body = "\n".join(
        [
            "data: " + json.dumps({"choices": [{"delta": {"reasoning_content": '{"kind":"stop"}'}}]}),
            "data: [DONE]",
            "",
        ]
    )
    monkeypatch.setattr(
        model.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, text=body)),
            **kwargs,
        ),
    )
    result = await OpenAIModel(ModelConfig("http://localhost/v1", "test", "")).respond("coordinator", {})
    assert json.loads(result) == {"kind": "stop"}


@pytest.mark.parametrize(
    "base,key",
    [
        ("http://remote.example/v1", "secret"),
        ("https://remote.example/v1", ""),
        ("http://user:secret@localhost/v1", ""),
        ("file:///tmp/model", ""),
    ],
)
def test_model_env_rejects_unsafe_config(monkeypatch, base, key):
    monkeypatch.setenv("EMERG_MODEL", "test")
    monkeypatch.setenv("EMERG_MODEL_BASE_URL", base)
    monkeypatch.setenv("EMERG_MODEL_API_KEY", key)
    with pytest.raises(ValueError):
        ModelConfig.from_env()


async def test_bounded_process_output_and_timeout():
    with pytest.raises(RuntimeError, match="output limit"):
        await process([sys.executable, "-c", "print('x'*10000)"], limit=100)
    with pytest.raises(TimeoutError):
        await process([sys.executable, "-c", "import time;time.sleep(10)"], timeout=0.1)


def inspect_info():
    return {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "NetworkMode": "emerg-lab_lab",
        },
        "Mounts": [{"Type": "bind", "Destination": "/workspace"}],
        "Config": {"User": "10001:10001", "Env": ["PATH=/usr/bin", "HOME=/tmp"]},
        "NetworkSettings": {"Networks": {"emerg-lab_lab": {}}},
    }


@pytest.mark.parametrize(
    "violation", ["root", "socket", "credential", "external", "privileged", "extra_network", "writable"]
)
async def test_docker_isolation_fail_closed(tmp_path, monkeypatch, violation):
    info = inspect_info()
    if violation == "root":
        info["Config"]["User"] = "0:0"
    elif violation == "socket":
        info["Mounts"].append({"Type": "bind", "Destination": "/var/run/docker.sock"})
    elif violation == "credential":
        info["Config"]["Env"].append("EMERG_MODEL_API_KEY=secret")
    elif violation == "privileged":
        info["HostConfig"]["Privileged"] = True
    elif violation == "extra_network":
        info["NetworkSettings"]["Networks"]["bridge"] = {}
    elif violation == "writable":
        info["HostConfig"]["ReadonlyRootfs"] = False

    async def fake(argv, **kwargs):
        data = [{"Internal": violation != "external"}] if argv[1] == "network" else [info]
        return 0, json.dumps(data), ""

    monkeypatch.setattr(docker, "process", fake)
    with pytest.raises(RuntimeError):
        await DockerRunner("a" * 32, tmp_path).verify()


async def test_docker_uses_one_mount_no_shell_no_model_credentials(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv("EMERG_MODEL_API_KEY", "never-in-container")

    async def fake(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "inspect":
            return 0, json.dumps([inspect_info()]), ""
        if argv[1] == "network":
            return 0, '[{"Internal":true}]', ""
        return 0, "container-id", ""

    monkeypatch.setattr(docker, "process", fake)
    runner = DockerRunner("b" * 32, tmp_path)
    await runner.start()
    await runner.stop()
    assert calls[0].count("--volume") == 1
    assert "--rm" in calls[0] and "--no-deps" in calls[0]
    assert "never-in-container" not in json.dumps(calls)
    assert calls[-1] == ["docker", "rm", "-f", runner.name]


async def test_docker_start_timeout_has_actionable_error(tmp_path, monkeypatch):
    calls = []

    async def timeout(argv, **kwargs):
        calls.append(kwargs["timeout"])
        raise TimeoutError()

    monkeypatch.setattr(docker, "process", timeout)
    with pytest.raises(RuntimeError, match="startup timed out after 90 seconds"):
        await DockerRunner("c" * 32, tmp_path).start()
    assert calls == [90]


async def test_doctor_reports_every_dependency_without_docker_or_model(monkeypatch):
    calls = []

    async def missing(*args, **kwargs):
        calls.append(args[0])
        raise FileNotFoundError()

    monkeypatch.setattr(doctor, "process", missing)
    monkeypatch.delenv("EMERG_MODEL", raising=False)
    monkeypatch.delenv("EMERG_MODEL_BASE_URL", raising=False)
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        doctor.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(lambda request: httpx.Response(503)), **kwargs
        ),
    )
    checks = await doctor.diagnose()
    assert len(checks) == 9
    assert {c["dependency"] for c in checks} >= {
        "Docker engine",
        "Kali image",
        "Model configuration",
        "Juice Shop lab",
    }
    assert sum(c["ok"] for c in checks) == 1
    lab_probe = next(argv for argv in calls if len(argv) > 1 and argv[1] == "run" and "emerg-lab_lab" in argv)
    assert "--network" in lab_probe
    assert "--read-only" in lab_probe
    assert "--cap-drop" in lab_probe
    assert "127.0.0.1" not in lab_probe[-1]
