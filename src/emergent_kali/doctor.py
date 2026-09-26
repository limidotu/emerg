from __future__ import annotations

import json

import httpx

from .docker import compose_file, process
from .model import ModelConfig


async def diagnose() -> list[dict]:
    checks = []

    async def check(name, argv, predicate=None):
        try:
            code, out, _ = await process(argv, timeout=8)
            ok = code == 0 and (predicate(out) if predicate else True)
            checks.append(
                {"dependency": name, "ok": bool(ok), "detail": "Ready" if ok else "Unavailable or invalid"}
            )
        except (OSError, TimeoutError, RuntimeError, ValueError):
            checks.append({"dependency": name, "ok": False, "detail": "Unavailable or timed out"})

    await check("Docker engine", ["docker", "version", "--format", "{{.Server.Version}}"])
    await check("Docker Compose", ["docker", "compose", "version"])
    checks.append(
        {"dependency": "Compose configuration", "ok": compose_file().is_file(), "detail": str(compose_file())}
    )
    await check(
        "Kali image",
        ["docker", "image", "inspect", "emerg-kali:local"],
        lambda value: json.loads(value)[0]["Config"]["User"].split(":")[0] not in {"", "0", "root"},
    )
    await check(
        "Kali tools",
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--entrypoint",
            "python3",
            "emerg-kali:local",
            "-c",
            "import shutil,sys;sys.exit(not all(shutil.which(x) for x in ('curl','nmap','nuclei','sqlmap')))",
        ],
    )
    try:
        config = ModelConfig.from_env()
        checks.append({"dependency": "Model configuration", "ok": True, "detail": config.model})
        headers = {"Authorization": "Bearer " + config.api_key} if config.api_key else {}
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            async with client.stream("GET", config.base_url + "/models", headers=headers) as response:
                ok = response.is_success
        checks.append(
            {
                "dependency": "Model endpoint",
                "ok": ok,
                "detail": "Ready" if ok else "The models endpoint failed",
            }
        )
    except ValueError as exc:
        checks.append({"dependency": "Model configuration", "ok": False, "detail": str(exc)})
        checks.append(
            {
                "dependency": "Model endpoint",
                "ok": False,
                "detail": "Set the model environment variables first",
            }
        )
    except httpx.HTTPError:
        checks.append(
            {"dependency": "Model endpoint", "ok": False, "detail": "Cannot connect to the model endpoint"}
        )
    await check(
        "Isolated lab network",
        ["docker", "network", "inspect", "emerg-lab_lab"],
        lambda value: json.loads(value)[0]["Internal"] is True,
    )
    lab_check = (
        "import http.client; c=http.client.HTTPConnection('juice-shop',3000,timeout=5); "
        "c.request('GET','/'); r=c.getresponse(); b=r.read(32768); "
        "assert r.status==200 and b'Juice Shop' in b; print('Juice Shop ready')"
    )
    await check(
        "Juice Shop lab",
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "emerg-lab_lab",
            "--user",
            "10001:10001",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=8m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "16",
            "--memory",
            "64m",
            "--cpus",
            ".25",
            "--entrypoint",
            "python3",
            "emerg-kali:local",
            "-c",
            lab_check,
        ],
        lambda output: "Juice Shop ready" in output,
    )
    return checks
