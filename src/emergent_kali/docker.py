from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from .models import lab_origin


def compose_file() -> Path:
    source = Path(__file__).resolve().parents[2] / "services" / "compose.yaml"
    if source.exists():
        return source
    return Path(__file__).parent / "bundle" / "services" / "compose.yaml"


async def process(argv: list[str], timeout: float = 15, limit: int = 262144) -> tuple[int, str, str]:
    """Bound both pipes and kill the Docker client when its caller stops."""
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    used = 0

    async def read(stream):
        nonlocal used
        result = bytearray()
        while chunk := await stream.read(4096):
            used += len(chunk)
            if used > limit:
                raise RuntimeError("The process output limit was reached.")
            result.extend(chunk)
        return result.decode("utf-8", "replace")

    jobs = [asyncio.create_task(read(proc.stdout)), asyncio.create_task(read(proc.stderr))]
    try:
        async with asyncio.timeout(timeout):
            out, err = await asyncio.gather(*jobs)
            code = await proc.wait()
            return code, out, err
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        for job in jobs:
            if not job.done():
                job.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)


class DockerRunner:
    def __init__(self, run_id: str, workspace: Path):
        self.name = "emerg-" + run_id
        self.workspace = workspace.resolve()
        self.created = False
        self.max_age = 330

    async def start(self):
        # Use the host UID on Linux to keep the mount writable without broad permissions.
        uid = os.getuid() if hasattr(os, "getuid") and os.getuid() != 0 else 10001
        gid = os.getgid() if hasattr(os, "getgid") and os.getgid() != 0 else 10001
        if hasattr(os, "getuid") and os.getuid() == 0:
            os.chown(self.workspace, uid, gid)
        self.created = True  # Clean up even if Docker creates the container before a client timeout.
        argv = [
            "docker",
            "compose",
            "-f",
            str(compose_file()),
            "run",
            "-d",
            "--rm",
            "--no-deps",
            "--name",
            self.name,
            "--user",
            f"{uid}:{gid}",
            "--volume",
            f"{self.workspace}:/workspace:rw",
        ]
        if os.environ.get("EMERG_LAB_URL"):
            argv.extend(["-e", "EMERG_LAB_URL=" + lab_origin()])
        argv.extend(
            ["kali-runner", "python3", "/opt/emerg/runtime.py", "serve", str(self.max_age)]
        )
        try:
            code, _, _ = await process(argv, timeout=90)
        except TimeoutError as exc:
            raise RuntimeError("Kali container startup timed out after 90 seconds.") from exc
        if code:
            raise RuntimeError("The Kali runner could not start. Run emerg doctor.")
        await self.verify()

    async def verify(self):
        code, output, _ = await process(["docker", "inspect", self.name])
        if code:
            raise RuntimeError("The runner configuration could not be checked.")
        info = json.loads(output)[0]
        host = info["HostConfig"]
        mounts = [m for m in info["Mounts"] if m["Type"] != "tmpfs"]
        user = info["Config"]["User"].split(":")[0]
        env_names = {item.split("=", 1)[0] for item in info["Config"]["Env"]}
        if (
            not user.isdigit()
            or int(user) == 0
            or host.get("Privileged")
            or not host.get("ReadonlyRootfs")
            or "ALL" not in [cap.upper() for cap in host.get("CapDrop", [])]
            or len(mounts) != 1
            or mounts[0]["Destination"] != "/workspace"
            or mounts[0]["Type"] != "bind"
            or not any("no-new-privileges" in opt for opt in host.get("SecurityOpt", []))
            or host.get("NetworkMode") == "host"
            or any(
                any(secret in name.upper() for secret in ("KEY", "TOKEN", "PASSWORD", "SECRET"))
                for name in env_names
            )
        ):
            raise RuntimeError("The runner isolation check failed.")
        networks = info["NetworkSettings"]["Networks"]
        if len(networks) != 1:
            raise RuntimeError("The runner must use one isolated lab network.")
        code, output, _ = await process(["docker", "network", "inspect", next(iter(networks))])
        if code or not json.loads(output)[0]["Internal"]:
            raise RuntimeError("The lab network must block external traffic.")

    async def execute(self, tool: str, arguments: dict, limits: dict) -> dict:
        payload = json.dumps({"tool": tool, "arguments": arguments, "limits": limits})
        code, out, _ = await process(
            ["docker", "exec", self.name, "python3", "/opt/emerg/runtime.py", "execute", payload],
            timeout=limits["command_seconds"] + 10,
            limit=limits["output_bytes"] * 8 + 16384,
        )
        if code:
            raise RuntimeError("The runner command failed.")
        try:
            result = json.loads(out)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("The runner returned an invalid result.") from exc
        return result

    async def pause(self):
        code, _, _ = await process(["docker", "pause", self.name])
        if code:
            raise RuntimeError("Docker could not pause the runner.")

    async def resume(self):
        code, _, _ = await process(["docker", "unpause", self.name])
        if code:
            raise RuntimeError("Docker could not resume the runner.")

    async def stop(self):
        if self.created:
            # Force removal also stops processes in a paused container.
            code, _, err = await process(["docker", "rm", "-f", self.name])
            if code and "No such container" not in err:
                raise RuntimeError(f"Container cleanup failed. Remove {self.name} with docker rm -f.")
            self.created = False


class FakeRunner:
    """Offline demo runner. It never starts a process or sends a request."""

    def __init__(self, run_id: str, workspace: Path):
        self.started = False
        self.stopped = False
        self.paused = False

    async def start(self):
        self.started = True

    async def execute(self, tool, arguments, limits):
        await asyncio.sleep(0.01)
        return {
            "stdout": "HTTP/1.1 200 OK\nPublic directory index: acquisitions.md\n",
            "stderr": "",
            "exit_code": 0,
            "truncated": False,
            "timed_out": False,
            "request_limit": False,
            "records": [
                {
                    "url": arguments["url"],
                    "status": 200,
                    "headers": {},
                    "body": "Public directory index: acquisitions.md",
                }
            ],
        }

    async def pause(self):
        self.paused = True

    async def resume(self):
        self.paused = False

    async def stop(self):
        self.stopped = True
