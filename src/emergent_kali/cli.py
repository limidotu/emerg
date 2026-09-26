from __future__ import annotations

import asyncio
import json
import sys
import threading
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from typer.core import TyperCommand

from .doctor import diagnose
from .engine import Engine
from .models import LAB, Limits, RunConfig
from .redaction import redact
from .reports import export_report
from .store import Store

app = typer.Typer(
    no_args_is_help=False,
    pretty_exceptions_enable=False,
    help="Run authorized security tests against the local Juice Shop lab.",
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        from .tui import EmergentApp

        EmergentApp().run()


class ScanCommand(TyperCommand):
    def make_context(self, info_name, args, parent=None, **extra):
        jsonl = "--jsonl" in args
        try:
            return super().make_context(info_name, args, parent=parent, **extra)
        except Exception as exc:
            # Typer reserves code 2 for syntax errors. emerg reserves it for findings.
            if getattr(exc, "exit_code", None) == 2:
                if jsonl:
                    typer.echo(
                        json.dumps(
                            {
                                "kind": "error",
                                "data": {"message": "Invalid scan arguments. Run emerg scan --help."},
                            }
                        )
                    )
                    raise typer.Exit(1) from None
                exc.exit_code = 1
            raise


def fail(exc: Exception, jsonl: bool = False):
    message = (
        "Invalid run setup: " + "; ".join(e["msg"] for e in exc.errors(include_input=False))
        if isinstance(exc, ValidationError)
        else str(exc)
    )
    message = redact(message)
    if jsonl:
        typer.echo(json.dumps({"kind": "error", "data": {"message": message}}))
    else:
        typer.echo("Error: " + message, err=True)
    raise typer.Exit(1)


@app.command(cls=ScanCommand)
def scan(
    authorization: Annotated[str, typer.Option(help="Explicit statement that you may test this lab.")] = "",
    allowlist: Annotated[
        list[str] | None, typer.Option(help="Exact target origin. Required even for a mock run.")
    ] = None,
    target: str = LAB,
    instructions: str = "Check the lab for exposed information.",
    depth: str = "quick",
    mock: Annotated[
        bool, typer.Option(help="Use fake tools and a fake model. No Docker or network calls.")
    ] = False,
    jsonl: Annotated[bool, typer.Option("--jsonl", help="Stream JSON Lines events.")] = False,
    time_limit: int = 3600,
    command_limit: int = 20,
    output_limit: int = 65536,
    request_rate: int = 2,
    request_limit: int = 100,
    control_stdin: Annotated[
        bool, typer.Option(help="Read pause, resume, and cancel commands from stdin.")
    ] = False,
):
    """Run headless. Exit 0: clear, 1: error/cancel, 2: validated findings."""
    store = None
    try:
        config = RunConfig(
            target=target,
            authorization=authorization,
            allowlist=allowlist or [],
            instructions=instructions,
            depth=depth,
            mock=mock,
            limits=Limits(
                seconds=time_limit,
                commands=command_limit,
                output_bytes=output_limit,
                requests_per_second=request_rate,
                requests=request_limit,
            ),
        )
        store = Store()

        def stream(event):
            if jsonl:
                typer.echo(json.dumps(event))
            else:
                data = event["data"]
                typer.echo(f"{event['kind']}: " + json.dumps(data, ensure_ascii=False))

        engine = Engine(store, config, on_event=stream)

        async def run():
            if control_stdin:
                loop = asyncio.get_running_loop()

                def controls():
                    for line in sys.stdin:
                        action = {
                            "pause": engine.pause,
                            "resume": engine.resume,
                            "cancel": engine.cancel,
                        }.get(line.strip())
                        if action and not loop.is_closed():
                            loop.call_soon_threadsafe(action)

                threading.Thread(target=controls, daemon=True).start()
            return await engine.run()

        code = asyncio.run(run())
    except (ValueError, RuntimeError, OSError) as exc:
        fail(exc, jsonl)
    except KeyboardInterrupt:
        raise typer.Exit(1)
    finally:
        if store:
            store.close()
    raise typer.Exit(code)


@app.command()
def runs():
    """List the latest 100 saved runs."""
    store = Store()
    try:
        for row in store.runs():
            typer.echo(f"{row['id']}  {row['state']:10}  {row['created']}")
    finally:
        store.close()


@app.command()
def show(run_id: str):
    """Display a saved run and its validated findings."""
    store = Store()
    try:
        typer.echo(
            json.dumps(redact({"run": store.run(run_id), "findings": store.findings(run_id)}), indent=2)
        )
    except ValueError as exc:
        fail(exc)
    finally:
        store.close()


@app.command()
def report(run_id: str, format: str = "markdown", output: Path | None = None):
    """Export validated findings as markdown, json, csv, or sarif."""
    store = Store()
    try:
        suffix = {"markdown": "md", "json": "json", "csv": "csv", "sarif": "sarif"}.get(format)
        if not suffix:
            raise ValueError("Format must be markdown, json, csv, or sarif.")
        destination = output or store.workspace(run_id) / f"report.{suffix}"
        export_report(store, run_id, format, destination)
        typer.echo(str(destination.resolve()))
    except (ValueError, OSError) as exc:
        fail(exc)
    finally:
        store.close()


@app.command()
def doctor(json_output: Annotated[bool, typer.Option("--json")] = False):
    """Check every local dependency. No scan runs."""
    checks = redact(asyncio.run(diagnose()))
    if json_output:
        typer.echo(json.dumps(checks, indent=2))
    else:
        for check in checks:
            typer.echo(f"{'OK' if check['ok'] else 'FAIL'}  {check['dependency']}: {check['detail']}")
    raise typer.Exit(0 if all(check["ok"] for check in checks) else 1)


if __name__ == "__main__":
    app()
