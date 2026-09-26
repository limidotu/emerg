from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Callable

from pydantic import ValidationError

from .docker import DockerRunner, FakeRunner
from .model import MockModel, OpenAIModel, parse_plain
from .models import (
    lab_origin,
    RESPONSE_ADAPTER,
    Assignment,
    Citation,
    Finding,
    FindingDraft,
    Observation,
    Plan,
    RunConfig,
    State,
    Stop,
    ToolArgs,
    ToolCall,
    ToolResult,
)
from .signatures import (
    ONCE_PER_RUN,
    START_PATHS,
    concrete_paths,
    detect,
    echoed_account,
    mentioned_paths,
    priority_paths,
    sibling_map_path,
    secured_reads,
    unread_paths,
)
from .redaction import redact
from .runner_runtime import command
from .store import Store

SCHEMA_NOTE = "Return one JSON object that matches the response schema. No Markdown fences."


def _with_kind_note(note: str, label: str) -> str:
    if "union_tag_not_found" not in label:
        return note
    return (
        note
        + " The object must include kind. Allowed values are tool_call, observation, finding, and stop."
    )


def _short_key(key: object) -> str:
    if not isinstance(key, str) or not key or len(key) > 40:
        return ""
    if not (key[0].isascii() and (key[0].isalpha() or key[0] == "_")):
        return ""
    if not all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in key):
        return ""
    return key


def object_key_note(text: str) -> str:
    """Name up to eight short object keys. Do not copy values."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""
    names = sorted({name for key in data if (name := _short_key(key))})
    if not names:
        return ""
    return " Object keys: " + ", ".join(names[:8]) + "."


def schema_error_note(exc: Exception, text: str = "") -> str:
    """Name the validator error type and short object keys. Do not copy model text."""
    kinds: list[str] = []
    if isinstance(exc, ValidationError):
        for err in exc.errors():
            kind = "".join(ch for ch in str(err.get("type") or "") if ch.isalnum() or ch == "_")
            if kind and kind not in kinds:
                kinds.append(kind)
            if len(kinds) == 3:
                break
    label = ", ".join(kinds) if kinds else "json_invalid"
    return _with_kind_note(SCHEMA_NOTE + " Error type: " + label + ".", label) + object_key_note(text)


def same_evidence_candidate(candidate, other) -> bool:
    """True when the location and quotes match. The title text may differ."""
    left = candidate.model_dump()
    right = other.model_dump()
    left.pop("title", None)
    right.pop("title", None)
    return left == right


def validator_host_note(schema_note: str, wrong_shape: bool) -> str:
    """Retry the validator. A schema failure also repeats the unchanged-candidate rule."""
    notes = []
    if schema_note:
        notes.append(schema_note)
    if wrong_shape or schema_note:
        notes.append("Return the candidate object unchanged. Set decision to confirmed or rejected.")
    return " ".join(notes)


def schema_failure_note(message: str, used: bool) -> str:
    """Give one invalid JSON response a schema note. It does not count toward the stop."""
    if used or "invalid JSON" not in message:
        return ""
    return schema_note_from_refusal(message)


def schema_note_from_refusal(message: str) -> str:
    """Rebuild the reminder from the error type already stored on the refusal."""
    marker = "Error type: "
    if marker not in message:
        return SCHEMA_NOTE
    tail = message.split(marker, 1)[1]
    head = tail.split(".", 1)[0]
    label = "".join(ch for ch in head if ch.isalnum() or ch in {"_", ",", " "}).strip(" .,")
    note = _with_kind_note(SCHEMA_NOTE + " Error type: " + (label or "json_invalid") + ".", label)
    if "Object keys: " not in message:
        return note
    raw = message.split("Object keys: ", 1)[1].split(".", 1)[0]
    names = []
    for part in raw.split(","):
        key = _short_key(part.strip())
        if key and key not in names:
            names.append(key)
        if len(names) == 8:
            break
    if not names:
        return note
    return note + " Object keys: " + ", ".join(names) + "."


def clip_evidence(evidence: dict, limit: int = 1500) -> dict:
    """Give the model short record excerpts. The stored evidence stays complete."""
    clipped = {}
    for evidence_id, item in evidence.items():
        records = []
        for record in item.get("records") or []:
            url = record.get("url") or ""
            body = record.get("body") or ""
            if isinstance(url, str) and static_asset(url):
                continue
            if isinstance(body, str) and _api_body(body):
                continue
            if isinstance(body, str) and html_markup(body):
                continue
            if len(body) > limit:
                body = body[:limit]
            records.append({"url": record.get("url"), "status": record.get("status"), "body": body})
        clipped[evidence_id] = {
            "tool": item.get("tool"),
            "exit_code": item.get("exit_code"),
            "truncated": bool(item.get("truncated")),
            "records": records,
        }
    return clipped


def html_markup(body: str) -> bool:
    """True when the body is a page shell rather than a data response."""
    text = body.lstrip().casefold()
    return text.startswith("<!--") or text.startswith("<!doctype") or text.startswith("<html")


def alternate_record(evidence: dict, refused: str) -> str:
    """One captured URL from this run, other than the refused location."""
    seen: list[str] = []
    for item in evidence.values():
        if item.get("exit_code") != 0:
            continue
        for record in item.get("records") or []:
            url = record.get("url")
            body = record.get("body") or ""
            if not isinstance(url, str) or url == refused or url in seen:
                continue
            if not isinstance(body, str) or len(body) < 8 or record.get("status") != 200:
                continue
            if "openapi" in body.casefold() and '"paths"' in body:
                continue
            if html_markup(body):
                continue
            seen.append(url)
    return seen[0] if seen else ""


_STATIC_SUFFIX = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".map",
    ".woff",
    ".woff2",
)


def static_asset(url: str) -> bool:
    """True when the URL names a static file rather than a data response."""
    return url.split("?", 1)[0].casefold().endswith(_STATIC_SUFFIX)


def _api_body(body: str) -> bool:
    """True when the body is an API document."""
    folded = body.casefold()
    if "openapi" not in folded and "swagger" not in folded:
        return False
    return '"paths"' in body or "\npaths:" in "\n" + body


def _data_quote_record(record: dict) -> bool:
    """True for a long public data body. Pages, specs, and static files do not count."""
    url = record.get("url")
    body = record.get("body") or ""
    if not isinstance(url, str) or static_asset(url):
        return False
    if not isinstance(body, str) or len(body) < 80 or record.get("status") != 200:
        return False
    return not html_markup(body) and not _api_body(body)


def has_data_record(evidence: dict) -> bool:
    """True when this run captured at least one long public data body."""
    for item in evidence.values():
        if item.get("exit_code") != 0:
            continue
        if any(_data_quote_record(record) for record in item.get("records") or []):
            return True
    return False


def uncovered_quote_url(evidence: dict, findings: list[dict]) -> str:
    """The longest captured data URL that has no stored finding."""
    covered = {item.get("location") for item in findings}
    best = ""
    best_len = 0
    for item in evidence.values():
        if item.get("exit_code") != 0:
            continue
        for record in item.get("records") or []:
            if not _data_quote_record(record) or record.get("url") in covered:
                continue
            body = record.get("body") or ""
            if len(body) > best_len:
                best = record["url"]
                best_len = len(body)
    return best


def empty_quote_note(message: str, history: list[dict], used: bool) -> str:
    """Repeat one verbatim-quote note after an empty response."""
    if used or "had no text" not in message:
        return ""
    return latest_quote_note(history)


def empty_data_note(message: str, used: bool, evidence: dict, findings: list[dict]) -> str:
    """One note after an empty response when a data record exists and no quote note does."""
    if used or "had no text" not in message or not has_data_record(evidence):
        return ""
    other = uncovered_quote_url(evidence, findings)
    if other:
        return (
            "Copy one verbatim quote from the body of "
            + other
            + ". Set location to that URL."
        )
    return "The captured data records already have findings. Return stop."


def latest_quote_note(history: list[dict]) -> str:
    """The latest host note that asks for a verbatim quote."""
    for item in reversed(history):
        summary = item.get("summary") or ""
        if item.get("kind") == "observation" and "Copy one verbatim quote" in summary:
            return summary
    return ""


def observation_quote_note(history: list[dict], already_refused: bool) -> str:
    """Repeat the latest verbatim-quote request once."""
    if already_refused:
        return ""
    return latest_quote_note(history)


def refuse_stop(count: int, quote: str) -> bool:
    """Refuse the first stop, and one more stop when a quote note is waiting."""
    if count <= 0:
        return True
    return count == 1 and bool(quote)


def stop_quote_note(history: list[dict], refused_candidate: bool) -> str:
    """Refuse stop by repeating the newest note. A closed stop note wins over an older quote."""
    for item in reversed(history):
        summary = item.get("summary") or ""
        if item.get("kind") != "observation":
            continue
        closed = "Return stop" in summary and "findings" in summary and "http://" not in summary
        if closed or "Copy one verbatim quote" in summary:
            return summary
    for item in reversed(history):
        summary = item.get("summary") or ""
        if item.get("kind") == "observation" and "Return stop" in summary:
            return summary
    if refused_candidate:
        return (
            "The host refused stop. Copy one verbatim quote from the body "
            "of the record whose URL equals the location."
        )
    return (
        "The host refused stop. Return one candidate finding. "
        "Copy a verbatim quote from a captured record body and set location to that record URL."
    )


def repeat_refusal_note(count: int, evidence: dict, findings: list[dict]) -> str:
    """After two captured-URL refusals, ask for a quote instead of another path."""
    if count >= 2:
        other = uncovered_quote_url(evidence, findings)
        if other:
            return (
                "The host refused this tool call. Every path is already captured. "
                "Copy one verbatim quote from the body of "
                + other
                + ". Set location to that URL."
            )
        return (
            "The host refused this tool call. Every path is already captured. "
            "The captured data records already have findings. Return stop."
        )
    return (
        "The host refused this tool call. Every path is already captured. "
        "Choose a path from a captured response that is not yet a captured URL."
    )


def covered_location_note(evidence: dict, findings: list[dict], location: str) -> str:
    """Name an uncovered URL when this location already has a stored finding."""
    if not any(item.get("location") == location for item in findings):
        return ""
    other = uncovered_quote_url(evidence, findings)
    base = "The host refused this finding. That location already has a stored finding. "
    if not other or other == location:
        return base + "The captured data records already have findings. Return stop."
    return base + "Copy one verbatim quote from the body of " + other + ". Set location to that URL."


def closed_quote_note(note: str) -> bool:
    """True when no uncovered URL remains and the note should end web-test."""
    if "Return stop" in note and "findings" in note and "http://" not in note:
        return True
    return "captured record that has no stored finding" in note


def note_ends_closed_role(role: str, note: str, count: int) -> bool:
    """End web-test after a closed note twice. End reconnaissance after a plan note twice."""
    if not closed_quote_note(note) or count < 2:
        return False
    if role == "web-test":
        return True
    return role == "reconnaissance" and "kind plan is invalid" in note


def stored_quote_note(evidence: dict, findings: list[dict], location: str) -> str:
    """Point at one uncovered URL when the quote is already stored."""
    other = uncovered_quote_url(evidence, findings)
    base = "The host refused this finding. That quote is already stored for this location. "
    if other and other != location:
        return (
            base
            + "Copy one verbatim quote from the body of "
            + other
            + ". Set location to that URL."
        )
    return base + "Copy a different verbatim quote from the record body."


def title_quote_mismatch(title: str, quotes: set[str]) -> bool:
    """True when a secret title is not supported by the quote."""
    folded = title.casefold()
    if not any(word in folded for word in ("secret", "credential", "password")):
        return False
    blob = " ".join(quotes).casefold()
    if "@" in blob:
        return False
    return not any(word in blob for word in ("secret", "password", "credential", "token"))


def source_map_location(location: str) -> bool:
    """True when the finding points at a source map rather than a data record."""
    return location.split("?", 1)[0].casefold().endswith(".map")


def markup_refusal_note() -> str:
    """Refuse page markup without sending the model back to that page."""
    return (
        "The host refused this finding. Do not quote the page markup. "
        "Copy one verbatim quote from a captured data record."
    )


def source_map_note() -> str:
    """Refuse a source map quote without naming a covered URL."""
    return (
        "The host refused this finding. Do not quote a source map. "
        "Copy one verbatim quote from a captured data record."
    )


def markup_quote(quotes: set[str]) -> bool:
    """True when the quote is the page shell rather than a specific disclosure."""
    for quote in quotes:
        text = quote.lstrip().casefold()
        if text.startswith("<!--") or text.startswith("<!doctype") or text.startswith("<html"):
            return True
    return False


def reused_quote(findings: list[dict], location: str, quotes: set[str]) -> bool:
    """True when this location already stores the same text or a copy that contains it."""
    for item in findings:
        if item.get("location") != location:
            continue
        stored = {
            citation.get("quote")
            for citation in item.get("evidence") or []
            if citation.get("quote")
        }
        for quote in quotes:
            for prior in stored:
                if quote == prior or quote in prior or prior in quote:
                    return True
    return False


def only_repeated_targets(origin: str, call: ToolCall, captured: set[str]) -> bool:
    """True when every requested URL is already stored for this run."""
    if not captured or call.tool not in {"content_discovery", "crawl", "http_probe"}:
        return False
    targets = [origin + path for path in call.arguments.paths if path.startswith("/")]
    url = call.arguments.url
    if url.startswith(origin) and url.rstrip("/") != origin.rstrip("/"):
        targets.append(url.split("?", 1)[0])
    return bool(targets) and all(target in captured for target in targets)


def named_paths(evidence: dict) -> set[str]:
    """Paths a captured response in this run actually names."""
    records = []
    spec = ""
    named: set[str] = set()
    for item in evidence.values():
        for record in item.get("records") or []:
            if not isinstance(record, dict):
                continue
            records.append(record)
            body = record.get("body") or ""
            if isinstance(body, str) and '"paths"' in body and "openapi" in body.casefold():
                spec = body
            for path in mentioned_paths(record):
                named.add(path)
    for path in concrete_paths(spec, records):
        named.add(path)
    return named


def requests_unnamed_path(origin: str, call: ToolCall, named: set[str]) -> bool:
    """True when a requested path was not named by a captured response."""
    if not named or call.tool not in {"content_discovery", "crawl", "http_probe"}:
        return False
    requested: list[str] = []
    for path in call.arguments.paths:
        if not isinstance(path, str) or not path:
            continue
        if not path.startswith("/"):
            path = "/" + path
        requested.append(path.split("?", 1)[0])
    url = call.arguments.url
    if url.startswith(origin):
        suffix = url[len(origin) :].split("?", 1)[0]
        if suffix and suffix != "/":
            requested.append(suffix if suffix.startswith("/") else "/" + suffix)
    return any(path not in named for path in requested)


class RunCancelled(Exception):
    pass


class RolePolicyError(RuntimeError):
    pass


def fit_tool_result(result: dict, budget: int) -> dict:
    """Keep a tool result inside the remaining output budget."""
    fitted = dict(result)
    fitted["records"] = list(result.get("records") or [])

    def size() -> int:
        return len(json.dumps(fitted).encode())

    if size() <= budget:
        return fitted
    fitted["truncated"] = True
    stdout = fitted.get("stdout") or ""
    while stdout and size() > budget:
        stdout = stdout[: len(stdout) // 2]
        fitted["stdout"] = stdout
    while fitted["records"] and size() > budget:
        fitted["records"].pop()
    if size() > budget:
        fitted["stdout"] = ""
        fitted["stderr"] = ""
    return fitted


def repair_tool_kind(text: str) -> str:
    """Add a missing kind for a tool call, an observation, or stop. Copy an explicit type. Do not invent a finding."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(data, dict) or "kind" in data:
        return text
    label = data.get("type")
    if isinstance(label, str) and label in {"tool_call", "observation", "finding", "stop", "plan"}:
        data["kind"] = label
        data.pop("type", None)
        return json.dumps(data)
    if "tool" in data and "arguments" in data:
        data["kind"] = "tool_call"
        return json.dumps(data)
    summary = data.get("summary")
    if isinstance(summary, str) and summary.strip() and "finding" not in data and "tool" not in data:
        data["kind"] = "observation"
        return json.dumps(data)
    reason = data.get("reason")
    blocked = {"finding", "tool", "summary", "tasks"}
    if (
        isinstance(reason, str)
        and len(reason.strip()) >= 3
        and not blocked.intersection(data)
        and set(data) <= {"reason"}
    ):
        data["kind"] = "stop"
        return json.dumps(data)
    role = data.get("role")
    task = data.get("task")
    if (
        role in {"reconnaissance", "web-test"}
        and isinstance(task, str)
        and 3 <= len(task.strip()) <= 1000
        and "tool" not in data
        and "finding" not in data
    ):
        return json.dumps({"kind": "plan", "tasks": [{"role": role, "task": task.strip()}]})
    return text


class Engine:
    def __init__(
        self,
        store: Store,
        config: RunConfig,
        model=None,
        runner_factory=None,
        on_event: Callable[[dict], None] | None = None,
    ):
        self.store = store
        self.config = config
        self.run_id = store.create_run(config)
        self.model = model
        factory = runner_factory or (FakeRunner if config.mock else DockerRunner)
        self.runner = factory(self.run_id, store.workspace(self.run_id))
        self.runner.max_age = config.limits.seconds + 30
        self.on_event = on_event or (lambda event: None)
        self.cancel_requested = False
        self.pause_requested = False
        self.container_paused = False
        self.deadline = 0.0
        self.command_count = 0
        self.model_count = 0
        self.output_used = 0
        self.candidates: dict[str, FindingDraft] = {}

    def emit(self, kind: str, **data):
        event = self.store.event(self.run_id, kind, data)
        self.on_event(event)

    def state(self, value: State, error: str | None = None):
        self.store.transition(self.run_id, value, error)
        self.emit("state", state=value, error=error)

    def pause(self):
        self.pause_requested = True

    def resume(self):
        self.pause_requested = False

    def cancel(self):
        self.cancel_requested = True

    async def checkpoint(self):
        while True:
            if self.cancel_requested:
                raise RunCancelled()
            if time.monotonic() >= self.deadline:
                raise RuntimeError("The run time limit was reached.")
            current = State(self.store.run(self.run_id)["state"])
            if self.pause_requested and current in {State.RUNNING, State.PAUSED}:
                if not self.container_paused:
                    await self.runner.pause()
                    self.container_paused = True
                    self.state(State.PAUSED)
                await asyncio.sleep(0.05)
                continue
            if self.container_paused:
                await self.runner.resume()
                self.container_paused = False
                self.state(State.RUNNING)
            return

    async def guarded(self, awaitable):
        task = asyncio.create_task(awaitable)
        try:
            while not task.done():
                await self.checkpoint()
                await asyncio.wait({task}, timeout=0.05)
            await self.checkpoint()
            return await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def ask(self, role: str, context: dict):
        await self.checkpoint()
        self.model_count += 1
        if self.model_count > 60:
            raise RuntimeError("The model turn limit was reached.")
        self.emit("agent", role=role, status="thinking")
        text = await self.guarded(self.model.respond(role, redact(context)))
        if not isinstance(text, str) or len(text.encode()) > 65536:
            raise RuntimeError("The model response exceeded its size limit.")
        text = repair_tool_kind(text)
        try:
            response = RESPONSE_ADAPTER.validate_json(text)
        except (ValidationError, ValueError) as exc:
            note = schema_error_note(exc, text)
            raise RuntimeError(
                f"The {role} model returned invalid JSON or a response outside the schema. {note}"
            ) from exc
        self.emit("agent", role=role, status=response.kind, response=response.model_dump())
        return response

    async def tool(self, role: str, call: ToolCall):
        if role == "reconnaissance" and call.tool not in {"http_probe", "port_scan", "crawl"}:
            raise RolePolicyError(
                "The host refused "
                + call.tool
                + ". Reconnaissance may use only http_probe, port_scan, and crawl."
            )
        if self.config.depth == "quick" and call.tool == "sql_check":
            raise RuntimeError("SQL checks require standard or deep scan depth.")
        cap = min(self.config.limits.commands, {"quick": 6, "standard": 20, "deep": 100}[self.config.depth])
        if self.command_count >= cap:
            raise RuntimeError("The command limit was reached.")
        remaining = self.config.limits.output_bytes - self.output_used
        if remaining < 1024:
            raise RuntimeError("The run output limit was reached.")
        limits = self.config.limits.model_dump()
        limits["output_bytes"] = remaining
        limits["command_seconds"] = max(
            1, min(limits["command_seconds"], int(self.deadline - time.monotonic()))
        )
        args = call.arguments.model_dump()
        args["ports"] = [int(lab_origin().rsplit(":", 1)[-1])]
        argv = command(call.tool, args, limits)
        self.command_count += 1
        self.emit("command_approved", role=role, tool=call.tool, argv=argv, command_number=self.command_count)
        result = await self.guarded(self.runner.execute(call.tool, args, limits))
        try:
            result = ToolResult.model_validate(redact(result)).model_dump()
        except ValidationError as exc:
            raise RuntimeError("The runner returned a result outside the tool schema.") from exc
        result = fit_tool_result(result, remaining)
        if result["truncated"] and result["exit_code"] == -9 and not result["timed_out"]:
            result["exit_code"] = 0
        size = len(json.dumps(result).encode())
        if size > remaining:
            raise RuntimeError("The run output limit was reached.")
        self.output_used += size
        evidence_id = self.store.save_evidence(self.run_id, {"tool": call.tool, "arguments": args, **result})
        self.emit("tool_result", role=role, evidence_id=evidence_id, **result)
        if result["timed_out"] or result["request_limit"]:
            raise RuntimeError("A tool reached its time, output, or request limit.")
        if result["exit_code"] != 0 and not result["truncated"]:
            raise RuntimeError(f"The {call.tool} tool failed with exit code {result['exit_code']}.")
        self.file_signatures(evidence_id, result["records"])
        return result

    def matching_citations(self, draft: FindingDraft):
        evidence = self.store.evidence(self.run_id)
        kept = []
        for citation in draft.evidence:
            item = evidence.get(citation.evidence_id)
            if not item or item.get("exit_code") != 0 or "[REDACTED]" in citation.quote:
                continue
            records = [record for record in item.get("records", []) if record.get("url") == draft.location]
            if any(
                citation.quote in (record.get("body") or "")
                or citation.quote in json.dumps(record, ensure_ascii=False)
                for record in records
            ):
                kept.append(citation)
        return kept

    def check_finding(self, draft: FindingDraft):
        evidence = self.store.evidence(self.run_id)
        for citation in draft.evidence:
            item = evidence.get(citation.evidence_id)
            if not item or item.get("exit_code") != 0 or "[REDACTED]" in citation.quote:
                raise ValueError("A finding cites missing, failed, or redacted evidence.")
            records = [r for r in item.get("records", []) if r.get("url") == draft.location]
            if not records or not any(
                citation.quote in json.dumps(r, ensure_ascii=False) or citation.quote in r.get("body", "")
                for r in records
            ):
                raise ValueError("A finding quote does not match captured evidence at its affected location.")

    def quote_refusal_note(self, location: str, quote_refusals: int) -> str:
        """After two bad quotes, name one uncovered URL. Do not name a covered URL."""
        if quote_refusals >= 2:
            other = uncovered_quote_url(
                self.store.evidence(self.run_id), self.store.findings(self.run_id)
            )
            if other and other != location:
                return (
                    "The host refused this finding. Copy one verbatim quote from the body of "
                    + other
                    + ". Set location to that URL."
                )
        return (
            "The host refused this finding. Copy one verbatim quote from the body "
            "of the record whose URL equals the location."
        )

    async def assigned_task(self, assignment):
        task_id = uuid.uuid4().hex
        role = assignment.role
        self.store.execute(
            "INSERT INTO tasks VALUES(?,?,?,?,?)",
            (task_id, self.run_id, role, redact(assignment.task), "running"),
        )
        self.emit("task", task_id=task_id, role=role, description=assignment.task, state="running")
        history = []
        filed = False
        stop_refusals = 0
        refused_observation = False
        refused_candidate = False
        quote_refusals = 0
        closed_count = 0
        repeat_refusals = 0
        failures = 0
        schema_used = False
        empty_used = False
        schema_retry = ""

        def deliver_closed(note: str) -> bool:
            nonlocal closed_count
            if closed_quote_note(note):
                closed_count += 1
            history.append({"kind": "observation", "summary": note, "evidence_ids": []})
            self.emit("agent", role=role, status="refused", response={"reason": note})
            return note_ends_closed_role(role, note, closed_count)

        try:
            for _ in range({"quick": 5, "standard": 8, "deep": 12}[self.config.depth]):
                payload = {
                    "task": assignment.task,
                    "target": self.config.target,
                    "instructions": self.config.instructions,
                    "depth": self.config.depth,
                    "history": history[-12:],
                    "evidence": clip_evidence(self.store.evidence(self.run_id)),
                    "known_findings": [item["title"] for item in self.store.findings(self.run_id)],
                }
                if schema_retry:
                    payload["host_note"] = schema_note_from_refusal(schema_retry)
                schema_retry = ""
                try:
                    response = await self.ask(role, payload)
                except RuntimeError as exc:
                    self.emit("agent", role=role, status="refused", response={"reason": str(exc)})
                    note = schema_failure_note(str(exc), schema_used)
                    if note:
                        schema_used = True
                        schema_retry = str(exc)
                        history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                        continue
                    if "had no text" in str(exc) and empty_used:
                        break
                    note = empty_quote_note(str(exc), history, empty_used)
                    if not note and role == "web-test":
                        note = empty_data_note(
                            str(exc),
                            empty_used,
                            self.store.evidence(self.run_id),
                            self.store.findings(self.run_id),
                        )
                    if note:
                        empty_used = True
                        history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                        continue
                    failures += 1
                    if failures >= 2:
                        break
                    note = "The host discarded that turn. Continue from the captured evidence."
                    history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                    continue
                failures = 0
                history.append(response.model_dump())
                if isinstance(response, ToolCall):
                    captured = {
                        record.get("url")
                        for item in self.store.evidence(self.run_id).values()
                        for record in item.get("records") or []
                        if isinstance(record.get("url"), str)
                    }
                    if only_repeated_targets(lab_origin(), response, captured):
                        repeat_refusals += 1
                        note = repeat_refusal_note(
                            repeat_refusals,
                            self.store.evidence(self.run_id),
                            self.store.findings(self.run_id),
                        )
                        if deliver_closed(note):
                            break
                        continue
                    if requests_unnamed_path(
                        lab_origin(), response, named_paths(self.store.evidence(self.run_id))
                    ):
                        note = (
                            "The host refused this tool call. A requested path was not named by a captured response. "
                            "Choose a path that appears in a captured response."
                        )
                        history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                        self.emit("agent", role=role, status="refused", response={"reason": note})
                        continue
                    try:
                        await self.tool(role, response)
                    except RolePolicyError as exc:
                        history.append({"kind": "observation", "summary": str(exc), "evidence_ids": []})
                        self.emit("agent", role=role, status="refused", response={"reason": str(exc)})
                elif isinstance(response, Finding) and response.decision == "candidate":
                    draft = response.finding.model_copy(
                        update={"evidence": self.matching_citations(response.finding)}
                    )
                    if not draft.evidence:
                        refused_candidate = True
                        quote_refusals += 1
                        findings = self.store.findings(self.run_id)
                        evidence = self.store.evidence(self.run_id)
                        if source_map_location(response.finding.location):
                            note = source_map_note()
                        else:
                            note = covered_location_note(
                                evidence, findings, response.finding.location
                            ) or self.quote_refusal_note(response.finding.location, quote_refusals)
                        if deliver_closed(note):
                            break
                        continue
                    try:
                        self.check_finding(draft)
                    except ValueError as exc:
                        refused_candidate = True
                        quote_refusals += 1
                        note = covered_location_note(
                            self.store.evidence(self.run_id),
                            self.store.findings(self.run_id),
                            draft.location,
                        ) or self.quote_refusal_note(draft.location, quote_refusals)
                        if not note.startswith("The host refused this finding. That location") and quote_refusals < 2:
                            note = "The host refused this finding. " + str(exc)
                        if deliver_closed(note):
                            break
                        continue
                    quotes = {citation.quote for citation in draft.evidence}
                    if source_map_location(draft.location):
                        refused_candidate = True
                        quote_refusals += 1
                        note = source_map_note()
                        history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                        self.emit("agent", role=role, status="refused", response={"reason": note})
                        continue
                    if markup_quote(quotes):
                        refused_candidate = True
                        quote_refusals += 1
                        note = markup_refusal_note()
                        history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                        self.emit("agent", role=role, status="refused", response={"reason": note})
                        continue
                    if title_quote_mismatch(draft.title, quotes):
                        refused_candidate = True
                        quote_refusals += 1
                        note = (
                            "The host refused this finding. The quote does not show a secret, "
                            "password, credential, token, or email."
                        )
                        history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                        self.emit("agent", role=role, status="refused", response={"reason": note})
                        continue
                    if reused_quote(self.store.findings(self.run_id), draft.location, quotes):
                        refused_candidate = True
                        quote_refusals += 1
                        note = stored_quote_note(
                            self.store.evidence(self.run_id),
                            self.store.findings(self.run_id),
                            draft.location,
                        )
                        covered = covered_location_note(
                            self.store.evidence(self.run_id),
                            self.store.findings(self.run_id),
                            draft.location,
                        )
                        if covered:
                            note = covered
                        if deliver_closed(note):
                            break
                        continue
                    candidate = FindingDraft.model_validate(redact(draft.model_dump()))
                    self.candidates[candidate.stable_id] = candidate
                    self.store.save_finding(
                        self.run_id, {"id": candidate.stable_id, **candidate.model_dump()}, False
                    )
                    filed = True
                    if role == "web-test" and self.store.findings(self.run_id):
                        break
                elif isinstance(response, Observation):
                    if any(item not in self.store.evidence(self.run_id) for item in response.evidence_ids):
                        raise ValueError("The observation cites unknown evidence.")
                    quote_note = observation_quote_note(history[:-1], refused_observation)
                    if quote_note:
                        refused_observation = True
                        history.append({"kind": "observation", "summary": quote_note, "evidence_ids": []})
                        self.emit("agent", role=role, status="refused", response={"reason": quote_note})
                        continue
                    prior = [item for item in history[:-1] if item.get("kind") == "observation"]
                    if any(item.get("summary") == response.summary for item in prior):
                        break
                elif isinstance(response, Stop):
                    had_tool = any(item.get("kind") == "tool_call" for item in history[:-1])
                    quote = latest_quote_note(history[:-1])
                    if (
                        role == "web-test"
                        and not filed
                        and (had_tool or refused_candidate)
                        and refuse_stop(stop_refusals, quote)
                    ):
                        stop_refusals += 1
                        note = stop_quote_note(history[:-1], refused_candidate)
                        if deliver_closed(note):
                            break
                        continue
                    break
                else:
                    if response.kind == "plan":
                        note = (
                            "The host refused this plan. kind plan is invalid for the "
                            + role
                            + " role. Allowed kinds are tool_call, observation, finding, and stop. "
                            "The captured data records already have findings. Return stop."
                        )
                        if deliver_closed(note):
                            break
                        continue
                    note = (
                        "The host refused this "
                        + response.kind
                        + " decision. Return a tool call, an observation, a candidate finding, or stop."
                    )
                    history.append({"kind": "observation", "summary": note, "evidence_ids": []})
                    self.emit("agent", role=role, status="refused", response={"reason": note})
            else:
                self.emit(
                    "agent",
                    role=role,
                    status="refused",
                    response={"reason": "The host ended the task at the turn limit."},
                )
        except BaseException:
            self.store.execute("UPDATE tasks SET state='failed' WHERE id=?", (task_id,))
            self.emit("task", task_id=task_id, role=role, state="failed")
            raise
        self.store.execute("UPDATE tasks SET state='completed' WHERE id=?", (task_id,))
        self.emit("task", task_id=task_id, role=role, state="completed")

    def _captured_spec(self) -> str:
        for item in self.store.evidence(self.run_id).values():
            for record in item.get("records") or []:
                body = record.get("body") or ""
                if isinstance(body, str) and '"paths"' in body and "openapi" in body.casefold():
                    return body
        return ""

    def file_signatures(self, evidence_id: str, records: list[dict]) -> None:
        """Record a host finding when a captured response matches a disclosure rule."""
        known = {item["id"] for item in self.store.findings(self.run_id)}
        seen_once = {
            item["title"] for item in self.store.findings(self.run_id) if item["title"] in ONCE_PER_RUN
        }
        spec = self._captured_spec()
        for record in records:
            for item in detect(record) + secured_reads(spec, record):
                if item["title"] in ONCE_PER_RUN and item["title"] in seen_once:
                    continue
                draft = FindingDraft(
                    title=item["title"],
                    severity=item["severity"],
                    category=item["category"],
                    location=item["location"],
                    evidence=[Citation(evidence_id=evidence_id, quote=item["quote"])],
                    reproduction=item["reproduction"],
                    impact=item["impact"],
                    remediation=item["remediation"],
                )
                if draft.stable_id in known or draft.stable_id in self.candidates:
                    continue
                try:
                    self.check_finding(draft)
                except ValueError:
                    continue
                data = {
                    "id": draft.stable_id,
                    **draft.model_dump(),
                    "validation_reason": "The host matched a lab disclosure signature.",
                }
                self.store.save_finding(self.run_id, data, True)
                known.add(draft.stable_id)
                if item["title"] in ONCE_PER_RUN:
                    seen_once.add(item["title"])
                self.emit("finding", **data)
        stored = []
        for item in self.store.evidence(self.run_id).values():
            stored.extend(item.get("records") or [])
        covered = {item.get("location") for item in self.store.findings(self.run_id)}
        echo = echoed_account(stored, covered)
        if not echo or echo["title"] in seen_once:
            return
        evidence_id = ""
        for stored_id, item in self.store.evidence(self.run_id).items():
            if any(record.get("url") == echo["location"] for record in item.get("records") or []):
                evidence_id = stored_id
                break
        if not evidence_id:
            return
        draft = FindingDraft(
            title=echo["title"],
            severity=echo["severity"],
            category=echo["category"],
            location=echo["location"],
            evidence=[Citation(evidence_id=evidence_id, quote=echo["quote"])],
            reproduction=echo["reproduction"],
            impact=echo["impact"],
            remediation=echo["remediation"],
        )
        if draft.stable_id in known or draft.stable_id in self.candidates:
            return
        try:
            self.check_finding(draft)
        except ValueError:
            return
        data = {
            "id": draft.stable_id,
            **draft.model_dump(),
            "validation_reason": "The host matched a lab disclosure signature.",
        }
        self.store.save_finding(self.run_id, data, True)
        self.emit("finding", **data)

    async def surface_sweep(self) -> None:
        """Read the live target. Later paths come only from this run's responses."""
        if self.config.depth != "deep":
            return
        if self.config.limits.output_bytes < 524288:
            self.config.limits.output_bytes = 524288
        if self.config.limits.command_seconds < 90:
            self.config.limits.command_seconds = 90
        origin = lab_origin()
        port = int(origin.rsplit(":", 1)[-1])
        seen: set[str] = set()
        queue = list(START_PATHS)
        spec_body = ""
        for _ in range(6):
            if spec_body:
                front = [path for path in priority_paths(spec_body) if path not in seen]
                queue = front + [path for path in queue if path not in front]
            batch: list[str] = []
            while queue and len(batch) < 8:
                path = queue.pop(0)
                if path in seen:
                    continue
                seen.add(path)
                batch.append(path)
            if not batch:
                break
            result = await self.tool(
                "web-test",
                ToolCall(
                    kind="tool_call",
                    tool="content_discovery",
                    arguments=ToolArgs(url=origin, paths=batch, max_pages=20, ports=[port]),
                ),
            )
            for record in result["records"]:
                body = record.get("body") or ""
                if isinstance(body, str) and '"paths"' in body and "openapi" in body.casefold():
                    spec_body = body
                for path in mentioned_paths(record):
                    if path not in seen:
                        queue.append(path)
                sibling = sibling_map_path(str(record.get("url") or ""))
                if sibling and sibling not in seen and sibling not in queue:
                    queue.append(sibling)
            for path in concrete_paths(spec_body, result["records"]):
                if path not in seen and path not in queue:
                    queue.append(path)

    async def read_one_unread(self) -> None:
        """After the model stops, read one path a captured response already named."""
        if self.config.depth != "deep":
            return
        origin = lab_origin()
        records = []
        captured = set()
        for item in self.store.evidence(self.run_id).values():
            for record in item.get("records") or []:
                records.append(record)
                url = record.get("url")
                if isinstance(url, str):
                    captured.add(url)
        pending = unread_paths(records, self._captured_spec(), captured, origin)
        if not pending:
            return
        port = int(origin.rsplit(":", 1)[-1])
        await self.tool(
            "web-test",
            ToolCall(
                kind="tool_call",
                tool="content_discovery",
                arguments=ToolArgs(url=origin, paths=pending[:1], max_pages=20, ports=[port]),
            ),
        )

    async def workflow(self):
        await self.surface_sweep()
        plan = None
        coordinator = {
            "target": self.config.target,
            "instructions": self.config.instructions,
            "depth": self.config.depth,
            "limits": self.config.limits.model_dump(),
        }
        try:
            plan = await self.ask("coordinator", coordinator)
        except RuntimeError as exc:
            self.emit("agent", role="coordinator", status="refused", response={"reason": str(exc)})
            if "invalid JSON" in str(exc):
                try:
                    plan = await self.ask(
                        "coordinator",
                        {**coordinator, "host_note": schema_note_from_refusal(str(exc))},
                    )
                except RuntimeError as retry_exc:
                    plan = None
                    self.emit(
                        "agent",
                        role="coordinator",
                        status="refused",
                        response={"reason": str(retry_exc)},
                    )
        if isinstance(plan, Plan) and {t.role for t in plan.tasks} == {"reconnaissance", "web-test"}:
            assignments = list(plan.tasks)
        elif self.store.evidence(self.run_id) or self.store.findings(self.run_id):
            self.emit(
                "agent",
                role="coordinator",
                status="refused",
                response={
                    "reason": "The planner did not return a task plan. The host continues from captured evidence."
                },
            )
            assignments = [
                Assignment(role="reconnaissance", task="Read the lab origin and report one observation."),
                Assignment(
                    role="web-test",
                    task="Use one path that appears in a captured response. File a candidate only with a verbatim quote.",
                ),
            ]
        else:
            raise RuntimeError("The coordinator must assign reconnaissance and web-test tasks.")
        for assignment in assignments:
            await self.assigned_task(assignment)
        await self.read_one_unread()
        for candidate in list(self.candidates.values()):
            try:
                verdict = None
                schema_note = ""
                wrong_shape = False
                json_retries = 0
                for _ in range(3):
                    payload = {
                        "candidate": candidate.model_dump(),
                        "evidence": clip_evidence(self.store.evidence(self.run_id)),
                    }
                    note = validator_host_note(schema_note, wrong_shape)
                    if note:
                        payload["host_note"] = note
                    try:
                        verdict = await self.ask("validator", payload)
                    except RuntimeError as exc:
                        if "invalid JSON" not in str(exc) or json_retries >= 1:
                            raise
                        json_retries += 1
                        schema_note = schema_note_from_refusal(str(exc))
                        continue
                    if (
                        isinstance(verdict, Finding)
                        and verdict.decision in {"confirmed", "rejected"}
                        and same_evidence_candidate(candidate, verdict.finding)
                    ):
                        break
                    if wrong_shape:
                        raise RuntimeError("The validator must confirm or reject the unchanged candidate.")
                    wrong_shape = True
                else:
                    raise RuntimeError("The validator must confirm or reject the unchanged candidate.")
                if verdict.decision == "confirmed":
                    self.check_finding(candidate)
                    data = {
                        "id": candidate.stable_id,
                        **candidate.model_dump(),
                        "validation_reason": verdict.reason,
                    }
                    self.store.save_finding(self.run_id, data, True)
                    self.emit("finding", **data)
            except RuntimeError as exc:
                if not self.store.findings(self.run_id):
                    raise
                self.emit("agent", role="validator", status="refused", response={"reason": str(exc)})
                break
        findings = self.store.findings(self.run_id)
        await self.write_plain(findings)
        findings = self.store.findings(self.run_id)
        report_error = ""
        try:
            report = await self.ask("report", {"findings": findings})
        except RuntimeError as exc:
            report = None
            report_error = str(exc)
        if not isinstance(report, Observation):
            self.emit(
                "agent",
                role="report",
                status="refused",
                response={
                    "reason": report_error
                    or "The host kept the stored findings. The report text was not usable."
                },
            )
        # Reports use stored, validated records. Free model prose is never a report finding.
        finish_error = ""
        try:
            final = await self.ask("coordinator", {"phase": "finish", "findings": findings})
        except RuntimeError as exc:
            final = None
            finish_error = str(exc)
        if not isinstance(final, Stop):
            try:
                final = await self.ask(
                    "coordinator",
                    {
                        "phase": "finish",
                        "findings": findings,
                        "host_note": "Return one stop object. Do not return a plan or an observation.",
                    },
                )
            except RuntimeError as exc:
                final = None
                finish_error = str(exc)
        if not isinstance(final, Stop):
            self.emit(
                "agent",
                role="coordinator",
                status="refused",
                response={"reason": finish_error or "The host closed the run after the report."},
            )

    async def write_plain(self, findings: list[dict]):
        """Ask the model for one short explanation per finding. Keep the stored long text."""
        explain = getattr(self.model, "explain", None)
        if not findings or explain is None or self.model_count > 60:
            return
        self.model_count += 1
        try:
            text = await self.guarded(explain(findings))
        except Exception:
            self.emit(
                "agent",
                role="report",
                status="refused",
                response={"reason": "The short explanations were not stored."},
            )
            return
        if not isinstance(text, str):
            return
        plains = parse_plain(text, findings)
        for finding in findings:
            sentence = plains.get(finding.get("id"))
            if not sentence:
                continue
            finding["plain"] = sentence
            self.store.save_finding(self.run_id, finding, True)

    async def run(self) -> int:
        self.deadline = time.monotonic() + self.config.limits.seconds
        final_state, error = State.COMPLETED, None
        self.emit("run_created", mock=self.config.mock, target=self.config.target)
        try:
            self.state(State.STARTING)
            self.model = self.model or (MockModel() if self.config.mock else OpenAIModel())
            await self.guarded(self.runner.start())
            self.state(State.RUNNING)
            await self.workflow()
        except (RunCancelled, asyncio.CancelledError, KeyboardInterrupt):
            final_state, error = State.CANCELLED, "The user cancelled the run."
        except Exception as exc:
            final_state, error = State.FAILED, str(exc) or type(exc).__name__
        finally:
            try:
                await self.runner.stop()
            except Exception as exc:
                final_state, error = State.FAILED, str(exc) or type(exc).__name__
            if self.store.run(self.run_id)["state"] == State.PAUSED and final_state == State.COMPLETED:
                final_state, error = State.CANCELLED, "The run stopped while paused."
            self.state(final_state, error)
        if final_state != State.COMPLETED:
            return 1
        return 2 if self.store.findings(self.run_id) else 0
