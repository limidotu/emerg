from __future__ import annotations

import hashlib
import os
import re
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

LAB = "http://juice-shop:3000"


def lab_origin() -> str:
    """One internal lab service. A dotted host is rejected."""
    raw = os.environ.get("EMERG_LAB_URL", LAB).strip()
    parts = urlsplit(raw)
    host = parts.hostname or ""
    if (
        parts.scheme != "http"
        or not re.fullmatch(r"[a-z0-9-]{1,63}", host)
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
        or parts.port is None
    ):
        raise ValueError("EMERG_LAB_URL must be http://<service>:<port> for one lab service.")
    return f"http://{host}:{parts.port}"
Role = Literal["coordinator", "reconnaissance", "web-test", "validator", "report"]
ToolName = Literal[
    "http_probe",
    "port_scan",
    "crawl",
    "content_discovery",
    "template_scan",
    "sql_check",
    "form_check",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Limits(StrictModel):
    seconds: int = Field(default=3600, ge=10, le=3600)
    command_seconds: int = Field(default=30, ge=1, le=120)
    output_bytes: int = Field(default=65536, ge=1024, le=1048576)
    requests_per_second: int = Field(default=2, ge=1, le=10)
    commands: int = Field(default=20, ge=1, le=100)
    requests: int = Field(default=100, ge=1, le=1000)


class RunConfig(StrictModel):
    target: str = LAB
    authorization: str = Field(min_length=8, max_length=2000)
    allowlist: list[str] = Field(min_length=1, max_length=1)
    instructions: str = Field(default="Check the lab for exposed information.", max_length=4000)
    depth: Literal["quick", "standard", "deep"] = "quick"
    limits: Limits = Field(default_factory=Limits)
    mock: bool = False

    @field_validator("authorization")
    @classmethod
    def nonempty_authorization(cls, value: str) -> str:
        if len(value.strip()) < 8:
            raise ValueError("Supply an explicit authorization statement.")
        return value.strip()

    @field_validator("target")
    @classmethod
    def exact_target(cls, value: str) -> str:
        if value != lab_origin():
            raise ValueError(f"Only the included lab is permitted: {lab_origin()}")
        return value

    @field_validator("allowlist")
    @classmethod
    def exact_allowlist(cls, value: list[str]) -> list[str]:
        if value != [lab_origin()]:
            raise ValueError(
                f"The exact allowlist must be [{lab_origin()}]. Wildcards and external targets are disabled."
            )
        return value


class ToolArgs(StrictModel):
    url: str = Field(max_length=2048)
    ports: list[int] = Field(default_factory=lambda: [3000], min_length=1, max_length=1)
    max_pages: int = Field(default=5, ge=1, le=20)
    paths: list[str] = Field(default_factory=lambda: ["/robots.txt", "/ftp/"], max_length=20)


class Citation(StrictModel):
    evidence_id: str = Field(min_length=1, max_length=80)
    quote: str = Field(min_length=8, max_length=2000)


class HTTPRecord(StrictModel):
    url: str = Field(max_length=2048)
    status: int = Field(ge=100, le=599)
    headers: dict[str, str]
    body: str


class ToolResult(StrictModel):
    stdout: str
    stderr: str
    exit_code: int
    records: list[HTTPRecord] = Field(max_length=1000)
    truncated: bool
    timed_out: bool
    request_limit: bool


class FindingDraft(StrictModel):
    title: str = Field(min_length=3, max_length=200)
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: str = Field(min_length=3, max_length=100)
    location: str = Field(min_length=1, max_length=2048)
    evidence: list[Citation] = Field(min_length=1, max_length=10)
    reproduction: list[str] = Field(min_length=1, max_length=10)
    impact: str = Field(min_length=5, max_length=2000)
    remediation: str = Field(min_length=5, max_length=2000)

    @property
    def stable_id(self) -> str:
        parts = [
            " ".join(self.category.casefold().split()),
            " ".join(self.title.casefold().split()),
            self.location,
        ]
        return "EMERG-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    @field_validator("location")
    @classmethod
    def scoped_location(cls, value: str) -> str:
        from .runner_runtime import check_url

        check_url(value)
        return value

    @field_validator("title", "category", "impact", "remediation")
    @classmethod
    def strip_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Text must not be blank.")
        return value.strip()

    @field_validator("reproduction")
    @classmethod
    def reproduction_steps(cls, value: list[str]) -> list[str]:
        if any(not step.strip() or len(step) > 2000 for step in value):
            raise ValueError("Reproduction steps must contain text and stay within 2000 characters.")
        return [step.strip() for step in value]


class Assignment(StrictModel):
    role: Literal["reconnaissance", "web-test"]
    task: str = Field(min_length=3, max_length=1000)


class Plan(StrictModel):
    kind: Literal["plan"]
    tasks: list[Assignment] = Field(min_length=1, max_length=6)


class ToolCall(StrictModel):
    kind: Literal["tool_call"]
    tool: ToolName
    arguments: ToolArgs


class Observation(StrictModel):
    kind: Literal["observation"]
    summary: str = Field(min_length=1, max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class Finding(StrictModel):
    kind: Literal["finding"]
    decision: Literal["candidate", "confirmed", "rejected"]
    finding: FindingDraft
    reason: str = Field(min_length=3, max_length=2000)


class Stop(StrictModel):
    kind: Literal["stop"]
    reason: str = Field(min_length=3, max_length=2000)


Response = Annotated[Plan | ToolCall | Observation | Finding | Stop, Field(discriminator="kind")]
RESPONSE_ADAPTER = TypeAdapter(Response)


class State(StrEnum):
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TRANSITIONS = {
    State.CREATED: {State.STARTING, State.CANCELLED, State.FAILED},
    State.STARTING: {State.RUNNING, State.CANCELLED, State.FAILED},
    State.RUNNING: {State.PAUSED, State.COMPLETED, State.CANCELLED, State.FAILED},
    State.PAUSED: {State.RUNNING, State.CANCELLED, State.FAILED},
    State.COMPLETED: set(),
    State.CANCELLED: set(),
    State.FAILED: set(),
}


def origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"
