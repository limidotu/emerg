"""One redaction boundary for database rows, evidence, events, and reports."""

import os
import re
from typing import Any
from urllib.parse import quote

SECRET_KEY = re.compile(r"(?i)(authorization|cookie|password|passwd|secret|token|api[-_]?key|credential)")
ASSIGNMENT = re.compile(
    r"""(?ix)(["']?(?:[\w-]*(?:password|passwd|secret|token|api[-_]?key|credential)[\w-]*)["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&<>}\]]+)"""
)
HEADER = re.compile(r"(?im)((?:authorization|proxy-authorization|set-cookie|cookie)\s*:\s*)[^\r\n]+")
PROSE_SECRET = re.compile(
    r"(?i)((?:password|passwd|api[-_ ]?key|access[-_ ]?token|secret)\s+is\s+)[^\s,;<>]+"
)
BEARER = re.compile(r"(?i)\bBearer\s+[^\s\"'<>,;]+")
KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|$))|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if SECRET_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    for name, secret in os.environ.items():
        if SECRET_KEY.search(name) and len(secret) >= 4:
            value = value.replace(secret, "[REDACTED]")
            value = value.replace(quote(secret, safe=""), "[REDACTED]")
    value = HEADER.sub(r"\1[REDACTED]", value)
    value = BEARER.sub("Bearer [REDACTED]", value)
    value = ASSIGNMENT.sub(r"\1[REDACTED]", value)
    value = PROSE_SECRET.sub(r"\1[REDACTED]", value)
    value = KEY.sub("[REDACTED]", value)
    value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    return ANSI.sub("", value)
