"""One redaction boundary for database rows, evidence, events, and reports."""

import os
import re
from typing import Any
from urllib.parse import quote

SECRET_KEY = re.compile(r"(?i)(authorization|cookie|password|passwd|secret|token|api[-_]?key|credential)")
_ASSIGN_KEY = re.compile(
    r"""(?ix)(["']?(?:[\w-]*(?:password|passwd|secret|token|api[-_]?key|credential)[\w-]*)["']?\s*[:=]\s*)"""
)
HEADER = re.compile(r"(?im)((?:authorization|proxy-authorization|set-cookie|cookie)\s*:\s*)[^\r\n]+")
PROSE_SECRET = re.compile(
    r"(?i)((?:password|passwd|api[-_ ]?key|access[-_ ]?token|secret)\s+is\s+)[^\s,;<>]+"
)
BEARER = re.compile(r"(?i)\bBearer\s+[^\s\"'<>,;]+")
KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|$))|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _json_value_end(text: str, start: int) -> int:
    """End index of one JSON value, a quoted string, or a bare token."""
    if start >= len(text):
        return start
    first = text[start]
    if first in "\"'":
        index = start + 1
        escape = False
        while index < len(text):
            char = text[index]
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == first:
                return index + 1
            index += 1
        return len(text)
    if first in "{[":
        stack = ["}" if first == "{" else "]"]
        index = start + 1
        inside = False
        escape = False
        while index < len(text) and stack:
            char = text[index]
            if inside:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    inside = False
            elif char == '"':
                inside = True
            elif char == "{":
                stack.append("}")
            elif char == "[":
                stack.append("]")
            elif char == stack[-1]:
                stack.pop()
            index += 1
        return index
    index = start
    while index < len(text) and text[index] not in " \t\r\n,;&<>}]":
        index += 1
    return index


def _redact_assignments(text: str) -> str:
    """Replace a secret assignment. A JSON value becomes a JSON string."""
    parts = []
    cursor = 0
    for match in _ASSIGN_KEY.finditer(text):
        if match.start() < cursor:
            continue
        end = _json_value_end(text, match.end())
        parts.append(text[cursor : match.start()])
        if end <= match.end():
            parts.append(match.group(1))
            cursor = match.end()
            continue
        value = text[match.end() : end]
        prefix = match.group(1)
        if value[:1] in "\"'[{" or '"' in prefix:
            parts.append(prefix + '"[REDACTED]"')
        else:
            parts.append(prefix + "[REDACTED]")
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


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
    value = _redact_assignments(value)
    value = PROSE_SECRET.sub(r"\1[REDACTED]", value)
    value = KEY.sub("[REDACTED]", value)
    value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    return ANSI.sub("", value)
