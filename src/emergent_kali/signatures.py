"""Host checks for public Juice Shop disclosures.

These rules match text already present in a captured GET response.
They do not build exploit requests.
"""

from __future__ import annotations

import os
import json
import re
from urllib.parse import urljoin, urlsplit

LAB_ORIGIN = "http://juice-shop:3000"
# A fresh run starts here. These names are documentation entry points, not prior findings.
START_PATHS = [
    "/",
    "/robots.txt",
    "/.well-known/security.txt",
    "/.env",
    "/openapi.json",
    "/swagger.json",
    "/ui/",
]
_MUTATION = {"delete", "drop", "reset", "destroy", "exec"}

# Small responses first so a tight output budget keeps them.
SURFACE_PATHS = [
    "/robots.txt",
    "/main.js",
    "/.well-known/security.txt",
    "/.well-known/csaf/provider-metadata.json",
    "/ftp/acquisitions.md",
    "/ftp/",
    "/encryptionkeys/",
    "/support/logs/",
    "/ftp/package.json.bak",
    "/ftp/coupons_2013.md.bak",
    "/rest/qwertz",
    "/api/Users",
    "/api/Feedbacks",
    "/api/SecurityQuestions",
    "/snippets",
    "/encryptionkeys/jwt.pub",
    "/rest/memories",
    "/metrics",
    "/rest/admin/application-configuration",
    "/api/Challenges",
]


def allowed_netlocs() -> set[str]:
    allowed = {"juice-shop:3000"}
    raw = os.environ.get("EMERG_LAB_URL", "").strip()
    parts = urlsplit(raw) if raw else None
    if parts and parts.scheme == "http" and parts.hostname and parts.port:
        allowed.add(f"{parts.hostname}:{parts.port}")
    return allowed


def lab_path(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.netloc not in allowed_netlocs() or parts.fragment:
        return ""
    path = parts.path or "/"
    if parts.query:
        return path + "?" + parts.query
    return path


def dynamic(path: str, body: str, url: str) -> list[dict]:
    """Findings that depend on the response shape, not one fixed sentence."""
    found = []
    if path == "/rest/memories":
        for index, char in enumerate(body):
            if ord(char) <= 127:
                continue
            quote = body[max(0, index - 24) : index + 1]
            if len(quote) < 8 or quote not in body:
                break
            found.append(
                {
                    "title": "Missing Encoding",
                    "severity": "low",
                    "category": "Improper Input Validation",
                    "location": url,
                    "quote": quote,
                    "reproduction": ["GET /rest/memories"],
                    "impact": "A public response includes a file name that is not encoded.",
                    "remediation": "Encode file names before you put them in a URL.",
                }
            )
            break
    if "/support/logs/access.log." in path:
        match = _LOG_GET.search(body)
        quote = match.group(0) if match else ""
        if quote and "password" not in quote.casefold() and quote in body:
            found.append(
                {
                    "title": "Access Log",
                    "severity": "medium",
                    "category": "Sensitive Data Exposure",
                    "location": url,
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can read the server access log.",
                    "remediation": "Require authentication before access logs.",
                }
            )
    marker = "<title>listing directory"
    start = body.find(marker)
    if start >= 0:
        end = body.find("</title>", start)
        quote = body[start : end + len("</title>")] if end > start else ""
        if 8 <= len(quote) <= 200 and quote in body:
            found.append(
                {
                    "title": "Public directory listing",
                    "severity": "low",
                    "category": "Information exposure",
                    "location": url,
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can read the names of files in this directory.",
                    "remediation": "Disable directory listings.",
                }
            )
    return found


def child_paths(record: dict) -> list[str]:
    """Return safe file paths named by a directory listing."""
    path = lab_path(str(record.get("url") or ""))
    body = record.get("body") or ""
    if not path.endswith("/") or "<title>listing directory" not in body or not isinstance(body, str):
        return []
    children = []
    for raw in _HREF.findall(body):
        name = raw[2:] if raw.startswith("./") else raw
        if not _NAME.fullmatch(name):
            continue
        if not (name.endswith((".md", ".pdf", ".txt")) or name.startswith("access.log.")):
            continue
        child = path + name
        if child not in children and child not in SURFACE_PATHS:
            children.append(child)
    return children


def safe_read_path(path: str) -> bool:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return False
    if len(path) > 80 or ".." in path or "{" in path or "?" in path or "\\" in path:
        return False
    if not re.fullmatch(r"/[A-Za-z0-9_./~-]*", path):
        return False
    segments = [segment.casefold() for segment in path.split("/") if segment]
    return not any(segment in _MUTATION or segment == "password" for segment in segments)


_QUOTED_PATH = re.compile(r'"(/[^"\\]{0,80})"\s*:')
_LINK = re.compile(r"""(?:href|src)=(?:"([^"]+)"|'([^']+)')""")
_FORM_ACTION = re.compile(
    r"""<form\b[^>]*\baction=(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.IGNORECASE,
)
_BASE_HREF = re.compile(
    r"""<base\b[^>]*\bhref=(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.IGNORECASE,
)
_NAMED_SEGMENT = re.compile(r'(?<![A-Za-z0-9_./:~-])(/[A-Za-z0-9_-]+)(?![A-Za-z0-9_./-])')
_EXACT_PATH_VALUE = re.compile(r':\s*"(/[^"\\]{0,80})"')
_QUOTED_ABSOLUTE = re.compile(r"""["'](/[A-Za-z0-9_./~-]{1,80})["']""")


_HEADER_LINK = re.compile(r"<([^>\s]+)>")


def header_paths(record: dict) -> list[str]:
    """Same-origin paths named by a Location or Link header."""
    url = str(record.get("url") or "")
    if not lab_path(url):
        return []
    raw_values = []
    location = _header(record, "location")
    if location:
        raw_values.append(location.split(";", 1)[0].strip())
    link = _header(record, "link")
    if link:
        raw_values.extend(_HEADER_LINK.findall(link))
    found = []
    for raw in raw_values:
        if not raw or raw.startswith(("#", "mailto:", "javascript:")):
            continue
        joined = urljoin(url, raw.split("#", 1)[0])
        parts = urlsplit(joined)
        if parts.scheme not in {"", "http"} or (parts.netloc and parts.netloc not in allowed_netlocs()):
            continue
        path = parts.path or "/"
        if safe_read_path(path) and path not in found:
            found.append(path)
        if len(found) >= 8:
            break
    return found


def absolute_url_paths(body: str) -> list[str]:
    """Paths named by absolute same-origin URLs in JSON strings."""
    if not isinstance(body, str):
        return []
    stripped = body.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    document = _api_document(body)
    found = []

    def visit(value, under_example: bool) -> None:
        if len(found) >= 8:
            return
        if isinstance(value, list):
            for item in value:
                visit(item, under_example)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                skip = under_example or (document and str(key).casefold() in {"example", "examples"})
                visit(item, skip)
            return
        if under_example or not isinstance(value, str) or not value.startswith("http://") or any(char.isspace() for char in value):
            return
        parts = urlsplit(value.split("#", 1)[0])
        if parts.scheme != "http" or parts.netloc not in allowed_netlocs():
            return
        path = parts.path or "/"
        if safe_read_path(path) and path not in found:
            found.append(path)

    visit(data, False)
    return found


def mentioned_paths(record: dict) -> list[str]:
    """Paths named by this response. Prose that merely contains a slash does not count."""
    body = record.get("body") or ""
    found: list[str] = []
    if isinstance(body, str) and '"paths"' in body and ("openapi" in body.casefold() or "swagger" in body.casefold()):
        for path in json_paths(body):
            if path not in found:
                found.append(path)
    for path in child_paths(record):
        if path not in found:
            found.append(path)
    for path in linked_paths(record):
        if path not in found:
            found.append(path)
    for path in form_paths(record):
        if path not in found:
            found.append(path)
    for path in header_paths(record):
        if path not in found:
            found.append(path)
    for path in absolute_url_paths(body):
        if path not in found:
            found.append(path)
    if isinstance(body, str) and not _api_document(body):
        for path in named_segment_paths(body):
            if path not in found:
                found.append(path)
        for path in exact_path_values(body):
            if path not in found:
                found.append(path)
        for path in quoted_script_paths(str(record.get("url") or ""), body):
            if path not in found:
                found.append(path)
    return found


def sibling_map_path(url: str) -> str:
    """The source map next to a script or stylesheet."""
    path = lab_path(url) if "://" in url else url
    if not isinstance(path, str):
        return ""
    lower = path.casefold()
    if not lower.endswith((".js", ".css")) or lower.endswith(".map"):
        return ""
    sibling = path + ".map"
    if not safe_read_path(sibling):
        return ""
    return sibling


def named_segment_paths(body: str) -> list[str]:
    """One-segment paths named as whole tokens in a JSON string. A slash inside a word does not count."""
    if not isinstance(body, str):
        return []
    stripped = body.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return []
    found = []
    for match in _NAMED_SEGMENT.finditer(body):
        path = match.group(1)
        if path in found or not safe_read_path(path):
            continue
        found.append(path)
        if len(found) >= 4:
            break
    return found


def exact_path_values(body: str) -> list[str]:
    """JSON string values that are exactly a safe path. A path inside a sentence does not count."""
    if not isinstance(body, str):
        return []
    stripped = body.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return []
    found = []
    for match in _EXACT_PATH_VALUE.finditer(body):
        path = match.group(1)
        if path in found or not safe_read_path(path):
            continue
        found.append(path)
        if len(found) >= 8:
            break
    return found


def _path_windows(body: str) -> list[tuple[str, str]]:
    """Return each documented path and the operation text that follows it."""
    import json

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        data = None
    paths = data.get("paths") if isinstance(data, dict) else None
    if isinstance(paths, dict):
        windows = []
        for key, value in paths.items():
            if isinstance(key, str):
                windows.append((key, json.dumps(value)))
        return windows
    start = body.find('"paths"')
    chunk = body[start:] if start >= 0 else ""
    matches = list(_QUOTED_PATH.finditer(chunk))
    windows = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(chunk)
        windows.append((match.group(1), chunk[match.end() : end]))
    return windows


def _has_get(window: str) -> bool:
    return re.search(r'"get"\s*:', window) is not None


def json_paths(body: str) -> list[str]:
    found = []
    for key, window in _path_windows(body):
        if _has_get(window) and safe_read_path(key) and key not in found:
            found.append(key)
    return found


def unread_paths(records: list[dict], spec: str, captured: set[str], origin: str) -> list[str]:
    """Paths named by these responses that this run has not requested."""
    named: list[str] = []
    for record in records:
        for path in mentioned_paths(record):
            if path not in named:
                named.append(path)
    for path in concrete_paths(spec, records):
        if path not in named:
            named.append(path)
    for record in records:
        sibling = sibling_map_path(str(record.get("url") or ""))
        if sibling and sibling not in named:
            named.append(sibling)
    return [path for path in named if origin + path not in captured]


def priority_paths(body: str) -> list[str]:
    """Documented GET operations that prepare stored data. Read them first."""
    found = []
    for key, window in _path_windows(body):
        text = window.casefold()
        if "database" in text and "populat" in text and safe_read_path(key) and key not in found:
            found.append(key)
    return found


_ONE_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_JSON_STRING = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"\\]{1,40})"')
_JSON_NUMBER = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*(\d{1,12})(?![\d.])')
_VALUE = re.compile(r"[A-Za-z0-9._-]{1,40}")


def _single_placeholder(path: str) -> str:
    """The name of the only placeholder in a documented path. Zero or two names do not count."""
    names = _placeholder_names(path)
    return names[0] if len(names) == 1 else ""


def _placeholder_names(path: str) -> list[str]:
    """Placeholder names in a documented path. A broken brace does not count."""
    if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_./{}~-]*", path):
        return []
    if path.count("{") != path.count("}"):
        return []
    names = _ONE_PLACEHOLDER.findall(path)
    if len(names) != path.count("{"):
        return []
    return names


def concrete_paths(spec: str, records: list[dict]) -> list[str]:
    """Fill one documented placeholder with a value copied from this run."""
    templates: list[tuple[str, str]] = []
    for key, window in _path_windows(spec):
        name = _single_placeholder(key)
        if name and _has_get(window):
            templates.append((key, name))
    values: dict[str, list[str]] = {}
    for record in records:
        body = record.get("body") or ""
        if not isinstance(body, str) or _api_document(body):
            continue
        for key, value in _JSON_STRING.findall(body):
            if key.casefold() in {"password", "passwd", "secret", "token"}:
                continue
            if not _VALUE.fullmatch(value):
                continue
            bucket = values.setdefault(key, [])
            if value not in bucket:
                bucket.append(value)
        for key, value in _JSON_NUMBER.findall(body):
            if key.casefold() in {"password", "passwd", "secret", "token"}:
                continue
            bucket = values.setdefault(key, [])
            if value not in bucket:
                bucket.append(value)
    found = []
    for template, name in templates:
        for value in values.get(name, [])[:16]:
            path = template.replace("{" + name + "}", value)
            if safe_read_path(path) and path not in found:
                found.append(path)
    for key, window in _path_windows(spec):
        names = _placeholder_names(key)
        if len(names) != 2 or names[0] == names[1] or not _has_get(window):
            continue
        left = values.get(names[0], [])
        right = values.get(names[1], [])
        if len(left) != 1 or len(right) != 1:
            continue
        path = key.replace("{" + names[0] + "}", left[0]).replace("{" + names[1] + "}", right[0])
        if safe_read_path(path) and path not in found:
            found.append(path)
    return found[:16]


def quoted_script_paths(url: str, body: str) -> list[str]:
    """Quoted strings in a script that are exactly a safe absolute path."""
    path = lab_path(url) if "://" in url else url
    if not isinstance(path, str) or not isinstance(body, str):
        return []
    lower = path.casefold().split("?", 1)[0]
    if not lower.endswith(".js") or lower.endswith(".map"):
        return []
    plain = []
    static = []
    for match in _QUOTED_ABSOLUTE.finditer(body):
        candidate = match.group(1)
        if not safe_read_path(candidate):
            continue
        bucket = static if candidate.casefold().endswith(_STATIC_SUFFIX) else plain
        if candidate not in bucket:
            bucket.append(candidate)
    return (plain + static)[:8]


def _get_operation(window: str) -> str:
    """Return the get operation object. A sibling method does not count."""
    match = re.search(r'"get"\s*:\s*\{', window)
    if not match:
        return ""
    start = match.end() - 1
    depth = 0
    for index, char in enumerate(window[start:], start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return window[start : index + 1]
    return ""


def _template_matches(template: str, path: str) -> bool:
    parts = []
    for segment in template.split("/"):
        if len(segment) > 2 and segment.startswith("{") and segment.endswith("}"):
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(segment))
    return re.fullmatch("/".join(parts), path) is not None


def secured_reads(spec: str, record: dict) -> list[dict]:
    """A documented protected GET returned a body to a request with no credentials."""
    if not spec or record.get("status") != 200 or (record.get("headers") or {}).get("X-Emerg-Actor"):
        return []
    url = str(record.get("url") or "")
    path = lab_path(url)
    body = record.get("body") or ""
    if not path or not isinstance(body, str) or _api_document(body):
        return []
    windows = [(key, window) for key, window in _path_windows(spec) if _has_get(window)]
    exact = [item for item in windows if item[0] == path]
    chosen = exact or [item for item in windows if "{" in item[0] and _template_matches(item[0], path)]
    protected = any(re.search(r'"security"\s*:', _get_operation(window)) for _, window in chosen)
    if not protected:
        return []
    quote = ""
    secret = _SECRET_FIELD.search(body)
    mail = _EMAIL.search(body)
    if secret and "[REDACTED]" not in secret.group(0):
        quote = secret.group(0)
    elif mail and len(mail.group(0)) >= 8:
        quote = mail.group(0)
    if not quote or quote not in body:
        return []
    return [
        {
            "title": "A protected record is public",
            "severity": "high",
            "category": "Broken Access Control",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "The document requires credentials, and the record is still public.",
            "remediation": "Require a valid credential before this record.",
        }
    ]


def _page_base(url: str, body: str) -> str:
    """The base href for relative links. An external base does not count."""
    if not isinstance(body, str) or _api_document(body):
        return url
    match = _BASE_HREF.search(body)
    if not match:
        return url
    raw = match.group(1) or match.group(2) or match.group(3) or ""
    if not raw or raw.startswith(("#", "mailto:", "javascript:")):
        return url
    joined = urljoin(url, raw.split("#", 1)[0])
    parts = urlsplit(joined)
    if parts.scheme not in {"", "http"} or (parts.netloc and parts.netloc not in allowed_netlocs()):
        return url
    return joined


def linked_paths(record: dict) -> list[str]:
    """Same-origin links named by this page."""
    url = str(record.get("url") or "")
    body = record.get("body") or ""
    if not lab_path(url) or not isinstance(body, str):
        return []
    base = _page_base(url, body)
    found = []
    for groups in _LINK.findall(body):
        raw = groups[0] or groups[1]
        if raw.startswith(("#", "mailto:", "javascript:")):
            continue
        joined = urljoin(base, raw.split("#", 1)[0])
        parts = urlsplit(joined)
        if parts.scheme not in {"", "http"} or (parts.netloc and parts.netloc not in allowed_netlocs()):
            continue
        path = parts.path or "/"
        if safe_read_path(path) and path not in found:
            found.append(path)
    return found


def form_paths(record: dict) -> list[str]:
    """Same-origin paths named by an HTML form action."""
    url = str(record.get("url") or "")
    body = record.get("body") or ""
    if not lab_path(url) or not isinstance(body, str) or _api_document(body):
        return []
    base = _page_base(url, body)
    found = []
    for groups in _FORM_ACTION.findall(body):
        raw = groups[0] or groups[1] or groups[2]
        if not raw or raw.startswith(("#", "mailto:", "javascript:")):
            continue
        joined = urljoin(base, raw.split("#", 1)[0])
        parts = urlsplit(joined)
        if parts.scheme not in {"", "http"} or (parts.netloc and parts.netloc not in allowed_netlocs()):
            continue
        path = parts.path or "/"
        if safe_read_path(path) and path not in found:
            found.append(path)
        if len(found) >= 8:
            break
    return found


def _exception_quote(body: str) -> str:
    for marker in ("OperationalError", "IntegrityError", "Traceback (most recent call last)", "Exception"):
        index = body.find(marker)
        if index < 0:
            continue
        title_at = body.rfind("<title>", 0, index)
        if title_at >= 0 and index - title_at < 400:
            end = body.find("</title>", index)
            if end > index:
                quote = body[title_at : end + len("</title>")]
                if quote in body and 8 <= len(quote) <= 200:
                    return quote
        quote = body[max(0, index - 20) : index + len(marker)]
        if quote in body and len(quote) >= 8:
            return quote[:200]
    return ""


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SECRET_FIELD = re.compile(
    r'"(?:password|passwd|secret|auth_token|access_token|api_key)"\s*:'
)
_EXTRA_SECRET = re.compile(r'"(?:private_key|refresh_token|client_secret|id_token)"\s*:')
_DOTENV_LINE = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z][A-Za-z0-9_]*)([ \t]*=)")
_DOTENV_SECRET = ("password", "passwd", "secret", "token", "apikey", "api_key", "credential")
_ADMIN_FLAG = re.compile(r'"admin"\s*:\s*(?:true|false)')
_ADMIN_ROLE = re.compile(r'"role"\s*:\s*"admin"')
_SERVER_VERSION = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,40}/\d+\.\d+")
_PRODUCT_VERSION = re.compile(r"[A-Za-z][A-Za-z0-9._-]{1,40}[/ ]v?\d+\.\d+\.\d+")
_ACCOUNT_KEY = re.compile(
    r'"(user|username|owner|account)"\s*:\s*"([A-Za-z][A-Za-z0-9._-]{2,40})"'
)
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
    ".map",
)
SERVER_BANNER = "Response header shows a server version"
PRODUCT_VERSION = "Public response shows a product version"
ACCOUNT_ECHO = "Public response names another account"
ONCE_PER_RUN = {SERVER_BANNER, PRODUCT_VERSION, ACCOUNT_ECHO}


def _api_document(body: str) -> bool:
    folded = body.casefold()
    if "openapi" not in folded and "swagger" not in folded:
        return False
    return '"paths"' in body or "\npaths:" in "\n" + body


def _login_difference(path: str, body: str, url: str) -> list[dict]:
    """The login error for a known account differs from the error for an unknown account."""
    redacted = body.find("[REDACTED]")
    if redacted >= 0:
        tail = re.match(r'\s*([^"\\]{8,80})', body[redacted + len("[REDACTED]") :])
        quote = tail.group(1).strip() if tail else ""
    else:
        match = re.search(r'"message"\s*:\s*"([^"]{8,160})"', body)
        quote = match.group(1) if match else ""
    if (
        len(quote) < 8
        or quote not in body
        or "password" in quote.casefold()
        or "incorrect" in quote.casefold()
        or "[REDACTED]" in quote
        or "[redacted]" in quote
    ):
        return []
    return [
        {
            "title": "Login errors identify a valid account",
            "severity": "medium",
            "category": "Identification and Authentication Failures",
            "location": url,
            "quote": quote,
            "reproduction": [f"POST {path}"],
            "impact": "The login error tells a caller whether the account exists.",
            "remediation": "Return the same error for an unknown account and a wrong password.",
        }
    ]


def _changed_password(path: str, body: str, url: str, record: dict) -> dict | None:
    """Another account changed this password. The quote is the success message."""
    headers = record.get("headers") or {}
    if not isinstance(headers, dict) or headers.get("X-Emerg-Write") != "1":
        return None
    match = re.search(r'"message"\s*:\s*"([^"]{8,160})"', body)
    if not match:
        return None
    quote = match.group(1)
    if "[REDACTED]" in quote or "[redacted]" in quote:
        parts = [part.strip() for part in re.split(r"\[REDACTED\]|\[redacted\]", quote)]
        quote = max(parts, key=len, default="")
    folded = quote.casefold()
    if (
        len(quote) < 8
        or quote not in body
        or "[REDACTED]" in quote
        or "[redacted]" in quote
        or any(word in folded for word in ("fail", "error", "denied", "invalid", "unauthorized"))
    ):
        return None
    target = headers.get("X-Emerg-Target")
    step = target if isinstance(target, str) and target.startswith("/") and "{" not in target else path
    return {
        "title": "Another account can change this password",
        "severity": "high",
        "category": "Broken Access Control",
        "location": url,
        "quote": quote,
        "reproduction": [f"PUT {step}"],
        "impact": "A credential for one account can change another account's password.",
        "remediation": "Allow a password change only for the account that owns it.",
    }


def _changed_email(path: str, body: str, url: str, record: dict) -> dict | None:
    """Another account changed this email. The quote is the new address."""
    headers = record.get("headers") or {}
    if not isinstance(headers, dict) or headers.get("X-Emerg-Mail") != "1":
        return None
    if "debug" in path.casefold():
        return None
    mail = _EMAIL.search(body)
    if not mail:
        return None
    quote = mail.group(0)
    if quote not in body or "[REDACTED]" in quote or len(quote) < 8:
        return None
    target = headers.get("X-Emerg-Target")
    step = target if isinstance(target, str) and target.startswith("/") and "{" not in target else path
    return {
        "title": "Another account can change this email",
        "severity": "high",
        "category": "Broken Access Control",
        "location": url,
        "quote": quote,
        "reproduction": [f"PUT {step}"],
        "impact": "A credential for one account can change another account's email.",
        "remediation": "Allow an email change only for the account that owns it.",
    }


def _deleted_account(path: str, body: str, url: str, record: dict) -> dict | None:
    """Another account deleted this account. The quote is the success message."""
    headers = record.get("headers") or {}
    status = record.get("status")
    if not isinstance(headers, dict) or headers.get("X-Emerg-Delete") != "1":
        return None
    if not isinstance(status, int) or status >= 300:
        return None
    match = re.search(r'"message"\s*:\s*"([^"]{8,160})"', body)
    if not match:
        return None
    quote = match.group(1)
    folded = quote.casefold()
    if (
        len(quote) < 8
        or quote not in body
        or "[REDACTED]" in quote
        or "[redacted]" in quote
        or "@" in quote
        or any(word in folded for word in ("fail", "error", "denied", "invalid", "unauthorized"))
    ):
        return None
    return {
        "title": "Another account can delete this account",
        "severity": "high",
        "category": "Broken Access Control",
        "location": url,
        "quote": quote,
        "reproduction": [f"DELETE {path}"],
        "impact": "A credential for one account can delete another account.",
        "remediation": "Allow an account delete only for the account that owns it.",
    }


def _opened_account(path: str, body: str, url: str, actor: str) -> dict | None:
    """A password from a public response returned this account."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", actor):
        return None
    for key in ("user", "username", "owner"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', body)
        if match and match.group(1) != actor:
            return None
    mail = _EMAIL.search(body)
    if not mail:
        return None
    quote = mail.group(0)
    if quote not in body or "[REDACTED]" in quote or len(quote) < 8:
        return None
    return {
        "title": "A public password can read this account",
        "severity": "high",
        "category": "Broken Access Control",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A password from a public response can read this account.",
        "remediation": "Remove passwords from public responses.",
    }


def _cross_user(path: str, body: str, url: str, actor: str) -> list[dict]:
    """A credential for one account returned another account's secret."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", actor):
        return []
    owner = ""
    for key in ("user", "username", "owner"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', body)
        if match and match.group(1) != actor:
            owner = match.group(1)
            break
    secret = _SECRET_FIELD.search(body)
    if not owner or not secret:
        return []
    quote = secret.group(0)
    if quote not in body or "[REDACTED]" in quote or "[redacted]" in quote or len(quote) < 8:
        return []
    return [
        {
            "title": "Another account can read this secret",
            "severity": "high",
            "category": "Broken Access Control",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "An account other than the owner can read this secret.",
            "remediation": "Return this record only to its owner.",
        }
    ]


def _page_markup(body: str) -> bool:
    text = body.lstrip().casefold()
    return text.startswith("<!doctype") or text.startswith("<html") or text.startswith("<!--")


def _dotenv_quote(body: str) -> str:
    """The key and equals sign from one dotenv assignment. The value stays out of the quote."""
    for match in _DOTENV_LINE.finditer(body):
        key = match.group(1)
        folded = key.casefold()
        if not any(part in folded for part in _DOTENV_SECRET):
            continue
        quote = key + match.group(2)
        if len(quote) < 8 or quote not in body or "[REDACTED]" in quote:
            continue
        return quote
    return ""


def _exposure(path: str, body: str, url: str) -> list[dict]:
    """Quotes copied from a normal response that shows a secret field or an email."""
    found = []
    secret = _SECRET_FIELD.search(body)
    if (
        not secret
        and not path.casefold().endswith(_STATIC_SUFFIX)
        and not _page_markup(body)
    ):
        secret = _EXTRA_SECRET.search(body)
    if secret:
        quote = secret.group(0)
        if quote in body and "[REDACTED]" not in quote and len(quote) >= 8:
            found.append(
                {
                    "title": "Public response includes a secret field",
                    "severity": "high",
                    "category": "Sensitive Data Exposure",
                    "location": url,
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can read a secret field in this response.",
                    "remediation": "Remove secret fields from public responses.",
                }
            )
    admin = None
    for candidate in _ADMIN_FLAG.finditer(body):
        admin = candidate
        if candidate.group(0).rstrip().endswith("true"):
            break
    if admin:
        quote = admin.group(0)
        if quote in body and len(quote) >= 8:
            found.append(
                {
                    "title": "Public response shows an admin flag",
                    "severity": "high",
                    "category": "Sensitive Data Exposure",
                    "location": url,
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can see which account is an administrator.",
                    "remediation": "Remove privilege flags from public responses.",
                }
            )
    role = _ADMIN_ROLE.search(body)
    if role and not admin:
        quote = role.group(0)
        if quote in body and len(quote) >= 8 and "[REDACTED]" not in quote:
            found.append(
                {
                    "title": "Public response shows an admin flag",
                    "severity": "high",
                    "category": "Sensitive Data Exposure",
                    "location": url,
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can see which account is an administrator.",
                    "remediation": "Remove privilege flags from public responses.",
                }
            )
    mail = _EMAIL.search(body)
    if mail:
        quote = mail.group(0)
        if quote in body and "[REDACTED]" not in quote and len(quote) >= 8:
            found.append(
                {
                    "title": "Public response lists an email address",
                    "severity": "medium",
                    "category": "Sensitive Data Exposure",
                    "location": url,
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can read an email address from this response.",
                    "remediation": "Require authentication before user details.",
                }
            )
    return found


def _header(record: dict, name: str) -> str:
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name and isinstance(value, str):
            return value
    return ""


def _download(path: str, record: dict, url: str) -> dict | None:
    """Quote a download header on a public data response. A static file does not count."""
    if path.casefold().split("?", 1)[0].endswith(_STATIC_SUFFIX):
        return None
    body = record.get("body") or ""
    if record.get("status") != 200 or (isinstance(body, str) and _api_document(body)):
        return None
    if _header(record, "x-emerg-actor"):
        return None
    value = _header(record, "content-disposition")
    folded = value.casefold()
    if "filename=" not in folded and not folded.startswith("attachment"):
        return None
    quote = value.split('"', 1)[0].strip() if '"' in value else value.strip()
    if "\n" in quote or "[REDACTED]" in quote or not 8 <= len(quote) <= 200 or quote not in value:
        return None
    return {
        "title": "Public response offers a file download",
        "severity": "low",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can download this file.",
        "remediation": "Require authentication before this download.",
    }


_DISALLOW = re.compile(r"(?m)^[ \t]*Disallow:[ \t]+/[A-Za-z0-9_./~-]{1,60}")
_CONTACT = re.compile(r"(?m)^[ \t]*Contact:[ \t]+\S{1,80}")


def _security_contact(path: str, body: str, url: str, status: object) -> dict | None:
    """Quote one Contact line from a public security.txt. A 404 body does not count."""
    if status != 200 or path != "/.well-known/security.txt":
        return None
    match = _CONTACT.search(body)
    if not match:
        return None
    quote = match.group(0).strip()
    if quote not in body or len(quote) < 8 or "[REDACTED]" in quote:
        return None
    return {
        "title": "Security Policy",
        "severity": "info",
        "category": "Miscellaneous",
        "location": url,
        "quote": quote,
        "reproduction": ["GET /.well-known/security.txt"],
        "impact": "The security contact is public. That is expected for this file.",
        "remediation": "Keep the contact current and do not add private data.",
    }


def _robots_disallow(path: str, body: str, url: str, status: object) -> dict | None:
    """Quote one Disallow line from a public robots file. A 404 body does not count."""
    if status != 200 or path != "/robots.txt":
        return None
    match = _DISALLOW.search(body)
    if not match:
        return None
    quote = match.group(0).strip()
    if quote not in body or len(quote) < 8 or "[REDACTED]" in quote:
        return None
    return {
        "title": "Robots file names a private path",
        "severity": "low",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": ["GET /robots.txt"],
        "impact": "The robots file shows a path that was meant to stay private.",
        "remediation": "Do not list private paths in robots.txt.",
    }


def _server_banner(path: str, record: dict, url: str) -> dict | None:
    """Quote a Server header when it includes a product version."""
    value = _header(record, "server")
    if (
        not value
        or "\n" in value
        or "[REDACTED]" in value
        or not 8 <= len(value) <= 200
        or not _SERVER_VERSION.search(value)
    ):
        return None
    return {
        "title": SERVER_BANNER,
        "severity": "low",
        "category": "Information exposure",
        "location": url,
        "quote": value,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read the server product and version.",
        "remediation": "Remove the version from the Server header.",
    }


def _product_version(path: str, body: str, url: str) -> dict | None:
    """Quote one product version from a public body that is not an API document."""
    if _api_document(body):
        return None
    match = _PRODUCT_VERSION.search(body)
    if not match:
        return None
    quote = match.group(0)
    if "[REDACTED]" in quote or not 8 <= len(quote) <= 80 or quote not in body:
        return None
    return {
        "title": PRODUCT_VERSION,
        "severity": "low",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read a product name and version.",
        "remediation": "Remove product versions from public responses.",
    }


def _data_record(record: dict) -> bool:
    """True for a public data body. Pages, API documents, and static files do not count."""
    url = record.get("url")
    body = record.get("body") or ""
    if record.get("status") != 200 or not isinstance(url, str) or not isinstance(body, str):
        return False
    if len(body) < 8 or url.split("?", 1)[0].casefold().endswith(_STATIC_SUFFIX):
        return False
    if _api_document(body):
        return False
    text = body.lstrip().casefold()
    return not (text.startswith("<!--") or text.startswith("<!doctype") or text.startswith("<html"))


def echoed_account(records: list[dict], covered: set[str]) -> dict | None:
    """Quote one account name that a different response already listed."""
    sources: dict[str, set[str]] = {}
    for record in records:
        if not _data_record(record):
            continue
        body = record["body"]
        names = {match.group(2) for match in _ACCOUNT_KEY.finditer(body)}
        if names and _EMAIL.search(body):
            sources.setdefault(record["url"], set()).update(names)
    known = {name for names in sources.values() for name in names}
    if not known:
        return None
    for record in records:
        if not _data_record(record):
            continue
        url = record["url"]
        if url in sources or url in covered:
            continue
        body = record["body"]
        for match in _ACCOUNT_KEY.finditer(body):
            name = match.group(2)
            if name not in known:
                continue
            quote = match.group(0)
            if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 80:
                continue
            path = lab_path(url)
            if not path:
                continue
            return {
                "title": ACCOUNT_ECHO,
                "severity": "low",
                "category": "Sensitive Data Exposure",
                "location": url,
                "quote": quote,
                "reproduction": [f"GET {path}"],
                "impact": "Anyone can read an account name in this response.",
                "remediation": "Remove account names from responses that do not need them.",
            }
    return None


def _auth_exception(path: str, body: str, url: str, status) -> dict | None:
    """Quote an UnauthorizedError token from a 401 or 403 body. Any path."""
    if status not in {401, 403}:
        return None
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if _api_document(body) or _page_markup(body):
        return None
    if not re.search(r"(?<![A-Za-z])UnauthorizedError(?![A-Za-z])", body):
        return None
    quote = "UnauthorizedError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Authentication errors expose exception names",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "An anonymous request receives an internal exception name.",
        "remediation": "Return a generic unauthorized response.",
    }


def _private_href(path: str, body: str, url: str, status) -> dict | None:
    """Quote one href or src that names a backup or database file. Any HTTP 200 path."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _PRIVATE_HREF.search(body)
    if not match:
        return None
    quote = match.group(0)
    if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 200:
        return None
    return {
        "title": "Public directory lists a private file",
        "severity": "medium",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "The public directory names a private file.",
        "remediation": "Remove private files from the public directory.",
    }


def _password_form(path: str, body: str, url: str, status) -> dict | None:
    """Quote one type=password attribute from an HTTP 200 body. Any path."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _PASSWORD_INPUT.search(body)
    if not match:
        return None
    quote = match.group(0)
    if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 200:
        return None
    return {
        "title": "Public page contains a password form",
        "severity": "low",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "The public page includes a password field.",
        "remediation": "Do not expose a password form on a public page.",
    }


def _confidential(path: str, body: str, url: str, status) -> dict | None:
    """Quote a confidential sentence from any HTTP 200 body."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "This document is confidential!"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Confidential Document",
        "severity": "high",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read a confidential document.",
        "remediation": "Remove the confidential document from the public site.",
    }


def _metrics(path: str, body: str, url: str, status) -> dict | None:
    """Quote one metrics help line from any HTTP 200 body."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _METRIC_HELP.search(body)
    if not match:
        return None
    quote = match.group(0).strip()
    if quote not in body or "[REDACTED]" in quote or not quote.startswith("# HELP "):
        return None
    if not 8 <= len(quote) <= 200:
        return None
    return {
        "title": "Exposed Metrics",
        "severity": "medium",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read application counters.",
        "remediation": "Require authentication before the metrics page.",
    }


def _blocked_file(path: str, body: str, url: str, status) -> dict | None:
    """Quote a blocked-file sentence from any HTTP 403 body."""
    if status != 403 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "Only .md and .pdf files are allowed!"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Blocked file name returns a detailed error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "The file server returns a detailed error for a blocked name.",
        "remediation": "Return a generic error and do not confirm private file names.",
    }


_PUBLIC_KEY_LINES = (
    "-----BEGIN RSA PUBLIC KEY-----",
    "-----BEGIN PUBLIC KEY-----",
)


def _public_key(path: str, body: str, url: str, status) -> dict | None:
    """Quote a public key header from any HTTP 200 body."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = next((line for line in _PUBLIC_KEY_LINES if line in body), "")
    if not quote or "[REDACTED]" in quote:
        return None
    return {
        "title": "JWT verification key is public",
        "severity": "medium",
        "category": "Cryptographic Issues",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can download the JWT verification key.",
        "remediation": "Do not publish signing material on a public path.",
    }


def _unexpected_path(path: str, body: str, url: str, status) -> dict | None:
    """Quote an unexpected-path error from any HTTP 500 body."""
    if status != 500 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "Error: Unexpected path"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Error Handling",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "An unknown path returns a detailed server error.",
        "remediation": "Return a generic error page for unknown paths.",
    }


def _any_origin(path: str, record: dict, url: str) -> dict | None:
    """Quote a wildcard CORS header. A static file or an API document does not count."""
    body = record.get("body") or ""
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if isinstance(body, str) and (_api_document(body) or _page_markup(body)):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != "access-control-allow-origin" or not isinstance(value, str):
            continue
        if value.strip() != "*":
            return None
        quote = json.dumps({str(key): value.strip()}, ensure_ascii=False)[1:-1]
        if quote not in json.dumps(record, ensure_ascii=False) or len(quote) < 8 or "[REDACTED]" in quote:
            return None
        return {
            "title": "Public response allows any origin",
            "severity": "low",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "Any site can read this response from a browser.",
            "remediation": "Allow only the origins that should call this service.",
        }
    return None


def _auth_scheme(path: str, record: dict, url: str) -> dict | None:
    """Quote a login challenge header. A static file, HTML page, or API document does not count."""
    body = record.get("body") or ""
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if isinstance(body, str) and (_api_document(body) or _page_markup(body)):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != "www-authenticate" or not isinstance(value, str):
            continue
        quote = value.strip()
        if "\n" in quote or "[REDACTED]" in quote or len(quote) < 8 or len(quote) > 200:
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Login challenge names an authentication scheme",
            "severity": "low",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "Anyone can read which login scheme this response expects.",
            "remediation": "Send this challenge only to clients that must sign in.",
        }
    return None


_INDEX_OF = re.compile(r"(?m)(?:^|>)[ \t]*(Index of /[^\r\n<]{0,80})")


def _directory_index(path: str, body: str, url: str, status) -> dict | None:
    """Quote a directory listing title. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _INDEX_OF.search(body)
    if not match:
        return None
    quote = match.group(1).strip()
    if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 90:
        return None
    return {
        "title": "Public directory lists files",
        "severity": "low",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read the file names in this directory.",
        "remediation": "Turn off directory listings.",
    }


def _php_info(path: str, body: str, url: str, status) -> dict | None:
    """Quote a PHP info page. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "phpinfo()"
    if quote not in body:
        return None
    return {
        "title": "Public response shows a PHP info page",
        "severity": "medium",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read the PHP settings on this page.",
        "remediation": "Remove the PHP info page from the public site.",
    }


_GIT_REF = re.compile(r"(?m)^[ \t]*(ref: refs/[^\r\n]{1,120})")


def _git_ref(path: str, body: str, url: str, status) -> dict | None:
    """Quote a git reference line. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _GIT_REF.search(body)
    if not match:
        return None
    quote = match.group(1).strip()
    if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 140:
        return None
    return {
        "title": "Public response exposes a git reference",
        "severity": "medium",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read a git branch name from this response.",
        "remediation": "Remove the git metadata from the public site.",
    }


def _framework_error(path: str, body: str, url: str) -> dict | None:
    """Quote a default framework error page. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "Whitelabel Error Page"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a framework error page",
        "severity": "low",
        "category": "Information exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can see that this site uses a default framework error page.",
        "remediation": "Replace the default error page with a short generic page.",
    }


_PRIVATE_KEY_LINES = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
)


def _private_key(path: str, body: str, url: str) -> dict | None:
    """Quote a private-key header. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = next((line for line in _PRIVATE_KEY_LINES if line in body), "")
    if not quote or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response exposes a private key",
        "severity": "high",
        "category": "Cryptographic Issues",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read a private key from this response.",
        "remediation": "Remove the private key from the public site.",
    }


def _cookie_flag(path: str, record: dict, url: str) -> dict | None:
    """Quote a cookie that has no HttpOnly flag. A static file, HTML page, or API document does not count."""
    body = record.get("body") or ""
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if isinstance(body, str) and (_api_document(body) or _page_markup(body)):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != "set-cookie" or not isinstance(value, str):
            continue
        quote = value.strip()
        if "\n" in quote or "[REDACTED]" in quote or not 8 <= len(quote) <= 200:
            return None
        if "httponly" in quote.casefold():
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Public response sets a cookie without HttpOnly",
            "severity": "medium",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "A browser script can read this cookie.",
            "remediation": "Set the HttpOnly flag on this cookie.",
        }
    return None


_DEBUG_TRUE = re.compile(r"(?m)^[ \t]*(DEBUG[ \t]*=[ \t]*True)\b")


def _debug_flag(path: str, body: str, url: str) -> dict | None:
    """Quote a true debug assignment. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _DEBUG_TRUE.search(body)
    if not match:
        return None
    quote = match.group(1).strip()
    if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 40:
        return None
    return {
        "title": "Public response shows a debug flag",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can see that debug mode is on.",
        "remediation": "Turn debug mode off on the public site.",
    }


def _inline_script(path: str, record: dict, url: str) -> dict | None:
    """Quote an inline-script policy token. A static file or an API document does not count."""
    body = record.get("body") or ""
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if isinstance(body, str) and _api_document(body):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    quote = "unsafe-inline"
    for key, value in headers.items():
        if str(key).lower() != "content-security-policy" or not isinstance(value, str):
            continue
        if quote not in value or "[REDACTED]" in value:
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Public response allows inline scripts",
            "severity": "medium",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "A browser can run a script that this page did not expect.",
            "remediation": "Remove unsafe-inline from the content security policy.",
        }
    return None


def _dynamic_code(path: str, record: dict, url: str) -> dict | None:
    """Quote a dynamic-code policy token. A static file or an API document does not count."""
    body = record.get("body") or ""
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if isinstance(body, str) and _api_document(body):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    quote = "unsafe-eval"
    for key, value in headers.items():
        if str(key).lower() != "content-security-policy" or not isinstance(value, str):
            continue
        if quote not in value or "[REDACTED]" in value:
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Public response allows dynamic code",
            "severity": "medium",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "A browser can run code that this page builds as text.",
            "remediation": "Remove unsafe-eval from the content security policy.",
        }
    return None


_ENCODED_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,77})")


def _encoded_token(path: str, body: str, url: str, status) -> dict | None:
    """Quote an encoded token from a public data response. A page, static file, or API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body) or _page_markup(body):
        return None
    match = _ENCODED_TOKEN.search(body)
    if not match:
        return None
    quote = match.group(1)
    if quote not in body or "[REDACTED]" in quote or not 11 <= len(quote) <= 80:
        return None
    return {
        "title": "Public response includes an encoded token",
        "severity": "high",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "Anyone can read an encoded token from this response.",
        "remediation": "Remove encoded tokens from public responses.",
    }


def _framing(path: str, record: dict, url: str) -> dict | None:
    """Quote a framing header that does not deny frames. A static file or an API document does not count."""
    body = record.get("body") or ""
    if path.casefold().endswith(_STATIC_SUFFIX):
        return None
    if isinstance(body, str) and _api_document(body):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != "x-frame-options" or not isinstance(value, str):
            continue
        quote = value.strip()
        folded = quote.casefold()
        if folded in {"deny", "sameorigin"}:
            return None
        if "\n" in quote or "[REDACTED]" in quote or not 8 <= len(quote) <= 200:
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Public response allows framing",
            "severity": "low",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "Another site can frame this response.",
            "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
        }
    return None


def _json_labeled_html(path: str, record: dict, url: str) -> dict | None:
    """Quote a content type that calls a JSON body HTML. A static file or an API document does not count."""
    body = record.get("body") or ""
    if not isinstance(body, str) or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    stripped = body.lstrip()
    if not stripped.startswith("{") or stripped.startswith("<"):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != "content-type" or not isinstance(value, str):
            continue
        if "text/html" not in value.casefold():
            return None
        quote = value.strip()
        if "\n" in quote or "[REDACTED]" in quote or len(quote) < 8 or len(quote) > 200:
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Public response labels JSON as HTML",
            "severity": "low",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "A browser may treat this JSON as a page.",
            "remediation": "Send JSON with a JSON content type.",
        }
    return None


def _html_labeled_json(path: str, record: dict, url: str) -> dict | None:
    """Quote a content type that calls an HTML body JSON. A static file or an API document does not count."""
    body = record.get("body") or ""
    if not isinstance(body, str) or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    stripped = body.lstrip()
    if not stripped.startswith("<") or stripped.startswith("{"):
        return None
    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).lower() != "content-type" or not isinstance(value, str):
            continue
        if "application/json" not in value.casefold():
            return None
        quote = value.strip()
        if "\n" in quote or "[REDACTED]" in quote or len(quote) < 8 or len(quote) > 200:
            return None
        if quote not in json.dumps(record, ensure_ascii=False):
            return None
        return {
            "title": "Public response labels HTML as JSON",
            "severity": "low",
            "category": "Security Misconfiguration",
            "location": url,
            "quote": quote,
            "reproduction": [f"GET {path}"],
            "impact": "A client may treat this page as data.",
            "remediation": "Send HTML with an HTML content type.",
        }
    return None


_META_REFRESH = re.compile(r"""http-equiv\s*=\s*(?:"refresh"|'refresh')""", re.IGNORECASE)


def _meta_refresh(path: str, body: str, url: str, status) -> dict | None:
    """Quote a refresh attribute. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    match = _META_REFRESH.search(body)
    if not match:
        return None
    quote = match.group(0)
    if quote not in body or "[REDACTED]" in quote or not 8 <= len(quote) <= 40:
        return None
    return {
        "title": "Public page refreshes to another address",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A browser can leave this page for another address.",
        "remediation": "Remove the refresh attribute from the public page.",
    }


def _cookie_read(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that reads a cookie. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "document.cookie"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page reads a cookie from script",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can read a cookie.",
        "remediation": "Stop public pages from reading cookies in script.",
    }


def _markup_write(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that writes markup. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "innerHTML"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page writes markup from script",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can write markup into the page.",
        "remediation": "Stop public pages from writing markup in script.",
    }


def _document_write(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that writes the document. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "document.write"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page writes the document from script",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can write into the document.",
        "remediation": "Stop public pages from writing the document in script.",
    }


def _local_storage(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that reads local storage. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "localStorage"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page reads local storage",
        "severity": "low",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can read data stored in the browser.",
        "remediation": "Do not keep sensitive data in local storage.",
    }


def _session_storage(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that reads session storage. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "sessionStorage"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page reads session storage",
        "severity": "low",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can read data stored for this browser session.",
        "remediation": "Do not keep sensitive data in session storage.",
    }


def _browser_database(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that reads a browser database. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "indexedDB"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page reads a browser database",
        "severity": "low",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can read data stored in the browser database.",
        "remediation": "Do not keep sensitive data in the browser database.",
    }


def _browser_message(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that sends a browser message. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "postMessage"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page sends a browser message",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can send data to another browsing context.",
        "remediation": "Check the target before a page sends a browser message.",
    }


def _page_socket(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that opens a socket. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "WebSocket"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page opens a socket",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can open a network socket from the browser.",
        "remediation": "Limit the addresses a public page can open.",
    }


def _document_domain(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that sets the document domain. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "document.domain"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page sets the document domain",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can relax the browser origin check.",
        "remediation": "Do not set the document domain on a public page.",
    }


def _window_open(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that opens another window. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "window.open"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page opens another window",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can open another browser window.",
        "remediation": "Do not open another window from a public page.",
    }


def _browser_request(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that sends a browser request. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "XMLHttpRequest"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page sends a browser request",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can send a request from the browser.",
        "remediation": "Limit the requests a public page can send.",
    }


def _browser_address(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that sends the browser to another address. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "location.href"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page sends the browser to another address",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can send the browser to another address.",
        "remediation": "Do not send the browser to another address from a public page.",
    }


def _outer_markup(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that writes outer markup. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "outerHTML"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page writes outer markup from script",
        "severity": "medium",
        "category": "Cross-Site Scripting",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can replace an element with markup.",
        "remediation": "Do not write outer markup from a public page script.",
    }


def _worker_script(path: str, body: str, url: str, status) -> dict | None:
    """Quote a script that loads a worker script. A static file or an API document does not count."""
    if status != 200 or path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "importScripts"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public page loads a worker script",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "A script on this page can load another script into a worker.",
        "remediation": "Do not load a worker script from a public page.",
    }


_DATABASE_SCHEMES = (
    "r2dbc:postgresql://",
    "jdbc:postgresql://",
    "elasticsearch://",
    "r2dbc:mariadb://",
    "foundationdb://",
    "r2dbc:mysql://",
    "mongodb+srv://",
    "clickhouse://",
    "jdbc:mysql://",
    "opensearch://",
    "postgresql://",
    "memcached://",
    "cassandra://",
    "cockroach://",
    "timescale://",
    "jdbc:sqlserver://",
    "sqlserver://",
    "firestore://",
    "snowflake://",
    "arangodb://",
    "rethinkdb://",
    "tarantool://",
    "couchbase://",
    "influxdb://",
    "dynamodb://",
    "cosmosdb://",
    "orientdb://",
    "yugabyte://",
    "scylladb://",
    "bigtable://",
    "informix://",
    "postgres://",
    "mongodb://",
    "couchdb://",
    "jdbc:mariadb://",
    "mariadb://",
    "faunadb://",
    "spanner://",
    "sqlite://",
    "jdbc:oracle://",
    "oracle://",
    "rediss://",
    "voltdb://",
    "ignite://",
    "sybase://",
    "exasol://",
    "hbase://",
    "crate://",
    "vertica://",
    "teradata://",
    "monetdb://",
    "questdb://",
    "jdbc:hsqldb://",
    "hsqldb://",
    "duckdb://",
    "presto://",
    "greenplum://",
    "redshift://",
    "impala://",
    "vitess://",
    "jdbc:trino://",
    "trino://",
    "jdbc:aerospike://",
    "aerospike://",
    "jdbc:derby://",
    "derby://",
    "jdbc:hazelcast://",
    "hazelcast://",
    "jdbc:druid://",
    "druid://",
    "jdbc:maxdb://",
    "maxdb://",
    "jdbc:pinot://",
    "pinot://",
    "jdbc:geode://",
    "geode://",
    "jdbc:marklogic://",
    "marklogic://",
    "jdbc:surrealdb://",
    "surrealdb://",
    "jdbc:edgedb://",
    "edgedb://",
    "jdbc:documentdb://",
    "documentdb://",
    "jdbc:gridgain://",
    "gridgain://",
    "jdbc:ravendb://",
    "ravendb://",
    "jdbc:firebird://",
    "firebird://",
    "jdbc:interbase://",
    "interbase://",
    "jdbc:memsql://",
    "memsql://",
    "jdbc:singlestore://",
    "singlestore://",
    "jdbc:percona://",
    "percona://",
    "jdbc:citus://",
    "citus://",
    "jdbc:nuodb://",
    "nuodb://",
    "jdbc:spark://",
    "spark://",
    "jdbc:neo4j://",
    "neo4j://",
    "jdbc:mssql://",
    "mssql://",
    "mysql://",
    "jdbc:redis://",
    "redis://",
)


def _database_address(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a database scheme. An API document does not count. The rest of the address stays out."""
    if _api_document(body):
        return None
    quote = next((scheme for scheme in _DATABASE_SCHEMES if scheme in body), "")
    if not quote or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response includes a database address",
        "severity": "high",
        "category": "Sensitive Data Exposure",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response includes a database address.",
        "remediation": "Remove database addresses from public responses.",
    }


def _stack_trace(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a stack trace. An API document does not count."""
    if _api_document(body):
        return None
    quote = "Traceback"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a stack trace",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal stack trace.",
        "remediation": "Hide stack traces from public responses.",
    }


def _syntax_error(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a syntax error. An API document does not count."""
    if _api_document(body):
        return None
    quote = "SyntaxError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a syntax error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal syntax error.",
        "remediation": "Hide syntax errors from public responses.",
    }


def _certificate(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a certificate header. An API document does not count."""
    if _api_document(body):
        return None
    quote = "-----BEGIN CERTIFICATE-----"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response exposes a certificate",
        "severity": "low",
        "category": "Cryptographic Issues",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response exposes a certificate.",
        "remediation": "Remove certificates from public responses.",
    }


def _query_schema(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a query schema. An API document does not count."""
    if _api_document(body):
        return None
    quote = "__schema"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a query schema",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows the query schema.",
        "remediation": "Do not expose the query schema on a public response.",
    }


def _framework_debugger(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a framework debugger in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "Werkzeug"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a framework debugger",
        "severity": "high",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows a framework debugger.",
        "remediation": "Disable the framework debugger on public responses.",
    }


def _reference_error(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a reference error in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "ReferenceError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a reference error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal reference error.",
        "remediation": "Hide reference errors from public responses.",
    }


def _type_error(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a type error in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "TypeError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a type error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal type error.",
        "remediation": "Hide type errors from public responses.",
    }


def _range_error(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a range error in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "RangeError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a range error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal range error.",
        "remediation": "Hide range errors from public responses.",
    }


def _uri_error(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a URI error in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "URIError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a URI error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal URI error.",
        "remediation": "Hide URI errors from public responses.",
    }


def _eval_error(path: str, body: str, url: str, _status) -> dict | None:
    """Quote an eval error in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "EvalError"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows an eval error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows an internal eval error.",
        "remediation": "Hide eval errors from public responses.",
    }


def _server_error_page(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a server error page in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "Internal Server Error"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response shows a server error page",
        "severity": "low",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response shows a server error page.",
        "remediation": "Hide server error pages from public responses.",
    }


def _database_console(path: str, body: str, url: str, _status) -> dict | None:
    """Quote a database console name in the body. A static file or an API document does not count."""
    if path.casefold().endswith(_STATIC_SUFFIX) or _api_document(body):
        return None
    quote = "phpMyAdmin"
    if quote not in body or "[REDACTED]" in quote:
        return None
    return {
        "title": "Public response names a database console",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "location": url,
        "quote": quote,
        "reproduction": [f"GET {path}"],
        "impact": "This response names a database console.",
        "remediation": "Remove the database console from public responses.",
    }


def detect(record: dict) -> list[dict]:
    """Return finding drafts whose quote is copied from this record."""
    path = lab_path(str(record.get("url") or ""))
    body = record.get("body") or ""
    status = record.get("status")
    if not path or not isinstance(body, str) or not isinstance(record.get("url"), str):
        return []
    found = dynamic(path, body, record["url"])
    for rule in RULES:
        if path not in rule["paths"]:
            continue
        if rule.get("status") is not None and status != rule["status"]:
            continue
        needle = rule["needle"]
        if needle not in body:
            continue
        found.append(
            {
                "title": rule["title"],
                "severity": rule["severity"],
                "category": rule["category"],
                "location": record["url"],
                "quote": needle,
                "reproduction": [f"GET {path}"],
                "impact": rule["impact"],
                "remediation": rule["remediation"],
            }
        )
    robots = _robots_disallow(path, body, record["url"], status)
    if robots and not any(item["title"] == robots["title"] for item in found):
        found.append(robots)
    contact = _security_contact(path, body, record["url"], status)
    if contact and not any(item["title"] == contact["title"] for item in found):
        found.append(contact)
    actor = str((record.get("headers") or {}).get("X-Emerg-Actor") or "")
    library = path.casefold().endswith(".map")
    if status == 200 and not library and not _api_document(body) and not actor and not _page_markup(body):
        quote = _dotenv_quote(body)
        if quote:
            found.append(
                {
                    "title": "Public response includes a secret field",
                    "severity": "high",
                    "category": "Sensitive Data Exposure",
                    "location": record["url"],
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "Anyone can read a secret field in this response.",
                    "remediation": "Remove secret fields from public responses.",
                }
            )
    if status == 200 and not library and not _api_document(body) and not actor:
        found.extend(_exposure(path, body, record["url"]))
    if status == 200 and actor:
        found.extend(_cross_user(path, body, record["url"], actor))
        opened = _opened_account(path, body, record["url"], actor)
        if opened and not any(item["title"] == opened["title"] for item in found):
            found.append(opened)
    changed = _changed_password(path, body, record["url"], record)
    if changed and not any(item["title"] == changed["title"] for item in found):
        found.append(changed)
    mailed = _changed_email(path, body, record["url"], record)
    if mailed and not any(item["title"] == mailed["title"] for item in found):
        found.append(mailed)
    removed = _deleted_account(path, body, record["url"], record)
    if removed and not any(item["title"] == removed["title"] for item in found):
        found.append(removed)
    if (record.get("headers") or {}).get("X-Emerg-Enum") == "1":
        found.extend(_login_difference(path, body, record["url"]))
    auth = _auth_exception(path, body, record["url"], status)
    if auth and not any(item["title"] == auth["title"] for item in found):
        found.append(auth)
    listed = _private_href(path, body, record["url"], status)
    if listed:
        found.append(listed)
    form = _password_form(path, body, record["url"], status)
    if form:
        found.append(form)
    secret = _confidential(path, body, record["url"], status)
    if secret and not any(item["title"] == secret["title"] for item in found):
        found.append(secret)
    metrics = _metrics(path, body, record["url"], status)
    if metrics and not any(item["title"] == metrics["title"] for item in found):
        found.append(metrics)
    blocked = _blocked_file(path, body, record["url"], status)
    if blocked and not any(item.get("quote") == blocked["quote"] for item in found):
        found.append(blocked)
    key = _public_key(path, body, record["url"], status)
    if key and not any(item["title"] == key["title"] for item in found):
        found.append(key)
    unexpected = _unexpected_path(path, body, record["url"], status)
    if unexpected and not any(item["title"] == unexpected["title"] for item in found):
        found.append(unexpected)
    origin = _any_origin(path, record, record["url"])
    if origin and not any(item["title"] == origin["title"] for item in found):
        found.append(origin)
    scheme = _auth_scheme(path, record, record["url"])
    if scheme and not any(item["title"] == scheme["title"] for item in found):
        found.append(scheme)
    listing = _directory_index(path, body, record["url"], status)
    if listing and not any(item["title"] == listing["title"] for item in found):
        found.append(listing)
    phpinfo = _php_info(path, body, record["url"], status)
    if phpinfo and not any(item["title"] == phpinfo["title"] for item in found):
        found.append(phpinfo)
    git_ref = _git_ref(path, body, record["url"], status)
    if git_ref and not any(item["title"] == git_ref["title"] for item in found):
        found.append(git_ref)
    framework = _framework_error(path, body, record["url"])
    if framework and not any(item["title"] == framework["title"] for item in found):
        found.append(framework)
    private = _private_key(path, body, record["url"])
    if private and not any(item["title"] == private["title"] or item.get("quote") == private["quote"] for item in found):
        found.append(private)
    cookie = _cookie_flag(path, record, record["url"])
    if cookie and not any(item["title"] == cookie["title"] for item in found):
        found.append(cookie)
    debug = _debug_flag(path, body, record["url"])
    if debug and not any(item["title"] == debug["title"] for item in found):
        found.append(debug)
    inline = _inline_script(path, record, record["url"])
    if inline and not any(item["title"] == inline["title"] for item in found):
        found.append(inline)
    dynamic_code = _dynamic_code(path, record, record["url"])
    if dynamic_code and not any(item["title"] == dynamic_code["title"] for item in found):
        found.append(dynamic_code)
    encoded = _encoded_token(path, body, record["url"], status)
    if encoded and not any(item["title"] == encoded["title"] for item in found):
        found.append(encoded)
    framing = _framing(path, record, record["url"])
    if framing and not any(item["title"] == framing["title"] for item in found):
        found.append(framing)
    labeled = _json_labeled_html(path, record, record["url"])
    if labeled and not any(item["title"] == labeled["title"] for item in found):
        found.append(labeled)
    mislabeled = _html_labeled_json(path, record, record["url"])
    if mislabeled and not any(item["title"] == mislabeled["title"] for item in found):
        found.append(mislabeled)
    refresh = _meta_refresh(path, body, record["url"], status)
    if refresh and not any(item["title"] == refresh["title"] for item in found):
        found.append(refresh)
    cookie_read = _cookie_read(path, body, record["url"], status)
    if cookie_read and not any(item["title"] == cookie_read["title"] for item in found):
        found.append(cookie_read)
    markup = _markup_write(path, body, record["url"], status)
    if markup and not any(item["title"] == markup["title"] for item in found):
        found.append(markup)
    written = _document_write(path, body, record["url"], status)
    if written and not any(item["title"] == written["title"] for item in found):
        found.append(written)
    stored = _local_storage(path, body, record["url"], status)
    if stored and not any(item["title"] == stored["title"] for item in found):
        found.append(stored)
    session = _session_storage(path, body, record["url"], status)
    if session and not any(item["title"] == session["title"] for item in found):
        found.append(session)
    browser_db = _browser_database(path, body, record["url"], status)
    if browser_db and not any(item["title"] == browser_db["title"] for item in found):
        found.append(browser_db)
    message = _browser_message(path, body, record["url"], status)
    if message and not any(item["title"] == message["title"] for item in found):
        found.append(message)
    opened = _page_socket(path, body, record["url"], status)
    if opened and not any(item["title"] == opened["title"] for item in found):
        found.append(opened)
    doc_domain = _document_domain(path, body, record["url"], status)
    if doc_domain and not any(item["title"] == doc_domain["title"] for item in found):
        found.append(doc_domain)
    popup = _window_open(path, body, record["url"], status)
    if popup and not any(item["title"] == popup["title"] for item in found):
        found.append(popup)
    browser_request = _browser_request(path, body, record["url"], status)
    if browser_request and not any(item["title"] == browser_request["title"] for item in found):
        found.append(browser_request)
    address = _browser_address(path, body, record["url"], status)
    if address and not any(item["title"] == address["title"] for item in found):
        found.append(address)
    outer = _outer_markup(path, body, record["url"], status)
    if outer and not any(item["title"] == outer["title"] for item in found):
        found.append(outer)
    worker = _worker_script(path, body, record["url"], status)
    if worker and not any(item["title"] == worker["title"] for item in found):
        found.append(worker)
    database = _database_address(path, body, record["url"], status)
    if database and not any(item["title"] == database["title"] for item in found):
        found.append(database)
    trace = _stack_trace(path, body, record["url"], status)
    if trace and not any(item["title"] == trace["title"] for item in found):
        found.append(trace)
    syntax = _syntax_error(path, body, record["url"], status)
    if syntax and not any(item["title"] == syntax["title"] for item in found):
        found.append(syntax)
    certificate = _certificate(path, body, record["url"], status)
    if certificate and not any(item["title"] == certificate["title"] for item in found):
        found.append(certificate)
    query_schema = _query_schema(path, body, record["url"], status)
    if query_schema and not any(item["title"] == query_schema["title"] for item in found):
        found.append(query_schema)
    framework = _framework_debugger(path, body, record["url"], status)
    if framework and not any(item["title"] == framework["title"] for item in found):
        found.append(framework)
    reference = _reference_error(path, body, record["url"], status)
    if reference and not any(item["title"] == reference["title"] for item in found):
        found.append(reference)
    type_error = _type_error(path, body, record["url"], status)
    if type_error and not any(item["title"] == type_error["title"] for item in found):
        found.append(type_error)
    range_error = _range_error(path, body, record["url"], status)
    if range_error and not any(item["title"] == range_error["title"] for item in found):
        found.append(range_error)
    uri_error = _uri_error(path, body, record["url"], status)
    if uri_error and not any(item["title"] == uri_error["title"] for item in found):
        found.append(uri_error)
    eval_error = _eval_error(path, body, record["url"], status)
    if eval_error and not any(item["title"] == eval_error["title"] for item in found):
        found.append(eval_error)
    server_page = _server_error_page(path, body, record["url"], status)
    if server_page and not any(item["title"] == server_page["title"] for item in found):
        found.append(server_page)
    console = _database_console(path, body, record["url"], status)
    if console and not any(item["title"] == console["title"] for item in found):
        found.append(console)
    if isinstance(status, int) and status >= 500:
        quote = _exception_quote(body)
        if quote:
            found.append(
                {
                    "title": "Server error exposes an internal exception",
                    "severity": "medium",
                    "category": "Information exposure",
                    "location": record["url"],
                    "quote": quote,
                    "reproduction": [f"GET {path}"],
                    "impact": "The error page shows an internal exception.",
                    "remediation": "Return a generic error page and keep the details in the server log.",
                }
            )
    banner = _server_banner(path, record, record["url"])
    if banner:
        found.append(banner)
    download = _download(path, record, record["url"])
    if download:
        found.append(download)
    product = _product_version(path, body, record["url"])
    if product:
        found.append(product)
    return found


_LOG_GET = re.compile(r'"GET /[A-Za-z0-9_./-]* HTTP/1\.[01]"')
_HREF = re.compile(r'href="([^"]+)"')
_PRIVATE_HREF = re.compile(
    r"""(?:href|src)=(?:"[^"]+\.(?:bak|kdbx|sql|old|zip)"|'[^']+\.(?:bak|kdbx|sql|old|zip)')""",
    re.IGNORECASE,
)
_PASSWORD_INPUT = re.compile(r"""type=(?:"password"|'password')""", re.IGNORECASE)
_METRIC_HELP = re.compile(r"(?m)^[ \t]*# HELP [^\r\n]{1,180}")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


RULES: list[dict] = [
    {
        "paths": {"/ftp/acquisitions.md"},
        "needle": "This document is confidential!",
        "title": "Confidential Document",
        "severity": "high",
        "category": "Sensitive Data Exposure",
        "impact": "Anyone can read the acquisition plan.",
        "remediation": "Remove the file from the public file server.",
    },
    {
        "paths": {"/metrics"},
        "needle": "# HELP file_uploads_count",
        "title": "Exposed Metrics",
        "severity": "medium",
        "category": "Sensitive Data Exposure",
        "impact": "Anyone can read application counters.",
        "remediation": "Require authentication before the metrics page.",
    },
    {
        "paths": {"/.well-known/security.txt"},
        "status": 200,
        "needle": "Contact: mailto:donotreply@owasp-juice.shop",
        "title": "Security Policy",
        "severity": "info",
        "category": "Miscellaneous",
        "impact": "The security contact is public. That is expected for this file.",
        "remediation": "Keep the contact current and do not add private data.",
    },
    {
        "paths": {"/robots.txt"},
        "status": 200,
        "needle": "Disallow: /ftp",
        "title": "Robots file names a private path",
        "severity": "low",
        "category": "Information exposure",
        "impact": "The robots file shows a path that was meant to stay private.",
        "remediation": "Do not list private paths in robots.txt.",
    },
    {
        "paths": {"/api/Challenges"},
        "needle": "finding the Score Board",
        "title": "Score Board",
        "severity": "low",
        "category": "Miscellaneous",
        "impact": "The public challenge API names the Score Board.",
        "remediation": "Do not publish hidden challenge names to anonymous clients.",
    },
    {
        "paths": {"/rest/admin/application-configuration"},
        "status": 200,
        "needle": '"application":{"domain":"juice-sh.op"',
        "title": "Administration configuration is public",
        "severity": "medium",
        "category": "Security Misconfiguration",
        "impact": "Anyone can read the application configuration.",
        "remediation": "Require an administrator session for this endpoint.",
    },
    {
        "paths": {"/api/Feedbacks"},
        "needle": "***in@juice-sh.op",
        "title": "Email Leak",
        "severity": "medium",
        "category": "Sensitive Data Exposure",
        "impact": "Public feedback contains a customer email address.",
        "remediation": "Remove email addresses from public feedback.",
    },
    {
        "paths": {"/api/SecurityQuestions"},
        "needle": '"question":"Your eldest siblings middle name?"',
        "title": "Security questions are public",
        "severity": "medium",
        "category": "Broken Authentication",
        "impact": "Anyone can read the security questions used for password reset.",
        "remediation": "Require a session before this list.",
    },
    {
        "paths": {"/rest/memories"},
        "needle": '"caption":',
        "title": "User memories are public",
        "severity": "low",
        "category": "Sensitive Data Exposure",
        "impact": "Anyone can read user photo captions.",
        "remediation": "Require a session before user memories.",
    },
    {
        "paths": {"/snippets"},
        "needle": '"directoryListingChallenge"',
        "title": "Challenge keys are listed in snippets",
        "severity": "low",
        "category": "Information exposure",
        "impact": "A public file lists internal challenge keys.",
        "remediation": "Remove challenge keys from public client files.",
    },
    {
        "paths": {"/encryptionkeys/jwt.pub"},
        "needle": "-----BEGIN RSA PUBLIC KEY-----",
        "title": "JWT verification key is public",
        "severity": "medium",
        "category": "Cryptographic Issues",
        "impact": "Anyone can download the JWT verification key.",
        "remediation": "Do not publish signing material on a public path.",
    },
    {
        "paths": {"/ftp/package.json.bak"},
        "status": 403,
        "needle": "Only .md and .pdf files are allowed!",
        "title": "Blocked file name returns a detailed error",
        "severity": "low",
        "category": "Security Misconfiguration",
        "impact": "The file server returns a detailed error for a blocked name.",
        "remediation": "Return a generic error and do not confirm private file names.",
    },
    {
        "paths": {"/rest/qwertz"},
        "status": 500,
        "needle": "Error: Unexpected path",
        "title": "Error Handling",
        "severity": "low",
        "category": "Security Misconfiguration",
        "impact": "An unknown path returns a detailed server error.",
        "remediation": "Return a generic error page for unknown paths.",
    },
    {
        "paths": {"/ftp/coupons_2013.md.bak"},
        "status": 403,
        "needle": "Only .md and .pdf files are allowed!",
        "title": "Forgotten Sales Backup",
        "severity": "low",
        "category": "Sensitive Data Exposure",
        "impact": "The file server confirms a blocked backup name.",
        "remediation": "Remove backup files and return a generic error.",
    },
    {
        "paths": {"/api/Users"},
        "status": 401,
        "needle": "UnauthorizedError: No Authorization header was found",
        "title": "Authentication errors expose exception names",
        "severity": "low",
        "category": "Security Misconfiguration",
        "impact": "An anonymous request receives an internal exception name.",
        "remediation": "Return a generic unauthorized response.",
    },
    {
        "paths": {"/ftp/", "/ftp"},
        "needle": 'href="incident-support.kdbx"',
        "title": "Password database file is listed",
        "severity": "medium",
        "category": "Sensitive Data Exposure",
        "impact": "The public file list names a database file.",
        "remediation": "Remove database files from the public file server.",
    },
    {
        "paths": {"/ftp/", "/ftp"},
        "needle": 'href="eastere.gg"',
        "title": "Easter Egg file name is listed",
        "severity": "low",
        "category": "Information exposure",
        "impact": "The public file list names eastere.gg.",
        "remediation": "Remove private file names from the public file server.",
    },
    {
        "paths": {"/.well-known/csaf/provider-metadata.json"},
        "needle": '"role": "csaf_trusted_provider"',
        "title": "Security Advisory",
        "severity": "info",
        "category": "Miscellaneous",
        "impact": "The public CSAF feed identifies this application.",
        "remediation": "Publish only advisories that are meant to be public.",
    },
    {
        "paths": {"/main.js"},
        "needle": 'F("score-board")',
        "title": "Score Board",
        "severity": "low",
        "category": "Miscellaneous",
        "impact": "The client script names the score board route.",
        "remediation": "Remove hidden route names from the public script.",
    },
    {
        "paths": {"/main.js"},
        "needle": 'F("privacy-security/privacy-policy")',
        "title": "Privacy Policy",
        "severity": "low",
        "category": "Miscellaneous",
        "impact": "The client script names the privacy policy route.",
        "remediation": "Link the privacy policy from a normal page.",
    },
    {
        "paths": {"/main.js"},
        "needle": "Maybe /administration will work?",
        "title": "Admin Section",
        "severity": "low",
        "category": "Broken Access Control",
        "impact": "The client script names the administration route.",
        "remediation": "Remove the administration route from the public script.",
    },
    {
        "paths": {"/api/Users"},
        "status": 201,
        "needle": '"status":"success"',
        "title": "Empty User Registration",
        "severity": "medium",
        "category": "Improper Input Validation",
        "impact": "The registration endpoint accepts an account when the password field is absent.",
        "remediation": "Reject registration when the password is missing.",
    },
    {
        "paths": {"/rest/captcha/", "/rest/captcha"},
        "needle": '"answer":',
        "title": "CAPTCHA Bypass",
        "severity": "medium",
        "category": "Broken Anti Automation",
        "impact": "The captcha response includes the answer.",
        "remediation": "Keep the captcha answer on the server.",
    },
    {
        "paths": {"/api/Feedbacks"},
        "status": 201,
        "needle": '"status":"success"',
        "title": "Zero Stars",
        "severity": "low",
        "category": "Improper Input Validation",
        "impact": "The feedback endpoint accepts a zero-star rating.",
        "remediation": "Reject a rating that is outside the allowed range.",
    },
]
