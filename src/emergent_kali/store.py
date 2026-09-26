from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_data_path

from .models import TRANSITIONS, RunConfig, State
from .redaction import redact


def data_dir() -> Path:
    return Path(os.environ.get("EMERG_DATA_DIR", user_data_path("emerg", appauthor=False)))


def now() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or data_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / "emerg.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), url TEXT);
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, target_id TEXT REFERENCES targets(id),
                state TEXT NOT NULL, created TEXT, config TEXT, error TEXT);
            CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id),
                role TEXT, description TEXT, state TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, run_id TEXT REFERENCES runs(id),
                created TEXT, kind TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id),
                path TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS findings(id TEXT, run_id TEXT REFERENCES runs(id), validated INTEGER,
                data TEXT, PRIMARY KEY(id, run_id));
            CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id),
                path TEXT, format TEXT);
        """)
        self.db.commit()

    def close(self):
        with self.lock:
            self.db.close()

    def execute(self, sql: str, params=()):
        with self.lock:
            cursor = self.db.execute(sql, params)
            rows = [dict(row) for row in cursor.fetchall()]
            self.db.commit()
            return rows

    def create_run(self, config: RunConfig) -> str:
        run_id = uuid.uuid4().hex
        self.execute("INSERT OR IGNORE INTO projects VALUES('lab','Juice Shop lab')")
        self.execute("INSERT OR IGNORE INTO targets VALUES('juice-shop','lab',?)", (config.target,))
        self.execute(
            "INSERT INTO runs VALUES(?, 'juice-shop', ?, ?, ?, NULL)",
            (run_id, State.CREATED, now(), json.dumps(redact(config.model_dump()))),
        )
        self.workspace(run_id).mkdir(parents=True)
        return run_id

    def workspace(self, run_id: str) -> Path:
        if not __import__("re").fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("Invalid run ID.")
        return self.root / "runs" / run_id

    def run(self, run_id: str) -> dict:
        rows = self.execute("SELECT * FROM runs WHERE id=?", (run_id,))
        if not rows:
            raise ValueError("Run not found.")
        row = rows[0]
        row["config"] = json.loads(row["config"])
        return row

    def runs(self) -> list[dict]:
        return self.execute("SELECT id,state,created FROM runs ORDER BY created DESC LIMIT 100")

    def transition(self, run_id: str, state: State, error: str | None = None):
        with self.lock:
            current = State(self.run(run_id)["state"])
            if state not in TRANSITIONS[current]:
                raise ValueError(f"Invalid run transition: {current} to {state}.")
            self.execute("UPDATE runs SET state=?,error=? WHERE id=?", (state, redact(error), run_id))

    def event(self, run_id: str, kind: str, data: dict) -> dict:
        event = {"run_id": run_id, "time": now(), "kind": kind, "data": redact(data)}
        self.execute(
            "INSERT INTO events(run_id,created,kind,data) VALUES(?,?,?,?)",
            (run_id, event["time"], kind, json.dumps(event["data"])),
        )
        with (self.workspace(run_id) / "audit.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        return event

    def save_evidence(self, run_id: str, data: dict) -> str:
        evidence_id = "ev-" + uuid.uuid4().hex
        data = redact(data)
        path = self.workspace(run_id) / f"{evidence_id}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.execute(
            "INSERT INTO evidence VALUES(?,?,?,?)", (evidence_id, run_id, str(path), json.dumps(data))
        )
        return evidence_id

    def evidence(self, run_id: str) -> dict:
        return {
            row["id"]: json.loads(row["data"])
            for row in self.execute("SELECT * FROM evidence WHERE run_id=?", (run_id,))
        }

    def save_finding(self, run_id: str, finding: dict, validated: bool):
        finding = redact(finding)
        self.execute(
            "INSERT INTO findings VALUES(?,?,?,?) ON CONFLICT(id,run_id) DO UPDATE SET "
            "validated=MAX(findings.validated,excluded.validated),data=excluded.data",
            (finding["id"], run_id, int(validated), json.dumps(finding)),
        )

    def findings(self, run_id: str, validated: bool = True) -> list[dict]:
        return [
            json.loads(row["data"])
            for row in self.execute(
                "SELECT data FROM findings WHERE run_id=? AND validated=? ORDER BY id",
                (run_id, int(validated)),
            )
        ]
