from __future__ import annotations

import json
import os

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
)

from .engine import Engine
from .models import LAB, RunConfig
from .redaction import redact
from .store import Store

ROLES = ("coordinator", "reconnaissance", "web-test", "validator", "report")


class EmergentApp(App):
    TITLE = "emerg | Local security lab"
    BINDINGS = [
        Binding("ctrl+c", "quit", "Cancel and quit", priority=True),
        Binding("ctrl+p", "pause_run", "Pause / resume", priority=True),
    ]
    CSS = """
    Screen { background: #101923; }
    TabPane { padding: 1 2; }
    Label { margin-top: 1; }
    Input, Select { margin-bottom: 1; }
    #setup-scroll { height: 1fr; }
    #controls { height: 3; margin-top: 1; }
    Button { margin-right: 1; }
    #agents { height: 7; }
    .agent { width: 1fr; padding: 1; border: round #337789; }
    #timeline { height: 9; }
    #output { height: 1fr; min-height: 5; border: solid #337789; }
    #status { height: 3; padding: 1; color: #8cdbc3; }
    #findings, #history { height: 10; }
    #finding-view { height: 3; }
    #view-label { width: 16; height: 3; content-align: left middle; }
    #simple-switch { height: 3; }
    #details { height: 1fr; border: solid #337789; }
    #setup-error { color: #ff9e91; height: auto; }
    """

    def __init__(self, store: Store | None = None, engine_factory=Engine):
        super().__init__()
        self.store = store or Store()
        self.owns_store = store is None
        self.engine_factory = engine_factory
        self.engine = None
        self.worker = None
        self.active = False
        self.selected_run = None
        self.selected_finding = None
        self.visible_findings = {}
        self.view_mode = {}
        self._switch_guard = False

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Run setup", id="setup"):
                with VerticalScroll(id="setup-scroll"):
                    yield Label("Target")
                    yield Input(LAB, id="target")
                    yield Label("Authorization statement (required)")
                    yield Input(placeholder="I am authorized to test this local lab.", id="authorization")
                    yield Label("Exact allowlist (required)")
                    yield Input(placeholder=LAB, id="allowlist")
                    yield Label("Instructions")
                    yield Input("Check the lab for exposed information.", id="instructions")
                    yield Label("Scan depth")
                    yield Select(
                        [("Quick", "quick"), ("Standard", "standard"), ("Deep", "deep")],
                        value="quick",
                        allow_blank=False,
                        id="depth",
                    )
                    yield Label("Model (set EMERG_MODEL before launch)")
                    yield Input(os.environ.get("EMERG_MODEL", "Not configured"), disabled=True, id="model")
                    yield Label("Offline mock run")
                    yield Switch(False, id="mock")
                    yield Static("", id="setup-error", markup=False)
                    yield Button("Start run", variant="success", id="start")
            with TabPane("Live run", id="live"):
                yield Static("No active run", id="status", markup=False)
                with Horizontal(id="agents"):
                    for role in ROLES:
                        yield Static(f"{role}\nIdle", id="agent-" + role, classes="agent", markup=False)
                yield DataTable(id="timeline")
                yield RichLog(id="output", max_lines=200, wrap=True, markup=False, highlight=False)
                with Horizontal(id="controls"):
                    yield Button("Pause / resume", id="pause", disabled=True)
                    yield Button("Cancel", variant="error", id="cancel", disabled=True)
            with TabPane("Findings", id="finding-tab"):
                yield DataTable(id="findings", cursor_type="row")
                with Horizontal(id="finding-view"):
                    yield Static("Simple", id="view-label", markup=False)
                    yield Switch(value=True, id="simple-switch", disabled=True)
                yield RichLog(id="details", wrap=True, markup=False, highlight=False, max_lines=500)
            with TabPane("History", id="history-tab"):
                yield DataTable(id="history", cursor_type="row")
                yield Button("Refresh history", id="refresh")
        yield Footer()

    def on_mount(self):
        self.query_one("#timeline", DataTable).add_columns("Role", "Task / event", "State")
        self.query_one("#findings", DataTable).add_columns("Severity", "Title", "Location")
        self.query_one("#history", DataTable).add_columns("Run ID", "State", "Created")
        self.refresh_history()

    def refresh_history(self):
        table = self.query_one("#history", DataTable)
        table.clear()
        for run in self.store.runs():
            table.add_row(run["id"], run["state"], run["created"], key=run["id"])

    def load_findings(self, run_id):
        self.selected_run = run_id
        table = self.query_one("#findings", DataTable)
        table.clear()
        self.visible_findings = {f["id"]: f for f in self.store.findings(run_id)}
        for finding in self.visible_findings.values():
            table.add_row(finding["severity"], finding["title"], finding["location"], key=finding["id"])
        self.selected_finding = None
        self._set_simple_switch(True, enabled=False)
        details = self.query_one("#details", RichLog)
        details.clear()
        details.write(
            f"Run {run_id}: {len(self.visible_findings)} validated findings. "
            "Select a finding. Use the switch to change the description."
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        key = str(event.row_key.value)
        if event.data_table.id == "history":
            self.load_findings(key)
            self.set_focus(None)
            self.query_one(TabbedContent).active = "finding-tab"
            self.call_after_refresh(self.query_one("#findings", DataTable).focus)
        elif event.data_table.id == "findings" and key in self.visible_findings:
            self.selected_finding = key
            simple = self.view_mode.get(key, True)
            self._set_simple_switch(simple, enabled=True)
            self.write_details(self.visible_findings[key], simple)

    def _set_simple_switch(self, simple: bool, enabled: bool):
        self._switch_guard = True
        switch = self.query_one("#simple-switch", Switch)
        switch.disabled = not enabled
        switch.value = simple
        self.query_one("#view-label", Static).update("Simple" if simple else "Detailed")
        self._switch_guard = False

    def write_details(self, finding: dict, simple: bool):
        details = self.query_one("#details", RichLog)
        details.clear()
        if simple:
            details.write(finding.get("plain") or "A short explanation is not ready.")
            return
        lines = [
            finding.get("title") or "",
            "Severity: " + str(finding.get("severity") or ""),
            "Location: " + str(finding.get("location") or ""),
            "",
            "Impact",
            finding.get("impact") or "",
            "",
            "Remediation",
            finding.get("remediation") or "",
            "",
            "Reproduction",
        ]
        lines.extend(str(step) for step in finding.get("reproduction") or [])
        lines.extend(["", "Evidence"])
        for cite in finding.get("evidence") or []:
            quote = cite.get("quote") if isinstance(cite, dict) else ""
            if quote:
                lines.append(str(quote))
        details.write("\n".join(lines))

    def on_switch_changed(self, event: Switch.Changed):
        if event.switch.id != "simple-switch" or self._switch_guard:
            return
        key = self.selected_finding
        if not key or key not in self.visible_findings:
            return
        self.view_mode[key] = event.value
        self.query_one("#view-label", Static).update("Simple" if event.value else "Detailed")
        self.write_details(self.visible_findings[key], event.value)

    def on_button_pressed(self, event: Button.Pressed):
        match event.button.id:
            case "start":
                self.start_run()
            case "pause":
                self.action_pause_run()
            case "cancel":
                if self.engine and self.active:
                    self.engine.cancel()
            case "refresh":
                self.refresh_history()

    def start_run(self):
        if self.active:
            return
        try:
            config = RunConfig(
                target=self.query_one("#target", Input).value,
                authorization=self.query_one("#authorization", Input).value,
                allowlist=[self.query_one("#allowlist", Input).value],
                instructions=self.query_one("#instructions", Input).value,
                depth=self.query_one("#depth", Select).value,
                mock=self.query_one("#mock", Switch).value,
            )
            self.engine = self.engine_factory(self.store, config, on_event=self.receive_event)
        except ValueError:
            self.query_one("#setup-error", Static).update(
                "Enter an authorization statement and the exact lab allowlist."
            )
            return
        self.query_one("#setup-error", Static).update("")
        self.query_one("#output", RichLog).clear()
        self.query_one("#timeline", DataTable).clear()
        for role in ROLES:
            self.query_one("#agent-" + role, Static).update(role + "\nIdle")
        self.active = True
        self.query_one("#start", Button).disabled = True
        self.query_one("#pause", Button).disabled = False
        self.query_one("#cancel", Button).disabled = False
        self.set_focus(None)
        self.query_one(TabbedContent).active = "live"
        self.call_after_refresh(self.query_one("#output", RichLog).focus)
        self.worker = self.run_worker(self.execute_run(), exclusive=True)

    async def execute_run(self):
        try:
            await self.engine.run()
        finally:
            self.active = False
            self.query_one("#start", Button).disabled = False
            self.query_one("#pause", Button).disabled = True
            self.query_one("#cancel", Button).disabled = True
            self.refresh_history()
            self.load_findings(self.engine.run_id)

    def receive_event(self, event):
        data = redact(event["data"])
        if event["kind"] == "state":
            self.query_one("#status", Static).update(
                f"Run {event['run_id']} | {data['state']} | {data.get('error') or ''}"
            )
        elif event["kind"] == "agent":
            text = f"{data['role']}\n{data['status']}"
            response = data.get("response")
            if data.get("status") == "refused" and isinstance(response, dict) and response.get("reason"):
                text += "\n" + str(response["reason"])
            self.query_one("#agent-" + data["role"], Static).update(text)
        elif event["kind"] == "task":
            table = self.query_one("#timeline", DataTable)
            if table.row_count >= 100:
                table.remove_row(next(iter(table.rows)))
            table.add_row(data["role"], data.get("description", data["task_id"][:8]), data["state"])
        elif event["kind"] in {"tool_result", "command_approved", "finding"}:
            self.query_one("#output", RichLog).write(json.dumps(data, indent=2))

    def action_pause_run(self):
        if self.engine and self.active:
            self.engine.resume() if self.engine.pause_requested else self.engine.pause()

    async def action_quit(self):
        if self.engine and self.active:
            self.engine.cancel()
            if self.worker:
                await self.worker.wait()
        self.exit()

    def on_unmount(self):
        if self.engine and self.active:
            self.engine.cancel()
        if self.owns_store and not self.active:
            self.store.close()
