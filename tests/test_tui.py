import asyncio

from textual.widgets import DataTable, Input, RichLog, Static, Switch, TabbedContent

from emergent_kali.docker import FakeRunner
from emergent_kali.engine import Engine
from emergent_kali.models import LAB, State
from emergent_kali.tui import EmergentApp


def _log_text(log: RichLog) -> str:
    parts = []
    for line in log.lines:
        for segment in line:
            parts.append(segment.text)
    return "".join(parts)


async def test_tui_mock_run_updates_agents_timeline_findings_history(store):
    app = EmergentApp(store)
    async with app.run_test(size=(120, 48)) as pilot:
        app.query_one("#authorization", Input).value = "I own and authorize this lab."
        app.query_one("#allowlist", Input).value = LAB
        app.query_one("#mock", Switch).value = True
        await pilot.click("#start")
        async with asyncio.timeout(8):
            while app.active:
                await pilot.pause(0.05)
        assert app.engine is not None
        assert store.run(app.engine.run_id)["state"] == "completed"
        assert app.query_one("#timeline", DataTable).row_count == 4
        assert app.query_one("#findings", DataTable).row_count == 1
        assert app.query_one("#history", DataTable).row_count == 1
        assert "completed" in str(app.query_one("#status", Static).render())
        app.query_one(TabbedContent).active = "history-tab"
        await pilot.pause()
        app.query_one("#history", DataTable).focus()
        await pilot.press("enter")
        assert app.query_one(TabbedContent).active == "finding-tab"


async def test_tui_refuses_empty_authorization(store):
    app = EmergentApp(store)
    async with app.run_test(size=(120, 48)) as pilot:
        await pilot.click("#start")
        assert app.engine is None
        assert "authorization" in str(app.query_one("#setup-error", Static).render())


async def test_tui_pause_and_cancel_remove_active_runner(store):
    class SlowRunner(FakeRunner):
        async def execute(self, *args):
            await asyncio.sleep(20)
            return await super().execute(*args)

    app = EmergentApp(
        store, engine_factory=lambda *args, **kwargs: Engine(*args, runner_factory=SlowRunner, **kwargs)
    )
    async with app.run_test(size=(120, 48)) as pilot:
        app.query_one("#authorization", Input).value = "I authorize this lab test."
        app.query_one("#allowlist", Input).value = LAB
        app.query_one("#mock", Switch).value = True
        await pilot.click("#start")
        async with asyncio.timeout(4):
            while not app.engine.command_count:
                await pilot.pause(0.02)
        assert app.query_one(TabbedContent).active == "live"
        await pilot.press("ctrl+p")
        async with asyncio.timeout(4):
            while not app.engine.runner.paused:
                await pilot.pause(0.02)
        assert "paused" in str(app.query_one("#status", Static).render())
        await pilot.click("#cancel")
        async with asyncio.timeout(4):
            while app.active:
                await pilot.pause(0.02)
        assert app.engine.runner.stopped
        assert store.run(app.engine.run_id)["state"] == "cancelled"


async def test_each_finding_keeps_its_own_simple_switch(store, config):
    run_id = store.create_run(config)
    store.transition(run_id, State.STARTING)
    store.transition(run_id, State.RUNNING)
    store.transition(run_id, State.COMPLETED)
    store.save_finding(
        run_id,
        {
            "id": "one",
            "title": "Public email",
            "severity": "medium",
            "category": "Sensitive Data Exposure",
            "location": LAB + "/users",
            "evidence": [{"evidence_id": "ev-1", "quote": "ada@example.com"}],
            "reproduction": ["GET /users"],
            "impact": "Anyone can read an email address from this response.",
            "remediation": "Require authentication before user details.",
            "plain": "Anyone can open this page and read an email address.",
        },
        True,
    )
    store.save_finding(
        run_id,
        {
            "id": "two",
            "title": "Admin flag",
            "severity": "high",
            "category": "Sensitive Data Exposure",
            "location": LAB + "/debug",
            "evidence": [{"evidence_id": "ev-2", "quote": '"admin": true'}],
            "reproduction": ["GET /debug"],
            "impact": "Anyone can see which account is an administrator.",
            "remediation": "Remove privilege flags from public responses.",
            "plain": "This page shows which account is an administrator.",
        },
        True,
    )
    app = EmergentApp(store)
    async with app.run_test(size=(120, 48)) as pilot:
        app.query_one(TabbedContent).active = "history-tab"
        await pilot.pause()
        app.query_one("#history", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        details = app.query_one("#details", RichLog)
        assert "Anyone can open this page and read an email address." in _log_text(details)
        assert "Remediation" not in _log_text(details)
        await pilot.click("#simple-switch")
        await pilot.pause()
        detailed = _log_text(details)
        assert "Remediation" in detailed
        assert "Anyone can read an email address from this response." in detailed
        assert "Detailed" in str(app.query_one("#view-label", Static).render())
        app.query_one("#findings", DataTable).focus()
        await pilot.press("down", "enter")
        await pilot.pause()
        assert "This page shows which account is an administrator." in _log_text(details)
        assert app.query_one("#simple-switch", Switch).value
        await pilot.press("up", "enter")
        await pilot.pause()
        assert "Remediation" in _log_text(details)
        assert not app.query_one("#simple-switch", Switch).value
