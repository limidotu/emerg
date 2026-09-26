import asyncio
import json

import pytest
from pydantic import ValidationError

from emergent_kali.docker import FakeRunner
from emergent_kali.engine import (
    Engine,
    alternate_record,
    closed_quote_note,
    covered_location_note,
    note_ends_closed_role,
    named_paths,
    only_repeated_targets,
    requests_unnamed_path,
    reused_quote,
    object_key_note,
    schema_error_note,
    same_evidence_candidate,
    empty_data_note,
    empty_quote_note,
    schema_failure_note,
    schema_note_from_refusal,
    validator_host_note,
    stored_quote_note,
    markup_quote,
    markup_refusal_note,
    source_map_location,
    source_map_note,
    observation_quote_note,
    refuse_stop,
    repair_tool_kind,
    stop_quote_note,
    repeat_refusal_note,
    title_quote_mismatch,
)
from emergent_kali.model import MockModel, parse_plain
from emergent_kali.models import LAB, RESPONSE_ADAPTER, FindingDraft, Limits, State, ToolArgs, ToolCall


def test_a_tool_call_of_captured_urls_is_a_repeat():
    origin = "http://juice-shop:3000"
    call = ToolCall(
        kind="tool_call",
        tool="content_discovery",
        arguments=ToolArgs(url=origin, paths=["/users/v1/name1"]),
    )
    captured = {origin + "/users/v1/name1"}
    assert only_repeated_targets(origin, call, captured)
    assert not only_repeated_targets(origin, call, {origin + "/other"})


@pytest.mark.parametrize("findings,code", [(True, 2), (False, 0)])
async def test_complete_run(store, config, findings, code):
    events = []
    engine = Engine(store, config, model=MockModel(findings), on_event=events.append)
    assert await engine.run() == code
    assert store.run(engine.run_id)["state"] == "completed"
    assert engine.runner.stopped
    assert len(store.findings(engine.run_id)) == int(findings)
    assert len([e for e in events if e["kind"] == "command_approved"]) == 2
    assert {e["data"]["role"] for e in events if e["kind"] == "agent"} >= {
        "coordinator",
        "reconnaissance",
        "web-test",
        "report",
    }
    for finding in store.findings(engine.run_id):
        assert finding["evidence"] and finding["remediation"]
        assert finding["plain"] == finding["title"] + ". A visitor can see this without signing in."


def test_parse_plain_keeps_only_short_sentences_for_known_ids():
    findings = [{"id": "one"}, {"id": "two"}]
    text = json.dumps(
        {
            "items": [
                {"id": "one", "plain": "Anyone can read an email address on this page."},
                {"id": "two", "plain": "X-Emerg-Enum shows a private flag."},
                {"id": "missing", "plain": "This id is not a stored finding."},
                {"id": "one", "plain": "no"},
            ]
        }
    )
    assert parse_plain(text, findings) == {"one": "Anyone can read an email address on this page."}
    assert parse_plain("not json", findings) == {}


@pytest.mark.parametrize(
    "response",
    [
        "not json",
        "{}",
        '{"kind":"stop","reason":"done","shell":"bash"}',
        '{"kind":"tool_call","tool":"shell","arguments":{"url":"http://evil"}}',
    ],
)
async def test_malformed_model_output_fails_closed(store, config, response):
    class BadModel:
        async def respond(self, *_):
            return response

    engine = Engine(store, config, model=BadModel())
    assert await engine.run() == 1
    assert store.run(engine.run_id)["state"] == "failed"
    assert not store.findings(engine.run_id)
    assert engine.runner.stopped


def test_state_transitions(store, config):
    run_id = store.create_run(config)
    with pytest.raises(ValueError):
        store.transition(run_id, State.COMPLETED)
    for state in [State.STARTING, State.RUNNING, State.PAUSED, State.RUNNING, State.COMPLETED]:
        store.transition(run_id, state)
    with pytest.raises(ValueError):
        store.transition(run_id, State.RUNNING)


async def test_invalid_evidence_is_not_a_finding(store, config):
    engine = Engine(store, config)
    assert await engine.run() == 2
    data = store.findings(engine.run_id)[0]
    draft = FindingDraft.model_validate(
        {k: v for k, v in data.items() if k not in {"id", "validation_reason"}}
    )
    assert draft.stable_id == data["id"]
    draft.title = "  PUBLIC DIRECTORY INDEX  "
    assert draft.stable_id == data["id"]
    draft.evidence[0].quote = "Invented evidence never captured"
    with pytest.raises(ValueError, match="does not match"):
        engine.check_finding(draft)
    draft.evidence[0].evidence_id = "ev-other-run"
    with pytest.raises(ValueError, match="missing"):
        engine.check_finding(draft)


class _Dump:
    def __init__(self, data):
        self.data = data

    def model_dump(self):
        return dict(self.data)


def test_a_title_change_keeps_the_same_quote():
    base = {
        "title": "Original title",
        "location": "http://lab/a",
        "severity": "low",
        "evidence": [{"quote": "visible quote"}],
    }
    assert same_evidence_candidate(_Dump(base), _Dump({**base, "title": "Other title"}))
    assert not same_evidence_candidate(_Dump(base), _Dump({**base, "location": "http://lab/b"}))
    assert not same_evidence_candidate(_Dump(base), _Dump({**base, "evidence": [{"quote": "other"}]}))
    assert not same_evidence_candidate(_Dump(base), _Dump({**base, "severity": "high"}))


def test_one_empty_response_repeats_a_quote_note():
    history = [
        {
            "kind": "observation",
            "summary": "Copy one verbatim quote from the body of http://lab/open. Set location to that URL.",
        }
    ]
    message = "The model response had no text."
    note = empty_quote_note(message, history, False)
    assert "http://lab/open" in note
    assert "tool call" not in note.casefold()
    assert empty_quote_note(message, history, True) == ""
    assert empty_quote_note("The model request exceeded the time limit.", history, False) == ""
    assert empty_quote_note(message, [], False) == ""


def test_one_empty_web_test_response_names_an_uncovered_data_url():
    message = "The model response had no text."
    evidence = {
        "ev-1": {
            "exit_code": 0,
            "records": [
                {"url": "http://lab/open", "status": 200, "body": "q" * 90},
                {"url": "http://lab/covered", "status": 200, "body": "z" * 120},
                {"url": "http://lab/app.js.map", "status": 200, "body": "m" * 200},
                {"url": "http://lab/short", "status": 200, "body": "short"},
            ],
        }
    }
    note = empty_data_note(message, False, evidence, [{"location": "http://lab/covered"}])
    assert "http://lab/open" in note
    assert "http://lab/covered" not in note
    assert ".map" not in note
    closed = empty_data_note(
        message,
        False,
        evidence,
        [{"location": "http://lab/covered"}, {"location": "http://lab/open"}],
    )
    assert "http://" not in closed
    assert "Return stop" in closed
    assert "verbatim quote" not in closed
    assert empty_data_note(message, True, evidence, []) == ""
    short = {"ev-1": {"exit_code": 0, "records": [{"url": "http://lab/ftp", "status": 200, "body": "short body"}]}}
    assert empty_data_note(message, False, short, []) == ""


def test_a_tool_object_without_kind_becomes_a_tool_call():
    raw = json.dumps({"tool": "http_probe", "arguments": {"url": "http://juice-shop:3000/"}})
    response = RESPONSE_ADAPTER.validate_json(repair_tool_kind(raw))
    assert response.kind == "tool_call"
    finding = json.dumps(
        {
            "decision": "candidate",
            "reason": "A guess from the model.",
            "finding": {"title": "Guessed issue"},
        }
    )
    assert "kind" not in json.loads(repair_tool_kind(finding))
    note = json.dumps({"summary": "The root page returned HTTP 200."})
    assert RESPONSE_ADAPTER.validate_json(repair_tool_kind(note)).kind == "observation"
    mixed = json.dumps({"summary": "A guess from the model.", "finding": {"title": "Guessed issue"}})
    assert "kind" not in json.loads(repair_tool_kind(mixed))
    stop = json.dumps({"reason": "The assigned task is complete."})
    assert RESPONSE_ADAPTER.validate_json(repair_tool_kind(stop)).kind == "stop"
    plan = json.dumps({"reason": "A plan.", "tasks": []})
    assert "kind" not in json.loads(repair_tool_kind(plan))
    typed = json.dumps({"type": "stop", "reason": "The assigned task is complete."})
    assert RESPONSE_ADAPTER.validate_json(repair_tool_kind(typed)).kind == "stop"
    marked = json.dumps(
        {"type": "finding", "decision": "candidate", "reason": "A guess from the model.", "finding": {"title": "x"}}
    )
    assert json.loads(repair_tool_kind(marked))["kind"] == "finding"
    unknown = json.dumps({"type": "note", "reason": "Not a kind."})
    assert "kind" not in json.loads(repair_tool_kind(unknown))
    assignment = json.dumps({"role": "reconnaissance", "task": "Probe the lab."})
    plan_response = RESPONSE_ADAPTER.validate_json(repair_tool_kind(assignment))
    assert plan_response.kind == "plan"
    assert plan_response.tasks[0].role == "reconnaissance"
    assert plan_response.tasks[0].task == "Probe the lab."
    other = json.dumps({"role": "report", "task": "Probe the lab."})
    assert "kind" not in json.loads(repair_tool_kind(other))


def test_one_json_failure_gets_a_schema_note():
    message = (
        "The web-test model returned invalid JSON or a response outside the schema. "
        "Error type: json_invalid."
    )
    note = schema_failure_note(message, False)
    assert "Error type: json_invalid" in note
    assert "tool call" not in note.casefold()
    assert schema_failure_note(message, True) == ""
    assert schema_failure_note("The model response had no text.", False) == ""


async def test_json_after_an_empty_response_still_asks_once(store, config):
    class EmptyThenJson(MockModel):
        def __init__(self):
            super().__init__(findings=True)
            self.phase = 0

        async def respond(self, role, context):
            if role != "web-test":
                return await super().respond(role, context)
            self.phase += 1
            if self.phase == 1:
                raise RuntimeError("The model response had no text.")
            if self.phase == 2:
                return "not json"
            self.turns["web-test"] = 1
            return await super().respond(role, context)

    engine = Engine(store, config, model=EmptyThenJson())
    assert await engine.run() == 2
    assert "Public directory index" in [item["title"] for item in store.findings(engine.run_id)]


def test_a_validator_json_retry_includes_both_notes():
    schema = schema_note_from_refusal(
        "The validator model returned invalid JSON. Error type: union_tag_invalid."
    )
    note = validator_host_note(schema, False)
    assert "Error type: union_tag_invalid" in note
    assert "unchanged" in note
    assert "confirmed or rejected" in note
    assert "decision to confirmed or rejected" in validator_host_note("", True)
    assert "decision to candidate" not in validator_host_note("", True)
    assert validator_host_note("", False) == ""


async def test_validator_json_retry_can_confirm(store, config):
    class RetryValidator(MockModel):
        def __init__(self):
            super().__init__(findings=True)
            self.calls = 0
            self.notes = []

        async def respond(self, role, context):
            if role != "validator":
                return await super().respond(role, context)
            self.calls += 1
            self.notes.append(context.get("host_note", ""))
            if self.calls == 1:
                response = json.loads(await super().respond(role, context))
                response["decision"] = "candidate"
                response["finding"]["title"] = "Rewritten title"
                return json.dumps(response)
            if self.calls == 2:
                return "not json"
            return await super().respond(role, context)

    model = RetryValidator()
    engine = Engine(store, config, model=model)
    assert await engine.run() == 2
    assert model.calls == 3
    assert "unchanged" in model.notes[2]
    assert "Error type:" in model.notes[2]
    assert store.findings(engine.run_id)[0]["title"] == "Public directory index"


async def test_a_confirmed_title_change_keeps_the_original(store, config):
    class TitleChange(MockModel):
        async def respond(self, role, context):
            if role != "validator":
                return await super().respond(role, context)
            response = json.loads(await super().respond(role, context))
            response["finding"]["title"] = "Different title"
            return json.dumps(response)

    engine = Engine(store, config, model=TitleChange())
    assert await engine.run() == 2
    assert store.findings(engine.run_id)[0]["title"] == "Public directory index"


async def test_validator_cannot_change_candidate(store, config):
    class ChangedModel(MockModel):
        async def respond(self, role, context):
            response = json.loads(await super().respond(role, context))
            if role == "validator":
                response["finding"]["severity"] = "critical"
            return json.dumps(response)

    engine = Engine(store, config, model=ChangedModel())
    assert await engine.run() == 1
    assert not store.findings(engine.run_id)


async def test_reconnaissance_forbidden_tool_continues(store, config):
    class OneBadTool(MockModel):
        def __init__(self):
            super().__init__()
            self.refused = False

        async def respond(self, role, context):
            if role == "reconnaissance" and not self.refused:
                self.refused = True
                return json.dumps(
                    {
                        "kind": "tool_call",
                        "tool": "content_discovery",
                        "arguments": {"url": "http://juice-shop:3000", "paths": ["/ftp/"]},
                    }
                )
            return await super().respond(role, context)

    events = []
    engine = Engine(store, config, model=OneBadTool(), on_event=events.append)
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"
    assert not any(
        event["data"].get("tool") == "content_discovery"
        for event in events
        if event["kind"] == "command_approved"
    )


async def test_repeated_observation_ends_task(store, config):
    class RepeatObservation(MockModel):
        def __init__(self):
            super().__init__()
            self.extra = 0

        async def respond(self, role, context):
            if role == "reconnaissance" and self.turns.get(role, 0) >= 1:
                self.extra += 1
                if self.extra > 2:
                    raise AssertionError("The repeated observation did not end the task.")
                return json.dumps(
                    {
                        "kind": "observation",
                        "summary": "The root page returned HTTP 200.",
                        "evidence_ids": [],
                    }
                )
            return await super().respond(role, context)

    engine = Engine(store, config, model=RepeatObservation())
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"


async def test_stop_after_a_refused_candidate_asks_for_a_verbatim_quote(store, config):
    location = "http://juice-shop:3000/ftp/"

    class BadThenQuote(MockModel):
        def __init__(self):
            super().__init__(findings=False)
            self.phase = 0

        async def respond(self, role, context):
            if role != "web-test":
                return await super().respond(role, context)
            self.phase += 1
            if self.phase == 1:
                return json.dumps(
                    {
                        "kind": "finding",
                        "decision": "candidate",
                        "reason": "A guess.",
                        "finding": {
                            "title": "Guessed issue",
                            "severity": "low",
                            "category": "Information exposure",
                            "location": location,
                            "evidence": [
                                {"evidence_id": "missing", "quote": "this quote is not in the body"}
                            ],
                            "reproduction": ["GET /ftp/"],
                            "impact": "A visitor can read a file name.",
                            "remediation": "Restrict the directory.",
                        },
                    }
                )
            if self.phase == 2:
                return json.dumps({"kind": "stop", "reason": "Done."})
            evidence_id = next(reversed(context["evidence"]))
            return json.dumps(
                {
                    "kind": "finding",
                    "decision": "candidate",
                    "reason": "The index names a file.",
                    "finding": {
                        "title": "Listed acquisitions file",
                        "severity": "low",
                        "category": "Information exposure",
                        "location": location,
                        "evidence": [{"evidence_id": evidence_id, "quote": "acquisitions.md"}],
                        "reproduction": ["GET /ftp/"],
                        "impact": "A visitor can read a file name.",
                        "remediation": "Restrict the directory.",
                    },
                }
            )

    engine = Engine(store, config, model=BadThenQuote())
    assert await engine.run() == 2
    titles = [item["title"] for item in store.findings(engine.run_id)]
    assert "Listed acquisitions file" in titles
    assert "Guessed issue" not in titles


def test_an_echoed_account_is_stored_once(store, config):
    engine = Engine(store, config)
    records = [
        {
            "url": "http://juice-shop:3000/users",
            "status": 200,
            "headers": {},
            "body": '{"username":"ada","email":"ada@example.com"}',
        },
        {
            "url": "http://juice-shop:3000/items",
            "status": 200,
            "headers": {},
            "body": '{"title":"one","user":"ada"}',
        },
    ]
    evidence_id = store.save_evidence(
        engine.run_id,
        {"tool": "content_discovery", "exit_code": 0, "records": records},
    )
    engine.file_signatures(evidence_id, records)
    engine.file_signatures(evidence_id, records)
    echoes = [
        item
        for item in store.findings(engine.run_id)
        if item["title"] == "Public response names another account"
    ]
    assert len(echoes) == 1
    assert echoes[0]["location"] == "http://juice-shop:3000/items"
    assert echoes[0]["evidence"][0]["quote"] == '"user":"ada"'


def test_a_server_banner_is_stored_once(store, config, monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    engine = Engine(store, config)
    records = [
        {
            "url": "http://vampi:5000/",
            "status": 200,
            "headers": {"Server": "Example/1.2.3"},
            "body": "ok",
        },
        {
            "url": "http://vampi:5000/robots.txt",
            "status": 200,
            "headers": {"Server": "Example/1.2.3"},
            "body": "ok",
        },
    ]
    evidence_id = store.save_evidence(
        engine.run_id,
        {"tool": "content_discovery", "exit_code": 0, "records": records},
    )
    engine.file_signatures(evidence_id, records)
    banners = [
        item
        for item in store.findings(engine.run_id)
        if item["title"] == "Response header shows a server version"
    ]
    assert len(banners) == 1
    assert banners[0]["evidence"][0]["quote"] == "Example/1.2.3"
    assert banners[0]["location"] == "http://vampi:5000/"


def test_an_unnamed_path_is_refused(monkeypatch):
    monkeypatch.setenv("EMERG_LAB_URL", "http://vampi:5000")
    evidence = {
        "ev-1": {
            "exit_code": 0,
            "records": [
                {
                    "url": "http://vampi:5000/users/v1",
                    "status": 200,
                    "body": '<a href="/books/v1">books</a>',
                }
            ],
        }
    }
    named = named_paths(evidence)
    origin = "http://vampi:5000"
    invented = ToolCall(
        kind="tool_call",
        tool="content_discovery",
        arguments=ToolArgs(url=origin, paths=["/backup"], max_pages=1, ports=[5000]),
    )
    named_call = ToolCall(
        kind="tool_call",
        tool="content_discovery",
        arguments=ToolArgs(url=origin, paths=["/books/v1"], max_pages=1, ports=[5000]),
    )
    assert requests_unnamed_path(origin, invented, named)
    assert not requests_unnamed_path(origin, named_call, named)
    assert not requests_unnamed_path(origin, invented, set())


def test_a_second_stop_is_refused_once():
    quote = "Copy one verbatim quote from the body of http://lab:5000/open. Set location to that URL."
    assert refuse_stop(0, "")
    assert refuse_stop(1, quote)
    assert not refuse_stop(1, "")
    assert not refuse_stop(2, quote)


def test_stop_after_a_quote_note_repeats_that_note():
    named = (
        "The host refused this finding. That location already has a stored finding. "
        "Copy one verbatim quote from the body of http://lab:5000/open. Set location to that URL."
    )
    history = [{"kind": "observation", "summary": named}]
    note = stop_quote_note(history, True)
    assert note == named
    assert "URL equals the location" not in note
    fallback = stop_quote_note([], True)
    assert "URL equals the location" in fallback


def test_a_later_stop_note_wins_over_an_older_quote_note():
    older = (
        "The host refused this tool call. Every path is already captured. "
        "Copy one verbatim quote from a captured record body. Set location to that record URL."
    )
    newer = (
        "The host refused this finding. That location already has a stored finding. "
        "The captured data records already have findings. Return stop."
    )
    history = [
        {"kind": "observation", "summary": older},
        {"kind": "observation", "summary": newer},
    ]
    assert stop_quote_note(history, True) == newer
    assert stop_quote_note(list(reversed(history)), True) == older


def test_one_observation_after_a_quote_request_is_refused():
    history = [
        {
            "kind": "observation",
            "summary": "Copy one verbatim quote from the body of http://lab:5000/open. Set location to that URL.",
        }
    ]
    note = observation_quote_note(history, False)
    assert "verbatim quote" in note
    assert "http://lab:5000/open" in note
    assert observation_quote_note(history, True) == ""
    assert observation_quote_note([{"kind": "observation", "summary": "The root page returned HTTP 200."}], False) == ""


def test_a_second_repeat_asks_for_a_quote():
    evidence = {
        "ev-1": {
            "exit_code": 0,
            "records": [
                {"url": "http://lab:5000/app.js", "status": 200, "body": "x" * 400},
                {"url": "http://lab:5000/ui/", "status": 200, "body": "<!DOCTYPE html><html></html>"},
                {
                    "url": "http://lab:5000/openapi.yaml",
                    "status": 200,
                    "body": "openapi: 3.0.0\npaths:\n  /x:\n    get:\n      summary: long\n" + ("y" * 300),
                },
                {"url": "http://lab:5000/known", "status": 200, "body": "abcdefghij"},
                {"url": "http://lab:5000/short", "status": 200, "body": "qrstuvwxyz"},
                {"url": "http://lab:5000/open", "status": 200, "body": "z" * 80},
            ],
        }
    }
    findings = [{"location": "http://lab:5000/known"}]
    first = repeat_refusal_note(1, evidence, findings)
    second = repeat_refusal_note(2, evidence, findings)
    assert "Choose a path" in first
    assert "http://lab:5000/open" not in first
    assert "http://lab:5000/open" in second
    assert "verbatim quote" in second
    assert "Choose a path" not in second
    assert "http://lab:5000/app.js" not in second
    assert "http://lab:5000/ui/" not in second
    assert "openapi.yaml" not in second
    assert "http://lab:5000/short" not in second
    covered = findings + [{"location": "http://lab:5000/open"}]
    closed = repeat_refusal_note(2, evidence, covered)
    assert "Return stop" in closed
    assert "findings" in closed
    assert "verbatim quote" not in closed
    assert "http://" not in closed
    assert closed_quote_note(closed)


def test_a_secret_title_needs_a_secret_quote():
    assert title_quote_mismatch("Exposed user secrets", {"Database populated."})
    assert not title_quote_mismatch("Exposed user secrets", {'"secret":'})
    assert not title_quote_mismatch("Exposed user secrets", {"ada@example.com"})
    assert not title_quote_mismatch("Public directory index", {"acquisitions.md"})


def test_a_source_map_quote_is_refused():
    assert source_map_location("http://lab/ui/app.js.map")
    assert source_map_location("http://lab/ui/app.css.map?x=1")
    assert not source_map_location("http://lab/ui/app.js")
    note = source_map_note()
    assert "source map" in note
    assert "http" not in note
    assert ".map" not in note


async def test_a_verbatim_source_map_quote_is_not_stored(store, config):
    holder = {}
    location = LAB + "/ui/app.js.map"

    class MapQuote(MockModel):
        def __init__(self):
            super().__init__(findings=False)
            self.phase = 0

        async def respond(self, role, context):
            if role != "web-test":
                return await super().respond(role, context)
            self.phase += 1
            if self.phase > 1:
                return json.dumps({"kind": "stop", "reason": "Done."})
            engine = holder["engine"]
            evidence_id = engine.store.save_evidence(
                engine.run_id,
                {
                    "tool": "content_discovery",
                    "exit_code": 0,
                    "records": [
                        {
                            "url": location,
                            "status": 200,
                            "body": '{"password":"present","email":"ada@example.com"}',
                        }
                    ],
                },
            )
            return json.dumps(
                {
                    "kind": "finding",
                    "decision": "candidate",
                    "reason": "A library file names a field.",
                    "finding": {
                        "title": "Public response includes a secret field",
                        "severity": "high",
                        "category": "Sensitive Data Exposure",
                        "location": location,
                        "evidence": [{"evidence_id": evidence_id, "quote": '"password":'}],
                        "reproduction": ["GET /ui/app.js.map"],
                        "impact": "Anyone can read a secret field in this response.",
                        "remediation": "Remove secret fields from public responses.",
                    },
                }
            )

    model = MapQuote()
    engine = Engine(store, config, model=model)
    holder["engine"] = engine
    await engine.run()
    assert all(not item["location"].endswith(".map") for item in store.findings(engine.run_id))
    assert all(not item.location.endswith(".map") for item in engine.candidates.values())


def test_a_markup_refusal_does_not_name_the_page():
    note = markup_refusal_note()
    assert "page markup" in note
    assert "data record" in note
    assert "Copy one verbatim quote" in note
    assert "http" not in note
    assert "URL equals the location" not in note
    history = [{"kind": "observation", "summary": note}]
    assert stop_quote_note(history, True) == note


def test_page_markup_is_not_a_credential_quote():
    assert markup_quote({"<!-- page shell -->\n<!DOCTYPE html><html>"})
    assert not markup_quote({'"admin": true'})


def test_a_covered_location_names_an_uncovered_url():
    evidence = {
        "ev-1": {
            "exit_code": 0,
            "records": [
                {"url": "http://vampi:5000/a", "status": 200, "body": "abcdefghij"},
                {"url": "http://vampi:5000/ui/", "status": 200, "body": "<!DOCTYPE html><html></html>"},
                {"url": "http://vampi:5000/app.js", "status": 200, "body": "x" * 80},
                {
                    "url": "http://vampi:5000/openapi.yaml",
                    "status": 200,
                    "body": "openapi: 3.0.0\npaths:\n  /x:\n" + ("y" * 80),
                },
                {"url": "http://vampi:5000/status", "status": 200, "body": "short body"},
                {"url": "http://vampi:5000/b", "status": 200, "body": "klmnopqrst"},
                {"url": "http://vampi:5000/c", "status": 200, "body": "qrstuvwxyz" * 8},
            ],
        }
    }
    findings = [{"location": "http://vampi:5000/a"}, {"location": "http://vampi:5000/b"}]
    note = covered_location_note(evidence, findings, "http://vampi:5000/a")
    assert "http://vampi:5000/c" in note
    assert "http://vampi:5000/b" not in note
    assert "http://vampi:5000/ui/" not in note
    assert "http://vampi:5000/status" not in note
    assert "http://vampi:5000/app.js" not in note
    assert "openapi.yaml" not in note
    assert covered_location_note(evidence, [], "http://vampi:5000/a") == ""
    full = findings + [{"location": "http://vampi:5000/c"}]
    closed = covered_location_note(evidence, full, "http://vampi:5000/a")
    assert "already has a stored finding" in closed
    assert "Return stop" in closed
    assert "verbatim quote" not in closed
    assert "http://vampi:5000/a" not in closed
    assert "http://vampi:5000/c" not in closed
    assert "URL equals the location" not in closed
    assert stop_quote_note([{"kind": "observation", "summary": closed}], True) == closed


def test_a_closed_quote_note_ends_web_test_after_two():
    note = (
        "The host refused this finding. That location already has a stored finding. "
        "Copy one verbatim quote from a captured record that has no stored finding."
    )
    named = (
        "The host refused this finding. That location already has a stored finding. "
        "Copy one verbatim quote from the body of http://lab/open. Set location to that URL."
    )
    assert closed_quote_note(note)
    assert not closed_quote_note(named)
    assert not note_ends_closed_role("web-test", note, 1)
    assert note_ends_closed_role("web-test", note, 2)
    assert not note_ends_closed_role("reconnaissance", note, 2)
    assert not note_ends_closed_role("web-test", named, 4)
    plan = (
        "The host refused this plan. kind plan is invalid for the reconnaissance role. "
        "Allowed kinds are tool_call, observation, finding, and stop. "
        "The captured data records already have findings. Return stop."
    )
    assert closed_quote_note(plan)
    assert not note_ends_closed_role("reconnaissance", plan, 1)
    assert note_ends_closed_role("reconnaissance", plan, 2)
    assert note_ends_closed_role("web-test", plan, 2)


async def test_two_closed_notes_end_web_test(store, config):
    holder = {}

    class Repeat(MockModel):
        def __init__(self):
            super().__init__(findings=False)
            self.web_turns = 0

        async def respond(self, role, context):
            if role != "web-test":
                return await super().respond(role, context)
            engine = holder["engine"]
            location = LAB + "/covered"
            if not any(item.get("location") == location for item in engine.store.findings(engine.run_id)):
                engine.store.save_evidence(
                    engine.run_id,
                    {
                        "tool": "content_discovery",
                        "exit_code": 0,
                        "records": [{"url": location, "status": 200, "body": "q" * 90}],
                    },
                )
                engine.store.save_finding(
                    engine.run_id,
                    {
                        "id": "covered",
                        "title": "Covered note",
                        "severity": "low",
                        "category": "Information exposure",
                        "location": location,
                        "evidence": [],
                        "reproduction": ["GET /covered"],
                        "impact": "Anyone can read this response.",
                        "remediation": "Remove the extra text from the response.",
                    },
                    True,
                )
            self.web_turns += 1
            return json.dumps(
                {
                    "kind": "finding",
                    "decision": "candidate",
                    "reason": "A guess.",
                    "finding": {
                        "title": "Guessed issue",
                        "severity": "low",
                        "category": "Information exposure",
                        "location": location,
                        "evidence": [{"evidence_id": "missing", "quote": "this quote is not in the body"}],
                        "reproduction": ["GET /covered"],
                        "impact": "A visitor can read a file name.",
                        "remediation": "Restrict the directory.",
                    },
                }
            )

    model = Repeat()
    engine = Engine(store, config, model=model)
    holder["engine"] = engine
    await engine.run()
    assert model.web_turns == 2


async def test_a_closed_stop_note_ends_web_test(store, config):
    holder = {}

    class FindingThenStop(MockModel):
        def __init__(self):
            super().__init__(findings=False)
            self.web_turns = 0

        async def respond(self, role, context):
            if role != "web-test":
                return await super().respond(role, context)
            engine = holder["engine"]
            location = LAB + "/covered"
            if not any(item.get("location") == location for item in engine.store.findings(engine.run_id)):
                engine.store.save_evidence(
                    engine.run_id,
                    {
                        "tool": "content_discovery",
                        "exit_code": 0,
                        "records": [{"url": location, "status": 200, "body": "q" * 90}],
                    },
                )
                engine.store.save_finding(
                    engine.run_id,
                    {
                        "id": "covered",
                        "title": "Covered note",
                        "severity": "low",
                        "category": "Information exposure",
                        "location": location,
                        "evidence": [],
                        "reproduction": ["GET /covered"],
                        "impact": "Anyone can read this response.",
                        "remediation": "Remove the extra text from the response.",
                    },
                    True,
                )
            self.web_turns += 1
            if self.web_turns == 1:
                return json.dumps(
                    {
                        "kind": "finding",
                        "decision": "candidate",
                        "reason": "A guess.",
                        "finding": {
                            "title": "Guessed issue",
                            "severity": "low",
                            "category": "Information exposure",
                            "location": location,
                            "evidence": [{"evidence_id": "missing", "quote": "this quote is not in the body"}],
                            "reproduction": ["GET /covered"],
                            "impact": "A visitor can read a file name.",
                            "remediation": "Restrict the directory.",
                        },
                    }
                )
            return json.dumps({"kind": "stop", "reason": "Done."})

    model = FindingThenStop()
    engine = Engine(store, config, model=model)
    holder["engine"] = engine
    await engine.run()
    assert model.web_turns == 2


def test_a_stored_quote_names_another_captured_url():
    evidence = {
        "ev-1": {
            "exit_code": 0,
            "records": [
                {"url": "http://vampi:5000/", "status": 200, "body": "o" * 90},
                {"url": "http://vampi:5000/a", "status": 200, "body": "a" * 90},
                {"url": "http://vampi:5000/short", "status": 200, "body": "short body"},
                {"url": "http://vampi:5000/b", "status": 200, "body": "b" * 90},
            ],
        }
    }
    findings = [{"location": "http://vampi:5000/"}, {"location": "http://vampi:5000/a"}]
    note = stored_quote_note(evidence, findings, "http://vampi:5000/a")
    assert "body of http://vampi:5000/b" in note
    assert "body of http://vampi:5000/." not in note
    assert "short" not in note
    assert "already stored" in note
    covered = findings + [{"location": "http://vampi:5000/b"}]
    fallback = stored_quote_note(evidence, covered, "http://vampi:5000/a")
    assert "body of http" not in fallback
    assert "different verbatim quote" in fallback


def test_alternate_record_skips_the_refused_url_and_the_spec():
    evidence = {
        "ev-1": {
            "exit_code": 0,
            "records": [
                {
                    "url": "http://vampi:5000/openapi.json",
                    "status": 200,
                    "body": '{"openapi":"3.0.0","paths":{}}',
                },
                {"url": "http://vampi:5000/a", "status": 200, "body": "abcdefghij"},
                {"url": "http://vampi:5000/b", "status": 200, "body": "klmnopqrst"},
            ],
        }
    }
    assert alternate_record(evidence, "http://vampi:5000/a") == "http://vampi:5000/b"
    assert alternate_record(evidence, "http://vampi:5000/b") == "http://vampi:5000/a"


def test_two_bad_quotes_name_an_uncovered_url(store, config):
    engine = Engine(store, config)
    records = [
        {"url": "http://juice-shop:3000/", "status": 200, "body": "o" * 90},
        {"url": "http://juice-shop:3000/short", "status": 200, "body": "short body"},
        {"url": "http://juice-shop:3000/open", "status": 200, "body": "q" * 90},
    ]
    store.save_evidence(engine.run_id, {"tool": "content_discovery", "exit_code": 0, "records": records})
    store.save_finding(
        engine.run_id,
        {
            "id": "origin",
            "title": "Origin note",
            "severity": "low",
            "category": "Information exposure",
            "location": "http://juice-shop:3000/",
            "evidence": [],
            "reproduction": ["GET /"],
            "impact": "Anyone can read this response.",
            "remediation": "Remove the extra text from the response.",
        },
        True,
    )
    note = engine.quote_refusal_note("http://juice-shop:3000/missing", 2)
    assert "http://juice-shop:3000/open" in note
    assert "http://juice-shop:3000/short" not in note
    assert "body of http://juice-shop:3000/." not in note
    store.save_finding(
        engine.run_id,
        {
            "id": "open",
            "title": "Open note",
            "severity": "low",
            "category": "Information exposure",
            "location": "http://juice-shop:3000/open",
            "evidence": [],
            "reproduction": ["GET /open"],
            "impact": "Anyone can read this response.",
            "remediation": "Remove the extra text from the response.",
        },
        True,
    )
    fallback = engine.quote_refusal_note("http://juice-shop:3000/missing", 2)
    assert "body of http" not in fallback
    assert "URL equals the location" in fallback


async def test_second_refused_quote_names_another_captured_record(store, config):
    location = "http://juice-shop:3000/missing"

    class TwoBad(MockModel):
        def __init__(self):
            super().__init__(findings=False)
            self.phase = 0
            self.named = False

        async def respond(self, role, context):
            if role != "web-test":
                return await super().respond(role, context)
            self.phase += 1
            if self.phase <= 2:
                return json.dumps(
                    {
                        "kind": "finding",
                        "decision": "candidate",
                        "reason": "A guess.",
                        "finding": {
                            "title": "Guessed issue",
                            "severity": "low",
                            "category": "Information exposure",
                            "location": location,
                            "evidence": [
                                {"evidence_id": "missing", "quote": "this quote is not in the body"}
                            ],
                            "reproduction": ["GET /missing"],
                            "impact": "A visitor can read a file name.",
                            "remediation": "Restrict the directory.",
                        },
                    }
                )
            blob = json.dumps(context.get("history") or [])
            self.named = "http://juice-shop:3000/ftp/" in blob
            self.generic = "URL equals the location" in blob
            return json.dumps({"kind": "stop", "reason": "Done."})

    model = TwoBad()
    engine = Engine(store, config, model=model)
    assert await engine.run() == 0
    assert model.generic
    assert not model.named


def test_a_repeated_quote_at_the_same_location_is_not_new():
    findings = [
        {
            "location": "http://vampi:5000/users/v1/_debug",
            "evidence": [{"quote": '"admin": true'}],
        }
    ]
    assert reused_quote(findings, "http://vampi:5000/users/v1/_debug", {'"admin": true'})
    assert reused_quote(
        findings,
        "http://vampi:5000/users/v1/_debug",
        {'{"name": "ada", "admin": true}'},
    )
    assert not reused_quote(findings, "http://vampi:5000/users/v1/_debug", {'"email":'})
    assert not reused_quote(findings, "http://vampi:5000/books/v1", {'"admin": true'})


async def test_web_test_stop_is_refused_until_a_finding(store, config):
    class StopEarly(MockModel):
        def __init__(self):
            super().__init__()
            self.skipped = False

        async def respond(self, role, context):
            if role == "web-test" and not self.skipped and self.turns.get(role, 0) >= 1:
                self.skipped = True
                return json.dumps({"kind": "stop", "reason": "Stopping before a finding."})
            return await super().respond(role, context)

    engine = Engine(store, config, model=StopEarly())
    assert await engine.run() == 2
    assert store.findings(engine.run_id)


async def test_out_of_role_decision_is_refused(store, config):
    class PlansDuringRecon(MockModel):
        def __init__(self):
            super().__init__()
            self.once = False

        async def respond(self, role, context):
            if role == "reconnaissance" and not self.once and self.turns.get(role, 0) >= 1:
                self.once = True
                return json.dumps(
                    {
                        "kind": "plan",
                        "tasks": [
                            {"role": "reconnaissance", "task": "Probe the lab."},
                            {"role": "web-test", "task": "Check the directory."},
                        ],
                    }
                )
            return await super().respond(role, context)

    engine = Engine(store, config, model=PlansDuringRecon())
    assert await engine.run() == 2
    audit = (store.workspace(engine.run_id) / "audit.jsonl").read_text(encoding="utf-8")
    assert "kind plan is invalid for the reconnaissance role" in audit
    assert "Allowed kinds are tool_call, observation, finding, and stop." in audit
    assert "Return stop." in audit


async def test_two_plan_refusals_end_reconnaissance(store, config):
    class Plans(MockModel):
        def __init__(self):
            super().__init__()
            self.recon_turns = 0

        async def respond(self, role, context):
            if role == "reconnaissance":
                self.recon_turns += 1
                return json.dumps(
                    {
                        "kind": "plan",
                        "tasks": [
                            {"role": "reconnaissance", "task": "Probe the lab."},
                            {"role": "web-test", "task": "Check the directory."},
                        ],
                    }
                )
            return await super().respond(role, context)

    model = Plans()
    engine = Engine(store, config, model=model)
    assert await engine.run() == 2
    assert model.recon_turns == 2


async def test_unmatched_citation_is_dropped(store, config):
    class ExtraQuote(MockModel):
        async def respond(self, role, context):
            text = await super().respond(role, context)
            data = json.loads(text)
            if role == "web-test" and data.get("kind") == "finding":
                evidence_id = data["finding"]["evidence"][0]["evidence_id"]
                data["finding"]["evidence"].append(
                    {"evidence_id": evidence_id, "quote": "This sentence is not in the captured body."}
                )
                return json.dumps(data)
            return text

    engine = Engine(store, config, model=ExtraQuote())
    assert await engine.run() == 2
    finding = store.findings(engine.run_id)[0]
    assert len(finding["evidence"]) == 1
    assert "acquisitions.md" in finding["evidence"][0]["quote"]


async def test_run_completes_when_coordinator_does_not_stop(store, config):
    class TalkativeCoordinator(MockModel):
        async def respond(self, role, context):
            if role == "coordinator" and context.get("phase") == "finish":
                return json.dumps({"kind": "observation", "summary": "The report is complete.", "evidence_ids": []})
            return await super().respond(role, context)

    engine = Engine(store, config, model=TalkativeCoordinator())
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"


async def test_rejected_candidates_never_reach_report(store, config):
    class RejectModel(MockModel):
        async def respond(self, role, context):
            response = json.loads(await super().respond(role, context))
            if role == "validator":
                response["decision"] = "rejected"
            return json.dumps(response)

    engine = Engine(store, config, model=RejectModel())
    assert await engine.run() == 0
    assert len(store.findings(engine.run_id, validated=False)) == 1


class SlowRunner(FakeRunner):
    async def execute(self, *args):
        await asyncio.sleep(20)
        return await super().execute(*args)


async def until(predicate):
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(0.01)


async def test_pause_resume_cancel_inflight(store, config):
    engine = Engine(store, config, runner_factory=SlowRunner)
    task = asyncio.create_task(engine.run())
    await until(lambda: engine.command_count == 1)
    engine.pause()
    await until(lambda: engine.runner.paused)
    assert store.run(engine.run_id)["state"] == "paused"
    engine.resume()
    await until(lambda: not engine.runner.paused)
    engine.cancel()
    assert await asyncio.wait_for(task, 2) == 1
    assert engine.runner.stopped
    assert store.run(engine.run_id)["state"] == "cancelled"


async def test_deadline_applies_while_paused(store, config):
    engine = Engine(store, config, runner_factory=SlowRunner)
    task = asyncio.create_task(engine.run())
    await until(lambda: engine.command_count == 1)
    engine.pause()
    await until(lambda: engine.runner.paused)
    engine.deadline = 0
    assert await asyncio.wait_for(task, 2) == 1
    assert engine.runner.stopped
    assert "time limit" in store.run(engine.run_id)["error"]


@pytest.mark.parametrize("limits", [Limits(commands=1)])
async def test_limits_stop_run(store, config, limits):
    config.limits = limits
    engine = Engine(store, config)
    assert await engine.run() == 1
    assert engine.runner.stopped


async def test_oversized_tool_output_is_truncated(store, config):
    config.limits = Limits(output_bytes=8192)

    class LargeRunner(FakeRunner):
        def __init__(self, run_id, workspace):
            super().__init__(run_id, workspace)
            self.calls = 0

        async def execute(self, *args):
            result = await super().execute(*args)
            self.calls += 1
            if self.calls == 2:
                result["stdout"] = "x" * 20000
            return result

    events = []
    engine = Engine(store, config, runner_factory=LargeRunner, on_event=events.append)
    assert await engine.run() == 2
    assert any(event["data"].get("truncated") for event in events if event["kind"] == "tool_result")


async def test_truncated_kill_continues(store, config):
    class KilledRunner(FakeRunner):
        def __init__(self, run_id, workspace):
            super().__init__(run_id, workspace)
            self.calls = 0

        async def execute(self, *args):
            result = await super().execute(*args)
            self.calls += 1
            if self.calls == 2:
                result["exit_code"] = -9
                result["truncated"] = True
            return result

    engine = Engine(store, config, runner_factory=KilledRunner)
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"


async def test_start_failure_still_removes_runner(store, config):
    class BrokenRunner(FakeRunner):
        async def start(self):
            raise RuntimeError("Failed startup")

    engine = Engine(store, config, runner_factory=BrokenRunner)
    assert await engine.run() == 1
    assert engine.runner.stopped


async def test_malformed_tool_result_fails_closed(store, config):
    class BrokenRunner(FakeRunner):
        async def execute(self, *args):
            return {"stdout": "secret", "exit_code": "0"}

    engine = Engine(store, config, runner_factory=BrokenRunner)
    assert await engine.run() == 1
    assert engine.runner.stopped
    assert store.evidence(engine.run_id) == {}


async def test_validator_error_keeps_host_findings(store, config):
    class SweepRunner(FakeRunner):
        async def execute(self, tool, arguments, limits):
            result = await super().execute(tool, arguments, limits)
            if tool == "content_discovery":
                body = "This document is confidential! Do not distribute!"
                result["records"] = [
                    {
                        "url": "http://juice-shop:3000/ftp/acquisitions.md",
                        "status": 200,
                        "headers": {},
                        "body": body,
                    }
                ]
                result["stdout"] = body
            return result

    class DeadValidator(MockModel):
        async def respond(self, role, context):
            if role == "validator":
                raise RuntimeError(
                    "The model request failed. Check the model environment variables and endpoint."
                )
            return await super().respond(role, context)

    config.depth = "deep"
    engine = Engine(store, config, model=DeadValidator(), runner_factory=SweepRunner)
    assert await engine.run() == 2
    assert any(item["title"] == "Confidential Document" for item in store.findings(engine.run_id))


async def test_planner_error_keeps_host_findings(store, config):
    class SweepRunner(FakeRunner):
        async def execute(self, tool, arguments, limits):
            result = await super().execute(tool, arguments, limits)
            if tool == "content_discovery":
                body = "This document is confidential! Do not distribute!"
                result["records"] = [
                    {
                        "url": "http://juice-shop:3000/ftp/acquisitions.md",
                        "status": 200,
                        "headers": {},
                        "body": body,
                    }
                ]
                result["stdout"] = body
            return result

    class DeadPlanner(MockModel):
        async def respond(self, role, context):
            if role == "coordinator" and context.get("phase") != "finish":
                raise RuntimeError(
                    "The model request failed. Check the model environment variables and endpoint."
                )
            return await super().respond(role, context)

    config.depth = "deep"
    engine = Engine(store, config, model=DeadPlanner(), runner_factory=SweepRunner)
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"
    assert any(item["title"] == "Confidential Document" for item in store.findings(engine.run_id))


async def test_model_error_keeps_stored_findings(store, config):
    class Flaky(MockModel):
        async def respond(self, role, context):
            if role == "web-test" and self.turns.get(role, 0) >= 2:
                raise RuntimeError(
                    "The model request failed. Check the model environment variables and endpoint."
                )
            return await super().respond(role, context)

    engine = Engine(store, config, model=Flaky())
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"
    assert store.findings(engine.run_id)


async def test_bad_report_still_completes(store, config):
    class BadReport(MockModel):
        async def respond(self, role, context):
            if role == "report":
                return "not json"
            return await super().respond(role, context)

    engine = Engine(store, config, model=BadReport())
    assert await engine.run() == 2
    assert store.run(engine.run_id)["state"] == "completed"
    assert store.findings(engine.run_id)
    audit = (store.workspace(engine.run_id) / "audit.jsonl").read_text(encoding="utf-8")
    assert "The report model returned invalid JSON or a response outside the schema." in audit


def test_schema_note_keeps_the_error_type_and_drops_model_text():
    try:
        RESPONSE_ADAPTER.validate_json("not json at all")
    except ValidationError as exc:
        note = schema_error_note(exc)
    else:
        raise AssertionError("invalid JSON must fail validation")
    assert note.startswith("Return one JSON object")
    assert "Error type:" in note
    assert "not json" not in note
    leaked = schema_note_from_refusal("The model said secret-token. Error type: json_invalid. more text")
    assert "json_invalid" in leaked
    assert "secret-token" not in leaked
    assert "must include kind" not in leaked
    tagged = schema_note_from_refusal("secret-token. Error type: union_tag_not_found.")
    assert "union_tag_not_found" in tagged
    assert "must include kind" in tagged
    assert "secret-token" not in tagged


def test_a_schema_note_names_object_keys_without_values():
    raw = json.dumps({"url": "http://lab/secret-token", "tool": "http_probe", "has space": 1})
    try:
        RESPONSE_ADAPTER.validate_json(raw)
    except ValidationError as exc:
        note = schema_error_note(exc, raw)
    else:
        raise AssertionError("a tool object without kind must fail validation")
    assert "Object keys: tool, url." in note
    assert "secret-token" not in note
    assert "has space" not in note
    rebuilt = schema_note_from_refusal("The model said secret-token. " + note)
    assert rebuilt.endswith("Object keys: tool, url.")
    assert "secret-token" not in rebuilt
    assert object_key_note("not json") == ""


async def test_schema_failure_retries_once_with_a_reminder(store, config):
    class SchemaThenStop(MockModel):
        def __init__(self):
            super().__init__()
            self.saw_note = False

        async def respond(self, role, context):
            if role == "web-test" and context.get("host_note"):
                self.saw_note = True
            if role == "web-test" and self.turns.get(role, 0) == 0 and not context.get("host_note"):
                return "not json"
            return await super().respond(role, context)

    model = SchemaThenStop()
    engine = Engine(store, config, model=model)
    assert await engine.run() == 2
    assert model.saw_note


async def test_web_test_stops_after_one_extra_finding(store, config):
    class LoopFindings(MockModel):
        def __init__(self):
            super().__init__()
            self.web_calls = 0

        async def respond(self, role, context):
            if role == "web-test":
                self.web_calls += 1
            if role == "web-test" and self.turns.get(role, 0) >= 1:
                evidence_id = next(reversed(context["evidence"]))
                return json.dumps(
                    {
                        "kind": "finding",
                        "decision": "candidate",
                        "reason": "The file index is public.",
                        "finding": {
                            "title": "Public directory index",
                            "severity": "low",
                            "category": "Information exposure",
                            "location": "http://juice-shop:3000/ftp/",
                            "evidence": [
                                {
                                    "evidence_id": evidence_id,
                                    "quote": "Public directory index: acquisitions.md",
                                }
                            ],
                            "reproduction": ["GET /ftp/ without authentication."],
                            "impact": "Visitors can see names of published files.",
                            "remediation": "Disable directory indexes and restrict access to private files.",
                        },
                    }
                )
            return await super().respond(role, context)

    class SweepRunner(FakeRunner):
        async def execute(self, tool, arguments, limits):
            result = await super().execute(tool, arguments, limits)
            if tool == "content_discovery":
                body = "This document is confidential! Do not distribute!"
                result["records"] = [
                    {
                        "url": "http://juice-shop:3000/ftp/acquisitions.md",
                        "status": 200,
                        "headers": {},
                        "body": body,
                    }
                ]
                result["stdout"] = body
            return result

    config.depth = "deep"
    engine = Engine(store, config, model=LoopFindings(), runner_factory=SweepRunner)
    assert await engine.run() == 2
    assert engine.model.web_calls == 2


async def test_deep_sweep_follows_a_listed_log(store, config):
    class ListingRunner(FakeRunner):
        def __init__(self, run_id, workspace):
            super().__init__(run_id, workspace)
            self.discoveries = 0

        async def execute(self, tool, arguments, limits):
            result = await super().execute(tool, arguments, limits)
            if tool != "content_discovery":
                return result
            self.discoveries += 1
            if self.discoveries == 1:
                body = (
                    '<title>listing directory /support/logs/</title>'
                    '<a href="access.log.2026-09-24"></a>'
                )
                url = "http://juice-shop:3000/support/logs/"
            else:
                body = '"GET /robots.txt HTTP/1.1"'
                url = "http://juice-shop:3000/support/logs/access.log.2026-09-24"
            result["records"] = [{"url": url, "status": 200, "headers": {}, "body": body}]
            result["stdout"] = body
            return result

    config.depth = "deep"
    engine = Engine(store, config, runner_factory=ListingRunner)
    assert await engine.run() == 2
    titles = {item["title"] for item in store.findings(engine.run_id)}
    assert "Access Log" in titles
    assert engine.runner.discoveries == 2


async def test_deep_sweep_records_a_host_finding(store, config):
    class SweepRunner(FakeRunner):
        async def execute(self, tool, arguments, limits):
            result = await super().execute(tool, arguments, limits)
            if tool == "content_discovery":
                body = "This document is confidential! Do not distribute!"
                result["records"] = [
                    {
                        "url": "http://juice-shop:3000/ftp/acquisitions.md",
                        "status": 200,
                        "headers": {},
                        "body": body,
                    }
                ]
                result["stdout"] = body
            return result

    config.depth = "deep"
    engine = Engine(store, config, runner_factory=SweepRunner)
    assert await engine.run() == 2
    titles = {item["title"] for item in store.findings(engine.run_id)}
    assert "Confidential Document" in titles
    assert "Public directory index" in titles


async def test_empty_runtime_exception_is_visible_in_saved_run(store, config):
    class TimedOutRunner(FakeRunner):
        async def start(self):
            raise TimeoutError()

    engine = Engine(store, config, runner_factory=TimedOutRunner)
    assert await engine.run() == 1
    assert store.run(engine.run_id)["error"] == "TimeoutError"
