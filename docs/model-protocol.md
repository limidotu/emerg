# Model response protocol

The canonical machine-readable schema is [model-response.schema.json](model-response.schema.json).
`RESPONSE_ADAPTER` in `models.py` produces this schema and validates every model response.
All objects reject unknown fields. There is no general-purpose shell tool.

Each response is one JSON object with a `kind` discriminator:

| Kind | Required fields | Authorized role |
| --- | --- | --- |
| `plan` | `tasks`: one to six role/task assignments | Coordinator at run start |
| `tool_call` | `tool`, `arguments` | Reconnaissance or web-test |
| `observation` | `summary`, optional `evidence_ids` | Reconnaissance, web-test, report |
| `finding` | `decision`, `finding`, `reason` | Candidate from a test role, verdict from validator |
| `stop` | `reason` | Test role at task end, coordinator at run end |

A coordinator plan must contain both reconnaissance and web-test work.
The validator only returns `confirmed` or `rejected` for the unchanged candidate.
The report role returns an observation about the validated findings supplied by the host.
The engine rejects out-of-role responses even when they pass schema validation.

## Example plan

```json
{
  "kind": "plan",
  "tasks": [
    {"role": "reconnaissance", "task": "Probe the lab."},
    {"role": "web-test", "task": "Check /ftp/ for an exposed directory index."}
  ]
}
```

## Example tool call

```json
{
  "kind": "tool_call",
  "tool": "http_probe",
  "arguments": {"url": "http://juice-shop:3000/ftp/"}
}
```

Tool names are `http_probe`, `port_scan`, `crawl`, `content_discovery`, `template_scan`, and `sql_check`.
Every tool needs a scoped URL. Optional arguments are `ports`, `max_pages`, and `paths`.
The port list must equal `[3000]`. The page limit is one to 20.
Content paths must start with one slash and remain within the lab origin.
Reconnaissance can request only HTTP probes, port scans, and crawling.

The host returns a saved evidence ID with bounded stdout, stderr, exit code, and captured HTTP records.
Each HTTP record contains its URL, status, filtered headers, and a body excerpt.
Evidence IDs are run-specific. The model cannot create them.

## Finding fields

A finding contains `title`, `severity`, `category`, `location`, `evidence`, `reproduction`, `impact`, and `remediation`.
Severity is `info`, `low`, `medium`, `high`, or `critical`.
Each evidence citation contains `evidence_id` and a verbatim `quote` of at least eight characters.
The host creates the stable finding ID. The model does not supply it.
All report findings need nonempty remediation and at least one citation.

## Failure behavior

Invalid JSON, excess response size, schema errors, and missing evidence end the run with exit code 1.
A tool outside the role policy does not run. The host returns that refusal to the same role.
A repeated observation ends that task. The run continues with the next task.
Web-test must return a candidate finding after a tool when the evidence supports an issue.
The host refuses one early stop so that finding can be returned.
A finding quote that does not match evidence is refused. The role can try again.
Repeated refusals end the task when the turn limit is reached, and that limit ends the run.
The application does not save raw malformed responses or provider error bodies.
The runner is removed even when parsing or validation fails.
The mock model uses this same protocol and supplies a complete offline example.
