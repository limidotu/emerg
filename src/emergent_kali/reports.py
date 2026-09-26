from __future__ import annotations

import csv
import io
import json
import uuid
from pathlib import Path

from .redaction import redact
from .store import Store


def markdown_text(value: str) -> str:
    return value.replace("<", "&lt;").replace(">", "&gt;").replace("`", "\\`").replace("#", "\\#")


def report_data(store: Store, run_id: str) -> dict:
    run = store.run(run_id)
    findings = store.findings(run_id)
    all_evidence = store.evidence(run_id)
    used = {citation["evidence_id"] for f in findings for citation in f["evidence"]}
    for finding in findings:
        if not finding.get("remediation") or not finding.get("evidence"):
            raise ValueError("A report finding has no evidence or remediation.")
        if any(c["evidence_id"] not in all_evidence for c in finding["evidence"]):
            raise ValueError("A report finding references missing evidence.")
    return redact(
        {
            "run": {
                "id": run_id,
                "state": run["state"],
                "created": run["created"],
                "target": run["config"]["target"],
                "mock": run["config"]["mock"],
            },
            "findings": findings,
            "evidence": {key: all_evidence[key] for key in sorted(used)},
        }
    )


def render_report(data: dict, format: str) -> str:
    data = redact(data)
    findings = data["findings"]
    if format == "json":
        return json.dumps(data, indent=2) + "\n"
    if format == "markdown":
        lines = [
            "# emerg security report",
            "",
            f"Run: {data['run']['id']}",
            f"State: {data['run']['state']}",
            f"Target: {data['run']['target']}",
            f"Mock data: {data['run']['mock']}",
            "",
            f"Validated findings: {len(findings)}",
            "",
        ]
        for finding in findings:
            lines += [
                f"## {markdown_text(finding['title'])}",
                "",
                f"ID: {finding['id']}",
                f"Severity: {finding['severity']}",
                f"Category: {markdown_text(finding['category'])}",
                f"Location: {markdown_text(finding['location'])}",
                "",
            ]
            if finding.get("plain"):
                lines += ["### Simple", "", markdown_text(finding["plain"]), ""]
            lines += [
                "### Impact",
                "",
                markdown_text(finding["impact"]),
                "",
                "### Remediation",
                "",
                markdown_text(finding["remediation"]),
                "",
                "### Reproduction",
                "",
            ]
            lines += [f"{i}. {markdown_text(step)}" for i, step in enumerate(finding["reproduction"], 1)]
            lines += ["", "### Evidence", ""]
            for citation in finding["evidence"]:
                lines += [
                    f"Evidence: {citation['evidence_id']}",
                    "",
                    "> " + markdown_text(citation["quote"]).replace("\n", "\n> "),
                    "",
                ]
        return "\n".join(lines) + "\n"
    if format == "csv":
        output = io.StringIO(newline="")
        columns = [
            "id",
            "title",
            "severity",
            "category",
            "location",
            "evidence",
            "reproduction",
            "impact",
            "remediation",
        ]
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        for finding in findings:
            row = {
                key: json.dumps(finding[key]) if isinstance(finding[key], list) else str(finding[key])
                for key in columns
            }
            # Stop spreadsheet formula execution when users open a CSV report.
            row = {
                key: "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value
                for key, value in row.items()
            }
            writer.writerow(row)
        return output.getvalue()
    if format == "sarif":
        rules = [
            {"id": f["id"], "shortDescription": {"text": f["title"]}, "help": {"text": f["remediation"]}}
            for f in findings
        ]
        results = [
            {
                "ruleId": f["id"],
                "level": {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "info": "note",
                }[f["severity"]],
                "message": {"text": f["title"] + ": " + f["impact"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["location"]}}}],
                "partialFingerprints": {"emergStableId": f["id"]},
                "properties": {
                    "evidence": f["evidence"],
                    "remediation": f["remediation"],
                    "reproduction": f["reproduction"],
                    "category": f["category"],
                },
            }
            for f in findings
        ]
        return (
            json.dumps(
                {
                    "version": "2.1.0",
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "emerg", "version": "0.1.0", "rules": rules}},
                            "properties": data["run"],
                            "results": results,
                        }
                    ],
                },
                indent=2,
            )
            + "\n"
        )
    raise ValueError("Format must be markdown, json, csv, or sarif.")


def export_report(store: Store, run_id: str, format: str, destination: Path) -> Path:
    content = render_report(report_data(store, run_id), format)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    store.execute(
        "INSERT INTO artifacts VALUES(?,?,?,?)",
        (uuid.uuid4().hex, run_id, str(destination.resolve()), format),
    )
    return destination
