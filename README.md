# emerg

`emerg` is a local terminal application for authorized security tests of the included OWASP Juice Shop lab.
It has a full-screen Textual interface and a Typer command-line interface.
Model calls run on the host. Six typed tools run in one temporary Kali container per scan.

The application has no web interface, accounts, hosted mode, or automatic code fixes.
External scan targets are disabled. The only accepted target and allowlist entry is `http://juice-shop:3000`.

## Install

Use Python 3.12 or later. Real scans also require Docker with Linux containers and Docker Compose.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
emerg --help
```

On Linux or macOS, activate the environment with `source .venv/bin/activate`.
The package installs the `emerg` command. It also supports `python -m emergent_kali.cli`.

## Offline end-to-end demo

This demo needs no Docker, model service, or network connection after package installation.
It creates a clearly marked mock run with one validated demonstration finding.

```text
emerg scan --mock --authorization "I am authorized to test this local lab." --allowlist http://juice-shop:3000
emerg runs
emerg show RUN_ID
emerg report RUN_ID --format markdown
```

Replace `RUN_ID` with the ID from the scan output or run list.
The demo exits with code **2** because it contains a validated finding.
Use `--jsonl` to stream JSON Lines instead of plain text.

To complete the same demo in the terminal interface:

1. Run `emerg`.
2. Enter your authorization statement and the exact allowlist `http://juice-shop:3000`.
3. Enable **Offline mock run**.
4. Select **Start run**.
5. Open **Findings**, then select the finding to read its evidence and remediation.

The live view shows all five agent roles, a task timeline, and up to 200 output lines.
Use **Pause / resume**, **Cancel**, or `Ctrl+P` during a scan.
`Ctrl+C` cancels the active scan, removes its runner, and closes the interface.
The **History** tab opens findings from saved runs.
Small terminals can scroll through the setup form.

## Model configuration

Set model configuration through environment variables only.
The setup screen shows the configured model. It does not accept or store model credentials.

| Variable | Purpose | Default |
| --- | --- | --- |
| `EMERG_MODEL` | Installed or available model name | Required for real runs |
| `EMERG_MODEL_BASE_URL` | OpenAI-compatible API base URL | `http://localhost:11434/v1` |
| `EMERG_MODEL_API_KEY` | Model API credential | Empty for local Ollama |
| `EMERG_DATA_DIR` | Local state and workspace directory | Platform application data directory |

For Ollama, start its local service and install a model that can return structured JSON.
Set `EMERG_MODEL` to that model name. Example environment setup in PowerShell:

```powershell
$env:EMERG_MODEL = "your-installed-model"
$env:EMERG_MODEL_BASE_URL = "http://localhost:11434/v1"
emerg doctor
```

For Bash:

```bash
export EMERG_MODEL="your-installed-model"
export EMERG_MODEL_BASE_URL="http://localhost:11434/v1"
emerg doctor
```

Other compatible endpoints need `/chat/completions`, JSON object responses, and a `/models` health check.
Remote model endpoints require HTTPS and `EMERG_MODEL_API_KEY`.
A configured remote provider receives redacted scan context. Use local Ollama to keep model requests on this computer.
The application does not load `.env` files or pass host credentials to Docker.
The adapter rejects malformed responses instead of guessing the intended action.

## Start the real lab

Start Docker Desktop or the local Docker engine before these commands.
Image builds and pulls need internet access. The scan network blocks external traffic.

```text
docker compose -f services/compose.yaml build kali-runner
docker compose -f services/compose.yaml up -d juice-shop
emerg doctor
```

Juice Shop does not expose a host port. The runner and doctor check access it on the isolated Compose network.
Use `http://juice-shop:3000` in the allowlist.

`emerg doctor` checks Docker, Compose, the Compose file, the Kali image, installed tools, model configuration, the model endpoint, network isolation, and Juice Shop.
It reports every check even when a dependency fails. It does not start a scan or download a model.

Run a real scan after every dependency is ready:

```text
emerg scan --authorization "I am authorized to test this local Juice Shop lab." --allowlist http://juice-shop:3000 --depth standard --instructions "Probe the lab and check /ftp/ for an exposed directory index."
```

Run `emerg` for the same workflow in the terminal interface. Leave **Offline mock run** disabled.
Model decisions can differ across runs. A real scan does not guarantee a finding.
The fixed mock demo supplies a repeatable example of the complete workflow.

Stop the lab when finished:

```text
docker compose -f services/compose.yaml down
```

## Commands and exit codes

| Command | Result |
| --- | --- |
| `emerg` | Open the terminal interface |
| `emerg scan` | Run a headless scan with plain-text events |
| `emerg scan --jsonl` | Stream one JSON event per line |
| `emerg runs` | List the latest 100 runs |
| `emerg show RUN_ID` | Show a run and its validated findings |
| `emerg report RUN_ID --format markdown` | Export a Markdown report |
| `emerg report RUN_ID --format json` | Export findings and redacted evidence |
| `emerg report RUN_ID --format csv` | Export a spreadsheet-safe finding table |
| `emerg report RUN_ID --format sarif` | Export SARIF 2.1.0 |
| `emerg doctor --json` | Return dependency checks as JSON |

Reports default to the run workspace. Use `--output PATH` to choose another location.
Only validated findings enter reports. Each finding includes evidence, reproduction steps, impact, and remediation.
SARIF and CSV include evidence IDs and quoted evidence. JSON also includes the captured records.

Headless scan exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Completed with no validated findings |
| 1 | Setup error, tool error, model error, reached limit, or cancellation |
| 2 | Completed with one or more validated findings |

`Ctrl+C` cancels a headless run and removes its container.
With `--control-stdin`, enter `pause`, `resume`, or `cancel` on separate input lines.
The input control also accepts a pipe from another local process.

## Tools and limits

| Typed tool | Implementation | Restrictions |
| --- | --- | --- |
| `http_probe` | curl | HTTP GET through the scope gate |
| `port_scan` | Nmap TCP connect | Port 3000 only, no raw sockets or scripts |
| `crawl` | Python HTML link walker | Same origin, no JavaScript, at most 20 pages |
| `content_discovery` | Python HTTP requests | At most 20 explicit relative paths |
| `template_scan` | Nuclei | One bundled directory-index template, no arbitrary templates or callbacks |
| `sql_check` | sqlmap | Product search `q` parameter only, risk 1, level 1, boolean/error checks |

SQL checks need standard or deep scan depth.
They exclude stacked queries, time-delay tests, data dumps, file access, and operating-system commands.
The initial search value must contain only letters, digits, spaces, underscores, or hyphens.
The tool can only inspect the lab. It cannot accept user-supplied flags or scripts.

| Limit | Default | Accepted maximum |
| --- | --- | --- |
| Run wall time | 3600 seconds | 3600 seconds |
| One command | 30 seconds | 120 seconds in the Python configuration |
| Total captured tool output | 64 KiB | 1 MiB |
| Request rate | 2 per second | 10 per second |
| Requests per run | 100 | 1000 |
| Commands per run | 20 | 100 |
| Model responses per run | 60 | Fixed |

CLI options are `--time-limit`, `--command-limit`, `--output-limit`, `--request-rate`, and `--request-limit`.
Quick depth caps commands at six. Standard depth caps commands at 20. Deep depth uses the configured command limit.
Task model turns have depth limits of five, eight, and twelve.
Captured output includes stdout, stderr, HTTP evidence, and result metadata.
HTTP bodies are bounded excerpts. The application never saves unlimited tool output.
Each HTTP request passes through a serial gate. One Nmap connection also consumes the shared request budget.

Pause freezes the runner container and blocks further agent actions.
Wall time continues during pause. A time, command, or request limit ends the run with exit code 1.
Output past the budget is truncated, and the run continues.
The host removes the runner on completion, cancellation, or failure.
A container lifetime guard also stops an active runner after the run budget plus 30 seconds.
After a host crash while Docker is paused, remove the paused container manually with `docker rm -f emerg-RUN_ID`.

## Storage and redaction

Default state locations are `%LOCALAPPDATA%\emerg` on Windows and `~/.local/share/emerg` on Linux.
macOS uses `~/Library/Application Support/emerg`.
SQLite stores projects, targets, runs, tasks, events, findings, evidence, and artifacts.
Each run has its own `runs/RUN_ID` workspace with `audit.jsonl`, redacted evidence files, and reports.
Every approved tool command enters the audit log before execution.
Finding IDs use a stable hash of the normalized title, category, and affected location.

The same redactor handles storage, model context, terminal events, and reports.
It removes credential fields, authorization headers, cookies, common token formats, URL credentials, and configured secret values.
It also removes terminal control sequences. CSV exports protect cells from formula execution.
Raw response bodies exist only in process memory or temporary container files before host redaction.
Arbitrary unlabeled secrets cannot be identified reliably. Do not put real credentials in this disposable lab.

The Kali runner uses a non-root UID, no Linux capabilities, a read-only root filesystem, and resource limits.
Its only host mount is the current run workspace. `/tmp` uses temporary container memory.
It receives no model credentials and has no Docker socket.
The host checks container settings and network isolation before it permits tools.

## Tests

```text
python -m pytest -q
ruff check src tests
ruff format --check src tests
```

Tests use fake Docker runners and model responses. Adapter tests use an in-memory HTTP transport.
Textual pilot tests complete the mock workflow and inspect the live view and history.
The suite does not contact a model provider or require Docker.

The real Kali image and model workflow require the local dependencies listed by `emerg doctor`.
The initial implementation was tested with Python 3.14 on Windows.
Docker integration could not run in that session because the Docker daemon was stopped.

See [design decisions](docs/decisions.md) and the [model protocol](docs/model-protocol.md).
External target support remains later work. It needs a separate network policy and explicit scope design.
