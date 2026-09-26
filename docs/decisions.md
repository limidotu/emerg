# Design decisions

## 1. One local application and two interfaces

Typer and Textual call the same asynchronous `Engine`.
The engine owns state transitions, model turns, evidence checks, limits, and cleanup.
The terminal interface runs the engine in a Textual worker on the same event loop.
The CLI streams the same stored events as text or JSON Lines.
There is no application web service or browser interface.

SQLite uses foreign keys and write-ahead logging. Each Store owns a connection and a lock.
State changes reject invalid transitions. Terminal states cannot resume.
Interrupted records remain visible in history. The application does not silently resume a scan after a crash.

## 2. Lab scope is an exact origin

Only `http://juice-shop:3000` is valid in setup and the allowlist.
Tool URLs can add paths and queries. They cannot change the scheme, host, or port.
The policy rejects user information, fragments, control characters, and backslashes.
No hostname aliases, wildcards, IP ranges, or external targets are available.
The host and container import the same command policy source.

Compose uses an internal network shared by Juice Shop and each temporary runner.
Docker documents `internal: true` as external network isolation in its [network reference](https://docs.docker.com/reference/compose-file/networks/).
Juice Shop publishes no host port. Doctor probes it from a short-lived, locked-down Kali container on the lab network.

The runner image is a trusted local build. Models cannot choose a different image, network, mount, UID, or Docker command.
The host checks the actual container configuration before tools run.
The Docker administrator and application source are within the local trust boundary.

## 3. Typed commands and an internal HTTP gate

Agents request structured tools. A fixed dispatcher builds argument vectors and starts processes without a shell.
Command policy rejects extra fields, extra ports, unsafe content paths, and arbitrary SQL baselines.
The application records the approved command before Docker executes it.

Curl, the HTML walker, Nuclei, and sqlmap use a loopback HTTP gate inside the runner.
The gate permits only GET and HEAD to the exact lab origin.
It drops request credentials, Host overrides, response cookies, and redirect locations.
It records bounded response excerpts and applies a shared request counter and minimum interval.
The isolated network supplies a second barrier against external traffic.

Nmap uses one unprivileged TCP connection to port 3000.
It consumes one request reservation before execution and disables retries and raw socket scans.
The walker handles crawling and content discovery without a browser or executable page content.

Nuclei receives one bundled HTTP template. Updates and external callbacks are disabled.
Its fixed options follow the upstream [Nuclei command reference](https://github.com/projectdiscovery/nuclei/blob/dev/README.md).
sqlmap uses boolean and error techniques at level 1 and risk 1, with no extraction options.
The upstream [sqlmap usage guide](https://github.com/sqlmapproject/sqlmap/wiki/Usage) documents these controls and redirect handling.

The image uses Kali rolling packages, so tool versions can change on rebuild.
Juice Shop has an explicit version tag. Fully reproducible Kali builds need a later image-digest and package-version policy.

## 4. Model decisions have a strict protocol

The coordinator supplies a bounded plan with reconnaissance and web-test assignments.
Those roles request tools, record observations, propose candidate findings, and stop their assigned tasks.
The host routes every candidate through the validator before the report role receives it.
The coordinator must then return a stop decision.
Role-specific checks reject a valid JSON response when the role lacks permission for that action.

The host sends the JSON schema with each request and requests JSON object output.
Pydantic rejects missing fields, unknown fields, wrong types, and unknown decision kinds.
A malformed response fails the run. There is no automatic repair or shell fallback.
Target content is untrusted evidence, including any embedded instructions.

The adapter uses environment variables and the OpenAI-compatible chat-completions protocol.
[Ollama documents](https://github.com/ollama/ollama/blob/main/docs/api/openai-compatibility.mdx) support for this protocol and `response_format`.
Only the host can access model credentials.
The endpoint choice is independent of Docker. A remote endpoint does not enable a hosted application mode.

## 5. Validation precedes report inclusion

Findings have stable IDs from normalized title, category, and exact location.
A candidate needs an evidence ID from the same run and a verbatim quote from that location.
Failed tool output and missing evidence cannot support a finding.
The validator must return the candidate unchanged with a confirmed or rejected decision.
The host checks its evidence again before it marks the finding as validated.

Evidence checks prove provenance. The validator model assesses whether the evidence supports the security claim.
This distinction limits false claims but does not make model judgment infallible.
The report role sees only validated records. Report exporters read those records directly.
Unrestricted model summary text never creates report findings.

## 6. Budgets apply outside model judgment

The engine enforces command count, model turns, total output, and wall time.
The container enforces per-command time, bounded pipes, HTTP scope, rate, and request count.
Docker limits memory, CPU, processes, privileges, and writable paths.
The host bounds Docker client output and removes the container during cleanup.

Pause uses Docker pause and blocks further engine actions. It does not extend the deadline.
Cancel interrupts pending work, then removes the container.
The runner has a finite lifetime if the host exits without cleanup.
A paused container needs manual removal after a host crash because Docker freezes its lifetime guard too.

The output budget measures serialized tool results across the run. It excludes fixed metadata and model events.
Output past that budget is truncated to fit. The run keeps the stored excerpt.
Model events have separate schema, size, and turn limits.
The terminal output widget retains at most 200 display lines.

## 7. Redaction occurs before persistence

The redactor handles structured secret fields, labeled text, common token formats, headers, and configured environment secrets.
Evidence, audit events, findings, model context, and exports pass through it.
The runtime does not persist raw evidence in the workspace.
Tool scratch data stays in the temporary container filesystem.
Unknown secrets without labels or recognizable formats remain a detection limit.

## 8. Later work

External scan targets are explicitly out of scope for this version.
That feature needs independent authorization design, DNS and address pinning, redirect policy, and a controlled egress boundary.
It must not be enabled by replacing the current allowlist constant.

Other later work includes image digest pins, stronger finding-specific validators, and graceful recovery of interrupted runs.
No accounts, browser UI, hosted application mode, or automatic code fixes are planned here.
