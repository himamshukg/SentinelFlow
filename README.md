# SentinelFlow

An AI Agent Security Gateway. Agents may *propose* tool calls. A deterministic policy engine in the backend decides `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. Mock tools run only after `ALLOW`. The HTTP API never trusts a client-supplied decision.

This repository uses synthetic dummy files, a fake mailbox, and a fake ledger. It does not send email, delete real files, or move money.

## Architecture and API

The React dashboard sends proposals to the FastAPI backend. The backend binds each request to a server-configured agent credential, validates the proposal with the policy engine, then either blocks it, places it in the in-memory approval queue, or calls a simulated tool after an `ALLOW` decision. Audit events are stored in SQLite. The browser is not an authorization boundary.

| Method and endpoint | Purpose | Access |
|---|---|---|
| `GET /api/health` | Health/version check | Public |
| `GET /api/scenarios` | List predefined simulations | Public |
| `GET /api/identity` | Resolve the bearer credential to an agent ID | Agent credential |
| `POST /api/evaluate` | Evaluate and, only when allowed, run a simulated action | Agent credential |
| `GET /api/events` | Read filtered audit events for the authenticated agent | Agent credential |
| `GET /api/pending` | List that agent's pending approvals | Agent credential |
| `POST /api/requests/{request_id}/approve` | Approve a pending action | Agent credential and separate approval token |
| `POST /api/requests/{request_id}/deny` | Deny a pending action | Agent credential and separate approval token |

SentinelFlow is a local demonstration, not a production security gateway. Before hosting it on a public network, a deployment needs HTTPS and suitable secret management, and must account for the lack of rate limiting, expiring user sessions, durable pending approvals, and request idempotency. SQLite must live on persistent storage and be shared consistently with the backend; this setup is intended for one host and is not configured for horizontally scaled instances. No real-world tool integration is included.

## Installation

Python 3.10 or newer.

```powershell
cd SentinelFlow
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

That installs the package plus FastAPI, Uvicorn, pytest, and httpx. Python dependencies use minimum version ranges in `pyproject.toml`; there is no Python lockfile, so installations are not bit-for-bit reproducible across dates.

## Environment setup

Configuration variables:

| Variable | Meaning | Default |
|---|---|---|
| `SENTINELFLOW_ENV` | `development` or `production` | `development` |
| `SENTINELFLOW_CORS_ORIGINS` | Comma-separated browser origins | In development: `http://localhost:5173` and `http://127.0.0.1:5173`. In production: empty (no wildcard). |
| `SENTINELFLOW_MAX_BODY_BYTES` | Max JSON body size | `16384` |
| `SENTINELFLOW_APPROVAL_TOKEN` | Bearer token required by HTTP approve/deny endpoints | Unset (approval endpoints disabled) |
| `SENTINELFLOW_AGENT_TOKENS` | JSON object mapping agent IDs to unique bearer credentials (each at least 32 characters) | Unset (protected API routes return 503) |
| `SENTINELFLOW_AUDIT_DB_PATH` | SQLite database file for audit events | `data/sentinelflow-audit.sqlite3` under the project root |

Production must set explicit origins. `*` is stripped when `SENTINELFLOW_ENV=production`.

```powershell
$env:SENTINELFLOW_ENV = "development"
$env:SENTINELFLOW_CORS_ORIGINS = "http://localhost:5173"
$env:SENTINELFLOW_AGENT_TOKENS = '{"docs_agent":"replace-with-a-random-token-of-at-least-32-chars","mail_agent":"replace-with-another-random-token-of-at-least-32-chars","ops_agent":"replace-with-another-random-token-of-at-least-32-chars","finance_agent":"replace-with-another-random-token-of-at-least-32-chars"}'
$env:SENTINELFLOW_APPROVAL_TOKEN = "replace-with-a-separate-random-token-of-at-least-32-chars"
$env:SENTINELFLOW_AUDIT_DB_PATH = "data/sentinelflow-audit.sqlite3"
```

Use unique random credentials for each agent and a separate random approval token. Never commit real values. Generate values locally with Python's `secrets` module (for example, `py -c "import secrets; print(secrets.token_urlsafe(32))"`) and set them in the shell or service environment before starting the API. `.env.example` is a template only; the backend does not load dotenv files automatically. The frontend asks for an agent credential at runtime and keeps it in page memory only. Do not put agent credentials in Vite variables, source files, or browser storage.

For a quick local setup in one PowerShell window, generate one token per mock agent and a separate approval token, then start the backend in that same window:

```powershell
$docsToken = py -c "import secrets; print(secrets.token_urlsafe(32))"
$mailToken = py -c "import secrets; print(secrets.token_urlsafe(32))"
$opsToken = py -c "import secrets; print(secrets.token_urlsafe(32))"
$financeToken = py -c "import secrets; print(secrets.token_urlsafe(32))"
$env:SENTINELFLOW_AGENT_TOKENS = (@{ docs_agent = $docsToken; mail_agent = $mailToken; ops_agent = $opsToken; finance_agent = $financeToken } | ConvertTo-Json -Compress)
$env:SENTINELFLOW_APPROVAL_TOKEN = py -c "import secrets; print(secrets.token_urlsafe(32))"
.\.venv\Scripts\python.exe -m uvicorn sentinelflow.api:app --host 127.0.0.1 --port 8000
```

Keep `$docsToken` available in that shell for API examples. To copy it into the browser dashboard, run `Write-Output $docsToken` and paste it into the credential field for `docs_agent`; use the corresponding variable for another selected agent. The separate approval token is only needed for approval API operations.

The JSON `agent_id` in an evaluate request is checked against the identity mapped from the bearer credential. It is not accepted as proof of identity. Health and predefined scenario listing are public; `/api/identity`, evaluate, event retrieval, pending approval retrieval, and approval mutations require an agent bearer credential. `/api/identity` reports only the agent ID mapped to the supplied credential, so the dashboard can tell you which agent is connected. Policy evaluation remains mandatory after authentication. Approval mutations additionally require the separate `X-Approval-Token` value; the agent token alone cannot approve a request. Pending approvals currently exist in memory and are lost when the backend restarts.

The audit database schema is created automatically when the audit log is first used. Relative database paths are resolved from the project root; the default file is `<project-root>/data/sentinelflow-audit.sqlite3`. SQLite comes from Python's standard library, so no database package or service is required. Database files are ignored by Git. Audit rows retain the event arguments for review, while API responses continue to redact sensitive values; protect the database file and its backups using appropriate filesystem permissions because SQLite does not encrypt them by default.

### Audit behavior around simulated execution

For an `ALLOW` decision (including an approved pending request), SentinelFlow first inserts and commits an `execution_started` audit row. Only after that write succeeds does the gateway call the simulated tool. When the tool returns or raises, the gateway updates that same row in a separate short SQLite transaction; it does not hold a database transaction open while the tool runs. A simulated tool failure is recorded as unsuccessful with a generic error message.

If the initial audit write fails, the API returns HTTP `503` with code `audit_unavailable`, and the action is not run. If the tool has already run but SQLite cannot save the final outcome, the response remains a structured evaluation result with `audit_integrity_error: true` and a message that the action may have run. The row remains marked `execution_started`; the dashboard labels that outcome unknown. Check the audit database and simulated tool state before manually retrying.

The API does not implement idempotency keys for `/api/evaluate`: repeating a request creates a new request and may run the simulated action again. Approval requests are claimed in process before execution, so a repeated approval does not re-run a request already attempted; pending approvals are in memory, and this is not a cross-process or restart-safe exactly-once guarantee. These guarantees apply only to the current local simulated tools, not to real side effects or a distributed deployment.

## Run the API locally

```powershell
.\.venv\Scripts\python.exe -m uvicorn sentinelflow.api:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs for the interactive schema. OpenAPI is generated from the same Pydantic models the server uses.

## Example requests

Health:

```powershell
curl http://127.0.0.1:8000/api/health
```

```json
{"status": "ok", "version": "0.1.0"}
```

List attack simulations (descriptions only; email bodies are redacted):

```powershell
curl http://127.0.0.1:8000/api/scenarios
```

Evaluate a permitted read. The policy engine authorizes this, then a mock file is read:

```powershell
curl -X POST http://127.0.0.1:8000/api/evaluate -H "Authorization: Bearer $docsToken" -H "Content-Type: application/json" -d "{\"action\":\"read_file\",\"arguments\":{\"path\":\"/workspace/docs/readme.md\"},\"agent_id\":\"docs_agent\"}"
```

Include the matching agent credential in the `Authorization` header (shown in PowerShell using a `$docsToken` variable set to the server-configured `docs_agent` token):

```powershell
curl -H "Authorization: Bearer $docsToken" http://127.0.0.1:8000/api/events
curl -X POST http://127.0.0.1:8000/api/evaluate -H "Authorization: Bearer $docsToken" -H "Content-Type: application/json" -d "{\"action\":\"read_file\",\"arguments\":{\"path\":\"/workspace/docs/readme.md\"},\"agent_id\":\"docs_agent\"}"
```

```json
{
  "request_id": "req-1",
  "decision": "ALLOW",
  "rule_id": "ALLOW_READ_FILE",
  "reason": "Agent 'docs_agent' may read '/workspace/docs/readme.md'.",
  "executed": true,
  "execution_success": true,
  "pending": false,
  "error": null,
  "audit_integrity_error": false,
  "output": {"status": "ok", "path": "/workspace/docs/readme.md", "content": "[redacted]"}
}
```

A restricted read is evaluated the same way using the matching `docs_agent` credential. The API still returns HTTP 200: the request was valid, and the **decision** is `BLOCK`. The mock does not run.

```powershell
curl -X POST http://127.0.0.1:8000/api/evaluate -H "Authorization: Bearer $docsToken" -H "Content-Type: application/json" -d "{\"action\":\"read_file\",\"arguments\":{\"path\":\"/workspace/hr/salaries.txt\"},\"agent_id\":\"docs_agent\"}"
```

Recent audit events (newest first). Filter with `decision` and `action`, cap with `limit`:

```powershell
curl -H "Authorization: Bearer $docsToken" "http://127.0.0.1:8000/api/events?decision=BLOCK&limit=20"
```

Events are stored in SQLite and now include a UTC `timestamp` field in the existing event response.

List pending approval requests (sensitive argument values are redacted), then approve or deny one with the configured bearer token:

```powershell
curl -H "Authorization: Bearer $docsToken" http://127.0.0.1:8000/api/pending
curl -X POST http://127.0.0.1:8000/api/requests/req-1/approve -H "Authorization: Bearer $docsToken" -H "X-Approval-Token: $env:SENTINELFLOW_APPROVAL_TOKEN"
curl -X POST http://127.0.0.1:8000/api/requests/req-2/deny -H "Authorization: Bearer $docsToken" -H "X-Approval-Token: $env:SENTINELFLOW_APPROVAL_TOKEN"
```

Both an agent credential and the separate approval token are required for approval mutations. If the approval token is unset, HTTP approvals return `503` and do not change pending requests. Invalid or missing credentials return `401`.

Sending `"decision": "ALLOW"` in the evaluate body is rejected with HTTP 422. Extra fields are forbidden so the client cannot smuggle an authorization result.

## Run the test suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m sentinelflow.scenarios
```

## Run the React dashboard

The Vite frontend lives in `frontend/`. In a second PowerShell window, install its dependencies and start the dev server:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

Open http://127.0.0.1:5173. The frontend uses `http://127.0.0.1:8000` as its local API default. To change it, copy `frontend/.env.example` to `frontend/.env.local` and set `VITE_API_BASE_URL` to the backend origin. Vite exposes `VITE_` variables to browser code, so do not put secrets in them.

The backend's development CORS defaults already allow `http://127.0.0.1:5173`. For a different frontend origin, set `SENTINELFLOW_CORS_ORIGINS` on the backend to the exact permitted origin.

Build the frontend for a production bundle with:

```powershell
cd frontend
npm.cmd run build
```

## Default mock agents

| Agent | Tool | Typical result |
|---|---|---|
| `docs_agent` | `read_file` under `/workspace/docs` | ALLOW |
| `mail_agent` | `send_email` to `company.com` | ALLOW |
| `mail_agent` | `send_email` outside `company.com` | REQUIRE_APPROVAL |
| `ops_agent` | `delete_file` under `/workspace/tmp` | REQUIRE_APPROVAL |
| `finance_agent` | `transfer_funds` above 1000 | REQUIRE_APPROVAL |
| anyone | unknown tool | BLOCK |
