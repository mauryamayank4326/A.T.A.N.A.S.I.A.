# M.A.U.R.Y.A.

**Modern Automated Reconnaissance, Unification, Reporting, and Yielding Assistant**

M.A.U.R.Y.A. is a Python-based external attack surface management and cyber threat intelligence platform. It provides an asynchronous FastAPI backend for orchestrating reconnaissance tasks, tracking scans and targets, and persisting discovery data in SQLite.

## Features

- **Concurrent reconnaissance orchestration** with configurable concurrency and per-task timeouts
- **Scan lifecycle management** for pending, running, completed, and failed scans
- **Shodan host search** using an optional API key
- **TCP port probing** across a default set of common service ports
- **Email extraction** from caller-supplied text, with normalization and deduplicated observations
- **Passive reconnaissance helpers** for certificate, WHOIS, and DNS-oriented discovery
- **Async SQLite persistence** through SQLAlchemy and aiosqlite
- **Structured API errors** and request ID logging
- **Health reporting** that verifies database connectivity
- **Environment-backed configuration** with Pydantic settings validation

## Current status

- **Development milestone:** 0.36.0
- **Lifecycle:** Day 36 / 50

By the end of Day 36, the application should have:
1. Chart.js integrated into the existing dashboard.
2. A versioned analytics API endpoint.
3. A backend analytics service that aggregates persisted reconnaissance data.
4. A dashboard analytics section.
5. A first chart showing scan-status distribution.
6. A second chart showing reconnaissance asset distribution.
7. Tests for analytics aggregation and API responses.
Expected result: M.A.U.R.Y.A. can display a visual summary of its collected reconnaissance data without exposing raw database records unnecessarily.

### Dashboard design direction

The interface will follow a security operations center (SOC) aesthetic:

- Dark background.
- High-contrast typography.
- Subtle borders and panels.
- Clear operational status indicators.
- Responsive navigation.
- Compact data tables.
- Minimal decorative elements.

The dashboard, Jinja2 templates, and static asset directories are not yet present in the current application.

## Technology stack

- Python 3.10+
- FastAPI
- Pydantic and Pydantic Settings
- SQLAlchemy 2.x with async SQLite
- HTTPX
- Uvicorn
- pytest and Ruff

## Project structure

```text
app/
├── api/v1/          # Health and scan API routes
├── core/            # Database and observability setup
├── models/          # SQLAlchemy persistence models
├── schemas/         # Request and response models
├── services/
│   ├── lifecycle/   # Scan lifecycle coordination
│   ├── orchestration/ # Concurrent reconnaissance and persistence
│   ├── persistence/ # Reconnaissance result storage
│   └── recon/       # Shodan, TCP, WHOIS, email, and passive collectors
tests/               # Unit and integration tests
data/                # Local SQLite database
```

## Getting started

### Requirements

- Python 3.10 or newer
- A virtual environment tool such as `venv`

### Installation

```bash
git clone https://github.com/mauryamayank4326/A.T.A.N.A.S.I.A.git
cd A.T.A.N.A.S.I.A

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

### Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

The application reads settings with the `MAURYA_` prefix:

| Setting | Default | Description |
| --- | --- | --- |
| `MAURYA_APP_NAME` | `M.A.U.R.Y.A.` | Application name |
| `MAURYA_ENVIRONMENT` | `development` | `development`, `test`, `staging`, or `production` |
| `MAURYA_DEBUG` | `false` | Enable FastAPI debug behavior |
| `MAURYA_LOG_LEVEL` | `INFO` | Logging level |
| `MAURYA_API_PREFIX` | `/api/v1` | Versioned API prefix |
| `MAURYA_DATABASE_URL` | `sqlite+aiosqlite:///./data/osint.db` | Async SQLite database URL |
| `MAURYA_SHODAN_API_KEY` | unset | Enables Shodan reconnaissance |
| `MAURYA_HTTP_TIMEOUT_SECONDS` | `10.0` | HTTP task timeout |
| `MAURYA_MAX_CONCURRENCY` | `20` | Maximum concurrent reconnaissance tasks |

Only `sqlite+aiosqlite` database URLs are accepted.

### Running the API

```bash
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`.

- OpenAPI documentation: <http://127.0.0.1:8000/docs>
- ReDoc: <http://127.0.0.1:8000/redoc>
- Health check: `http://127.0.0.1:8000/api/v1/health`

## API

### Health check

```http
GET /api/v1/health
```

Example response:

```json
{
  "status": "ok",
  "service": "maurya",
  "database": "connected"
}
```

### Create a scan

The current API creates a scan for an existing target:

```http
POST /api/v1/scans
Content-Type: application/json

{
  "target_id": "00000000-0000-0000-0000-000000000000"
}
```

Response status: `201 Created`

When `MAURYA_SHODAN_API_KEY` is configured, a new scan runs the Shodan and TCP port reconnaissance tasks concurrently. Without a Shodan key, the scan remains persisted with no reconnaissance tasks launched.

The public target-management endpoints are not yet implemented, so test and application code that creates targets must use the target model or database session directly.

## Reconnaissance modules

| Module | Purpose |
| --- | --- |
| `recon/shodan.py` | Searches Shodan for hosts associated with a domain |
| `recon/tcp_probe.py` | Probes common TCP ports asynchronously |
| `recon/email_harvester.py` | Extracts and deduplicates email observations from supplied text |
| `recon/whois_lookup.py` | Performs WHOIS lookups |
| `recon/crtsh.py` | Queries certificate transparency data |
| `recon/passive_recon.py` | Provides passive DNS and related discovery helpers |
| `recon/recon_summary.py` | Combines and summarizes reconnaissance results |

The recon modules are defensive building blocks. Each external request must only be made against systems the operator is authorized to assess.

### Email harvesting example

Email harvesting operates only on text already collected by the caller:

```python
from app.services.orchestration.reconnaissance import (
    build_email_task,
    run_concurrent_reconnaissance,
)

source_texts = [
    ("https://example.com/contact", "Contact security@example.com"),
]

report = await run_concurrent_reconnaissance(tasks=[build_email_task(source_texts)])

print(report.results)
```

The module does not crawl pages, access mailboxes, verify accounts, send email, or collect credentials.

## Persistence

M.A.U.R.Y.A. stores targets, scans, subdomains, exposed ports, and discovered emails using SQLAlchemy models. The database is initialized automatically during the FastAPI application lifespan.

The persistence coordinator currently recognizes the `shodan` and `tcp_ports` task names. Email-harvest observations are represented by `DiscoveredEmail`, but their orchestration/persistence integration is not complete.

## Testing and quality checks

Run the test suite:

```bash
pytest -v
```

Run lint and formatting checks:

```bash
ruff check .
ruff format --check .
```

Format source and test files:

```bash
ruff format .
```

## Authorization and responsible use

Use M.A.U.R.Y.A. only with explicit authorization for the targets and systems assessed. Obtain approval before:

- Running network scans
- Accessing third-party intelligence providers
- Crawling or collecting public-source content
- Performing repeated or high-volume reconnaissance

The operator is responsible for complying with applicable law, provider terms, rate limits, and organizational scope.

## Development status

The backend API, database models, orchestration framework, reconnaissance services, and test suite are implemented. A dashboard and public target-management API are not yet part of the current application.
