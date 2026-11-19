# M.A.U.R.Y.A.

**Multi-source Analysis for Uncovering Reconnaissance & Yielding Actionable-intel**

Modern OSINT & Threat Recon Dashboard.

## Mission

M.A.U.R.Y.A. is an asynchronous External Attack Surface Management
(EASM) and Cyber Threat Intelligence (CTI) reconnaissance platform.

Longer-term goals include:

- asynchronous network collection;
- modular OSINT workers;
- relational intelligence persistence;
- fault-isolated reconnaissance tasks;
- operational attack-surface visualization;
- structured forensic export.

## Current Status

Development milestone: 0.29.0

Lifecycle: Day 29 / 50

Days 26–28 introduced persistence, concurrent reconnaissance execution, and transaction management.

Day 29 introduces a formal lifecycle for the Scan model.

The existing scan statuses are:

PENDING

RUNNING

COMPLETED

FAILED

The lifecycle service will control transitions between these states.

Expected lifecycle

          Scan Created
               |
               v
            PENDING
               |
               v
            RUNNING
            /     \
           /       \
          v         v
     COMPLETED    FAILED

A scan should not be marked COMPLETED simply because the reconnaissance tasks have finished. Its required persistence operations must also have succeeded.

Day 29 deliverables

Implement a dedicated scan lifecycle service.

Implement validated status transitions.

Set started_at when a scan enters RUNNING.

Set completed_at when a scan reaches a terminal state.

Prevent invalid transitions.

Handle execution and persistence failures consistently.

Add lifecycle unit and database integration tests.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Create a local environment file if you want to override the defaults:

```bash
cp .env.example .env
```

The app reads settings with the `MAURYA_` prefix. By default, it uses
`sqlite+aiosqlite:///./data/osint.db` and serves the health endpoint at
`http://127.0.0.1:8000/api/v1/health`. The API prefix defaults to `/api/v1`;
it can be overridden through application settings.

Run the app:

```bash
uvicorn app.main:app --reload
```

Run tests and code-quality checks:

```bash
pytest -v
ruff check .
ruff format --check .
```
