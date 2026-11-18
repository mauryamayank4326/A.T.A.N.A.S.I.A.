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

Development milestone: 0.28.0

Lifecycle: Day 28 / 50

Day 28 establishes reliable transaction management for reconnaissance data.

The application now has three relevant capabilities:

Day 26: reconnaissance observations can be persisted through SQLAlchemy.

Day 27: independent reconnaissance tasks can execute concurrently and produce a structured execution report.

Day 28: successful reconnaissance results can be persisted atomically.

The persistence layer must not commit individual observations independently. If an operation fails halfway through, previously inserted observations from the same persistence operation must not remain committed.

Day 28 deliverables

Add an orchestration-level persistence coordinator.

Validate the reconnaissance execution report before database writes.

Persist successful Shodan and TCP results within one transaction.

Roll back the transaction when persistence raises an exception.

Preserve the Day 26 persistence service's flush-only behavior.

Add tests for successful commits, rollbacks, and unsuccessful reconnaissance tasks.

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
