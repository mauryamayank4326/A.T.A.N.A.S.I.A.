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

Development milestone: 0.27.0

Lifecycle: Day 27 / 50

The objective of Day 27 is to introduce a centralized asynchronous orchestration engine responsible for coordinating independent reconnaissance operations.

Previously, reconnaissance services could be invoked individually:

Certificate Transparency discovery.

WHOIS lookups.

Shodan host searches.

TCP port probing.

TCP service identification.

Sequential execution increases total scan duration because independent operations wait for one another unnecessarily.

Day 27 introduces concurrent execution.

Instead of:

Start Shodan
    |
    v
Wait for Shodan
    |
    v
Start TCP probing
    |
    v
Wait for TCP probing
    |
    v
Finish

M.A.U.R.Y.A. will support:

             Reconnaissance Orchestrator
                       |
          +------------+------------+
          |            |            |
          v            v            v
       Shodan         TCP         WHOIS
       Search        Probing      Lookup
          |            |            |
          +------------+------------+
                       |
                       v
              Execution Results
                       |
                       v
               Recon Summary
                       |
                       v
               Persistence Layer

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
