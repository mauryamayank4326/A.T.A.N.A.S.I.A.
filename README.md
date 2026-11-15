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

Development milestone: 0.24.0

Lifecycle: Day 24 / 50

Day 24 strengthens the TCP reconnaissance implementation developed during Days 22 and 23.

Day 22 established asynchronous TCP connection probing. Day 23 extended successful open-port observations with initial banner collection and confidence-qualified service identification.

The supplied implementation already contains these capabilities. Day 24 should improve their reliability rather than introduce another independent scanner.

Objectives

Correct service-classification ordering for ambiguous and recognizable banners.

Preserve the distinction between observed evidence and conventional port hints.

Verify that banner collection respects its byte and timeout limits.

Verify reliable connection cleanup after successful and unsuccessful reads.

Test enrichment of open-port observations.

Ensure closed, filtered, and error observations remain unchanged.

Expand regression coverage without breaking Day 22 behavior.

Scope boundary: No vulnerability detection, exploitation, authentication attempts, or intrusive protocol negotiation.
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
