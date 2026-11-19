# M.A.U.R.Y.A.

**Multi-source Analysis for Uncovering Reconnaissance & Yielding Actionable-intel**

M.A.U.R.Y.A. is an asynchronous External Attack Surface Management (EASM) and
Cyber Threat Intelligence (CTI) reconnaissance platform. Its goal is to
coordinate modular reconnaissance tasks, persist useful findings, and make
attack-surface intelligence actionable.

## Current status

- **Development milestone:** 0.30.0
- **Lifecycle:** Day 30 / 50

Days 26–29 established the foundations for reconnaissance task orchestration,
scan lifecycle management, and persistence. Day 30 adds email extraction from
text supplied by authorized sources.

### Email harvesting

The email harvester:

- extracts candidate addresses from supplied text;
- normalizes email addresses while preserving the local-part representation;
- rejects malformed or unsupported candidates;
- deduplicates addresses case-insensitively within each source text; and
- attaches the source identifier to each structured observation.

`build_email_task(source_texts)` wraps pre-collected `(source, text)` pairs in an
independent `email_harvest` orchestration task. For example:

```python
from app.services.orchestration.reconnaissance import (
    build_email_task,
    run_concurrent_reconnaissance,
)

source_texts = [
    ("https://example.com/contact", "Contact security@example.com"),
]

report = await run_concurrent_reconnaissance(
    tasks=[build_email_task(source_texts)]
)
```

This feature processes text provided by the caller; it does not fetch pages or
add a network collector. Source retrieval and authorization remain the
responsibility of the relevant collector.

### Persistence status

The `DiscoveredEmail` ORM model is present, but the Day 28 persistence
coordinator currently recognizes only the `shodan` and `tcp_ports` task names.
It does not automatically persist `email_harvest` results. Integrating email
observations with persistence requires an explicit extension of that contract
and verification against the model.

### Scope and authorization

Use M.A.U.R.Y.A. only for authorized OSINT and defensive security assessments.
Email harvesting is limited to extracting addresses from supplied source text.
It does not implement mailbox access, credential collection, email account
verification, unsolicited messaging, or indiscriminate crawling.

## Getting started

Create and activate a virtual environment, then install the development
dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

To override local defaults, create an environment file:

```bash
cp .env.example .env
```

Settings use the `MAURYA_` prefix. By default, the application uses
`sqlite+aiosqlite:///./data/osint.db` and serves its health endpoint at
`http://127.0.0.1:8000/api/v1/health`. The API prefix defaults to `/api/v1` and
can be overridden through application settings.

Run the application:

```bash
uvicorn app.main:app --reload
```

Run tests and code-quality checks:

```bash
pytest -v
ruff check .
ruff format --check .
```
