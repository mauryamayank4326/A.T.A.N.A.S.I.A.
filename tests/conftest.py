import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.database import create_database_engine, create_session_factory
from app.main import create_app
from app.models import Base, Target
from app.models.scan import Scan, ScanStatus


@pytest.fixture
async def session(tmp_path: Path) -> AsyncGenerator[AsyncSession, None]:
    database_path = tmp_path / "models.db"
    settings = Settings(
        environment="test",
        debug=False,
        database_url=f"sqlite+aiosqlite:///{database_path}",
    )
    engine = create_database_engine(settings)

    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        session_factory = create_session_factory(engine)

        async with session_factory() as database_session:
            yield database_session
    finally:
        await engine.dispose()


@pytest.fixture
async def db_session(session: AsyncSession) -> AsyncGenerator[AsyncSession, None]:
    yield session


@pytest.fixture
async def scan_factory(db_session: AsyncSession):
    """Create scans with a valid target for lifecycle tests."""

    async def create_scan(status: ScanStatus = ScanStatus.PENDING) -> Scan:
        target = Target(domain=f"{uuid4().hex}.example")
        db_session.add(target)
        await db_session.flush()

        scan = Scan(target_id=target.id, status=status)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)
        return scan

    return create_scan


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Create a FastAPI client backed by an isolated SQLite database."""
    settings = Settings(
        app_name="M.A.U.R.Y.A. Test",
        environment="test",
        debug=False,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        shodan_api_key=None,
    )
    application = create_app(settings)

    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture
async def async_client(tmp_path: Path) -> AsyncGenerator[AsyncClient, None]:
    """Create an async FastAPI client backed by an isolated SQLite database."""
    settings = Settings(
        app_name="M.A.U.R.Y.A. Async Test",
        environment="test",
        debug=False,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'async-api.db'}",
        shodan_api_key=None,
    )
    application = create_app(settings)

    async with application.router.lifespan_context(application):
        transport = ASGITransport(app=application)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as test_client:
            yield test_client


@pytest.fixture
def target(client: TestClient) -> Target:
    """Persist a valid target for scan-creation requests."""

    async def create_target() -> Target:
        async with client.app.state.db_session_factory() as database_session:
            created_target = Target(domain="example.com")
            database_session.add(created_target)
            await database_session.commit()
            await database_session.refresh(created_target)
            return created_target

    return asyncio.run(create_target())
