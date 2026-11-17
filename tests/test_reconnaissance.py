"""Tests for reconnaissance persistence."""

from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from app.models import Base
from app.models.exposed_port import ExposedPort
from app.models.scan import Scan
from app.models.target import Target
from app.services.persistence.reconnaissance import (
    execute_scan_persistence,
    persist_reconnaissance_results,
)
from app.services.recon.shodan import (
    ShodanHostObservation,
    ShodanSearchResult,
)
from app.services.recon.tcp_probe import (
    TCPPortObservation,
    TCPPortStatus,
)


@pytest.fixture
async def db_session():
    """Provide an isolated in-memory SQLite database."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def scan_id(db_session):
    """Create a target and scan for persistence tests."""
    target = Target(domain="example.com")
    db_session.add(target)
    await db_session.flush()

    scan = Scan(target_id=target.id)
    db_session.add(scan)
    await db_session.flush()

    return scan.id


@pytest.fixture
def shodan_result():
    """Provide a sample Shodan result."""
    observation = ShodanHostObservation(
        ip="203.0.113.10",
        port=22,
        transport="tcp",
        hostnames=("example.com",),
        domains=("example.com",),
        organization="Example Org",
        product="OpenSSH",
        timestamp=None,
    )

    return ShodanSearchResult(
        domain="example.com",
        query="hostname:example.com",
        total=1,
        observations=(observation,),
    )


@pytest.mark.asyncio
async def test_persist_shodan_observation(
    db_session,
    scan_id,
    shodan_result,
):
    """Shodan observations should be persisted."""
    result = await persist_reconnaissance_results(
        session=db_session,
        scan_id=scan_id,
        shodan_result=shodan_result,
        tcp_observations=[],
    )

    assert result.inserted == 1

    records = await db_session.scalars(select(ExposedPort).where(ExposedPort.scan_id == scan_id))

    saved = list(records)

    assert len(saved) == 1
    assert saved[0].host == "203.0.113.10"
    assert saved[0].port == 22
    assert saved[0].protocol == "tcp"


@pytest.mark.asyncio
async def test_persist_open_tcp_observation(
    db_session,
    scan_id,
):
    """Open TCP observations should be persisted."""
    shodan = ShodanSearchResult(
        domain="example.com",
        query="hostname:example.com",
        total=0,
        observations=(),
    )

    tcp = TCPPortObservation(
        host="203.0.113.20",
        port=80,
        status=TCPPortStatus.OPEN,
        latency_ms=12.5,
        service_name="http",
        service_confidence="high",
    )

    result = await persist_reconnaissance_results(
        db_session,
        scan_id,
        shodan,
        [tcp],
    )

    assert result.inserted == 1

    saved = await db_session.scalar(select(ExposedPort).where(ExposedPort.scan_id == scan_id))

    assert saved is not None
    assert saved.port == 80
    assert saved.service_name == "http"


@pytest.mark.asyncio
async def test_closed_tcp_observation_is_ignored(
    db_session,
    scan_id,
):
    """Closed ports should not be persisted as exposed ports."""
    shodan = ShodanSearchResult(
        domain="example.com",
        query="hostname:example.com",
        total=0,
        observations=(),
    )

    tcp = TCPPortObservation(
        host="203.0.113.20",
        port=81,
        status=TCPPortStatus.CLOSED,
        latency_ms=1.0,
    )

    result = await persist_reconnaissance_results(
        db_session,
        scan_id,
        shodan,
        [tcp],
    )

    assert result.inserted == 0
    assert result.total_processed == 0


@pytest.mark.asyncio
async def test_repeated_persistence_does_not_duplicate(
    db_session,
    scan_id,
    shodan_result,
):
    """Repeated calls should not duplicate an endpoint."""
    first = await persist_reconnaissance_results(
        db_session,
        scan_id,
        shodan_result,
        [],
    )

    second = await persist_reconnaissance_results(
        db_session,
        scan_id,
        shodan_result,
        [],
    )

    assert first.inserted == 1
    assert second.unchanged == 1

    count = await db_session.scalar(
        select(func.count()).select_from(ExposedPort).where(ExposedPort.scan_id == scan_id)
    )

    assert count == 1


@pytest.mark.asyncio
async def test_missing_scan_raises_value_error(
    db_session,
    shodan_result,
):
    """Unknown scan IDs should be rejected."""
    with pytest.raises(ValueError, match="does not exist"):
        await persist_reconnaissance_results(
            db_session,
            uuid4(),
            shodan_result,
            [],
        )


@pytest.mark.asyncio
async def test_shodan_domain_must_match_scan_target(
    db_session,
    scan_id,
    shodan_result,
):
    """Shodan observations for another domain should be rejected."""
    mismatched_result = ShodanSearchResult(
        domain="other.example",
        query="hostname:other.example",
        total=1,
        observations=shodan_result.observations,
    )

    with pytest.raises(ValueError, match="does not match the scan target"):
        await persist_reconnaissance_results(
            db_session,
            scan_id,
            mismatched_result,
            [],
        )

    count = await db_session.scalar(
        select(func.count()).select_from(ExposedPort).where(ExposedPort.scan_id == scan_id)
    )
    assert count == 0


@pytest.mark.asyncio
async def test_execute_scan_persistence_commits(
    db_session,
    scan_id,
    shodan_result,
):
    """The service-layer entry point should commit successful persistence."""
    result = await execute_scan_persistence(
        db_session,
        scan_id,
        shodan_result,
        [],
    )

    assert result.inserted == 1
    assert not db_session.in_transaction()

    count = await db_session.scalar(
        select(func.count()).select_from(ExposedPort).where(ExposedPort.scan_id == scan_id)
    )
    assert count == 1


@pytest.mark.asyncio
async def test_execute_scan_persistence_rolls_back_on_commit_failure(
    db_session,
    scan_id,
    shodan_result,
    monkeypatch,
):
    """Failed commits should roll back staged reconnaissance records."""

    async def fail_commit():
        raise RuntimeError("commit failed")

    monkeypatch.setattr(db_session, "commit", fail_commit)

    with pytest.raises(RuntimeError, match="commit failed"):
        await execute_scan_persistence(
            db_session,
            scan_id,
            shodan_result,
            [],
        )

    count = await db_session.scalar(
        select(func.count()).select_from(ExposedPort).where(ExposedPort.scan_id == scan_id)
    )
    assert count == 0


@pytest.mark.asyncio
async def test_empty_observations_return_zero_counts(
    db_session,
    scan_id,
):
    """An empty result should not create database records."""
    empty_result = ShodanSearchResult(
        domain="example.com",
        query="hostname:example.com",
        total=0,
        observations=(),
    )

    result = await persist_reconnaissance_results(
        db_session,
        scan_id,
        empty_result,
        [],
    )

    assert result.inserted == 0
    assert result.updated == 0
    assert result.unchanged == 0
    assert result.total_processed == 0
