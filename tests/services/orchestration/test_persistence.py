import pytest

from app.services.orchestration.persistence import (
    ReconnaissancePersistenceError,
    persist_execution_report,
)
from app.services.orchestration.reconnaissance import (
    ReconExecutionReport,
    ReconTaskResult,
    ReconTaskStatus,
)


def make_report() -> ReconExecutionReport:
    return ReconExecutionReport(
        results=(
            ReconTaskResult(
                name="shodan",
                status=ReconTaskStatus.SUCCESS,
                duration_ms=100,
                value=None,
                error_type=None,
            ),
            ReconTaskResult(
                name="tcp_ports",
                status=ReconTaskStatus.SUCCESS,
                duration_ms=150,
                value=(),
                error_type=None,
            ),
        )
    )


@pytest.mark.asyncio
async def test_rejects_existing_transaction(db_session):
    # Trigger SQLAlchemy autobegin.
    await db_session.execute(__import__("sqlalchemy").text("SELECT 1"))

    report = make_report()

    with pytest.raises(ReconnaissancePersistenceError):
        await persist_execution_report(
            session=db_session,
            scan_id="test-scan",
            report=report,
        )


@pytest.mark.asyncio
async def test_rejects_report_without_successful_results(db_session):
    report = ReconExecutionReport(
        results=(
            ReconTaskResult(
                name="shodan",
                status=ReconTaskStatus.FAILED,
                duration_ms=100,
                value=None,
                error_type="RuntimeError",
            ),
            ReconTaskResult(
                name="tcp_ports",
                status=ReconTaskStatus.TIMED_OUT,
                duration_ms=150,
                value=None,
                error_type="TimeoutError",
            ),
        )
    )

    with pytest.raises(ReconnaissancePersistenceError):
        await persist_execution_report(
            session=db_session,
            scan_id="test-scan",
            report=report,
        )


@pytest.mark.asyncio
async def test_rejects_invalid_scan_id(db_session):
    with pytest.raises(ValueError):
        await persist_execution_report(
            session=db_session,
            scan_id=" ",
            report=make_report(),
        )


@pytest.mark.asyncio
async def test_rejects_invalid_report_type(db_session):
    with pytest.raises(TypeError):
        await persist_execution_report(
            session=db_session,
            scan_id="test-scan",
            report=object(),
        )
