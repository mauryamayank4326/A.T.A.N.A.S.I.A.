from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.scan import ScanStatus
from app.services.lifecycle.scan import transition_scan
from app.services.orchestration.persistence import (
    persist_execution_report,
)
from app.services.orchestration.reconnaissance import (
    ReconExecutionReport,
    ReconTask,
    run_concurrent_reconnaissance,
)

logger = logging.getLogger(__name__)


async def _transition_with_transaction(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    status: ScanStatus,
) -> None:
    """Perform one lifecycle transition in its own transaction."""

    async with session_factory() as session:
        async with session.begin():
            await transition_scan(
                session=session,
                scan_id=scan_id,
                new_status=status,
            )


async def _persist_report(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    report: ReconExecutionReport,
) -> None:
    """
    Delegate transaction ownership to the Day 28 coordinator.

    Do not call session.begin() here: persist_execution_report()
    already owns and commits its transaction.
    """

    async with session_factory() as session:
        await persist_execution_report(
            session=session,
            scan_id=scan_id,
            report=report,
        )


async def _mark_failed(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
) -> None:
    """Attempt to mark a scan failed without hiding the original error."""

    try:
        await _transition_with_transaction(
            session_factory=session_factory,
            scan_id=scan_id,
            status=ScanStatus.FAILED,
        )
    except Exception:
        logger.exception(
            "Could not transition scan %s to FAILED",
            scan_id,
        )


async def run_scan_lifecycle(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    tasks: list[ReconTask],
    max_concurrency: int = 5,
    default_timeout_seconds: float = 15.0,
) -> ReconExecutionReport:
    """
    Run a scan through its lifecycle.

    Sequence:
      PENDING -> RUNNING -> reconnaissance -> persistence -> COMPLETED

    On an execution or persistence exception:
      RUNNING -> FAILED
    """

    # 1. Commit the RUNNING transition before reconnaissance begins.
    await _transition_with_transaction(
        session_factory=session_factory,
        scan_id=scan_id,
        status=ScanStatus.RUNNING,
    )

    try:
        # 2. Execute the Day 27 reconnaissance tasks.
        report = await run_concurrent_reconnaissance(
            tasks=tasks,
            max_concurrency=max_concurrency,
            default_timeout_seconds=default_timeout_seconds,
        )

        # 3. Persist successful results using the Day 28 transaction.
        await _persist_report(
            session_factory=session_factory,
            scan_id=scan_id,
            report=report,
        )

        # 4. Mark the scan complete only after persistence succeeds.
        await _transition_with_transaction(
            session_factory=session_factory,
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
        )

        return report

    except Exception:
        # 5. Use a separate session and transaction for failure status.
        await _mark_failed(
            session_factory=session_factory,
            scan_id=scan_id,
        )
        raise
