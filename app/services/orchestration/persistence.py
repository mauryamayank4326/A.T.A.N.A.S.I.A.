from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.orchestration.reconnaissance import (
    ReconExecutionReport,
    ReconTaskStatus,
)
from app.services.persistence.reconnaissance import (
    PersistenceSummary,
    persist_reconnaissance_results,
)
from app.services.recon.shodan import ShodanSearchResult
from app.services.recon.tcp_probe import TCPPortObservation


class ReconnaissancePersistenceError(Exception):
    """Raised when reconnaissance results cannot be persisted."""


class ReconnaissanceReportError(ReconnaissancePersistenceError):
    """Raised when the execution report is invalid."""


@dataclass(frozen=True, slots=True)
class TransactionalPersistenceResult:
    """Result of an atomic reconnaissance persistence operation."""

    persistence: PersistenceSummary
    successful_tasks: int
    failed_tasks: int
    timed_out_tasks: int


def _extract_successful_result(
    report: ReconExecutionReport,
    task_name: str,
) -> object | None:
    for result in report.results:
        if result.name == task_name:
            if result.status is ReconTaskStatus.SUCCESS:
                return result.value

            return None

    return None


def _validate_report(report: ReconExecutionReport) -> None:
    if not isinstance(report, ReconExecutionReport):
        raise TypeError("report must be a ReconExecutionReport")

    names = [result.name for result in report.results]

    if len(names) != len(set(names)):
        raise ReconnaissanceReportError("Reconnaissance report contains duplicate task names.")


async def persist_execution_report(
    session: AsyncSession,
    scan_id: str,
    report: ReconExecutionReport,
) -> TransactionalPersistenceResult:
    """
    Persist successful Shodan and TCP results atomically.

    The supplied session must not already have an active transaction.
    This function owns the transaction and commits it on success.
    """

    if not isinstance(session, AsyncSession):
        raise TypeError("session must be an AsyncSession")

    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ValueError("scan_id must be a non-empty string")

    _validate_report(report)

    if session.in_transaction():
        raise ReconnaissancePersistenceError(
            "The session already has an active transaction. "
            "Provide a fresh session or let the caller own the transaction."
        )

    shodan_value = _extract_successful_result(report, "shodan")
    tcp_value = _extract_successful_result(report, "tcp_ports")

    if shodan_value is not None and not isinstance(shodan_value, ShodanSearchResult):
        raise ReconnaissanceReportError("The successful shodan task returned an invalid result.")

    if tcp_value is not None:
        if not isinstance(tcp_value, list | tuple):
            raise ReconnaissanceReportError(
                "The successful tcp_ports task must return a list or tuple."
            )

        if not all(isinstance(item, TCPPortObservation) for item in tcp_value):
            raise ReconnaissanceReportError("The tcp_ports task contains an invalid observation.")

    if shodan_value is None and tcp_value is None:
        raise ReconnaissancePersistenceError("No successful reconnaissance results are available.")

    tcp_observations = tuple(tcp_value) if tcp_value is not None else tuple()

    if shodan_value is None:
        raise ReconnaissanceReportError(
            "The Day 26 persistence contract requires a ShodanSearchResult. "
            "A TCP-only persistence operation needs an explicit "
            "TCP-only persistence path."
        )

    try:
        async with session.begin():
            persistence_summary = await persist_reconnaissance_results(
                session=session,
                scan_id=scan_id,
                shodan_result=shodan_value,
                tcp_observations=tcp_observations,
            )

    except Exception as exc:
        raise ReconnaissancePersistenceError(
            "The reconnaissance persistence transaction failed."
        ) from exc

    successful_tasks = sum(result.status is ReconTaskStatus.SUCCESS for result in report.results)

    failed_tasks = sum(result.status is ReconTaskStatus.FAILED for result in report.results)

    timed_out_tasks = sum(result.status is ReconTaskStatus.TIMED_OUT for result in report.results)

    return TransactionalPersistenceResult(
        persistence=persistence_summary,
        successful_tasks=successful_tasks,
        failed_tasks=failed_tasks,
        timed_out_tasks=timed_out_tasks,
    )
