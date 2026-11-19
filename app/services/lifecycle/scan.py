from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan, ScanStatus


class ScanLifecycleError(Exception):
    """Base exception for scan lifecycle operations."""


class ScanNotFoundError(ScanLifecycleError):
    """Raised when the requested scan does not exist."""


class InvalidScanTransitionError(ScanLifecycleError):
    """Raised when a scan transition is not permitted."""


_ALLOWED_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.PENDING: {
        ScanStatus.RUNNING,
        ScanStatus.FAILED,
    },
    ScanStatus.RUNNING: {
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.FAILED: set(),
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_scan_transition(
    current_status: ScanStatus,
    new_status: ScanStatus,
) -> None:
    """Validate whether a scan status transition is allowed."""

    if not isinstance(current_status, ScanStatus):
        raise TypeError("current_status must be a ScanStatus")

    if not isinstance(new_status, ScanStatus):
        raise TypeError("new_status must be a ScanStatus")

    allowed = _ALLOWED_TRANSITIONS[current_status]

    if new_status not in allowed:
        raise InvalidScanTransitionError(
            f"Transition from {current_status.value} to {new_status.value} is not permitted."
        )


async def transition_scan(
    session: AsyncSession,
    scan_id: str,
    new_status: ScanStatus,
) -> Scan:
    """
    Change a scan's lifecycle status.

    This function flushes changes but never commits.
    The caller owns the transaction.
    """

    if not isinstance(session, AsyncSession):
        raise TypeError("session must be an AsyncSession")

    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ValueError("scan_id must be a non-empty string")

    if not isinstance(new_status, ScanStatus):
        raise TypeError("new_status must be a ScanStatus")

    try:
        scan_uuid = UUID(scan_id)
    except (ValueError, AttributeError):
        raise ScanNotFoundError(f"Scan '{scan_id}' was not found.") from None

    scan = await session.get(Scan, scan_uuid)

    if scan is None:
        raise ScanNotFoundError(f"Scan '{scan_id}' was not found.")

    validate_scan_transition(
        current_status=scan.status,
        new_status=new_status,
    )

    now = _utc_now()

    if new_status is ScanStatus.RUNNING:
        if scan.started_at is not None:
            raise InvalidScanTransitionError(
                "A scan that already has started_at cannot be restarted."
            )

        scan.started_at = now

    if new_status in {
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
    }:
        scan.completed_at = now

    scan.status = new_status

    await session.flush()

    return scan
