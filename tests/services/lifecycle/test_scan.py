import pytest

from app.models.scan import ScanStatus
from app.services.lifecycle.scan import (
    InvalidScanTransitionError,
    ScanNotFoundError,
    transition_scan,
    validate_scan_transition,
)


def test_pending_to_running_is_allowed():
    validate_scan_transition(
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
    )


def test_pending_to_failed_is_allowed():
    validate_scan_transition(
        ScanStatus.PENDING,
        ScanStatus.FAILED,
    )


def test_running_to_completed_is_allowed():
    validate_scan_transition(
        ScanStatus.RUNNING,
        ScanStatus.COMPLETED,
    )


def test_running_to_failed_is_allowed():
    validate_scan_transition(
        ScanStatus.RUNNING,
        ScanStatus.FAILED,
    )


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (ScanStatus.COMPLETED, ScanStatus.RUNNING),
        (ScanStatus.COMPLETED, ScanStatus.FAILED),
        (ScanStatus.FAILED, ScanStatus.RUNNING),
        (ScanStatus.FAILED, ScanStatus.COMPLETED),
        (ScanStatus.PENDING, ScanStatus.COMPLETED),
        (ScanStatus.RUNNING, ScanStatus.PENDING),
    ],
)
def test_invalid_transitions_are_rejected(current, new):
    with pytest.raises(InvalidScanTransitionError):
        validate_scan_transition(current, new)


@pytest.mark.asyncio
async def test_missing_scan_raises_error(db_session):
    with pytest.raises(ScanNotFoundError):
        await transition_scan(
            session=db_session,
            scan_id="missing-scan",
            new_status=ScanStatus.RUNNING,
        )


@pytest.mark.asyncio
async def test_pending_scan_can_start(db_session, scan_factory):
    scan = await scan_factory(
        status=ScanStatus.PENDING,
    )

    updated = await transition_scan(
        session=db_session,
        scan_id=str(scan.id),
        new_status=ScanStatus.RUNNING,
    )

    assert updated.status is ScanStatus.RUNNING
    assert updated.started_at is not None
    assert updated.completed_at is None


@pytest.mark.asyncio
async def test_running_scan_can_complete(db_session, scan_factory):
    scan = await scan_factory(
        status=ScanStatus.RUNNING,
    )

    updated = await transition_scan(
        session=db_session,
        scan_id=str(scan.id),
        new_status=ScanStatus.COMPLETED,
    )

    assert updated.status is ScanStatus.COMPLETED
    assert updated.completed_at is not None


@pytest.mark.asyncio
async def test_running_scan_can_fail(db_session, scan_factory):
    scan = await scan_factory(
        status=ScanStatus.RUNNING,
    )

    updated = await transition_scan(
        session=db_session,
        scan_id=str(scan.id),
        new_status=ScanStatus.FAILED,
    )

    assert updated.status is ScanStatus.FAILED
    assert updated.completed_at is not None
