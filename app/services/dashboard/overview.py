"""Read-only query operations for the dashboard overview."""

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Scan, ScanStatus


@dataclass(frozen=True, slots=True)
class DashboardOverview:
    """Scan metrics and recent activity for the dashboard overview."""

    metrics: dict[str, int]
    recent_scans: list[Scan]


async def get_dashboard_overview(session: AsyncSession) -> DashboardOverview:
    """Return scan metrics and the latest scans for the dashboard."""

    status_query = select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
    status_result = await session.execute(status_query)
    status_counts = {status: count for status, count in status_result.all()}

    metrics = {
        "total": sum(status_counts.values()),
        "pending": status_counts.get(ScanStatus.PENDING, 0),
        "running": status_counts.get(ScanStatus.RUNNING, 0),
        "completed": status_counts.get(ScanStatus.COMPLETED, 0),
        "failed": status_counts.get(ScanStatus.FAILED, 0),
    }

    recent_query = (
        select(Scan).options(selectinload(Scan.target)).order_by(Scan.created_at.desc()).limit(20)
    )
    recent_result = await session.execute(recent_query)

    return DashboardOverview(
        metrics=metrics,
        recent_scans=list(recent_result.scalars().all()),
    )
