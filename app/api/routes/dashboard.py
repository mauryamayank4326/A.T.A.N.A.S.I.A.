from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db_session
from app.models.scan import Scan, ScanStatus

APP_DIR = Path(__file__).resolve().parents[2]

templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


@router.get("/")
async def dashboard_overview(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Render the reconnaissance operations dashboard."""

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
    recent_scans = recent_result.scalars().all()

    return templates.TemplateResponse(
        request=request,
        name="dashboard/index.html",
        context={
            "metrics": metrics,
            "recent_scans": recent_scans,
        },
    )
