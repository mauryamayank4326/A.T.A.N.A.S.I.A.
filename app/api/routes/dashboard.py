from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db_session
from app.models.scan import Scan, ScanStatus
from app.services.dashboard.targets import get_target_by_id, list_targets

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


@router.get(
    "/targets",
    response_class=HTMLResponse,
    name="dashboard_targets",
)
async def dashboard_targets(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    """Render the paginated target console."""

    result = await list_targets(
        session,
        page=page,
        page_size=page_size,
    )
    return templates.TemplateResponse(
        request=request,
        name="dashboard/targets/index.html",
        context={
            "targets": result.items,
            "total": result.total,
            "page": result.page,
            "page_size": result.page_size,
            "total_pages": result.total_pages,
        },
    )


@router.get(
    "/targets/{target_id}",
    response_class=HTMLResponse,
    name="dashboard_target_detail",
)
async def dashboard_target_detail(
    request: Request,
    target_id: UUID,
    session: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Render a target and its scan history."""

    target = await get_target_by_id(session, target_id)
    if target is None:
        raise HTTPException(
            status_code=404,
            detail="Target not found",
        )

    scans = sorted(
        target.scans,
        key=lambda scan: (
            scan.started_at is not None,
            scan.started_at,
        ),
        reverse=True,
    )
    return templates.TemplateResponse(
        request=request,
        name="dashboard/targets/detail.html",
        context={
            "target": target,
            "scans": scans,
        },
    )
