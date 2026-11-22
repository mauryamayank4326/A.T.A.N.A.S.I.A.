from pathlib import Path
from typing import Annotated, Literal
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
from app.services.dashboard.telemetry import get_telemetry

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


@router.get(
    "/telemetry",
    response_class=HTMLResponse,
    name="dashboard_telemetry",
)
async def dashboard_telemetry(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    target_id: Annotated[UUID | None, Query()] = None,
    scan_id: Annotated[UUID | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    sort_by: Annotated[str, Query(max_length=50)] = "name",
    sort_order: Literal["asc", "desc"] = Query(default="asc"),
    subdomain_page: Annotated[int | None, Query(ge=1)] = None,
    port_page: Annotated[int | None, Query(ge=1)] = None,
    email_page: Annotated[int | None, Query(ge=1)] = None,
    subdomain_query: Annotated[str | None, Query()] = None,
    port_query: Annotated[str | None, Query()] = None,
    email_query: Annotated[str | None, Query()] = None,
):
    """Render persisted reconnaissance telemetry."""

    telemetry = await get_telemetry(
        session,
        page=page,
        page_size=page_size,
        target_id=target_id,
        scan_id=scan_id,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        subdomain_page=subdomain_page,
        port_page=port_page,
        email_page=email_page,
        subdomain_query=subdomain_query,
        port_query=port_query,
        email_query=email_query,
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard/telemetry/index.html",
        context={
            "telemetry": telemetry,
            "target_id": target_id,
            "filters": {
                "target_id": target_id,
                "scan_id": scan_id,
                "search": search,
                "sort_by": sort_by,
                "sort_order": sort_order,
                "page": page,
                "page_size": page_size,
            },
        },
    )
