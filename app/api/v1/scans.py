"""Scan management endpoints for API version 1."""

from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db_session
from app.exceptions import APIError
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.schemas.scan import ScanCreate, ScanRead
from app.services.orchestration.reconnaissance import ReconTask
from app.services.orchestration.scan_runner import run_scan_lifecycle
from app.services.recon.shodan import search_shodan_hosts
from app.services.recon.tcp_probe import scan_tcp_ports

router = APIRouter(prefix="/scans", tags=["scans"])

DEFAULT_TCP_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 3389, 8080)


def build_recon_tasks(
    *,
    domain: str,
    shodan_api_key,
    http_timeout_seconds: float,
) -> list[ReconTask]:
    """Build the named reconnaissance tasks for a target scan."""

    async def shodan_callable():
        async with httpx.AsyncClient(timeout=http_timeout_seconds) as client:
            return await search_shodan_hosts(
                domain=domain,
                client=client,
                api_key=shodan_api_key,
            )

    async def tcp_callable():
        return await scan_tcp_ports(
            host=domain,
            ports=DEFAULT_TCP_PORTS,
        )

    return [
        ReconTask(name="shodan", execute=shodan_callable),
        ReconTask(name="tcp_ports", execute=tcp_callable),
    ]


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a reconnaissance scan",
)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> Scan:
    """Create a pending scan for an existing target."""

    target_result = await session.execute(select(Target).where(Target.id == payload.target_id))
    target = target_result.scalar_one_or_none()

    if target is None:
        raise APIError(
            code="TARGET_NOT_FOUND",
            message="The requested target was not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
    )

    try:
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

    except IntegrityError as exc:
        await session.rollback()
        raise APIError(
            code="SCAN_CREATION_CONFLICT",
            message="The scan could not be created because of a data conflict.",
            status_code=status.HTTP_409_CONFLICT,
        ) from exc

    except SQLAlchemyError as exc:
        await session.rollback()
        raise APIError(
            code="SCAN_CREATION_FAILED",
            message="The scan could not be created.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from exc

    settings = request.app.state.settings

    if settings.shodan_api_key is not None:
        tasks = build_recon_tasks(
            domain=target.domain,
            shodan_api_key=settings.shodan_api_key,
            http_timeout_seconds=settings.http_timeout_seconds,
        )

        await run_scan_lifecycle(
            session_factory=request.app.state.db_session_factory,
            scan_id=str(scan.id),
            tasks=tasks,
            max_concurrency=settings.max_concurrency,
            default_timeout_seconds=settings.http_timeout_seconds,
        )

    return scan
