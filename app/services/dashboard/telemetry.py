"""Read-only telemetry queries for the dashboard."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovered_email import DiscoveredEmail
from app.models.exposed_port import ExposedPort
from app.models.scan import Scan
from app.models.subdomain import Subdomain
from app.models.target import Target


@dataclass(frozen=True, slots=True)
class TelemetryResult:
    subdomains: list[tuple[Any, Any, Any]]
    ports: list[tuple[Any, Any, Any]]
    emails: list[tuple[Any, Any, Any]]
    subdomain_total: int
    port_total: int
    email_total: int
    subdomain_page: int
    port_page: int
    email_page: int
    page_size: int

    @property
    def subdomain_total_pages(self) -> int:
        return (self.subdomain_total + self.page_size - 1) // self.page_size

    @property
    def port_total_pages(self) -> int:
        return (self.port_total + self.page_size - 1) // self.page_size

    @property
    def email_total_pages(self) -> int:
        return (self.email_total + self.page_size - 1) // self.page_size


def _validate_pagination(page: int, page_size: int) -> None:
    if isinstance(page, bool) or not isinstance(page, int) or page < 1:
        raise ValueError("page must be a positive integer")

    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
        raise ValueError("page_size must be between 1 and 100")


async def _count_records(
    session: AsyncSession,
    model: type,
    target_id: UUID | None,
) -> int:
    statement = select(func.count()).select_from(model).join(Scan, model.scan_id == Scan.id)

    if target_id is not None:
        statement = statement.where(Scan.target_id == target_id)

    total = await session.scalar(statement)
    return int(total or 0)


async def get_telemetry(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    target_id: UUID | None = None,
    subdomain_page: int | None = None,
    port_page: int | None = None,
    email_page: int | None = None,
) -> TelemetryResult:
    """Retrieve paginated subdomain, port, and email observations."""

    _validate_pagination(page, page_size)
    subdomain_page = page if subdomain_page is None else subdomain_page
    port_page = page if port_page is None else port_page
    email_page = page if email_page is None else email_page
    _validate_pagination(subdomain_page, page_size)
    _validate_pagination(port_page, page_size)
    _validate_pagination(email_page, page_size)

    subdomain_statement = (
        select(Subdomain, Scan, Target)
        .join(Scan, Subdomain.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .order_by(Subdomain.created_at.desc(), Subdomain.id.desc())
        .offset((subdomain_page - 1) * page_size)
        .limit(page_size)
    )

    port_statement = (
        select(ExposedPort, Scan, Target)
        .join(Scan, ExposedPort.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .order_by(ExposedPort.created_at.desc(), ExposedPort.id.desc())
        .offset((port_page - 1) * page_size)
        .limit(page_size)
    )

    email_statement = (
        select(DiscoveredEmail, Scan, Target)
        .join(Scan, DiscoveredEmail.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .order_by(DiscoveredEmail.created_at.desc(), DiscoveredEmail.id.desc())
        .offset((email_page - 1) * page_size)
        .limit(page_size)
    )

    if target_id is not None:
        subdomain_statement = subdomain_statement.where(Scan.target_id == target_id)
        port_statement = port_statement.where(Scan.target_id == target_id)
        email_statement = email_statement.where(Scan.target_id == target_id)

    subdomains = (await session.execute(subdomain_statement)).all()

    ports = (await session.execute(port_statement)).all()

    emails = (await session.execute(email_statement)).all()

    subdomain_total = await _count_records(session, Subdomain, target_id)
    port_total = await _count_records(session, ExposedPort, target_id)
    email_total = await _count_records(session, DiscoveredEmail, target_id)

    return TelemetryResult(
        subdomains=list(subdomains),
        ports=list(ports),
        emails=list(emails),
        subdomain_total=subdomain_total,
        port_total=port_total,
        email_total=email_total,
        subdomain_page=subdomain_page,
        port_page=port_page,
        email_page=email_page,
        page_size=page_size,
    )
