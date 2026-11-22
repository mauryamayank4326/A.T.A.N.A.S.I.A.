"""Read-only telemetry queries for the dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Select, asc, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.discovered_email import DiscoveredEmail
from app.models.exposed_port import ExposedPort
from app.models.scan import Scan
from app.models.subdomain import Subdomain
from app.models.target import Target

TelemetryKind = Literal["subdomains", "ports", "emails"]

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class TelemetryPagination:
    page: int
    page_size: int
    total: int

    @property
    def total_pages(self) -> int:
        if self.total == 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size


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


def validate_pagination(page: int, page_size: int) -> None:
    if isinstance(page, bool) or not isinstance(page, int) or page < 1:
        raise ValueError("page must be a positive integer")

    if (
        isinstance(page_size, bool)
        or not isinstance(page_size, int)
        or not 1 <= page_size <= MAX_PAGE_SIZE
    ):
        raise ValueError("page_size must be between 1 and 100")


def escape_like(value: str) -> str:
    """Escape LIKE wildcards so search behaves as literal substring matching."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def apply_pagination(
    statement: Select,
    *,
    page: int,
    page_size: int,
) -> Select:
    validate_pagination(page, page_size)
    return statement.offset((page - 1) * page_size).limit(page_size)


def apply_target_filter(
    statement: Select,
    *,
    target_id: UUID | None,
) -> Select:
    if target_id is not None:
        statement = statement.where(Scan.target_id == target_id)
    return statement


def apply_scan_filter(
    statement: Select,
    *,
    scan_id: UUID | None,
) -> Select:
    if scan_id is not None:
        statement = statement.where(Scan.id == scan_id)
    return statement


def search_subdomains(statement: Select, query: str | None) -> Select:
    if not query or not query.strip():
        return statement

    pattern = f"%{escape_like(query.strip())}%"
    return statement.where(
        or_(
            Subdomain.fqdn.ilike(pattern, escape="\\"),
            Target.domain.ilike(pattern, escape="\\"),
        )
    )


def search_ports(statement: Select, query: str | None) -> Select:
    if not query or not query.strip():
        return statement

    pattern = f"%{escape_like(query.strip())}%"
    return statement.where(
        or_(
            ExposedPort.host.ilike(pattern, escape="\\"),
            ExposedPort.service_name.ilike(pattern, escape="\\"),
        )
    )


def search_emails(statement: Select, query: str | None) -> Select:
    if not query or not query.strip():
        return statement

    pattern = f"%{escape_like(query.strip())}%"
    return statement.where(
        or_(
            DiscoveredEmail.email_address.ilike(pattern, escape="\\"),
            DiscoveredEmail.source.ilike(pattern, escape="\\"),
        )
    )


async def count_rows(
    session: AsyncSession,
    statement: Select,
) -> int:
    count_statement = select(func.count()).select_from(statement.order_by(None).subquery())
    result = await session.execute(count_statement)
    return int(result.scalar_one())


def subdomain_sort_column(sort_by: str):
    allowed = {
        "name": Subdomain.fqdn,
        "target": Target.domain,
    }
    return allowed.get(sort_by, Subdomain.fqdn)


def port_sort_column(sort_by: str):
    allowed = {
        "port": ExposedPort.port,
        "name": ExposedPort.host,
        "host": ExposedPort.host,
        "service": ExposedPort.service_name,
        "protocol": ExposedPort.protocol,
    }
    return allowed.get(sort_by, ExposedPort.port)


def email_sort_column(sort_by: str):
    allowed = {
        "name": DiscoveredEmail.email_address,
        "email": DiscoveredEmail.email_address,
        "source": DiscoveredEmail.source,
        "target": Target.domain,
    }
    return allowed.get(sort_by, DiscoveredEmail.email_address)


def apply_sort(
    statement: Select,
    *,
    column,
    direction: str,
) -> Select:
    ordering = desc(column) if direction == "desc" else asc(column)
    return statement.order_by(ordering)


async def get_telemetry(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    target_id: UUID | None = None,
    subdomain_page: int | None = None,
    port_page: int | None = None,
    email_page: int | None = None,
    subdomain_query: str | None = None,
    port_query: str | None = None,
    email_query: str | None = None,
    scan_id: UUID | None = None,
    search: str | None = None,
    sort_by: str = "name",
    sort_order: Literal["asc", "desc"] = "asc",
) -> TelemetryResult:
    """Retrieve paginated subdomain, port, and email observations."""

    validate_pagination(page, page_size)
    subdomain_page = page if subdomain_page is None else subdomain_page
    port_page = page if port_page is None else port_page
    email_page = page if email_page is None else email_page
    validate_pagination(subdomain_page, page_size)
    validate_pagination(port_page, page_size)
    validate_pagination(email_page, page_size)

    subdomain_statement = (
        select(Subdomain, Scan, Target)
        .join(Scan, Subdomain.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
    )
    subdomain_statement = apply_target_filter(
        subdomain_statement,
        target_id=target_id,
    )
    subdomain_statement = apply_scan_filter(subdomain_statement, scan_id=scan_id)
    subdomain_statement = search_subdomains(subdomain_statement, search)
    subdomain_statement = search_subdomains(subdomain_statement, subdomain_query)
    subdomain_total = await count_rows(session, subdomain_statement)
    subdomain_statement = apply_sort(
        subdomain_statement,
        column=subdomain_sort_column(sort_by),
        direction=sort_order,
    ).order_by(Subdomain.id.desc())
    subdomain_statement = apply_pagination(
        subdomain_statement,
        page=subdomain_page,
        page_size=page_size,
    )

    port_statement = (
        select(ExposedPort, Scan, Target)
        .join(Scan, ExposedPort.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
    )
    port_statement = apply_target_filter(port_statement, target_id=target_id)
    port_statement = apply_scan_filter(port_statement, scan_id=scan_id)
    port_statement = search_ports(port_statement, search)
    port_statement = search_ports(port_statement, port_query)
    port_total = await count_rows(session, port_statement)
    port_statement = apply_sort(
        port_statement,
        column=port_sort_column(sort_by),
        direction=sort_order,
    ).order_by(ExposedPort.id.desc())
    port_statement = apply_pagination(
        port_statement,
        page=port_page,
        page_size=page_size,
    )

    email_statement = (
        select(DiscoveredEmail, Scan, Target)
        .join(Scan, DiscoveredEmail.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
    )
    email_statement = apply_target_filter(email_statement, target_id=target_id)
    email_statement = apply_scan_filter(email_statement, scan_id=scan_id)
    email_statement = search_emails(email_statement, search)
    email_statement = search_emails(email_statement, email_query)
    email_total = await count_rows(session, email_statement)
    email_statement = apply_sort(
        email_statement,
        column=email_sort_column(sort_by),
        direction=sort_order,
    ).order_by(DiscoveredEmail.id.desc())
    email_statement = apply_pagination(
        email_statement,
        page=email_page,
        page_size=page_size,
    )

    subdomains = (await session.execute(subdomain_statement)).all()

    ports = (await session.execute(port_statement)).all()

    emails = (await session.execute(email_statement)).all()

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
