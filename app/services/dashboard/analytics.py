from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    DiscoveredEmail,
    ExposedPort,
    Scan,
    ScanStatus,
    Subdomain,
)


def _status_value(status: object) -> str:
    value = getattr(status, "value", status)
    return str(value).lower()


async def get_analytics_overview(
    session: AsyncSession,
) -> dict[str, object]:
    # Count scans by status.
    status_statement = select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
    status_result = await session.execute(status_statement)

    status_counts = {_status_value(status): int(count) for status, count in status_result.all()}

    # Include zero-count statuses for a stable chart contract.
    status_distribution = [
        {
            "status": _status_value(status),
            "count": status_counts.get(_status_value(status), 0),
        }
        for status in ScanStatus
    ]

    # Count all persisted scan records.
    total_scans_statement = select(func.count(Scan.id))
    total_scans = int((await session.execute(total_scans_statement)).scalar_one())

    # Count persisted reconnaissance records.
    subdomain_statement = select(func.count(Subdomain.id))
    total_subdomains = int((await session.execute(subdomain_statement)).scalar_one())

    port_statement = select(func.count(ExposedPort.id))
    total_exposed_ports = int((await session.execute(port_statement)).scalar_one())

    email_statement = select(func.count(DiscoveredEmail.id))
    total_discovered_emails = int((await session.execute(email_statement)).scalar_one())

    asset_distribution = [
        {
            "asset_type": "Subdomains",
            "count": total_subdomains,
        },
        {
            "asset_type": "Exposed Ports",
            "count": total_exposed_ports,
        },
        {
            "asset_type": "Discovered Emails",
            "count": total_discovered_emails,
        },
    ]

    port_distribution = await get_port_distribution(
        session,
        limit=10,
    )
    service_distribution = await get_service_distribution(
        session,
        limit=10,
    )

    return {
        "total_scans": total_scans,
        "scan_status_distribution": status_distribution,
        "total_subdomains": total_subdomains,
        "total_exposed_ports": total_exposed_ports,
        "total_discovered_emails": total_discovered_emails,
        "asset_distribution": asset_distribution,
        "port_distribution": port_distribution,
        "service_distribution": service_distribution,
    }


async def get_port_distribution(
    session,
    *,
    limit: int = 10,
) -> list[dict[str, int]]:
    """
    Return the most frequently observed exposed ports.

    Counts persisted ExposedPort observations, not unique hosts.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")

    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")

    statement = (
        select(
            ExposedPort.port.label("port"),
            func.count(ExposedPort.id).label("count"),
        )
        .group_by(ExposedPort.port)
        .order_by(
            func.count(ExposedPort.id).desc(),
            ExposedPort.port.asc(),
        )
        .limit(limit)
    )

    result = await session.execute(statement)

    return [
        {
            "port": row.port,
            "count": row.count,
        }
        for row in result.all()
    ]


async def get_service_distribution(
    session,
    *,
    limit: int = 10,
) -> list[dict[str, int | str]]:
    """
    Return the most frequently observed service names.

    NULL and empty service names are grouped as 'unknown'.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")

    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")

    normalized_service = func.coalesce(
        func.nullif(func.trim(ExposedPort.service_name), ""),
        "unknown",
    )

    statement = (
        select(
            normalized_service.label("service_name"),
            func.count(ExposedPort.id).label("count"),
        )
        .group_by(normalized_service)
        .order_by(
            func.count(ExposedPort.id).desc(),
            normalized_service.asc(),
        )
        .limit(limit)
    )

    result = await session.execute(statement)

    return [
        {
            "service_name": row.service_name,
            "count": row.count,
        }
        for row in result.all()
    ]
