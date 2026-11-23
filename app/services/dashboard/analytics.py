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

    return {
        "total_scans": total_scans,
        "scan_status_distribution": status_distribution,
        "total_subdomains": total_subdomains,
        "total_exposed_ports": total_exposed_ports,
        "total_discovered_emails": total_discovered_emails,
        "asset_distribution": asset_distribution,
    }
