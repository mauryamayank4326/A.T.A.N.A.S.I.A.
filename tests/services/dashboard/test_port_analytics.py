import pytest

from app.models import ExposedPort
from app.services.dashboard.analytics import (
    get_port_distribution,
    get_service_distribution,
)


@pytest.mark.asyncio
async def test_port_distribution_counts_observations(db_session, scan_factory):
    scan = await scan_factory()

    db_session.add_all(
        [
            ExposedPort(
                scan_id=scan.id,
                host="192.0.2.1",
                port=443,
                protocol="tcp",
                service_name="https",
            ),
            ExposedPort(
                scan_id=scan.id,
                host="192.0.2.2",
                port=443,
                protocol="tcp",
                service_name="https",
            ),
            ExposedPort(
                scan_id=scan.id,
                host="192.0.2.3",
                port=22,
                protocol="tcp",
                service_name="ssh",
            ),
        ]
    )
    await db_session.flush()

    result = await get_port_distribution(db_session)

    assert result == [
        {"port": 443, "count": 2},
        {"port": 22, "count": 1},
    ]


@pytest.mark.asyncio
async def test_service_distribution_groups_missing_names(db_session, scan_factory):
    scan = await scan_factory()

    db_session.add_all(
        [
            ExposedPort(
                scan_id=scan.id,
                host="192.0.2.10",
                port=8080,
                protocol="tcp",
                service_name=None,
            ),
            ExposedPort(
                scan_id=scan.id,
                host="192.0.2.11",
                port=8443,
                protocol="tcp",
                service_name="",
            ),
            ExposedPort(
                scan_id=scan.id,
                host="192.0.2.12",
                port=22,
                protocol="tcp",
                service_name="ssh",
            ),
        ]
    )
    await db_session.flush()

    result = await get_service_distribution(db_session)

    assert any(item["service_name"] == "unknown" for item in result)
    assert any(item["service_name"] == "ssh" for item in result)

    service_counts = {item["service_name"]: item["count"] for item in result}
    assert service_counts["unknown"] == 2
    assert service_counts["ssh"] == 1
