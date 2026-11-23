import pytest

from app.models import (
    DiscoveredEmail,
    ExposedPort,
    Scan,
    ScanStatus,
    Subdomain,
    Target,
)
from app.services.dashboard.analytics import get_analytics_overview


@pytest.mark.asyncio
async def test_analytics_overview_returns_success(async_client):
    response = await async_client.get("/api/v1/analytics/overview")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_analytics_overview_has_expected_fields(async_client):
    response = await async_client.get("/api/v1/analytics/overview")

    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "scan_status_distribution" in data
    assert "total_subdomains" in data
    assert "total_exposed_ports" in data
    assert "total_discovered_emails" in data
    assert "asset_distribution" in data


@pytest.mark.asyncio
async def test_analytics_counts_are_non_negative(async_client):
    response = await async_client.get("/api/v1/analytics/overview")

    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] >= 0
    assert data["total_subdomains"] >= 0
    assert data["total_exposed_ports"] >= 0
    assert data["total_discovered_emails"] >= 0

    for item in data["scan_status_distribution"]:
        assert item["count"] >= 0

    for item in data["asset_distribution"]:
        assert item["count"] >= 0


@pytest.mark.asyncio
async def test_analytics_service_returns_exact_seeded_counts(db_session):
    target = Target(domain="analytics.example")
    db_session.add(target)
    await db_session.flush()

    pending_scan = Scan(target_id=target.id, status=ScanStatus.PENDING)
    completed_scan = Scan(target_id=target.id, status=ScanStatus.COMPLETED)
    db_session.add_all([pending_scan, completed_scan])
    await db_session.flush()

    db_session.add_all(
        [
            Subdomain(scan_id=pending_scan.id, fqdn="api.analytics.example"),
            Subdomain(scan_id=completed_scan.id, fqdn="www.analytics.example"),
            ExposedPort(scan_id=pending_scan.id, host="192.0.2.10", port=80, protocol="tcp"),
            ExposedPort(scan_id=completed_scan.id, host="192.0.2.11", port=443, protocol="tcp"),
            DiscoveredEmail(
                scan_id=pending_scan.id,
                email_address="admin@analytics.example",
                source="crtsh",
            ),
        ]
    )
    await db_session.commit()

    data = await get_analytics_overview(db_session)

    assert data["total_scans"] == 2
    assert data["total_subdomains"] == 2
    assert data["total_exposed_ports"] == 2
    assert data["total_discovered_emails"] == 1

    status_counts = {item["status"]: item["count"] for item in data["scan_status_distribution"]}
    assert status_counts == {
        "pending": 1,
        "running": 0,
        "completed": 1,
        "failed": 0,
    }

    asset_counts = {item["asset_type"]: item["count"] for item in data["asset_distribution"]}
    assert asset_counts == {
        "Subdomains": 2,
        "Exposed Ports": 2,
        "Discovered Emails": 1,
    }


@pytest.mark.asyncio
async def test_analytics_service_zero_record_behavior(db_session):
    data = await get_analytics_overview(db_session)

    assert data["total_scans"] == 0
    assert data["total_subdomains"] == 0
    assert data["total_exposed_ports"] == 0
    assert data["total_discovered_emails"] == 0
    assert all(item["count"] == 0 for item in data["scan_status_distribution"])
    assert all(item["count"] == 0 for item in data["asset_distribution"])
