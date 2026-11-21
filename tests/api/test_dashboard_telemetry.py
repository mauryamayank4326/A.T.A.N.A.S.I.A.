"""Endpoint tests for reconnaissance telemetry."""

import asyncio
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.models.discovered_email import DiscoveredEmail
from app.models.exposed_port import ExposedPort
from app.models.scan import Scan
from app.models.subdomain import Subdomain
from app.models.target import Target


def _create_observations(client: TestClient, target: Target) -> tuple[str, str]:
    async def create() -> tuple[str, str]:
        async with client.app.state.db_session_factory() as session:
            other_target = Target(domain="other.example")
            session.add(other_target)
            await session.flush()

            first_scan = Scan(target_id=target.id)
            second_scan = Scan(target_id=other_target.id)
            session.add_all([first_scan, second_scan])
            await session.flush()

            older = datetime(2026, 1, 1, tzinfo=timezone.utc)
            newer = older + timedelta(minutes=1)
            session.add_all(
                [
                    Subdomain(
                        scan_id=first_scan.id,
                        fqdn="older.example.com",
                        source="dns",
                        created_at=older,
                    ),
                    Subdomain(
                        scan_id=first_scan.id,
                        fqdn="newer.example.com",
                        source="dns",
                        created_at=newer,
                    ),
                    ExposedPort(
                        scan_id=first_scan.id,
                        host="service.example.com",
                        port=443,
                        protocol="tcp",
                        service_name="https",
                    ),
                    ExposedPort(
                        scan_id=second_scan.id,
                        host="other-service.example",
                        port=8080,
                        protocol="udp",
                        service_name="alternate",
                    ),
                    DiscoveredEmail(
                        scan_id=first_scan.id,
                        email_address="older@example.com",
                        source="website",
                        created_at=older,
                    ),
                    DiscoveredEmail(
                        scan_id=first_scan.id,
                        email_address="newer@example.com",
                        source="directory",
                        created_at=newer,
                    ),
                    Subdomain(
                        scan_id=second_scan.id,
                        fqdn="other.example",
                        source="dns",
                    ),
                    DiscoveredEmail(
                        scan_id=second_scan.id,
                        email_address="other@other.example",
                        source="website",
                    ),
                ]
            )
            await session.commit()
            return str(first_scan.id), str(second_scan.id)

    return asyncio.run(create())


def test_telemetry_page_renders(client: TestClient):
    response = client.get("/dashboard/telemetry")

    assert response.status_code == 200
    assert "Reconnaissance Telemetry" in response.text
    assert "Discovered Subdomains" in response.text
    assert "Exposed Ports" in response.text
    assert "Discovered Email Addresses" in response.text
    assert "No subdomain observations found." in response.text
    assert "No exposed-port observations found." in response.text
    assert "No discovered email observations found." in response.text


def test_telemetry_rejects_invalid_page(client: TestClient):
    response = client.get("/dashboard/telemetry?page=0")

    assert response.status_code == 422


def test_telemetry_rejects_oversized_page_size(client: TestClient):
    response = client.get("/dashboard/telemetry?page_size=101")

    assert response.status_code == 422


def test_telemetry_accepts_target_filter(client: TestClient, target):
    response = client.get(f"/dashboard/telemetry?target_id={target.id}")

    assert response.status_code == 200


def test_telemetry_renders_model_fields_and_scan_provenance(
    client: TestClient,
    target: Target,
):
    first_scan_id, _ = _create_observations(client, target)

    response = client.get("/dashboard/telemetry")

    assert response.status_code == 200
    assert "newer.example.com" in response.text
    assert target.domain in response.text
    assert "service.example.com" in response.text
    assert "443" in response.text
    assert "tcp" in response.text
    assert "https" in response.text
    assert "newer@example.com" in response.text
    assert "directory" in response.text
    assert response.text.count(first_scan_id) >= 1
    assert "shodan_api_key" not in response.text


def test_telemetry_target_filter_excludes_other_target_records(
    client: TestClient,
    target: Target,
):
    _create_observations(client, target)

    response = client.get(f"/dashboard/telemetry?target_id={target.id}")

    assert response.status_code == 200
    assert "newer.example.com" in response.text
    assert "other.example" not in response.text
    assert "other@other.example" not in response.text
    assert "other-service.example" not in response.text


def test_telemetry_paginates_each_observation_type_independently(
    client: TestClient,
    target: Target,
):
    _create_observations(client, target)

    response = client.get(
        f"/dashboard/telemetry?target_id={target.id}&page_size=1"
        "&subdomain_page=2&port_page=1&email_page=2"
    )

    assert response.status_code == 200
    assert "older.example.com" in response.text
    assert "newer.example.com" not in response.text
    assert "service.example.com" in response.text
    assert "older@example.com" in response.text
    assert "newer@example.com" not in response.text


def test_telemetry_rejects_invalid_target_uuid(client: TestClient):
    response = client.get("/dashboard/telemetry?target_id=not-a-uuid")

    assert response.status_code == 422
