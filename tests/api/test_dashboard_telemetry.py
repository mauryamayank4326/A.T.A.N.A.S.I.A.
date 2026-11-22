"""Endpoint tests for reconnaissance telemetry."""

import asyncio
import re
from datetime import datetime, timedelta, timezone
from html import unescape
from urllib.parse import parse_qs, urlparse
from uuid import UUID

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
    assert 'name="search"' in response.text
    assert 'name="target_id"' in response.text
    assert 'name="scan_id"' in response.text
    assert 'name="page_size"' in response.text
    assert "Apply filters" in response.text
    assert "Clear filters" in response.text
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


def test_telemetry_accepts_search(client: TestClient):
    response = client.get(
        "/dashboard/telemetry",
        params={"search": "example"},
    )

    assert response.status_code == 200


def test_telemetry_accepts_sort_order(client: TestClient):
    response = client.get(
        "/dashboard/telemetry",
        params={
            "sort_by": "port",
            "sort_order": "desc",
        },
    )

    assert response.status_code == 200


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


def test_telemetry_pagination_links_preserve_active_filters(
    client: TestClient,
    target: Target,
):
    first_scan_id, _ = _create_observations(client, target)

    async def add_port() -> None:
        async with client.app.state.db_session_factory() as session:
            session.add(
                ExposedPort(
                    scan_id=UUID(first_scan_id),
                    host="backup.example.com",
                    port=8443,
                    protocol="tcp",
                    service_name="https",
                )
            )
            await session.commit()

    asyncio.run(add_port())

    response = client.get(
        "/dashboard/telemetry",
        params={
            "target_id": str(target.id),
            "scan_id": first_scan_id,
            "search": "example",
            "sort_by": "name",
            "sort_order": "desc",
            "page_size": "1",
        },
    )

    assert response.status_code == 200
    expected_page_params = {
        "subdomain_page": "2",
        "port_page": "2",
        "email_page": "2",
    }
    hrefs = re.findall(r'<a href="([^"]+)"', response.text)
    pagination_queries = [parse_qs(urlparse(unescape(href)).query) for href in hrefs]

    for page_param, page_value in expected_page_params.items():
        query = next(query for query in pagination_queries if query.get(page_param) == [page_value])
        assert query["target_id"] == [str(target.id)]
        assert query["scan_id"] == [first_scan_id]
        assert query["search"] == ["example"]
        assert query["sort_by"] == ["name"]
        assert query["sort_order"] == ["desc"]
        assert query["page_size"] == ["1"]


def test_telemetry_filters_all_categories_by_scan_id(
    client: TestClient,
    target: Target,
):
    _, second_scan_id = _create_observations(client, target)

    response = client.get(f"/dashboard/telemetry?scan_id={second_scan_id}")

    assert response.status_code == 200
    assert "other.example" in response.text
    assert "other-service.example" in response.text
    assert "other@other.example" in response.text
    assert "newer.example.com" not in response.text
    assert "service.example.com" not in response.text
    assert "newer@example.com" not in response.text


def test_telemetry_global_search_filters_each_category(
    client: TestClient,
    target: Target,
):
    _create_observations(client, target)

    response = client.get("/dashboard/telemetry?search=older")

    assert response.status_code == 200
    assert "older.example.com" in response.text
    assert "newer.example.com" not in response.text
    assert "service.example.com" not in response.text
    assert "older@example.com" in response.text
    assert "newer@example.com" not in response.text


def test_telemetry_rejects_invalid_scan_uuid(client: TestClient):
    response = client.get("/dashboard/telemetry?scan_id=not-a-uuid")

    assert response.status_code == 422


def test_telemetry_rejects_invalid_sort_order(client: TestClient):
    response = client.get("/dashboard/telemetry?sort_order=random")

    assert response.status_code == 422


def test_telemetry_searches_each_observation_type(
    client: TestClient,
    target: Target,
):
    _create_observations(client, target)

    response = client.get(
        "/dashboard/telemetry?subdomain_query=older&port_query=https&email_query=directory"
    )

    assert response.status_code == 200
    assert "older.example.com" in response.text
    assert "newer.example.com" not in response.text
    assert "service.example.com" in response.text
    assert "other-service.example" not in response.text
    assert "newer@example.com" in response.text
    assert "older@example.com" not in response.text


def test_telemetry_search_treats_like_wildcards_literally(
    client: TestClient,
    target: Target,
):
    _create_observations(client, target)

    response = client.get("/dashboard/telemetry?subdomain_query=%25")

    assert response.status_code == 200
    assert "older.example.com" not in response.text
    assert "newer.example.com" not in response.text


def test_telemetry_rejects_invalid_target_uuid(client: TestClient):
    response = client.get("/dashboard/telemetry?target_id=not-a-uuid")

    assert response.status_code == 422
