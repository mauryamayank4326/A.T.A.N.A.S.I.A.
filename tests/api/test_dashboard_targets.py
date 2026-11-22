"""Tests for the dashboard target console."""

import asyncio
import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.models import Target
from app.models.scan import Scan, ScanStatus


def test_target_console_renders(client: TestClient, target: Target):
    response = client.get("/dashboard/targets")

    assert response.status_code == 200
    assert "Target Console" in response.text
    assert "Target Inventory" in response.text
    assert target.domain in response.text
    assert f"/dashboard/targets/{target.id}" in response.text
    assert "Not scanned" in response.text
    assert "api_key" not in response.text
    assert "internal scan error" not in response.text


def test_target_with_multiple_scans_shows_count_and_latest_failed_status(
    client: TestClient,
    target: Target,
):
    async def create_scans() -> None:
        now = datetime.now(timezone.utc)
        async with client.app.state.db_session_factory() as session:
            session.add_all(
                [
                    Scan(
                        target_id=target.id,
                        status=ScanStatus.COMPLETED,
                        created_at=now - timedelta(minutes=1),
                    ),
                    Scan(
                        target_id=target.id,
                        status=ScanStatus.FAILED,
                        created_at=now,
                    ),
                ]
            )
            await session.commit()

    asyncio.run(create_scans())

    response = client.get("/dashboard/targets")

    assert response.status_code == 200
    assert re.search(r">\s*2\s*</td>", response.text)
    assert re.search(r">\s*failed\s*</span>", response.text)
    assert "bg-red-500/10 text-red-400" in response.text

    detail_response = client.get(f"/dashboard/targets/{target.id}")
    assert detail_response.status_code == 200
    assert "bg-emerald-500/10 text-emerald-400" in detail_response.text
    assert "bg-red-500/10 text-red-400" in detail_response.text

    overview_response = client.get("/dashboard/")
    assert overview_response.status_code == 200
    assert "bg-emerald-500/10 text-emerald-400" in overview_response.text
    assert "bg-red-500/10 text-red-400" in overview_response.text


def test_target_console_empty_state(client: TestClient):
    response = client.get("/dashboard/targets")

    assert response.status_code == 200
    assert "No targets registered" in response.text


def test_target_console_rejects_invalid_page(client: TestClient):
    response = client.get("/dashboard/targets?page=0")

    assert response.status_code == 422


def test_target_console_rejects_oversized_page(client: TestClient):
    response = client.get("/dashboard/targets?page_size=101")

    assert response.status_code == 422


def test_unknown_target_returns_404(client: TestClient):
    response = client.get(f"/dashboard/targets/{uuid4()}")

    assert response.status_code == 404


def test_target_detail_renders_target_and_scan_history(
    client: TestClient,
    target: Target,
):
    response = client.get(f"/dashboard/targets/{target.id}")

    assert response.status_code == 200
    assert target.domain in response.text
    assert "Scan History" in response.text
    assert "No reconnaissance history" in response.text


def test_target_detail_rejects_non_uuid_id(client: TestClient):
    response = client.get("/dashboard/targets/nonexistent-target")

    assert response.status_code == 422
