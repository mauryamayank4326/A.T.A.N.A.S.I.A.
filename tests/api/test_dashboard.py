from uuid import uuid4


def test_dashboard_returns_html(client):
    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_dashboard_displays_overview(client):
    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "Dashboard Overview" in response.text
    assert "Recent Scans" in response.text


def test_dashboard_displays_scan_metrics(client):
    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "Total Scans" in response.text
    assert "Pending" in response.text
    assert "Running" in response.text
    assert "Completed" in response.text
    assert "Failed Scans" in response.text


def test_dashboard_handles_empty_scan_database(client):
    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "No reconnaissance scans have been recorded." in response.text


def test_dashboard_target_routes_are_registered_once(client):
    from app.api.routes.dashboard import router as dashboard_router

    paths = [
        route.path
        for route in dashboard_router.routes
        if route.path in {
            "/dashboard/targets",
            "/dashboard/targets/{target_id}",
        }
    ]

    assert paths.count("/dashboard/targets") == 1
    assert paths.count("/dashboard/targets/{target_id}") == 1


def test_dashboard_target_detail_requires_uuid(client):
    response = client.get("/dashboard/targets/not-a-uuid")

    assert response.status_code == 422


def test_unknown_uuid_target_returns_404(client):
    response = client.get(f"/dashboard/targets/{uuid4()}")

    assert response.status_code == 404
