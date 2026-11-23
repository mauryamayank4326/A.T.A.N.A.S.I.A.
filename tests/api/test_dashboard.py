from uuid import uuid4


def test_dashboard_returns_html(client):
    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_dashboard_routes_are_registered(client):
    dashboard_paths = {
        path for path in client.app.openapi()["paths"] if path.startswith("/dashboard")
    }

    assert dashboard_paths == {
        "/dashboard/",
        "/dashboard/analytics",
        "/dashboard/targets",
        "/dashboard/targets/{target_id}",
        "/dashboard/telemetry",
    }


def test_dashboard_analytics_page_renders(client):
    response = client.get("/dashboard/analytics")

    assert response.status_code == 200
    assert "Reconnaissance Analytics" in response.text
    assert "scanStatusChart" in response.text
    assert "assetDistributionChart" in response.text
    assert "/static/js/analytics.js" in response.text


def test_dashboard_stylesheet_is_mounted(client):
    response = client.get("/static/css/app.css")

    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]


def test_dashboard_loads_pinned_chartjs(client):
    response = client.get("/dashboard/")

    assert response.status_code == 200
    assert "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js" in response.text


def test_dashboard_overview_renders(client):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Dashboard Overview" in response.text


def test_dashboard_targets_page_renders(client):
    response = client.get("/dashboard/targets")

    assert response.status_code == 200


def test_dashboard_telemetry_page_renders(client):
    response = client.get("/dashboard/telemetry")

    assert response.status_code == 200


def test_dashboard_unknown_route_returns_404(client):
    response = client.get("/dashboard/not-a-real-page")

    assert response.status_code == 404


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
    assert "No scans available" in response.text
    assert "Your recent scan activity will appear here." in response.text


def test_dashboard_target_routes_are_registered_once(client):
    from app.api.routes.dashboard import router as dashboard_router

    paths = [
        route.path
        for route in dashboard_router.routes
        if route.path
        in {
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
