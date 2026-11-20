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
