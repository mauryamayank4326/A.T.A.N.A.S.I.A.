import pytest

from app.services.recon.recon_summary import (
    ReconSummary,
    build_recon_summary,
)
from app.services.recon.shodan import (
    ShodanHostObservation,
    ShodanSearchResult,
)
from app.services.recon.tcp_probe import (
    TCPPortObservation,
    TCPPortStatus,
)


@pytest.fixture
def shodan_result():
    return ShodanSearchResult(
        domain="example.com",
        query="hostname:example.com",
        total=2,
        observations=(
            ShodanHostObservation(
                ip="203.0.113.10",
                port=443,
                transport="tcp",
                hostnames=("www.example.com",),
                domains=("example.com",),
                organization="Example Organization",
                product="Example Server",
                timestamp="2026-11-16T10:00:00",
            ),
            ShodanHostObservation(
                ip="203.0.113.11",
                port=22,
                transport="tcp",
                hostnames=("ssh.example.com",),
                domains=("example.com",),
                organization=None,
                product=None,
                timestamp=None,
            ),
        ),
    )


@pytest.fixture
def tcp_observations():
    return [
        TCPPortObservation(
            host="203.0.113.10",
            port=443,
            status=TCPPortStatus.OPEN,
            latency_ms=15.2,
            banner="HTTP/1.1 200 OK",
            service_name="http",
            service_confidence="high",
        ),
        TCPPortObservation(
            host="203.0.113.10",
            port=22,
            status=TCPPortStatus.CLOSED,
            latency_ms=8.1,
        ),
        TCPPortObservation(
            host="203.0.113.10",
            port=8080,
            status=TCPPortStatus.FILTERED,
            latency_ms=2000.0,
            error="Connection attempt timed out.",
        ),
        TCPPortObservation(
            host="203.0.113.10",
            port=3306,
            status=TCPPortStatus.ERROR,
            latency_ms=3.0,
            error="OSError",
        ),
    ]


def test_build_recon_summary(
    shodan_result,
    tcp_observations,
):
    summary = build_recon_summary(
        domain="EXAMPLE.COM",
        shodan_result=shodan_result,
        tcp_observations=tcp_observations,
    )

    assert isinstance(summary, ReconSummary)
    assert summary.domain == "example.com"
    assert summary.shodan_result is shodan_result
    assert summary.tcp_observation_count == 4
    assert summary.shodan_observation_count == 2


def test_recon_summary_calculates_port_metrics(
    shodan_result,
    tcp_observations,
):
    summary = build_recon_summary(
        domain="example.com",
        shodan_result=shodan_result,
        tcp_observations=tcp_observations,
    )

    assert summary.open_port_count == 1
    assert summary.closed_port_count == 1
    assert summary.filtered_port_count == 1
    assert summary.error_port_count == 1
    assert summary.identified_service_count == 1


def test_recon_summary_preserves_all_observations(
    shodan_result,
    tcp_observations,
):
    summary = build_recon_summary(
        domain="example.com",
        shodan_result=shodan_result,
        tcp_observations=tcp_observations,
    )

    assert len(summary.shodan_result.observations) == 2
    assert len(summary.tcp_observations) == 4


def test_recon_summary_converts_tcp_list_to_tuple(
    shodan_result,
    tcp_observations,
):
    summary = build_recon_summary(
        domain="example.com",
        shodan_result=shodan_result,
        tcp_observations=tcp_observations,
    )

    assert isinstance(summary.tcp_observations, tuple)


def test_rejects_mismatched_shodan_domain(shodan_result):
    with pytest.raises(ValueError, match="does not match"):
        build_recon_summary(
            domain="another-example.com",
            shodan_result=shodan_result,
            tcp_observations=[],
        )


def test_rejects_invalid_shodan_result():
    with pytest.raises(TypeError, match="ShodanSearchResult"):
        build_recon_summary(
            domain="example.com",
            shodan_result=None,
            tcp_observations=[],
        )


def test_rejects_invalid_tcp_collection(shodan_result):
    with pytest.raises(TypeError, match="list or tuple"):
        build_recon_summary(
            domain="example.com",
            shodan_result=shodan_result,
            tcp_observations="invalid",
        )


def test_rejects_invalid_tcp_observation(shodan_result):
    with pytest.raises(TypeError, match="TCPPortObservation"):
        build_recon_summary(
            domain="example.com",
            shodan_result=shodan_result,
            tcp_observations=["invalid"],
        )


def test_empty_tcp_observations_are_valid(shodan_result):
    summary = build_recon_summary(
        domain="example.com",
        shodan_result=shodan_result,
        tcp_observations=[],
    )

    assert summary.tcp_observation_count == 0
    assert summary.open_port_count == 0
    assert summary.identified_service_count == 0
