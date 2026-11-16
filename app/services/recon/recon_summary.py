"""Normalized integration contract for reconnaissance results."""

from __future__ import annotations

from dataclasses import dataclass

from app.services.recon.shodan import ShodanSearchResult
from app.services.recon.tcp_probe import (
    TCPPortObservation,
    TCPPortStatus,
)
from app.services.recon.whois_lookup import normalize_domain


@dataclass(frozen=True, slots=True)
class ReconSummary:
    """Preserve Shodan and live TCP observations in one result."""

    domain: str
    shodan_result: ShodanSearchResult
    tcp_observations: tuple[TCPPortObservation, ...]

    @property
    def shodan_observation_count(self) -> int:
        """Return the number of Shodan observations collected."""
        return len(self.shodan_result.observations)

    @property
    def tcp_observation_count(self) -> int:
        """Return the number of TCP observations collected."""
        return len(self.tcp_observations)

    @property
    def open_port_count(self) -> int:
        """Return the number of successfully connected TCP ports."""
        return sum(
            observation.status == TCPPortStatus.OPEN for observation in self.tcp_observations
        )

    @property
    def closed_port_count(self) -> int:
        """Return the number of TCP ports reported closed."""
        return sum(
            observation.status == TCPPortStatus.CLOSED for observation in self.tcp_observations
        )

    @property
    def filtered_port_count(self) -> int:
        """Return the number of TCP ports that timed out."""
        return sum(
            observation.status == TCPPortStatus.FILTERED for observation in self.tcp_observations
        )

    @property
    def error_port_count(self) -> int:
        """Return the number of TCP probes with errors."""
        return sum(
            observation.status == TCPPortStatus.ERROR for observation in self.tcp_observations
        )

    @property
    def identified_service_count(self) -> int:
        """Count open TCP observations with a service estimate."""
        return sum(
            observation.status == TCPPortStatus.OPEN and observation.service_name is not None
            for observation in self.tcp_observations
        )


def build_recon_summary(
    domain: str,
    shodan_result: ShodanSearchResult,
    tcp_observations: tuple[TCPPortObservation, ...] | list[TCPPortObservation],
) -> ReconSummary:
    """Validate and combine existing Shodan and TCP reconnaissance results."""

    normalized_domain = normalize_domain(domain)

    if not isinstance(shodan_result, ShodanSearchResult):
        raise TypeError("shodan_result must be a ShodanSearchResult.")

    if shodan_result.domain != normalized_domain:
        raise ValueError("Shodan result domain does not match the requested domain.")

    if not isinstance(tcp_observations, (tuple, list)):
        raise TypeError("tcp_observations must be a list or tuple.")

    if not all(isinstance(observation, TCPPortObservation) for observation in tcp_observations):
        raise TypeError("Every TCP observation must be a TCPPortObservation.")

    return ReconSummary(
        domain=normalized_domain,
        shodan_result=shodan_result,
        tcp_observations=tuple(tcp_observations),
    )
