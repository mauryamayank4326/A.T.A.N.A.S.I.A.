"""Persistence operations for reconnaissance observations."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.exposed_port import ExposedPort
from app.models.scan import Scan
from app.models.target import Target
from app.services.recon.shodan import ShodanSearchResult
from app.services.recon.tcp_probe import (
    TCPPortObservation,
    TCPPortStatus,
)
from app.services.recon.whois_lookup import normalize_domain


@dataclass(frozen=True, slots=True)
class PersistenceSummary:
    """Summarize reconnaissance persistence operations."""

    inserted: int
    updated: int
    unchanged: int

    @property
    def total_processed(self) -> int:
        """Return the number of unique observations processed."""
        return self.inserted + self.updated + self.unchanged


def _validate_port(port: int) -> None:
    """Validate a network port number."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("Port must be an integer.")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")


def _normalize_host(host: str) -> str:
    """Validate and normalize a host identifier."""
    if not isinstance(host, str):
        raise TypeError("Host must be a string.")

    normalized = host.strip().lower()

    if not normalized:
        raise ValueError("Host cannot be empty.")

    if len(normalized) > 253:
        raise ValueError("Host exceeds the database column length.")

    return normalized


def _build_observation_map(
    shodan_result: ShodanSearchResult,
    tcp_observations: tuple[TCPPortObservation, ...],
) -> dict[tuple[str, int, str], str | None]:
    """Combine supported observations using the database uniqueness key."""
    observations: dict[
        tuple[str, int, str],
        str | None,
    ] = {}

    for item in shodan_result.observations:
        host = _normalize_host(item.ip)
        _validate_port(item.port)

        protocol = item.transport.strip().lower()

        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported Shodan transport: {item.transport!r}")

        key = (host, item.port, protocol)
        observations.setdefault(key, None)

    for item in tcp_observations:
        if not isinstance(item, TCPPortObservation):
            raise TypeError("Every TCP observation must be a TCPPortObservation.")

        if item.status != TCPPortStatus.OPEN:
            continue

        host = _normalize_host(item.host)
        _validate_port(item.port)

        key = (host, item.port, "tcp")
        service_name = item.service_name

        if service_name is not None:
            service_name = service_name.strip() or None

        existing_service = observations.get(key)

        if existing_service is None or service_name is not None:
            observations[key] = service_name

    return observations


async def execute_scan_persistence(
    session: AsyncSession,
    scan_id: UUID,
    shodan_result: ShodanSearchResult,
    tcp_observations: tuple[TCPPortObservation, ...] | list[TCPPortObservation],
) -> PersistenceSummary:
    """Persist scan results as one transaction.

    This is the service-layer entry point for callers that need
    reconnaissance persistence committed atomically.
    """
    try:
        summary = await persist_reconnaissance_results(
            session=session,
            scan_id=scan_id,
            shodan_result=shodan_result,
            tcp_observations=tcp_observations,
        )

        await session.commit()

        return summary

    except Exception:
        await session.rollback()
        raise


async def persist_reconnaissance_results(
    session: AsyncSession,
    scan_id: UUID,
    shodan_result: ShodanSearchResult,
    tcp_observations: tuple[TCPPortObservation, ...] | list[TCPPortObservation],
) -> PersistenceSummary:
    """Persist Shodan and open TCP observations for an existing scan.

    The caller owns transaction commit and rollback.

    Args:
        session: Active SQLAlchemy asynchronous session.
        scan_id: UUID of the scan receiving the observations.
        shodan_result: Normalized Shodan search result.
        tcp_observations: TCP port observations.

    Returns:
        Counts of inserted, updated, and unchanged records.

    Raises:
        TypeError: If supplied objects have invalid types.
        ValueError: If the scan does not exist or observations are invalid.
        sqlalchemy.exc.SQLAlchemyError: If database operations fail.
    """
    if not isinstance(session, AsyncSession):
        raise TypeError("session must be an AsyncSession.")

    if not isinstance(scan_id, UUID):
        raise TypeError("scan_id must be a UUID.")

    if not isinstance(shodan_result, ShodanSearchResult):
        raise TypeError("shodan_result must be a ShodanSearchResult.")

    if not isinstance(tcp_observations, list | tuple):
        raise TypeError("tcp_observations must be a list or tuple.")

    tcp_items = tuple(tcp_observations)

    if any(not isinstance(item, TCPPortObservation) for item in tcp_items):
        raise TypeError("Every TCP observation must be a TCPPortObservation.")

    scan_domain = await session.scalar(
        select(Target.domain).join(Scan, Scan.target_id == Target.id).where(Scan.id == scan_id)
    )

    if scan_domain is None:
        raise ValueError(f"Scan {scan_id} does not exist.")

    if normalize_domain(shodan_result.domain) != normalize_domain(scan_domain):
        raise ValueError("Shodan result domain does not match the scan target domain.")

    observation_map = _build_observation_map(
        shodan_result,
        tcp_items,
    )

    if not observation_map:
        return PersistenceSummary(
            inserted=0,
            updated=0,
            unchanged=0,
        )

    existing_records = await session.scalars(
        select(ExposedPort).where(ExposedPort.scan_id == scan_id)
    )

    existing_map = {
        (
            record.host.lower(),
            record.port,
            record.protocol.lower(),
        ): record
        for record in existing_records
    }

    inserted = 0
    updated = 0
    unchanged = 0

    for key, service_name in observation_map.items():
        host, port, protocol = key
        existing = existing_map.get(key)

        if existing is None:
            record = ExposedPort(
                scan_id=scan_id,
                host=host,
                port=port,
                protocol=protocol,
                service_name=service_name,
            )
            session.add(record)
            inserted += 1
            continue

        if existing.service_name is None and service_name is not None:
            existing.service_name = service_name
            updated += 1
        else:
            unchanged += 1

    await session.flush()

    return PersistenceSummary(
        inserted=inserted,
        updated=updated,
        unchanged=unchanged,
    )
