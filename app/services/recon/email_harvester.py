from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Conservative candidate extraction.
# This is not a complete implementation of every RFC mailbox syntax.
EMAIL_PATTERN = re.compile(
    r"(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
    r"(?![A-Z0-9-])",
    re.IGNORECASE,
)

MAX_EMAIL_LENGTH = 254
MAX_LOCAL_PART_LENGTH = 64
MAX_DOMAIN_LENGTH = 253


class EmailHarvestError(Exception):
    """Base exception for email harvesting."""


@dataclass(frozen=True, slots=True)
class EmailObservation:
    """A normalized email address and its source attribution."""

    email: str
    source: str


def normalize_email(candidate: str) -> str | None:
    """
    Normalize a candidate email address.

    The local part is preserved. The domain is lowercased.
    Returns None for candidates outside the supported syntax.
    """

    if not isinstance(candidate, str):
        return None

    value = candidate.strip()

    if not value or len(value) > MAX_EMAIL_LENGTH:
        return None

    if value.count("@") != 1:
        return None

    local_part, domain = value.rsplit("@", 1)

    if not local_part or not domain:
        return None

    if len(local_part) > MAX_LOCAL_PART_LENGTH:
        return None

    if len(domain) > MAX_DOMAIN_LENGTH:
        return None

    if local_part.startswith(".") or local_part.endswith("."):
        return None

    if ".." in local_part:
        return None

    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+",
        local_part,
    ):
        return None

    domain = domain.lower()

    labels = domain.split(".")

    if len(labels) < 2:
        return None

    for label in labels:
        if not label or len(label) > 63:
            return None

        if label.startswith("-") or label.endswith("-"):
            return None

        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None

    return f"{local_part}@{domain}"


def validate_source(source: str) -> str:
    """
    Validate and normalize a source URL or source identifier.

    HTTP and HTTPS URLs are accepted. Other non-empty identifiers
    are retained for non-URL source references.
    """

    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")

    value = source.strip()

    parsed = urlparse(value)

    if parsed.scheme or parsed.netloc:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("source URL must use HTTP or HTTPS")

        if not parsed.hostname:
            raise ValueError("source URL must contain a hostname")

        if parsed.username or parsed.password:
            raise ValueError("source URL must not contain credentials")

    return value


def extract_emails(
    text: str,
    source: str,
) -> tuple[EmailObservation, ...]:
    """
    Extract and deduplicate email candidates from supplied text.

    The first occurrence of an address is retained.
    Deduplication is case-insensitive for the complete address,
    while the output preserves the first local-part representation.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    normalized_source = validate_source(source)

    observations: list[EmailObservation] = []
    seen: set[str] = set()

    for match in EMAIL_PATTERN.finditer(text):
        normalized = normalize_email(match.group(0))

        if normalized is None:
            continue

        comparison_key = normalized.casefold()

        if comparison_key in seen:
            continue

        seen.add(comparison_key)

        observations.append(
            EmailObservation(
                email=normalized,
                source=normalized_source,
            )
        )

    return tuple(observations)


def merge_email_observations(
    *collections: tuple[EmailObservation, ...],
) -> tuple[EmailObservation, ...]:
    """
    Merge multiple observation collections without duplicate addresses.

    The first observation encountered is retained.
    """

    merged: list[EmailObservation] = []
    seen: set[str] = set()

    for collection in collections:
        for observation in collection:
            if not isinstance(observation, EmailObservation):
                raise TypeError("collections must contain EmailObservation objects")

            key = observation.email.casefold()

            if key in seen:
                continue

            seen.add(key)
            merged.append(observation)

    return tuple(merged)
