import pytest

from app.services.recon.email_harvester import (
    EmailObservation,
    extract_emails,
    merge_email_observations,
    normalize_email,
    validate_source,
)


def test_normalize_email_lowercases_domain():
    assert normalize_email("Security@EXAMPLE.COM") == ("Security@example.com")


def test_normalize_email_preserves_local_part():
    assert normalize_email("Admin@Example.com") == ("Admin@example.com")


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "not-an-email",
        "@example.com",
        "user@",
        "user@example",
        "user..name@example.com",
        ".user@example.com",
        "user.@example.com",
        "user@example..com",
        "user@-example.com",
        "user@example-.com",
        "user@@example.com",
    ],
)
def test_invalid_email_candidates_are_rejected(candidate):
    assert normalize_email(candidate) is None


def test_extract_emails_from_text():
    text = """
    Contact security@example.com for security issues.
    General enquiries: info@example.org
    """

    result = extract_emails(
        text,
        source="https://example.com/contact",
    )

    assert result == (
        EmailObservation(
            email="security@example.com",
            source="https://example.com/contact",
        ),
        EmailObservation(
            email="info@example.org",
            source="https://example.com/contact",
        ),
    )


def test_extract_emails_deduplicates_case_insensitively():
    text = """
    Security@Example.com
    security@example.com
    SECURITY@EXAMPLE.COM
    """

    result = extract_emails(
        text,
        source="https://example.com",
    )

    assert len(result) == 1
    assert result[0].email == "Security@example.com"


def test_extract_emails_ignores_invalid_candidates():
    text = """
    valid@example.com
    invalid@@example.com
    another@example.org
    """

    result = extract_emails(
        text,
        source="https://example.com",
    )

    assert [item.email for item in result] == [
        "valid@example.com",
        "another@example.org",
    ]


def test_extract_emails_requires_string():
    with pytest.raises(TypeError):
        extract_emails(
            text=123,
            source="https://example.com",
        )


def test_extract_emails_requires_valid_source():
    with pytest.raises(ValueError):
        extract_emails(
            text="security@example.com",
            source="ftp://example.com",
        )


def test_source_rejects_credentials():
    with pytest.raises(ValueError):
        validate_source("https://user:password@example.com/contact")


def test_merge_email_observations():
    first = (
        EmailObservation(
            email="security@example.com",
            source="https://example.com/security",
        ),
    )

    second = (
        EmailObservation(
            email="security@EXAMPLE.COM",
            source="https://example.com/contact",
        ),
        EmailObservation(
            email="info@example.com",
            source="https://example.com/contact",
        ),
    )

    result = merge_email_observations(first, second)

    assert len(result) == 2
    assert result[0].source == "https://example.com/security"
    assert result[1].email == "info@example.com"


def test_merge_rejects_invalid_observation():
    with pytest.raises(TypeError):
        merge_email_observations((object(),))


def test_empty_text_returns_empty_tuple():
    result = extract_emails(
        text="No email addresses here.",
        source="https://example.com",
    )

    assert result == ()
