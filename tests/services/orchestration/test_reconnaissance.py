"""Tests for concurrent reconnaissance orchestration."""

import asyncio

import pytest

from app.services.orchestration.reconnaissance import (
    ReconTask,
    ReconTaskStatus,
    build_email_task,
    run_concurrent_reconnaissance,
)


@pytest.mark.asyncio
async def test_successful_task_returns_result():
    """A successful task should preserve its return value."""

    async def collector():
        return {"domain": "example.com"}

    report = await run_concurrent_reconnaissance(
        tasks=[
            ReconTask(
                name="collector",
                execute=collector,
            )
        ]
    )

    assert report.total_tasks == 1
    assert report.successful_tasks == 1
    assert report.failed_tasks == 0
    assert report.timed_out_tasks == 0

    assert report.results[0].value == {"domain": "example.com"}


@pytest.mark.asyncio
async def test_task_failure_is_isolated():
    """One failed task must not prevent another from succeeding."""

    async def successful_collector():
        return "success"

    async def failing_collector():
        raise RuntimeError("Simulated provider failure.")

    report = await run_concurrent_reconnaissance(
        tasks=[
            ReconTask(
                name="successful",
                execute=successful_collector,
            ),
            ReconTask(
                name="failing",
                execute=failing_collector,
            ),
        ]
    )

    assert report.total_tasks == 2
    assert report.successful_tasks == 1
    assert report.failed_tasks == 1

    assert report.results[0].status == ReconTaskStatus.SUCCESS
    assert report.results[1].status == ReconTaskStatus.FAILED
    assert report.results[1].error_type == "RuntimeError"


@pytest.mark.asyncio
async def test_task_timeout_is_reported():
    """A task exceeding its timeout should be marked timed out."""

    async def slow_collector():
        await asyncio.sleep(1)
        return "finished"

    report = await run_concurrent_reconnaissance(
        tasks=[
            ReconTask(
                name="slow",
                execute=slow_collector,
                timeout_seconds=0.01,
            )
        ]
    )

    assert report.timed_out_tasks == 1
    assert report.results[0].status == ReconTaskStatus.TIMED_OUT


@pytest.mark.asyncio
async def test_concurrency_limit_is_respected():
    """The maximum active task count should not exceed the limit."""

    active = 0
    maximum_active = 0

    async def collector():
        nonlocal active, maximum_active

        active += 1
        maximum_active = max(maximum_active, active)

        try:
            await asyncio.sleep(0.03)
            return "complete"
        finally:
            active -= 1

    tasks = [
        ReconTask(
            name=f"collector-{index}",
            execute=collector,
        )
        for index in range(6)
    ]

    report = await run_concurrent_reconnaissance(
        tasks=tasks,
        max_concurrency=2,
    )

    assert report.successful_tasks == 6
    assert maximum_active <= 2


@pytest.mark.asyncio
async def test_empty_task_list_returns_empty_report():
    """An empty task collection should return an empty report."""

    report = await run_concurrent_reconnaissance(
        tasks=[],
    )

    assert report.total_tasks == 0
    assert report.successful_tasks == 0
    assert report.failed_tasks == 0
    assert report.timed_out_tasks == 0
    assert report.completed_successfully is False


@pytest.mark.asyncio
async def test_duplicate_task_names_are_rejected():
    """Task names must be unique."""

    async def collector():
        return None

    tasks = [
        ReconTask(name="shodan", execute=collector),
        ReconTask(name="shodan", execute=collector),
    ]

    with pytest.raises(ValueError, match="unique"):
        await run_concurrent_reconnaissance(tasks)


@pytest.mark.asyncio
async def test_invalid_concurrency_is_rejected():
    """Concurrency must be a positive integer."""

    with pytest.raises(ValueError):
        await run_concurrent_reconnaissance(
            tasks=[],
            max_concurrency=0,
        )


@pytest.mark.asyncio
async def test_task_duration_is_recorded():
    """Execution results should include elapsed time."""

    async def collector():
        await asyncio.sleep(0.01)
        return "complete"

    report = await run_concurrent_reconnaissance(
        tasks=[
            ReconTask(
                name="duration-test",
                execute=collector,
            )
        ]
    )

    assert report.results[0].duration_ms > 0


@pytest.mark.asyncio
async def test_individual_task_timeout_overrides_default():
    """A task-specific timeout should override the default."""

    async def collector():
        await asyncio.sleep(0.02)
        return "complete"

    report = await run_concurrent_reconnaissance(
        tasks=[
            ReconTask(
                name="custom-timeout",
                execute=collector,
                timeout_seconds=0.5,
            )
        ],
        default_timeout_seconds=0.001,
    )

    assert report.successful_tasks == 1


@pytest.mark.asyncio
async def test_email_task_extracts_from_precollected_source_texts():
    task = build_email_task(
        [
            ("https://example.com/contact", "security@example.com"),
            ("https://example.org/about", "info@example.org"),
        ]
    )

    report = await run_concurrent_reconnaissance(tasks=[task])

    assert report.results[0].name == "email_harvest"
    assert report.results[0].status == ReconTaskStatus.SUCCESS
    assert [
        (observation.email, observation.source)
        for observation in report.results[0].value
    ] == [
        ("security@example.com", "https://example.com/contact"),
        ("info@example.org", "https://example.org/about"),
    ]
