"""Concurrent reconnaissance task orchestration."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from enum import Enum

from app.services.recon.shodan import search_shodan_hosts
from app.services.recon.tcp_probe import scan_tcp_ports


class ReconTaskStatus(str, Enum):
    """Represent the execution state of a reconnaissance task."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class ReconTask:
    """Represent an independently executable reconnaissance task."""

    name: str
    execute: Callable[[], Awaitable[object]]
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Task name cannot be empty.")

        if not callable(self.execute):
            raise TypeError("Task execute must be callable.")

        if self.timeout_seconds is not None:
            if isinstance(self.timeout_seconds, bool) or not isinstance(
                self.timeout_seconds, int | float
            ):
                raise TypeError("Task timeout must be numeric.")

            if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
                raise ValueError("Task timeout must be a positive finite number.")


@dataclass(frozen=True, slots=True)
class ReconTaskResult:
    """Store the outcome of one reconnaissance task."""

    name: str
    status: ReconTaskStatus
    duration_ms: float
    value: object | None = None
    error_type: str | None = None

    @property
    def succeeded(self) -> bool:
        """Return whether the task succeeded."""
        return self.status == ReconTaskStatus.SUCCESS


@dataclass(frozen=True, slots=True)
class ReconExecutionReport:
    """Represent the consolidated reconnaissance execution report."""

    results: tuple[ReconTaskResult, ...]

    @property
    def total_tasks(self) -> int:
        return len(self.results)

    @property
    def successful_tasks(self) -> int:
        return sum(result.status == ReconTaskStatus.SUCCESS for result in self.results)

    @property
    def failed_tasks(self) -> int:
        return sum(result.status == ReconTaskStatus.FAILED for result in self.results)

    @property
    def timed_out_tasks(self) -> int:
        return sum(result.status == ReconTaskStatus.TIMED_OUT for result in self.results)

    @property
    def completed_successfully(self) -> bool:
        """Return true only when every task succeeded."""
        return self.total_tasks > 0 and self.successful_tasks == self.total_tasks


def _validate_timeout(value: float) -> None:
    """Validate the default execution timeout."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError("Default timeout must be numeric.")

    if not math.isfinite(value) or value <= 0:
        raise ValueError("Default timeout must be a positive finite number.")


async def _execute_task(
    task: ReconTask,
    semaphore: asyncio.Semaphore,
    default_timeout_seconds: float,
) -> ReconTaskResult:
    """Execute one task under a concurrency limit and timeout."""

    timeout = task.timeout_seconds if task.timeout_seconds is not None else default_timeout_seconds

    async with semaphore:
        started_at = time.perf_counter()

        try:
            value = await asyncio.wait_for(
                task.execute(),
                timeout=timeout,
            )

            duration_ms = (time.perf_counter() - started_at) * 1000

            return ReconTaskResult(
                name=task.name,
                status=ReconTaskStatus.SUCCESS,
                duration_ms=duration_ms,
                value=value,
            )

        except TimeoutError:
            duration_ms = (time.perf_counter() - started_at) * 1000

            return ReconTaskResult(
                name=task.name,
                status=ReconTaskStatus.TIMED_OUT,
                duration_ms=duration_ms,
                error_type="TimeoutError",
            )

        except Exception as exc:
            duration_ms = (time.perf_counter() - started_at) * 1000

            return ReconTaskResult(
                name=task.name,
                status=ReconTaskStatus.FAILED,
                duration_ms=duration_ms,
                error_type=type(exc).__name__,
            )


async def run_concurrent_reconnaissance(
    tasks: Sequence[ReconTask],
    max_concurrency: int = 5,
    default_timeout_seconds: float = 15.0,
) -> ReconExecutionReport:
    """Run independent reconnaissance tasks concurrently.

    Each task has an isolated result. Ordinary task exceptions and
    timeouts do not prevent other tasks from completing.

    Args:
        tasks: Reconnaissance tasks to execute.
        max_concurrency: Maximum simultaneous task executions.
        default_timeout_seconds: Timeout used when a task does not
            define its own timeout.

    Returns:
        A consolidated execution report.

    Raises:
        TypeError: If arguments have invalid types.
        ValueError: If configuration or task names are invalid.
        asyncio.CancelledError: If the orchestrator itself is cancelled.
    """
    if not isinstance(tasks, list | tuple):
        raise TypeError("tasks must be a list or tuple.")

    if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
        raise TypeError("max_concurrency must be an integer.")

    if max_concurrency < 1:
        raise ValueError("max_concurrency must be at least 1.")

    _validate_timeout(default_timeout_seconds)

    task_list = tuple(tasks)

    if any(not isinstance(task, ReconTask) for task in task_list):
        raise TypeError("Every item must be a ReconTask.")

    names = [task.name for task in task_list]

    if len(names) != len(set(names)):
        raise ValueError("Reconnaissance task names must be unique.")

    semaphore = asyncio.Semaphore(max_concurrency)

    results = await asyncio.gather(
        *(
            _execute_task(
                task,
                semaphore,
                default_timeout_seconds,
            )
            for task in task_list
        )
    )

    return ReconExecutionReport(
        results=tuple(results),
    )


async def run_target_reconnaissance(
    domain,
    client,
    api_key,
    host,
    ports,
):
    tasks = [
        ReconTask(
            name="shodan",
            execute=lambda: search_shodan_hosts(
                domain=domain,
                client=client,
                api_key=api_key,
            ),
            timeout_seconds=12,
        ),
        ReconTask(
            name="tcp_ports",
            execute=lambda: scan_tcp_ports(
                host=host,
                ports=ports,
            ),
            timeout_seconds=15,
        ),
    ]

    return await run_concurrent_reconnaissance(
        tasks=tasks,
        max_concurrency=2,
        default_timeout_seconds=15,
    )
