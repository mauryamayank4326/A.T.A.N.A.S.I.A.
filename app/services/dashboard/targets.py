"""Read-only query operations for the dashboard target console."""

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.target import Target


@dataclass(frozen=True, slots=True)
class TargetListResult:
    """Paginated target listing."""

    items: Sequence[Target]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        if self.total == 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size


def _validate_pagination(page: int, page_size: int) -> None:
    if isinstance(page, bool) or not isinstance(page, int) or page < 1:
        raise ValueError("page must be a positive integer")

    if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
        raise ValueError("page_size must be between 1 and 100")


async def list_targets(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
) -> TargetListResult:
    """Return targets in stable, paginated order."""

    _validate_pagination(page, page_size)

    count_statement = select(func.count()).select_from(Target)
    total = await session.scalar(count_statement)
    total = int(total or 0)

    statement = (
        select(Target)
        .options(selectinload(Target.scans))
        .order_by(Target.domain.asc(), Target.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )

    result = await session.scalars(statement)
    targets = result.unique().all()

    return TargetListResult(
        items=targets,
        total=total,
        page=page,
        page_size=page_size,
    )


async def get_target_by_id(
    session: AsyncSession,
    target_id: UUID,
) -> Target | None:
    """Retrieve one target and its scans."""

    statement = select(Target).where(Target.id == target_id).options(selectinload(Target.scans))

    result = await session.scalars(statement)
    return result.unique().one_or_none()
