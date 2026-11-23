from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.schemas.analytics import AnalyticsOverviewResponse
from app.services.dashboard.analytics import get_analytics_overview

router = APIRouter(
    prefix="/analytics",
    tags=["Analytics"],
)


@router.get(
    "/overview",
    response_model=AnalyticsOverviewResponse,
)
async def analytics_overview(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> AnalyticsOverviewResponse:
    data = await get_analytics_overview(session)
    return AnalyticsOverviewResponse(**data)
