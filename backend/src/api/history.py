"""ClearCage — History API with pagination, filters, search.

GET /api/history — paginated list of all analyses
GET /api/history/{id} — single analysis detail (alias for results)
"""

from fastapi import APIRouter, Query

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
async def list_analyses(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Results per page"),
    status: str | None = Query(None, description="Filter by status (queued|running|complete|failed)"),
    type_filter: str | None = Query(None, alias="type", description="Filter by type (file|url)"),
    category: str | None = Query(None, description="Filter by verdict category"),
    search: str | None = Query(None, description="Search in target (filename or URL)"),
):
    """List all analyses with pagination and optional filters."""
    from sqlalchemy import select, func
    from storage.database import get_session, Analysis, Verdict

    async with (await get_session).__aenter__() as db:
        query = select(Analysis).options()

        # Apply filters
        if status:
            query = query.where(Analysis.status == status)
        if type_filter:
            query = query.where(Analysis.type == type_filter)
        if category:
            query = query.join(Verdict).where(Verdict.category == category)
        if search:
            query = query.where(Analysis.target.ilike(f"%{search}%"))

        # Count total for pagination
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Paginate
        offset = (page - 1) * per_page
        query = query.order_by(Analysis.created_at.desc()).offset(offset).limit(per_page)
        result = await db.execute(query)
        analyses = result.scalars().all()

        return {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page if per_page else 1,
            "items": [
                {
                    "id": a.id,
                    "type": a.type,
                    "target": a.target,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "verdict": (
                        {
                            "score": a.verdict.score,
                            "category": a.verdict.category,
                            "threat_type": a.verdict.threat_type,
                        }
                        if a.verdict
                        else None
                    ),
                }
                for a in analyses
            ],
        }


@router.get("/stats")
async def get_stats():
    """Dashboard statistics summary."""
    from sqlalchemy import select, func
    from storage.database import get_session, Analysis, Verdict

    async with (await get_session).__aenter__() as db:
        # Total analyses
        total = await db.execute(select(func.count()).select_from(Analysis))
        total_count = total.scalar() or 0

        # By status
        status_result = await db.execute(
            select(Analysis.status, func.count()).group_by(Analysis.status)
        )
        by_status = dict(status_result.all())

        # By verdict category
        cat_result = await db.execute(
            select(Verdict.category, func.count()).group_by(Verdict.category)
        )
        by_category = dict(cat_result.all()) if cat_result.all() else {}

        # Average score
        avg_result = await db.execute(select(func.avg(Verdict.score)))
        avg_score = avg_result.scalar() or 0.0

        return {
            "total_analyses": total_count,
            "by_status": by_status,
            "by_category": by_category,
            "average_score": round(avg_score, 2),
        }
