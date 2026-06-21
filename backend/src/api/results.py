"""ClearCage — Analysis result API + SSE stream endpoints.

GET  /api/analysis/{id}        — full analysis status + verdict (JSON)
GET  /api/analysis/{id}/stream — SSE stream for real-time updates
GET  /api/export/{id}/json     — JSON export of analysis report
GET  /api/export/{id}/csv      — CSV export of indicators
"""

import csv
import io
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, Response

router = APIRouter(prefix="/api", tags=["results"])


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Retrieve full analysis status, phases, and verdict."""
    from storage.database import get_session, Analysis

    async with (await get_session).__aenter__() as db:
        analysis = await db.get(Analysis, analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        return {
            "id": analysis.id,
            "type": analysis.type,
            "target": analysis.target,
            "status": analysis.status,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "updated_at": analysis.updated_at.isoformat() if analysis.updated_at else None,
            "phases": [
                {
                    "name": p.phase_name,
                    "status": p.status,
                    "started_at": p.started_at.isoformat() if p.started_at else None,
                    "completed_at": p.completed_at.isoformat() if p.completed_at else None,
                    "findings": json.loads(p.raw_output) if p.raw_output else {},
                }
                for p in analysis.phases
            ],
            "verdict": (
                {
                    "score": analysis.verdict.score,
                    "category": analysis.verdict.category,
                    "threat_type": analysis.verdict.threat_type,
                    "summary": analysis.verdict.summary,
                }
                if analysis.verdict
                else None
            ),
        }


@router.get("/analysis/{analysis_id}/stream")
async def stream_analysis(analysis_id: str):
    """SSE stream for real-time analysis progress updates."""
    from engine.orchestrator import sse_bus

    queue = sse_bus.subscribe(analysis_id)

    async def event_generator():
        try:
            while True:
                try:
                    message = await queue.get()
                    yield f"data: {message}\n\n"
                except Exception:
                    break
        finally:
            sse_bus.unsubscribe(analysis_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


@router.get("/export/{analysis_id}/json")
async def export_json(analysis_id: str):
    """Export full analysis report as JSON (for SIEM/ticketing integration)."""
    from storage.database import get_session, Analysis

    async with (await get_session).__aenter__() as db:
        analysis = await db.get(Analysis, analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        report = {
            "clearcage_report": True,
            "version": "0.1.0",
            "analysis_id": analysis.id,
            "type": analysis.type,
            "target": analysis.target,
            "status": analysis.status,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "phases": [],
            "verdict": None,
        }

        for p in analysis.phases:
            report["phases"].append({
                "name": p.phase_name,
                "status": p.status,
                "findings": json.loads(p.raw_output) if p.raw_output else {},
            })

        if analysis.verdict:
            report["verdict"] = {
                "score": analysis.verdict.score,
                "category": analysis.verdict.category,
                "threat_type": analysis.verdict.threat_type,
                "summary": analysis.verdict.summary,
            }

    return Response(
        content=json.dumps(report, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="clearcage-{analysis_id}.json"'},
    )


@router.get("/export/{analysis_id}/csv")
async def export_csv(analysis_id: str):
    """Export analysis indicators as CSV (for SIEM/ticketing integration)."""
    from storage.database import get_session, Analysis

    async with (await get_session).__aenter__() as db:
        analysis = await db.get(Analysis, analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["phase", "indicator", "value"])

        for p in analysis.phases:
            findings = json.loads(p.raw_output) if p.raw_output else {}
            for key, value in _flatten_dict(findings).items():
                writer.writerow([p.phase_name, key, str(value)])

        # Include verdict indicators if available
        if analysis.verdict:
            writer.writerow(["verdict", "score", str(analysis.verdict.score)])
            writer.writerow(["verdict", "category", analysis.verdict.category])
            writer.writerow(["verdict", "threat_type", analysis.verdict.threat_type])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="clearcage-{analysis_id}.csv"'},
    )


def _flatten_dict(d, parent_key="", sep="."):
    """Flatten a nested dict for CSV export."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list):
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, v))
    return dict(items)
