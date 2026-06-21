"""ClearCage — File/URL upload API endpoints.

POST /api/analyze/file  — upload a file for analysis
POST /api/analyze/url   — submit a URL for analysis
GET  /api/analysis/{id} — retrieve analysis status + verdict
"""

import os
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/api/analyze", tags=["analysis"])

MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))


@router.post("/file", response_class=HTMLResponse)
async def analyze_file(file: UploadFile = File(...)):
    """Upload a file for containerized analysis. Returns HTML fragment (HTMX)."""
    # Size check
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_MB * 1024 * 1024:
        return f'<div class="alert alert-error"><span>File too large (max {MAX_FILE_SIZE_MB}MB)</span></div>'

    # Store encrypted
    from storage.file_store import store_file
    file_id = store_file(content)

    # Create analysis record in DB
    import uuid
    from datetime import datetime, timezone
    from storage.database import get_session, Analysis, AnalysisPhase
    async with (await get_session).__aenter__() as db:
        analysis_id = uuid.uuid4().hex[:12]
        analysis = Analysis(
            id=analysis_id,
            type="file",
            target=f"stored://{file_id}/{file.filename}",
            status="queued",
        )
        # Create phase placeholders
        for phase_name in ("pre_analysis", "static", "intelligence", "sandbox"):
            analysis.phases.append(AnalysisPhase(phase_name=phase_name, status="pending"))
        db.add(analysis)
        await db.commit()

    # Kick off async analysis (fire-and-forget via background task)
    from engine.orchestrator import start_analysis
    import asyncio
    asyncio.create_task(start_analysis(analysis_id))

    return f'''
    <div class="alert alert-success">
        <span>✓ File "{file.filename}" queued for analysis</span>
    </div>
    <a href="/analysis/{analysis_id}" class="btn btn-primary btn-sm mt-2">
        View Results →
    </a>'''


@router.post("/url", response_class=HTMLResponse)
async def analyze_url(request: Request):
    """Submit a URL for analysis. Returns HTML fragment (HTMX)."""
    # Parse form data or JSON body
    try:
        body = await request.body()
        import json
        data = json.loads(body)
        url = data.get("url_input", "")
    except Exception:
        # Fall back to form data
        form = await request.form()
        url = form.get("url_input", "")

    if not url or not url.startswith(("http://", "https://")):
        return '<div class="alert alert-error"><span>Invalid URL — must start with http:// or https://</span></div>'

    # Create analysis record
    import uuid
    from storage.database import get_session, Analysis, AnalysisPhase
    async with (await get_session).__aenter__() as db:
        analysis_id = uuid.uuid4().hex[:12]
        analysis = Analysis(
            id=analysis_id,
            type="url",
            target=url,
            status="queued",
        )
        for phase_name in ("pre_analysis", "static", "intelligence", "sandbox"):
            analysis.phases.append(AnalysisPhase(phase_name=phase_name, status="pending"))
        db.add(analysis)
        await db.commit()

    # Kick off async analysis
    from engine.orchestrator import start_analysis
    import asyncio
    asyncio.create_task(start_analysis(analysis_id))

    return f'''
    <div class="alert alert-success">
        <span>✓ URL queued for analysis</span>
    </div>
    <a href="/analysis/{analysis_id}" class="btn btn-secondary btn-sm mt-2">
        View Results →
    </a>'''
