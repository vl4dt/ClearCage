"""ClearCage — FastAPI application factory."""

from contextlib import asynccontextmanager
import logging
import os

from fastapi import FastAPI
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ── Lifespan ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    from storage.database import init_db
    from engine.scoring import load_scoring_config
    from engine.jobs import start_jobs, stop_jobs

    await init_db()
    load_scoring_config()
    start_jobs()

    logging.info("ClearCage backend started")
    yield
    stop_jobs()
    logging.info("ClearCage backend shutting down")


# ── App Factory ─────────────────────────────────────────────────────

app = FastAPI(
    title="ClearCage",
    description="Threat analysis platform — static + dynamic sandbox",
    version="0.1.0",
    lifespan=lifespan,
)

# Templates (Jinja2 + HTMX)
templates = Jinja2Templates(directory="src/templates")

# Static files (CSS, JS helpers)
app.mount("/static", StaticFiles(directory="static"), name="static")

# API routers
from api.analyze import router as analyze_router
from api.results import router as results_router
from api.history import router as history_router
app.include_router(analyze_router)
app.include_router(results_router)
app.include_router(history_router)


# ── Page Routes ─────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request):
    """Landing page with quick submit forms."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/submit/file", response_class=HTMLResponse)
async def submit_file_page(request):
    """File upload page."""
    return templates.TemplateResponse("submit_file.html", {"request": request})


@app.get("/submit/url", response_class=HTMLResponse)
async def submit_url_page(request):
    """URL analysis submission page."""
    return templates.TemplateResponse("submit_url.html", {"request": request})


@app.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_page(request, analysis_id: str):
    """Live results viewer (SSE-driven)."""
    return templates.TemplateResponse(
        "analysis.html",
        {"request": request, "analysis_id": analysis_id},
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request):
    """Stats, heatmaps, trend charts."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/history", response_class=HTMLResponse)
async def history_page(request):
    """Searchable scan log."""
    return templates.TemplateResponse("history.html", {"request": request})
