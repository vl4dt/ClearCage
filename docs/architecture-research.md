# ClearCage — Architecture Design Document

> Created: 2026-06-21  
> Status: Grilled and finalized  
> Related: [CONTEXT.md](../CONTEXT.md), [ADR-0001: DinD Isolation](adr/0001-dind-isolation.md)

---

## Project Vision

A cross-platform (Windows / Linux / macOS) web application for analyzing suspicious files and URLs through containerized static and dynamic analysis, with real-time progress tracking and structured threat classification.

**Core principles:**
- Secure by default — Docker-in-Docker isolated analysis, no host contamination
- Efficient — lightweight API-driven intel + containerized deep scans
- Effective — identifies threat type (phishing, malware, ransomware, drive-by, packed, etc.)
- Cross-platform — one `docker compose up`, one `docker compose down -v`

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     docker-compose.yml                          │
│                                                                 │
│  ┌──────────────────────┐    ┌─────────────────────────────┐    │
│  │   FastAPI Backend    │◄──►│   CAPEv2 Sandbox Service    │    │
│  │                      │    │   (systemcrafters/capeweb)  │    │
│  │  • HTML templates    │    │                             │    │
│  │  • REST API          │    │  Dynamic execution sandbox  │    │
│  │  • SSE streaming     │    │  Runtime behavior analysis  │    │
│  │  • DinD daemon       │    │  C2, FS, registry changes   │    │
│  │  • SQLite storage    │    └─────────────────────────────┘    │
│  │                      │                                       │
│  │  DinD spawns:        │    ┌─────────────────────────────┐    │
│  │  • remnux/yara       │    │   Shared Volumes            │    │
│  │  • remnux/pefile     │    │   • yara-rules (ro)         │    │
│  │  • remnux/remnux-    │    │   • samples (encrypted)     │    │
│  │    distro            │    │   • sqlite.db               │    │
│  └──────────────────────┘    └─────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**One repo, two services, one command.** The FastAPI backend serves HTML pages, REST API endpoints, and SSE streams. DinD inside the backend spawns ephemeral analysis containers. CAPEv2 runs as a separate service for dynamic sandboxing.

---

## 2. Technology Stack (Final)

### Backend: Python / FastAPI

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Framework | **FastAPI** | Async-native, auto OpenAPI docs, native malware analysis ecosystem |
| Docker SDK | **docker-py** | Official Python SDK for DinD container orchestration |
| Analysis libs | **pefile**, **yara-python**, **oletools**, **magika**, **ssdeep** | Battle-tested Python libraries for structured parsing |
| Database | **SQLite** (WAL mode) | Zero extra services, file-based, ships with Python |
| ORM | **SQLAlchemy** or **Tortoise-ORM** | SQLAlchemy for sync flexibility, Tortoise for async-native |
| File encryption | **cryptography** (Fernet/AES-256) | Sample storage at rest |

### Frontend: Server-Rendered HTML (No JS Framework)

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Templating | **Jinja2** | FastAPI-native, fast, powerful template inheritance |
| CSS framework | **Tailwind CSS + daisyUI** | Modern component-rich UI, zero JS required |
| Interactivity | **HTMX** | Server-driven UI updates, native SSE support |
| Charts | **ApexCharts** | Radial gauges, heatmaps, trend lines (vanilla JS) |
| Tables | **Tabulator** or **DataTables** | Sortable/filterable IOC grids (vanilla JS) |

### Why No React/Vue/Svelte?

- Eliminates Node.js runtime, build step, and separate frontend container
- HTMX + SSE handles real-time updates natively (`hx-trigger="sse:..."`)
- ApexCharts + Tabulator provide all needed data viz without framework wrappers
- One language (Python), one container, one deploy command
- "Sacrifice React, not Python" — Python's malware analysis ecosystem is irreplaceable

---

## 3. Docker Analysis Engine

### Phase Pipeline

```
Analysis Request → Orchestrator → Phase Pipeline:
  ┌─────────────────────────────────────────────────────────┐
  │ Phase 1: Pre-Analysis (native Python, no Docker)        │
  │   ├─ File hash (SHA-256, MD5, SHA-1)                   │
  │   ├─ File type detection (magic bytes via magika)       │
  │   └─ Extension mismatch check                           │
  ├─────────────────────────────────────────────────────────┤
  │ Phase 2: Static Analysis (DinD ephemeral containers)    │
  │   ├─ YARA scan → malware family pattern matching        │
  │   ├─ PE analysis → imports, sections, entropy           │
  │   ├─ Strings + regex → IOC extraction                   │
  │   ├─ Office docs → macro detection (oletools)           │
  │   └─ PDFs → embedded scripts (pdfid, pdftotext)         │
  ├─────────────────────────────────────────────────────────┤
  │ Phase 3: Threat Intelligence (external APIs)            │
  │   ├─ VirusTotal → multi-engine reputation               │
  │   ├─ URLScan.io → URL behavior analysis                 │
  │   └─ AbuseIPDB → IP/domain reputation                   │
  ├─────────────────────────────────────────────────────────┤
  │ Phase 4: Dynamic Sandbox (CAPEv2, always enabled)       │
  │   └─ CAPE REST API → runtime behavior, C2, FS changes   │
  ├─────────────────────────────────────────────────────────┤
  │ Phase 5: Scoring & Classification                       │
  │   └─ ThreatScoringEngine → verdict + categories + IOCs  │
  └─────────────────────────────────────────────────────────┘
```

### Ephemeral Container Strategy (Static Phases)

| Container | Image | Duration | Network | Detects |
|-----------|-------|----------|---------|---------|
| YARA scan | `remnux/yara:latest` | ~5s | none | Malware families, known patterns |
| PE analysis | `remnux/pefile:latest` | ~3s | none | Suspicious imports, packed sections, high entropy |
| Strings/IOCs | `remnux/remnux-distro:noble` | ~2s | none | Embedded URLs, IPs, commands, registry keys |
| Office macros | `remnux/remnux-distro:noble` (oletools) | ~3s | none | Macro malware in DOC/XLS/PPT |
| PDF analysis | `remnux/remnux-distro:noble` (pdfid/pdftotext) | ~2s | none | Embedded JS, forms, suspicious objects |

### CAPEv2 Dynamic Sandbox (Phase 4)

| Aspect | Configuration |
|--------|--------------|
| Image | `systemcrafters/capeweb:latest` |
| Duration | 60-180s per sample |
| Network | Isolated bridge (detect C2 without hitting real internet) |
| Integration | REST API client (`POST /api/v2/file`, poll `GET /api/v2/tasks/{id}`) |
| Results mapped to | Verdict scoring engine (behavioral signals weighted ×3.0+) |

### Security Guardrails (All Containers)

```python
# All containers spawned via docker-py with these defaults:
container_config = {
    "AutoRemove": True,              # --rm equivalent
    "Binds": [f"{sample_path}:/files/sample:ro"],  # read-only mount
    "Memory": 536870912,             # 512MB limit
    "CpuQuota": 100000,              # 1 CPU core
    "NetworkMode": "none",           # no network (static phases)
    "Privileged": False,             # never privileged
    "ReadOnlyRootfs": True,          # read-only root filesystem
}
```

---

## 4. Threat Classification & Scoring

### Verdict Model

```python
class IOC(BaseModel):
    type: Literal["url", "ip", "domain", "email", "fileHash", "registryKey", "command"]
    value: str
    context: str  # where found, e.g., "strings output line 234"

class ThreatVerdict(BaseModel):
    score: float                  # 0.0 - 10.0
    level: Literal["Clean", "Suspicious", "Malicious", "Critical"]
    categories: list[str]         # ["Ransomware", "Backdoor", "Phishing"]
    confidence: Literal["Low", "Medium", "High"]
    iocs: list[IOC]
    yara_matches: list[YaraMatch]
    vt_score: float | None        # VirusTotal positives/total ratio
    cape_behaviors: list[str] | None  # CAPEv2 behavioral findings
    summary: str
```

### Configurable Scoring Weights

Weights loaded from `config/scoring.yaml` at startup, tunable per deployment:

```yaml
# config/scoring.yaml
scoring:
  weights:
    vt_detection_ratio: 4.0       # VirusTotal positives / total engines
    yara_family_match: 2.0        # Per YARA rule match
    suspicious_pe_import: 0.5     # Per suspicious API import
    high_entropy_section: 1.0     # Per section with entropy > 7.0
    embedded_bad_url: 1.5         # Per URL to known-bad domain
    extension_mismatch: 0.5       # File type ≠ extension
    macro_detected: 2.0           # Office macro code found
    pdf_embedded_script: 1.5      # PDF contains JavaScript
    urlscan_verdict_malicious: 3.0 # URLScan flags as malicious
    capev2_malicious_behavior: 3.0 # Per CAPE behavioral indicator

  thresholds:
    clean: 2.0
    suspicious: 5.0
    malicious: 8.0
    # >= 8.0 → Critical
```

### Scoring Signals Reference

| Signal | Weight (default) | Example |
|--------|-----------------|---------|
| VirusTotal detection ratio | ×4.0 | 5/70 engines = 0.29 → +1.16 |
| YARA family matches | ×2.0 each | 2 matches → +4.0 |
| Suspicious PE imports | ×0.5 each | CreateRemoteThread, VirtualAllocEx |
| High entropy sections (>7.0) | ×1.0 | Packed/encrypted binary |
| Embedded URLs to bad domains | ×1.5 each | C2 URLs found in strings |
| File extension mismatch | ×0.5 | .txt that's actually PE |
| Office macro detected | ×2.0 | VBA code in DOCM/XLSM |
| PDF embedded JavaScript | ×1.5 | Embedded JS in PDF objects |
| URLScan verdict "malicious" | ×3.0 | Drive-by/phishing site |
| CAPEv2 malicious behavior | ×3.0+ | Keylogging, C2 beacon, ransomware encryption |

**Thresholds:** `< 2.0` → Clean · `< 5.0` → Suspicious · `< 8.0` → Malicious · `≥ 8.0` → Critical

---

## 5. Real-time Communication (SSE)

### Architecture

```
Browser (HTMX) ←── SSE stream ── FastAPI Backend ←── Docker/Cape ── Analysis
     │                       │                  │                      │
  PhaseProgress bar       Event dispatch    Spawn container        Stream stdout
  IocTable update         SSE push          Parse output           Write results
  VerdictBadge            Auto-reconnect    Score verdict          Return data
```

### SSE Event Types

```python
# FastAPI SSE events streamed to /api/analysis/{id}/stream
class AnalysisEvent(BaseModel):
    event: Literal[
        "phase_started",      # Phase began
        "progress",           # Phase progress update
        "ioc_found",          # New IOC discovered
        "yara_match",         # YARA rule matched
        "cape_task_submitted",# Sample submitted to CAPE
        "cape_progress",      # CAPE sandbox progress
        "phase_complete",     # Phase finished with summary
        "complete"            # Full analysis complete + verdict
    ]
    phase: str | None         # Which phase emitted this event
    data: dict                # Event-specific payload
    timestamp: datetime
```

### HTMX Integration (Template Snippet)

```html
<!-- Live phase progress bar -->
<div id="progress-panel"
     hx-trigger="sse:progress"
     hx-get="/api/analysis/{{ analysis_id }}/progress">
</div>

<!-- IOC table updates live as IOCs are discovered -->
<div id="ioc-list"
     hx-trigger="sse:ioc_found"
     hx-get="/api/analysis/{{ analysis_id }}/iocs">
</div>

<!-- Verdict appears when analysis completes -->
<div id="verdict-panel"
     hx-trigger="sse:complete"
     hx-get="/api/analysis/{{ analysis_id }}/verdict">
</div>
```

### Fallback

REST polling endpoint (`GET /api/analysis/{id}`) for CLI tools, AI agents, and non-browser clients.

---

## 6. Data Persistence

| Store | Purpose | Implementation |
|-------|---------|----------------|
| **SQLite** (WAL mode) | Scan history, verdicts, IOCs, metadata | `sqlite3` built-in + SQLAlchemy/Tortoise ORM |
| **Filesystem** (encrypted) | Uploaded samples, auto-purged per retention | Fernet/AES-256 at rest, configurable TTL |

### Retention Policy

- Default TTL: **7 days** for unpinned samples
- **Pin/unpin toggle** per scan — pinned scans survive cleanup
- Metadata (verdicts, IOCs) preserved even after sample deletion
- Background cleanup job runs daily via `APScheduler`

---

## 7. API Surface

### REST Endpoints

```
POST   /api/analyze/file         — multipart file upload → { analysisId }
POST   /api/analyze/url          — JSON body { url } → { analysisId }
GET    /api/analysis/{id}        — pollable result (CLI/agent fallback)
GET    /api/analysis/{id}/report — full structured report JSON
GET    /api/analysis/{id}/stream — SSE stream for live progress
GET    /api/analysis/{id}/iocs   — current IOC list (HTMX partial)
GET    /api/analysis/{id}/verdict — final verdict (HTMX partial)
GET    /api/history              — paginated scan history with filters
DELETE /api/analysis/{id}        — cleanup scan + sample
POST   /api/threat-check         — quick reputation lookup (VT/URLScan only)
GET    /api/export/{id}/json     — download full report as JSON
GET    /api/export/{id}/csv      — download IOC list as CSV
```

### CLI Interface (AI Agents / Scripts)

```bash
# File analysis
curl -F "file=@suspicious.exe" http://localhost:8000/api/analyze/file
# → {"analysisId": "abc-123", "status": "queued"}

# URL analysis
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious.example.com"}'

# Poll result (CLI fallback for SSE)
curl http://localhost:8000/api/analysis/abc-123

# Quick reputation check (no full scan)
curl -X POST http://localhost:8000/api/threat-check \
  -H "Content-Type: application/json" \
  -d '{"type": "url", "value": "https://suspicious.example.com"}'

# Download report
curl -o report.json http://localhost:8000/api/export/abc-123/json
```

---

## 8. Concurrency Model

```python
import asyncio

analysis_semaphore = asyncio.Semaphore(3)  # max 3 concurrent analyses

async def run_analysis(sample: Sample):
    async with analysis_semaphore:
        # Phase 1-5 execute here
        # Additional submissions queue until a slot opens
        verdict = await execute_pipeline(sample)
        return verdict
```

- **In-memory semaphore** limits concurrent analyses to 3
- No Redis or external queue needed — single container, bounded concurrency
- Each analysis spawns its own ephemeral Docker containers independently
- Queue position visible via SSE to waiting clients

---

## 9. Project Structure (Final)

```
ClearCage/
├── CONTEXT.md                          ← Glossary + decisions log
├── docker-compose.yml                  ← One command: up/down
├── .env.example                        ← API keys, config overrides
│
├── backend/
│   ├── Dockerfile                      ← Python 3.12-slim + DinD
│   ├── requirements.txt                ← FastAPI, docker-py, pefile, etc.
│   ├── config/
│   │   └── scoring.yaml               ← Tunable scoring weights + thresholds
│   └── src/
│       ├── main.py                     ← FastAPI app entry point
│       ├── api/
│       │   ├── analyze.py              ← POST /api/analyze/file, /url
│       │   ├── analysis.py             ← GET /api/analysis/{id}/*
│       │   ├── history.py              ← GET /api/history
│       │   └── export.py               ← GET /api/export/{id}/json,csv
│       ├── engine/
│       │   ├── orchestrator.py         ← Phase pipeline orchestration
│       │   ├── docker_runner.py        ← DinD container spawn/stream (docker-py)
│       │   ├── pre_analysis.py         ← Native: hashes, MIME, extension check
│       │   ├── static_analysis.py      ← YARA, strings, PE via DinD containers
│       │   ├── threat_intel.py         ← VirusTotal + URLScan + AbuseIPDB clients
│       │   ├── cape_client.py          ← CAPEv2 REST API client
│       │   └── scoring.py              ← Configurable scoring → verdict
│       ├── storage/
│       │   ├── database.py             ← SQLite (SQLAlchemy/Tortoise)
│       │   ├── file_store.py           ← Encrypted sample storage + retention
│       │   └── cleanup.py              ← Background TTL cleanup job
│       ├── models/
│       │   ├── analysis.py             ← Pydantic models (Verdict, IOC, etc.)
│       │   └── db.py                   ← SQLAlchemy ORM models
│       └── templates/                  ← Jinja2 HTML templates
│           ├── base.html               ← Layout: navbar, sidebar, scripts
│           ├── index.html              ← Landing + quick submit
│           ├── submit_file.html        ← Drag-drop file upload
│           ├── submit_url.html         ← URL analysis submission
│           ├── analysis.html           ← Live results viewer (SSE-driven)
│           ├── dashboard.html          ← Stats, heatmaps, trends
│           └── history.html            ← Searchable scan log
│
├── static/                             ← Compiled CSS + JS
│   ├── css/
│   │   └── app.css                     ← Tailwind + daisyUI compiled output
│   └── js/
│       ├── charts.js                   ← ApexCharts initialization helpers
│       └── tables.js                   ← Tabulator/DataTables helpers
│
├── yara-rules/                         ← Auto-updated YARA rulesets (volume mount)
├── docs/
│   ├── architecture-research.md        ← This document
│   └── adr/
│       └── 0001-dind-isolation.md      ← DinD security decision
│
└── scripts/
    └── analyze.sh                      ← CLI wrapper for curl-based analysis
```

---

## 10. Key Dependencies

### Python Backend

| Package | Purpose |
|---------|---------|
| `fastapi` + `uvicorn` | Async web framework + ASGI server |
| `jinja2` | HTML templating |
| `docker` (docker-py) | DinD container orchestration |
| `pefile` | PE file header/section/import analysis |
| `yara-python` | YARA pattern matching (native fallback) |
| `oletools` | Office macro detection |
| `magika` | File type detection from magic bytes |
| `ssdeep` | Fuzzy hashing for similarity detection |
| `sqlalchemy` or `tortoise-orm` | SQLite ORM layer |
| `cryptography` | Fernet/AES-256 sample encryption |
| `aiohttp` | Async HTTP client (VirusTotal, URLScan, CAPE API) |
| `pyyaml` | Load scoring config from YAML |
| `apscheduler` | Background cleanup + YARA auto-update jobs |
| `python-multipart` | File upload handling in FastAPI |

### Frontend (Vanilla JS, no framework)

| Library | Purpose | Delivery |
|---------|---------|----------|
| **HTMX** | Server-driven UI updates, SSE support | CDN or local `<script>` |
| **Tailwind CSS + daisyUI** | Utility CSS + pre-built components | Build step (npm) or CDN |
| **ApexCharts** | Radial gauges, heatmaps, trend lines | CDN or local `<script>` |
| **Tabulator** | Sortable/filterable IOC data tables | CDN or local `<script>` |

### Docker Images (Analysis Containers)

| Image | Purpose |
|-------|---------|
| `remnux/yara:latest` | YARA malware pattern matching |
| `remnux/pefile:latest` | PE file header/section/import analysis |
| `remnux/remnux-distro:noble` | General tools (strings, oletools, pdfid) |
| `systemcrafters/capeweb:latest` | CAPEv2 dynamic sandbox service |

### External APIs

| API | Purpose | Free Tier | Required? |
|-----|---------|-----------|-----------|
| VirusTotal | Multi-engine reputation (70+ scanners) | 4 req/min, 500/day | No — graceful degradation |
| URLScan.io | URL behavior analysis, HAR capture | ~100 scans/month | No — graceful degradation |
| AbuseIPDB | IP/domain reputation | 1000 credits/month | No — graceful degradation |

---

## 11. Deployment

### Quick Start

```bash
# 1. Clone + configure
git clone <repo> && cd ClearCage
cp .env.example .env
# Edit .env: add VIRUSTOTAL_API_KEY, URLSCAN_API_KEY (optional)

# 2. Build + start
docker compose up -d --build

# 3. Open browser
open http://localhost:8000
```

### Daily Operations

```bash
docker compose logs -f api          # Watch live logs
docker compose restart api          # Apply config changes
docker compose down -v              # Full teardown (removes volumes)
```

### docker-compose.yml (Target)

```yaml
services:
  api:
    build: ./backend
    ports:
      - "8000:8000"
    privileged: true                # DinD requirement
    volumes:
      - yara-rules:/app/yara-rules:ro
      - samples:/app/storage
      - ./config:/app/config:ro
    environment:
      DOCKER_HOST: unix:///var/run/docker.sock
      VIRUSTOTAL_API_KEY: ${VIRUSTOTAL_API_KEY:-}
      URLSCAN_API_KEY: ${URLSCAN_API_KEY:-}
      ABUSEIPDB_API_KEY: ${ABUSEIPDB_API_KEY:-}
    depends_on:
      cape:
        condition: service_healthy

  cape:
    image: systemcrafters/capeweb:latest
    ports:
      - "8081:8000"                 # CAPE web UI (optional access)
    volumes:
      - cape-data:/opt/cape/data
      - samples:/app/samples:ro     # Shared sample access
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v2/about"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  yara-rules:
  samples:
  cape-data:
```

---

## 12. Phased Build Plan

### Phase 1 — Core Engine (Week 1–2)
- Python project scaffold + Dockerfile + DinD setup
- FastAPI app with Jinja2 templates + Tailwind/daisyUI base layout
- Native pre-analysis: file hashes, MIME detection (magika), extension mismatch
- YARA scan via DinD (`remnux/yara` container)
- File upload endpoint + basic results page
- SQLite storage (SQLAlchemy/Tortoise ORM)
- Configurable scoring engine from YAML

### Phase 2 — Static Analysis + UI Polish (Week 3–4)
- PE analysis via DinD (`remnux/pefile`)
- Strings extraction + IOC regex patterns (URLs, IPs, domains, emails)
- Office macro detection (oletools via `remnux/remnux-distro`)
- PDF analysis (pdfid, pdftotext)
- SSE streaming for live phase progress
- ApexCharts integration: threat score gauge, trend charts
- Tabulator IOC table with sorting/filtering
- Sample retention: 7-day TTL + pin/unpin toggle

### Phase 3 — Threat Intelligence + CAPEv2 (Week 5–6)
- VirusTotal API client (graceful degradation if key missing)
- URLScan.io API client (URL analysis pipeline)
- AbuseIPDB enrichment for extracted IPs/domains
- CAPEv2 REST API client integration
- Dynamic sandbox phase in pipeline
- Dashboard page with threat heatmap + scan stats
- JSON + CSV report export

### Phase 4 — Polish + Operations (Week 7–8)
- YARA auto-update from GitHub repos (daily cron via APScheduler)
- Searchable scan history with multi-column filters
- CLI wrapper script (`scripts/analyze.sh`)
- PDF report export (WeasyPrint template)
- Rate limiting per IP
- Error handling + retry logic for external APIs

### Phase 5 — Advanced (Week 9+)
- Batch analysis (ZIP upload → recursive scan)
- ELF binary support (readelf, objdump via DinD)
- MITRE ATT&CK technique mapping
- STIX 2.1 export format
- MCP server integration for AI agent programmatic access

---

## 13. Alternative Architectures Considered & Rejected

### Next.js Full-Stack (React + TypeScript)
**Rejected because:** Sacrifices Python's malware analysis ecosystem (pefile, yara-python, oletools, ssdeep). The orchestrator's parsing of structured analysis output is significantly more robust in Python than in Node.js regex. Decision: "Sacrifice React, not Python."

### Separate Frontend Container (React/Vue + FastAPI)
**Rejected because:** Violates "one command deploy, easy teardown" requirement. Adds Node.js runtime, build step, and inter-service networking complexity. HTMX + Jinja2 provides equivalent UX without the overhead.

### Direct Docker Socket Mount
**Rejected because:** Grants root-equivalent host access. If backend is compromised via malicious file upload, attacker owns the host. Replaced with DinD isolation ([ADR-0001](adr/0001-dind-isolation.md)).

### Redis-backed Job Queue (Celery/BullMQ)
**Rejected because:** Horizontal scaling impossible in single-container deployment anyway. In-memory `asyncio.Semaphore(3)` provides sufficient concurrency control with zero extra services.

---

## Appendix A: REMnux MCP Server Reference

- Repository: <https://github.com/REMnux/remnux-mcp-server>
- Supports Docker exec, SSH, and HTTP modes
- Provides `analyze_file`, `suggest_tools`, `get_tool_help` tools
- Built-in IOC extraction, path sandboxing, security guardrails
- Can run alongside ClearCage for AI agent integration

## Appendix B: Key Docker Images Reference

| Image | Docker Hub | Description |
|-------|-----------|-------------|
| `remnux/remnux-distro:noble` | [link](https://hub.docker.com/r/remnux/remnux-distro) | Full REMnux toolkit (strings, oletools, pdfid, etc.) |
| `remnux/yara` | [link](https://hub.docker.com/r/remnux/yara) | YARA pattern matching engine |
| `remnux/pefile` | [link](https://hub.docker.com/r/remnux/pefile) | PE file analysis (imports, sections, entropy) |
| `systemcrafters/capeweb` | [link](https://hub.docker.com/r/systemcrafters/capeweb) | CAPEv2 sandbox with web interface + REST API |

## Appendix C: HTMX + SSE Pattern Reference

HTMX's native SSE support eliminates the need for WebSocket libraries:

```html
<!-- Connect to SSE stream -->
<div hx-trigger="sse:phase_started" hx-get="/api/analysis/{{ id }}/events"></div>

<!-- Each SSE event triggers an HTMX fetch for fresh HTML partials -->
<!-- Server renders Jinja2 template fragment, returns HTML -->
<!-- HTMX swaps it into the DOM automatically -->
```

This pattern keeps all rendering logic server-side (Python + Jinja2) while providing real-time UI updates. No JavaScript state management needed.
