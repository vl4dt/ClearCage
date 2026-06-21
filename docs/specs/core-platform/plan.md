# Plan: ClearCage Core Platform

> Feature: `core-platform`  
> Created: 2026-06-21  
> Status: Draft — awaiting review  
> Related: [spec.md](./spec.md), [CONTEXT.md](../../CONTEXT.md), [architecture-research.md](../../docs/architecture-research.md)

---

## Existing System Context

**Current state:** Greenfield project. No code exists. Documentation only:

| Path | Purpose |
|------|---------|
| `CONTEXT.md` | Glossary + 18 finalized architectural decisions |
| `docs/architecture-research.md` | Full architecture spec (FastAPI + HTMX + DinD + CAPEv2) |
| `docs/adr/0001-dind-isolation.md` | DinD security decision rationale |
| `docs/specs/core-platform/spec.md` | Feature requirements and acceptance criteria |

**No existing code, database, or infrastructure to migrate from.**

---

## Proposed Architecture

### Directory Structure (Target)

```
ClearCage/
├── .env.example                        ← API key placeholders (no secrets committed)
├── .gitignore                          ← .env, __pycache__, node_modules, *.db, storage/
├── docker-compose.yml                  ← api + cape services, named volumes
├── CONTEXT.md                          ← Glossary + decisions log
│
├── backend/
│   ├── Dockerfile                      ← Python 3.12-slim + DinD entrypoint
│   ├── requirements.txt                ← FastAPI, docker-py, pefile, yara-python, etc.
│   └── src/
│       ├── main.py                     ← FastAPI app factory, lifespan setup
│       ├── api/
│       │   ├── analyze.py              ← POST /api/analyze/file, POST /api/analyze/url
│       │   ├── analysis.py             ← GET /api/analysis/{id}, /stream, /iocs, /verdict
│       │   ├── history.py              ← GET /api/history
│       │   └── export.py               ← GET /api/export/{id}/json, /csv
│       ├── engine/
│       │   ├── orchestrator.py         ← Phase pipeline (asyncio.Semaphore, event bus)
│       │   ├── docker_runner.py        ← DinD container lifecycle (docker-py)
│       │   ├── pre_analysis.py         ← Native: hashes, magika MIME, extension check
│       │   ├── static_analysis.py      ← YARA, PE, strings, oletools, pdfid via DinD
│       │   ├── threat_intel.py         ← VirusTotal, URLScan, AbuseIPDB async clients
│       │   ├── cape_client.py          ← CAPEv2 REST API client (submit, poll, fetch)
│       │   └── scoring.py              ← YAML-configurable scoring → ThreatVerdict
│       ├── storage/
│       │   ├── database.py             ← SQLite engine, session factory, WAL pragma
│       │   ├── models.py               ← SQLAlchemy ORM: Analysis, IOC, YaraMatch, ScanResult
│       │   ├── file_store.py           ← Encrypted sample storage + retrieval
│       │   └── cleanup.py              ← APScheduler job: TTL purge + YARA auto-update
│       └── templates/                  ← Jinja2 HTML (HTMX-driven)
│           ├── base.html               ← Layout: navbar, sidebar, HTMX/ApexCharts scripts
│           ├── index.html              ← Landing + quick submit forms
│           ├── submit_file.html        ← Drag-drop file upload zone
│           ├── submit_url.html         ← URL analysis submission form
│           ├── analysis.html           ← Live results viewer (SSE-driven panels)
│           ├── dashboard.html          ← Stats, heatmaps, trends (ApexCharts)
│           └── history.html            ← Searchable scan log (Tabulator table)
│
├── config/
│   └── scoring.yaml                    ← Tunable weights + thresholds (volume-mounted :ro)
│
├── static/
│   ├── css/
│   │   └── app.css                     ← Tailwind + daisyUI compiled (or CDN fallback)
│   └── js/
│       ├── charts.js                   ← ApexCharts init helpers (gauge, heatmap, trends)
│       └── tables.js                   ← Tabulator init helpers (IOC table, history grid)
│
├── yara-rules/                         ← Bundled default YARA rules (volume mount :ro)
│   └── defaults/
│       ├── eicar.yara                  ← Test rule for EICAR sample
│       └── suspicious_pe.yara          ← Generic PE anomaly detection
│
├── docs/
│   ├── architecture-research.md        ← Full architecture reference
│   ├── adr/
│   │   └── 0001-dind-isolation.md      ← DinD decision
│   └── specs/
│       └── core-platform/
│           ├── spec.md                 ← Feature requirements
│           └── plan.md                 ← This document
│
└── scripts/
    └── analyze.sh                      ← CLI wrapper (curl-based, cross-platform)
```

### Service Topology

```
docker-compose.yml:
  services:
    api:      FastAPI + DinD daemon (port 8000, privileged: true)
    cape:     CAPEv2 sandbox service (port 8081, healthcheck required)

  volumes:
    yara-rules:  Mounted :ro into api container
    samples:     Encrypted file storage + SQLite DB
    cape-data:   CAPEv2 internal state
```

### Data Flow (File Analysis)

```
User uploads file via /submit/file
  → POST /api/analyze/file → { analysisId }
  → Redirect to /analysis/{analysisId}
  → Browser connects to GET /api/analysis/{id}/stream (SSE)

Backend orchestrator:
  Phase 1 (native):   hash(file) + magika(file) + extension_check()
    ├─ SSE: phase_started("pre-analysis")
    └─ SSE: phase_complete("pre-analysis")

  Phase 2 (DinD):     spawn yara, pefile, strings, oletools containers
    ├─ SSE: phase_started("static-analysis")
    ├─ SSE: ioc_found({type, value, context})
    ├─ SSE: yara_match({rule, tags})
    └─ SSE: phase_complete("static-analysis")

  Phase 3 (external): VirusTotal + URLScan lookups (skip if no keys)
    ├─ SSE: phase_started("threat-intel")
    └─ SSE: phase_complete("threat-intel")

  Phase 4 (CAPEv2):   POST /api/v2/file → poll GET /api/v2/tasks/{id}
    ├─ SSE: phase_started("dynamic-sandbox")
    ├─ SSE: cape_task_submitted({taskId})
    ├─ SSE: cape_progress({percent})
    └─ SSE: phase_complete("dynamic-sandbox")

  Phase 5 (native):   scoring.py → ThreatVerdict from all phase results
    ├─ SSE: phase_started("scoring")
    └─ SSE: complete({verdict})

Browser HTMX swaps:
  #progress-panel ← hx-trigger="sse:progress"
  #ioc-list       ← hx-trigger="sse:ioc_found"
  #verdict-panel  ← hx-trigger="sse:complete"
```

---

## Data / API / Model Changes

### Database Schema (SQLite)

```sql
-- Analyses table (one row per submitted sample/URL)
CREATE TABLE analyses (
    id TEXT PRIMARY KEY,                    -- UUID
    type TEXT NOT NULL CHECK(type IN ('file', 'url')),
    filename TEXT,                          -- original filename (NULL for URLs)
    url TEXT,                               -- target URL (NULL for files)
    sha256 TEXT,                            -- file hash (NULL for URLs)
    md5 TEXT,
    sha1 TEXT,
    mime_type TEXT,                         -- detected via magika
    file_size INTEGER,                      -- bytes (NULL for URLs)
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued', 'running', 'complete', 'failed')),
    pinned INTEGER NOT NULL DEFAULT 0,      -- 1 = survive TTL cleanup
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    score REAL,                             -- final threat score (0-10)
    level TEXT CHECK(level IN ('Clean', 'Suspicious', 'Malicious', 'Critical')),
    confidence TEXT CHECK(confidence IN ('Low', 'Medium', 'High')),
    categories TEXT,                        -- JSON array: ["Ransomware", "Backdoor"]
    summary TEXT                            -- human-readable verdict summary
);

-- IOCs extracted during analysis
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL REFERENCES analyses(id),
    type TEXT NOT NULL CHECK(type IN ('url', 'ip', 'domain', 'email', 'fileHash', 'registryKey', 'command')),
    value TEXT NOT NULL,
    context TEXT                            -- source: "strings line 234", "YARA rule X"
);

-- YARA rule matches
CREATE TABLE yara_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL REFERENCES analyses(id),
    rule_name TEXT NOT NULL,
    tags TEXT                               -- comma-separated tags
);

-- Phase results (key-value per phase)
CREATE TABLE phase_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL REFERENCES analyses(id),
    phase TEXT NOT NULL,                    -- "pre-analysis", "static-analysis", etc.
    key TEXT NOT NULL,                      -- signal name
    value TEXT,                             -- JSON-serialized result
    weight_applied REAL                     -- score contribution
);

-- Indexes for fast lookups
CREATE INDEX idx_analyses_status ON analyses(status);
CREATE INDEX idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX idx_analyses_pinned ON analyses(pinned);
CREATE INDEX idx_iocs_analysis ON iocs(analysis_id);
CREATE INDEX idx_yara_matches_analysis ON yara_matches(analysis_id);
CREATE INDEX idx_phase_results_analysis ON phase_results(analysis_id);
```

### REST API Surface

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `POST` | `/api/analyze/file` | Upload file for analysis | `{ analysisId, status }` |
| `POST` | `/api/analyze/url` | Submit URL for analysis | `{ analysisId, status }` |
| `GET` | `/api/analysis/{id}` | Pollable result (CLI fallback) | Full analysis JSON |
| `GET` | `/api/analysis/{id}/stream` | SSE stream for live progress | `text/event-stream` |
| `GET` | `/api/analysis/{id}/iocs` | Current IOC list (HTMX partial) | HTML fragment |
| `GET` | `/api/analysis/{id}/verdict` | Final verdict display (HTMX partial) | HTML fragment |
| `GET` | `/api/history` | Paginated scan history | `{ items, total, page }` |
| `DELETE` | `/api/analysis/{id}` | Delete analysis + sample | `{ ok }` |
| `POST` | `/api/threat-check` | Quick reputation lookup | `{ vt_score, urlscan_verdict }` |
| `GET` | `/api/export/{id}/json` | Download full report as JSON | `application/json` |
| `GET` | `/api/export/{id}/csv` | Download IOC list as CSV | `text/csv` |

### SSE Event Schema

```python
class AnalysisEvent(BaseModel):
    event: Literal[
        "phase_started",
        "progress",
        "ioc_found",
        "yara_match",
        "cape_task_submitted",
        "cape_progress",
        "phase_complete",
        "complete"
    ]
    phase: str | None
    data: dict  # event-specific payload
    timestamp: datetime
```

### Scoring Config (`config/scoring.yaml`)

```yaml
scoring:
  weights:
    vt_detection_ratio: 4.0
    yara_family_match: 2.0
    suspicious_pe_import: 0.5
    high_entropy_section: 1.0
    embedded_bad_url: 1.5
    extension_mismatch: 0.5
    macro_detected: 2.0
    pdf_embedded_script: 1.5
    urlscan_verdict_malicious: 3.0
    capev2_malicious_behavior: 3.0

  thresholds:
    clean: 2.0
    suspicious: 5.0
    malicious: 8.0
```

---

## Implementation Phases

### Phase A: Foundation (Week 1)

**Goal:** Docker compose starts, backend serves HTML, file upload accepted and stored.

| Step | File(s) | Description |
|------|---------|-------------|
| A1 | `backend/Dockerfile`, `backend/requirements.txt` | Python 3.12-slim + DinD entrypoint, pip install deps |
| A2 | `docker-compose.yml` | api service (DinD) + cape service, named volumes |
| A3 | `backend/src/main.py` | FastAPI app factory, lifespan setup (DB init, config load) |
| A4 | `backend/src/storage/database.py`, `models.py` | SQLite engine, WAL pragma, ORM models, migration on startup |
| A5 | `backend/src/storage/file_store.py` | Encrypted sample storage (Fernet), retrieval by analysis ID |
| A6 | `backend/src/api/analyze.py` | POST /api/analyze/file (upload → store → queue) + POST /api/analyze/url |
| A7 | `config/scoring.yaml`, `.env.example` | Default scoring weights, API key placeholders |
| A8 | `backend/src/templates/base.html`, `index.html` | Jinja2 layout with Tailwind/daisyUI CDN, navbar, sidebar |
| A9 | `backend/src/templates/submit_file.html`, `submit_url.html` | HTMX forms for file drop + URL submission |

**Verification:**
- `docker compose up -d --build` starts without errors
- `curl http://localhost:8000` returns 200 with HTML
- `curl -F "file=@test.txt" http://localhost:8000/api/analyze/file` returns `{ analysisId }`
- SQLite DB created in volume, tables exist

---

### Phase B: Analysis Pipeline Core (Week 2)

**Goal:** 5-phase pipeline executes, SSE streams progress, verdict produced.

| Step | File(s) | Description |
|------|---------|-------------|
| B1 | `backend/src/engine/orchestrator.py` | Async orchestrator with `asyncio.Semaphore(3)`, event bus for SSE |
| B2 | `backend/src/engine/docker_runner.py` | DinD container lifecycle via docker-py (spawn, stream, cleanup) |
| B3 | `backend/src/engine/pre_analysis.py` | Native: SHA-256/MD5/SHA1, magika MIME, extension mismatch check |
| B4 | `backend/src/engine/static_analysis.py` | YARA scan via DinD, PE analysis, strings extraction, IOC regex |
| B5 | `backend/src/engine/scoring.py` | Load YAML weights, compute score → ThreatVerdict with level/categories |
| B6 | `backend/src/api/analysis.py` | GET /api/analysis/{id}, /stream (SSE), /iocs, /verdict endpoints |
| B7 | `backend/src/templates/analysis.html` | Live results viewer: progress bars, IOC table, verdict panel (HTMX + SSE) |
| B8 | `yara-rules/defaults/eicar.yara`, `suspicious_pe.yara` | Bundled default YARA rules |

**Verification:**
- Upload EICAR test file → completes all phases → "Malicious" verdict with YARA match
- Upload benign text file → completes all phases → "Clean" verdict
- SSE stream delivers events in correct order (phase_started → progress → complete)
- `/api/analysis/{id}` returns full JSON result

---

### Phase C: Threat Intelligence + CAPEv2 (Week 3)

**Goal:** External API enrichment and dynamic sandboxing integrated.

| Step | File(s) | Description |
|------|---------|-------------|
| C1 | `backend/src/engine/threat_intel.py` | VirusTotal, URLScan.io, AbuseIPDB async clients with graceful degradation |
| C2 | `backend/src/engine/cape_client.py` | CAPEv2 REST API client: submit file, poll task, fetch report |
| C3 | `backend/src/engine/orchestrator.py` | Phase 3 (threat intel) + Phase 4 (CAPEv2) integrated into pipeline |
| C4 | `docker-compose.yml` | Verify cape service healthcheck, shared volume for sample access |
| C5 | `backend/src/api/export.py` | GET /api/export/{id}/json, GET /api/export/{id}/csv |

**Verification:**
- Analysis without API keys → Phase 3 logged as "skipped" (no crash), pipeline continues
- Analysis with VT key → VT score incorporated into verdict
- CAPEv2 task submitted and completed → behavioral data in verdict
- JSON export contains full verdict, IOCs, YARA matches, phase summaries
- CSV export contains type/value/context columns for all IOCs

---

### Phase D: UI Polish + Operations (Week 4)

**Goal:** Dashboard, history, retention, YARA updates, CLI wrapper.

| Step | File(s) | Description |
|------|---------|-------------|
| D1 | `backend/src/api/history.py` | GET /api/history with pagination, filters, search |
| D2 | `backend/src/templates/history.html` | Searchable scan log with Tabulator table |
| D3 | `backend/src/templates/dashboard.html` | Stats cards, threat heatmap, trend charts (ApexCharts) |
| D4 | `static/js/charts.js`, `static/js/tables.js` | ApexCharts + Tabulator initialization helpers |
| D5 | `backend/src/storage/cleanup.py` | APScheduler job: 7-day TTL purge + YARA auto-update from GitHub |
| D6 | `scripts/analyze.sh` | CLI wrapper for curl-based analysis (file, URL, status, export) |

**Verification:**
- History page lists all past analyses with sortable columns
- Dashboard displays scan stats and threat distribution
- Pinned scans survive cleanup job run
- YARA rules updated from GitHub repo on startup
- `./scripts/analyze.sh file test.exe` submits and polls result

---

## Verification Strategy

### Unit Tests (pytest)

| Module | Test Focus |
|--------|-----------|
| `engine/pre_analysis.py` | Hash computation, MIME detection, extension mismatch logic |
| `engine/scoring.py` | Weight loading from YAML, score computation, threshold mapping |
| `engine/threat_intel.py` | API client graceful degradation (mock missing keys) |
| `storage/file_store.py` | Encrypt/decrypt roundtrip, TTL enforcement |
| `api/analyze.py` | File size limit enforcement, URL validation |

### Integration Tests

| Scenario | Verification |
|----------|-------------|
| Full pipeline (benign file) | E2E: upload → 5 phases → Clean verdict in <30s |
| Full pipeline (EICAR test) | E2E: upload → YARA match → Malicious verdict |
| SSE stream delivery | HTTP client connects to `/stream`, receives all event types |
| SQLite concurrent reads | Multiple GET requests during analysis complete without lock errors |
| DinD container isolation | Spawned containers have `--network none`, read-only mounts |

### Manual Acceptance Checklist

- [ ] `docker compose up -d --build` starts cleanly
- [ ] Landing page loads at `http://localhost:8000`
- [ ] File upload completes, SSE shows live progress
- [ ] Verdict page displays score gauge, IOCs, phase summaries
- [ ] JSON/CSV export downloads work
- [ ] History page lists all scans
- [ ] Pinned scan survives cleanup
- [ ] Platform works without API keys configured

---

## Migration / Rollback Concerns

**Not applicable** — greenfield project with no prior code or data to migrate.

### Disaster Recovery

| Scenario | Recovery |
|----------|----------|
| `docker compose down -v` wipes everything | Re-run `docker compose up -d --build`; samples lost, DB recreated empty |
| DinD daemon fails to start inside container | Check `privileged: true` in docker-compose; verify Docker Engine version ≥ 24.0 |
| CAPEv2 healthcheck never passes | Platform continues without Phase 4; check CAPE image pull, resource limits |
| SQLite corruption | Delete `.db` file from volume, restart; scan history lost but samples intact |

### Volume Backup Strategy (Future)

```bash
# Manual backup of persistent data
docker run --rm -v clearcage_samples:/src -v $(pwd):/backup alpine \
  tar czf /backup/samples-backup.tar.gz -C /src .
```

---

## Risks and Trade-offs

### Technical Risks

| Risk | Mitigation | Phase |
|------|-----------|-------|
| **DinD `privileged: true`** reduces isolation vs direct socket mount | Accept trade-off per ADR-0001; analysis containers still non-privileged, read-only, network-isolated | All |
| **CAPEv2 startup ~30s** delays first dynamic analysis | SSE informs user of "CAPE initializing" state; Phase 4 queues until healthcheck passes | C |
| **YARA auto-update fails** → stale rules | Bundled defaults always present; daily cron with error logging; manual `docker compose restart api` triggers re-sync | D |
| **SQLite write contention** under 3 concurrent analyses | WAL mode + single-writer pattern: only the orchestrator writes results, reads are concurrent-safe | All |
| **Large file uploads** exceed container memory | Hard 50MB limit at upload endpoint; clear error message to user | A |

### Architectural Trade-offs

| Trade-off | Acceptance |
|-----------|------------|
| **No auth** → anyone on the network can access | Explicit requirement: local-only trusted network. Document in README. |
| **Single container** → no horizontal scaling | Explicit constraint: bounded concurrency (3) is sufficient for local analysis tool |
| **HTMX over React** → less client-side interactivity | Accept: server-driven UI eliminates JS build step, reduces bundle to zero |
| **SSE over WebSocket** → unidirectional only | Accept: analysis progress is server→client; no bidirectional needs identified |
| **DinD overhead** vs direct socket | Accept: security isolation outweighs ~5-10% performance penalty for static phases |
