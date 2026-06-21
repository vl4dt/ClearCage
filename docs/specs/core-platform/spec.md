# Spec: ClearCage Core Platform

> Feature: `core-platform`  
> Created: 2026-06-21  
> Status: Draft — awaiting plan review

---

## Problem / Opportunity

Security analysts need a local, cross-platform tool to analyze suspicious files and URLs without relying on cloud services, complex multi-container deployments, or platform-specific dependencies. Existing solutions are either:

- **Cloud-only** (VirusTotal web UI, URLScan) — require internet, expose samples externally
- **Complex self-hosted** (full REMnux VM, Cuckoo sandbox) — heavy setup, steep learning curve
- **CLI-only** (yara, strings, pefile) — powerful but no unified interface or real-time feedback

ClearCage fills the gap: a single-command Docker deployment that provides containerized static + dynamic analysis with a live web UI, configurable threat scoring, and exportable reports — all on a trusted local network.

---

## Users / Actors

| Actor | Description |
|-------|-------------|
| **Security Analyst** | Primary user. Submits suspicious files/URLs, reviews verdicts, exports IOCs for ticketing/SIEM |
| **SOC Team Lead** | Reviews dashboards, tunes scoring weights, manages sample retention policies |
| **AI Agent (e.g., Pi)** | Submits analyses programmatically via REST API, consumes JSON reports |
| **Script / Automation** | Uses CLI wrapper (`curl`-based) for batch analysis or CI/CD pipeline integration |

---

## Goals

1. **One-command deployment** — `docker compose up -d` starts the entire platform (backend + CAPEv2 sandbox)
2. **Real-time analysis visibility** — SSE streams phase progress, IOC discovery, and verdict to the browser
3. **Configurable threat scoring** — YAML-based weights allow per-deployment tuning without code changes
4. **Graceful API degradation** — platform functions fully without external API keys (VirusTotal, URLScan)
5. **Secure by default** — DinD isolation prevents analysis containers from accessing the host
6. **Exportable results** — JSON and CSV downloads from day one for SIEM/ticketing integration

---

## Non-Goals

1. **Authentication or multi-tenancy** — local-only trusted network, no user accounts
2. **Horizontal scaling** — single container, bounded concurrency (max 3 analyses)
3. **ELF/APK analysis** — deferred to Tier 2/3 file type rollout
4. **STIX/TAXII export** — deferred until JSON/CSV/PDF are proven
5. **Custom YARA rule uploads** — auto-updated from trusted repos only, no user-authored rules
6. **Batch ZIP upload** — single-file/single-URL analysis only in MVP

---

## Requirements

### Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| F1 | Accept file uploads (PE/EXE/DLL, Office docs, PDFs, scripts) up to 50MB | Must |
| F2 | Accept URL submissions for link analysis | Must |
| F3 | Run 5-phase analysis pipeline: Pre-analysis → Static → Threat Intel → Dynamic (CAPEv2) → Scoring | Must |
| F4 | Stream real-time progress via SSE to browser | Must |
| F5 | Produce structured Verdict with score, level, categories, confidence, IOCs | Must |
| F6 | Store scan history in SQLite with configurable retention (7-day TTL + pin/unpin) | Must |
| F7 | Export reports as JSON and CSV | Must |
| F8 | Display threat score gauge (ApexCharts radial), IOC table, phase progress bars | Must |
| F9 | Load scoring weights from YAML config file | Must |
| F10 | Auto-update YARA rules from trusted GitHub repos on startup + daily cron | Should |
| F11 | Quick reputation check endpoint (VT/URLScan only, no full scan) | Could |
| F12 | Dashboard with scan stats, threat heatmap, trend charts | Could |

### Non-Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| NF1 | Cross-platform: Windows, Linux, macOS via Docker Desktop / Docker Engine | Must |
| NF2 | DinD isolation: analysis containers never access host filesystem or network | Must |
| NF3 | Resource caps per analysis container: 512MB RAM, 1 CPU core | Must |
| NF4 | Concurrency limit: max 3 concurrent analyses (in-memory semaphore) | Must |
| NF5 | Graceful degradation: platform starts and runs without external API keys | Must |
| NF6 | File samples encrypted at rest (Fernet/AES-256) | Should |
| NF7 | SQLite WAL mode for concurrent read access | Should |

---

## Acceptance Criteria

- [ ] `docker compose up -d --build` starts the platform with no errors
- [ ] Landing page loads at `http://localhost:8000` with file upload and URL submission forms
- [ ] Uploading a known-benign file completes all 5 phases and produces a "Clean" verdict
- [ ] Uploading a known-malware sample (EICAR test file) triggers YARA match and "Malicious" verdict
- [ ] SSE stream delivers phase_started, progress, ioc_found, and complete events in real-time
- [ ] Verdict page displays threat score gauge, IOC table, and phase summaries
- [ ] JSON and CSV export downloads work for completed analyses
- [ ] Scoring weights loaded from `config/scoring.yaml` affect verdict output
- [ ] Platform starts and completes analyses without VirusTotal/URLScan API keys configured
- [ ] Scan history page lists all past analyses with sortable columns
- [ ] Pinned scans survive the 7-day TTL cleanup job
- [ ] DinD containers run with `--rm`, read-only mounts, `--network none` (static phases)

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| DinD `privileged: true` requirement reduces isolation benefit | Medium | High | Accept trade-off — still better than host socket mount; documented in ADR-0001 |
| CAPEv2 startup slow (~30s health check) delays first analysis | High | Medium | SSE informs user of "CAPE initializing" state; Phase 4 queues until healthy |
| YARA auto-update fails silently, rules become stale | Low | Medium | Bundled defaults as fallback; daily cron with logging |
| SQLite write-lock contention under concurrent analyses | Low | Medium | WAL mode + single-writer pattern (one analysis at a time writes results) |
| Large file uploads (>50MB) exceed container memory limits | Medium | Low | Hard limit enforced at upload endpoint; clear error message |

---

## Open Questions / Assumptions

| Question | Assumption |
|----------|------------|
| CAPEv2 Windows VM image availability | `systemcrafters/capeweb` includes a pre-configured Windows monitor VM |
| Tailwind CSS build step in Python container | Use CDN for Tailwind/daisyUI to avoid npm build step; or pre-compile CSS during Docker build |
| ApexCharts + Tabulator loaded via CDN vs local | CDN for simplicity; no JS bundler needed |
| Max analysis duration before timeout | 5 minutes default (configurable); CAPEv2 tasks killed if exceeding limit |
