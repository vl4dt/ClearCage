# ClearCage — Context & Glossary

> Living document. Updated during grilling sessions and as decisions crystallize.

## Project Name

**ClearCage** — transparent containment for threat analysis. The "Cage" refers to Docker-isolated sandbox containers where suspicious samples execute safely. "Clear" refers to real-time visibility into the analysis process via SSE (Server-Sent Events) streaming.

## Vision

A cross-platform (Windows / Linux / macOS) web application for analyzing suspicious files and URLs through containerized static and dynamic analysis, with real-time progress tracking and structured threat classification.

## Core Principles

- **Secure by default** — Docker-isolated analysis, no host contamination
- **Efficient** — lightweight API-driven intel + containerized deep scans
- **Effective** — identifies threat type (phishing, malware, ransomware, drive-by, packed, etc.)
- **Cross-platform** — no Windows or .NET lock-in

## Glossary

| Term | Definition |
|------|-----------|
| **Sample** | A suspicious file or URL submitted for analysis. Files are stored encrypted at rest with configurable retention. URLs are not stored, only analyzed via external APIs. |
| **Analysis** | The end-to-end process of examining a Sample through multiple phases (pre-analysis → static → threat intel → optional dynamic → scoring). Produces a Report. |
| **Phase** | A discrete stage within an Analysis (e.g., "YARA scan", "PE analysis", "VirusTotal lookup"). Phases run sequentially or in parallel, each producing partial results streamed to the client in real-time. |
| **Verdict** | The final threat assessment produced by the Scoring Engine, including a numeric score (0–10), threat level (Clean/Suspicious/Malicious/Critical), categories, confidence, and extracted IOCs. |
| **IOC (Indicator of Compromise)** | A discrete artifact extracted during analysis: URLs, IPs, domains, emails, file hashes, registry keys, or commands. Each IOC includes its source context (e.g., "strings output line 234"). |
| **Container** | An ephemeral Docker container spawned for a single Phase. Always run with `--rm`, read-only mounts, resource limits, and network isolation (static phases). |
| **Threat Intel** | External reputation APIs (VirusTotal, URLScan.io, AbuseIPDB) used to enrich Analysis results with multi-engine detection data. |
| **Dynamic Sandbox** | Phase 4 using CAPEv2 for runtime behavior monitoring. Enabled by default, runs after static analysis completes. |

## Decisions Log

| Date | Decision | Status |
|------|----------|--------|
| 2026-06-21 | Project name: **ClearCage** (replaced RazorCage) | ✅ Finalized |
| 2026-06-21 | Cross-platform requirement: Win/Linux/macOS, no .NET lock-in | ✅ Finalized |
| 2026-06-21 | Monorepo + single `docker-compose.yml` deployment (one command up/down) | ✅ Finalized |
| 2026-06-21 | Python backend (FastAPI) for analysis engine over Node.js/Next.js | ✅ Finalized |
| 2026-06-21 | Single-container monolith: FastAPI serves HTML + API + WebSocket (no separate frontend) | ✅ Finalized |
| 2026-06-21 | UI layer: Tailwind CSS + daisyUI components, ApexCharts for data viz, HTMX for interactivity | ✅ Finalized |
| 2026-06-21 | No authentication — local-only deployment on trusted network | ✅ Finalized |
| 2026-06-21 | In-memory concurrency pool (asyncio.Semaphore, max 3 concurrent analyses) | ✅ Finalized |
| 2026-06-21 | CAPEv2 dynamic sandbox included from day one (Phase 4 enabled by default) | ✅ Finalized |
| 2026-06-21 | Sample retention: manual + auto hybrid (7-day TTL default, pin/unpin toggle per scan) | ✅ Finalized |
| 2026-06-21 | External threat intel APIs: graceful degradation (app works without keys, Phase 3 skipped if missing) | ✅ Finalized |
| 2026-06-21 | YARA rules: auto-update from trusted GitHub repos on startup/daily cron, bundled defaults as fallback | ✅ Finalized |
| 2026-06-21 | File type support tiered: Tier 1 MVP (PE/EXE/DLL, Office docs, PDFs, Scripts, URLs), Tier 2 (ELF, Archives+recursive), Tier 3 (APK/IPA) | ✅ Finalized |
| 2026-06-21 | Real-time updates: SSE (Server-Sent Events) over WebSocket — HTMX-native, unidirectional, simpler | ✅ Finalized |
| 2026-06-21 | Docker access: DinD (Docker-in-Docker) for isolation over direct socket mount | ✅ Finalized | [ADR-0001](docs/adr/0001-dind-isolation.md) |
| 2026-06-21 | Report export: JSON + CSV from day one, PDF Phase 2, STIX deferred | ✅ Finalized |
| 2026-06-21 | Threat scoring: configurable weights via YAML/JSON config file (`.env`-adjacent), per-deployment tuning | ✅ Finalized |
| 2026-06-21 | Database: SQLite (file-based, WAL mode, zero extra services) | ✅ Finalized |
| 2026-06-21 | CAPEv2 integration: REST API client (official HTTP endpoints, no shared volumes or DB coupling) | ✅ Finalized |
