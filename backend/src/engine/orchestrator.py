"""ClearCage — Async analysis orchestrator.

Manages the full pipeline with concurrency control (Semaphore) and SSE events
for real-time progress updates to the frontend.

Pipeline phases:
  1. Pre-analysis  — hashes, MIME type (magika), extension check
  2. Static        — YARA scan, PE parsing, strings extraction
  3. Intelligence  — VirusTotal, URLScan, AbuseIPDB (graceful degradation)
  4. Sandbox       — CAPEv2 dynamic analysis (file only)
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

logger = logging.getLogger(__name__)

# ── Concurrency Control ────────────────────────────────────────────

MAX_CONCURRENT = int(__import__("os").environ.get("MAX_CONCURRENT_ANALYSES", "3"))
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

# ── SSE Event Bus ──────────────────────────────────────────────────

class SSEBus:
    """In-memory pub/sub for Server-Sent Events."""

    def __init__(self):
        # analysis_id → list of asyncio.Queue (one per connected client)
        self._subscribers: dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, analysis_id: str) -> asyncio.Queue:
        """Create a new SSE subscriber queue for an analysis."""
        q = asyncio.Queue(maxsize=100)  # bounded to prevent memory issues
        self._subscribers.setdefault(analysis_id, []).append(q)
        return q

    def unsubscribe(self, analysis_id: str, queue: asyncio.Queue):
        """Remove a subscriber."""
        if analysis_id in self._subscribers:
            try:
                self._subscribers[analysis_id].remove(queue)
            except ValueError:
                pass
            if not self._subscribers[analysis_id]:
                del self._subscribers[analysis_id]

    async def publish(self, analysis_id: str, event: str, data: dict):
        """Broadcast an SSE event to all subscribers of an analysis."""
        message = json.dumps({"event": event, "data": data})
        for q in self._subscribers.get(analysis_id, []):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass  # drop if subscriber is too slow

    def cleanup(self, analysis_id: str):
        """Remove all subscribers for a completed analysis."""
        self._subscribers.pop(analysis_id, None)


sse_bus = SSEBus()


# ── Pipeline Phases ────────────────────────────────────────────────

async def _phase_pre_analysis(analysis_id: str, target: str, is_file: bool) -> dict:
    """Phase 1: Compute hashes, detect MIME type, check extension."""
    findings = {}

    if is_file:
        from storage.file_store import retrieve_file
        # Extract file_id from target "stored://{id}/{name}"
        parts = target.split("/")
        file_id = parts[1].replace("stored://", "")
        data = retrieve_file(file_id)
        if data is None:
            return {"error": "Sample file missing from storage"}

        # Hashes
        findings["md5"] = hashlib.md5(data).hexdigest()
        findings["sha1"] = hashlib.sha1(data).hexdigest()
        findings["sha256"] = hashlib.sha256(data).hexdigest()
        findings["size"] = len(data)

        # MIME type (magika)
        try:
            import magika
            mgk = magika.Magika()
            result = mgk.identify_bytes(data)
            findings["mime_type"] = result.output_label
            findings["predicted_extension"] = result.predicted_extension
        except Exception as e:
            logger.warning("Magika MIME detection failed: %s", e)
            findings["mime_type"] = "unknown"

        # Extension mismatch check
        if parts[-1]:  # original filename
            ext = Path(parts[-1]).suffix.lower().lstrip(".")
            pred_ext = findings.get("predicted_extension", "")
            if ext and pred_ext and ext != pred_ext:
                findings["extension_mismatch"] = True
                findings["actual_ext"] = ext
                findings["expected_ext"] = pred_ext

    else:
        # URL analysis — extract domain, protocol
        from urllib.parse import urlparse
        parsed = urlparse(target)
        findings["domain"] = parsed.hostname or ""
        findings["protocol"] = parsed.scheme
        findings["path"] = parsed.path

    return findings


async def _phase_static(analysis_id: str, target: str, pre_findings: dict) -> dict:
    """Phase 2: YARA scan, PE analysis, strings extraction via DinD."""
    findings = {"yara_matches": [], "pe_info": {}, "strings_sample": []}

    # Only for files
    if target.startswith("stored://"):
        from storage.file_store import retrieve_file
        parts = target.split("/")
        file_id = parts[1].replace("stored://", "")
        data = retrieve_file(file_id)

        if data:
            # Write to temp for container analysis
            tmp_path = f"/app/storage/tmp/{file_id}"
            Path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
            Path(tmp_path).write_bytes(data)

            try:
                from engine.container_runner import run_yara, run_strings

                # YARA scan
                yara_result = await run_yara(tmp_path)
                if yara_result["exit_code"] == 0 and yara_result["stdout"].strip():
                    for line in yara_result["stdout"].strip().splitlines():
                        parts_line = line.split(maxsplit=1)
                        if len(parts_line) >= 2:
                            findings["yara_matches"].append({
                                "rule": parts_line[0],
                                "target": parts_line[1] if len(parts_line) > 1 else "",
                            })

                # Strings extraction (sample)
                strings_result = await run_strings(tmp_path, count=50)
                if strings_result["stdout"].strip():
                    findings["strings_sample"] = (
                        strings_result["stdout"].strip().splitlines()[:50]
                    )
            finally:
                # Cleanup temp
                try:
                    Path(tmp_path).unlink()
                except FileNotFoundError:
                    pass

    return findings


async def _phase_intelligence(analysis_id: str, target: str, pre_findings: dict) -> dict:
    """Phase 3: External threat intel APIs (graceful degradation)."""
    from engine.threat_intel import vt_client, urlscan_client, abuseipdb_client

    findings = {"vt": None, "urlscan": None, "abuseipdb": None}

    # File-based: check VirusTotal by hash
    if target.startswith("stored://"):
        sha256 = pre_findings.get("sha256", "")
        if sha256:
            findings["vt"] = await vt_client.analyze_hash(sha256)
    else:
        # URL-based: check VirusTotal + URLScan
        findings["vt"] = await vt_client.analyze_url(target)
        findings["urlscan"] = await urlscan_client.search_url(target)

        # Check domain IP on AbuseIPDB
        from urllib.parse import urlparse
        domain = urlparse(target).hostname
        if domain:
            try:
                import socket
                ip = socket.gethostbyname(domain)
                findings["abuseipdb"] = await abuseipdb_client.check_ip(ip)
            except socket.gaierror:
                findings["abuseipdb"] = {"error": "DNS resolution failed"}

    return findings


async def _phase_sandbox(analysis_id: str, target: str) -> dict:
    """Phase 4: CAPEv2 dynamic sandbox analysis (files only)."""
    findings = {"cape_task_id": None, "behavior": [], "verdict": "skipped"}

    if not target.startswith("stored://"):
        findings["verdict"] = "not_applicable"
        return findings

    from storage.file_store import retrieve_file
    parts = target.split("/")
    file_id = parts[1].replace("stored://", "")
    file_name = parts[-1] if len(parts) > 2 else f"sample_{file_id}"
    data = retrieve_file(file_id)

    if not data:
        findings["verdict"] = "failed"
        return findings

    # Write to temp for CAPE submission
    tmp_path = f"/app/storage/tmp/{file_id}"
    Path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    Path(tmp_path).write_bytes(data)

    try:
        from engine.cape_client import CAPEv2Client
        cape = CAPEv2Client()

        task_id = await cape.submit_file(tmp_path, file_name)
        if task_id:
            findings["cape_task_id"] = task_id
            report = await cape.poll_task(task_id, max_polls=30)
            if report:
                indicators = await cape.fetch_behavior_indicators(task_id)
                findings["behavior"] = indicators[:100]  # cap at 100
                findings["verdict"] = "complete"
        else:
            findings["verdict"] = "skipped"
    except Exception as e:
        logger.warning("Sandbox phase failed: %s", e)
        findings["verdict"] = "failed"
    finally:
        try:
            Path(tmp_path).unlink()
        except FileNotFoundError:
            pass

    return findings


# ── Main Orchestrator ──────────────────────────────────────────────

async def start_analysis(analysis_id: str):
    """Execute the full analysis pipeline for a given analysis ID."""
    async with semaphore:
        logger.info("Starting analysis %s", analysis_id)

        # Load analysis record
        from storage.database import get_session, Analysis, Verdict
        async with (await get_session).__aenter__() as db:
            analysis = await db.get(Analysis, analysis_id)
            if not analysis:
                logger.error("Analysis %s not found", analysis_id)
                return

            analysis.status = "running"
            await db.commit()

        # Run pipeline phases sequentially
        is_file = analysis.type == "file"
        phase_names = ["pre_analysis", "static", "intelligence", "sandbox"]

        all_findings = {}
        for phase_name in phase_names:
            await sse_bus.publish(analysis_id, "phase_start", {"phase": phase_name})
            logger.info("Analysis %s: phase %s", analysis_id, phase_name)

            try:
                if phase_name == "pre_analysis":
                    findings = await _phase_pre_analysis(analysis_id, analysis.target, is_file)
                elif phase_name == "static":
                    findings = await _phase_static(analysis_id, analysis.target, all_findings.get("pre_analysis", {}))
                elif phase_name == "intelligence":
                    findings = await _phase_intelligence(analysis_id, analysis.target, all_findings.get("pre_analysis", {}))
                elif phase_name == "sandbox":
                    findings = await _phase_sandbox(analysis_id, analysis.target)
                else:
                    findings = {}

                all_findings[phase_name] = findings

                # Save phase result to DB
                async with (await get_session).__aenter__() as db:
                    analysis = await db.get(Analysis, analysis_id)
                    for phase in analysis.phases:
                        if phase.phase_name == phase_name:
                            phase.status = "complete"
                            phase.completed_at = datetime.now(timezone.utc)
                            phase.raw_output = json.dumps(findings)
                    await db.commit()

                await sse_bus.publish(analysis_id, "phase_complete", {
                    "phase": phase_name,
                    "findings_count": len(findings),
                })

            except Exception as e:
                logger.error("Phase %s failed for %s: %s", phase_name, analysis_id, e)
                async with (await get_session).__aenter__() as db:
                    analysis = await db.get(Analysis, analysis_id)
                    for phase in analysis.phases:
                        if phase.phase_name == phase_name:
                            phase.status = "failed"
                            phase.raw_output = json.dumps({"error": str(e)})
                    await db.commit()
                await sse_bus.publish(analysis_id, "phase_failed", {
                    "phase": phase_name,
                    "error": str(e),
                })

        # Compute final verdict
        from engine.scoring import ThreatScorer
        scorer = ThreatScorer()

        # Score based on findings
        pre = all_findings.get("pre_analysis", {})
        static = all_findings.get("static", {})
        intel = all_findings.get("intelligence", {})
        sandbox = all_findings.get("sandbox", {})

        if pre.get("extension_mismatch"):
            scorer.add_indicator("extension_mismatch", description="File extension doesn't match detected type")

        for yara_match in static.get("yara_matches", []):
            scorer.add_indicator("yara_family_match", description=yara_match.get("rule", "unknown"))

        # Save verdict
        verdict = scorer.compute_verdict()
        async with (await get_session).__aenter__() as db:
            analysis = await db.get(Analysis, analysis_id)
            analysis.status = "complete"
            analysis.verdict = Verdict(
                score=verdict.score,
                category=verdict.category,
                threat_type=verdict.threat_type,
                summary=verdict.summary,
            )
            await db.commit()

        await sse_bus.publish(analysis_id, "complete", {
            "verdict": verdict.to_dict(),
            "findings": {k: _serialize(v) for k, v in all_findings.items()},
        })
        logger.info("Analysis %s complete — %s (score: %.1f)", analysis_id, verdict.category, verdict.score)


def _serialize(obj):
    """Make arbitrary objects JSON-serializable."""
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)
