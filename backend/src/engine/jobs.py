"""ClearCage — Background jobs: TTL cleanup + YARA auto-update.

Runs via APScheduler on startup.  Configurable intervals via environment
variables (default: hourly cleanup, daily YARA refresh).
"""

import logging
import os
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# ── YARA Rule Repos ────────────────────────────────────────────────

YARA_REPOS = [
    # (repo_url, subdirectory)
    ("https://raw.githubusercontent.com/Yara-Rules/rules/master/sigfinders", "sigfinders"),
    ("https://raw.githubusercontent.com/Yara-Rules/rules/master/malware", "malware"),
]

YARA_RULES_DIR = Path("/app/yara-rules")


# ── TTL Cleanup ─────────────────────────────────────────────────────

async def job_ttl_cleanup():
    """Purge expired unpinned samples."""
    from storage.file_store import purge_expired
    try:
        purged = purge_expired()
        if purged:
            logger.info("TTL cleanup: purged %d expired samples", purged)
        else:
            logger.debug("TTL cleanup: nothing to purge")
    except Exception as e:
        logger.error("TTL cleanup failed: %s", e)


# ── YARA Auto-Update ───────────────────────────────────────────────

async def job_update_yara_rules():
    """Pull latest YARA rules from trusted GitHub repos."""
    logger.info("Starting YARA rule update...")
    updated = 0

    for repo_url, subdir in YARA_REPOS:
        try:
            target_dir = YARA_RULES_DIR / "community" / subdir
            target_dir.mkdir(parents=True, exist_ok=True)

            # Fetch directory listing (GitHub raw doesn't list dirs, so we use API)
            api_url = f"https://api.github.com/repos/Yara-Rules/rules/contents/{subdir}"
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(api_url)
                if resp.status_code != 200:
                    logger.warning("YARA repo listing failed for %s: %d", subdir, resp.status_code)
                    continue

                files = resp.json()
                for f in files:
                    if f["type"] == "file" and f["name"].endswith(".yar"):
                        rule_path = target_dir / f["name"]
                        download_url = f["download_url"]
                        rule_content = await _fetch_raw(download_url, client)
                        if rule_content:
                            rule_path.write_text(rule_content)
                            updated += 1

        except Exception as e:
            logger.warning("YARA update failed for %s: %s", subdir, e)

    logger.info("YARA rule update complete: %d rules fetched", updated)


async def _fetch_raw(url: str, client: httpx.AsyncClient) -> str | None:
    """Fetch a raw file from GitHub."""
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return None


# ── Scheduler Setup ────────────────────────────────────────────────

from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()


def start_jobs():
    """Register and start all background jobs."""
    cleanup_interval = int(os.getenv("TTL_CLEANUP_HOURS", "1"))
    yara_update_interval = int(os.getenv("YARA_UPDATE_HOURS", "24"))

    scheduler.add_job(
        job_ttl_cleanup,
        "interval",
        hours=cleanup_interval,
        id="ttl_cleanup",
        name="Purge expired samples",
        replace_existing=True,
    )
    scheduler.add_job(
        job_update_yara_rules,
        "interval",
        hours=yara_update_interval,
        id="yara_update",
        name="Update YARA rules from GitHub",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Background jobs started (cleanup=%dh, yara=%dh)", cleanup_interval, yara_update_interval)


def stop_jobs():
    """Gracefully stop all background jobs."""
    scheduler.shutdown(wait=False)
