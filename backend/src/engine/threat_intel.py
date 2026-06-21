"""ClearCage — External threat intelligence clients.

Graceful degradation: all methods return None on failure so the pipeline
continues with static analysis results alone.  APIs activate automatically
when keys are configured in .env.
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)


# ── VirusTotal Client ──────────────────────────────────────────────

class VirusTotalClient:
    """VirusTotal v3 API client."""

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.enabled = bool(self.api_key)
        self.base_url = "https://www.virustotal.com/api/v3"

    async def analyze_hash(self, sha256: str) -> dict | None:
        """Look up a file hash in VirusTotal. Returns detection summary."""
        if not self.enabled:
            logger.debug("VirusTotal API key not configured, skipping")
            return None

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.base_url}/files/{sha256}",
                    headers={"x-apikey": self.api_key},
                )
                if resp.status_code == 404:
                    return {"not_found": True, "last_analysis_stats": {}}

                resp.raise_for_status()
                data = resp.json()
                attributes = data.get("data", {}).get("attributes", {})

                return {
                    "total_votes": attributes.get("total_votes", {}),
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "meaningful_name": attributes.get("meaningful_name", "unknown"),
                    "type_description": attributes.get("type_description", ""),
                    "reputation": attributes.get("reputation", 0),
                }
        except Exception as e:
            logger.warning("VirusTotal lookup failed for %s: %s", sha256, e)
            return None

    async def analyze_url(self, url: str) -> dict | None:
        """Look up a URL in VirusTotal."""
        if not self.enabled:
            return None

        try:
            import hashlib
            url_hash = hashlib.md5(url.encode()).hexdigest()

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.base_url}/urls/{url_hash}",
                    headers={"x-apikey": self.api_key},
                )
                if resp.status_code == 404:
                    return {"not_found": True}

                resp.raise_for_status()
                data = resp.json()
                attributes = data.get("data", {}).get("attributes", {})

                return {
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "last_analysis_results_count": len(
                        attributes.get("last_analysis_results", {})
                    ),
                    "category_verbose": attributes.get("category_verbose", ""),
                    "popularity_ranks": attributes.get("popularity_ranks", {}),
                }
        except Exception as e:
            logger.warning("VirusTotal URL lookup failed for %s: %s", url, e)
            return None


# ── URLScan Client ─────────────────────────────────────────────────

class URLScanClient:
    """URLScan.io API client."""

    def __init__(self):
        self.api_key = os.getenv("URLSCAN_API_KEY", "")
        self.enabled = bool(self.api_key)
        self.base_url = "https://urlscan.io/api/v1"

    async def analyze_url(self, url: str) -> dict | None:
        """Submit a URL to URLScan for analysis."""
        if not self.enabled:
            logger.debug("URLScan API key not configured, skipping")
            return None

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Submit URL for scanning
                resp = await client.post(
                    f"{self.base_url}/scan",
                    headers={"API-Key": self.api_key},
                    content=url,
                )
                resp.raise_for_status()
                result = resp.json()

                return {
                    "uuid": result.get("uuid"),
                    "message": result.get("message"),
                }
        except Exception as e:
            logger.warning("URLScan submission failed for %s: %s", url, e)
            return None

    async def search_url(self, url: str) -> dict | None:
        """Search URLScan's database for existing scans of a URL."""
        if not self.enabled:
            return None

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.base_url}/search",
                    headers={"API-Key": self.api_key},
                    params={"q": f"url:{url}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    if results:
                        latest = results[0].get("page", {})
                        return {
                            "verdict": latest.get("verdict", {}),
                            "url": latest.get("url"),
                            "status_code": latest.get("statusCode"),
                            "title": latest.get("title"),
                        }
        except Exception as e:
            logger.warning("URLScan search failed for %s: %s", url, e)

        return None


# ── AbuseIPDB Client ───────────────────────────────────────────────

class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation."""

    def __init__(self):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.enabled = bool(self.api_key)
        self.base_url = "https://api.abuseipdb.io/api/v2"

    async def check_ip(self, ip: str) -> dict | None:
        """Check IP reputation on AbuseIPDB."""
        if not self.enabled:
            logger.debug("AbuseIPDB API key not configured, skipping")
            return None

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.base_url}/blacklist/{ip}",
                    headers={
                        "Key": self.api_key,
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 404:
                    return {"not_found": True, "isBlacklisted": False}

                resp.raise_for_status()
                data = resp.json()
                data.get("data", {})

                return {
                    "isBlacklisted": data.get("data", {}).get("isBlacklisted", False),
                    "abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore", 0),
                    "totalReports": data.get("data", {}).get("totalReports", 0),
                    "lastReportedAt": data.get("data", {}).get("lastReportedAt"),
                }
        except Exception as e:
            logger.warning("AbuseIPDB check failed for %s: %s", ip, e)
            return None


# ── Singleton Instances ────────────────────────────────────────────

vt_client = VirusTotalClient()
urlscan_client = URLScanClient()
abuseipdb_client = AbuseIPDBClient()
