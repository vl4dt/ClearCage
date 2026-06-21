"""ClearCage — CAPEv2 REST API client.

Communicates with the official CAPEv2 web interface via HTTP.
Implements graceful degradation: all methods return None on failure
so the pipeline can continue with static analysis results alone.
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CAPE_API_URL = "http://cape:8000/api/v2"  # matches docker-compose service name


class CAPEv2Client:
    """Async REST client for CAPEv2 sandbox."""

    def __init__(self, base_url: str = CAPE_API_URL, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._healthy: bool | None = None

    async def healthcheck(self) -> bool:
        """Check if CAPE API is reachable."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as http:
                resp = await http.get(f"{self.base_url}/about")
                self._healthy = resp.status_code == 200
        except Exception as e:
            logger.warning("CAPE healthcheck failed: %s", e)
            self._healthy = False
        return self._healthy or False

    async def submit_file(
        self,
        file_path: str,
        file_name: str,
        timeout: int | None = None,
        options: dict | None = None,
    ) -> int | None:
        """Submit a file for dynamic analysis. Returns task ID or None."""
        if not await self.healthcheck():
            logger.info("CAPE unavailable, skipping dynamic analysis")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout * 2) as http:
                with open(file_path, "rb") as f:
                    files = {"file": (file_name, f)}
                    data = {}
                    if timeout:
                        data["timeout"] = str(timeout)
                    if options:
                        data["options"] = str(options)

                    resp = await http.post(
                        f"{self.base_url}/task/create/file",
                        files=files,
                        data=data,
                    )
                    resp.raise_for_status()
                    result = resp.json()
                    task_id = result.get("task_id") or result.get("id")
                    logger.info("CAPE task submitted: %s", task_id)
                    return task_id
        except Exception as e:
            logger.warning("CAPE file submission failed: %s", e)
            return None

    async def poll_task(self, task_id: int, max_polls: int = 60, poll_interval: float = 10.0) -> dict | None:
        """Poll a CAPE task until complete or timeout. Returns analysis report."""
        if not await self.healthcheck():
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout * 2) as http:
                for attempt in range(max_polls):
                    resp = await http.get(f"{self.base_url}/task/{task_id}")
                    resp.raise_for_status()
                    data = resp.json()

                    status = data.get("status", "")
                    if status in ("reported", "completed"):
                        logger.info("CAPE task %d completed", task_id)
                        return data

                    await httpx.AsyncClient().__aenter__()  # noop for interval
                    import asyncio
                    await asyncio.sleep(poll_interval)

                logger.warning("CAPE task %d timed out after %d polls", task_id, max_polls)
                return None
        except Exception as e:
            logger.warning("CAPE task polling failed: %s", e)
            return None

    async def fetch_malware_report(self, task_id: int) -> dict | None:
        """Fetch the final malware analysis report for a task."""
        if not await self.healthcheck():
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout * 2) as http:
                resp = await http.get(f"{self.base_url}/malware/{task_id}")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.warning("CAPE report fetch failed: %s", e)
            return None

    async def fetch_behavior_indicators(self, task_id: int) -> list[dict]:
        """Extract behavioral indicators from CAPE report for scoring."""
        report = await self.fetch_malware_report(task_id)
        if not report:
            return []

        indicators = []
        behavior = report.get("behavior", {})
        processes = behavior.get("processes", [])

        for proc in processes:
            calls = proc.get("calls", [])
            for call_group in calls:
                category = call_group.get("category", "")
                calls_list = call_group.get("calls", [])
                for call in calls_list:
                    api = call.get("api", "")
                    args = call.get("arguments", {})
                    if api:
                        indicators.append({
                            "process": proc.get("process_name", "unknown"),
                            "category": category,
                            "api": api,
                            "arguments": args,
                        })

        return indicators
