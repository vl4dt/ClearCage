"""ClearCage — DinD container runner.

Spawns isolated Docker containers for static analysis tools (YARA, pefile, etc.)
with strict resource limits and network isolation.
"""

import asyncio
import logging
import os
from pathlib import Path

import docker

logger = logging.getLogger(__name__)

# DinD client (connects to the Docker socket inside the DinD container)
DOCKER_HOST = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
client = docker.from_env()

# Default resource caps
DEFAULT_MEMORY = os.getenv("ANALYSIS_MEMORY", "512m")
DEFAULT_CPUS = float(os.getenv("ANALYSIS_CPUS", "1.0"))
DEFAULT_TIMEOUT = int(os.getenv("ANALYSIS_TIMEOUT_SEC", "120"))


class AnalysisContainer:
    """Context manager for a single analysis container execution."""

    def __init__(
        self,
        image: str,
        command: list[str],
        volumes: dict[str, dict[str, str]] | None = None,
        network_mode: str = "none",
        memory: str = DEFAULT_MEMORY,
        cpus: float = DEFAULT_CPUS,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.image = image
        self.command = command
        self.volumes = volumes or {}
        self.network_mode = network_mode
        self.memory = memory
        self.cpus = cpus
        self.timeout = timeout
        self.container = None
        self.stdout = ""
        self.stderr = ""

    async def run(self) -> dict:
        """Execute the container and return {exit_code, stdout, stderr, duration}."""
        try:
            # Ensure image is available (pull if missing)
            try:
                client.images.get(self.image)
            except docker.errors.ImageNotFound:
                logger.info("Pulling image: %s", self.image)
                client.images.pull(self.image)

            # Spawn container
            self.container = client.containers.run(
                self.image,
                command=self.command,
                volumes=self.volumes,
                network_mode=self.network_mode,
                mem_limit=self.memory,
                nano_cpus=int(self.cpus * 1e9),
                remove=True,  # --rm: auto-cleanup on exit
                detach=True,
                stdin_open=False,
                tty=False,
            )

            # Wait with timeout
            start = asyncio.get_event_loop().time()
            try:
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self.container.wait, {"condition": "not-running"}
                    ),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("Container %s timed out after %ds", self.image, self.timeout)
                self.container.kill()
                result = {"StatusCode": 124}  # conventional timeout code

            duration = asyncio.get_event_loop().time() - start

            # Collect logs
            logs = self.container.logs(stream=False, stderr=True)
            self.stdout = logs.decode("utf-8", errors="replace")

            exit_code = result.get("StatusCode", -1)

            return {
                "exit_code": exit_code,
                "stdout": self.stdout,
                "stderr": "",
                "duration": round(duration, 2),
            }

        except docker.errors.APIError as e:
            logger.error("Docker API error: %s", e)
            return {"exit_code": -1, "stdout": "", "stderr": str(e), "duration": 0}
        finally:
            if self.container:
                try:
                    self.container.remove(force=True)
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.container:
            try:
                self.container.remove(force=True)
            except Exception:
                pass


# ── Convenience Runners ─────────────────────────────────────────────

async def run_yara(
    sample_path: str,
    rules_dir: str = "/app/yara-rules",
) -> dict:
    """Run YARA scan on a sample inside an isolated container."""
    runner = AnalysisContainer(
        image="remnux/yara:latest",
        command=["yara", "-r", f"{rules_dir}/*.yara", sample_path],
        volumes={
            {"bind": sample_path, "mode": "ro"},
            {"bind": rules_dir, "mode": "ro"},
        },
        network_mode="none",
    )
    return await runner.run()


async def run_pefile_analysis(sample_path: str) -> dict:
    """Run pefile-based static analysis inside an isolated container."""
    runner = AnalysisContainer(
        image="remnux/pefile:latest",
        command=["python3", "-c", f"import pefile, json; pe=pefile.PE('{sample_path}'); print(json.dumps(pe.__dict__))"],
        volumes={
            {"bind": sample_path, "mode": "ro"},
        },
        network_mode="none",
    )
    return await runner.run()


async def run_strings(sample_path: str, count: int = 100) -> dict:
    """Extract printable strings from a sample."""
    runner = AnalysisContainer(
        image="remnux/remnux-distro:noble",
        command=["strings", "-n", "6", "-n", str(count), sample_path],
        volumes={
            {"bind": sample_path, "mode": "ro"},
        },
        network_mode="none",
    )
    return await runner.run()
