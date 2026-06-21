"""ClearCage — Configurable threat scoring engine.

Reads weights and thresholds from config/scoring.yaml (or embedded defaults).
Produces a ThreatVerdict with numeric score, category, and threat type.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


# ── Data Classes ────────────────────────────────────────────────────

class ThreatCategory(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class ThreatVerdict:
    """Final analysis verdict."""
    score: float = 0.0
    category: str = ThreatCategory.CLEAN.value
    threat_type: str = "unknown"
    indicators: list[dict] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 2),
            "category": self.category,
            "threat_type": self.threat_type,
            "indicators": self.indicators,
            "summary": self.summary,
        }


# ── Config Loader ───────────────────────────────────────────────────

_DEFAULT_CONFIG = {
    "scoring": {
        "weights": {
            "vt_detection_ratio": 4.0,
            "yara_family_match": 2.0,
            "suspicious_pe_import": 0.5,
            "high_entropy_section": 1.0,
            "embedded_bad_url": 1.5,
            "extension_mismatch": 0.5,
            "macro_detected": 2.0,
            "pdf_embedded_script": 1.5,
            "urlscan_verdict_malicious": 3.0,
            "capev2_malicious_behavior": 3.0,
        },
        "thresholds": {
            "clean": 2.0,
            "suspicious": 5.0,
            "malicious": 8.0,
        },
    }
}

_config: dict = _DEFAULT_CONFIG


def load_scoring_config(path: str = "/app/config/scoring.yaml") -> dict:
    """Load scoring weights + thresholds from YAML config."""
    global _config
    config_path = Path(path)
    if config_path.exists():
        try:
            _config = yaml.safe_load(config_path.read_text()) or _DEFAULT_CONFIG
            logger.info("Loaded scoring config from %s", path)
        except Exception as e:
            logger.warning("Failed to load scoring config, using defaults: %s", e)
    else:
        logger.info("No scoring config at %s, using embedded defaults", path)
    return _config


def get_weight(indicator_name: str) -> float:
    """Get the weight for a scoring indicator."""
    weights = _config.get("scoring", {}).get("weights", {})
    return weights.get(indicator_name, 1.0)


def get_thresholds() -> dict:
    """Get category thresholds."""
    return _config.get("scoring", {}).get("thresholds", {
        "clean": 2.0,
        "suspicious": 5.0,
        "malicious": 8.0,
    })


# ── Scorer ──────────────────────────────────────────────────────────

class ThreatScorer:
    """Accumulates indicators and computes final verdict."""

    def __init__(self):
        self._indicators: list[dict] = []
        self._score: float = 0.0

    def add_indicator(
        self,
        name: str,
        count: int = 1,
        description: str = "",
        weight_override: float | None = None,
    ):
        """Add a scoring indicator."""
        weight = weight_override or get_weight(name)
        points = weight * count
        self._score += points
        self._indicators.append({
            "name": name,
            "count": count,
            "weight": round(weight, 2),
            "points": round(points, 2),
            "description": description,
        })

    def compute_verdict(self, threat_type: str = "unknown") -> ThreatVerdict:
        """Finalize the verdict based on accumulated indicators."""
        thresholds = get_thresholds()
        score = self._score

        # Determine category
        if score >= thresholds.get("malicious", 8.0):
            category = ThreatCategory.CRITICAL.value
        elif score >= thresholds.get("suspicious", 5.0):
            category = ThreatCategory.MALICIOUS.value
        elif score >= thresholds.get("clean", 2.0):
            category = ThreatCategory.SUSPICIOUS.value
        else:
            category = ThreatCategory.CLEAN.value

        # Auto-detect threat type from strongest indicators
        if threat_type == "unknown":
            indicator_names = {i["name"] for i in self._indicators}
            if "yara_family_match" in indicator_names:
                yara_hits = [i for i in self._indicators if i["name"] == "yara_family_match"]
                threat_type = yara_hits[0]["description"] if yara_hits[0]["description"] else "malware"
            elif "macro_detected" in indicator_names:
                threat_type = "macro_malware"
            elif "urlscan_verdict_malicious" in indicator_names:
                threat_type = "phishing"
            elif "high_entropy_section" in indicator_names:
                threat_type = "packed"

        summary = self._build_summary(category, threat_type)

        return ThreatVerdict(
            score=score,
            category=category,
            threat_type=threat_type,
            indicators=self._indicators,
            summary=summary,
        )

    def _build_summary(self, category: str, threat_type: str) -> str:
        """Generate a human-readable summary."""
        parts = [f"Score: {self._score:.1f} ({category.upper()})"]
        if threat_type != "unknown":
            parts.append(f"Threat type: {threat_type}")
        if self._indicators:
            top = sorted(self._indicators, key=lambda i: i["points"], reverse=True)[:3]
            parts.append("Key indicators: " + ", ".join(
                f"{i['name']} ({i['points']:.1f})" for i in top
            ))
        return ". ".join(parts) + "."
