import json
import uuid
import random
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from constants import RULES, CVE_CATALOG

logger = logging.getLogger(__name__)


class BaseGenerator(ABC):
    """
    Abstract base class untuk semua skenario generator.

    Setiap subclass wajib mengimplementasikan:
        - scenario_name (property)
        - generate_events() (method)
    """

    ASSETS_FILE = Path(__file__).parent / "assets.json"
    OUTPUT_DIR  = Path(__file__).parent / "output"

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.OUTPUT_DIR.mkdir(exist_ok=True)
        self.assets = self._load_assets()

    # Abstract interface — wajib diimplementasi subclass
    @property
    @abstractmethod
    def scenario_name(self) -> str:
        """Label skenario, e.g. 'normal', 'spike'."""

    @abstractmethod
    def generate_events(self) -> list[dict]:
        """Generate dan return list of event dicts."""

    # Shared utilities
    def _load_assets(self) -> list[dict]:
        with open(self.ASSETS_FILE, "r") as f:
            return json.load(f)

    def _get_asset(self, asset_id: str | None = None) -> dict:
        """Return satu asset. Jika asset_id None, pilih random."""
        if asset_id:
            return next(a for a in self.assets if a["asset_id"] == asset_id)
        return random.choice(self.assets)

    def _get_assets_by_type(self, asset_type: str) -> list[dict]:
        return [a for a in self.assets if a["asset_type"] == asset_type]

    def _get_assets_by_criticality(self, criticality: str) -> list[dict]:
        return [a for a in self.assets if a["criticality"] == criticality]

    def _build_alert_event(
        self,
        asset: dict,
        rule_id: str,
        timestamp: datetime,
        override_severity: int | None = None,
    ) -> dict:
        """
        Bangun satu event alert berdasarkan rule catalog.
        override_severity dipakai untuk skenario yang perlu memaksa severity.
        """
        rule = RULES[rule_id]
        severity = override_severity if override_severity is not None else rule["severity"]

        return {
            "event_id":         str(uuid.uuid4()),
            "timestamp":        timestamp.isoformat(),
            "asset_id":         asset["asset_id"],
            "hostname":         asset["hostname"],
            "severity":         severity,
            "category":         rule["category"],
            "event_type":       rule["event_type"],
            "rule_id":          rule_id,
            "rule_description": rule["description"],
            "cve_id":           None,
            "cvss_score":       None,
            "scenario":         self.scenario_name,
        }

    def _build_vuln_event(
        self,
        asset: dict,
        cve: dict,
        timestamp: datetime,
    ) -> dict:
        """Bangun satu event vulnerability berdasarkan CVE catalog."""
        # Map CVSS score ke severity Wazuh
        cvss = cve["cvss_score"]
        if cvss >= 9.0:
            rule_id, severity = "VULN-001", 15
        elif cvss >= 7.0:
            rule_id, severity = "VULN-002", 12
        elif cvss >= 4.0:
            rule_id, severity = "VULN-003", 8
        else:
            rule_id, severity = "VULN-004", 4

        rule = RULES[rule_id]

        return {
            "event_id":         str(uuid.uuid4()),
            "timestamp":        timestamp.isoformat(),
            "asset_id":         asset["asset_id"],
            "hostname":         asset["hostname"],
            "severity":         severity,
            "category":         rule["category"],
            "event_type":       "vuln",
            "rule_id":          rule_id,
            "rule_description": f"{rule['description']} - {cve['product']}",
            "cve_id":           cve["cve_id"],
            "cvss_score":       cvss,
            "scenario":         self.scenario_name,
        }

    def _random_cve(self, min_cvss: float = 0.0) -> dict:
        pool = [c for c in CVE_CATALOG if c["cvss_score"] >= min_cvss]
        return random.choice(pool)

    def save(self, events: list[dict]) -> Path:
        """Simpan events ke JSON file di output/."""
        output_path = self.OUTPUT_DIR / f"events_{self.scenario_name}.json"
        with open(output_path, "w") as f:
            json.dump(events, f, indent=2, default=str)

        logger.info(
            "Scenario %-20s → %4d events saved to %s",
            self.scenario_name,
            len(events),
            output_path,
        )
        return output_path

    def run(self) -> Path:
        """Entry point: generate → save → return path."""
        logger.info("Generating scenario: %s", self.scenario_name)
        events = self.generate_events()
        return self.save(events)