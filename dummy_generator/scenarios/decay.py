"""
Karakteristik:
- Dimulai dari kondisi post-spike (risk score tinggi)
- Tim SOC merespons: patching, isolasi aset, reset password
- Risk score turun bertahap seiring waktu (exponential decay simulation)
- Tujuan: membuktikan dashboard menampilkan penurunan skor setelah remediasi
"""

import random
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_generator import BaseGenerator
from constants import SCENARIO_DECAY, CVE_CATALOG


class RemediationPhase(NamedTuple):
    day_offset: int
    volume_multiplier: float   # relatif terhadap post-spike volume
    max_severity: int          # batas atas severity pada fase ini
    vuln_events: bool          # apakah masih ada vuln events
    description: str


# Definisi fase remediasi "decay curve"
REMEDIATION_PHASES = [
    RemediationPhase(0, 1.0,  15, True,  "Post-spike: full anomaly"),
    RemediationPhase(1, 0.6,  12, True,  "SOC response: contain & investigate"),
    RemediationPhase(2, 0.3,   9, False, "Patch deployed: vuln resolved"),
    RemediationPhase(3, 0.15,  7, False, "Enhanced monitoring: low residual"),
    RemediationPhase(4, 0.05,  5, False, "Normalized: back to baseline"),
]


class DecayScenario(BaseGenerator):

    scenario_name = SCENARIO_DECAY

    def __init__(
        self,
        start_date: datetime | None = None,
        seed: int = 42,
    ):
        super().__init__(seed=seed)
        self.start_date = start_date or (
            datetime.now(tz=timezone.utc) - timedelta(days=len(REMEDIATION_PHASES))
        )

        # Target: aset yang telah di-remediate
        critical = self._get_assets_by_criticality("critical")
        high     = self._get_assets_by_criticality("high")
        self.remediated_assets = random.sample(critical, k=2) + random.sample(high, k=1)

        print(f"  [DecayScenario] Remediated assets:")
        for a in self.remediated_assets:
            print(f"    - {a['asset_id']} ({a['criticality']})")

    def generate_events(self) -> list[dict]:
        events: list[dict] = []

        for phase in REMEDIATION_PHASES:
            day_start = self.start_date + timedelta(days=phase.day_offset)
            print(
                f"  Day {phase.day_offset}: [{phase.description}] "
                f"vol={phase.volume_multiplier}x | max_sev={phase.max_severity}"
            )
            events.extend(
                self._generate_phase_events(day_start, phase)
            )

        events.sort(key=lambda e: e["timestamp"])
        return events

    def _generate_phase_events(
        self,
        day_start: datetime,
        phase: RemediationPhase,
    ) -> list[dict]:
        events = []

        base_volume = 200  # volume hari 0 (post-spike)
        volume      = int(base_volume * phase.volume_multiplier)

        # Alert pool yang relevan untuk fase ini
        if phase.max_severity >= 12:
            rule_pool = ["5551", "5503", "40112", "100201", "5502", "40113"]
        elif phase.max_severity >= 9:
            rule_pool = ["5503", "5502", "550", "40112", "5552"]
        elif phase.max_severity >= 7:
            rule_pool = ["5502", "550", "551", "40111", "5710"]
        else:
            rule_pool = ["5501", "5502", "554", "40111"]

        for _ in range(volume):
            ts = day_start.replace(
                hour=random.randint(0, 23),
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )

            # Aset yang terkena: campuran remediated dan lainnya
            if random.random() < 0.7:
                asset = random.choice(self.remediated_assets)
            else:
                asset = self._get_asset()

            rule_id = random.choice(rule_pool)

            # severity tidak melebihi batas fase
            from constants import RULES
            base_severity = RULES.get(rule_id, {}).get("severity", 5)
            actual_severity = min(base_severity, phase.max_severity)

            events.append(
                self._build_alert_event(
                    asset=asset,
                    rule_id=rule_id,
                    timestamp=ts,
                    override_severity=actual_severity,
                )
            )

        # Tambah vuln events jika fase masih memerlukan
        if phase.vuln_events:
            events.extend(
                self._generate_residual_vuln(day_start, phase)
            )

        return events

    def _generate_residual_vuln(
        self,
        day_start: datetime,
        phase: RemediationPhase,
    ) -> list[dict]:
        """CVE yang belum di-patch (hari 0–1 saja)."""
        events  = []
        n_vulns = int(5 * phase.volume_multiplier)  # makin sedikit di fase lanjut

        for _ in range(n_vulns):
            ts = day_start.replace(
                hour=random.randint(1, 4),  # scan dini hari
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )
            asset = random.choice(self.remediated_assets)
            # Pilih CVE high/critical yang belum di-resolve
            cve = self._random_cve(min_cvss=7.0)
            events.append(
                self._build_vuln_event(asset=asset, cve=cve, timestamp=ts)
            )

        return events