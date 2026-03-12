"""
Skenario 3: Vulnerability Cluster — CVE terkonsentrasi pada beberapa aset.

Karakteristik:
- Simulasi hasil vulnerability scan yang menemukan CVE kritis di 3-5 aset
- Aset yang terkena: campuran server dan workstation, belum di-patch
- Volume alert: medium (bukan spike), tapi severity tinggi karena CVSS
- Disertai alert integrity (file berubah tanpa otorisasi) sebagai penanda
- Tujuan: menguji apakah risk score naik signifikan karena komponen vuln_score
"""

import random
from datetime import datetime, timedelta, timezone

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_generator import BaseGenerator
from constants import SCENARIO_VULN, CVE_CATALOG


class VulnClusterScenario(BaseGenerator):

    scenario_name = SCENARIO_VULN

    def __init__(
        self,
        start_date: datetime | None = None,
        days: int = 5,
        seed: int = 42,
    ):
        super().__init__(seed=seed)
        self.start_date = start_date or (
            datetime.now(tz=timezone.utc) - timedelta(days=days)
        )
        self.days = days

        # Pilih 3–5 aset yang "belum di-patch" sebagai target cluster
        all_assets = self.assets
        n_targets  = random.randint(3, 5)
        self.vuln_targets = random.sample(all_assets, k=n_targets)

        # Assign CVE ke setiap target (1–3 CVE per aset)
        self.asset_cve_map: dict[str, list[dict]] = {}
        for asset in self.vuln_targets:
            n_cve = random.randint(1, 3)
            # Prioritaskan CVE dengan CVSS tinggi untuk aset kritis
            min_cvss = 7.0 if asset["criticality"] in ("critical", "high") else 4.0
            pool     = [c for c in CVE_CATALOG if c["cvss_score"] >= min_cvss]
            selected = random.sample(pool, k=min(n_cve, len(pool)))
            self.asset_cve_map[asset["asset_id"]] = selected

        print(f"  [VulnClusterScenario] Vulnerable assets:")
        for asset in self.vuln_targets:
            cves = [c["cve_id"] for c in self.asset_cve_map[asset["asset_id"]]]
            print(f"    - {asset['asset_id']}: {cves}")

    def generate_events(self) -> list[dict]:
        events: list[dict] = []

        for day_offset in range(self.days):
            day_start = self.start_date + timedelta(days=day_offset)

            # Background: aktivitas normal semua aset
            events.extend(self._generate_background(day_start))

            # Vulnerability events: scan dilakukan tiap hari (simulasi daily scan)
            events.extend(self._generate_vuln_events(day_start))

            # Integrity alerts: beberapa aset vulnerable menunjukkan perubahan file
            # (menandakan eksploitasi atau percobaan eksploitasi)
            if day_offset >= 1:  # mulai hari ke-2
                events.extend(self._generate_integrity_alerts(day_start))

        events.sort(key=lambda e: e["timestamp"])
        return events

    def _generate_background(self, day_start: datetime) -> list[dict]:
        """Normal background activity untuk semua aset."""
        events   = []
        bg_rules = ["5501", "5502", "554", "40111"]
        volume   = random.randint(50, 90)

        for _ in range(volume):
            ts = day_start.replace(
                hour=random.randint(7, 18),
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )
            events.append(
                self._build_alert_event(
                    asset=self._get_asset(),
                    rule_id=random.choice(bg_rules),
                    timestamp=ts,
                )
            )
        return events

    def _generate_vuln_events(self, day_start: datetime) -> list[dict]:
        """
        Generate vulnerability scan results.
        Scan biasanya dijalankan dini hari (00:00–04:00) atau
        setelah jam kerja (18:00–22:00) agar tidak ganggu produksi.
        """
        events = []

        # Tentukan jam scan
        scan_hour = random.choice([1, 2, 3, 19, 20, 21])

        for asset in self.vuln_targets:
            cve_list = self.asset_cve_map[asset["asset_id"]]
            for i, cve in enumerate(cve_list):
                # Tiap CVE ditemukan berselang beberapa menit
                ts = day_start.replace(
                    hour=scan_hour,
                    minute=random.randint(0, 59),
                    second=(i * 30) % 60,  # selisih 30 detik antar CVE
                )
                events.append(
                    self._build_vuln_event(
                        asset=asset,
                        cve=cve,
                        timestamp=ts,
                    )
                )
        return events

    def _generate_integrity_alerts(self, day_start: datetime) -> list[dict]:
        """
        Beberapa aset vulnerable menunjukkan perubahan file tak terduga.
        Simulasi adanya exploit attempt atau unauthorized config change.
        """
        events = []
        integrity_rules = ["550", "551", "554"]

        # Hanya subset dari vuln targets yang mengalami integrity alert
        affected = random.sample(
            self.vuln_targets,
            k=max(1, len(self.vuln_targets) // 2),
        )

        for asset in affected:
            n_alerts = random.randint(2, 6)
            for _ in range(n_alerts):
                ts = day_start.replace(
                    hour=random.randint(8, 18),
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59),
                )
                events.append(
                    self._build_alert_event(
                        asset=asset,
                        rule_id=random.choice(integrity_rules),
                        timestamp=ts,
                    )
                )
        return events