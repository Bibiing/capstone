"""
Skenario 2: Lonjakan insiden mendadak (Incident Burst).

Karakteristik:
- Trigger  : 1 hari normal → lalu tiba-tiba ada attack window 2–4 jam
- Target   : 1–2 aset kritis (server/app)
- Volume   : melonjak 8–15x dari baseline dalam window pendek
- Severity : mayoritas 10–15 (brute force, malware, port scan)
- Tujuan   : membuktikan risk score naik drastis dan terdeteksi sebagai spike
"""

import random
from datetime import datetime, timedelta, timezone

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_generator import BaseGenerator
from constants import SCENARIO_SPIKE

# Rule yang muncul saat incident burst
ATTACK_RULE_WEIGHTS = {
    "5551": 25,   # Brute force attack
    "5503": 20,   # Multiple auth failures
    "5552": 15,   # Account locked
    "40112": 15,  # Port scan detected
    "40113": 10,  # Suspicious outbound
    "100201": 8,  # Suspicious process
    "100200": 5,  # Malware detected
    "40114": 2,   # DNS tunneling
}

# Rule latar belakang saat spike (aset lain tetap normal)
BACKGROUND_RULE_WEIGHTS = {
    "5501": 50,
    "5502": 20,
    "554":  15,
    "550":  10,
    "40111": 5,
}


class SpikeScenario(BaseGenerator):

    scenario_name = SCENARIO_SPIKE

    def __init__(
        self,
        start_date: datetime | None = None,
        days: int = 3,
        seed: int = 42,
    ):
        super().__init__(seed=seed)
        self.start_date = start_date or (
            datetime.now(tz=timezone.utc) - timedelta(days=days)
        )
        self.days = days

        # Tentukan target aset yang diserang — pilih dari aset kritis
        critical_assets = self._get_assets_by_criticality("critical")
        self.target_assets = random.sample(
            critical_assets, k=min(2, len(critical_assets))
        )
        target_ids = [a["asset_id"] for a in self.target_assets]
        print(f"  [SpikeScenario] Target assets: {target_ids}")

    def generate_events(self) -> list[dict]:
        events: list[dict] = []

        # Day 1: normal baseline untuk semua aset
        events.extend(self._generate_normal_day(day_offset=0))

        # Day 2: spike terjadi di tengah hari
        events.extend(self._generate_normal_day(day_offset=1, volume=40))
        events.extend(self._generate_attack_window(day_offset=1))
        events.extend(self._generate_normal_day_tail(day_offset=1))

        # Day 3: aftermath — masih ada sisa anomali, mulai reda
        if self.days >= 3:
            events.extend(self._generate_aftermath_day(day_offset=2))

        events.sort(key=lambda e: e["timestamp"])
        return events

    # Internal helpers
    def _generate_normal_day(
        self,
        day_offset: int,
        volume: int = 80,
    ) -> list[dict]:
        """Generate aktivitas normal untuk semua aset."""
        events = []
        rule_ids = list(BACKGROUND_RULE_WEIGHTS.keys())
        weights  = list(BACKGROUND_RULE_WEIGHTS.values())
        day_start = self.start_date + timedelta(days=day_offset)

        for _ in range(volume):
            ts = day_start.replace(
                hour=random.randint(7, 17),
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )
            events.append(
                self._build_alert_event(
                    asset=self._get_asset(),
                    rule_id=random.choices(rule_ids, weights=weights, k=1)[0],
                    timestamp=ts,
                )
            )
        return events

    def _generate_attack_window(self, day_offset: int) -> list[dict]:
        """
        Simulasi serangan intens selama 2–3 jam pada target aset.
        Volume: 200–400 events dalam window pendek.
        """
        events = []
        rule_ids = list(ATTACK_RULE_WEIGHTS.keys())
        weights  = list(ATTACK_RULE_WEIGHTS.values())

        day_start   = self.start_date + timedelta(days=day_offset)
        attack_hour = random.randint(10, 14)   # serangan di jam kerja
        window_mins = random.randint(120, 180)  # durasi 2–3 jam
        volume      = random.randint(200, 400)

        for _ in range(volume):
            # Random timestamp dalam window serangan
            offset_secs = random.randint(0, window_mins * 60)
            ts = day_start.replace(
                hour=attack_hour, minute=0, second=0
            ) + timedelta(seconds=offset_secs)

            # Fokus ke target aset, sesekali ke aset lain (lateral movement)
            asset = (
                random.choice(self.target_assets)
                if random.random() < 0.85
                else self._get_asset()
            )

            rule_id = random.choices(rule_ids, weights=weights, k=1)[0]

            events.append(
                self._build_alert_event(
                    asset=asset,
                    rule_id=rule_id,
                    timestamp=ts,
                )
            )
        return events

    def _generate_normal_day_tail(self, day_offset: int) -> list[dict]:
        """Aktivitas sore hari setelah serangan (post-attack quiet)."""
        events = []
        rule_ids = list(BACKGROUND_RULE_WEIGHTS.keys())
        weights  = list(BACKGROUND_RULE_WEIGHTS.values())
        day_start = self.start_date + timedelta(days=day_offset)

        for _ in range(30):
            ts = day_start.replace(
                hour=random.randint(17, 21),
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )
            events.append(
                self._build_alert_event(
                    asset=self._get_asset(),
                    rule_id=random.choices(rule_ids, weights=weights, k=1)[0],
                    timestamp=ts,
                )
            )
        return events

    def _generate_aftermath_day(self, day_offset: int) -> list[dict]:
        """
        Hari setelah insiden: masih ada residual anomali dari target aset, tapi volume sudah jauh berkurang.
        """
        events = []
        day_start = self.start_date + timedelta(days=day_offset)

        # Sisa anomali — severity masih agak tinggi tapi volume kecil
        residual_rules  = ["5503", "40112", "5552", "40113"]
        residual_volume = random.randint(20, 50)

        for _ in range(residual_volume):
            ts = day_start.replace(
                hour=random.randint(8, 18),
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
            )
            asset = (
                random.choice(self.target_assets)
                if random.random() < 0.7
                else self._get_asset()
            )
            events.append(
                self._build_alert_event(
                    asset=asset,
                    rule_id=random.choice(residual_rules),
                    timestamp=ts,
                )
            )

        # Aktivitas normal latar belakang
        events.extend(self._generate_normal_day(day_offset=day_offset, volume=60))
        return events