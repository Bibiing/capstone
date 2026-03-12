"""
Skenario 1: Aktivitas harian normal tanpa anomali.

Karakteristik:
- Volume  : 60-120 events/hari, terdistribusi merata sepanjang jam kerja
- Severity: mayoritas 1-6 (informational/low), sesekali medium (7-9)
- Category: didominasi auth (login success/fail biasa)
- Tujuan  : membangun baseline risk score yang rendah (~10-30)
"""

import random
from datetime import datetime, timedelta, timezone

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from base_generator import BaseGenerator
from constants import SCENARIO_NORMAL


# Rule yang muncul di hari normal beserta bobotnya (weight = probabilitas relatif)
NORMAL_RULE_WEIGHTS = {
    "5501": 40,   # Login success     — sangat sering
    "5502": 20,   # Login failed      — sesekali salah password
    "554":  15,   # File added        — update/deploy rutin
    "550":  10,   # Integrity changed — patch/config change
    "551":   5,   # File deleted      — cleanup rutin
    "40111": 7,   # Firewall block    — traffic umum
    "5710":  3,   # Non-existent user — typo username
}


class NormalScenario(BaseGenerator):

    scenario_name = SCENARIO_NORMAL

    def __init__(
        self,
        start_date: datetime | None = None,
        days: int = 7,
        seed: int = 42,
    ):
        super().__init__(seed=seed)
        # Default: 7 hari ke belakang dari sekarang
        self.start_date = start_date or (
            datetime.now(tz=timezone.utc) - timedelta(days=days)
        )
        self.days = days

    def generate_events(self) -> list[dict]:
        events: list[dict] = []

        rule_ids = list(NORMAL_RULE_WEIGHTS.keys())
        weights  = list(NORMAL_RULE_WEIGHTS.values())

        for day_offset in range(self.days):
            day_start = self.start_date + timedelta(days=day_offset)

            # Volume harian sedikit bervariasi — lebih realistis
            daily_volume = random.randint(60, 120)

            for _ in range(daily_volume):
                # Distribusi jam kerja: puncak di 08:00–17:00 WIB
                hour   = self._weighted_hour()
                minute = random.randint(0, 59)
                second = random.randint(0, 59)

                ts = day_start.replace(
                    hour=hour, minute=minute, second=second,
                )

                asset   = self._get_asset()
                rule_id = random.choices(rule_ids, weights=weights, k=1)[0]

                events.append(
                    self._build_alert_event(
                        asset=asset,
                        rule_id=rule_id,
                        timestamp=ts,
                    )
                )

        # Sort kronologis
        events.sort(key=lambda e: e["timestamp"])
        return events

    @staticmethod
    def _weighted_hour() -> int:
        """
        Distribusi jam:
        - 07:00–08:00 : mulai masuk kantor
        - 08:00–17:00 : jam kerja utama (bobot tinggi)
        - 17:00–20:00 : lembur tipis
        - 20:00–07:00 : sangat sepi (maintenance/batch job)
        """
        hour_weights = {
            0: 1, 1: 1, 2: 2, 3: 2, 4: 1, 5: 1,
            6: 2, 7: 5, 8: 10, 9: 12, 10: 12, 11: 11,
            12: 8, 13: 11, 14: 12, 15: 12, 16: 10,
            17: 7, 18: 5, 19: 4, 20: 3, 21: 2, 22: 2, 23: 1,
        }
        hours   = list(hour_weights.keys())
        weights = list(hour_weights.values())
        return random.choices(hours, weights=weights, k=1)[0]