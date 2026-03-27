"""Pure scoring logic for I, V, T, and R calculation."""

from __future__ import annotations

from typing import Iterable


ALERT_WEIGHTS = {
    "low": {"range": range(1, 5), "weight": 1},
    "medium": {"range": range(5, 8), "weight": 5},
    "high": {"range": range(8, 12), "weight": 10},
    "critical": {"range": range(12, 16), "weight": 25},
}


def calculate_v(sca_score: float) -> float:
    """Calculate vulnerability score V from SCA pass percentage."""
    sca = max(0.0, min(100.0, sca_score))
    return round(100.0 - sca, 2)


def calculate_t(alerts: Iterable[dict], t_previous: float, decay: float = 0.5) -> float:
    """Calculate time-decayed threat score T."""
    if not 0.0 <= decay <= 1.0:
        raise ValueError("decay must be between 0 and 1")

    t_new = 0.0
    for alert in alerts:
        level = int(alert.get("level", 0))
        for tier in ALERT_WEIGHTS.values():
            if level in tier["range"]:
                t_new += tier["weight"]
                break

    t_new = min(t_new, 100.0)
    t_now = t_new + (max(0.0, t_previous) * decay)
    return round(min(t_now, 100.0), 2)


def calculate_r(
    impact_i: float,
    vulnerability_v: float,
    threat_t: float,
    w1: float = 0.3,
    w2: float = 0.7,
) -> float:
    """Calculate final risk score R = I x (w1 x V + w2 x T)."""
    if abs((w1 + w2) - 1.0) > 1e-6:
        raise ValueError("w1 + w2 must equal 1.0")

    i = max(0.0, min(1.0, impact_i))
    v = max(0.0, min(100.0, vulnerability_v))
    t = max(0.0, min(100.0, threat_t))

    return round(min(i * ((w1 * v) + (w2 * t)), 100.0), 2)


def classify_severity(score_r: float) -> str:
    """Map risk score into CVSS-adapted severity label."""
    score = max(0.0, min(100.0, score_r))
    if score < 40:
        return "Low"
    if score < 70:
        return "Medium"
    if score < 90:
        return "High"
    return "Critical"
