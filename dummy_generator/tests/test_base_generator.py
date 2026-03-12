from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime, timezone

import pytest

# Path setup
GENERATOR_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(GENERATOR_DIR))
sys.path.insert(0, str(GENERATOR_DIR / "scenarios"))

from base_generator import BaseGenerator
from constants import (
    RULES,
    CVE_CATALOG,
    VALID_CATEGORIES,
    VALID_EVENT_TYPES,
    SCENARIO_NORMAL,
    SCENARIO_SPIKE,
    SCENARIO_VULN,
    SCENARIO_DECAY,
)
from scenarios.normal import NormalScenario
from scenarios.spike import SpikeScenario
from scenarios.vuln import VulnClusterScenario
from scenarios.decay import DecayScenario

# Konstanta Data Contract (ground truth)
CONTRACT_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"timestamp", "asset_id", "severity", "category", "event_type"}
)
CONTRACT_VALID_CATEGORIES: frozenset[str] = frozenset(
    {"auth", "malware", "integrity", "network"}
)
CONTRACT_VALID_EVENT_TYPES: frozenset[str] = frozenset(
    {"alert", "vuln", "control"}
)
SEVERITY_MIN = 1
SEVERITY_MAX = 15

# Seed deterministik agar test reproducible
SEED = 42


# Fixture — generate events sekali per skenario dan cache di sesi
@pytest.fixture(scope="session")
def normal_events() -> list[dict]:
    return NormalScenario(seed=SEED).generate_events()


@pytest.fixture(scope="session")
def spike_events() -> list[dict]:
    return SpikeScenario(seed=SEED).generate_events()


@pytest.fixture(scope="session")
def vuln_events() -> list[dict]:
    return VulnClusterScenario(seed=SEED).generate_events()


@pytest.fixture(scope="session")
def decay_events() -> list[dict]:
    return DecayScenario(seed=SEED).generate_events()


@pytest.fixture(scope="session")
def all_events(normal_events, spike_events, vuln_events, decay_events) -> list[dict]:
    return normal_events + spike_events + vuln_events + decay_events


# 1. TestDataContract — invariant
class TestDataContract:
    """
    Kelompok test ini memastikan TIDAK ADA SATU PUN event yang dihasilkan
    generator melanggar Data Contract. Test bersifat parameterisasi atas
    seluruh kombinasi skenario sehingga pelanggaran pada satu skenario
    menyebabkan satu test gagal — bukan seluruh suite.
    """

    @pytest.mark.parametrize("scenario_name,fixture_name", [
        ("normal",            "normal_events"),
        ("spike",             "spike_events"),
        ("vuln_cluster",      "vuln_events"),
        ("remediation_decay", "decay_events"),
    ])
    def test_required_fields_present(
        self, scenario_name: str, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """Setiap event harus memiliki semua field wajib Data Contract."""
        events: list[dict] = request.getfixturevalue(fixture_name)
        assert events, f"Skenario '{scenario_name}' tidak menghasilkan event apapun."

        for i, ev in enumerate(events):
            missing = CONTRACT_REQUIRED_FIELDS - ev.keys()
            assert not missing, (
                f"[{scenario_name}] Event[{i}] kekurangan field wajib: {missing!r}\n"
                f"Event: {ev}"
            )

    @pytest.mark.parametrize("scenario_name,fixture_name", [
        ("normal",            "normal_events"),
        ("spike",             "spike_events"),
        ("vuln_cluster",      "vuln_events"),
        ("remediation_decay", "decay_events"),
    ])
    def test_severity_within_bounds(
        self, scenario_name: str, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """
        Severity HARUS berupa integer dalam rentang [1, 15] tanpa pengecualian.

        Ini adalah invariant paling kritis: nilai di luar rentang ini akan
        menyebabkan constraint violation di tabel PostgreSQL dan merusak
        kalkulasi risk score.
        """
        events: list[dict] = request.getfixturevalue(fixture_name)

        violations: list[str] = []
        for i, ev in enumerate(events):
            sev = ev.get("severity")
            # Cek tipe (bool adalah subclass int di Python tolak juga)
            if not isinstance(sev, int) or isinstance(sev, bool):
                violations.append(
                    f"Event[{i}]: severity bukan integer (type={type(sev).__name__}, val={sev!r})"
                )
            elif not (SEVERITY_MIN <= sev <= SEVERITY_MAX):
                violations.append(
                    f"Event[{i}]: severity={sev} di luar batas [{SEVERITY_MIN}, {SEVERITY_MAX}]"
                )

        assert not violations, (
            f"[{scenario_name}] Ditemukan {len(violations)} pelanggaran severity:\n"
            + "\n".join(violations[:10])
        )

    @pytest.mark.parametrize("scenario_name,fixture_name", [
        ("normal",            "normal_events"),
        ("spike",             "spike_events"),
        ("vuln_cluster",      "vuln_events"),
        ("remediation_decay", "decay_events"),
    ])
    def test_category_is_valid(
        self, scenario_name: str, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """
        Field 'category' harus berupa salah satu dari nilai yang diizinkan.
        Nilai 'vulnerability' adalah pelanggaran yang pernah terjadi —
        dijaga agar tidak terulang.
        """
        events: list[dict] = request.getfixturevalue(fixture_name)

        invalid: list[str] = []
        for i, ev in enumerate(events):
            cat = ev.get("category")
            if cat not in CONTRACT_VALID_CATEGORIES:
                invalid.append(f"Event[{i}]: category={cat!r}")

        assert not invalid, (
            f"[{scenario_name}] Ditemukan {len(invalid)} category tidak valid "
            f"(diizinkan: {sorted(CONTRACT_VALID_CATEGORIES)}):\n"
            + "\n".join(invalid[:10])
        )

    @pytest.mark.parametrize("scenario_name,fixture_name", [
        ("normal",            "normal_events"),
        ("spike",             "spike_events"),
        ("vuln_cluster",      "vuln_events"),
        ("remediation_decay", "decay_events"),
    ])
    def test_event_type_is_valid(
        self, scenario_name: str, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """Field 'event_type' harus salah satu dari {'alert', 'vuln', 'control'}."""
        events: list[dict] = request.getfixturevalue(fixture_name)

        invalid: list[str] = []
        for i, ev in enumerate(events):
            et = ev.get("event_type")
            if et not in CONTRACT_VALID_EVENT_TYPES:
                invalid.append(f"Event[{i}]: event_type={et!r}")

        assert not invalid, (
            f"[{scenario_name}] Ditemukan {len(invalid)} event_type tidak valid "
            f"(diizinkan: {sorted(CONTRACT_VALID_EVENT_TYPES)}):\n"
            + "\n".join(invalid[:10])
        )

    @pytest.mark.parametrize("scenario_name,fixture_name", [
        ("normal",            "normal_events"),
        ("spike",             "spike_events"),
        ("vuln_cluster",      "vuln_events"),
        ("remediation_decay", "decay_events"),
    ])
    def test_timestamp_parseable(
        self, scenario_name: str, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """Field 'timestamp' harus berupa string ISO-8601 yang valid."""
        events: list[dict] = request.getfixturevalue(fixture_name)

        invalid: list[str] = []
        for i, ev in enumerate(events):
            ts = ev.get("timestamp")
            if not isinstance(ts, str):
                invalid.append(f"Event[{i}]: timestamp bukan string ({type(ts).__name__})")
                continue
            try:
                datetime.fromisoformat(ts)
            except ValueError:
                invalid.append(f"Event[{i}]: timestamp tidak valid ({ts!r})")

        assert not invalid, (
            f"[{scenario_name}] Ditemukan {len(invalid)} timestamp tidak valid:\n"
            + "\n".join(invalid[:10])
        )

    @pytest.mark.parametrize("scenario_name,fixture_name", [
        ("normal",            "normal_events"),
        ("spike",             "spike_events"),
        ("vuln_cluster",      "vuln_events"),
        ("remediation_decay", "decay_events"),
    ])
    def test_asset_id_not_empty(
        self, scenario_name: str, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        """Field 'asset_id' harus berupa string non-kosong."""
        events: list[dict] = request.getfixturevalue(fixture_name)

        invalid: list[str] = []
        for i, ev in enumerate(events):
            aid = ev.get("asset_id")
            if not isinstance(aid, str) or not aid.strip():
                invalid.append(f"Event[{i}]: asset_id={aid!r}")

        assert not invalid, (
            f"[{scenario_name}] Ditemukan {len(invalid)} asset_id kosong/None:\n"
            + "\n".join(invalid[:10])
        )


# 2. TestBaseGeneratorUtility — unit test helper internal BaseGenerator
class TestBaseGeneratorUtility:
    """Test yang menarget metode utilitas di BaseGenerator secara langsung."""

    @pytest.fixture(scope="class")
    def gen(self) -> NormalScenario:
        """NormalScenario dipakai sebagai representasi konkret BaseGenerator."""
        return NormalScenario(seed=SEED)

    def test_load_assets_returns_list(self, gen: NormalScenario) -> None:
        """_load_assets harus mengembalikan list non-kosong."""
        assert isinstance(gen.assets, list)
        assert len(gen.assets) > 0

    def test_load_assets_have_required_keys(self, gen: NormalScenario) -> None:
        """Setiap asset harus memiliki key yang dibutuhkan generator."""
        required_keys = {"asset_id", "hostname", "asset_type", "criticality"}
        for asset in gen.assets:
            missing = required_keys - asset.keys()
            assert not missing, f"Asset kekurangan key: {missing!r} — asset={asset}"

    def test_get_asset_random_returns_valid(self, gen: NormalScenario) -> None:
        """_get_asset(None) harus mengembalikan asset dari daftar yang ada."""
        asset = gen._get_asset()
        assert asset in gen.assets

    def test_get_asset_by_id(self, gen: NormalScenario) -> None:
        """_get_asset(id) harus mengembalikan asset dengan id yang persis."""
        target_id = gen.assets[0]["asset_id"]
        result    = gen._get_asset(target_id)
        assert result["asset_id"] == target_id

    def test_get_assets_by_criticality(self, gen: NormalScenario) -> None:
        """_get_assets_by_criticality harus memfilter dengan benar."""
        critical = gen._get_assets_by_criticality("critical")
        for asset in critical:
            assert asset["criticality"] == "critical"

    def test_build_alert_event_severity_in_bounds(self, gen: NormalScenario) -> None:
        """
        _build_alert_event harus menghasilkan severity dalam [1, 15]
        untuk semua rule_id yang ada di catalog.
        """
        asset = gen.assets[0]
        ts    = datetime.now(tz=timezone.utc)
        for rule_id in RULES:
            ev = gen._build_alert_event(asset=asset, rule_id=rule_id, timestamp=ts)
            sev = ev["severity"]
            assert SEVERITY_MIN <= sev <= SEVERITY_MAX, (
                f"rule_id={rule_id}: severity={sev} di luar batas"
            )

    def test_build_alert_event_override_severity(self, gen: NormalScenario) -> None:
        """override_severity harus menggantikan severity bawaan rule."""
        asset    = gen.assets[0]
        ts       = datetime.now(tz=timezone.utc)
        override = 7
        ev = gen._build_alert_event(
            asset=asset,
            rule_id="5501",
            timestamp=ts,
            override_severity=override,
        )
        assert ev["severity"] == override

    def test_build_alert_event_category_valid(self, gen: NormalScenario) -> None:
        """_build_alert_event harus menghasilkan category yang valid."""
        asset = gen.assets[0]
        ts    = datetime.now(tz=timezone.utc)
        for rule_id in RULES:
            ev = gen._build_alert_event(asset=asset, rule_id=rule_id, timestamp=ts)
            assert ev["category"] in CONTRACT_VALID_CATEGORIES, (
                f"rule_id={rule_id}: category={ev['category']!r} tidak valid"
            )

    def test_build_vuln_event_from_cvss(self, gen: NormalScenario) -> None:
        """
        _build_vuln_event harus memetakan CVSS ke severity dengan benar
        dan event_type harus selalu 'vuln'.
        """
        asset = gen.assets[0]
        ts    = datetime.now(tz=timezone.utc)

        test_cases = [
            ({"cve_id": "CVE-test-1", "cvss_score": 9.8,  "product": "X"}, 15),
            ({"cve_id": "CVE-test-2", "cvss_score": 7.5,  "product": "Y"}, 12),
            ({"cve_id": "CVE-test-3", "cvss_score": 5.0,  "product": "Z"},  8),
            ({"cve_id": "CVE-test-4", "cvss_score": 2.0,  "product": "W"},  4),
        ]
        for cve, expected_sev in test_cases:
            ev = gen._build_vuln_event(asset=asset, cve=cve, timestamp=ts)
            assert ev["event_type"] == "vuln", (
                f"CVSS={cve['cvss_score']}: event_type harus 'vuln', dapat {ev['event_type']!r}"
            )
            assert ev["severity"] == expected_sev, (
                f"CVSS={cve['cvss_score']}: severity harus {expected_sev}, dapat {ev['severity']}"
            )
            assert ev["category"] in CONTRACT_VALID_CATEGORIES, (
                f"CVSS={cve['cvss_score']}: category={ev['category']!r} tidak valid"
            )

    def test_build_vuln_event_severity_in_bounds(self, gen: NormalScenario) -> None:
        """Semua CVE di catalog harus menghasilkan severity dalam [1, 15]."""
        asset = gen.assets[0]
        ts    = datetime.now(tz=timezone.utc)
        for cve in CVE_CATALOG:
            ev = gen._build_vuln_event(asset=asset, cve=cve, timestamp=ts)
            sev = ev["severity"]
            assert SEVERITY_MIN <= sev <= SEVERITY_MAX, (
                f"{cve['cve_id']}: severity={sev} di luar batas"
            )

    def test_scenario_name_property(self) -> None:
        """scenario_name harus mengembalikan label yang benar per kelas."""
        assert NormalScenario(seed=SEED).scenario_name == SCENARIO_NORMAL
        assert SpikeScenario(seed=SEED).scenario_name  == SCENARIO_SPIKE
        assert VulnClusterScenario(seed=SEED).scenario_name == SCENARIO_VULN
        assert DecayScenario(seed=SEED).scenario_name  == SCENARIO_DECAY


# 3. TestNormalScenario — karakteristik khusus skenario Normal
class TestNormalScenario:

    def test_produces_events(self, normal_events: list[dict]) -> None:
        assert len(normal_events) > 0

    def test_events_sorted_by_timestamp(self, normal_events: list[dict]) -> None:
        """Events harus diurut kronologis (kontrak implisit generator)."""
        timestamps = [ev["timestamp"] for ev in normal_events]
        assert timestamps == sorted(timestamps), (
            "Events normal tidak terurut secara kronologis"
        )

    def test_no_high_severity_dominance(self, normal_events: list[dict]) -> None:
        """
        Pada skenario normal, events severity tinggi (>=11) tidak boleh
        mendominasi — harus di bawah 20% dari total.
        """
        high_count = sum(1 for ev in normal_events if ev["severity"] >= 11)
        ratio = high_count / len(normal_events)
        assert ratio < 0.20, (
            f"Skenario Normal: {ratio:.1%} events severity >=11 "
            f"(maks 20% diizinkan) — tidak mencerminkan aktivitas normal"
        )

    def test_auth_category_dominant(self, normal_events: list[dict]) -> None:
        """
        Auth harus menjadi kategori terbanyak di skenario normal
        (mencerminkan aktivitas login harian).
        """
        from collections import Counter
        cat_counts = Counter(ev["category"] for ev in normal_events)
        auth_count = cat_counts.get("auth", 0)
        max_count  = max(cat_counts.values())
        assert auth_count == max_count, (
            f"Skenario Normal: 'auth' ({auth_count}) bukan kategori terbanyak "
            f"(terbanyak: {cat_counts.most_common(1)[0]})"
        )

    def test_no_vuln_events_in_normal(self, normal_events: list[dict]) -> None:
        """Skenario normal tidak boleh mengandung event_type 'vuln'."""
        vuln_count = sum(1 for ev in normal_events if ev["event_type"] == "vuln")
        assert vuln_count == 0, (
            f"Skenario Normal mengandung {vuln_count} event bertipe 'vuln'"
        )

    def test_scenario_label(self, normal_events: list[dict]) -> None:
        """Semua event harus berlabel skenario yang benar."""
        wrong = [ev for ev in normal_events if ev.get("scenario") != SCENARIO_NORMAL]
        assert not wrong, f"{len(wrong)} event berlabel skenario salah"


# 4. TestSpikeScenario — karakteristik khusus skenario Spike
class TestSpikeScenario:

    def test_produces_events(self, spike_events: list[dict]) -> None:
        assert len(spike_events) > 0

    def test_high_severity_events_present(self, spike_events: list[dict]) -> None:
        """
        Skenario spike harus mengandung events severity tinggi (>=10)
        dalam jumlah yang signifikan (>30% dari total).
        """
        high_count = sum(1 for ev in spike_events if ev["severity"] >= 10)
        ratio      = high_count / len(spike_events)
        assert ratio > 0.30, (
            f"Skenario Spike: hanya {ratio:.1%} events severity >=10 "
            f"(minimal 30% diperlukan untuk mencerminkan insiden)"
        )

    def test_spike_day_has_more_events_than_baseline(
        self, spike_events: list[dict]
    ) -> None:
        """
        Hari spike harus memiliki volume signifikan lebih banyak dari
        hari baseline (normal). Rasio minimal 2:1.
        """
        from collections import Counter

        day_counts = Counter(
            datetime.fromisoformat(ev["timestamp"]).date()
            for ev in spike_events
        )
        if len(day_counts) < 2:
            pytest.skip("Tidak cukup hari untuk membandingkan spike vs baseline")

        days_sorted = sorted(day_counts.keys())
        baseline_day = days_sorted[0]
        # Hari dengan volume tertinggi harus > 2x hari pertama
        max_day_count  = max(day_counts.values())
        baseline_count = day_counts[baseline_day]
        ratio = max_day_count / max(baseline_count, 1)

        assert ratio >= 2.0, (
            f"Skenario Spike: rasio volume hari-sibuk/baseline={ratio:.1f}x "
            f"(minimal 2x). Detail: {dict(day_counts)}"
        )

    def test_scenario_label(self, spike_events: list[dict]) -> None:
        wrong = [ev for ev in spike_events if ev.get("scenario") != SCENARIO_SPIKE]
        assert not wrong, f"{len(wrong)} event berlabel skenario salah"


# 5. TestVulnClusterScenario — karakteristik khusus skenario Vuln Cluster
class TestVulnClusterScenario:

    def test_produces_events(self, vuln_events: list[dict]) -> None:
        assert len(vuln_events) > 0

    def test_contains_vuln_event_type(self, vuln_events: list[dict]) -> None:
        """
        Skenario vuln_cluster HARUS mengandung events bertipe 'vuln'
        sebagai inti dari skenario ini.
        """
        vuln_count = sum(1 for ev in vuln_events if ev["event_type"] == "vuln")
        assert vuln_count > 0, (
            "Skenario VulnCluster tidak menghasilkan SATU PUN event bertipe 'vuln'"
        )

    def test_vuln_concentrated_on_few_assets(self, vuln_events: list[dict]) -> None:
        """
        Vuln events harus terkonsentrasi pada subset kecil aset
        (definisi 'cluster'). Kurang dari 50% aset yang dikenal
        boleh memiliki vuln events.
        """
        from collections import Counter

        gen             = VulnClusterScenario(seed=SEED)
        total_assets    = len(gen.assets)
        vuln_only       = [ev for ev in vuln_events if ev["event_type"] == "vuln"]
        assets_with_vuln = len(set(ev["asset_id"] for ev in vuln_only))

        ratio = assets_with_vuln / total_assets
        assert ratio < 0.50, (
            f"Skenario VulnCluster: vuln tersebar di {assets_with_vuln}/{total_assets} "
            f"aset ({ratio:.0%}). Seharusnya terkonsentrasi (<50% aset)."
        )

    def test_vuln_events_have_cve_id(self, vuln_events: list[dict]) -> None:
        """Setiap event bertipe 'vuln' harus memiliki cve_id yang terisi."""
        missing_cve = [
            ev for ev in vuln_events
            if ev["event_type"] == "vuln" and not ev.get("cve_id")
        ]
        assert not missing_cve, (
            f"{len(missing_cve)} vuln events tidak memiliki cve_id"
        )

    def test_scenario_label(self, vuln_events: list[dict]) -> None:
        wrong = [ev for ev in vuln_events if ev.get("scenario") != SCENARIO_VULN]
        assert not wrong, f"{len(wrong)} event berlabel skenario salah"


# 6. TestDecayScenario — karakteristik khusus skenario Decay
class TestDecayScenario:

    def test_produces_events(self, decay_events: list[dict]) -> None:
        assert len(decay_events) > 0

    def test_volume_decreases_over_time(self, decay_events: list[dict]) -> None:
        """
        Volume harian harus menurun secara keseluruhan dari hari pertama
        ke hari terakhir skenario.
        """
        from collections import Counter

        day_counts = Counter(
            datetime.fromisoformat(ev["timestamp"]).date()
            for ev in decay_events
        )
        days = sorted(day_counts.keys())
        assert len(days) >= 2, "Decay scenario harus mencakup minimal 2 hari"

        # Hari pertama harus lebih ramai dari hari terakhir
        first_day_count = day_counts[days[0]]
        last_day_count  = day_counts[days[-1]]
        assert first_day_count > last_day_count, (
            f"Skenario Decay: volume hari pertama ({first_day_count}) "
            f"tidak lebih besar dari hari terakhir ({last_day_count})"
        )

    def test_avg_severity_decreases_over_time(self, decay_events: list[dict]) -> None:
        """
        Rata-rata severity per hari harus menunjukkan tren menurun —
        ini adalah sinyal utama skenario decay/remediasi berhasil.
        """
        from collections import defaultdict

        day_severities: dict = defaultdict(list)
        for ev in decay_events:
            day = datetime.fromisoformat(ev["timestamp"]).date()
            day_severities[day].append(ev["severity"])

        days   = sorted(day_severities.keys())
        avgs   = [
            sum(day_severities[d]) / len(day_severities[d])
            for d in days
        ]

        assert len(avgs) >= 3, "Perlu minimal 3 hari untuk validasi tren decay"

        # Hari pertama harus lebih tinggi dari hari terakhir
        assert avgs[0] > avgs[-1], (
            f"Skenario Decay: avg severity hari 0 ({avgs[0]:.2f}) "
            f"tidak lebih tinggi dari hari terakhir ({avgs[-1]:.2f}). "
            f"Tren: {[round(a, 2) for a in avgs]}"
        )

    def test_last_day_matches_normal_baseline(self, decay_events: list[dict]) -> None:
        """
        Hari terakhir (setelah remediasi penuh) harus memiliki severity
        rendah (avg < 6), mencerminkan kembali ke kondisi normal.
        """
        from collections import defaultdict

        day_severities: dict = defaultdict(list)
        for ev in decay_events:
            day = datetime.fromisoformat(ev["timestamp"]).date()
            day_severities[day].append(ev["severity"])

        last_day   = max(day_severities.keys())
        last_avg   = sum(day_severities[last_day]) / len(day_severities[last_day])
        assert last_avg < 6.0, (
            f"Skenario Decay: avg severity hari terakhir {last_avg:.2f} >= 6.0 "
            f"— belum mencerminkan kondisi normal setelah remediasi"
        )

    def test_scenario_label(self, decay_events: list[dict]) -> None:
        wrong = [ev for ev in decay_events if ev.get("scenario") != SCENARIO_DECAY]
        assert not wrong, f"{len(wrong)} event berlabel skenario salah"


# 7. TestSchemaConsistency — validasi catalog di constants.py itu sendiri
class TestSchemaConsistency:
    """
    Test untuk memastikan RULES catalog di constants.py konsisten
    dengan Data Contract. Ini mencegah bug seperti category='vulnerability'
    yang pernah terjadi.
    """

    def test_all_rules_have_required_keys(self) -> None:
        """Setiap entri RULES harus memiliki key yang dibutuhkan."""
        required = {"description", "severity", "category", "event_type"}
        for rule_id, rule in RULES.items():
            missing = required - rule.keys()
            assert not missing, (
                f"Rule '{rule_id}' kekurangan key: {missing!r}"
            )

    def test_all_rule_severities_in_bounds(self) -> None:
        """Semua severity di RULES catalog harus dalam [1, 15]."""
        for rule_id, rule in RULES.items():
            sev = rule["severity"]
            assert isinstance(sev, int) and not isinstance(sev, bool), (
                f"Rule '{rule_id}': severity bukan integer ({type(sev).__name__})"
            )
            assert SEVERITY_MIN <= sev <= SEVERITY_MAX, (
                f"Rule '{rule_id}': severity={sev} di luar batas [{SEVERITY_MIN}, {SEVERITY_MAX}]"
            )

    def test_all_rule_categories_valid(self) -> None:
        """
        Semua category di RULES catalog harus valid.
        Test ini secara eksplisit menangkap regreñsi 'vulnerability'.
        """
        for rule_id, rule in RULES.items():
            cat = rule["category"]
            assert cat in CONTRACT_VALID_CATEGORIES, (
                f"Rule '{rule_id}': category={cat!r} tidak valid. "
                f"Gunakan salah satu dari {sorted(CONTRACT_VALID_CATEGORIES)}"
            )

    def test_all_rule_event_types_valid(self) -> None:
        """Semua event_type di RULES catalog harus valid."""
        for rule_id, rule in RULES.items():
            et = rule["event_type"]
            assert et in CONTRACT_VALID_EVENT_TYPES, (
                f"Rule '{rule_id}': event_type={et!r} tidak valid. "
                f"Gunakan salah satu dari {sorted(CONTRACT_VALID_EVENT_TYPES)}"
            )

    def test_cve_catalog_has_required_keys(self) -> None:
        """Setiap entri CVE_CATALOG harus memiliki key yang dibutuhkan."""
        required = {"cve_id", "cvss_score", "product"}
        for cve in CVE_CATALOG:
            missing = required - cve.keys()
            assert not missing, f"CVE entry kekurangan key: {missing!r} — {cve}"

    def test_cve_catalog_cvss_in_range(self) -> None:
        """CVSS score harus dalam rentang [0.0, 10.0]."""
        for cve in CVE_CATALOG:
            cvss = cve["cvss_score"]
            assert isinstance(cvss, (int, float)), (
                f"{cve['cve_id']}: cvss_score bukan angka ({type(cvss).__name__})"
            )
            assert 0.0 <= cvss <= 10.0, (
                f"{cve['cve_id']}: cvss_score={cvss} di luar [0.0, 10.0]"
            )
