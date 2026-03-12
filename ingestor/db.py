"""
Data Access Layer (DAL) untuk Wazuh Telemetry Ingestor.

  1. Manajemen koneksi ke PostgreSQL via SQLAlchemy.
  2. Validasi skema event (Data Contract) sebelum insert.
  3. Bulk insert yang efisien menggunakan psycopg2.extras.execute_values.
  4. Penanganan error yang bersih dengan exception bertipe khusus.

Data Contract yang Ditegakkan:
  - timestamp  : string ISO-8601 yang dapat di-parse
  - asset_id   : string non-kosong
  - severity   : integer, 1 ≤ severity ≤ 15
  - category   : salah satu dari {'auth', 'malware', 'integrity', 'network'}
  - event_type : salah satu dari {'alert', 'vuln', 'control'}
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

load_dotenv()

logger = logging.getLogger(__name__)

# Konstanta Data Contract
VALID_CATEGORIES: frozenset[str] = frozenset({"auth", "malware", "integrity", "network"})
VALID_EVENT_TYPES: frozenset[str] = frozenset({"alert", "vuln", "control"})
REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"timestamp", "asset_id", "severity", "category", "event_type"}
)
SEVERITY_MIN = 1
SEVERITY_MAX = 15

# Ukuran batch untuk satu transaksi INSERT; nilai ini menyeimbangkan antara
# overhead koneksi dan ukuran payload per transaksi.
DEFAULT_BATCH_SIZE = 500


# Custom Exception
class SchemaValidationError(ValueError):
    """
    Dilempar ketika satu event melanggar Data Contract.

    Atribut:
        event_index (int)  : posisi event di dalam list input (0-based).
        field       (str)  : nama field yang bermasalah.
        reason      (str)  : penjelasan pelanggaran.
        raw_value   (Any)  : nilai aktual yang diterima.
    """

    def __init__(
        self,
        event_index: int,
        field: str,
        reason: str,
        raw_value: Any = None,
    ) -> None:
        self.event_index = event_index
        self.field       = field
        self.reason      = reason
        self.raw_value   = raw_value
        super().__init__(
            f"Event[{event_index}] — field '{field}': {reason} (got {raw_value!r})"
        )


# Koneksi Database
def build_engine(echo: bool = False) -> Engine:
    """
    Buat SQLAlchemy Engine dari environment variables.

    Variabel yang dibutuhkan (lihat .env.example):
        POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST,
        POSTGRES_PORT, POSTGRES_DB
    """
    user     = os.getenv("POSTGRES_USER", "admin")
    password = os.getenv("POSTGRES_PASSWORD", "admin")
    host     = os.getenv("POSTGRES_HOST", "localhost")
    port     = os.getenv("POSTGRES_PORT", "5432")
    database = os.getenv("POSTGRES_DB", "risk_scoring")

    url = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
    return create_engine(url, pool_pre_ping=True, echo=echo)


def ping(engine: Engine) -> str:
    """Uji koneksi dan kembalikan versi PostgreSQL sebagai string."""
    with engine.connect() as conn:
        row = conn.execute(text("SELECT version()")).fetchone()
        return row[0]


# Validasi Event (Data Contract)
def _validate_one(index: int, event: dict) -> None:
    """
    Validasi satu event dict terhadap Data Contract.
    Melempar SchemaValidationError pada pelanggaran pertama yang ditemukan.

    Urutan pengecekan disesuaikan dengan kritisitas field:
      1. Field wajib ada (presence check)
      2. Tipe data
      3. Rentang / nilai yang diizinkan
    """
    #  1. Presence check 
    missing = REQUIRED_FIELDS - event.keys()
    if missing:
        raise SchemaValidationError(
            index, str(missing), "field wajib tidak ada", None
        )

    #  2. timestamp: harus string ISO-8601 yang valid 
    ts = event["timestamp"]
    if not isinstance(ts, str):
        raise SchemaValidationError(
            index, "timestamp", "harus berupa string ISO-8601", ts
        )
    try:
        datetime.fromisoformat(ts)
    except ValueError:
        raise SchemaValidationError(
            index, "timestamp", "format ISO-8601 tidak valid", ts
        )

    #  3. asset_id: string non-kosong 
    asset_id = event["asset_id"]
    if not isinstance(asset_id, str) or not asset_id.strip():
        raise SchemaValidationError(
            index, "asset_id", "harus berupa string non-kosong", asset_id
        )

    #  4. severity: integer dalam rentang [1, 15] 
    severity = event["severity"]
    if not isinstance(severity, int) or isinstance(severity, bool):
        raise SchemaValidationError(
            index, "severity", "harus berupa integer", severity
        )
    if not (SEVERITY_MIN <= severity <= SEVERITY_MAX):
        raise SchemaValidationError(
            index,
            "severity",
            f"harus berada dalam rentang [{SEVERITY_MIN}, {SEVERITY_MAX}]",
            severity,
        )

    #  5. category: nilai yang diizinkan 
    category = event["category"]
    if category not in VALID_CATEGORIES:
        raise SchemaValidationError(
            index,
            "category",
            f"harus salah satu dari {sorted(VALID_CATEGORIES)}",
            category,
        )

    #  6. event_type: nilai yang diizinkan 
    event_type = event["event_type"]
    if event_type not in VALID_EVENT_TYPES:
        raise SchemaValidationError(
            index,
            "event_type",
            f"harus salah satu dari {sorted(VALID_EVENT_TYPES)}",
            event_type,
        )


def validate_events(
    events: list[dict],
) -> tuple[list[dict], list[SchemaValidationError]]:
    """
    Validasi seluruh list event terhadap Data Contract.

    Tidak berhenti pada pelanggaran pertama — seluruh list diproses
    sehingga semua error dapat dilaporkan sekaligus.

    Returns:
        valid_events  : list event yang lolos validasi, siap di-insert.
        errors        : list SchemaValidationError untuk event yang gagal.
    """
    valid: list[dict]               = []
    errors: list[SchemaValidationError] = []

    for i, event in enumerate(events):
        try:
            _validate_one(i, event)
            valid.append(event)
        except SchemaValidationError as exc:
            errors.append(exc)

    return valid, errors


# Bulk Insert — Events
# Kolom yang di-insert ke tabel wazuh_events (urutan harus konsisten).
_EVENT_COLUMNS = (
    "event_id", "timestamp", "asset_id", "hostname",
    "severity", "category", "event_type",
    "rule_id", "rule_description",
    "cve_id", "cvss_score", "scenario",
)

# Template VALUES untuk psycopg2.extras.execute_values
_EVENT_VALUES_TEMPLATE = "(" + ", ".join(["%s"] * len(_EVENT_COLUMNS)) + ")"

_INSERT_SQL = f"""
    INSERT INTO wazuh_events ({", ".join(_EVENT_COLUMNS)})
    VALUES %s
    ON CONFLICT DO NOTHING
"""


def _event_to_row(event: dict) -> tuple:
    """Konversi event dict ke tuple berurutan sesuai _EVENT_COLUMNS."""
    return (
        event.get("event_id"),
        event["timestamp"],
        event["asset_id"],
        event.get("hostname"),
        event["severity"],
        event["category"],
        event["event_type"],
        event.get("rule_id"),
        event.get("rule_description"),
        event.get("cve_id"),
        event.get("cvss_score"),
        event.get("scenario"),
    )


def bulk_insert_events(
    engine: Engine,
    events: list[dict],
    batch_size: int = DEFAULT_BATCH_SIZE,
    *,
    skip_validation: bool = False,
) -> dict[str, Any]:
    """
    Insert event ke PostgreSQL secara efisien menggunakan
    psycopg2.extras.execute_values (jauh lebih cepat dari executemany
    karena mengirimkan seluruh batch dalam satu round-trip ke server).

    Args:
        engine          : SQLAlchemy Engine yang sudah terkonfigurasi.
        events          : list event dict yang akan di-insert.
        batch_size      : jumlah row per transaksi.
        skip_validation : jika True, lewati validasi skema (HANYA untuk
                          data yang sudah terbukti bersih).

    Returns:
        dict berisi kunci:
            'total'         : jumlah event input
            'inserted'      : jumlah row yang berhasil di-insert
            'skipped_invalid': jumlah event yang dibuang karena skema rusak
            'errors'        : list pesan error validasi (jika ada)
    """
    if not events:
        return {"total": 0, "inserted": 0, "skipped_invalid": 0, "errors": []}

    #  Validasi Skema 
    if skip_validation:
        valid_events = events
        schema_errors: list[SchemaValidationError] = []
    else:
        valid_events, schema_errors = validate_events(events)
        if schema_errors:
            logger.warning(
                "%d dari %d event dibuang karena melanggar Data Contract.",
                len(schema_errors),
                len(events),
            )
            for err in schema_errors:
                logger.warning("  Skema rusak: %s", err)

    if not valid_events:
        logger.error("Tidak ada event valid untuk di-insert.")
        return {
            "total": len(events),
            "inserted": 0,
            "skipped_invalid": len(schema_errors),
            "errors": [str(e) for e in schema_errors],
        }

    # Bulk Insert Per Batch 
    # Kita ambil raw psycopg2 connection dari SQLAlchemy agar bisa
    # menggunakan execute_values yang tidak tersedia di SQLAlchemy secara
    # langsung tanpa ekstensi tambahan.
    inserted_total = 0
    rows = [_event_to_row(ev) for ev in valid_events]

    try:
        from psycopg2.extras import execute_values  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "psycopg2-binary dibutuhkan untuk bulk insert. "
            "Jalankan: pip install psycopg2-binary"
        ) from exc

    with engine.connect() as sa_conn:
        raw_conn = sa_conn.connection
        cursor   = raw_conn.cursor()
        try:
            for batch_start in range(0, len(rows), batch_size):
                batch = rows[batch_start : batch_start + batch_size]
                execute_values(
                    cursor,
                    _INSERT_SQL,
                    batch,
                    template=_EVENT_VALUES_TEMPLATE,
                    page_size=batch_size,
                )
                inserted_total += len(batch)
                logger.debug(
                    "Batch %d–%d inserted (%d rows)",
                    batch_start,
                    batch_start + len(batch) - 1,
                    len(batch),
                )
            raw_conn.commit()
        except Exception as exc:
            raw_conn.rollback()
            logger.error("Bulk insert gagal, transaksi di-rollback: %s", exc)
            raise
        finally:
            cursor.close()

    return {
        "total":          len(events),
        "inserted":       inserted_total,
        "skipped_invalid": len(schema_errors),
        "errors":         [str(e) for e in schema_errors],
    }


# Bulk Insert — Assets (CMDB)

_ASSET_INSERT_SQL = text("""
    INSERT INTO assets
        (asset_id, hostname, asset_type, criticality,
         criticality_score, department, ip_address)
    VALUES
        (:asset_id, :hostname, :asset_type, :criticality,
         :criticality_score, :department, :ip_address)
    ON CONFLICT (asset_id) DO NOTHING
""")


def bulk_insert_assets(engine: Engine, assets: list[dict]) -> int:
    """
    Insert atau skip (ON CONFLICT DO NOTHING) asset CMDB.

    Returns:
        Jumlah baris yang berhasil di-insert.
    """
    if not assets:
        return 0

    inserted = 0
    with engine.begin() as conn:
        for asset in assets:
            try:
                conn.execute(_ASSET_INSERT_SQL, asset)
                inserted += 1
            except Exception as exc:
                logger.warning(
                    "Asset '%s' tidak dapat di-insert (loncat): %s",
                    asset.get("asset_id", "?"),
                    exc,
                )

    logger.info("Assets inserted: %d / %d", inserted, len(assets))
    return inserted


# Standalone entry point (untuk smoke test koneksi)

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    eng = build_engine()
    try:
        version = ping(eng)
        logger.info("Koneksi berhasil: %s", version)
    except Exception as exc:
        logger.error("Koneksi gagal: %s", exc)
        sys.exit(1)