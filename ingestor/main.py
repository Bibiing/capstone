"""
Service ingesti: membaca JSON output dummy generator → insert ke PostgreSQL.

Bisa dijalankan:
    1. Langsung: python main.py --input-dir ../dummy_generator/output
    2. Via generate_all.py --seed-db
    3. Via Docker sebagai service (mode watch)
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

load_dotenv(Path(__file__).parent.parent / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ingestor")


# DB connection
def get_engine():
    url = (
        f"postgresql+psycopg2://"
        f"{os.getenv('POSTGRES_USER', 'admin')}:"
        f"{os.getenv('POSTGRES_PASSWORD', 'changeme_secret')}"
        f"@{os.getenv('POSTGRES_HOST', 'localhost')}:"
        f"{os.getenv('POSTGRES_PORT', '5432')}/"
        f"{os.getenv('POSTGRES_DB', 'risk_scoring')}"
    )
    return create_engine(url, pool_pre_ping=True)


# Seed assets (CMDB)
def seed_assets(engine, assets_file: Path) -> int:
    with open(assets_file) as f:
        assets = json.load(f)

    inserted = 0
    with engine.begin() as conn:
        for asset in assets:
            try:
                conn.execute(
                    text("""
                        INSERT INTO assets
                            (asset_id, hostname, asset_type, criticality,
                             criticality_score, department, ip_address)
                        VALUES
                            (:asset_id, :hostname, :asset_type, :criticality,
                             :criticality_score, :department, :ip_address)
                        ON CONFLICT (asset_id) DO NOTHING
                    """),
                    asset,
                )
                inserted += 1
            except Exception as exc:
                logger.warning("Asset %s skip: %s", asset["asset_id"], exc)

    logger.info("Assets seeded: %d / %d", inserted, len(assets))
    return inserted


# Ingest events
BATCH_SIZE = 500  # insert per batch untuk efisiensi


def ingest_events(engine, events: list[dict], source_file: str) -> int:
    """Bulk insert events ke tabel wazuh_events."""
    if not events:
        return 0

    inserted = 0
    for i in range(0, len(events), BATCH_SIZE):
        batch = events[i : i + BATCH_SIZE]
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO wazuh_events
                            (event_id, timestamp, asset_id, hostname, severity,
                             category, event_type, rule_id, rule_description,
                             cve_id, cvss_score, scenario)
                        VALUES
                            (:event_id, :timestamp, :asset_id, :hostname, :severity,
                             :category, :event_type, :rule_id, :rule_description,
                             :cve_id, :cvss_score, :scenario)
                        ON CONFLICT DO NOTHING
                    """),
                    batch,
                )
                inserted += len(batch)
        except Exception as exc:
            logger.error("Batch insert failed (file=%s, batch=%d): %s", source_file, i, exc)

    return inserted


def load_and_ingest_file(engine, json_file: Path) -> dict:
    """Load satu JSON file dan ingest semua events-nya."""
    logger.info("Processing: %s", json_file.name)
    start = time.perf_counter()

    with open(json_file) as f:
        events = json.load(f)

    inserted = ingest_events(engine, events, json_file.name)
    elapsed  = time.perf_counter() - start

    result = {
        "file":     json_file.name,
        "total":    len(events),
        "inserted": inserted,
        "elapsed":  round(elapsed, 2),
    }
    logger.info(
        "  → %d/%d events inserted in %.2fs",
        inserted, len(events), elapsed,
    )
    return result


# Validation query — cek apakah data masuk dengan benar
def validate_ingestion(engine) -> None:
    """Jalankan beberapa query validasi setelah ingesti selesai."""
    queries = {
        "Total assets"     : "SELECT COUNT(*) FROM assets",
        "Total events"     : "SELECT COUNT(*) FROM wazuh_events",
        "Events per scenario": """
            SELECT scenario, COUNT(*) as count, AVG(severity)::numeric(4,1) as avg_sev
            FROM wazuh_events
            GROUP BY scenario ORDER BY count DESC
        """,
        "Top 5 assets by event count": """
            SELECT asset_id, COUNT(*) as events, MAX(severity) as max_sev
            FROM wazuh_events
            GROUP BY asset_id
            ORDER BY events DESC
            LIMIT 5
        """,
    }

    logger.info("\n--- Validation Report ---")
    with engine.connect() as conn:
        for label, sql in queries.items():
            try:
                result = conn.execute(text(sql))
                rows   = result.fetchall()
                logger.info("\n%s:", label)
                for row in rows:
                    logger.info("  %s", dict(row._mapping))
            except Exception as exc:
                logger.warning("Validation query failed [%s]: %s", label, exc)


# Main
def main() -> None:
    parser = argparse.ArgumentParser(description="Wazuh Telemetry Ingestor")
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path(__file__).parent.parent / "dummy_generator" / "output",
        help="Direktori berisi file events_*.json",
    )
    parser.add_argument(
        "--skip-assets",
        action="store_true",
        help="Lewati seeding asset CMDB.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        default=True,
        help="Jalankan validation query setelah ingesti (default: True).",
    )
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("Wazuh Telemetry Ingestor")
    logger.info("Input dir: %s", args.input_dir)
    logger.info("=" * 60)

    # Koneksi DB
    engine = get_engine()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("✅ Database connected")
    except Exception as exc:
        logger.error("❌ Cannot connect to database: %s", exc)
        sys.exit(1)

    # Seed CMDB
    if not args.skip_assets:
        assets_file = Path(__file__).parent.parent / "dummy_generator" / "assets.json"
        if assets_file.exists():
            seed_assets(engine, assets_file)
        else:
            logger.warning("assets.json not found at %s", assets_file)

    # Ingest semua file JSON di input-dir
    json_files = sorted(args.input_dir.glob("events_*.json"))
    if not json_files:
        logger.warning("No events_*.json files found in %s", args.input_dir)
        sys.exit(0)

    summary = []
    for json_file in json_files:
        result = load_and_ingest_file(engine, json_file)
        summary.append(result)

    # Ringkasan
    logger.info("\n--- Ingestion Summary ---")
    total_inserted = 0
    for r in summary:
        logger.info("  %-35s %4d / %4d events  (%.2fs)", r["file"], r["inserted"], r["total"], r["elapsed"])
        total_inserted += r["inserted"]
    logger.info("  TOTAL: %d events inserted", total_inserted)

    # Validasi
    if args.validate:
        validate_ingestion(engine)

    logger.info("=" * 60)
    logger.info("Ingestion complete ✅")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()