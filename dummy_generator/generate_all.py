import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed, Future
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("generate_all")

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "scenarios"))

from scenarios.normal import NormalScenario
from scenarios.spike  import SpikeScenario
from scenarios.vuln   import VulnClusterScenario
from scenarios.decay  import DecayScenario


# skenario
SCENARIO_REGISTRY: dict[str, type] = {
    "normal":             NormalScenario,
    "spike":              SpikeScenario,
    "vuln_cluster":       VulnClusterScenario,
    "remediation_decay":  DecayScenario,
}


# Statistik
def print_stats(scenario_name: str, events: list[dict]) -> None:
    """Tampilkan ringkasan statistik tiap skenario setelah generate."""
    if not events:
        return

    severities  = [e["severity"] for e in events]
    categories: dict[str, int]  = {}
    event_types: dict[str, int] = {}
    assets_hit: set[str]        = set()

    for e in events:
        categories[e["category"]]    = categories.get(e["category"], 0) + 1
        event_types[e["event_type"]] = event_types.get(e["event_type"], 0) + 1
        assets_hit.add(e["asset_id"])

    logger.info(
        "\n"
        "  ┌─────────────────────────────────────────────\n"
        "  │  Scenario   : %s\n"
        "  │  Total events: %d\n"
        "  │  Assets hit  : %d\n"
        "  │  Severity    : min=%d  max=%d  avg=%.1f\n"
        "  │  Categories  : %s\n"
        "  │  Event types : %s\n"
        "  └─────────────────────────────────────────────",
        scenario_name,
        len(events),
        len(assets_hit),
        min(severities),
        max(severities),
        sum(severities) / len(severities),
        dict(sorted(categories.items(), key=lambda x: -x[1])),
        event_types,
    )


# Worker function
def _run_scenario_worker(
    scenario_name: str,
    scenario_class_path: str,
    seed: int,
    output_dir: str,
    dry_run: bool,
) -> dict[str, Any]:
    import importlib
    import logging as _logging

    # Re-setup logging child process
    _logging.basicConfig(
        level=_logging.INFO,
        format=f"%(asctime)s | %(levelname)-8s | [{scenario_name}] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _log = _logging.getLogger(scenario_name)

    start = time.perf_counter()
    try:
        module_path, class_name = scenario_class_path.rsplit(".", 1)
        module  = importlib.import_module(module_path)
        ScenarioClass = getattr(module, class_name)

        _log.info("Generating scenario: %s (pid=%d)", scenario_name, os.getpid())
        gen    = ScenarioClass(seed=seed)
        events = gen.generate_events()
        count  = len(events)
        _log.info("Generated %d events", count)

        saved_path = None
        if not dry_run and events:
            output_path = Path(output_dir) / f"events_{scenario_name}.json"
            with open(output_path, "w") as f:
                json.dump(events, f, indent=2, default=str)
            saved_path = str(output_path)
            _log.info("Saved to %s", saved_path)

        return {
            "scenario":    scenario_name,
            "count":       count,
            "elapsed":     round(time.perf_counter() - start, 3),
            "output_path": saved_path,
            "error":       None,
        }

    except Exception as exc:
        return {
            "scenario":    scenario_name,
            "count":       0,
            "elapsed":     round(time.perf_counter() - start, 3),
            "output_path": None,
            "error":       str(exc),
        }


# Peta skenario → "module.ClassName" untuk dikirim ke worker
_SCENARIO_CLASS_PATHS: dict[str, str] = {
    "normal":            "scenarios.normal.NormalScenario",
    "spike":             "scenarios.spike.SpikeScenario",
    "vuln_cluster":      "scenarios.vuln.VulnClusterScenario",
    "remediation_decay": "scenarios.decay.DecayScenario",
}


# Orchestrator parallel
def run_scenarios_parallel(
    to_run: dict[str, type],
    seed: int,
    output_dir: Path,
    dry_run: bool,
    max_workers: int | None,
) -> dict[str, int]:
    results: dict[str, int] = {}
    output_dir.mkdir(exist_ok=True)

    if len(to_run) == 1:
        # Single-scenario
        name = next(iter(to_run))
        logger.info("Single scenario — serial execution: %s", name)
        result = _run_scenario_worker(
            scenario_name       = name,
            scenario_class_path = _SCENARIO_CLASS_PATHS[name],
            seed                = seed,
            output_dir          = str(output_dir),
            dry_run             = dry_run,
        )
        _handle_worker_result(result, results)
        return results

    # Multi-scenario
    effective_workers = min(
        max_workers or os.cpu_count() or 1,
        len(to_run),
    )
    logger.info(
        "Parallel execution: %d skenario x %d worker proses",
        len(to_run),
        effective_workers,
    )

    futures: dict[Future, str] = {}
    with ProcessPoolExecutor(max_workers=effective_workers) as executor:
        for name in to_run:
            future = executor.submit(
                _run_scenario_worker,
                scenario_name       = name,
                scenario_class_path = _SCENARIO_CLASS_PATHS[name],
                seed                = seed,
                output_dir          = str(output_dir),
                dry_run             = dry_run,
            )
            futures[future] = name

        for future in as_completed(futures):
            result = future.result()
            _handle_worker_result(result, results)

    return results


def _handle_worker_result(result: dict[str, Any], accumulator: dict[str, int]) -> None:
    """Proses hasil dari worker dan catat ke accumulator."""
    name = result["scenario"]
    if result["error"]:
        logger.error(
            "Scenario '%s' GAGAL setelah %.3fs: %s",
            name, result["elapsed"], result["error"],
        )
    else:
        logger.info(
            "Scenario '%-20s' selesai: %d events dalam %.3fs",
            name, result["count"], result["elapsed"],
        )
        accumulator[name] = result["count"]


# DB Seed
# Load semua JSON output dan insert ke PostgreSQL.
# Memanggil ingestor/main.py sebagai subprocess agar separation of concern terjaga.
def seed_to_db(output_dir: Path) -> None:
    try:
        import subprocess
        ingestor_path = Path(__file__).parent.parent / "ingestor" / "main.py"
        if not ingestor_path.exists():
            logger.warning("Ingestor tidak ditemukan di %s — skip DB seeding", ingestor_path)
            return

        logger.info("Seeding database via ingestor...")
        result = subprocess.run(
            [sys.executable, str(ingestor_path), "--input-dir", str(output_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info("DB seeding complete:\n%s", result.stdout)
        else:
            logger.error("DB seeding failed:\n%s", result.stderr)

    except Exception as exc:
        logger.error("Failed to seed DB: %s", exc)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cyber Risk Scoring — Dummy Data Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIO_REGISTRY.keys()),
        default=None,
        help="Generate satu skenario saja. Default: semua skenario secara paralel.",
    )
    parser.add_argument(
        "--seed-db",
        action="store_true",
        help="Seed hasil generate ke PostgreSQL via ingestor.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Hanya tampilkan statistik, tidak simpan file.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed untuk reprodusibilitas. Default: 42.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Jumlah worker proses untuk eksekusi paralel. "
            "Default: jumlah CPU (os.cpu_count())."
        ),
    )
    args = parser.parse_args()

    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    # skenario mana yang dijalankan
    to_run: dict[str, type] = (
        {args.scenario: SCENARIO_REGISTRY[args.scenario]}
        if args.scenario
        else dict(SCENARIO_REGISTRY)
    )

    logger.info("=" * 60)
    logger.info("Cyber Risk Scoring — Dummy Generator")
    logger.info("Started  : %s", datetime.now(tz=timezone.utc).isoformat())
    logger.info("Scenarios: %s", list(to_run.keys()))
    logger.info("Workers  : %s", args.workers or f"auto ({os.cpu_count()} CPU)")
    logger.info("=" * 60)

    start_time = time.perf_counter()

    # semua skenario (serial jika 1, paralel jika >1)
    results = run_scenarios_parallel(
        to_run      = to_run,
        seed        = args.seed,
        output_dir  = output_dir,
        dry_run     = args.dry_run,
        max_workers = args.workers,
    )

    elapsed = time.perf_counter() - start_time

    logger.info("=" * 60)
    logger.info("SUMMARY")
    logger.info("  Total events generated : %d", sum(results.values()))
    logger.info("  Breakdown              : %s", results)
    logger.info("  Elapsed                : %.3fs", elapsed)
    logger.info("  Output dir             : %s", output_dir)
    logger.info("=" * 60)

    if args.seed_db and not args.dry_run:
        seed_to_db(output_dir)


# guard ini untuk kompatibilitas ProcessPoolExecutor
if __name__ == "__main__":
    main()