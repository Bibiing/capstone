"""
Asset Registry — CMDB Management for the PoC.

Loads asset definitions from an asset-registry JSON file and upserts them into the
database. Also provides utilities to synchronise asset records with live
Wazuh agents.

The registry file (`config/assets_registry.json`) acts as the source
of truth for:
    - Asset identifiers and hostnames
    - Linked Wazuh agent IDs
    - Likert scores (pre-filled from a sample questionnaire)

In a production system, this data would come from an enterprise CMDB.

Commands (as a module script):
    python -m ingestion.asset_registry seed    Load/update assets from registry file
    python -m ingestion.asset_registry list    Print all registered assets
    python -m ingestion.asset_registry sync    Sync asset IDs with live Wazuh agents

Usage as a library:
    from ingestion.asset_registry import AssetRegistry

    registry = AssetRegistry.from_settings()
    registry.seed()
    assets = registry.get_all()
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from database.connection import get_session
from database import queries
from database.models import Asset
from ingestion.exceptions import AssetRegistryError
from ingestion.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

# Default registry file location relative to project root
DEFAULT_SEED_FILE = Path(__file__).parent.parent / "config" / "assets_registry.json"


class AssetRegistry:
    """
    Manages the asset CMDB for the Risk Scoring PoC.

    Provides idempotent seeding, live listing, and optional Wazuh agent
    ID synchronisation.
    """

    def __init__(
        self,
        seed_file: Path = DEFAULT_SEED_FILE,
        wazuh_client: Optional[WazuhClient] = None,
    ) -> None:
        self._seed_file = seed_file
        self._wazuh_client = wazuh_client

    @classmethod
    def from_settings(cls) -> "AssetRegistry":
        """Create an AssetRegistry with default settings."""
        return cls()

    # ── Seeding ────────────────────────────────────────────────────────────────

    def seed(self) -> int:
        """
        Load assets from the registry JSON file and upsert them into the database.

        Safe to call multiple times — uses ON CONFLICT DO UPDATE (idempotent).

        Returns:
            Number of assets upserted.

        Raises:
            AssetRegistryError: If the seed file is missing or malformed.
        """
        assets_data = self._load_seed_file()
        now = datetime.now(timezone.utc)
        count = 0

        with get_session() as session:
            for entry in assets_data:
                self._validate_seed_entry(entry)
                record = {
                    "asset_id": entry["asset_id"],
                    "hostname": entry["hostname"],
                    "wazuh_agent_id": entry.get("wazuh_agent_id"),
                    "ip_address": entry.get("ip_address"),
                    "likert_score": float(entry["likert_score"]),
                    "description": entry.get("description"),
                    "created_at": now,
                    "updated_at": now,
                }
                queries.upsert_asset(session, record)
                count += 1

        logger.info("Asset registry seeded: %d assets upserted.", count)
        return count

    # ── Listing ────────────────────────────────────────────────────────────────

    def get_all(self) -> list[Asset]:
        """Return all assets currently in the database."""
        with get_session() as session:
            return queries.get_all_assets(session)

    def get_by_id(self, asset_id: str) -> Optional[Asset]:
        """Return a single asset by its ID, or None."""
        with get_session() as session:
            return queries.get_asset_by_id(session, asset_id)

    # ── Wazuh Agent Sync ───────────────────────────────────────────────────────

    def sync_with_wazuh(self) -> dict[str, str]:
        """
        Match asset records to live Wazuh agents by hostname.

        Useful when agent IDs change (e.g. after a Wazuh reinstall).
        Updates wazuh_agent_id in the database for matching records.

        Returns:
            Dict mapping asset_id → new wazuh_agent_id for updated records.

        Note:
            Requires a WazuhClient to be provided at construction time.
        """
        if self._wazuh_client is None:
            raise AssetRegistryError(
                "Cannot sync with Wazuh: no WazuhClient provided. "
                "Use AssetRegistry(wazuh_client=WazuhClient.from_settings())."
            )

        live_agents = self._wazuh_client.get_agents(status="active")
        agent_map = {agent.name.lower(): agent.agent_id for agent in live_agents}

        updated: dict[str, str] = {}
        now = datetime.now(timezone.utc)

        with get_session() as session:
            assets = queries.get_all_assets(session)
            for asset in assets:
                matched_id = agent_map.get(asset.hostname.lower())
                if matched_id and matched_id != asset.wazuh_agent_id:
                    queries.upsert_asset(
                        session,
                        {
                            "asset_id": asset.asset_id,
                            "hostname": asset.hostname,
                            "wazuh_agent_id": matched_id,
                            "ip_address": asset.ip_address,
                            "likert_score": asset.likert_score,
                            "description": asset.description,
                            "updated_at": now,
                        },
                    )
                    updated[asset.asset_id] = matched_id
                    logger.info(
                        "Linked asset %s (%s) → agent %s",
                        asset.asset_id,
                        asset.hostname,
                        matched_id,
                    )

        if not updated:
            logger.info("Agent sync complete — no changes needed.")
        else:
            logger.info("Agent sync complete — %d asset(s) updated.", len(updated))

        return updated

    # ── Internal Helpers ───────────────────────────────────────────────────────

    def _load_seed_file(self) -> list[dict]:
        """Load and parse the JSON seed file. Raises AssetRegistryError on failure."""
        if not self._seed_file.exists():
            raise AssetRegistryError(
                f"Seed file not found: {self._seed_file}\n"
                f"Expected at: {self._seed_file.resolve()}"
            )
        try:
            return json.loads(self._seed_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AssetRegistryError(
                f"Seed file is not valid JSON: {self._seed_file}\n{exc}"
            ) from exc

    @staticmethod
    def _validate_seed_entry(entry: dict) -> None:
        """Validate a single asset seed entry. Raises AssetRegistryError if invalid."""
        required = ("asset_id", "hostname", "likert_score")
        for field in required:
            if field not in entry:
                raise AssetRegistryError(
                    f"Seed entry missing required field '{field}': {entry}"
                )

        score = entry.get("likert_score")
        if not isinstance(score, (int, float)) or not (1.0 <= float(score) <= 5.0):
            raise AssetRegistryError(
                f"Invalid likert_score '{score}' for asset '{entry.get('asset_id')}'. "
                f"Must be a number between 1.0 and 5.0."
            )


# =============================================================================
# CLI Entry Point
# =============================================================================

def _print_assets(assets: list[Asset]) -> None:
    if not assets:
        print("No assets registered.")
        return
    print(f"\n{'ASSET ID':<15} {'HOSTNAME':<30} {'AGENT':<8} {'LIKERT':>7} {'IMPACT':>7}")
    print("-" * 72)
    for a in assets:
        print(
            f"{a.asset_id:<15} {a.hostname:<30} "
            f"{a.wazuh_agent_id or 'N/A':<8} {a.likert_score:>7.1f} {a.impact:>7.2f}"
        )
    print(f"\nTotal: {len(assets)} asset(s)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    command = sys.argv[1] if len(sys.argv) > 1 else "help"
    registry = AssetRegistry.from_settings()

    if command == "seed":
        try:
            n = registry.seed()
            print(f"✅  Seeded {n} asset(s) into the database.")
        except AssetRegistryError as e:
            print(f"❌  Seed failed: {e}", file=sys.stderr)
            sys.exit(1)

    elif command == "list":
        _print_assets(registry.get_all())

    elif command == "sync":
        print("Syncing asset agent IDs with live Wazuh agents...")
        client = WazuhClient.from_settings()
        r = AssetRegistry(wazuh_client=client)
        try:
            updated = r.sync_with_wazuh()
            print(f"✅  Sync complete. {len(updated)} asset(s) updated.")
        finally:
            client.close()

    else:
        print("Usage: python -m ingestion.asset_registry [seed|list|sync]")
