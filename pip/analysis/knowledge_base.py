"""
pip/analysis/knowledge_base.py

Dynamic Knowledge Base.

Manages the local database of:
  - Kernel privilege escalation CVEs (NVD-sourced)
  - GTFOBins binary abuse data
  - MITRE ATT&CK technique stubs

All data is stored in data/*.json and can be synced with KnowledgeBase.sync().
Offline bundle is shipped with the repository for air-gapped use.
"""
from __future__ import annotations
import json
import urllib.request
from pathlib import Path
from rich.console import Console

console = Console()
_DATA_DIR = Path(__file__).parent.parent.parent / "data"

class KnowledgeBase:
    """Manages sync and query of the local threat intelligence database."""

    GTFOBINS_API = "https://gtfobins.github.io/gtfobins.json"

    def sync(self) -> None:
        """Download latest data from all sources. Safe to run offline (will fail gracefully)."""
        self._sync_gtfobins()
        console.print("[green]  Knowledge base sync complete.[/green]")

    def _sync_gtfobins(self) -> None:
        try:
            console.print("[dim]  Syncing GTFOBins...[/dim]")
            with urllib.request.urlopen(self.GTFOBINS_API, timeout=10) as resp:
                data = json.load(resp)
            out_path = _DATA_DIR / "gtfobins.json"
            with open(out_path, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"[green]  GTFOBins: {len(data)} entries saved.[/green]")
        except Exception as e:
            console.print(f"[yellow]  GTFOBins sync failed: {e}. Using cached data.[/yellow]")

    def query_kernel_cves(self, kernel_version: str) -> list[dict]:
        """
        Return known local privilege escalation CVEs for the given kernel version.
        Data is matched against the local NVD cache.
        """
        cve_db_path = _DATA_DIR / "kernel_cves.json"
        if not cve_db_path.exists():
            return []
        with open(cve_db_path) as f:
            db = json.load(f)
        major_minor = ".".join(kernel_version.split(".")[:2])
        return [entry for entry in db if major_minor in entry.get("affected_versions", [])]
