"""
pip/analysis/gtfobins.py

GTFOBins Integration.

Correlates SUID binaries, sudo rules, and Linux capabilities against
the GTFOBins database to generate exact exploitation commands.

Data source: data/gtfobins.json (synced by KnowledgeBase.sync())
"""
from __future__ import annotations
import json
from pathlib import Path
from pip.models.finding import Finding, FindingCategory

_DB_PATH = Path(__file__).parent.parent.parent / "data" / "gtfobins.json"

class GTFOBinsIntegration:
    """Enriches Findings with GTFOBins exploitation commands."""

    def __init__(self):
        self._db: dict = self._load()

    def _load(self) -> dict:
        if _DB_PATH.exists():
            with open(_DB_PATH) as f:
                return json.load(f)
        return {}

    def enrich(self, finding: Finding) -> None:
        """
        Look up the binary from a SUID/capability/sudo Finding
        and attach the GTFOBins exploit command if found.
        """
        if finding.category not in (FindingCategory.SUID, FindingCategory.CAPABILITY, FindingCategory.SUDO):
            return
        binary_name = Path(finding.affected_path).name if finding.affected_path else ""
        if not binary_name or binary_name not in self._db:
            return
        entry = self._db[binary_name]
        # Select the most relevant function for the finding type
        function_map = {
            FindingCategory.SUID:       "suid",
            FindingCategory.SUDO:       "sudo",
            FindingCategory.CAPABILITY: "capabilities",
        }
        fn_key = function_map.get(finding.category, "shell")
        functions = entry.get("functions", {})
        if fn_key in functions:
            cmds = functions[fn_key]
            if cmds:
                cmd_example = cmds[0].get("code", "")
                finding.exploit_cmd = cmd_example
                finding.gtfobins_url = f"https://gtfobins.github.io/gtfobins/{binary_name}/"
                finding.confidence = min(1.0, finding.confidence + 0.20)
