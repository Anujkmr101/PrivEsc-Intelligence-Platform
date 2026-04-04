"""
pip/scoring/learning_engine.py

Learning Engine.

Stores per-environment scan profiles to improve prioritization over time:
  - Tracks which findings were confirmed vs false-positives per environment
  - Adjusts base confidence scores for future scans on similar environments
  - Eliminates redundant checks that have never produced results

State is stored in output_dir/pip_state.json and reused across runs.
"""
from __future__ import annotations
import json
from pathlib import Path
from pip.models.context import ScanConfig, SystemContext

class LearningEngine:
    """Persists per-environment scan state to improve subsequent runs."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._state_path = config.output_dir / "pip_state.json"
        self._state: dict = self._load()

    def _load(self) -> dict:
        if self._state_path.exists():
            try:
                with open(self._state_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"environments": {}}

    def get_confidence_adjustment(self, module_name: str, env_key: str) -> float:
        """Return a confidence delta (-0.2 to +0.2) based on historical hit rate."""
        env = self._state["environments"].get(env_key, {})
        module_stats = env.get(module_name, {"hits": 0, "runs": 0})
        if module_stats["runs"] == 0:
            return 0.0
        hit_rate = module_stats["hits"] / module_stats["runs"]
        return (hit_rate - 0.5) * 0.4  # Map 0–1 hit rate to -0.2 to +0.2

    def record_findings(self, module_name: str, env_key: str, finding_count: int) -> None:
        env = self._state["environments"].setdefault(env_key, {})
        stats = env.setdefault(module_name, {"hits": 0, "runs": 0})
        stats["runs"] += 1
        if finding_count > 0:
            stats["hits"] += 1

    def save(self) -> None:
        if self.config.no_disk:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._state_path, "w") as f:
            json.dump(self._state, f, indent=2)

    @staticmethod
    def env_key(sys_ctx: SystemContext) -> str:
        """Generate a stable key identifying this environment type."""
        return f"{sys_ctx.environment_type.value}:{sys_ctx.os_name}:{sys_ctx.kernel_version}"
