# PIP Developer Documentation

**PrivEsc Intelligence Platform v2.0.0**

This document is for contributors and plugin authors building on top of PIP.
For end-user documentation, see the project [README](../README.md).

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Module Reference](#module-reference)
3. [Data Flow](#data-flow)
4. [Plugin API](#plugin-api)
5. [Adding a New Enumeration Check](#adding-a-new-enumeration-check)
6. [Attack Graph Model](#attack-graph-model)
7. [Scoring Formula](#scoring-formula)
8. [REST API Reference](#rest-api-reference)
9. [Running Tests](#running-tests)
10. [Release Checklist](#release-checklist)

---

## Project Structure

```
pip-toolkit/
├── pip.py                      # CLI entry point (Typer app)
├── pip/
│   ├── models/                 # Core data models (Finding, AttackPath, context)
│   ├── core/                   # Orchestrator, ContextEngine, StealthEngine, ShellCompat
│   ├── enum/                   # Built-in enumeration modules
│   ├── analysis/               # Correlation graph, GTFOBins, MITRE mapper, knowledge base
│   ├── scoring/                # Risk scorer, exploit validator, FP reducer, learning engine
│   ├── decision/               # Decision engine, exploit runner
│   ├── reporting/              # Executive, technical, and blue team reporters
│   └── api/                    # FastAPI server and JWT auth
├── plugins/
│   ├── enum/                   # Drop-in enumeration plugins
│   ├── exploit/                # Drop-in exploit plugins
│   ├── cloud/                  # Cloud-provider-specific plugins
│   └── correlation/            # Custom attack graph extensions
├── data/                       # Knowledge base (GTFOBins, NVD, MITRE ATT&CK)
├── tests/                      # Test suite (pytest)
├── docs/                       # Developer documentation
├── .github/workflows/ci.yml    # GitHub Actions CI pipeline
├── Dockerfile                  # Multi-stage container build
├── Makefile                    # Common dev tasks
├── pyproject.toml              # Build config, ruff, mypy, pytest, coverage
├── requirements.txt            # Runtime dependencies
└── requirements-dev.txt        # Dev + test dependencies
```

---

## Module Reference

### `pip/models/`

| Module         | Key Classes                                          |
|----------------|------------------------------------------------------|
| `finding.py`   | `Finding`, `FindingCategory`, `Severity`             |
| `attack_path.py` | `AttackPath`, `AttackStep`                         |
| `context.py`   | `ScanConfig`, `SystemContext`, `UserContext`, all enums |

### `pip/core/`

| Module              | Responsibility                                          |
|---------------------|---------------------------------------------------------|
| `orchestrator.py`   | 6-stage async pipeline coordinator                     |
| `context_engine.py` | Environment fingerprinting (OS, Docker, K8s, cloud)    |
| `stealth_engine.py` | Noise profile management, EDR-aware auto-downgrade     |
| `shell_compat.py`   | Safe command execution, restricted shell handling      |
| `plugin.py`         | Base classes: `EnumPlugin`, `ExploitPlugin`, `CloudPlugin`, `CorrelationPlugin` |

### `pip/analysis/`

| Module                 | Responsibility                                       |
|------------------------|------------------------------------------------------|
| `correlation_graph.py` | NetworkX-powered attack path builder                |
| `gtfobins.py`          | SUID/cap/sudo → GTFOBins exploit command enrichment |
| `mitre_mapper.py`      | Category → ATT&CK T-code tagging                    |
| `knowledge_base.py`    | Local DB sync (GTFOBins, NVD, MITRE)                |

### `pip/scoring/`

| Module                | Responsibility                                        |
|-----------------------|-------------------------------------------------------|
| `risk_scorer.py`      | Composite path scoring formula                       |
| `exploit_validator.py`| Tiered dry-run validation per finding category       |
| `fp_reducer.py`       | False positive suppression                           |
| `learning_engine.py`  | Per-environment hit-rate state persistence           |

---

## Data Flow

```
CLI args
   │
   ▼
ScanConfig (models/context.py)
   │
   ▼
Orchestrator.run()
   │
   ├─ Stage 1: ContextEngine.fingerprint()
   │      → SystemContext, UserContext
   │
   ├─ Stage 2: EnumModules.run() [parallel]
   │      → list[Finding]
   │
   ├─ Stage 3: GTFOBinsIntegration.enrich() + MitreMapper.tag()
   │           CorrelationGraphEngine.build_paths()
   │      → list[AttackPath] (unscored)
   │
   ├─ Stage 4: FPReducer.filter()
   │           ExploitValidator.validate() [per path]
   │           RiskScorer.score() [per path]
   │      → list[AttackPath] (scored, sorted)
   │
   ├─ Stage 5: DecisionEngine.present()
   │           [ExploitRunner.run() if --exploit]
   │
   └─ Stage 6: ExecutiveReporter / TechnicalReporter / BlueTeamReporter
```

---

## Plugin API

All plugins live in `plugins/<category>/` and are loaded at runtime by `Orchestrator._load_plugins()`.

### EnumPlugin

```python
from pip.core.plugin import EnumPlugin
from pip.models.finding import Finding, FindingCategory, Severity

class MyCheck(EnumPlugin):
    name = "my_check"

    def can_run(self, sys_ctx, user_ctx) -> bool:
        return sys_ctx.environment_type.value == "docker"  # optional gate

    async def run(self, sys_ctx, user_ctx, shell) -> list[Finding]:
        result = shell.run("cat /proc/1/cgroup")
        if "docker" in result.output:
            return [Finding(
                title="Running inside Docker",
                category=FindingCategory.CONTAINER,
                severity=Severity.INFO,
                description="Container environment confirmed via /proc/1/cgroup.",
                evidence=result.output[:100],
                source_module=self.name,
            )]
        return []
```

### CloudPlugin

Subclasses `EnumPlugin`. Add `provider = "aws" | "gcp" | "azure" | "any"`.
Activated automatically when ContextEngine detects the matching cloud.

### ExploitPlugin

Only runs when `--exploit` flag is active and the consent gate is confirmed.
Must implement `run()` and `rollback()`.

### CorrelationPlugin

Receives the NetworkX `DiGraph` after standard edge building.
Implement `enrich(graph, findings, sys_ctx)` to add custom nodes/edges.

---

## Attack Graph Model

The correlation graph is a directed graph where:

- **Nodes** represent system states (e.g. `"user_shell"`, `"file:/opt/backup.sh"`, `"root_shell"`)
- **Edges** carry a `Finding` object and a `weight` (inverse of confidence)
- All paths are extracted from `"user_shell"` to `"root_shell"`

Node naming conventions:

| Pattern                  | Meaning                              |
|--------------------------|--------------------------------------|
| `"user_shell"`           | Starting state (current access)      |
| `"root_shell"`           | Target state (full root access)      |
| `"file:<path>"`          | A specific file system path          |
| `"suid:<path>"`          | A SUID binary state                  |
| `"sudo:<cmd>"`           | A sudo rule                          |
| `"cron_root"`            | A root cron execution state          |
| `"service_restart"`      | Systemd service restart trigger      |
| `"container_escape"`     | Container escape intermediate        |
| `"kernel_exploit"`       | Kernel vulnerability state           |

To add custom edges from a `CorrelationPlugin`:

```python
def enrich(self, graph, findings, sys_ctx):
    graph.add_node("my_custom_state", label="My custom state")
    graph.add_edge("user_shell", "my_custom_state", finding=my_finding, weight=0.2)
    graph.add_edge("my_custom_state", "root_shell",  finding=my_finding, weight=0.2)
```

---

## Scoring Formula

```
composite = (exploitability × reliability × impact × stealth) ^ 0.25 × 10
```

Each component is `0.0–1.0`. The geometric mean (via 4th root) penalises any
weak component — a stealthy, exploitable, reliable path that only gives info
disclosure scores low because `impact = 0.1`.

| Component       | What it measures                                  |
|-----------------|---------------------------------------------------|
| exploitability  | How easy to attempt (step count, tool needs, auth)|
| reliability     | Probability of success (validated confidence)     |
| impact          | Always 1.0 for full root paths                    |
| stealth         | Probability of not being detected                 |

Stealth penalties: `auditd` −0.2, `CrowdStrike/Defender` −0.25, `SELinux enforcing` −0.4 (via reliability).
Stealth bonuses: `cron-based path` +0.15.

---

## REST API Reference

Start the server: `python pip.py serve --host 0.0.0.0 --port 8443`

Interactive docs: `https://localhost:8443/docs`

| Method | Path                              | Description                          |
|--------|-----------------------------------|--------------------------------------|
| GET    | `/health`                         | Liveness check (no auth)             |
| POST   | `/scan`                           | Start a new scan                     |
| GET    | `/scan/{scan_id}`                 | Poll scan status / results           |
| GET    | `/scan/{scan_id}/stream`          | SSE stream of scan progress          |
| GET    | `/scan/{scan_id}/report/{type}`   | Download a report (technical/executive/blue_team) |
| GET    | `/knowledge/sync`                 | Trigger knowledge base sync          |

Authentication: `Authorization: Bearer <jwt>` or `X-API-Key: <key>`.

---

## Running Tests

```bash
# All tests with coverage
make test

# Unit tests only (fast)
make test-unit

# Integration tests
make test-int

# Single test file
pytest tests/test_scoring.py -v

# Single test
pytest tests/test_scoring.py::TestRiskScorer::test_cron_path_has_higher_stealth_than_kernel -v
```

Coverage report: `htmlcov/index.html` (after `make test`).

---

## Release Checklist

- [ ] All tests pass: `make test`
- [ ] No linter errors: `make lint`
- [ ] No type errors: `make typecheck`
- [ ] Version bumped in `pyproject.toml` and `pip/api/server.py`
- [ ] `CHANGELOG.md` updated
- [ ] Knowledge base synced: `make update-kb`
- [ ] Docker image builds: `make docker`
- [ ] GitHub release created with `dist/` artifacts attached
