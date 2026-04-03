<div align="center">

<img src="https://img.shields.io/badge/version-2.0.0-blue?style=flat-square" />
<img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
<img src="https://img.shields.io/badge/MITRE%20ATT%26CK-aligned-orange?style=flat-square" />
<img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square&logo=linux&logoColor=white" />
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" />

# PrivEsc Intelligence Platform (PIP)

**Next-generation Linux privilege escalation automation for security professionals.**

Not *"here are 500 issues"* → but *"here is the verified, ranked path to root."*

[Features](#features) · [Architecture](#architecture) · [Quick Start](#quick-start) · [Usage](#usage) · [Modules](#modules) · [Reporting](#reporting) · [Roadmap](#roadmap) · [Contributing](#contributing)

</div>

---

## The Problem with Existing Tools

Every penetration tester knows the frustration: you run LinPEAS on a target, scroll through 400 color-coded lines, and still have to manually decide what matters. Existing tools enumerate. They do not *think.*

| What old tools give you | What PIP gives you |
|---|---|
| 200–500 unranked findings | Top-ranked, scored attack paths only |
| Isolated misconfigurations | Multi-hop chains: User → File → Cron → Root |
| "This kernel version might be vulnerable" | Verified exploits with 95%+ confidence score |
| Terminal-only output | Executive PDF, Technical JSON, Blue Team checklist |
| Environment-blind scanning | Docker / K8s / Cloud / bare metal-aware strategy |
| Static CVE database | Live-synced, technique-based knowledge base |

PIP resolves **25 systemic flaws** identified across LinPEAS, LinEnum, Linux Smart Enumeration, and Linux Exploit Suggester.

---

## Features

### Core Intelligence

- **Correlation Graph Engine** — converts isolated findings into full multi-hop attack paths using a NetworkX-powered graph. Nodes are system states; edges are exploitable actions.
- **Exploit Validation Engine** — dry-runs and sandbox-validates each path before presenting it. No more "this might work" guessing.
- **Risk Scoring Model** — every path is scored: `Exploitability × Reliability × Impact × Stealth`. You always know what to try first.
- **Decision Engine** — outputs the best path, fastest path, and stealthiest path to root. Ranked. Actionable. Explained.

### Environment Awareness

- **Context Fingerprinting** — detects bare metal, VM, Docker, Kubernetes, and cloud environments (AWS IMDSv1/v2, GCP, Azure metadata). Shifts strategy automatically.
- **Cloud + Container Module** — IAM role abuse, Docker socket exposure, privileged pod detection, K8s RBAC misconfiguration, namespace escape analysis.
- **Shell Compatibility Layer** — gracefully handles restricted shells (`rbash`, `lsh`). Falls back to POSIX-safe command variants. Never breaks silently.

### Stealth & Safety

- **Stealth Profile Engine** — three configurable noise profiles: `silent` / `normal` / `aggressive`. Avoids commands known to trigger EDR/AV rules. Memory-only mode by default (no disk writes).
- **Controlled Exploitation Engine** — staged execution with explicit `--exploit` consent gate. Full audit log. Kill-switch via `SIGINT` or configurable timeout. Rollback support where possible.
- **Read-only by default** — PIP never modifies the target system unless explicitly instructed.

### Discovery & Enumeration

- **Credential Intelligence Module** — discovers secrets from environment variables, `/proc/[pid]/mem` (safe inspection), cloud metadata endpoints, shell history, and git commit history.
- **GTFOBins Integration** — automatically correlates SUID binaries and Linux capabilities to GTFOBins abuse paths. Generates the exact working command for the binary version on the target.
- **Lateral Awareness Module** — pivot analysis across users via SSH trust chains, NFS shares, sudo rules, and shared writable paths.
- **MITRE ATT&CK Mapper** — every finding is tagged to an ATT&CK technique ID (T-code) for compliance and reporting alignment.

### Reporting (Three Audiences)

- **Executive Report** — risk level, root-possible Y/N, best path in plain English, business impact. PDF output. Board-ready.
- **Technical Report** — full findings in JSON/SARIF, ATT&CK technique mapping, CVSS scores, reproduction commands, raw evidence.
- **Blue Team / Hardening Report** — per-finding remediation commands, CIS Benchmark hardening checklist, and detection rules for each path found.

### Enterprise Integration

- **REST API** — FastAPI-based, JWT-authenticated, JSON streaming responses. Integrate PIP into any workflow.
- **CI/CD Bridge** — GitHub Actions, GitLab CI, Jenkins hooks. Fail builds on critical privilege escalation paths.
- **SIEM Export** — Splunk, ELK, and generic syslog adapters for enterprise SOC environments.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              LAYER 0 — Interface & Entry Points             │
│    Smart CLI (Typer)  │  REST API  │  CI/CD  │  SOC/SIEM   │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│              LAYER 1 — Adaptive Orchestrator                │
│   Context Fingerprinting │ Stealth Engine │ Shell Compat   │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│              LAYER 2 — Enumeration & Discovery              │
│  Smart Enum │ Credential Intel │ Cloud+Container │ Lateral  │
│             GTFOBins Integration │ MITRE Mapper             │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│              LAYER 3 — Correlation & Analysis               │
│     NetworkX Graph Engine │ Dynamic Knowledge Base          │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│              LAYER 4 — Validation & Scoring                 │
│    Exploit Validator │ Risk Scorer │ FP Reducer │ Learner   │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│              LAYER 5 — Decision & Execution                 │
│        Decision Engine │ Controlled Exploitation Engine     │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│              LAYER 6 — Reporting Engine                     │
│       Executive PDF │ Technical JSON/SARIF │ Blue Team      │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Requirements

- Python 3.11+
- Linux target system (local or remote)
- Explicit written authorization from the system owner

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pip-toolkit.git
cd pip-toolkit

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -m pip --version
```

### Minimal scan (read-only, safe)

```bash
python3 pip.py scan --target local
```

### Full engagement scan with reports

```bash
python3 pip.py scan \
  --mode deep \
  --stealth normal \
  --report all \
  --mitre-map \
  --blue-team \
  --output ./reports/engagement_001/
```

---

## Usage

### Scan Modes

| Mode | Description | Use Case |
|---|---|---|
| `quick` | Fast targeted scan, top findings only | Initial triage |
| `deep` | Full enumeration + correlation | Full engagement |
| `audit` | Read-only, no exploitation | Blue team / compliance |
| `stealth` | Low-noise, memory-only | Evasive red team |

### Stealth Profiles

| Profile | Description |
|---|---|
| `silent` | Minimal commands. No disk writes. Throttled execution. |
| `normal` | Balanced. Recommended for most engagements. |
| `aggressive` | Maximum coverage. No noise suppression. |

### Common Commands

```bash
# Blue team hardening audit (CIS Level 2)
python3 pip.py scan --mode audit --report blue-team --cis-level 2

# Stealth red team with consent-gated exploit execution
python3 pip.py scan --mode quick --stealth silent --exploit --confirm-each

# Cloud environment (AWS)
python3 pip.py scan --mode deep --cloud aws --imds-check

# Export for SIEM / ticketing
python3 pip.py scan --mode deep --output-format sarif --report technical

# Start REST API server
python3 pip.py serve --host 0.0.0.0 --port 8443 --auth jwt
```

### CLI Reference

```
usage: pip.py scan [OPTIONS]

Options:
  --mode           [quick|deep|audit|stealth]     Scan depth profile
  --stealth        [silent|normal|aggressive]     Noise control profile
  --report         [executive|technical|blue-team|all]
  --exploit        Enable controlled exploit execution (requires consent)
  --confirm-each   Require confirmation before each exploit step
  --mitre-map      Tag all findings to MITRE ATT&CK T-codes
  --blue-team      Include per-finding remediation output
  --cis-level      [1|2]  CIS Benchmark hardening level for audit mode
  --cloud          [aws|gcp|azure]  Cloud environment hints
  --imds-check     Check cloud instance metadata endpoints
  --output         Output directory for reports
  --output-format  [json|sarif|pdf|html]
  --no-disk        Memory-only mode — no artifacts written to target
  --timeout        Global scan timeout in seconds (default: 300)
```

---

## Modules

```
pip/
├── core/
│   ├── orchestrator.py          # Adaptive scan coordinator
│   ├── context_engine.py        # Environment fingerprinting
│   ├── stealth_engine.py        # Noise profile management
│   └── shell_compat.py          # Restricted shell handling
├── enum/
│   ├── smart_enum.py            # Context-aware enumeration
│   ├── credential_intel.py      # Multi-source credential harvesting
│   ├── cloud_container.py       # Docker / K8s / Cloud checks
│   └── lateral_awareness.py     # Pivot and lateral path analysis
├── analysis/
│   ├── correlation_graph.py     # NetworkX attack path engine
│   ├── gtfobins.py              # GTFOBins SUID/cap correlation
│   ├── knowledge_base.py        # Technique DB with auto-sync
│   └── mitre_mapper.py          # ATT&CK T-code tagging
├── scoring/
│   ├── exploit_validator.py     # Dry-run sandbox validation
│   ├── risk_scorer.py           # Composite path scoring
│   ├── fp_reducer.py            # False positive filtering
│   └── learning_engine.py       # Environment profile learning
├── decision/
│   ├── decision_engine.py       # Ranked path recommendation
│   └── exploit_runner.py        # Staged execution with consent gate
├── reporting/
│   ├── executive.py             # PDF executive summary
│   ├── technical.py             # JSON/SARIF technical report
│   └── blue_team.py             # Hardening checklist + remediation
├── api/
│   ├── server.py                # FastAPI REST server
│   ├── auth.py                  # JWT authentication
│   └── streaming.py             # JSON streaming responses
└── plugins/
    ├── enum/                    # Drop-in enumeration plugins
    ├── exploit/                 # Drop-in exploit modules
    ├── cloud/                   # Cloud-specific checks
    └── correlation/             # Custom correlation rules
```

---

## Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PIP — PrivEsc Intelligence Platform v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[ENV]    Docker container detected
         AppArmor: enabled  |  Seccomp: default
         Strategy: credential + host mount focus

[SCAN]   Deep mode  |  Stealth: normal  |  Modules: 14

━━ RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Risk Level    :  CRITICAL
  Root Access   :  POSSIBLE
  Paths Found   :  4
  Verified      :  2

━━ TOP PATH ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Method   :  Cron injection via writable script
  Score    :  9.6 / 10
  MITRE    :  T1053.003 (Scheduled Task/Job: Cron)
  Stealth  :  HIGH
  Time     :  ~30 seconds

  Steps:
    1. Write payload to /opt/backup.sh  (world-writable)
    2. Wait for cron execution           (root cron, 1-min interval)
    3. Root shell obtained

  Status   :  VERIFIED (dry-run passed)

━━ ALL PATHS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  #1  Cron injection          Score: 9.6  Verified: YES
  #2  SUID find abuse         Score: 8.1  Verified: YES   T1548.001
  #3  Sudo CVE-2021-3156      Score: 6.4  Verified: NO    T1068
  #4  Docker socket escape    Score: 5.9  Verified: NO    T1611

  Reports saved to: ./reports/engagement_001/
```

---

## Reporting

### Executive Report (PDF)
Designed for client delivery. Covers risk level, root-possible verdict, best attack path in plain English, and business impact summary. No technical jargon.

### Technical Report (JSON / SARIF)
Full findings with CVSS scores, ATT&CK T-codes, reproduction commands, raw evidence, and tool output. Compatible with SARIF-enabled tools (GitHub Advanced Security, VS Code).

### Blue Team Report
Per-finding remediation commands, CIS Benchmark hardening checklist (Level 1 or 2), and Sigma/Splunk detection rules for each attack path found. Turns a red team assessment into a hardening roadmap.

---

## Plugin System

PIP supports drop-in modules loaded at runtime:

```python
# plugins/enum/my_custom_check.py

from pip.core.plugin import EnumPlugin, Finding

class MyCustomCheck(EnumPlugin):
    name = "custom_suid_check"
    category = "suid"

    def run(self, context) -> list[Finding]:
        # Your enumeration logic here
        return [Finding(title="...", severity="high", mitre="T1548.001")]
```

Place the file in `plugins/enum/` — it is loaded automatically on next scan.

---

## Safety & Legal

> **PIP is designed exclusively for authorized security testing and defensive security research.**

- PIP is **read-only by default**. It does not modify the target system unless `--exploit` is explicitly passed.
- The `--exploit` flag requires an interactive confirmation prompt for each step. It cannot be bypassed non-interactively.
- A tamper-evident audit log of every command executed is written to `--output` directory.
- A global kill-switch terminates all activity immediately on `SIGINT` or timeout.

**You are solely responsible for ensuring you have written authorization before running PIP on any system.** Unauthorized use is illegal and unethical. The author accepts no liability for misuse.

---

## Comparison

| Feature | LinPEAS | LinEnum | LSE | LES | **PIP** |
|---|:---:|:---:|:---:|:---:|:---:|
| Context-aware enumeration | ~ | ✗ | ~ | ✗ | **✓** |
| Attack chain correlation | ✗ | ✗ | ✗ | ✗ | **✓** |
| Exploit validation | ✗ | ✗ | ✗ | ✗ | **✓** |
| Risk scoring | ~ | ✗ | ~ | ✗ | **✓** |
| MITRE ATT&CK alignment | ✗ | ✗ | ✗ | ✗ | **✓** |
| Container / K8s escape | ~ | ✗ | ✗ | ✗ | **✓** |
| Cloud IAM awareness | ~ | ✗ | ✗ | ✗ | **✓** |
| Stealth / noise control | ~ | ✗ | ✗ | ✗ | **✓** |
| Blue team output | ✗ | ✗ | ✗ | ✗ | **✓** |
| REST API + CI/CD | ✗ | ✗ | ✗ | ✗ | **✓** |
| Safe execution + rollback | ✗ | ✗ | ✗ | ✗ | **✓** |
| Executive PDF reporting | ✗ | ✗ | ✗ | ✗ | **✓** |

*~ = partial or basic support. LSE = Linux Smart Enumeration. LES = Linux Exploit Suggester.*

---

## Roadmap

- [ ] Windows privilege escalation parity (WinPIP)
- [ ] Active Directory / BloodHound correlation bridge
- [ ] Web-based dashboard (React + FastAPI)
- [ ] Automated exploit module generator from GTFOBins data
- [ ] LLM-assisted narrative report generation
- [ ] macOS privilege escalation module
- [ ] Burp Suite extension integration

---

## Contributing

Contributions are welcome, especially new enumeration plugins, exploit modules, and cloud provider checks.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-module`
3. Follow the plugin interface in `pip/core/plugin.py`
4. Add tests in `tests/`
5. Open a pull request with a clear description

Please read `CONTRIBUTING.md` for code style guidelines and the plugin API reference.

---

## Tech Stack

| Layer | Technologies |
|---|---|
| Core engine | Python 3.11+, asyncio, Pydantic v2 |
| CLI | Typer, Rich |
| Graph engine | NetworkX |
| REST API | FastAPI, JWT |
| Knowledge base | SQLite, auto-sync from NVD / ExploitDB / GTFOBins |
| Reporting | Jinja2, WeasyPrint, SARIF |
| Frameworks | MITRE ATT&CK, CIS Benchmarks, OWASP |

---

## License

MIT License — see `LICENSE` for details.

---

## Disclaimer

This tool is intended for use by authorized security professionals during legitimate penetration tests and security assessments. Always obtain written authorization before testing any system you do not own. The authors and contributors are not responsible for any unauthorized or illegal use of this software.

---

<div align="center">

Built for security professionals, by security professionals.

If PIP helped your engagement, consider starring the repo 

</div>
