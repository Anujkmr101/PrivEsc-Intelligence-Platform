# Contributing to PIP

Contributions are welcome — especially new enumeration plugins, exploit modules,
cloud provider checks, and detection rule stubs.

---

## Getting Started

```bash
git clone https://github.com/yourusername/pip-toolkit.git
cd pip-toolkit
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests/ -v        # All tests should pass before you start
```

---

## Types of Contribution

### Enumeration plugin (most wanted)
Drop a new `.py` file in `plugins/enum/`. It must expose a class with:
- A `name: str` attribute
- An `async def run(sys_ctx, user_ctx, shell) -> list[Finding]` method

See `plugins/enum/example_custom_check.py` for a complete template.

### Exploit module
Drop a new `.py` file in `plugins/exploit/`. Must expose a class that implements
the `ExploitPlugin` interface from `pip/core/plugin.py`.
Exploit modules **must not execute** without the `--exploit` flag being present
in the config — this is enforced by the `ExploitRunner`.

### Cloud provider check
Drop a new `.py` file in `plugins/cloud/`. Cloud modules are automatically
activated when the `ContextEngine` detects the relevant cloud provider.

### Correlation rule
Drop a new `.py` file in `plugins/correlation/`. These extend the attack graph
with custom node and edge definitions for organisation-specific scenarios.

---

## Code Style

We use `ruff` for linting and formatting:

```bash
ruff check pip/ tests/     # Lint
ruff format pip/ tests/    # Format
mypy pip/                  # Type check
```

All checks must pass before a PR is merged.

### Key conventions

- All public functions and classes must have docstrings.
- Use `ShellCompat.run()` for **all** command execution — never call `subprocess` directly.
- Every `Finding` must set `source_module = self.name`.
- Never write to the filesystem from an enumeration module. Use `shell.no_disk` check if needed.
- Use type hints throughout. `from __future__ import annotations` at the top of every file.

---

## Tests

All new code must include tests:

```bash
pytest tests/ -v --cov=pip --cov-report=term-missing
```

Coverage must not drop below the threshold in `pyproject.toml`.

Test file naming: `tests/test_<module_name>.py`.

---

## Pull Request Checklist

- [ ] Tests pass: `pytest tests/ -v`
- [ ] Linter clean: `ruff check pip/`
- [ ] Formatted: `ruff format --check pip/`
- [ ] No new secrets or credentials committed (check with `git diff --staged`)
- [ ] Plugin follows the interface in `example_custom_check.py`
- [ ] Docstrings on all public classes and functions
- [ ] PR description explains the attack vector being added

---

## Security Disclosure

If you find a security issue in PIP itself, please disclose it privately via the
GitHub Security Advisory feature rather than opening a public issue.
See `SECURITY.md` for details.
