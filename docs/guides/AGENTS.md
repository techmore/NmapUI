AGENTS.md

Overview
- This repository hosts a Python-based Flask application (NmapUI) with a lightweight front-end and a real-time data pipeline via Socket.IO. It also includes optional ARP scanning, Vulners-based CVE detection, and a traceroute-based network fingerprint.
- AGENTS.md provides guidance for automated agents that operate within this repository (build, test, lint, run, and code changes).

Repository conventions
- Language: Python 3.x, with optional Node assets for the UI, but Python-based tests and scripts drive the primary logic.
- Tests: Pytest is assumed for unit/integration tests if present.
- Linters/Formatters: flake8, mypy, and Black recommended.
- Documentation: AGENTS.md is the authoritative guide for agent behavior when running changes in this repo.

1) Build / lint / test commands
- Environment setup (macOS/Linux):
  - python3 -m venv .venv
  - source .venv/bin/activate
  - pip install -r requirements.txt
  - if using tests: pip install pytest pytest-mock
- Run lint (preferable first):
  - flake8 .
  - isort . --diff --check-only
  - black --check .
- Run type checks (if mypy configured):
  - mypy src || true
- Run tests (all):
  - pytest -q
- Run a single test (examples):
  - pytest -q tests/test_scan.py::TestQuickScan::test_snmp
  - pytest -k "arp" -q
- Build / packaging (optional):
  - python -m pip install --upgrade pip
  - python -m pip install build
  - python -m build
- Local app run (manual):
  - python app.py
  - Visit http://127.0.0.1:9000
- Documentation/test with CI-like checks:
  - Keep a minimal test matrix in CI (Python version, dependencies) to catch environment issues.

2) Code style guidelines
- General
  - Follow PEP8: line length 88 (Black default).
  - Prefer explicit code paths; minimize complex one-liners.
- Imports
  - Group imports in three blocks: standard library, third-party, local modules.
  - Put a blank line between groups.
  - Sort imports with isort.
- Formatting
  - Use Black for code formatting; enforce in CI.
  - Add meaningful docstrings for public APIs (module, class, function).
- Typing
  - Use type hints on public functions and API boundaries.
  - Import typing types: List, Dict, Optional, Tuple, Any.
  - Where appropriate, use TypedDict for structured dicts.
- Naming conventions
  - Functions/variables: snake_case
  - Classes: CamelCase
  - Constants: UPPER_SNAKE
- Error handling
  - Avoid bare except; catch specific exceptions.
  - Log errors with Python logging module; do not swallow exceptions silently.
  - Surface user-friendly error messages where appropriate.
- Logging and observability
  - Prefer logging over print statements for runtime info and errors.
  - Include timestamps, levels, and context in logs.
- Testing
  - Tests should be hermetic: mock external calls, avoid real network I/O.
  - Use fixtures to setup/teardown resources.
  - Name tests clearly to reflect behavior being tested.
- Security
  - Never commit credentials or secrets; use env vars/CI secrets.
  - Validate and sanitize external input.
  - Use timeouts and sane retry logic for external calls.
- ARP Scan integration
  - If ARP scanning is optional behind a feature flag, ensure default behavior is non-destructive.
  - Guard external tool invocation; provide clear user-facing messages if unavailable.
- Accessibility and UX
  - Ensure UI text is legible; provide alt text for images; consider keyboard navigation basics.
- ARP Scan integration
  - If ARP scanning is used, guard external tool usage behind a feature flag; document expectations.
-  - Provide a mechanism to opt-out of ARP on startup if needed.

3) Cursor rules (if any)
- If a Cursor policy exists, it will be under .cursor/rules/ or .cursorrules directory.
- Include: allowed commands, safe patterns, and disallowed operations; implementable in agent code.

4) Copilot rules (if any)
- If there is a Copilot policy (e.g., .github/copilot-instructions.md), include a concise summary:
  - Do not rely solely on Copilot for critical logic; verify all changes manually.
  - Ensure security-sensitive code is reviewed; add tests around Copilot-generated changes.

5) Guidance for agents
- Agents should:
  - Run in isolated environments; do not modify global system state beyond project scope
  - Use virtualenv or project-local environments
  - Respect existing codebase patterns; follow the repository's conventions
  - Prefer small, atomic commits with descriptive messages
  - Run targeted tests first before broader test suites
- On failure:
  - Log root cause; do not mask failures; add a follow-up task if needed
- If scope changes, update AGENTS.md before proceeding

6) Versioned format and merge policy
- For PRs: title begins with type and short summary; description includes rationale, tests, and any breaking changes
- Follow the repository's main branch policy; do not force-push to main unless user instructs

Notes
- If you have .cursor or .github copilot rules in this repo, place this AGENTS.md content in the repository root so agents see it during tasks.
