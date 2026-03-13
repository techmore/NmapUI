# Repository Layout

This project keeps a small root and pushes specialized assets into dedicated directories.

## Canonical Layout

- `/`
  - Stable entrypoints and top-level project metadata
  - Examples: `app.py`, `requirements.txt`, `README.md`, `install.sh`, `deploy.sh`
- `packaging/macos/`
  - macOS menu bar wrapper source and wrapper-specific documentation
- `packaging/pyinstaller/`
  - PyInstaller spec and packaging configuration
- `docs/guides/`
  - setup, testing, release, and contributor-facing guides
- `docs/notes/`
  - implementation notes, work plans, and one-off analysis documents
- `docs/audits/`
  - audit reports and detailed investigation writeups
- `tests/`
  - automated regression coverage

## Root Rules

Keep the repository root limited to files that a contributor should expect to open immediately when building, running, or packaging the app.

Do not add the following to the root:

- generated binaries or app bundles
- screenshots or sample outputs
- one-off analysis markdown files
- wrapper-specific documentation
- packaging-only configuration that can live under `packaging/`
