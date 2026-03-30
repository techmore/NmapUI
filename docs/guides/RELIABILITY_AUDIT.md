# NmapUI reliability audit (reference)

Short inventory for long-running and compliance-oriented deployments (private schools, evidence of network assessment cadence).

## Correctness

- **`nmapui/runtime.py`**: Type hints on `_select_release_asset` must not reference undefined names (use `str | None` or import `Optional`).
- **Update opener**: Socket handler must not assume macOS `open`; use `webbrowser` or skip when headless.

## Headless / server

- **`perform_app_update`**: Opening the download URL must respect `NMAPUI_SKIP_OPEN` / `NMAPUI_HEADLESS` so CI and servers do not invoke a GUI opener.
- **Idle / GitHub**: Automatic idle checks call the GitHub API; use `NMAPUI_DISABLE_UPDATE_CHECKS` to avoid network calls and auto-update UI on 24/7 or kiosk installs.

## Google Drive OAuth

- Access tokens refresh from stored refresh tokens (`ensure_google_drive_access_token`).
- Org policy or long inactivity can revoke refresh tokens; plan occasional re-authorization in the UI if uploads fail with auth errors.

## Security (non-interactive)

- Set `NMAPUI_USERNAME` and `NMAPUI_PASSWORD` for production; avoid `NMAPUI_TRUST_LOCAL_UI` except local development.
- See [DEPLOYMENT.md](DEPLOYMENT.md) for environment variables.
