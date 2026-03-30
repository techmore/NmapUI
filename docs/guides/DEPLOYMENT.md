# Deployment notes (unattended / schools)

Use a process manager (`systemd` on Linux, `launchd` on macOS) with `Restart=always` (or `KeepAlive` on macOS).

## Environment file example

Adjust paths and secrets for your site.

```bash
# Listen (defaults: 127.0.0.1 — use a reverse proxy for remote access)
export NMAPUI_HOST=127.0.0.1
export NMAPUI_PORT=5000

# Auth (required for non-trusted clients)
export NMAPUI_USERNAME=scanner
export NMAPUI_PASSWORD=your-secret

# Data and logs (optional overrides)
export NMAPUI_DATA_DIR=/var/lib/nmapui
export NMAPUI_LOG_DIR=/var/log/nmapui

# Long-running / headless: no GitHub update checks or auto-update banner
export NMAPUI_DISABLE_UPDATE_CHECKS=true

# Do not open a browser for “update” actions (servers, CI)
export NMAPUI_SKIP_OPEN=true

# Optional: trust only for local development
# export NMAPUI_TRUST_LOCAL_UI=false
```

## Health checks

- `GET /api/health/live` — process up.
- `GET /api/health/ready` — startup complete; expect `503` until dependencies and traceroute init finish.

## Compliance narrative (non-legal)

NmapUI can support evidence of **periodic scanning**, **retained reports** (local tree under `data/scans/`), and optional **Google Drive** sync for off-site backup. Configure retention and access controls to match your policy and insurance questionnaires.
