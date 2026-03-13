# Stable Release Checklist

Use this checklist when preparing the next stable NmapUI release.

## Build Readiness

- `python -m py_compile app.py` passes
- `pip install -r requirements.txt` succeeds in a clean virtualenv
- `VERSION` is present and correct for the release
- Local branch is pushed and reviewable

## Runtime Smoke Test

```bash
source .venv/bin/activate
NMAPUI_HOST=127.0.0.1 NMAPUI_PORT=9000 NMAPUI_DEBUG=false python app.py --quick &
APP_PID=$!
sleep 5
curl http://127.0.0.1:9000/api/health
kill $APP_PID
```

Expected:
- Health response includes `status: ok`
- `app_version` is populated

## Core Manual Checks

- Quick Scan starts and completes
- Generate PDF starts and streams progress
- Stop cancels an active scan or report
- Archive/history view opens
- HTML/XML/PDF artifact links work for an existing scan
- Auto-scan settings save and reload correctly

## Packaging Checks

- `pyinstaller --clean packaging/pyinstaller/nmapui.spec` succeeds
- `dist/NmapUI.app` launches
- Packaged app responds on `http://127.0.0.1:9000/api/health`

## Release Notes

- Document major changes since the previous stable build
- Call out any known limitations
- Note required system dependencies: `nmap`, `xsltproc`, `wkhtmltopdf` or fallback PDF tooling
