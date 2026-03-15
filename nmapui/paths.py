from pathlib import Path
from typing import Optional


BASE_DIR = Path(__file__).resolve().parents[1]
VULNERS_SCRIPT = BASE_DIR / "nmap-vulners" / "vulners.nse"
XSL_STYLESHEET = BASE_DIR / "nmap-modern.xsl"
XSL_STYLESHEET_PDF = BASE_DIR / "nmap-pdf-olive-legacy.xsl"
SCANS_DIR = BASE_DIR / "data" / "scans"
VERSION_FILE = BASE_DIR / "VERSION"
CURRENT_ASSIGNMENT_FILE = BASE_DIR / "data" / "current_assignment.json"
AUTO_SCAN_CONFIG_FILE = BASE_DIR / "auto_scan_config.json"
AUTO_SCAN_CONFIG_EXAMPLE_FILE = BASE_DIR / "config" / "auto_scan_config.example.json"
AUTO_SCAN_SCHEDULER_LOCK_FILE = BASE_DIR / "data" / "auto_scan_scheduler.lock"
SETTINGS_FILE = BASE_DIR / "data" / "settings.json"
RUNTIME_DB_FILE = BASE_DIR / "data" / "runtime.sqlite3"
GOOGLE_DRIVE_CREDENTIALS_FILE = BASE_DIR / "config" / "google_drive_credentials.json"
GOOGLE_DRIVE_TOKEN_FILE = BASE_DIR / "data" / "google_drive_tokens.json"
GOOGLE_DRIVE_TOKEN_KEY_FILE = BASE_DIR / "data" / "google_drive_tokens.key"
REMOTE_SYNC_SECRET_FILE = BASE_DIR / "data" / "remote_sync_secret.json"
REMOTE_SYNC_SECRET_KEY_FILE = BASE_DIR / "data" / "remote_sync_secret.key"


def resolve_scan_path(path: str) -> Optional[Path]:
    """Resolve a user-provided scan path and ensure it stays inside SCANS_DIR."""
    if not path:
        return None

    try:
        scan_dir = (SCANS_DIR / path).resolve()
        scans_root = SCANS_DIR.resolve()
    except (OSError, RuntimeError):
        return None

    try:
        scan_dir.relative_to(scans_root)
    except ValueError:
        return None

    return scan_dir
