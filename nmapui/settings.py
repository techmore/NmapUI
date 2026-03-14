from copy import deepcopy
from pathlib import Path
from typing import Any
import uuid
from urllib.parse import urlparse


SETTINGS_SCHEMA_VERSION = 1
DEFAULT_APP_SETTINGS = {
    "schema_version": SETTINGS_SCHEMA_VERSION,
    "target_profiles": [],
    "scan_rules": {
        "scan_only_mode": False,
        "excluded_targets": [],
    },
    "sync": {
        "google_drive": {
            "enabled": False,
            "folder_id": "",
            "status": "Not configured",
        },
        "remote_sync": {
            "enabled": False,
            "endpoint": "",
            "api_key": "",
            "api_key_configured": False,
            "status": "Not configured",
        },
    },
}


def _normalize_string_list(values: Any) -> list[str]:
    if isinstance(values, str):
        values = values.replace(",", "\n").splitlines()
    if not isinstance(values, list):
        values = []

    normalized = []
    seen = set()
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def normalize_target_profile(profile: Any) -> dict[str, Any]:
    profile = profile if isinstance(profile, dict) else {}
    return {
        "id": str(profile.get("id") or uuid.uuid4().hex[:12]),
        "name": str(profile.get("name", "") or "").strip(),
        "target": str(profile.get("target", "") or "").strip(),
        "customer_id": str(profile.get("customer_id", "") or "").strip(),
        "customer_name": str(profile.get("customer_name", "") or "").strip(),
        "notes": str(profile.get("notes", "") or "").strip(),
    }


def normalize_settings_document(document: Any) -> dict[str, Any]:
    document = document if isinstance(document, dict) else {}
    scan_rules = document.get("scan_rules")
    sync = document.get("sync")
    google_drive = sync.get("google_drive") if isinstance(sync, dict) else {}
    remote_sync = sync.get("remote_sync") if isinstance(sync, dict) else {}

    target_profiles = []
    for profile in document.get("target_profiles") or []:
        normalized = normalize_target_profile(profile)
        if normalized["name"] and normalized["target"]:
            target_profiles.append(normalized)

    return {
        "schema_version": int(
            document.get("schema_version", SETTINGS_SCHEMA_VERSION)
        ),
        "target_profiles": target_profiles,
        "scan_rules": {
            "scan_only_mode": bool(
                (scan_rules or {}).get("scan_only_mode", False)
            ),
            "excluded_targets": _normalize_string_list(
                (scan_rules or {}).get("excluded_targets", [])
            ),
        },
        "sync": {
            "google_drive": {
                "enabled": bool((google_drive or {}).get("enabled", False)),
                "folder_id": str((google_drive or {}).get("folder_id", "") or "").strip(),
                "status": str(
                    (google_drive or {}).get("status", "Not configured") or "Not configured"
                ).strip(),
            },
            "remote_sync": {
                "enabled": bool((remote_sync or {}).get("enabled", False)),
                "endpoint": str((remote_sync or {}).get("endpoint", "") or "").strip(),
                "api_key": str((remote_sync or {}).get("api_key", "") or "").strip(),
                "api_key_configured": bool(
                    str((remote_sync or {}).get("api_key", "") or "").strip()
                ),
                "status": str(
                    (remote_sync or {}).get("status", "Not configured") or "Not configured"
                ).strip(),
            },
        },
    }


def load_settings_state(*, settings_path, load_json_document) -> dict[str, Any]:
    return normalize_settings_document(
        load_json_document(settings_path, deepcopy(DEFAULT_APP_SETTINGS))
    )


def save_settings_state(*, settings_path, save_json_document, settings_state) -> dict[str, Any]:
    normalized = normalize_settings_document(settings_state)
    save_json_document(settings_path, normalized)
    return normalized


def validate_google_drive_settings(*, folder_id, credentials_path: Path) -> dict[str, Any]:
    folder_id = str(folder_id or "").strip()

    if folder_id and not all(ch.isalnum() or ch in "-_" for ch in folder_id):
        return {
            "success": False,
            "status": "Invalid folder ID format",
            "error": "Drive folder IDs should contain only letters, numbers, dashes, and underscores.",
        }

    if not credentials_path.exists():
        return {
            "success": False,
            "status": "OAuth credentials missing",
            "error": f"Missing Google Drive OAuth credentials file at {credentials_path}",
        }

    return {
        "success": True,
        "status": "Ready for Google Drive auth",
        "details": "OAuth credentials are present. Complete Drive auth separately before enabling uploads.",
    }


def validate_remote_sync_settings(*, endpoint, api_key, requests_module, timeout=5) -> dict[str, Any]:
    endpoint = str(endpoint or "").strip()
    api_key = str(api_key or "").strip()

    if not endpoint:
        return {
            "success": False,
            "status": "Endpoint required",
            "error": "Remote sync endpoint is required.",
        }

    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc:
        return {
            "success": False,
            "status": "Invalid endpoint",
            "error": "Remote sync endpoint must be a valid HTTPS URL.",
        }

    if not api_key:
        return {
            "success": False,
            "status": "API key required",
            "error": "Remote sync API key is required.",
        }

    try:
        response = requests_module.get(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "NmapUI settings validation",
            },
            timeout=timeout,
        )
    except Exception as exc:
        return {
            "success": False,
            "status": "Endpoint unreachable",
            "error": str(exc),
        }

    if 200 <= response.status_code < 300:
        return {
            "success": True,
            "status": "Remote sync credentials accepted",
            "details": f"Remote endpoint responded with HTTP {response.status_code}.",
        }

    if response.status_code in (401, 403):
        return {
            "success": False,
            "status": "API key rejected",
            "error": f"Remote endpoint rejected the API key with HTTP {response.status_code}.",
        }

    return {
        "success": False,
        "status": "Endpoint responded unexpectedly",
        "error": f"Remote endpoint returned HTTP {response.status_code}.",
    }
