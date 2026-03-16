from copy import deepcopy
import json
import os
from pathlib import Path
from typing import Any
import uuid
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

from .auto_monitor import normalize_auto_monitor_settings

SETTINGS_SCHEMA_VERSION = 1
ENCRYPTED_REMOTE_SYNC_SCHEMA_VERSION = 1
DEFAULT_APP_SETTINGS = {
    "schema_version": SETTINGS_SCHEMA_VERSION,
    "target_profiles": [],
    "scan_rules": {
        "scan_only_mode": False,
        "excluded_targets": [],
        "max_scan_minutes": 120,
    },
    "reports": {
        "save_to_desktop": False,
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
            "api_key_configured": False,
            "status": "Not configured",
        },
    },
    "auto_monitor": {
        "defaults": {
            "enabled_by_default": False,
            "recurrence": "weekly",
            "day_of_week": "sunday",
            "time": "01:00",
            "scan_mode": "complete_pdf",
        },
        "rules": [],
    },
}


def _set_owner_only_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_or_create_encryption_key(key_path: Path) -> bytes:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        key = key_path.read_bytes().strip()
        _set_owner_only_permissions(key_path)
        return key

    key = Fernet.generate_key()
    tmp_path = key_path.with_suffix(f"{key_path.suffix}.tmp")
    tmp_path.write_bytes(key)
    tmp_path.replace(key_path)
    _set_owner_only_permissions(key_path)
    return key


def load_remote_sync_secret(*, secret_path: Path, key_path: Path) -> str:
    if not secret_path.exists():
        return ""

    try:
        payload = json.loads(secret_path.read_text())
    except Exception:
        return ""

    ciphertext = str((payload or {}).get("ciphertext", "") or "").strip()
    if not ciphertext:
        return ""

    try:
        key = _load_or_create_encryption_key(key_path)
        decrypted = Fernet(key).decrypt(ciphertext.encode("utf-8"))
    except (InvalidToken, ValueError, OSError):
        return ""

    return str(decrypted.decode("utf-8")).strip()


def save_remote_sync_secret(*, secret_path: Path, key_path: Path, api_key: str) -> None:
    api_key = str(api_key or "").strip()
    if not api_key:
        clear_remote_sync_secret(secret_path=secret_path, key_path=key_path)
        return

    key = _load_or_create_encryption_key(key_path)
    encrypted_payload = Fernet(key).encrypt(api_key.encode("utf-8")).decode("utf-8")
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = secret_path.with_suffix(f"{secret_path.suffix}.tmp")
    tmp_path.write_text(
        json.dumps(
            {
                "schema_version": ENCRYPTED_REMOTE_SYNC_SCHEMA_VERSION,
                "ciphertext": encrypted_payload,
            },
            indent=2,
        )
    )
    tmp_path.replace(secret_path)
    _set_owner_only_permissions(secret_path)


def clear_remote_sync_secret(*, secret_path: Path, key_path: Path) -> None:
    if secret_path.exists():
        secret_path.unlink()
    if key_path.exists():
        key_path.unlink()


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
    scan_rules = profile.get("scan_rules")
    return {
        "id": str(profile.get("id") or uuid.uuid4().hex[:12]),
        "name": str(profile.get("name", "") or "").strip(),
        "target": str(profile.get("target", "") or "").strip(),
        "customer_id": str(profile.get("customer_id", "") or "").strip(),
        "customer_name": str(profile.get("customer_name", "") or "").strip(),
        "notes": str(profile.get("notes", "") or "").strip(),
        "scan_rules": {
            "scan_only_mode": bool((scan_rules or {}).get("scan_only_mode", False)),
            "excluded_targets": _normalize_string_list(
                (scan_rules or {}).get("excluded_targets", [])
            ),
            "max_scan_minutes": int((scan_rules or {}).get("max_scan_minutes", 120) or 120),
        },
    }


def normalize_settings_document(
    document: Any,
    *,
    remote_sync_api_key_configured: bool | None = None,
    customer_name_lookup=None,
) -> dict[str, Any]:
    document = document if isinstance(document, dict) else {}
    scan_rules = document.get("scan_rules")
    reports = document.get("reports")
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
            "max_scan_minutes": int((scan_rules or {}).get("max_scan_minutes", 120) or 120),
        },
        "reports": {
            "save_to_desktop": bool((reports or {}).get("save_to_desktop", False)),
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
                "api_key": "",
                "api_key_configured": (
                    bool(remote_sync_api_key_configured)
                    if remote_sync_api_key_configured is not None
                    else bool(str((remote_sync or {}).get("api_key", "") or "").strip())
                ),
                "status": str(
                    (remote_sync or {}).get("status", "Not configured") or "Not configured"
                ).strip(),
            },
        },
        "auto_monitor": normalize_auto_monitor_settings(
            document.get("auto_monitor", {}),
            customer_name_lookup=customer_name_lookup,
        ),
    }


def load_settings_state(
    *,
    settings_path,
    load_json_document,
    remote_sync_secret_path: Path | None = None,
    remote_sync_secret_key_path: Path | None = None,
) -> dict[str, Any]:
    raw_document = load_json_document(settings_path, deepcopy(DEFAULT_APP_SETTINGS))
    remote_sync = (raw_document or {}).get("sync", {}).get("remote_sync", {})
    legacy_api_key = str((remote_sync or {}).get("api_key", "") or "").strip()
    stored_api_key = ""
    if remote_sync_secret_path is not None and remote_sync_secret_key_path is not None:
        stored_api_key = load_remote_sync_secret(
            secret_path=remote_sync_secret_path,
            key_path=remote_sync_secret_key_path,
        )
        if legacy_api_key and not stored_api_key:
            save_remote_sync_secret(
                secret_path=remote_sync_secret_path,
                key_path=remote_sync_secret_key_path,
                api_key=legacy_api_key,
            )
            stored_api_key = legacy_api_key

    normalized = normalize_settings_document(
        raw_document,
        remote_sync_api_key_configured=bool(stored_api_key or legacy_api_key),
    )
    if legacy_api_key:
        normalized["sync"]["remote_sync"]["api_key"] = ""
    return normalized


def save_settings_state(
    *,
    settings_path,
    save_json_document,
    settings_state,
    remote_sync_secret_path: Path | None = None,
    remote_sync_secret_key_path: Path | None = None,
) -> dict[str, Any]:
    raw_remote_sync = (settings_state or {}).get("sync", {}).get("remote_sync", {})
    incoming_api_key = str((raw_remote_sync or {}).get("api_key", "") or "").strip()
    existing_api_key = ""
    if remote_sync_secret_path is not None and remote_sync_secret_key_path is not None:
        existing_api_key = load_remote_sync_secret(
            secret_path=remote_sync_secret_path,
            key_path=remote_sync_secret_key_path,
        )
        if incoming_api_key:
            save_remote_sync_secret(
                secret_path=remote_sync_secret_path,
                key_path=remote_sync_secret_key_path,
                api_key=incoming_api_key,
            )
        elif existing_api_key:
            save_remote_sync_secret(
                secret_path=remote_sync_secret_path,
                key_path=remote_sync_secret_key_path,
                api_key=existing_api_key,
            )

    normalized = normalize_settings_document(
        settings_state,
        remote_sync_api_key_configured=bool(incoming_api_key or existing_api_key),
    )
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


def get_effective_scan_rules(*, settings_state, target="", customer_id="") -> dict[str, Any]:
    normalized = normalize_settings_document(settings_state)
    global_rules = normalized.get("scan_rules", {})
    target = str(target or "").strip()
    customer_id = str(customer_id or "").strip()

    matched_profile = None
    for profile in normalized.get("target_profiles", []):
        if target and str(profile.get("target", "") or "").strip() != target:
            continue
        profile_customer_id = str(profile.get("customer_id", "") or "").strip()
        if profile_customer_id and customer_id and profile_customer_id != customer_id:
            continue
        matched_profile = profile
        break

    if matched_profile is None:
        return {
            "scan_only_mode": bool(global_rules.get("scan_only_mode", False)),
            "excluded_targets": _normalize_string_list(
                global_rules.get("excluded_targets", [])
            ),
            "max_scan_minutes": int(global_rules.get("max_scan_minutes", 120) or 120),
        }

    profile_rules = matched_profile.get("scan_rules", {})
    return {
        "scan_only_mode": bool(
            profile_rules.get("scan_only_mode", global_rules.get("scan_only_mode", False))
        ),
        "excluded_targets": _normalize_string_list(
            profile_rules.get("excluded_targets", global_rules.get("excluded_targets", []))
        ),
        "max_scan_minutes": int(
            (profile_rules.get("max_scan_minutes") or 0)
            or global_rules.get("max_scan_minutes", 120)
            or 120
        ),
    }
