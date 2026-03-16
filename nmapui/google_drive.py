import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from cryptography.fernet import Fernet, InvalidToken


GOOGLE_DRIVE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_DRIVE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
GOOGLE_DRIVE_UPLOAD_ENDPOINT = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink"
GOOGLE_DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
GOOGLE_DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"


def _format_google_drive_error(payload: dict) -> str:
    if not isinstance(payload, dict):
        return "Unknown error"
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("status") or "Google Drive API error"
        reasons = []
        for entry in error.get("errors", []) or []:
            if isinstance(entry, dict) and entry.get("reason"):
                reasons.append(entry["reason"])
        if reasons:
            unique = ", ".join(sorted(set(reasons)))
            return f"{message} ({unique})"
        return message
    if isinstance(error, str):
        return error
    return payload.get("error_description") or payload.get("message") or "Unknown error"
ENCRYPTED_TOKEN_SCHEMA_VERSION = 1


def _load_json_file(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _save_json_file(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2))
    tmp_path.replace(path)


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


def _load_encrypted_token_payload(token_path: Path, key_path: Path):
    if not token_path.exists():
        return None
    payload = _load_json_file(token_path, {})
    if not isinstance(payload, dict) or "ciphertext" not in payload:
        return None

    ciphertext = payload.get("ciphertext")
    if not ciphertext:
        return {}

    key = _load_or_create_encryption_key(key_path)
    decrypted = Fernet(key).decrypt(str(ciphertext).encode("utf-8"))
    decoded = json.loads(decrypted.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def load_google_drive_credentials(credentials_path: Path) -> dict:
    payload = _load_json_file(credentials_path, {})
    if "installed" in payload:
        payload = payload["installed"]
    if "web" in payload:
        payload = payload["web"]
    return payload if isinstance(payload, dict) else {}


def save_google_drive_credentials(credentials_path: Path, payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {"success": False, "error": "Invalid credentials payload"}
    _save_json_file(credentials_path, payload)
    _set_owner_only_permissions(credentials_path)
    return {"success": True, "status": "Google Drive credentials saved"}


def load_google_drive_token_state(token_path: Path, key_path: Path | None = None) -> dict:
    key_path = key_path or token_path.with_suffix(".key")
    try:
        encrypted_payload = _load_encrypted_token_payload(token_path, key_path)
    except InvalidToken:
        return {}
    if encrypted_payload is not None:
        return encrypted_payload

    payload = _load_json_file(token_path, {})
    if not isinstance(payload, dict):
        return {}
    if payload:
        save_google_drive_token_state(token_path, payload, key_path=key_path)
    return payload


def save_google_drive_token_state(token_path: Path, payload: dict, key_path: Path | None = None) -> dict:
    key_path = key_path or token_path.with_suffix(".key")
    key = _load_or_create_encryption_key(key_path)
    encrypted_payload = Fernet(key).encrypt(json.dumps(payload).encode("utf-8")).decode("utf-8")
    _save_json_file(
        token_path,
        {
            "schema_version": ENCRYPTED_TOKEN_SCHEMA_VERSION,
            "ciphertext": encrypted_payload,
        },
    )
    _set_owner_only_permissions(token_path)
    return payload


def clear_google_drive_token_state(token_path: Path, key_path: Path | None = None) -> None:
    if token_path.exists():
        token_path.unlink()
    key_path = key_path or token_path.with_suffix(".key")
    if key_path.exists():
        key_path.unlink()


def build_google_drive_auth_status(*, credentials_path: Path, token_path: Path, key_path: Path | None = None) -> dict:
    credentials = load_google_drive_credentials(credentials_path)
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    has_refresh_token = bool(token_state.get("refresh_token"))
    has_access_token = bool(token_state.get("access_token"))
    expires_at = token_state.get("expires_at")
    return {
        "configured": bool(credentials.get("client_id") and credentials.get("client_secret")),
        "connected": has_refresh_token or has_access_token,
        "expires_at": expires_at,
        "status": "Connected" if (has_refresh_token or has_access_token) else "Not connected",
    }


def _build_code_verifier() -> str:
    return secrets.token_urlsafe(48)


def _build_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def build_google_drive_auth_url(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    redirect_uri: str,
) -> dict:
    credentials = load_google_drive_credentials(credentials_path)
    if not credentials.get("client_id") or not credentials.get("client_secret"):
        return {
            "success": False,
            "error": f"Missing Google Drive OAuth credentials file at {credentials_path}",
        }

    state = secrets.token_urlsafe(24)
    code_verifier = _build_code_verifier()
    code_challenge = _build_code_challenge(code_verifier)
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    token_state["pending_auth"] = {
        "state": state,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    save_google_drive_token_state(token_path, token_state, key_path=key_path)

    query = urlencode(
        {
            "client_id": credentials["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GOOGLE_DRIVE_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return {"success": True, "auth_url": f"{GOOGLE_DRIVE_AUTH_ENDPOINT}?{query}"}


def exchange_google_drive_auth_code(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    code: str,
    state: str,
    requests_module,
) -> dict:
    credentials = load_google_drive_credentials(credentials_path)
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    pending_auth = token_state.get("pending_auth") or {}
    if not pending_auth or pending_auth.get("state") != state:
        return {"success": False, "error": "Invalid or expired Google Drive auth state."}

    response = requests_module.post(
        GOOGLE_DRIVE_TOKEN_ENDPOINT,
        data={
            "client_id": credentials.get("client_id", ""),
            "client_secret": credentials.get("client_secret", ""),
            "code": code,
            "code_verifier": pending_auth.get("code_verifier", ""),
            "grant_type": "authorization_code",
            "redirect_uri": pending_auth.get("redirect_uri", ""),
        },
        timeout=10,
    )
    payload = response.json()
    if response.status_code >= 400 or "access_token" not in payload:
        return {"success": False, "error": payload.get("error_description") or payload.get("error") or "Failed to exchange Google Drive auth code."}

    expires_in = int(payload.get("expires_in") or 3600)
    token_state.update(
        {
            "access_token": payload.get("access_token"),
            "refresh_token": payload.get("refresh_token") or token_state.get("refresh_token"),
            "scope": payload.get("scope", GOOGLE_DRIVE_SCOPE),
            "token_type": payload.get("token_type", "Bearer"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        }
    )
    token_state.pop("pending_auth", None)
    save_google_drive_token_state(token_path, token_state, key_path=key_path)
    return {"success": True, "status": "Google Drive connected"}


def _token_is_expired(token_state: dict) -> bool:
    expires_at = token_state.get("expires_at")
    if not expires_at:
        return False
    try:
        expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    return expiry <= (datetime.now(timezone.utc) + timedelta(minutes=1))


def ensure_google_drive_access_token(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
) -> str:
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    access_token = token_state.get("access_token")
    if access_token and not _token_is_expired(token_state):
        return access_token

    refresh_token = token_state.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("Google Drive is not connected.")

    credentials = load_google_drive_credentials(credentials_path)
    response = requests_module.post(
        GOOGLE_DRIVE_TOKEN_ENDPOINT,
        data={
            "client_id": credentials.get("client_id", ""),
            "client_secret": credentials.get("client_secret", ""),
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=10,
    )
    payload = response.json()
    if response.status_code >= 400 or "access_token" not in payload:
        raise RuntimeError(payload.get("error_description") or payload.get("error") or "Failed to refresh Google Drive access token.")

    expires_in = int(payload.get("expires_in") or 3600)
    token_state.update(
        {
            "access_token": payload.get("access_token"),
            "token_type": payload.get("token_type", "Bearer"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).isoformat(),
        }
    )
    save_google_drive_token_state(token_path, token_state, key_path=key_path)
    return token_state["access_token"]


def disconnect_google_drive(
    *,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
) -> dict:
    token_state = load_google_drive_token_state(token_path, key_path=key_path)
    token = token_state.get("refresh_token") or token_state.get("access_token")
    if token:
        try:
            requests_module.post(
                GOOGLE_DRIVE_REVOKE_ENDPOINT,
                params={"token": token},
                timeout=10,
            )
        except Exception:
            pass
    clear_google_drive_token_state(token_path, key_path=key_path)
    return {"success": True, "status": "Google Drive disconnected"}


def upload_files_to_google_drive(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    file_paths: list[Path],
    folder_id: str,
    file_name_map: dict[str, str] | None = None,
    requests_module,
) -> dict:
    access_token = ensure_google_drive_access_token(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        requests_module=requests_module,
    )
    uploaded = []
    for file_path in file_paths:
        override_name = (file_name_map or {}).get(str(file_path))
        metadata = {"name": override_name or file_path.name}
        if folder_id:
            metadata["parents"] = [folder_id]
        with file_path.open("rb") as file_handle:
            response = requests_module.post(
                GOOGLE_DRIVE_UPLOAD_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {access_token}",
                },
                files={
                    "metadata": (
                        "metadata.json",
                        json.dumps(metadata).encode("utf-8"),
                        "application/json; charset=UTF-8",
                    ),
                    "file": (file_path.name, file_handle, "application/octet-stream"),
                },
                timeout=30,
            )
        payload = response.json()
        if response.status_code >= 400:
            raise RuntimeError(payload.get("error", {}).get("message") or f"Drive upload failed for {file_path.name}.")
        uploaded.append(payload)

    return {
        "success": True,
        "uploaded": uploaded,
        "status": f"Uploaded {len(uploaded)} file(s) to Google Drive",
    }


def ensure_google_drive_reports_folder(
    *,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
    folder_name: str = "nmapui-reports",
) -> dict:
    access_token = ensure_google_drive_access_token(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        requests_module=requests_module,
    )
    headers = {"Authorization": f"Bearer {access_token}"}
    query = (
        "mimeType='application/vnd.google-apps.folder' "
        f"and name='{folder_name}' and trashed=false"
    )
    response = requests_module.get(
        GOOGLE_DRIVE_FILES_ENDPOINT,
        headers=headers,
        params={"q": query, "fields": "files(id,name)"},
        timeout=10,
    )
    payload = response.json()
    if response.status_code >= 400:
        error_detail = _format_google_drive_error(payload)
        return {
            "success": False,
            "error": f"Failed to query Drive folder (HTTP {response.status_code}): {error_detail}",
        }

    files = payload.get("files") or []
    if files:
        folder_id = files[0].get("id")
        return {"success": True, "folder_id": folder_id, "status": "Drive folder ready"}

    create_response = requests_module.post(
        GOOGLE_DRIVE_FILES_ENDPOINT,
        headers={**headers, "Content-Type": "application/json"},
        json={"name": folder_name, "mimeType": GOOGLE_DRIVE_FOLDER_MIME},
        timeout=10,
    )
    create_payload = create_response.json()
    if create_response.status_code >= 400:
        error_detail = _format_google_drive_error(create_payload)
        return {
            "success": False,
            "error": f"Failed to create Drive folder (HTTP {create_response.status_code}): {error_detail}",
        }
    return {
        "success": True,
        "folder_id": create_payload.get("id"),
        "status": "Drive folder created",
    }


def create_google_drive_folder(
    *,
    name: str,
    parent_id: str | None,
    credentials_path: Path,
    token_path: Path,
    key_path: Path | None = None,
    requests_module,
) -> dict:
    access_token = ensure_google_drive_access_token(
        credentials_path=credentials_path,
        token_path=token_path,
        key_path=key_path,
        requests_module=requests_module,
    )
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    payload = {"name": name, "mimeType": GOOGLE_DRIVE_FOLDER_MIME}
    if parent_id:
        payload["parents"] = [parent_id]
    response = requests_module.post(
        GOOGLE_DRIVE_FILES_ENDPOINT,
        headers=headers,
        json=payload,
        timeout=10,
    )
    create_payload = response.json()
    if response.status_code >= 400:
        error_detail = _format_google_drive_error(create_payload)
        return {
            "success": False,
            "error": f"Failed to create Drive folder (HTTP {response.status_code}): {error_detail}",
        }
    return {
        "success": True,
        "folder_id": create_payload.get("id"),
        "status": "Drive folder created",
    }
