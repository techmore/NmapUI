from pathlib import Path

from nmapui.google_drive import (
    build_google_drive_auth_status,
    build_google_drive_auth_url,
    ensure_google_drive_access_token,
    exchange_google_drive_auth_code,
    upload_files_to_google_drive,
)


def write_credentials(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '{"installed":{"client_id":"client-123","client_secret":"secret-456"}}'
    )


def test_build_google_drive_auth_url_persists_pending_state(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    write_credentials(credentials_path)

    result = build_google_drive_auth_url(
        credentials_path=credentials_path,
        token_path=token_path,
        redirect_uri="http://127.0.0.1:9000/api/settings/google-drive/callback",
    )

    assert result["success"] is True
    assert "accounts.google.com" in result["auth_url"]
    token_state = __import__("json").loads(token_path.read_text())
    assert token_state["pending_auth"]["state"]
    assert token_state["pending_auth"]["code_verifier"]


def test_exchange_google_drive_auth_code_saves_tokens(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    write_credentials(credentials_path)
    auth_result = build_google_drive_auth_url(
        credentials_path=credentials_path,
        token_path=token_path,
        redirect_uri="http://127.0.0.1:9000/api/settings/google-drive/callback",
    )
    token_state = __import__("json").loads(token_path.read_text())

    class ResponseStub:
        status_code = 200

        @staticmethod
        def json():
            return {
                "access_token": "access-123",
                "refresh_token": "refresh-456",
                "expires_in": 3600,
                "token_type": "Bearer",
            }

    class RequestsStub:
        @staticmethod
        def post(url, data=None, timeout=None):
            assert data["code"] == "code-123"
            return ResponseStub()

    result = exchange_google_drive_auth_code(
        credentials_path=credentials_path,
        token_path=token_path,
        code="code-123",
        state=token_state["pending_auth"]["state"],
        requests_module=RequestsStub,
    )

    assert auth_result["success"] is True
    assert result == {"success": True, "status": "Google Drive connected"}
    saved = __import__("json").loads(token_path.read_text())
    assert saved["access_token"] == "access-123"
    assert saved["refresh_token"] == "refresh-456"
    assert "pending_auth" not in saved


def test_ensure_google_drive_access_token_refreshes_expired_token(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    write_credentials(credentials_path)
    token_path.write_text(
        '{"refresh_token":"refresh-456","access_token":"stale","expires_at":"2020-01-01T00:00:00+00:00"}'
    )

    class ResponseStub:
        status_code = 200

        @staticmethod
        def json():
            return {"access_token": "fresh-123", "expires_in": 3600, "token_type": "Bearer"}

    class RequestsStub:
        @staticmethod
        def post(url, data=None, timeout=None):
            assert data["grant_type"] == "refresh_token"
            return ResponseStub()

    token = ensure_google_drive_access_token(
        credentials_path=credentials_path,
        token_path=token_path,
        requests_module=RequestsStub,
    )

    assert token == "fresh-123"


def test_upload_files_to_google_drive_posts_each_file(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    file_path = tmp_path / "report.pdf"
    write_credentials(credentials_path)
    token_path.write_text('{"access_token":"access-123","expires_at":"2099-01-01T00:00:00+00:00"}')
    file_path.write_bytes(b"pdf-data")
    uploaded_names = []

    class ResponseStub:
        status_code = 200

        def __init__(self, name):
            self.name = name

        def json(self):
            return {"id": f"id-{self.name}", "name": self.name}

    class RequestsStub:
        @staticmethod
        def post(url, headers=None, files=None, timeout=None):
            uploaded_names.append(files["file"][0])
            return ResponseStub(files["file"][0])

    result = upload_files_to_google_drive(
        credentials_path=credentials_path,
        token_path=token_path,
        file_paths=[file_path],
        folder_id="folder-123",
        requests_module=RequestsStub,
    )

    assert result["success"] is True
    assert uploaded_names == ["report.pdf"]


def test_build_google_drive_auth_status_reports_connected_token(tmp_path):
    credentials_path = tmp_path / "credentials.json"
    token_path = tmp_path / "tokens.json"
    write_credentials(credentials_path)
    token_path.write_text('{"refresh_token":"refresh-456"}')

    status = build_google_drive_auth_status(
        credentials_path=credentials_path,
        token_path=token_path,
    )

    assert status["configured"] is True
    assert status["connected"] is True
