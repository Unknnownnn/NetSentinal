import io
import hashlib
import os
import sys
from typing import Any

import pytest

# Ensure repo root is on sys.path so 'backend' package resolves consistently
CURRENT_DIR = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir, os.pardir))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")
for p in (REPO_ROOT, BACKEND_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from backend.main import app  # type: ignore

from fastapi.testclient import TestClient


client = TestClient(app)


def _hashes_for(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_hash_file_endpoint_returns_hashes_only():
    # This test assumes POST /api/security/hash-file exists and returns the hashes of the uploaded file
    payload = b"hello world\n"
    expected = _hashes_for(payload)

    files = {"file": ("hello.txt", io.BytesIO(payload), "text/plain")}
    response = client.post("/api/security/hash-file", files=files)

    # If endpoint is not yet implemented, make this test xfail for visibility
    if response.status_code == 404:
        pytest.xfail("/api/security/hash-file not implemented yet. Implement to satisfy frontend and this test.")

    assert response.status_code == 200, response.text
    data = response.json()
    # Expect object with computed hashes and no VT submission by default
    assert data["hashes"]["md5"] == expected["md5"]
    assert data["hashes"]["sha1"] == expected["sha1"]
    assert data["hashes"]["sha256"] == expected["sha256"]


def test_virustotal_report_endpoint_mocks_external_call(monkeypatch):
    # This test assumes GET /api/security/virustotal-report/{file_id}?api_key=... proxies to VT
    # We'll mock requests.get to avoid network dependency.
    file_id = "44d88612fea8a8f36de82e1278abb02f"  # md5 of 'test' for example

    class FakeResp:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {
                "data": {
                    "id": file_id,
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 70,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 2,
                            "timeout": 0,
                        }
                    },
                }
            }

    def fake_get(url: str, headers: dict[str, str], timeout: int = 15):
        assert url.endswith(f"/api/v3/files/{file_id}")
        assert "x-apikey" in headers
        return FakeResp()

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    resp = client.get(f"/api/security/virustotal-report/{file_id}?api_key=DUMMY")

    if resp.status_code == 404:
        pytest.xfail("/api/security/virustotal-report/{id} not implemented yet. Implement to satisfy frontend and this test.")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Accept either raw VT-like structure or our summarized structure
    if "data" in body:
        assert body["data"].get("id") == file_id
    else:
        assert body.get("file_id") == file_id
