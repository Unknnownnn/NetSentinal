import hashlib
import requests
import time
from typing import Optional

VT_BASE = "https://www.virustotal.com/api/v3"

class VirusTotalScanner:
    def __init__(self, api_key: Optional[str] = None, session: Optional[requests.Session] = None):
        self.api_key = api_key
        self.session = session or requests.Session()
        if api_key:
            self.session.headers.update({"x-apikey": api_key})

    def set_api_key(self, api_key: str):
        self.api_key = api_key
        self.session.headers.update({"x-apikey": api_key})

    def compute_hashes(self, file_bytes: bytes) -> dict:
        return {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest()
        }

    def scan_hash(self, hash_value: str) -> dict:
        """Lookup a file by hash on VirusTotal (requires API key)"""
        if not self.api_key:
            raise ValueError("VirusTotal API key not set")

        url = f"{VT_BASE}/files/{hash_value}"
        
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        # Use explicit headers for this request
        resp = self.session.get(url, headers=headers)
        
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError as e:
                return {"status": "json_error", "code": resp.status_code, "detail": f"JSON parse error: {str(e)}", "raw_response": resp.text}
        elif resp.status_code == 404:
            return {"status": "not_found", "code": 404, "message": "File not found in VirusTotal database"}
        else:
            return {"status": "error", "code": resp.status_code, "detail": resp.text}

    def upload_file(self, file_bytes: bytes, filename: str = "upload.bin") -> dict:
        """Upload file for scanning using correct VirusTotal API format."""
        if not self.api_key:
            raise ValueError("VirusTotal API key not set")

        url = f"{VT_BASE}/files"
        
        # Use correct VirusTotal API format
        files = {"file": (filename, file_bytes, "application/octet-stream")}
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        
        # Remove x-apikey from session headers temporarily to avoid conflicts
        session_headers = self.session.headers.copy()
        self.session.headers.clear()
        self.session.headers.update(headers)
        
        try:
            resp = self.session.post(url, files=files)
            
            if resp.status_code in (200, 201):
                try:
                    return resp.json()
                except ValueError as e:
                    return {"status": "json_error", "code": resp.status_code, "detail": f"JSON parse error: {str(e)}", "raw_response": resp.text}
            else:
                return {"status": "error", "code": resp.status_code, "detail": resp.text}
                
        finally:
            # Restore original session headers
            self.session.headers.clear()
            self.session.headers.update(session_headers)

# Simple module-level scanner instance (can be configured from main)
scanner = VirusTotalScanner()
