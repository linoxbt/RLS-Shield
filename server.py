"""HTTP server for RLS Shield.

This keeps the deployed agent dependency-free while making it easy to test from
the VPS, CI, or a marketplace reviewer. It exposes health, demo, and triage
endpoints using only Python's standard library.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rls_shield_agent import triage_security_findings

ROOT = Path(__file__).resolve().parent
SAMPLE_FINDINGS = """
Circle Webhook Accepts Unauthenticated Requests When Secret Is Unset.
The earnings_calls_select_full_content policy allows rows where price_usdc <= 0.
The user_roles table relies on the prevent_role_escalation trigger.
Public Can Execute SECURITY DEFINER Function without signing in.
Signed-In Users Can Execute SECURITY DEFINER Function.
"""


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _file_response(handler: BaseHTTPRequestHandler, path: Path, content_type: str) -> None:
    body = path.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class RLSShieldHandler(BaseHTTPRequestHandler):
    """Serve RLS Shield over HTTP."""

    server_version = "RLSShield/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        """Use the default compact access log format."""

        super().log_message(format, *args)

    def do_OPTIONS(self) -> None:
        _json_response(self, 200, {"ok": True})

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            _file_response(self, ROOT / "index.html", "text/html; charset=utf-8")
            return

        if path == "/styles.css":
            _file_response(self, ROOT / "styles.css", "text/css; charset=utf-8")
            return

        if path == "/app.js":
            _file_response(self, ROOT / "app.js", "text/javascript; charset=utf-8")
            return

        if path in ("/health", "/api/health"):
            _json_response(
                self,
                200,
                {
                    "status": "ok",
                    "agent": "RLS Shield",
                    "version": "1.0.0",
                    "requires_external_api": False,
                },
            )
            return

        if path in ("/demo", "/api/demo"):
            _json_response(self, 200, triage_security_findings(SAMPLE_FINDINGS))
            return

        _json_response(
            self,
            404,
            {
                "error": "Not found",
                "routes": ["GET /health", "GET /demo", "POST /triage"],
            },
        )

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path not in ("/triage", "/api/triage"):
            _json_response(self, 404, {"error": "Not found", "routes": ["POST /triage"]})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8") if content_length else ""
        scanner_output = raw_body

        if "application/json" in self.headers.get("Content-Type", ""):
            try:
                payload = json.loads(raw_body or "{}")
            except json.JSONDecodeError as exc:
                _json_response(self, 400, {"error": f"Invalid JSON: {exc.msg}"})
                return
            scanner_output = str(payload.get("scanner_output", ""))

        if not scanner_output.strip():
            _json_response(self, 400, {"error": "Provide scanner_output text or a raw text body."})
            return

        _json_response(self, 200, triage_security_findings(scanner_output))


def main() -> None:
    """Run the RLS Shield HTTP server."""

    host = os.getenv("RLS_SHIELD_HOST", "0.0.0.0")
    port = int(os.getenv("RLS_SHIELD_PORT", "8091"))
    server = ThreadingHTTPServer((host, port), RLSShieldHandler)
    print(f"RLS Shield listening on http://{host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
