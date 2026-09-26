from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .demo import DemoRunner
from .policy import PolicyEngine
from .scanner import RepositoryScanner

_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
_MAX_BODY = 65536


class ContextSentryService:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.engine = PolicyEngine(root=self.root)
        self.scanner = RepositoryScanner(self.root)
        self.demo = DemoRunner(self.engine)
        self.web_root = Path(__file__).resolve().parent.parent / "web"
        self.started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def state(self) -> dict[str, Any]:
        return {
            "product": "ContextSentry",
            "version": __version__,
            "started_at": self.started_at,
            "system": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "mode": self.engine.policy.get("mode", "enforce"),
                "workspace": self.root.name,
            },
            "policy": self.engine.summary(),
            "audit": self.engine.audit.summary(),
            "sessions": {"tainted": self.engine.sessions.count_tainted()},
            "demo": self.demo.status(),
        }

    def report(self) -> dict[str, Any]:
        findings = self.scanner.scan("demo/poisoned_repo")
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "product": "ContextSentry",
            "version": __version__,
            "policy": self.engine.summary(),
            "audit": self.engine.audit.summary(),
            "demo": self.demo.status(),
            "repository_scan": findings,
        }


def create_server(host: str, port: int, root: Path | str) -> ThreadingHTTPServer:
    service = ContextSentryService(root)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ContextSentry/0.1"

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/api/health":
                self._json({"status": "ok", "version": __version__})
                return
            if parsed.path == "/api/state":
                self._json(service.state())
                return
            if parsed.path == "/api/audit":
                try:
                    limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
                except (TypeError, ValueError):
                    self._error(HTTPStatus.BAD_REQUEST, "Invalid audit limit")
                    return
                try:
                    events = service.engine.audit.records(max(1, min(limit, 500)))
                    verification = service.engine.audit.verify()
                except (OSError, ValueError, json.JSONDecodeError) as error:
                    events = []
                    verification = {"valid": False, "error": str(error)}
                self._json({"events": events, "verification": verification})
                return
            if parsed.path == "/api/findings":
                query = parse_qs(parsed.query)
                relative = query.get("path", ["demo/poisoned_repo"])[0]
                self._json(service.scanner.scan(relative))
                return
            if parsed.path == "/api/report":
                payload = json.dumps(service.report(), ensure_ascii=False, indent=2).encode("utf-8")
                self._send(HTTPStatus.OK, payload, "application/json; charset=utf-8", {"Content-Disposition": "attachment; filename=contextsentry-report.json"})
                return
            if parsed.path in _STATIC_FILES:
                filename, content_type = _STATIC_FILES[parsed.path]
                try:
                    payload = (service.web_root / filename).read_bytes()
                except OSError:
                    self._error(HTTPStatus.NOT_FOUND, "Asset unavailable")
                    return
                self._send(HTTPStatus.OK, payload, content_type)
                return
            if parsed.path == "/favicon.ico":
                self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
                return
            self._error(HTTPStatus.NOT_FOUND, "Not found")

        def do_POST(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path == "/api/demo":
                state = service.demo.start()
                self._json(state, HTTPStatus.ACCEPTED)
                return
            if parsed.path == "/api/reset":
                service.demo.reset()
                service.engine.sessions.clear()
                service.engine.audit.clear()
                self._json({"status": "reset"})
                return
            if parsed.path == "/api/scan":
                try:
                    body = self._body()
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    self._error(HTTPStatus.BAD_REQUEST, f"Invalid request body: {error}")
                    return
                relative = str(body.get("path", "demo/poisoned_repo"))
                self._json(service.scanner.scan(relative))
                return
            self._error(HTTPStatus.NOT_FOUND, "Not found")

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > _MAX_BODY:
                raise ValueError("Request body too large")
            raw = self.rfile.read(length)
            if not raw:
                return {}
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("Expected a JSON object")
            return value

        def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send(status, payload, "application/json; charset=utf-8")

        def _error(self, status: HTTPStatus, message: str) -> None:
            self._json({"error": message}, status)

        def _send(self, status: HTTPStatus, payload: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> int:
    parser = argparse.ArgumentParser(prog="contextsentry")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--root", default=str(Path.cwd()), type=Path)
    arguments = parser.parse_args()
    server = create_server(arguments.host, arguments.port, arguments.root)
    print(f"ContextSentry listening on http://{arguments.host}:{arguments.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
