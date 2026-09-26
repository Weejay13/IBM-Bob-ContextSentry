from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from contextsentry.server import create_server


class ServerTests(unittest.TestCase):
    root = Path(__file__).resolve().parent.parent

    def setUp(self) -> None:
        self.server = create_server("127.0.0.1", 0, self.root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def get(self, path: str):
        with urlopen(f"{self.base}{path}", timeout=3) as response:
            return response.status, response.headers.get("Content-Type", ""), response.read()

    def post(self, path: str):
        request = Request(f"{self.base}{path}", data=b"{}", method="POST", headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())

    def test_health_endpoint(self) -> None:
        status, content_type, body = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_dashboard_and_apis(self) -> None:
        status, content_type, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn(b"ContextSentry", body)
        status, _, body = self.get("/api/findings?path=demo%2Fpoisoned_repo")
        self.assertEqual(status, 200)
        self.assertGreater(len(json.loads(body)["findings"]), 0)

    def test_demo_start_endpoint(self) -> None:
        status, payload = self.post("/api/demo")
        self.assertEqual(status, 202)
        self.assertIn(payload["status"], {"running", "complete"})

    def test_missing_route_returns_404(self) -> None:
        with self.assertRaises(HTTPError) as context:
            self.get("/missing")
        self.assertEqual(context.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
