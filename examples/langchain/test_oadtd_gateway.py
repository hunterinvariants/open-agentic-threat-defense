"""Tests for the OADTD gateway client against a stub server.

Standard library only — no LangChain, no LLM, no OADTD binary required:
    python -m unittest test_oadtd_gateway
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from oadtd_gateway import ALLOW, OADTDGateway, ToolBlocked


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        command = (body.get("command") or "") + " " + (body.get("arguments") or "")
        tool = body.get("tool_name", "")
        if tool == "unlisted_tool":
            verdict, reason = "deny", "tool not approved"
        elif "api_key" in command or "secret" in command:
            verdict, reason = "require_approval", "secret referenced"
        else:
            verdict, reason = "allow", "ok"
        out = json.dumps({"verdict": verdict, "reason": reason, "risk": "info"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class GatewayClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _StubHandler)
        port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.gateway = OADTDGateway(url=f"http://127.0.0.1:{port}")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_allow(self):
        decision = self.gateway.decide("asset_inventory", command="list assets")
        self.assertEqual(decision.verdict, ALLOW)
        self.gateway.enforce("asset_inventory", command="list assets")  # must not raise

    def test_deny_raises(self):
        with self.assertRaises(ToolBlocked):
            self.gateway.enforce("unlisted_tool", command="anything")

    def test_approval_blocks_by_default(self):
        with self.assertRaises(ToolBlocked):
            self.gateway.enforce("asset_inventory", command="read the api_key")

    def test_approval_allowed_when_opted_in(self):
        decision = self.gateway.enforce("asset_inventory", command="read the api_key", allow_on_approval=True)
        self.assertEqual(decision.verdict, "require_approval")


if __name__ == "__main__":
    unittest.main()
