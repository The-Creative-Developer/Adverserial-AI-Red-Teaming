"""Tests for demo/local_model_demo.py using a fake model server on 127.0.0.1.

No real model is involved: the fake server plays a "model" that is fooled
whenever the text mentions 'ignore', 'disregard' or 'code'.
"""

import contextlib
import io
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))

import assistant as a  # noqa: E402
import local_model_demo as lm  # noqa: E402

DOCS = a.load_docs(a.DEFAULT_DOCS)


def make_handler(always=None, status=200):
    class Handler(BaseHTTPRequestHandler):
        seen = []

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            Handler.seen.append((self.path, body))
            text = body["messages"][-1]["content"].lower()
            fooled = any(w in text for w in ("ignore", "disregard", "code"))
            tool = always or ("read_private" if fooled else "answer_faq")
            reply = json.dumps({"tool": tool})
            if self.path == "/api/chat":
                out = {"message": {"role": "assistant", "content": reply}}
            else:
                out = {"choices": [{"message": {"content": reply}}]}
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(out).encode())

        def log_message(self, *args):
            pass

    return Handler


@contextlib.contextmanager
def fake_server(**kw):
    handler = make_handler(**kw)
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", handler
    finally:
        srv.shutdown()
        srv.server_close()


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = lm.main(["--no-color", *argv])
    return code, out.getvalue(), err.getvalue()


class TestLocalModel(unittest.TestCase):
    def test_fooled_model_leaks_when_vulnerable_but_never_when_secure(self):
        with fake_server() as (url, _):
            code, out, _ = run_cli("--base-url", url)
        self.assertEqual(code, 0)
        self.assertIn("SECRET LEAK", out)
        secure_part = out.split("MODE: SECURE")[1].split("BEFORE / AFTER")[0]
        self.assertNotIn(a.SECRET, secure_part)

    def test_secure_mode_holds_even_if_model_always_asks_for_the_secret(self):
        with fake_server(always="read_private") as (url, _):
            code, out, _ = run_cli("--base-url", url, "--mode", "secure")
        self.assertEqual(code, 0)
        self.assertNotIn(a.SECRET, out)
        self.assertIn("DENY", out)

    def test_openai_compatible_backend(self):
        with fake_server() as (url, handler):
            code, out, _ = run_cli("--backend", "openai", "--base-url", url,
                                   "--case", "B", "--mode", "vulnerable")
        self.assertEqual(code, 0)
        self.assertIn("LEAK Internal code", out)
        self.assertEqual(handler.seen[0][0], "/v1/chat/completions")

    def test_request_is_deterministic_and_local(self):
        with fake_server() as (url, handler):
            run_cli("--base-url", url, "--case", "A", "--mode", "secure")
        _, body = handler.seen[0]
        self.assertEqual(body["options"]["temperature"], 0)
        self.assertEqual(body["format"], "json")

    def test_refuses_non_loopback_hosts(self):
        code, _, err = run_cli("--base-url", "http://example.com:11434")
        self.assertEqual(code, 2)
        self.assertIn("only talks to a model on this machine", err)

    def test_unreachable_server_is_a_clear_error(self):
        code, _, err = run_cli("--base-url", "http://127.0.0.1:9", "--timeout", "2")
        self.assertEqual(code, 2)
        self.assertIn("cannot reach", err)

    def test_missing_model_hints_at_pull(self):
        with fake_server(status=404) as (url, _):
            code, _, err = run_cli("--base-url", url, "--model", "nope")
        self.assertEqual(code, 2)
        self.assertIn("ollama pull nope", err)

    def test_parse_action_fails_safe(self):
        self.assertEqual(lm.parse_action('{"tool": "read_private"}').tool, "read_private")
        self.assertEqual(lm.parse_action("I think read_private").tool, "read_private")
        self.assertEqual(lm.parse_action("garbage").tool, "answer_faq")
        self.assertEqual(lm.parse_action("[1, 2]").tool, "answer_faq")

    def test_default_stub_unchanged(self):
        results = a.run_matrix(DOCS, a.CASES, a.AuditLog())
        for c in a.CASES:
            self.assertIs(results[("vulnerable", c.key)][0], c.expect_vulnerable)


if __name__ == "__main__":
    unittest.main()
