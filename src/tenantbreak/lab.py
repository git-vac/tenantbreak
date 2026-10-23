"""An intentionally vulnerable, read-only API with entirely invented records."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import secrets
import threading

from .config import decode_json, validate
from . import __version__

USERS = {
    "alice": {"id": "alice", "tenant": "acme", "role": "member"},
    "bob": {"id": "bob", "tenant": "acme", "role": "member"},
    "charlie": {"id": "charlie", "tenant": "nova", "role": "member"},
    "admin-acme": {"id": "admin-acme", "tenant": "acme", "role": "admin"},
}
# Ephemeral process-local credentials; never serialized into committed examples.
TOKENS = {identity: secrets.token_urlsafe(32) for identity in USERS}
INVOICES = {
    "inv-a104": {"id": "inv-a104", "tenant": "acme", "owner": "alice", "amount": 120, "marker": "TB-FIXTURE-ALICE-104"},
    "inv-a105": {"id": "inv-a105", "tenant": "acme", "owner": "bob", "amount": 240, "marker": "TB-FIXTURE-BOB-105"},
    "inv-n201": {"id": "inv-n201", "tenant": "nova", "owner": "charlie", "amount": 360, "marker": "TB-FIXTURE-CHARLIE-201"},
}


def demo_policy():
    return validate(decode_json(files("tenantbreak").joinpath("demo-policy.json").read_text(encoding="utf-8")))


def handler(mode):
    if mode not in {"vulnerable", "fixed"}:
        raise ValueError("unknown lab mode")

    class Handler(BaseHTTPRequestHandler):
        server_version = "TenantBreakLab/" + __version__
        sys_version = ""

        def log_message(self, *_):
            pass

        def send_json(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            identity = next((user for user, token in TOKENS.items() if self.headers.get("Authorization") == "Bearer " + token), None)
            if identity is None:
                return self.send_json(401, {"error": "authentication required"})
            user = USERS[identity]
            if self.path == "/api/me":
                return self.send_json(200, user)
            if self.path.startswith("/api/invoices/"):
                invoice = INVOICES.get(self.path.removeprefix("/api/invoices/"))
                if invoice is None:
                    return self.send_json(404, {"error": "not found"})
                # The vulnerable version authenticates but never checks ownership.
                if mode == "fixed" and not (user["tenant"] == invoice["tenant"] and (user["id"] == invoice["owner"] or user["role"] == "admin")):
                    return self.send_json(403, {"error": "forbidden"})
                return self.send_json(200, invoice)
            if self.path == "/api/admin/tenants/acme/export":
                # Tenant membership alone does not authorize an admin operation.
                if user["tenant"] != "acme" or (mode == "fixed" and user["role"] != "admin"):
                    return self.send_json(403, {"error": "forbidden"})
                return self.send_json(200, {"id": "export-acme", "tenant": "acme", "marker": "TB-FIXTURE-ACME-EXPORT", "rows": 2})
            self.send_json(404, {"error": "not found"})

    return Handler


@contextmanager
def server(mode="vulnerable", port=0):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler(mode))
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
