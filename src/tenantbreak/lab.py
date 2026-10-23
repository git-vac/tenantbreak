"""An intentionally vulnerable, read-only API with entirely invented records."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import secrets
import threading
from urllib.parse import parse_qs

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
REFRESH_TOKENS = {identity: secrets.token_urlsafe(32) for identity in USERS}
INVOICES = {
    "inv-a104": {"id": "inv-a104", "tenant": "acme", "owner": "alice", "amount": 120, "marker": "TB-FIXTURE-ALICE-104"},
    "inv-a105": {"id": "inv-a105", "tenant": "acme", "owner": "bob", "amount": 240, "marker": "TB-FIXTURE-BOB-105"},
    "inv-n201": {"id": "inv-n201", "tenant": "nova", "owner": "charlie", "amount": 360, "marker": "TB-FIXTURE-CHARLIE-201"},
}


def demo_policy(auth="bearer"):
    policy = decode_json(files("tenantbreak").joinpath("demo-policy.json").read_text(encoding="utf-8"))
    if auth not in {"bearer", "headers", "cookies", "refresh"}:
        raise ValueError("unknown lab authentication mode")
    if auth != "bearer":
        for identity in policy["identities"]:
            env = identity.pop("token_env")
            if auth == "refresh":
                identity["auth"] = {"type": "bearer", "token_env": env,
                                    "refresh": {"path": "/oauth/token", "refresh_token_env": env + "_REFRESH"}}
            else:
                name = "X-API-Key" if auth == "headers" else "session"
                identity["auth"] = {"type": auth, "values": {name: env}}
    return validate(policy)


def demo_environment():
    return {key: value for identity in demo_policy()["identities"]
            for key, value in ((identity["token_env"], TOKENS[identity["id"]]),
                               (identity["token_env"] + "_REFRESH", REFRESH_TOKENS[identity["id"]]))}


def handler(mode, auth="bearer"):
    if mode not in {"vulnerable", "fixed"}:
        raise ValueError("unknown lab mode")
    if auth not in {"bearer", "headers", "cookies", "refresh"}:
        raise ValueError("unknown lab authentication mode")
    access, refresh_tokens = dict(TOKENS), dict(REFRESH_TOKENS)

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
            name = "X-API-Key" if auth == "headers" else "Cookie" if auth == "cookies" else "Authorization"
            prefix = "session=" if auth == "cookies" else "" if auth == "headers" else "Bearer "
            identity = next((user for user, token in access.items() if self.headers.get(name) == prefix + token), None)
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

        def do_POST(self):
            if auth != "refresh" or self.path != "/oauth/token":
                return self.send_json(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 32768:
                    raise ValueError
                data = parse_qs(self.rfile.read(length).decode("ascii"), strict_parsing=True)
                token = data.get("refresh_token", [None])
                if set(data) != {"grant_type", "refresh_token"} or data["grant_type"] != ["refresh_token"] or len(token) != 1:
                    raise ValueError
            except (ValueError, UnicodeError):
                return self.send_json(400, {"error": "invalid_request"})
            identity = next((user for user, value in refresh_tokens.items() if token[0] == value), None)
            if identity is None:
                return self.send_json(400, {"error": "invalid_grant"})
            access[identity], refresh_tokens[identity] = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.send_json(200, {"access_token": access[identity], "token_type": "Bearer",
                                 "refresh_token": refresh_tokens[identity]})

    return Handler


@contextmanager
def server(mode="vulnerable", port=0, auth="bearer"):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler(mode, auth))
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
