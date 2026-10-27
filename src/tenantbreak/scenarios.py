"""Synthetic collection and disposable write fixtures for reproducible HTTP checks."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler
import json
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .config import decode_json, validate
from .lab import INVOICES, TOKENS, USERS, demo_policy

SCOPE = "/api/fixtures/tenantbreak/"


def collection_policy():
    policy = demo_policy()
    policy["name"] = "LedgerCloud collection authorization"
    policy["resources"] = policy["resources"][:3]
    for resource in policy["resources"]:
        resource["path"] = "/api/invoices"
        resource["collection"] = {"items": "/items", "next": "/next", "max_pages": 4, "max_items": 20,
                                  "identify": {"/id": resource["match"]["/id"], "/tenant": resource["match"]["/tenant"]}}
    partial = deepcopy(demo_policy()["resources"][0])
    partial["id"] = "alice-summary"
    partial["label"] = "Alice's invoice fields"
    partial["path"] = "/api/invoice-summaries/inv-a104"
    partial["match"]["/amount"] = 120
    partial["leak_match"] = {"/id": "inv-a104", "/amount": 120}
    policy["resources"].append(partial)
    return validate(policy)


def record(name, value="before"):
    return {"id": name, "tenant": "acme", "marker": "TB-DISPOSABLE-" + name, "value": value}


def write_policy():
    policy = demo_policy()
    policy.update(kind="write", disposable=True, name="LedgerCloud disposable write authorization", resources=[])
    for name, method in (("update", "PATCH"), ("delete", "DELETE"), ("create", "POST")):
        path = SCOPE + "records/" + name
        before = {"status": 404} if name == "create" else {"status": 200, "match": {"/value": "before"}}
        after = {"status": 404} if name == "delete" else {"status": 200, "match": {"/value": "after"}}
        request = {"method": method, "path": SCOPE + "records" if name == "create" else path}
        if name != "delete":
            request["json"] = record(name, "after") if name == "create" else {"value": "after"}
        reset = {"method": "DELETE", "path": path} if name == "create" else {"method": "PUT", "path": path, "json": record(name)}
        policy["resources"].append({"id": name, "label": name.capitalize() + " disposable record", "tenant": "acme",
            "path": path, "allow": ["alice", "admin-acme"], "control_identity": "alice",
            "match": {"/id": name, "/tenant": "acme", "/marker": "TB-DISPOSABLE-" + name},
            "write": {"scope": SCOPE, "fixture_pointer": "/marker",
                      "guard": {"path": SCOPE + "guard", "disposable_pointer": "/disposable",
                                "match": {"/id": "tenantbreak-lab", "/tenant": "acme", "/disposable": True}},
                      "before": before, "after": after, "request": request, "reset": reset}})
    return validate(policy)


def handler(mode, scenario, auth="bearer"):
    if mode not in {"vulnerable", "fixed"} or scenario not in {"collections", "writes"} or auth not in {"bearer", "headers", "cookies"}:
        raise ValueError("unsupported advanced lab mode")

    class Handler(BaseHTTPRequestHandler):
        server_version = "TenantBreakLab/" + __version__
        sys_version = ""
        records = {name: record(name) for name in ("update", "delete")}
        events = []

        def log_message(self, *_):
            pass

        def identity(self):
            name = "X-API-Key" if auth == "headers" else "Cookie" if auth == "cookies" else "Authorization"
            prefix = "session=" if auth == "cookies" else "" if auth == "headers" else "Bearer "
            return next((user for user, token in TOKENS.items() if self.headers.get(name) == prefix + token), None)

        def send_json(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def permitted(self, identity):
            return identity in {"alice", "admin-acme"}

        def do_GET(self):
            identity = self.identity()
            self.events.append(("GET", self.path, identity))
            if identity is None:
                return self.send_json(401, {"error": "authentication required"})
            user = USERS[identity]
            if self.path == "/api/me":
                return self.send_json(200, user)
            if scenario == "collections":
                parts = urlsplit(self.path)
                if parts.path == "/api/invoices":
                    rows = [deepcopy(item) for item in INVOICES.values() if mode == "vulnerable" or
                            (item["tenant"] == user["tenant"] and (item["owner"] == identity or user["role"] == "admin"))]
                    try:
                        page = int(parse_qs(parts.query).get("page", ["1"])[0])
                        if not 1 <= page <= 10:
                            raise ValueError
                    except ValueError:
                        return self.send_json(400, {"error": "invalid page"})
                    return self.send_json(200, {"items": rows[page-1:page], "next": f"/api/invoices?page={page+1}" if page < len(rows) else None})
                if parts.path == "/api/invoice-summaries/inv-a104":
                    if self.permitted(identity):
                        return self.send_json(200, INVOICES["inv-a104"])
                    if mode == "fixed":
                        return self.send_json(403, {"error": "forbidden"})
                    return self.send_json(200, {key: INVOICES["inv-a104"][key] for key in ("id", "amount")})
            elif scenario == "writes":
                if not self.permitted(identity):
                    return self.send_json(403, {"error": "forbidden"})
                if self.path == SCOPE + "guard":
                    return self.send_json(200, {"id": "tenantbreak-lab", "tenant": "acme", "disposable": True})
                name = self.path.removeprefix(SCOPE + "records/")
                if name in self.records:
                    return self.send_json(200, self.records[name])
            return self.send_json(404, {"error": "not found"})

        def mutate(self):
            identity = self.identity()
            self.events.append((self.command, self.path, identity))
            if identity is None:
                return self.send_json(401, {"error": "authentication required"})
            if scenario != "writes":
                return self.send_json(405, {"error": "method not allowed"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 16384:
                    raise ValueError
                body = decode_json(self.rfile.read(length)) if length else {}
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, UnicodeError):
                return self.send_json(400, {"error": "invalid body"})
            # Consume the bounded body before closing a denied request. Closing
            # with unread bytes can reset the connection before its reply arrives.
            if mode == "fixed" and not self.permitted(identity):
                return self.send_json(403, {"error": "forbidden"})
            if self.command == "POST" and self.path == SCOPE + "records":
                name = body.get("id")
                if name != "create" or name in self.records or body.get("marker") != "TB-DISPOSABLE-create" or body.get("tenant") != "acme":
                    return self.send_json(409, {"error": "invalid fixture"})
                self.records[name] = deepcopy(body)
                return self.send_json(201, {"created": True})
            name = self.path.removeprefix(SCOPE + "records/")
            if name not in {"update", "delete", "create"}:
                return self.send_json(404, {"error": "not found"})
            if self.command == "DELETE":
                self.records.pop(name, None)
            elif self.command == "PUT":
                if any(body.get(key) != record(name)[key] for key in ("id", "tenant", "marker")):
                    return self.send_json(400, {"error": "invalid fixture"})
                self.records[name] = deepcopy(body)
            elif self.command == "PATCH" and name in self.records:
                if set(body) != {"value"}:
                    return self.send_json(400, {"error": "invalid fixture"})
                self.records[name].update(body)
            else:
                return self.send_json(404, {"error": "not found"})
            self.send_json(200, {"completed": True})

        do_POST = do_PUT = do_PATCH = do_DELETE = mutate

    return Handler
