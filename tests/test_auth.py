from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import io
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, quote_plus

from tenantbreak import comparison
from tenantbreak.auth import Credential, definition
from tenantbreak.cli import main
from tenantbreak.config import PolicyError, credentials, validate
from tenantbreak.credential_file import read_credentials, refresh_output
from tenantbreak.engine import exit_code, run
from tenantbreak.lab import INVOICES, TOKENS, USERS, demo_environment, demo_policy, server
from tenantbreak.report import html, junit, terminal
from tenantbreak.saved import normalize, replay_cases


@contextmanager
def auth_api(policy, environment, behavior=None):
    state = SimpleNamespace(events=[], received=[], issued={}, rotations={})
    expected = credentials(policy, environment)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, status, body, headers=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/json")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def do_POST(self):
            data = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            user = next((identity["id"] for identity in policy["identities"]
                         if data.get("refresh_token") == [environment.get(definition(identity).get("refresh", {}).get("refresh_token_env"))]), None)
            state.events.append(("POST", self.path, user))
            state.received.append((dict(self.headers), data))
            state.issued[user], state.rotations[user] = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            if user:
                expected[user].headers = {"Authorization": "Bearer " + state.issued[user]}
            body = {"access_token": state.issued[user], "refresh_token": state.rotations[user], "token_type": "Bearer"}
            status, headers = 200, {}
            if behavior:
                status, body, headers = behavior("POST", self.path, user, status, body, headers, state)
            self.send(status, body, headers)

        def do_GET(self):
            user = next((key for key, credential in expected.items() if all(self.headers.get(name) == value for name, value in credential.headers.items())), None)
            state.events.append(("GET", self.path, user))
            state.received.append((dict(self.headers), None))
            if self.path == "/api/me":
                status, body = (200, USERS[user]) if user else (401, {"error": "unauthorized"})
            else:
                invoice = INVOICES.get(self.path.removeprefix("/api/invoices/"))
                permitted = invoice and user and (invoice["owner"] == user or (USERS[user]["role"] == "admin" and USERS[user]["tenant"] == invoice["tenant"]))
                status, body = (200, invoice) if permitted else (403, {"error": "forbidden"})
            headers = {}
            if behavior:
                status, body, headers = behavior("GET", self.path, user, status, body, headers, state)
            self.send(status, body, headers)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    state.address = f"http://127.0.0.1:{httpd.server_port}"
    try:
        yield state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)


def refresh_policy():
    policy = demo_policy("refresh")
    policy["resources"] = policy["resources"][:1]
    return policy


def evaluate(policy, api, *, refresh=False, sink=None, environment=None):
    env = demo_environment() if environment is None else environment
    return run(policy, credentials(policy, env, {"alice", "bob"}, refresh), base_url=api.address,
               case_ids=["alice-invoice:bob"], refresh_auth=refresh, refresh_sink=sink)


class AuthPolicyTests(unittest.TestCase):
    def test_legacy_and_all_explicit_auth_types_validate(self):
        for kind in ("bearer", "headers", "cookies", "refresh"):
            self.assertIsNotNone(validate(demo_policy(kind)))

    def test_bad_auth_definitions_rejected_before_network(self):
        invalid = [None, {"type": "shell"}, {"type": "headers", "values": {"Host": "TB_A"}},
                   {"type": "headers", "values": {"X-Key": "TB_A", "x-key": "TB_B"}},
                   {"type": "headers", "values": {"X-Key\r\nHost": "TB_A"}},
                   {"type": "cookies", "values": {"session; admin": "TB_A"}},
                   {"type": "bearer", "token_env": "bad-name"},
                   {"type": "bearer", "token_env": "TB_A", "refresh": {"path": "https://other.invalid/token", "refresh_token_env": "TB_R"}},
                   {"type": "bearer", "token_env": "TB_A", "refresh": {"path": "/token?secret=x", "refresh_token_env": "TB_R"}},
                   {"type": "bearer", "token_env": "TB_A", "refresh": {"path": "/token", "refresh_token_env": "TB_R", "client_auth": "basic"}}]
        for auth in invalid:
            policy = demo_policy()
            del policy["identities"][0]["token_env"]
            policy["identities"][0]["auth"] = auth
            with self.subTest(auth=auth), patch("tenantbreak.engine.Transport") as transport, self.assertRaises(PolicyError):
                run(policy, TOKENS)
            transport.assert_not_called()

    def test_ambiguous_and_conflicting_credential_names_rejected(self):
        policy = demo_policy()
        policy["identities"][0]["auth"] = {"type": "bearer", "token_env": "TB_OTHER"}
        with self.assertRaises(PolicyError):
            validate(policy)
        policy = refresh_policy()
        policy["identities"][0]["auth"]["refresh"]["refresh_token_env"] = "TB_BOB_TOKEN"
        with self.assertRaises(PolicyError):
            validate(policy)

    def test_cookie_and_header_injection_values_rejected(self):
        for kind, value in (("headers", "secret\r\nInjected: yes"), ("cookies", "secret; admin=yes"), ("cookies", '"quoted"'), ("cookies", "two values")):
            env = demo_environment()
            env["TB_ALICE_TOKEN"] = value
            with self.subTest(kind=kind), self.assertRaises(PolicyError):
                credentials(demo_policy(kind), env)

    def test_identical_custom_credentials_are_rejected(self):
        for kind in ("headers", "cookies"):
            env = {key: "same-opaque-account-value" for key in demo_environment()}
            with self.assertRaises(PolicyError):
                credentials(demo_policy(kind), env)

    def test_shared_refresh_tokens_are_rejected_before_exchange(self):
        env = demo_environment()
        env["TB_BOB_TOKEN_REFRESH"] = env["TB_ALICE_TOKEN_REFRESH"]
        with self.assertRaises(PolicyError):
            credentials(refresh_policy(), env, refresh_auth=True)

    def test_credentials_have_no_secret_repr(self):
        value = next(iter(credentials(demo_policy("cookies"), demo_environment()).values()))
        self.assertIsInstance(value, Credential)
        self.assertNotIn(TOKENS["alice"], repr(value))


class AuthHttpTests(unittest.TestCase):
    def test_complete_lab_matrices_with_headers_and_cookies(self):
        for kind in ("headers", "cookies"):
            policy = demo_policy(kind)
            with server("fixed", auth=kind) as address:
                report = run(policy, credentials(policy, demo_environment()), base_url=address)
            self.assertEqual(exit_code(report), 0)
            self.assertEqual(report["counts"], {"allowed": 6, "denied": 10})
            self.assertTrue(all(identity["auth_type"] == kind for identity in report["identities"]))
            self.assertEqual(normalize(report)["counts"], report["counts"])

    def test_multiple_headers_cookies_and_mixed_accounts_stay_isolated(self):
        policy, env = demo_policy("headers"), demo_environment()
        policy["identities"][0]["auth"]["values"]["X-Tenant-Key"] = "TB_TENANT_KEY"
        env["TB_TENANT_KEY"] = secrets.token_urlsafe(32)
        policy["identities"][1]["auth"] = {"type": "cookies", "values": {"session": "TB_BOB_TOKEN", "tenant": "TB_TENANT_KEY"}}
        with auth_api(policy, env) as api:
            report = evaluate(policy, api, environment=env)
        self.assertEqual(exit_code(report), 0)
        alice, bob = api.received[0][0], api.received[1][0]
        self.assertIn("X-Api-Key", alice)
        self.assertIn("X-Tenant-Key", alice)
        self.assertNotIn("Cookie", alice)
        self.assertIn("Cookie", bob)
        self.assertNotIn("X-Api-Key", bob)
        self.assertNotIn("Authorization", bob)

    def test_set_cookie_is_never_adopted_for_another_identity(self):
        policy, env = demo_policy("cookies"), demo_environment()
        def behavior(method, path, user, status, body, headers, state):
            return status, body, {"Set-Cookie": "session=" + TOKENS["alice"] + "; Path=/"}
        with auth_api(policy, env, behavior) as api:
            report = evaluate(policy, api)
        self.assertEqual(exit_code(report), 0)
        self.assertEqual(api.events[-1], ("GET", "/api/invoices/inv-a104", "bob"))

    def test_custom_authorization_scheme_and_invalid_identity(self):
        policy, env = demo_policy("headers"), demo_environment()
        for identity in policy["identities"]:
            identity["auth"]["values"] = {"Authorization": identity["auth"]["values"]["X-API-Key"]}
        env = {key: "Custom " + value for key, value in env.items()}
        def swapped(method, path, user, status, body, headers, state):
            return (200, USERS["alice"], headers) if user == "bob" and path == "/api/me" else (status, body, headers)
        with auth_api(policy, env, swapped) as api:
            report = evaluate(policy, api, environment=env)
        self.assertEqual(exit_code(report), 2)
        self.assertNotIn(("GET", "/api/invoices/inv-a104", "bob"), api.events)

    def test_cookie_redirect_does_not_send_credentials_to_sink(self):
        policy, env = demo_policy("cookies"), demo_environment()
        with auth_api(policy, env) as sink:
            def redirect(method, path, user, status, body, headers, state):
                return 307, {}, {"Location": sink.address + "/sink"}
            with auth_api(policy, env, redirect) as api:
                report = evaluate(policy, api)
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(sink.events, [])


class RefreshTests(unittest.TestCase):
    def test_refresh_is_opt_in_and_probe_401_is_not_retried(self):
        policy = refresh_policy()
        def expires(method, path, user, status, body, headers, state):
            return (401, {}, headers) if user == "bob" and path != "/api/me" else (status, body, headers)
        with auth_api(policy, demo_environment(), expires) as api:
            report = evaluate(policy, api)
        self.assertEqual([event[0] for event in api.events], ["GET"] * 4)
        self.assertEqual(report["cases"][0]["reason"], "authentication-rejected")

    def test_refresh_and_rotation_persist_before_identity_checks(self):
        policy, env, updates = refresh_policy(), demo_environment(), {}
        def saved(identity, value):
            self.assertTrue(all(event[0] == "POST" for event in api.events))
            updates[identity] = value
        with auth_api(policy, env) as api:
            report = evaluate(policy, api, refresh=True, sink=saved)
        self.assertEqual(exit_code(report), 0)
        self.assertEqual([event[0] for event in api.events], ["POST", "POST", "GET", "GET", "GET", "GET"])
        self.assertEqual(set(updates), {"alice", "bob"})
        self.assertEqual(updates["alice"]["TB_ALICE_TOKEN_REFRESH"], api.rotations["alice"])
        self.assertTrue(all(i["refresh_status"] == "succeeded" for i in report["identities"]))
        self.assertEqual(replay_cases(policy, normalize(report), ["alice-invoice:bob"]), ["alice-invoice:bob"])
        for headers, form in api.received[:2]:
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)
            self.assertEqual(set(form), {"grant_type", "refresh_token"})
        for output in (json.dumps(report), html(report), junit(report), terminal(report)):
            for value in [*env.values(), *api.issued.values(), *api.rotations.values()]:
                self.assertNotIn(value, output)

    def test_refresh_allows_missing_old_access_token(self):
        policy, env = refresh_policy(), demo_environment()
        selected = {"alice", "bob"}
        initial = credentials(policy, env, selected, True)
        env.pop("TB_ALICE_TOKEN")
        env.pop("TB_BOB_TOKEN")
        self.assertEqual(set(credentials(policy, env, selected, True)), set(initial))

    def test_basic_and_body_client_auth(self):
        for mode in ("basic", "body"):
            policy, env = refresh_policy(), demo_environment()
            env.update(TB_CLIENT_ID="synthetic-client-id", TB_CLIENT_SECRET=secrets.token_urlsafe(32))
            for identity in policy["identities"]:
                definition(identity)["refresh"].update(client_auth=mode, client_id_env="TB_CLIENT_ID", client_secret_env="TB_CLIENT_SECRET")
            with auth_api(policy, env) as api:
                report = evaluate(policy, api, environment=env, refresh=True, sink=lambda *_: None)
            self.assertEqual(exit_code(report), 0)
            headers, form = api.received[0]
            if mode == "basic":
                expected = quote_plus(env["TB_CLIENT_ID"]) + ":" + quote_plus(env["TB_CLIENT_SECRET"])
                self.assertEqual(headers["Authorization"], "Basic " + base64.b64encode(expected.encode()).decode())
                self.assertNotIn("client_secret", form)
            else:
                self.assertNotIn("Authorization", headers)
                self.assertEqual(form["client_secret"], [env["TB_CLIENT_SECRET"]])
            self.assertNotIn("TB_CLIENT_SECRET", json.dumps(report))

    def test_refresh_errors_never_become_passing_denials(self):
        scenarios = [(400, {"error": "invalid_grant"}, {}), (200, {"access_token": "opaque-new-value", "token_type": "MAC"}, {}),
                     (200, {"access_token": "bad\r\nvalue", "token_type": "Bearer"}, {}),
                     (200, b'{"access_token":', {}), (200, b"x" * 65537, {}),
                     (302, {}, {"Location": "/api/me"})]
        for status, body, headers in scenarios:
            def failure(method, path, user, old_status, old_body, old_headers, state):
                return (status, body, headers) if method == "POST" else (old_status, old_body, old_headers)
            with self.subTest(status=status, body_type=type(body).__name__), auth_api(refresh_policy(), demo_environment(), failure) as api:
                report = evaluate(refresh_policy(), api, refresh=True, sink=lambda *_: None)
            self.assertEqual(exit_code(report), 2)
            self.assertTrue(all(i["refresh_status"] == "failed" for i in report["identities"]))
            self.assertTrue(all(event[0] == "POST" for event in api.events))
            self.assertEqual(normalize(report)["cases"][0]["status"], "inconclusive")

    def test_rotation_is_saved_even_with_malformed_success(self):
        def bad_type(method, path, user, status, body, headers, state):
            if method == "POST":
                body["token_type"] = "MAC"
            return status, body, headers
        saved = {}
        with auth_api(refresh_policy(), demo_environment(), bad_type) as api:
            report = evaluate(refresh_policy(), api, refresh=True, sink=lambda identity, values: saved.update({identity: values}))
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(saved["bob"]["TB_BOB_TOKEN_REFRESH"], api.rotations["bob"])

    def test_refresh_redirect_is_not_followed(self):
        policy, env = refresh_policy(), demo_environment()
        with auth_api(policy, env) as sink:
            def redirect(method, path, user, status, body, headers, state):
                return 307, {}, {"Location": sink.address + "/token"}
            with auth_api(policy, env, redirect) as api:
                report = evaluate(policy, api, refresh=True, sink=lambda *_: None)
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(sink.events, [])

    def test_wrong_subject_after_refresh_blocks_probes(self):
        def swapped(method, path, user, status, body, headers, state):
            return (200, USERS["alice"], headers) if method == "GET" and user == "bob" and path == "/api/me" else (status, body, headers)
        with auth_api(refresh_policy(), demo_environment(), swapped) as api:
            report = evaluate(refresh_policy(), api, refresh=True, sink=lambda *_: None)
        self.assertEqual(exit_code(report), 2)
        self.assertNotIn(("GET", "/api/invoices/inv-a104", "bob"), api.events)

    def test_authentication_execution_mode_is_comparison_context(self):
        policy = refresh_policy()
        with auth_api(policy, demo_environment()) as api:
            before = evaluate(policy, api)
            after = evaluate(policy, api, refresh=True, sink=lambda *_: None)
        result = comparison.compare(before, after)
        self.assertEqual(comparison.exit_code(result), 2)
        self.assertIn("authentication-execution-differs", result["issues"])

    def test_no_private_sink_means_no_refresh_request(self):
        with patch("tenantbreak.engine.Transport") as transport, self.assertRaises(PolicyError):
            run(refresh_policy(), credentials(refresh_policy(), demo_environment(), refresh_auth=True), refresh_auth=True)
        transport.assert_not_called()

    def test_probe_expiry_after_enabled_refresh_is_not_retried(self):
        def expires(method, path, user, status, body, headers, state):
            return (401, {}, headers) if method == "GET" and user == "bob" and path != "/api/me" else (status, body, headers)
        with auth_api(refresh_policy(), demo_environment(), expires) as api:
            report = evaluate(refresh_policy(), api, refresh=True, sink=lambda *_: None)
        self.assertEqual(report["cases"][0]["reason"], "authentication-rejected")
        self.assertEqual(len(api.events), 6)

    def test_snapshot_failure_stops_before_next_request(self):
        def cannot_save(*_):
            raise OSError("synthetic disk failure")
        with auth_api(refresh_policy(), demo_environment()) as api, self.assertRaises(OSError):
            evaluate(refresh_policy(), api, refresh=True, sink=cannot_save)
        self.assertEqual(len(api.events), 1)

    def test_refresh_timeout_and_budget_produce_incomplete_evidence(self):
        def slow(method, path, user, status, body, headers, state):
            if method == "POST":
                time.sleep(0.08)
            return status, body, headers
        policy = refresh_policy()
        with auth_api(policy, demo_environment(), slow) as api:
            report = run(policy, credentials(policy, demo_environment(), {"alice", "bob"}, True), base_url=api.address,
                         case_ids=["alice-invoice:bob"], refresh_auth=True, refresh_sink=lambda *_: None,
                         timeout=0.01, max_seconds=0.02)
        self.assertEqual(exit_code(report), 2)
        self.assertTrue(all(event[0] == "POST" for event in api.events))
        self.assertTrue(all(i["refresh_status"] == "failed" for i in report["identities"]))


class PrivateCredentialCliTests(unittest.TestCase):
    def test_refresh_cli_snapshot_is_private_and_reusable(self):
        policy = refresh_policy()
        with tempfile.TemporaryDirectory() as folder, auth_api(policy, demo_environment()) as api:
            root = Path(folder).resolve()
            policy["base_url"] = api.address
            path = root / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            snapshot = root / "private" / "fresh.json"
            output = io.StringIO()
            args = ["run", str(path), "--case", "alice-invoice:bob", "--refresh-auth", "--refresh-out", str(snapshot)]
            with patch("tenantbreak.credential_file.Path.cwd", return_value=root), patch.dict(os.environ, demo_environment(), clear=True), redirect_stdout(output):
                self.assertEqual(main(args), 0)
                values = read_credentials(snapshot)
                self.assertEqual(values["TB_BOB_TOKEN"], api.issued["bob"])
                self.assertEqual(main(["run", str(path), "--case", "alice-invoice:bob", "--credentials-file", str(snapshot)]), 0)
            for value in values.values():
                self.assertNotIn(value, output.getvalue())
            if os.name != "nt":
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)

    def test_refresh_cli_rejects_bad_outputs_and_missing_opt_in_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            path = root / "policy.json"
            path.write_text(json.dumps(refresh_policy()), encoding="utf-8")
            snapshot = root / "private" / "existing.json"
            snapshot.parent.mkdir()
            snapshot.write_text("keep", encoding="utf-8")
            for options in (["--refresh-auth"], ["--refresh-out", str(snapshot)],
                            ["--refresh-auth", "--refresh-out", str(root / "public.json")],
                            ["--refresh-auth", "--refresh-out", str(snapshot)]):
                with patch("tenantbreak.credential_file.Path.cwd", return_value=root), patch.dict(os.environ, demo_environment(), clear=True), patch("tenantbreak.engine.Transport") as transport, redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["run", str(path), *options]), 2)
                transport.assert_not_called()
            self.assertEqual(snapshot.read_text(), "keep")

    def test_private_credential_parser_rejects_duplicates_and_wrong_shape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            target = root / "private" / "credentials.json"
            target.parent.mkdir()
            for content in ('{"format":"tenantbreak-credentials-v1","environment":{"A":"x","A":"y"}}', '{"format":"unknown","environment":{}}', '{"format":"tenantbreak-credentials-v1","environment":{"A":[]}}'):
                target.write_text(content, encoding="utf-8")
                with patch("tenantbreak.credential_file.Path.cwd", return_value=root), self.assertRaises(PolicyError):
                    read_credentials(target)


if __name__ == "__main__":
    unittest.main()
