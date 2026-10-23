from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from tenantbreak.cli import main
from tenantbreak.config import PolicyError, credentials, decode_json, fingerprint, load, origin, validate
from tenantbreak.engine import assertions, exit_code, run
from tenantbreak.lab import INVOICES, TOKENS, USERS, demo_policy, server
from tenantbreak.report import html, junit, terminal
from tenantbreak.transport import MAX_BODY, Transport


@contextmanager
def api(behavior=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            user_id = next((key for key, value in TOKENS.items() if token == value), None)
            requests.append((self.path, user_id))
            if self.path == "/api/me":
                status, body, headers = (200, USERS[user_id], {}) if user_id else (401, {"error": "unauthorized"}, {})
            else:
                invoice = INVOICES.get(self.path.removeprefix("/api/invoices/"))
                permitted = invoice and user_id and (invoice["owner"] == user_id or (USERS[user_id]["role"] == "admin" and USERS[user_id]["tenant"] == invoice["tenant"]))
                status, body, headers = (200, invoice, {}) if permitted else (403, {"error": "forbidden"}, {})
            if behavior:
                status, body, headers = behavior(self.path, user_id, status, body, headers)
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)


def one_resource():
    policy = demo_policy()
    policy["resources"] = policy["resources"][:1]
    return policy


def bob_case(report):
    return next(case for case in report["cases"] if case["identity"] == "bob")


class PolicyTests(unittest.TestCase):
    def test_example_policy_is_valid(self):
        self.assertEqual(len(validate(demo_policy())["resources"]), 4)

    def test_unknown_fields_and_methods_rejected(self):
        policy = demo_policy()
        policy["resources"][0]["method"] = "POST"
        with self.assertRaises(PolicyError):
            validate(policy)

    def test_paths_cannot_replace_origin(self):
        for path in ("https://other.test/x", "//other.test/x", "/\\other.test", "/x#fragment", "/x\r\nInjected: y"):
            with self.subTest(path=path), self.assertRaises(PolicyError):
                policy = demo_policy()
                policy["resources"][0]["path"] = path
                validate(policy)

    def test_origin_requires_explicit_http_opt_in(self):
        self.assertEqual(origin("http://127.0.0.1:8080/"), "http://127.0.0.1:8080")
        self.assertEqual(origin("http://[::1]:8080"), "http://[::1]:8080")
        with self.assertRaises(PolicyError):
            origin("http://staging.example.test")
        self.assertEqual(origin("http://staging.example.test", allow_http=True), "http://staging.example.test")

    def test_origin_rejects_credentials_and_url_extras(self):
        for url in ("https://user:password@example.test", "https://example.test/api", "https://example.test?key=secret", "https://example.test/#x", "https://example.test:0", "https://example.test:99999", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(PolicyError):
                origin(url)

    def test_missing_credentials_and_duplicate_tokens_rejected(self):
        with self.assertRaises(PolicyError):
            credentials(demo_policy(), {})
        environment = {item["token_env"]: "same-token" for item in demo_policy()["identities"]}
        with self.assertRaises(PolicyError):
            credentials(demo_policy(), environment)

    def test_invalid_token_does_not_appear_in_error(self):
        environment = {item["token_env"]: TOKENS[item["id"]] for item in demo_policy()["identities"]}
        environment["TB_ALICE_TOKEN"] = "private-token\nheader"
        with self.assertRaises(PolicyError) as caught:
            credentials(demo_policy(), environment)
        self.assertNotIn("private-token", str(caught.exception))

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(PolicyError):
            decode_json('{"allow": [], "allow": ["alice"]}')

    def test_non_finite_numbers_rejected(self):
        with self.assertRaises(PolicyError):
            decode_json('{"value": NaN}')

    def test_controls_must_be_allowed_and_markers_specific(self):
        policy = demo_policy()
        policy["resources"][0]["control_identity"] = "charlie"
        with self.assertRaises(PolicyError):
            validate(policy)
        policy = demo_policy()
        policy["resources"][0]["match"] = {"/success": True}
        with self.assertRaises(PolicyError):
            validate(policy)

    def test_pointer_escapes_arrays_and_json_types(self):
        checks = assertions({"a/b": {"~key": [True, 1, "1"]}}, {"/a~1b/~0key/0": 1, "/a~1b/~0key/1": 1, "/a~1b/~0key/2": 1, "/a~1b/~0key/01": True})
        self.assertEqual([item["matched"] for item in checks], [False, True, False, False])

    def test_oversize_policy_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaises(PolicyError):
                load(path)

    def test_fingerprint_tracks_rules_but_not_disposable_origin(self):
        first = demo_policy()
        second = deepcopy(first)
        second["base_url"] = "http://127.0.0.1:9999"
        self.assertEqual(fingerprint(first), fingerprint(second))
        second["resources"][0]["allow"].append("bob")
        self.assertNotEqual(fingerprint(first), fingerprint(second))


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vulnerable = server("vulnerable")
        cls.fixed = server("fixed")
        cls.before = run(demo_policy(), TOKENS, base_url=cls.vulnerable.__enter__(), mode="demo-vulnerable")
        cls.after = run(demo_policy(), TOKENS, base_url=cls.fixed.__enter__(), mode="demo-fixed")

    @classmethod
    def tearDownClass(cls):
        cls.vulnerable.__exit__(None, None, None)
        cls.fixed.__exit__(None, None, None)

    def test_vulnerable_lab_proves_nine_leaks(self):
        self.assertEqual(len(self.before["cases"]), 16)
        self.assertEqual(self.before["counts"]["confirmed-leak"], 9)
        self.assertEqual(exit_code(self.before), 1)
        self.assertTrue(all(item["valid"] for item in self.before["identities"] + self.before["controls"]))

    def test_fixed_lab_preserves_legitimate_access(self):
        self.assertEqual(exit_code(self.after), 0)
        self.assertEqual(self.after["counts"], {"allowed": 6, "denied": 10})
        self.assertEqual(self.before["policy_sha256"], self.after["policy_sha256"])

    def test_findings_cover_user_tenant_and_role_boundaries(self):
        cases = {case["id"]: case for case in self.before["cases"]}
        for case_id in ("alice-invoice:bob", "alice-invoice:charlie", "acme-export:alice"):
            self.assertEqual(cases[case_id]["status"], "confirmed-leak")

    def test_reports_omit_raw_data_and_tokens(self):
        for output in (json.dumps(self.before), html(self.before), terminal(self.before), junit(self.before)):
            for secret in TOKENS.values():
                self.assertNotIn(secret, output)
            self.assertNotIn("TB-FIXTURE-ALICE-104", output)
            self.assertNotIn('"amount"', output)

    def test_junit_matches_security_and_control_results(self):
        failed = ElementTree.fromstring(junit(self.before))
        passed = ElementTree.fromstring(junit(self.after))
        self.assertEqual(failed.attrib["tests"], "24")
        self.assertEqual(failed.attrib["failures"], "9")
        self.assertEqual(failed.attrib["errors"], "0")
        self.assertEqual(passed.attrib["failures"], "0")

    def test_html_escapes_target_supplied_labels(self):
        report = deepcopy(self.before)
        report["name"] = '<script>alert("injected")</script>'
        report["cases"][0]["label"] = '<img src=x onerror="alert(1)">'
        output = html(report)
        self.assertNotIn("<script>", output)
        self.assertNotIn("<img src", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertIn("default-src 'none'", output)


class FailureEvidenceTests(unittest.TestCase):
    def evaluate(self, behavior):
        with api(behavior) as (address, _):
            return run(one_resource(), TOKENS, base_url=address)

    def test_authenticated_success_with_wrong_body_is_inconclusive(self):
        def behavior(path, user, status, body, headers):
            if user == "bob" and path != "/api/me":
                return 200, {"message": "request accepted"}, headers
            return status, body, headers
        report = self.evaluate(behavior)
        self.assertEqual(bob_case(report)["status"], "inconclusive")
        self.assertEqual(exit_code(report), 2)

    def test_denial_status_with_protected_data_is_still_a_leak(self):
        report = self.evaluate(lambda path, user, status, body, headers: (403, INVOICES["inv-a104"], headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["status"], "confirmed-leak")

    def test_partial_protected_data_is_not_counted_as_a_clean_denial(self):
        report = self.evaluate(lambda path, user, status, body, headers: (403, {"id": "inv-a104"}, headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["status"], "inconclusive")
        self.assertEqual(bob_case(report)["reason"], "partial-protected-resource-match")

    def test_missing_owner_resource_does_not_produce_passing_denials(self):
        report = self.evaluate(lambda path, user, status, body, headers: (404, {"error": "missing"}, headers) if path != "/api/me" else (status, body, headers))
        self.assertFalse(report["controls"][0]["valid"])
        self.assertTrue(all(case["status"] == "inconclusive" for case in report["cases"]))

    def test_wrong_identity_response_invalidates_that_identity(self):
        report = self.evaluate(lambda path, user, status, body, headers: (200, USERS["alice"], headers) if user == "bob" and path == "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["reason"], "identity-unverified")
        self.assertEqual(exit_code(report), 2)

    def test_expired_credentials_do_not_count_as_security(self):
        report = self.evaluate(lambda path, user, status, body, headers: (401, {"error": "expired"}, headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["status"], "error")
        self.assertEqual(bob_case(report)["reason"], "authentication-rejected")

    def test_plaintext_denial_supported_without_claiming_json_evidence(self):
        report = self.evaluate(lambda path, user, status, body, headers: (403, b"Forbidden", headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["status"], "denied")
        self.assertTrue(all(not check["matched"] for check in bob_case(report)["assertions"]))

    def test_oversize_response_is_error(self):
        report = self.evaluate(lambda path, user, status, body, headers: (200, b"x" * (MAX_BODY + 1), headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["reason"], "response-too-large")
        self.assertEqual(exit_code(report), 2)

    def test_duplicate_response_keys_do_not_prove_a_leak(self):
        report = self.evaluate(lambda path, user, status, body, headers: (200, b'{"id":"inv-a104","id":"other","tenant":"acme","marker":"TB-FIXTURE-ALICE-104"}', headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["reason"], "invalid-json")

    def test_malformed_json_denial_cannot_hide_a_possible_leak(self):
        report = self.evaluate(lambda path, user, status, body, headers: (403, b'{"id":"inv-a104","id":"other"}', headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["status"], "error")
        self.assertEqual(bob_case(report)["reason"], "invalid-json")

    def test_server_failure_is_not_a_passing_denial(self):
        report = self.evaluate(lambda path, user, status, body, headers: (500, {"error": "backend failed"}, headers) if user == "bob" and path != "/api/me" else (status, body, headers))
        self.assertEqual(bob_case(report)["reason"], "server-error")

    def test_echoed_credential_never_enters_artifacts(self):
        def behavior(path, user, status, body, headers):
            if path != "/api/me":
                return 200, {"debug": "Bearer " + TOKENS[user]}, headers
            return status, body, headers
        report = self.evaluate(behavior)
        for token in TOKENS.values():
            self.assertNotIn(token, json.dumps(report))

    def test_redirect_is_not_followed_or_forwarded(self):
        with api() as (sink, sink_requests):
            with api(lambda path, user, status, body, headers: (302, {}, {"Location": sink + "/receive"})) as (address, _):
                response = Transport(address).get("/api/me", TOKENS["alice"])
        self.assertEqual(response.error, "redirect-refused")
        self.assertEqual(sink_requests, [])

    def test_ambient_proxy_is_ignored(self):
        with api() as (address, _), patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}):
            response = Transport(address).get("/api/me", TOKENS["alice"])
        self.assertEqual(response.status, 200)

    def test_request_timeout_returns_an_error(self):
        def slow(path, user, status, body, headers):
            time.sleep(0.1)
            return status, body, headers
        with api(slow) as (address, _):
            response = Transport(address, timeout=0.02).get("/api/me", TOKENS["alice"])
        self.assertEqual(response.error, "request-timeout")

    def test_exhausted_run_budget_makes_no_request(self):
        with api() as (address, received):
            transport = Transport(address)
            transport.deadline = time.monotonic() - 1
            response = transport.get("/api/me", TOKENS["alice"])
            self.assertEqual(received, [])
        self.assertEqual(response.error, "run-budget-exhausted")


class CliTests(unittest.TestCase):
    def test_lab_generates_private_credentials_without_printing_them(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            target = root / "private" / "lab-env.sh"
            output = io.StringIO()
            with patch("tenantbreak.cli.Path.cwd", return_value=root), patch("tenantbreak.cli.server", return_value=nullcontext("http://127.0.0.1:8080")), patch("tenantbreak.cli.time.sleep", side_effect=KeyboardInterrupt), redirect_stdout(output):
                self.assertEqual(main(["lab", "--credentials-out", str(target)]), 130)
            contents = target.read_text(encoding="utf-8")
            for token in TOKENS.values():
                self.assertIn(token, contents)
                self.assertNotIn(token, output.getvalue())

    def test_lab_credentials_cannot_be_written_outside_private_folder(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stderr(io.StringIO()):
            path = Path(folder) / "published.sh"
            self.assertEqual(main(["lab", "--credentials-out", str(path)]), 2)
            self.assertFalse(path.exists())

    def test_validate_needs_no_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps(demo_policy()), encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True), redirect_stdout(io.StringIO()):
                self.assertEqual(main(["validate", str(path)]), 0)

    def test_existing_report_is_preserved_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            path.write_text("keep me", encoding="utf-8")
            with patch("tenantbreak.cli.server") as fixture, redirect_stderr(io.StringIO()):
                self.assertEqual(main(["demo", "--html", str(path)]), 2)
                fixture.assert_not_called()
            self.assertEqual(path.read_text(), "keep me")

    def test_same_path_cannot_be_used_for_multiple_formats(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stderr(io.StringIO()):
            path = Path(folder) / "report"
            self.assertEqual(main(["demo", "--html", str(path), "--json", str(path)]), 2)
            self.assertFalse(path.exists())

    def test_cli_writes_actual_fixed_demo_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with redirect_stdout(io.StringIO()):
                result = main(["demo", "--mode", "fixed", "--html", str(root / "fixed.html"), "--json", str(root / "fixed.json"), "--junit", str(root / "fixed.xml")])
            self.assertEqual(result, 0)
            self.assertIn("Access matrix", (root / "fixed.html").read_text())
            self.assertEqual(json.loads((root / "fixed.json").read_text())["counts"], {"allowed": 6, "denied": 10})
            self.assertEqual(ElementTree.parse(root / "fixed.xml").getroot().attrib["errors"], "0")


if __name__ == "__main__":
    unittest.main()
