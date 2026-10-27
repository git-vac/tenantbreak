from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from tenantbreak import comparison
from tenantbreak.cli import main
from tenantbreak.config import PolicyError, validate
from tenantbreak.engine import exit_code, run
from tenantbreak.lab import INVOICES, TOKENS
from tenantbreak.report import html, junit, terminal
from tenantbreak.saved import normalize, replay_cases
from tenantbreak.scenarios import SCOPE, collection_policy, handler, record, write_policy
from tenantbreak.transport import Response, Transport
from tenantbreak.writes import run_writes


@contextmanager
def application(scenario, mode="fixed", route=None, alter=None):
    base = handler(mode, scenario)
    class Handler(base):
        received = []
        def send_json(self, status, body):
            if alter:
                status, body = alter(self, status, body)
            super().send_json(status, body)
        def do_GET(self):
            self.received.append(("GET", self.path, self.identity()))
            if not route or not route(self):
                super().do_GET()
        def mutate(self):
            self.received.append((self.command, self.path, self.identity()))
            if route:
                original = self.rfile
                body = original.read(int(self.headers.get("Content-Length", "0")))
                self.rfile = io.BytesIO(body)
                try:
                    if not route(self):
                        super().mutate()
                finally:
                    self.rfile = original
            else:
                super().mutate()
        do_POST = do_PATCH = do_PUT = do_DELETE = mutate
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(address=f"http://127.0.0.1:{httpd.server_port}", handler=Handler, received=Handler.received)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)


def collection_one():
    policy = collection_policy()
    policy["resources"] = policy["resources"][:1]
    return policy


def write_one():
    policy = write_policy()
    policy["resources"] = policy["resources"][:1]
    return policy


def read_bob(app, policy=None):
    return run(policy or collection_one(), TOKENS, base_url=app.address, case_ids=["alice-invoice:bob"])


def write_bob(app, policy=None, **options):
    return run_writes(policy or write_one(), TOKENS, base_url=app.address, enable_writes=True, case_ids=["update:bob"], **options)


class CollectionTests(unittest.TestCase):
    def test_complete_collection_and_partial_projection_experiments(self):
        for mode, expected, counts in (("vulnerable", 1, {"allowed": 7, "confirmed-leak": 9}), ("fixed", 0, {"allowed": 7, "denied": 9})):
            with application("collections", mode) as app:
                report = run(collection_policy(), TOKENS, base_url=app.address)
            self.assertEqual(exit_code(report), expected)
            self.assertEqual(report["counts"], counts)
            self.assertEqual(normalize(report)["counts"], counts)

    def test_rows_cannot_combine_to_prove_a_leak(self):
        def alter(req, status, body):
            if req.path == "/api/invoices" and req.identity() == "bob":
                body = {"items": [{"id": "inv-a104", "tenant": "acme"}, {"marker": "TB-FIXTURE-ALICE-104"}], "next": None}
            return status, body
        with application("collections", alter=alter) as app:
            report = read_bob(app)
        self.assertEqual(report["cases"][0]["status"], "inconclusive")
        self.assertEqual(exit_code(report), 2)

    def test_other_record_in_same_tenant_is_not_target_exposure(self):
        with application("collections") as app:
            report = read_bob(app)
        self.assertEqual(report["cases"][0]["status"], "denied")
        self.assertEqual(report["cases"][0]["reason"], "protected-record-absent-from-collection")

    def test_later_page_finding_has_record_location(self):
        policy = collection_policy()
        with application("collections", "vulnerable") as app:
            report = run(policy, TOKENS, base_url=app.address, case_ids=["charlie-invoice:bob"])
        case = report["cases"][0]
        self.assertEqual(case["status"], "confirmed-leak")
        self.assertEqual(len(case["collection"]["pages"]), 3)
        self.assertTrue(all(c["matched"] for c in case["collection"]["pages"][2]["assertions"]))
        self.assertIn("Page 3", html(report))
        self.assertNotIn("inv-n201", json.dumps(case["collection"]))

    def test_explicit_field_subset_confirms_partial_projection(self):
        policy = collection_policy()
        policy["resources"] = policy["resources"][-1:]
        with application("collections", "vulnerable") as app:
            report = run(policy, TOKENS, base_url=app.address, case_ids=["alice-summary:bob"])
        case = report["cases"][0]
        self.assertEqual(case["status"], "confirmed-leak")
        self.assertEqual(case["reason"], "protected-fields-returned")
        self.assertFalse(all(c["matched"] for c in case["assertions"]))
        self.assertTrue(all(c["matched"] for c in case["leak_assertions"]))
        self.assertEqual(normalize(report)["cases"][0]["status"], "confirmed-leak")

    def test_no_subset_configuration_keeps_partial_projection_inconclusive(self):
        policy = collection_policy()
        policy["resources"] = policy["resources"][-1:]
        del policy["resources"][0]["leak_match"]
        with application("collections", "vulnerable") as app:
            report = run(policy, TOKENS, base_url=app.address, case_ids=["alice-summary:bob"])
        self.assertEqual(report["cases"][0]["status"], "inconclusive")

    def test_page_limit_retains_early_finding_but_prevents_clean_exit(self):
        def alter(req, status, body):
            if req.identity() == "bob" and req.path.startswith("/api/invoices"):
                return 200, {"items": [deepcopy(INVOICES["inv-a104"])], "next": "/api/invoices?page=2"}
            return status, body
        policy = collection_one()
        policy["resources"][0]["collection"]["max_pages"] = 1
        with application("collections", alter=alter) as app:
            report = read_bob(app, policy)
        case = report["cases"][0]
        self.assertEqual(case["status"], "confirmed-leak")
        self.assertFalse(case["coverage_complete"])
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(normalize(report)["cases"][0]["status"], "confirmed-leak")
        xml = ElementTree.fromstring(junit(report))
        self.assertGreater(int(xml.attrib["errors"]), 0)
        self.assertEqual(xml.attrib["failures"], "1")
        self.assertEqual(comparison.exit_code(comparison.compare(report, report)), 2)

    def test_external_or_changed_endpoint_is_never_followed(self):
        for next_path in ("https://other.example.invalid/steal", "//other.example.invalid/steal", "/api/me", "/api/invoices#fragment", {"url": "/api/invoices"}):
            def alter(req, status, body):
                if req.identity() == "bob" and req.path.startswith("/api/invoices"):
                    return 200, {"items": [], "next": next_path}
                return status, body
            with self.subTest(next_path=next_path), application("collections", alter=alter) as app:
                report = read_bob(app)
            self.assertEqual(exit_code(report), 2)
            self.assertEqual(sum(path.startswith("/api/invoices") and who == "bob" for _, path, who in app.received), 1)

    def test_cycle_missing_cursor_and_invalid_items_are_incomplete(self):
        for body in ({"items": [], "next": "/api/invoices"}, {"items": []}, {"items": [None], "next": None}, {"items": {}, "next": None}):
            def alter(req, status, original):
                return (200, body) if req.identity() == "bob" and req.path.startswith("/api/invoices") else (status, original)
            with self.subTest(body=body), application("collections", alter=alter) as app:
                report = read_bob(app)
            self.assertEqual(exit_code(report), 2)
            self.assertFalse(report["cases"][0]["coverage_complete"])

    def test_later_denied_page_cannot_complete_a_scan(self):
        def alter(req, status, body):
            if req.identity() == "bob" and req.path.startswith("/api/invoices"):
                return (403, {"items": [], "next": None}) if "page=2" in req.path else (200, {"items": [], "next": "/api/invoices?page=2"})
            return status, body
        with application("collections", alter=alter) as app:
            report = read_bob(app)
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(report["cases"][0]["transport_error"], "pagination-page-rejected")

    def test_item_limit_and_owner_failure_prevent_passing(self):
        policy = collection_one()
        policy["resources"][0]["collection"]["max_items"] = 1
        with application("collections", "vulnerable") as app:
            report = read_bob(app, policy)
        self.assertEqual(exit_code(report), 2)
        self.assertFalse(report["controls"][0]["valid"])
        self.assertFalse(any(path.startswith("/api/invoices") and who == "bob" for _, path, who in app.received))

    def test_root_array_and_escaped_items_pointer(self):
        for pointer in ("", "/a~1b/~0items"):
            policy = collection_one()
            policy["resources"][0]["collection"].update(items=pointer, max_pages=1)
            policy["resources"][0]["collection"].pop("next")
            def alter(req, status, body):
                if req.path == "/api/invoices":
                    rows = body["items"]
                    return status, rows if pointer == "" else {"a/b": {"~items": rows}}
                return status, body
            with application("collections", alter=alter) as app:
                self.assertEqual(exit_code(read_bob(app, policy)), 0)

    def test_bad_policy_and_tampered_page_evidence_are_rejected(self):
        for change in ({"max_pages": 0}, {"max_items": 5001}, {"items": []}, {"identify": {"/id": "wrong", "/tenant": "acme"}}):
            policy = collection_one()
            policy["resources"][0]["collection"].update(change)
            with self.assertRaises(PolicyError):
                validate(policy)
        with application("collections", "vulnerable") as app:
            report = read_bob(app)
        broken = deepcopy(report)
        broken["cases"][0]["coverage_complete"] = False
        with self.assertRaises(PolicyError):
            normalize(broken)
        broken = deepcopy(report)
        broken["cases"][0]["collection"]["pages"][0]["items_seen"] = -1
        with self.assertRaises(PolicyError):
            normalize(broken)


class WriteTests(unittest.TestCase):
    def test_create_update_delete_experiments_restore_all_fixtures(self):
        for mode, counts in (("vulnerable", {"allowed": 6, "confirmed-write": 6}), ("fixed", {"allowed": 6, "denied": 6})):
            with application("writes", mode) as app:
                report = run_writes(write_policy(), TOKENS, base_url=app.address, enable_writes=True)
                self.assertEqual(app.handler.records, {name: record(name) for name in ("update", "delete")})
            self.assertEqual(report["counts"], counts)
            self.assertEqual(normalize(report)["counts"], counts)
            self.assertTrue(all(c["cleanup_verified"] for c in report["cases"] + report["controls"]))
            self.assertEqual(exit_code(report), 1 if mode == "vulnerable" else 0)
            self.assertIn("Cleanup", html(report))
            self.assertIn("PATCH", html(report))
            self.assertEqual(ElementTree.fromstring(junit(report)).attrib["failures"], "6" if mode == "vulnerable" else "0")

    def test_missing_opt_in_and_read_replay_make_no_network_requests(self):
        with patch("tenantbreak.engine.Transport") as transport:
            with self.assertRaises(PolicyError):
                run_writes(write_policy(), TOKENS)
            with self.assertRaises(PolicyError):
                run(write_policy(), TOKENS)
            transport.assert_not_called()
        with application("writes", "vulnerable") as app:
            report = write_bob(app)
        with self.assertRaises(PolicyError):
            replay_cases(write_one(), report)

    def test_success_response_without_change_is_not_allowed_or_denied(self):
        def route(req):
            if req.identity() == "bob" and req.command == "PATCH":
                req.send_json(200, {"completed": True})
                return True
        with application("writes", route=route) as app:
            report = write_bob(app)
        self.assertEqual(report["cases"][0]["status"], "inconclusive")

    def test_denial_response_with_real_change_is_a_confirmed_write(self):
        def alter(req, status, body):
            return (403, {"error": "forbidden"}) if req.command == "PATCH" and req.identity() == "bob" else (status, body)
        with application("writes", "vulnerable", alter=alter) as app:
            report = write_bob(app)
        self.assertEqual(report["cases"][0]["status"], "confirmed-write")
        self.assertEqual(report["cases"][0]["write"]["request"]["http_status"], 403)
        self.assertEqual(exit_code(report), 1)

    def test_failed_owner_positive_control_prevents_probe(self):
        def route(req):
            if req.command == "PATCH":
                req.send_json(200, {"completed": True})
                return True
        with application("writes", route=route) as app:
            report = write_bob(app)
        self.assertFalse(report["controls"][0]["valid"])
        self.assertFalse(any(method != "GET" and who == "bob" for method, _, who in app.received))
        self.assertEqual(exit_code(report), 2)

    def test_bad_guard_or_baseline_stops_before_any_mutation(self):
        for field in ("guard", "baseline"):
            def alter(req, status, body):
                if field == "guard" and req.path.endswith("/guard"):
                    return 200, {"id": "tenantbreak-lab", "tenant": "acme", "disposable": False}
                if field == "baseline" and req.path.endswith("/records/update") and req.command == "GET":
                    return 200, {**body, "value": "drifted"}
                return status, body
            with application("writes", alter=alter) as app:
                report = write_bob(app)
            self.assertEqual(exit_code(report), 2)
            self.assertTrue(all(method == "GET" for method, _, _ in app.received))

    def test_failed_cleanup_preserves_finding_and_stops_later_writes(self):
        state = {"dirty": False}
        def alter(req, status, body):
            if req.command == "PATCH" and req.identity() == "bob":
                state["dirty"] = True
            return status, body
        def route(req):
            if state["dirty"] and req.command == "PUT":
                req.send_json(500, {"error": "reset failed"})
                return True
        with application("writes", "vulnerable", route=route, alter=alter) as app:
            report = run_writes(write_policy(), TOKENS, base_url=app.address, enable_writes=True, case_ids=["update:bob", "update:charlie", "create:bob"])
        case = report["cases"][0]
        self.assertEqual(case["status"], "confirmed-write")
        self.assertFalse(case["cleanup_verified"])
        self.assertEqual(exit_code(report), 2)
        self.assertFalse(any(method != "GET" and who == "charlie" for method, _, who in app.received))
        self.assertEqual(normalize(report)["cases"][0]["status"], "confirmed-write")
        self.assertEqual(comparison.exit_code(comparison.compare(report, report)), 2)

    def test_changed_fixture_marker_prevents_blind_reset(self):
        def alter(req, status, body):
            if req.command == "PATCH" and req.identity() == "bob":
                req.records["update"]["marker"] = "different-resource-marker"
            return status, body
        with application("writes", "vulnerable", alter=alter) as app:
            report = write_bob(app)
        self.assertFalse(report["cases"][0]["cleanup_verified"])
        bob_index = next(i for i, event in enumerate(app.received) if event[0] == "PATCH" and event[2] == "bob")
        self.assertFalse(any(method != "GET" for method, _, _ in app.received[bob_index+1:]))

    def test_expired_actor_after_mutation_is_not_a_passing_denial(self):
        state = {"expired": False}
        def alter(req, status, body):
            if req.command == "PATCH" and req.identity() == "bob":
                state["expired"] = True
            if state["expired"] and req.identity() == "bob" and req.path == "/api/me":
                return 401, {"error": "expired"}
            return status, body
        with application("writes", alter=alter) as app:
            report = write_bob(app)
        self.assertEqual(report["cases"][0]["status"], "inconclusive")
        self.assertEqual(exit_code(report), 2)

    def test_ambiguous_timeout_attempts_cleanup_and_stops(self):
        original = Transport.write
        def ambiguous(channel, spec, headers):
            result = original(channel, spec, headers)
            return Response(error="request-timeout") if headers.get("Authorization") == "Bearer " + TOKENS["bob"] else result
        with application("writes", "vulnerable") as app, patch.object(Transport, "write", ambiguous):
            report = run_writes(write_one(), TOKENS, base_url=app.address, enable_writes=True, case_ids=["update:bob", "update:charlie"])
            self.assertEqual(app.handler.records["update"], record("update"))
        self.assertFalse(report["cases"][0]["cleanup_verified"])
        self.assertEqual(exit_code(report), 2)
        self.assertFalse(any(method != "GET" and who == "charlie" for method, _, who in app.received))

    def test_interrupt_after_dispatch_runs_cleanup_then_returns_130(self):
        original = Transport.write
        def interrupt(channel, spec, headers):
            result = original(channel, spec, headers)
            if headers.get("Authorization") == "Bearer " + TOKENS["bob"]:
                raise KeyboardInterrupt
            return result
        with application("writes", "vulnerable") as app, patch.object(Transport, "write", interrupt):
            report = write_bob(app)
            self.assertEqual(app.handler.records["update"], record("update"))
        self.assertEqual(exit_code(report), 130)
        self.assertTrue(normalize(report)["interrupted"])

    def test_cleanup_has_budget_after_normal_run_budget_expires(self):
        original = Transport.write
        def exhaust(channel, spec, headers):
            result = original(channel, spec, headers)
            if headers.get("Authorization") == "Bearer " + TOKENS["bob"]:
                channel.deadline = 0
            return result
        with application("writes", "vulnerable") as app, patch.object(Transport, "write", exhaust):
            report = write_bob(app)
            self.assertEqual(app.handler.records["update"], record("update"))
        self.assertTrue(report["cases"][0]["cleanup_verified"])
        self.assertEqual(exit_code(report), 2)

    def test_write_comparison_reports_verified_resolutions(self):
        reports = []
        for mode in ("vulnerable", "fixed"):
            with application("writes", mode) as app:
                reports.append(run_writes(write_policy(), TOKENS, base_url=app.address, enable_writes=True, mode="demo-" + mode))
        result = comparison.compare(*reports)
        self.assertEqual(result["counts"], {"unchanged": 6, "resolved-write": 6})
        self.assertEqual(comparison.exit_code(result), 0)
        self.assertIn("RESOLVED WRITES", comparison.html(result))
        self.assertEqual(comparison.exit_code(comparison.compare(reports[1], reports[0])), 1)

    def test_write_policy_constraints_and_tampered_saved_trial(self):
        changes = [("scope", "/"), ("fixture_pointer", "/unknown")]
        for key, value in changes:
            policy = write_one()
            policy["resources"][0]["write"][key] = value
            with self.assertRaises(PolicyError):
                validate(policy)
        for path in ("https://other.invalid/change", SCOPE + "../outside", SCOPE + "%2e%2e/outside", SCOPE + "records/update?target=other"):
            policy = write_one()
            policy["resources"][0]["write"]["request"]["path"] = path
            with self.assertRaises(PolicyError):
                validate(policy)
        with application("writes") as app:
            report = write_bob(app)
        broken = deepcopy(report)
        broken["cases"][0]["write"]["request"] = None
        with self.assertRaises(PolicyError):
            normalize(broken)

    def test_numerically_equal_states_cannot_prove_a_change(self):
        policy = write_one()
        policy["resources"][0]["write"]["before"]["match"] = {"/value": 1}
        policy["resources"][0]["write"]["after"]["match"] = {"/value": 1.0}
        with self.assertRaises(PolicyError):
            validate(policy)

    def test_saved_changed_and_unchanged_claims_cannot_both_pass(self):
        with application("writes", "vulnerable") as app:
            report = write_bob(app)
        broken = deepcopy(report)
        for check in broken["cases"][0]["write"]["unchanged"]["assertions"]:
            check.update(present=True, matched=True)
        with self.assertRaises(PolicyError):
            normalize(broken)

    def test_saved_write_cannot_drop_fresh_identity_evidence(self):
        with application("writes", "vulnerable") as app:
            report = write_bob(app)
        report["cases"][0]["write"]["actor_after"]["assertions"] = report["cases"][0]["write"]["actor_after"]["assertions"][:1]
        with self.assertRaises(PolicyError):
            normalize(report)

    def test_parent_post_requires_the_explicit_fixture_identifiers(self):
        policy = write_policy()
        policy["resources"][-1]["write"]["request"]["json"]["id"] = "another-record"
        with self.assertRaises(PolicyError):
            validate(policy)

    def test_payload_values_and_credentials_are_omitted_from_artifacts(self):
        policy = write_policy()
        policy["resources"] = policy["resources"][-1:]
        value = "private-fixture-payload-do-not-store"
        policy["resources"][0]["write"]["request"]["json"]["note"] = value
        with application("writes", "vulnerable") as app:
            report = run_writes(policy, TOKENS, base_url=app.address, enable_writes=True, case_ids=["create:bob"])
        for output in (json.dumps(report), html(report), junit(report), terminal(report)):
            for sensitive in [value, *TOKENS.values()]:
                self.assertNotIn(sensitive, output)

    def test_cli_requires_explicit_write_command_and_flag(self):
        with tempfile.TemporaryDirectory() as folder, redirect_stderr(io.StringIO()):
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps(write_one()), encoding="utf-8")
            for args in (["run", str(path)], ["write", str(path)], ["demo", "--scenario", "writes"]):
                with patch("tenantbreak.engine.Transport") as transport:
                    self.assertEqual(main(args), 2)
                    transport.assert_not_called()
        with application("writes") as app, tempfile.TemporaryDirectory() as folder, redirect_stdout(io.StringIO()):
            policy = write_one()
            policy["base_url"] = app.address
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            env = {identity["token_env"]: TOKENS[identity["id"]] for identity in policy["identities"]}
            with patch.dict("os.environ", env):
                self.assertEqual(main(["write", str(path), "--enable-writes", "--case", "update:bob"]), 0)


if __name__ == "__main__":
    unittest.main()
