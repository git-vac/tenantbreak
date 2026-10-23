from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree

from tenantbreak import comparison
from tenantbreak.cli import main
from tenantbreak.config import PolicyError, credentials, fingerprint
from tenantbreak.engine import exit_code, run
from tenantbreak.lab import TOKENS, demo_policy, server
from tenantbreak.report import html, junit, terminal
from tenantbreak.saved import load_report, normalize, replay_cases
from tenantbreak.selection import dependencies, select
from test_tenantbreak import api


class SelectionTests(unittest.TestCase):
    def test_one_case_keeps_owner_and_verifies_only_required_accounts(self):
        with api() as (address, requests):
            report = run(demo_policy(), {key: TOKENS[key] for key in ("alice", "bob")}, base_url=address, case_ids=["alice-invoice:bob"])
        self.assertEqual(requests, [("/api/me", "alice"), ("/api/me", "bob"), ("/api/invoices/inv-a104", "alice"), ("/api/invoices/inv-a104", "bob")])
        self.assertEqual([case["id"] for case in report["cases"]], ["alice-invoice:bob"])
        self.assertEqual(report["scope"]["total_cases"], 16)
        self.assertEqual(report["policy_sha256"], fingerprint(demo_policy()))
        self.assertEqual(exit_code(report), 0)
        self.assertIn("1/16", terminal(report))
        self.assertIn("1 of 16", html(report))
        self.assertIn("alice", html(report))
        xml = ElementTree.fromstring(junit(report))
        self.assertEqual(xml.attrib["tests"], "4")
        properties = {item.attrib["name"]: item.attrib["value"] for item in xml.findall("properties/property")}
        self.assertEqual(properties["selected_cases"], "1")
        self.assertEqual(properties["policy_cases"], "16")
        self.assertEqual(properties["scope"], "focused")

    def test_invalid_and_disjoint_selections_make_no_requests(self):
        for options in ({"case_ids": ["missing:bob"]}, {"identity_ids": ["missing"]}, {"resource_ids": ["missing"]}, {"identity_ids": ["alice"], "case_ids": ["alice-invoice:bob"]}):
            with self.subTest(options=options), patch("tenantbreak.engine.Transport") as transport, self.assertRaises(PolicyError):
                run(demo_policy(), TOKENS, **options)
            transport.assert_not_called()

    def test_failed_owner_control_is_retained_for_focused_case(self):
        with api(lambda path, user, status, body, headers: (404, {}, headers) if path != "/api/me" else (status, body, headers)) as (address, requests):
            report = run(demo_policy(), TOKENS, base_url=address, case_ids=["alice-invoice:bob"])
        self.assertEqual(exit_code(report), 2)
        self.assertEqual(report["cases"][0]["reason"], "owner-control-failed")
        self.assertNotIn(("/api/invoices/inv-a104", "bob"), requests)
        self.assertEqual(normalize(report)["cases"][0]["status"], "inconclusive")

    def test_sparse_case_selection_marks_other_cells_not_run(self):
        with api() as (address, _):
            report = run(demo_policy(), TOKENS, base_url=address, case_ids=["alice-invoice:bob", "bob-invoice:alice"])
        self.assertEqual(len(report["cases"]), 2)
        self.assertEqual(html(report).count("NOT RUN"), 2)
        self.assertEqual(len(normalize(report)["cases"]), 2)

    def test_only_selected_dependency_credentials_are_required(self):
        policy = demo_policy()
        selected = select(policy, identity_ids=["bob"], resource_ids=["alice-invoice"])
        env = {"TB_ALICE_TOKEN": TOKENS["alice"], "TB_BOB_TOKEN": TOKENS["bob"]}
        self.assertEqual(set(credentials(policy, env, dependencies(policy, selected))), {"alice", "bob"})

    def test_credentials_cannot_collide_with_policy_or_outcome_labels(self):
        for token in ("alice", "id", "error"):
            supplied = dict(TOKENS, alice=token)
            with self.subTest(token=token), patch("tenantbreak.engine.Transport") as transport, self.assertRaises(PolicyError):
                run(demo_policy(), supplied)
            transport.assert_not_called()


class SavedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with server("vulnerable") as address:
            cls.before = run(demo_policy(), TOKENS, base_url=address, mode="demo-vulnerable")
        with server("fixed") as address:
            cls.after = run(demo_policy(), TOKENS, base_url=address, mode="demo-fixed")

    def test_complete_experiment_resolves_nine_leaks(self):
        result = comparison.compare(self.before, self.after)
        self.assertEqual(result["counts"], {"unchanged": 7, "resolved-leak": 9})
        self.assertEqual(comparison.exit_code(result), 0)
        self.assertEqual(ElementTree.fromstring(comparison.junit(result)).attrib["errors"], "0")

    def test_reverse_experiment_detects_nine_new_leaks(self):
        result = comparison.compare(self.after, self.before)
        self.assertEqual(result["counts"]["new-leak"], 9)
        self.assertEqual(comparison.exit_code(result), 1)
        self.assertEqual(ElementTree.fromstring(comparison.junit(result)).attrib["failures"], "9")

    def test_persistent_leaks_keep_ci_failing(self):
        result = comparison.compare(self.before, self.before)
        self.assertEqual(result["counts"]["persistent-leak"], 9)
        self.assertEqual(comparison.exit_code(result), 1)

    def test_missing_test_never_becomes_a_resolved_leak(self):
        after = deepcopy(self.after)
        after["cases"].pop(1)
        after["scope"]["selected_cases"].pop(1)
        result = comparison.compare(self.before, after)
        self.assertEqual(comparison.exit_code(result), 2)
        self.assertNotIn("resolved-leak", result["counts"])
        self.assertIn("selected-cases-differ", result["issues"])

    def test_changed_policy_limits_or_case_definition_prevent_directional_claims(self):
        for change in ("policy", "limits", "definition"):
            after = deepcopy(self.after)
            if change == "policy":
                after["policy_sha256"] = "a" * 64
            elif change == "limits":
                after["limits"]["timeout"] = 3
            else:
                after["cases"][1]["definition_sha256"] = "b" * 64
            result = comparison.compare(self.before, after)
            self.assertEqual(comparison.exit_code(result), 2)
            self.assertTrue(any(row["status"] == "not-comparable" for row in result["rows"]))

    def test_non_demo_target_change_needs_explicit_acknowledgement(self):
        before, after = deepcopy(self.before), deepcopy(self.after)
        for report in (before, after):
            report["mode"] = "run"
            report.pop("fixture_id")
        self.assertEqual(comparison.exit_code(comparison.compare(before, after)), 2)
        acknowledged = comparison.compare(before, after, allow_target_change=True)
        self.assertEqual(comparison.exit_code(acknowledged), 0)
        self.assertTrue(acknowledged["target_change_acknowledged"])

    def test_changed_recorded_expectation_cannot_relabel_a_leak_as_unchanged(self):
        after = deepcopy(self.after)
        after["cases"][1]["expected"] = "allow"
        result = comparison.compare(self.before, after)
        self.assertEqual(result["rows"][1]["status"], "not-comparable")
        self.assertEqual(comparison.exit_code(result), 2)

    def test_demo_and_application_evidence_remain_distinct(self):
        after = deepcopy(self.after)
        after["mode"] = "run"
        after.pop("fixture_id")
        result = comparison.compare(self.before, after, allow_target_change=True)
        self.assertEqual(comparison.exit_code(result), 2)

    def test_legacy_reports_can_be_loaded_but_require_new_comparison_runs(self):
        legacy = deepcopy(self.before)
        legacy["schema_version"] = 1
        legacy.pop("scope")
        legacy.pop("fixture_id")
        for case in legacy["cases"]:
            case.pop("definition_sha256")
        self.assertEqual(normalize(legacy)["counts"]["confirmed-leak"], 9)
        self.assertEqual(len(replay_cases(demo_policy(), normalize(legacy))), 9)
        self.assertEqual(comparison.exit_code(comparison.compare(legacy, self.after)), 2)

    def test_edited_statuses_flags_and_counts_are_not_trusted(self):
        edited = deepcopy(self.before)
        edited["counts"] = {"confirmed-leak": 0}
        for case in edited["cases"]:
            case["status"] = "denied"
            case["control_valid"] = False
        restored = normalize(edited)
        self.assertEqual(restored["counts"]["confirmed-leak"], 9)
        self.assertEqual(comparison.compare(edited, self.after)["counts"]["resolved-leak"], 9)

    def test_failed_evidence_does_not_become_a_resolution(self):
        after = deepcopy(self.after)
        case = after["cases"][1]
        case["http_status"] = 401
        for check in case["assertions"]:
            check.update(present=False, matched=False)
        result = comparison.compare(self.before, after)
        self.assertEqual(result["rows"][1]["status"], "inconclusive")
        self.assertEqual(comparison.exit_code(result), 2)

    def test_duplicate_case_invalid_digest_or_scope_is_rejected(self):
        for mutation in ("duplicate", "digest", "scope", "assertion"):
            report = deepcopy(self.before)
            if mutation == "duplicate":
                report["cases"].append(deepcopy(report["cases"][0]))
            elif mutation == "digest":
                report["cases"][0]["response_sha256"] = "wrong"
            elif mutation == "scope":
                report["scope"]["selected_cases"] = []
            else:
                report["cases"][0]["assertions"][0].update(present=False, matched=True)
            with self.subTest(mutation=mutation), self.assertRaises(PolicyError):
                normalize(report)

    def test_saved_report_loader_rejects_duplicate_json_keys_and_wrong_tool(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            path.write_text('{"tool":"TenantBreak","tool":"other"}', encoding="utf-8")
            with self.assertRaises(PolicyError):
                load_report(path)
            report = deepcopy(self.before)
            report["tool"] = "other"
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(PolicyError):
                load_report(path)

    def test_replay_defaults_to_findings_and_rejects_changed_policy(self):
        self.assertEqual(len(replay_cases(demo_policy(), self.before)), 9)
        self.assertEqual(replay_cases(demo_policy(), self.before, ["alice-invoice:alice"]), ["alice-invoice:alice"])
        policy = demo_policy()
        policy["resources"][0]["allow"].append("bob")
        with self.assertRaises(PolicyError):
            replay_cases(policy, self.before)
        with self.assertRaises(PolicyError):
            replay_cases(demo_policy(), self.after)

    def test_replay_does_not_contact_url_from_saved_report(self):
        with tempfile.TemporaryDirectory() as folder, api() as (address, requests):
            root = Path(folder)
            policy = demo_policy()
            policy["base_url"] = address
            saved = deepcopy(self.before)
            saved["base_url"] = "https://unrelated.example.invalid"
            (root / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            (root / "saved.json").write_text(json.dumps(saved), encoding="utf-8")
            env = {"TB_ALICE_TOKEN": TOKENS["alice"], "TB_BOB_TOKEN": TOKENS["bob"]}
            with patch.dict("os.environ", env, clear=True), redirect_stdout(io.StringIO()):
                result = main(["replay", str(root / "policy.json"), str(root / "saved.json"), "--case", "alice-invoice:bob", "--json", str(root / "replayed.json")])
            self.assertEqual(result, 0)
            self.assertEqual(len(requests), 4)
            replayed, _ = load_report(root / "replayed.json")
            self.assertEqual(replayed["base_url"], address)
            self.assertIn("replay_of", replayed)

    def test_compare_cli_is_offline_and_preserves_input_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, report in (("before", self.before), ("after", self.after)):
                (root / f"{name}.json").write_text(json.dumps(report), encoding="utf-8")
            original = (root / "before.json").read_bytes()
            with patch("tenantbreak.engine.Transport") as transport, redirect_stdout(io.StringIO()):
                result = main(["compare", str(root / "before.json"), str(root / "after.json"), "--html", str(root / "diff.html"), "--json", str(root / "diff.json"), "--junit", str(root / "diff.xml")])
            transport.assert_not_called()
            self.assertEqual(result, 0)
            self.assertEqual((root / "before.json").read_bytes(), original)
            self.assertIn("RESOLVED LEAK", (root / "diff.html").read_text())
            self.assertEqual(json.loads((root / "diff.json").read_text())["counts"]["resolved-leak"], 9)

    def test_comparison_html_escapes_saved_labels(self):
        before, after = deepcopy(self.before), deepcopy(self.after)
        for report in (before, after):
            report["name"] = "<script>bad()</script>"
            report["cases"][0]["label"] = '<img src=x onerror="bad()">'
        output = comparison.html(comparison.compare(before, after))
        self.assertNotIn("<script>", output)
        self.assertNotIn("<img src", output)
        self.assertIn("&lt;script&gt;", output)


if __name__ == "__main__":
    unittest.main()
