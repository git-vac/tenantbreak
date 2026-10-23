from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tenantbreak.cli import main
from tenantbreak.config import PolicyError, load, validate
from tenantbreak.engine import run, exit_code
from tenantbreak.lab import TOKENS, demo_policy
from tenantbreak.onboarding import MAX_SPEC, finalize, from_openapi, read_spec, starter
from test_tenantbreak import api


def specification(version="3.1.1"):
    return {"openapi": version, "info": {"title": "Synthetic invoice API", "version": "1"},
            "servers": [{"url": "https://not-the-target.example.invalid/v9"}],
            "paths": {
                "/invoices/{invoiceId}": {"parameters": [{"name": "invoiceId", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "get": {"operationId": "getInvoice", "responses": {"200": {"description": "Invoice"}}},
                    "delete": {"operationId": "deleteInvoice", "responses": {"204": {"description": "Deleted"}}}},
                "/exports": {"get": {"operationId": "listExports", "parameters": [{"name": "account", "in": "query", "required": True, "schema": {"type": "string", "example": "DO-NOT-COPY-EXAMPLES"}}], "responses": {"200": {"description": "Exports"}}}},
            }}


class OnboardingTests(unittest.TestCase):
    def test_starter_is_explicitly_not_a_runnable_policy(self):
        draft = starter()
        self.assertEqual(draft["policy"]["resources"][0]["allow"], [])
        with self.assertRaises(PolicyError):
            validate(draft)
        with self.assertRaises(PolicyError):
            finalize(draft)

    def test_load_identifies_drafts_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "draft.json"
            path.write_text(json.dumps(starter()), encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, "finalize"):
                load(path)

    def test_imports_get_routes_and_leaves_permissions_unset(self):
        for version in ("3.0.4", "3.1.1", "3.2.1"):
            with self.subTest(version=version):
                draft = from_openapi(specification(version), base_url="https://staging.example.invalid", path_prefix="/api")
                resources = draft["policy"]["resources"]
                self.assertEqual(len(resources), 2)
                self.assertTrue(all(not resource["allow"] for resource in resources))
                self.assertTrue(all(resource["path"].startswith("/api/") for resource in resources))
                self.assertEqual(draft["policy"]["base_url"], "https://staging.example.invalid")
                self.assertEqual(draft["source"]["skipped_non_get_operations"], 1)
                text = json.dumps(draft)
                self.assertNotIn("DO-NOT-COPY-EXAMPLES", text)
                self.assertNotIn("not-the-target", text)
                self.assertNotIn("deleteInvoice", text)
                self.assertIn("__SET_QUERY_VALUE__", text)

    def test_no_credential_or_response_examples_are_copied(self):
        document = specification()
        document["components"] = {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "description": "PRIVATE-DESCRIPTION"}}}
        document["paths"]["/exports"]["get"]["responses"]["200"]["example"] = {"token": "PRIVATE-EXAMPLE"}
        draft = from_openapi(document, base_url="https://api.example.invalid")
        self.assertNotIn("PRIVATE-", json.dumps(draft))

    def test_operation_and_path_selectors_are_explicit(self):
        draft = from_openapi(specification(), base_url="http://127.0.0.1:8080", operation_ids=["getInvoice"])
        self.assertEqual(len(draft["policy"]["resources"]), 1)
        self.assertIn("{invoiceId}", draft["policy"]["resources"][0]["path"])
        document = specification()
        del document["paths"]["/invoices/{invoiceId}"]["get"]["operationId"]
        selected = from_openapi(document, base_url="https://api.example.invalid", path_filters=["/invoices/{invoiceId}"])
        self.assertEqual(len(selected["policy"]["resources"]), 1)
        with self.assertRaises(PolicyError):
            from_openapi(document, base_url="https://api.example.invalid", path_filters=["/missing"])
        with self.assertRaises(PolicyError):
            from_openapi(document, base_url="https://api.example.invalid", operation_ids=["unknown"])

    def test_local_parameter_references_and_operation_overrides(self):
        document = specification()
        document["components"] = {"parameters": {"Account": {"name": "account", "in": "query", "required": True}}}
        document["paths"]["/exports"]["parameters"] = [{"$ref": "#/components/parameters/Account"}]
        document["paths"]["/exports"]["get"]["parameters"] = [{"name": "account", "in": "query", "required": False}]
        draft = from_openapi(document, base_url="https://api.example.invalid", operation_ids=["listExports"])
        self.assertEqual(draft["policy"]["resources"][0]["path"], "/exports")

    def test_local_path_item_reference(self):
        document = specification()
        document["components"] = {"pathItems": {"Invoice": document["paths"]["/invoices/{invoiceId}"]}}
        document["paths"]["/invoices/{invoiceId}"] = {"$ref": "#/components/pathItems/Invoice"}
        draft = from_openapi(document, base_url="https://api.example.invalid")
        self.assertEqual(len(draft["policy"]["resources"]), 2)

    def test_remote_cyclic_and_ambiguous_references_are_rejected_without_network(self):
        for reference in ({"$ref": "https://spec.example.invalid/remote.json"}, {"$ref": "#/paths/~1exports"}, {"$ref": "#/paths/~1exports", "get": {}}):
            document = specification()
            document["paths"]["/exports"] = reference
            with self.subTest(reference=reference), self.assertRaises(PolicyError):
                from_openapi(document, base_url="https://api.example.invalid")

    def test_oversize_spec_duplicate_json_and_unknown_version_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "api.json"
            path.write_bytes(b" " * (MAX_SPEC + 1))
            with self.assertRaises(PolicyError):
                read_spec(path)
            path.write_text('{"openapi":"3.1.1","openapi":"3.0.4"}', encoding="utf-8")
            with self.assertRaises(PolicyError):
                read_spec(path)
        with self.assertRaises(PolicyError):
            from_openapi(specification("2.0"), base_url="https://api.example.invalid")

    def test_excess_routes_require_selection_and_missing_operation_ids_still_work(self):
        document = specification()
        document["paths"] = {f"/resource-{number}": {"get": {}} for number in range(65)}
        with self.assertRaises(PolicyError):
            from_openapi(document, base_url="https://api.example.invalid")
        draft = from_openapi(document, base_url="https://api.example.invalid", path_filters=["/resource-0"])
        self.assertEqual(len(draft["policy"]["resources"]), 1)

    def test_required_unsupported_parameters_are_explicit_in_draft(self):
        document = specification()
        document["paths"]["/exports"]["get"]["parameters"].append({"name": "X-Required", "in": "header", "required": True})
        draft = from_openapi(document, base_url="https://api.example.invalid", operation_ids=["listExports"])
        self.assertEqual(draft["source"]["operations"][0]["unsupported_required_parameter_locations"], ["header"])

    def test_invalid_spec_shapes_produce_controlled_errors(self):
        for mutation in ("paths", "get", "location", "params", "duplicate_id"):
            document = specification()
            if mutation == "paths":
                document["paths"] = []
            elif mutation == "get":
                document["paths"]["/exports"]["get"] = []
            elif mutation == "location":
                document["paths"]["/exports"]["get"]["parameters"][0]["in"] = []
            elif mutation == "params":
                document["paths"]["/exports"]["get"]["parameters"] = "wrong"
            else:
                document["paths"]["/exports"]["get"]["operationId"] = "getInvoice"
            with self.subTest(mutation=mutation), self.assertRaises(PolicyError):
                from_openapi(document, base_url="https://api.example.invalid")

    def test_finalization_rejects_unresolved_parameters_and_missing_access_rules(self):
        draft = starter()
        draft["policy"] = demo_policy()
        draft["policy"]["resources"][0]["path"] = "/api/invoices/{invoiceId}"
        with self.assertRaises(PolicyError):
            finalize(draft)
        draft["policy"] = demo_policy()
        draft["policy"]["resources"][0]["allow"] = []
        with self.assertRaises(PolicyError):
            finalize(draft)

    def test_import_edit_finalize_run_complete_workflow(self):
        with tempfile.TemporaryDirectory() as folder, api() as (address, requests):
            root = Path(folder)
            source, draft_path, policy_path = root / "api.json", root / "draft.json", root / "policy.json"
            source.write_text(json.dumps(specification()), encoding="utf-8")
            with patch("tenantbreak.engine.Transport") as transport, redirect_stdout(io.StringIO()):
                self.assertEqual(main(["import-openapi", str(source), "--base-url", address, "--path-prefix", "/api", "--operation", "getInvoice", "--out", str(draft_path)]), 0)
                transport.assert_not_called()
            self.assertEqual(requests, [])
            draft = json.loads(draft_path.read_text())
            original = demo_policy()
            draft["policy"]["identity_check"] = original["identity_check"]
            draft["policy"]["identities"] = original["identities"]
            resource = draft["policy"]["resources"][0]
            resource.update(path="/api/invoices/inv-a104", tenant="acme", allow=["alice", "admin-acme"], control_identity="alice", match=original["resources"][0]["match"])
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["finalize", str(draft_path), "--out", str(policy_path)]), 0)
            report = run(load(policy_path), TOKENS)
            self.assertEqual(exit_code(report), 0)
            self.assertEqual(report["counts"], {"allowed": 2, "denied": 2})
            self.assertEqual(len(requests), 9)

    def test_setup_commands_preserve_existing_files_and_do_not_require_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "draft.json"
            with patch.dict("os.environ", {}, clear=True), patch("tenantbreak.engine.Transport") as transport, redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init", "--out", str(target)]), 0)
                transport.assert_not_called()
            original = target.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["init", "--out", str(target)]), 2)
            self.assertEqual(target.read_bytes(), original)

    def test_missing_yaml_extra_has_actionable_error(self):
        real_import = __import__
        def without_yaml(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("not installed")
            return real_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "api.yaml"
            path.write_text("openapi: 3.1.1\npaths: {}\n", encoding="utf-8")
            with patch("builtins.__import__", side_effect=without_yaml), self.assertRaisesRegex(PolicyError, "openapi"):
                read_spec(path)


@unittest.skipUnless(importlib.util.find_spec("yaml"), "optional OpenAPI YAML extra is not installed")
class YamlTests(unittest.TestCase):
    def load_text(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "api.yaml"
            path.write_text(text, encoding="utf-8")
            return read_spec(path)[0]

    def test_yaml_with_unquoted_response_codes_imports(self):
        document = self.load_text("openapi: 3.1.1\ninfo: {title: Synthetic, version: '1'}\npaths:\n  /invoices/{id}:\n    get:\n      operationId: getInvoice\n      responses:\n        200: {description: Invoice}\n")
        draft = from_openapi(document, base_url="https://api.example.invalid")
        self.assertEqual(len(draft["policy"]["resources"]), 1)

    def test_duplicate_alias_merge_and_python_tags_are_rejected(self):
        examples = ["openapi: 3.1.1\nopenapi: 3.0.4\n", "a: &a [1]\nb: *a\n", "a: &a {x: 1}\nb: {<<: *a}\n", "a: !!python/object/apply:os.system ['must-never-run']\n", "a: 2026-10-23\n"]
        for text in examples:
            with self.subTest(text=text), patch("os.system") as command:
                with self.assertRaises(PolicyError):
                    self.load_text(text)
                command.assert_not_called()

    def test_excessive_yaml_nesting_is_rejected(self):
        with self.assertRaises(PolicyError):
            self.load_text("a: " + "[" * 70 + "1" + "]" * 70)


if __name__ == "__main__":
    unittest.main()
