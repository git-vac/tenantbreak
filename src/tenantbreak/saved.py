"""Bounded offline report loading; derive outcomes again from recorded evidence."""

from collections import Counter
from copy import deepcopy
from datetime import datetime
import hashlib
import math
from pathlib import Path
import re

from .config import PolicyError, _object, _slug, _string, decode_json, fingerprint, origin, request_path, validate
from .engine import assess, matched
from .selection import case_fingerprint, select
from .collections import assess_read, validate_evidence as validate_collection
from .writes import aggregate, assess_trial, cleanup_good, complete, validate_trial

MAX_REPORT = 16 * 1024 * 1024
STATUSES = {"allowed", "denied", "confirmed-leak", "confirmed-write", "inconclusive", "error"}


def _require(condition):
    if not condition:
        raise PolicyError("invalid saved report: inconsistent or unsupported evidence")


def _digest(value, optional=False):
    _require((optional and value is None) or (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)))


def _evidence(item):
    status = item.get("http_status")
    _require(status is None or (type(status) is int and 100 <= status <= 599))
    error = item.get("transport_error")
    _require(error is None or (isinstance(error, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,79}", error)))
    _digest(item.get("response_sha256"), optional=True)
    for name, maximum in (("response_bytes", 1024 * 1024 + 1), ("elapsed_ms", 7200000)):
        _require(type(item.get(name, 0)) is int and 0 <= item.get(name, 0) <= maximum)
    checks = item.get("assertions")
    _require(isinstance(checks, list) and len(checks) <= 16)
    seen = set()
    for check in checks:
        _object(check, {"pointer", "present", "matched"}, {"pointer", "present", "matched"}, "report assertion")
        pointer = _string(check["pointer"], "report pointer", 256)
        _require(pointer.startswith("/") and not re.search(r"~(?![01])", pointer) and pointer not in seen)
        seen.add(pointer)
        _require(type(check["present"]) is bool and type(check["matched"]) is bool)
        _require(not check["matched"] or check["present"])
    if status is not None and error is None:
        _digest(item.get("response_sha256"))
    return status == 200 and error is None and len(checks) >= 2 and matched(checks)


def _normalize(report):
    """Validate structure, copy it, and recompute flags/statuses/counts; not authentication."""
    _object(report, {"schema_version", "tool", "version", "name", "created_at", "mode", "base_url", "policy_sha256",
                     "limits", "scope", "fixture_id", "replay_of", "authentication", "identities", "controls", "cases", "counts", "notes", "kind", "write_limits", "interrupted"},
            {"schema_version", "tool", "version", "name", "created_at", "mode", "base_url", "policy_sha256",
             "limits", "identities", "controls", "cases", "counts", "notes"}, "saved report")
    result = deepcopy(report)
    writing = result.get("kind") == "write"
    _require("kind" not in result or writing)
    if writing:
        _object(result.get("write_limits"), {"cleanup_seconds"}, {"cleanup_seconds"}, "write limits")
        seconds = result["write_limits"]["cleanup_seconds"]
        _require(type(seconds) in (float, int) and math.isfinite(seconds) and 1 <= seconds <= 120)
        _require(type(result.get("interrupted")) is bool)
    else:
        _require("write_limits" not in result and "interrupted" not in result)
    _require(type(result["schema_version"]) is int and result["schema_version"] in {1, 2} and result["tool"] == "TenantBreak")
    for name in ("version", "name", "created_at"):
        _string(result[name], "report metadata", 256)
    try:
        _require(datetime.fromisoformat(result["created_at"]).utcoffset() is not None)
    except ValueError as exc:
        raise PolicyError("invalid saved report: timestamp") from exc
    _require(result["mode"] in {"run", "demo-vulnerable", "demo-fixed"})
    result["base_url"] = origin(result["base_url"], allow_http=True)
    _digest(result["policy_sha256"])
    if "replay_of" in result:
        _digest(result["replay_of"])
    if "fixture_id" in result:
        _require(result["fixture_id"] == "tenantbreak-ledgercloud-v1" and result["mode"].startswith("demo-"))
    if "authentication" in result:
        _object(result["authentication"], {"refresh_requested"}, {"refresh_requested"}, "report authentication")
        _require(type(result["authentication"]["refresh_requested"]) is bool)
    _object(result["limits"], {"timeout", "max_seconds"}, {"timeout", "max_seconds"}, "report limits")
    for value in result["limits"].values():
        _require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 3600)
    _require(isinstance(result["notes"], list) and len(result["notes"]) <= 16)
    for note in result["notes"]:
        _string(note, "report note", 1024)
    _require(isinstance(result["identities"], list) and 1 <= len(result["identities"]) <= 32)
    identity_map = {}
    evidence_keys = {"http_status", "response_sha256", "response_bytes", "elapsed_ms", "assertions", "transport_error"}
    read_keys = {"collection", "coverage_complete", "leak_assertions", "identify_assertions"}
    write_keys = {"write", "cleanup_verified", "execution_complete"}
    def extended(item):
        valid = _evidence(item)
        if "leak_assertions" in item:
            _evidence({**item, "assertions": item["leak_assertions"]})
            _require({c["pointer"] for c in item["leak_assertions"]} <= {c["pointer"] for c in item["assertions"]})
            _require(len(item["leak_assertions"]) in {0, *range(2, 17)})
            full = {c["pointer"]: c for c in item["assertions"]}
            _require(all(c == full[c["pointer"]] for c in item["leak_assertions"]))
        if "collection" in item:
            validate_collection(item, _evidence, _require, _digest)
            valid = valid and item["coverage_complete"]
        else:
            _require("coverage_complete" not in item and "identify_assertions" not in item)
        return valid
    for identity in result["identities"]:
        _object(identity, {"id", "tenant", "role", "valid", "auth_type", "refresh_status"} | evidence_keys,
                {"id", "tenant", "role", "valid", "http_status", "assertions", "transport_error"}, "report identity")
        _slug(identity["id"], "report identity")
        _require(identity["id"] not in identity_map and type(identity["valid"]) is bool)
        _string(identity["tenant"], "report tenant", 100)
        _string(identity["role"], "report role", 100)
        identity["valid"] = _evidence(identity)
        if "auth_type" in identity:
            _require(identity["auth_type"] in {"bearer", "headers", "cookies"})
        if "refresh_status" in identity:
            _require(identity["refresh_status"] in {"not-requested", "succeeded", "failed"})
            if identity["refresh_status"] != "not-requested":
                _require(result.get("authentication", {}).get("refresh_requested") is True and identity.get("auth_type") == "bearer")
            if identity["refresh_status"] == "failed":
                _require(not identity["valid"] and identity["http_status"] is None
                         and isinstance(identity["transport_error"], str) and identity["transport_error"].startswith("refresh-"))
        identity_map[identity["id"]] = identity
    _require(isinstance(result["controls"], list) and 1 <= len(result["controls"]) <= 64)
    control_map = {}
    for control in result["controls"]:
        _object(control, {"resource", "identity", "valid"} | evidence_keys | (write_keys if writing else read_keys),
                {"resource", "identity", "valid", "http_status", "assertions", "transport_error"}, "report control")
        _slug(control["resource"], "report resource")
        _require(isinstance(control["identity"], str) and control["identity"] in identity_map)
        _require(control["resource"] not in control_map and type(control["valid"]) is bool)
        if writing and "write" in control:
            trial = validate_trial(control["write"], _evidence, _require)
            _require(all(control[key] == value for key, value in aggregate(trial).items()))
            control["cleanup_verified"] = cleanup_good(trial)
            control["valid"] = identity_map[control["identity"]]["valid"] and assess_trial(trial, True)[0] == "allowed" and complete(trial)
        else:
            valid = extended(control)
            control["valid"] = identity_map[control["identity"]]["valid"] and valid and not writing
        control_map[control["resource"]] = control
    _require(isinstance(result["cases"], list) and 1 <= len(result["cases"]) <= 2048)
    seen = set()
    for case in result["cases"]:
        fields = {"id", "resource", "label", "resource_tenant", "identity", "identity_tenant", "role", "method", "path", "expected",
                  "control_valid", "identity_valid", "definition_sha256", "status", "reason"} | evidence_keys
        _object(case, fields | (write_keys if writing else read_keys), fields - {"definition_sha256", "response_sha256", "response_bytes", "elapsed_ms"}, "report case")
        _require(isinstance(case["identity"], str) and case["identity"] in identity_map)
        _require(isinstance(case["resource"], str) and case["resource"] in control_map)
        _require(case["id"] == case["resource"] + ":" + case["identity"] and case["id"] not in seen)
        seen.add(case["id"])
        for name, maximum in (("label", 120), ("resource_tenant", 100), ("reason", 120)):
            _string(case[name], "report case metadata", maximum)
        _require(case["method"] in ({"POST", "PUT", "PATCH", "DELETE"} if writing else {"GET"}) and case["expected"] in {"allow", "deny"} and case["status"] in STATUSES)
        _require(writing or case["status"] != "confirmed-write")
        request_path(case["path"])
        identity, control = identity_map[case["identity"]], control_map[case["resource"]]
        _require(case["identity_tenant"] == identity["tenant"] and case["role"] == identity["role"])
        _require(type(case["identity_valid"]) is bool and type(case["control_valid"]) is bool)
        if writing:
            _evidence(case)
        else:
            extended(case)
        if result["schema_version"] == 2:
            _digest(case.get("definition_sha256"))
        case["identity_valid"], case["control_valid"] = identity["valid"], control["valid"]
        if writing:
            if "write" in case:
                _require(case["identity_valid"] and case["control_valid"])
                trial = validate_trial(case["write"], _evidence, _require)
                _require(all(case[key] == value for key, value in aggregate(trial).items()))
                case["status"], case["reason"] = assess_trial(trial, case["expected"] == "allow")
                case["cleanup_verified"], case["execution_complete"] = cleanup_good(trial), complete(trial)
            else:
                _require(case["http_status"] is None and not case["assertions"] and case["transport_error"] in {"writes-stopped", "owner-control-failed", "identity-unverified"})
                case["status"], case["reason"] = "inconclusive", case["transport_error"]
            continue
        if case["identity_valid"] and case["control_valid"]:
            _require(case["http_status"] is not None or case["transport_error"] is not None)
            _require({check["pointer"] for check in case["assertions"]} == {check["pointer"] for check in control["assertions"]})
        else:
            # The engine never executes access probes when their prerequisites fail.
            _require(case["http_status"] is None and not case["assertions"])
        case["status"], case["reason"] = assess_read(allowed=case["expected"] == "allow", identity_valid=case["identity_valid"],
            control_valid=case["control_valid"], item=case)
    _require({case["resource"] for case in result["cases"]} == set(control_map))
    _require(set(identity_map) == {case["identity"] for case in result["cases"]} | {control["identity"] for control in result["controls"]})
    if result["schema_version"] == 2:
        _object(result.get("scope"), {"total_cases", "selected_cases"}, {"total_cases", "selected_cases"}, "report scope")
        scope = result["scope"]
        _require(type(scope["total_cases"]) is int and len(seen) <= scope["total_cases"] <= 2048)
        _require(isinstance(scope["selected_cases"], list) and all(isinstance(case, str) for case in scope["selected_cases"]))
        _require(len(scope["selected_cases"]) == len(seen) and set(scope["selected_cases"]) == seen)
    result["counts"] = dict(Counter(case["status"] for case in result["cases"]))
    if writing:
        _require(result["interrupted"] == any(item.get("write", {}).get("interrupted", False) for item in result["controls"] + result["cases"]))
    return result


def normalize(report):
    try:
        return _normalize(report)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("invalid saved report: inconsistent or unsupported evidence") from exc


def load_report(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_REPORT + 1)
        _require(len(data) <= MAX_REPORT)
        return normalize(decode_json(data)), hashlib.sha256(data).hexdigest()
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("cannot load saved report: expected bounded TenantBreak JSON evidence") from exc


def replay_cases(policy, report, case_ids=None):
    validate(policy)
    if policy.get("kind") == "write" or report.get("kind") == "write":
        raise PolicyError("write reports are compared offline; rerun writes explicitly with tenantbreak write")
    if fingerprint(policy) != report["policy_sha256"]:
        raise PolicyError("replay policy differs from the saved run; use run to evaluate a changed policy")
    source = {case["id"]: case for case in report["cases"]}
    selected = case_ids if case_ids is not None else [case["id"] for case in report["cases"] if case["status"] == "confirmed-leak"]
    if not selected or any(case not in source for case in selected):
        raise PolicyError("replay requires recorded case ids; no confirmed leaks were available or a selected case was not recorded")
    selected = select(policy, case_ids=selected)
    for resource in policy["resources"]:
        for identity in policy["identities"]:
            key = f"{resource['id']}:{identity['id']}"
            if key not in selected:
                continue
            recorded = source[key]
            expected = "allow" if identity["id"] in resource["allow"] else "deny"
            if recorded["path"] != resource["path"] or recorded["expected"] != expected:
                raise PolicyError("saved case metadata does not match the replay policy")
            if report["schema_version"] == 2 and recorded["definition_sha256"] != case_fingerprint(policy, resource, identity):
                raise PolicyError("saved case definition differs from the replay policy")
    return selected
