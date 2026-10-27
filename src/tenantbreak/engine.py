"""Verify identities and owner controls before assessing the access matrix."""

from collections import Counter
from datetime import datetime, timezone
import math

from . import __version__
from .config import PolicyError, fingerprint, origin, validate
from .auth import distinct, guard_secrets, refresh_one, supplied
from .selection import case_fingerprint, dependencies, select
from .transport import Response, Transport
from .evidence import assertions, evidence, matched, _scrub
from .collections import assess_read, read as read_collection


def assess(*, allowed, identity_valid, control_valid, http_status, checks, transport_error):
    if not identity_valid or not control_valid:
        return "inconclusive", "identity-unverified" if not identity_valid else "owner-control-failed"
    if transport_error:
        if transport_error == "non-json" and not allowed and http_status in {403, 404}:
            return "denied", "explicit-denial"
        return "error", transport_error
    if not allowed and matched(checks):
        return "confirmed-leak", "protected-resource-returned"
    if http_status == 401:
        return "error", "authentication-rejected"
    if allowed and http_status == 200 and matched(checks):
        return "allowed", "expected-resource-returned"
    if not allowed and any(check["matched"] for check in checks):
        return "inconclusive", "partial-protected-resource-match"
    if http_status is not None and http_status >= 500:
        return "error", "server-error"
    if not allowed and http_status in {403, 404}:
        return "denied", "explicit-denial"
    return "inconclusive", "expected-access-not-demonstrated" if allowed else "response-does-not-prove-denial-or-leak"


def prepare(policy, tokens, selected, *, base_url=None, timeout=5.0, max_seconds=120.0, allow_http=False,
            refresh_auth=False, refresh_sink=None):
    needed = dependencies(policy, selected)
    tokens = supplied(policy, tokens, needed, refresh_auth)
    if refresh_auth and not callable(refresh_sink):
        raise PolicyError("refresh requires a private credential output before requests begin")
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 3600 for value in (timeout, max_seconds)):
        raise ValueError("request timeout and run budget must be between 0 and 3600 seconds")
    base_url = origin(base_url or policy["base_url"], allow_http=allow_http)
    transport = Transport(base_url, timeout, max_seconds)
    refresh_errors = {}
    for identity in policy["identities"]:
        credential = tokens.get(identity["id"])
        if credential is not None and credential.refresh:
            error = refresh_one(transport, identity, credential, refresh_sink)
            if error:
                refresh_errors[identity["id"]] = error
    guard_secrets(policy, [value for credential in tokens.values() for value in credential.secrets])
    distinct(tokens)
    identity_results = []
    for identity in policy["identities"]:
        if identity["id"] not in needed:
            continue
        credential = tokens[identity["id"]]
        response = (Response(error=refresh_errors[identity["id"]]) if identity["id"] in refresh_errors
                    else transport.get(policy["identity_check"]["path"], credential.headers))
        checks = assertions(response.data, identity["verify"])
        valid = not response.error and response.status == 200 and matched(checks)
        identity_results.append({"id": identity["id"], "tenant": identity["tenant"], "role": identity["role"],
                                 "auth_type": credential.kind,
                                 "refresh_status": ("failed" if identity["id"] in refresh_errors else "succeeded") if credential.refresh else "not-requested",
                                 "valid": valid, **evidence(response, checks)})
    verified = {item["id"]: item["valid"] for item in identity_results}
    return base_url, transport, tokens, identity_results, verified


def read_resource(transport, resource, headers):
    if "collection" in resource:
        return read_collection(transport, resource, headers)
    response = transport.get(resource["path"], headers)
    item = evidence(response, assertions(response.data, resource["match"]))
    if "leak_match" in resource:
        item["leak_assertions"] = assertions(response.data, resource["leak_match"])
    return item


def run(policy, tokens, *, base_url=None, timeout=5.0, max_seconds=120.0, allow_http=False, mode="run",
        identity_ids=None, resource_ids=None, case_ids=None, refresh_auth=False, refresh_sink=None):
    validate(policy)
    if policy.get("kind") == "write":
        raise PolicyError("write policies require tenantbreak write with --enable-writes")
    if mode not in {"run", "demo-vulnerable", "demo-fixed"}:
        raise ValueError("unsupported run mode")
    selected = select(policy, identity_ids=identity_ids, resource_ids=resource_ids, case_ids=case_ids)
    base_url, transport, tokens, identity_results, verified = prepare(policy, tokens, selected, base_url=base_url,
        timeout=timeout, max_seconds=max_seconds, allow_http=allow_http, refresh_auth=refresh_auth, refresh_sink=refresh_sink)
    controls, cases = [], []
    for resource in policy["resources"]:
        if not any(case.startswith(resource["id"] + ":") for case in selected):
            continue
        controller = resource["control_identity"]
        if verified[controller]:
            item = read_resource(transport, resource, tokens[controller].headers)
            valid = not item["transport_error"] and item["http_status"] == 200 and matched(item["assertions"]) and item.get("coverage_complete", True)
            control = {"resource": resource["id"], "identity": controller, "valid": valid, **item}
        else:
            control = {"resource": resource["id"], "identity": controller, "valid": False,
                       "http_status": None, "assertions": [], "transport_error": "control-identity-unverified"}
        controls.append(control)
        for identity in policy["identities"]:
            if f"{resource['id']}:{identity['id']}" not in selected:
                continue
            allowed = identity["id"] in resource["allow"]
            case = {"id": f"{resource['id']}:{identity['id']}", "resource": resource["id"],
                    "label": resource["label"], "resource_tenant": resource["tenant"], "identity": identity["id"],
                    "identity_tenant": identity["tenant"], "role": identity["role"], "method": "GET",
                    "path": resource["path"], "expected": "allow" if allowed else "deny",
                    "control_valid": control["valid"], "identity_valid": verified[identity["id"]],
                    "definition_sha256": case_fingerprint(policy, resource, identity)}
            if not verified[identity["id"]] or not control["valid"]:
                case.update(status="inconclusive", reason="identity-unverified" if not verified[identity["id"]] else "owner-control-failed",
                            http_status=None, assertions=[], transport_error=None)
            else:
                case.update(read_resource(transport, resource, tokens[identity["id"]].headers))
                status, reason = assess_read(allowed=allowed, identity_valid=True, control_valid=True, item=case)
                case.update(status=status, reason=reason)
            cases.append(case)
    report = {"schema_version": 2, "tool": "TenantBreak", "version": __version__, "name": policy["name"],
              "created_at": datetime.now(timezone.utc).isoformat(), "mode": mode, "base_url": base_url,
              "policy_sha256": fingerprint(policy), "limits": {"timeout": timeout, "max_seconds": max_seconds},
              "authentication": {"refresh_requested": bool(refresh_auth)},
              "scope": {"total_cases": len(policy["identities"]) * len(policy["resources"]), "selected_cases": selected},
              "identities": identity_results, "controls": controls, "cases": cases,
              "counts": dict(Counter(case["status"] for case in cases)),
              "notes": ["Only the configured GET paths, identities and equality assertions were tested.",
                        "Denials require verified identities and a successful owner control.",
                        "Raw response bodies and authentication headers/cookies are not stored."]}
    if mode in {"demo-vulnerable", "demo-fixed"}:
        report["fixture_id"] = "tenantbreak-ledgercloud-v1"
    # Configuration strings can themselves accidentally contain credential values.
    secrets = {value for credential in tokens.values() for value in credential.secrets}
    return _scrub(report, sorted(secrets, key=len, reverse=True))


def exit_code(report):
    if report.get("interrupted"):
        return 130
    if any(not i["valid"] for i in report["identities"]) or any(not c["valid"] for c in report["controls"]):
        return 2
    if any(c["status"] in {"error", "inconclusive"} for c in report["cases"]):
        return 2
    if any(not c.get("coverage_complete", True) or not c.get("cleanup_verified", True) or not c.get("execution_complete", True) for c in report["cases"]):
        return 2
    return 1 if any(c["status"] in {"confirmed-leak", "confirmed-write"} for c in report["cases"]) else 0
