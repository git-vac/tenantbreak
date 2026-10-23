"""Verify identities and owner controls before assessing the access matrix."""

from collections import Counter
from datetime import datetime, timezone
import math

from . import __version__
from .config import credentials, fingerprint, origin, validate
from .selection import case_fingerprint, dependencies, select
from .transport import Transport


def assertions(data, expected):
    results = []
    for pointer, wanted in expected.items():
        current = data
        present = True
        for token in pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isascii() and token.isdigit() and (token == "0" or not token.startswith("0")) and len(token) < 10 and int(token) < len(current):
                current = current[int(token)]
            else:
                present = False
                break
        # Python's bool is an int; JSON true must never match numeric 1.
        same_type = type(current) is type(wanted) or (type(current) in (int, float) and type(wanted) in (int, float))
        results.append({"pointer": pointer, "present": present, "matched": present and same_type and current == wanted})
    return results


def matched(checks):
    return bool(checks) and all(check["matched"] for check in checks)


def evidence(response, checks):
    return {"http_status": response.status, "response_sha256": response.digest,
            "response_bytes": response.size, "elapsed_ms": response.elapsed_ms,
            "assertions": checks, "transport_error": response.error}


def _scrub(value, secrets):
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, list):
        return [_scrub(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _scrub(item, secrets) for key, item in value.items()}
    return value


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


def run(policy, tokens, *, base_url=None, timeout=5.0, max_seconds=120.0, allow_http=False, mode="run",
        identity_ids=None, resource_ids=None, case_ids=None):
    validate(policy)
    if mode not in {"run", "demo-vulnerable", "demo-fixed"}:
        raise ValueError("unsupported run mode")
    selected = select(policy, identity_ids=identity_ids, resource_ids=resource_ids, case_ids=case_ids)
    needed = dependencies(policy, selected)
    tokens = credentials(policy, {identity["token_env"]: tokens.get(identity["id"], "") for identity in policy["identities"]}, needed)
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 3600 for value in (timeout, max_seconds)):
        raise ValueError("request timeout and run budget must be between 0 and 3600 seconds")
    base_url = origin(base_url or policy["base_url"], allow_http=allow_http)
    transport = Transport(base_url, timeout, max_seconds)
    identity_results = []
    for identity in policy["identities"]:
        if identity["id"] not in needed:
            continue
        response = transport.get(policy["identity_check"]["path"], tokens[identity["id"]])
        checks = assertions(response.data, identity["verify"])
        valid = not response.error and response.status == 200 and matched(checks)
        identity_results.append({"id": identity["id"], "tenant": identity["tenant"], "role": identity["role"],
                                 "valid": valid, **evidence(response, checks)})
    verified = {item["id"]: item["valid"] for item in identity_results}
    controls, cases = [], []
    for resource in policy["resources"]:
        if not any(case.startswith(resource["id"] + ":") for case in selected):
            continue
        controller = resource["control_identity"]
        if verified[controller]:
            response = transport.get(resource["path"], tokens[controller])
            checks = assertions(response.data, resource["match"])
            valid = not response.error and response.status == 200 and matched(checks)
            control = {"resource": resource["id"], "identity": controller, "valid": valid, **evidence(response, checks)}
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
                response = transport.get(resource["path"], tokens[identity["id"]])
                checks = assertions(response.data, resource["match"])
                case.update(evidence(response, checks))
                status, reason = assess(allowed=allowed, identity_valid=True, control_valid=True,
                                        http_status=response.status, checks=checks, transport_error=response.error)
                case.update(status=status, reason=reason)
            cases.append(case)
    report = {"schema_version": 2, "tool": "TenantBreak", "version": __version__, "name": policy["name"],
              "created_at": datetime.now(timezone.utc).isoformat(), "mode": mode, "base_url": base_url,
              "policy_sha256": fingerprint(policy), "limits": {"timeout": timeout, "max_seconds": max_seconds},
              "scope": {"total_cases": len(policy["identities"]) * len(policy["resources"]), "selected_cases": selected},
              "identities": identity_results, "controls": controls, "cases": cases,
              "counts": dict(Counter(case["status"] for case in cases)),
              "notes": ["Only the configured GET paths, identities and equality assertions were tested.",
                        "Denials require verified identities and a successful owner control.",
                        "Raw response bodies and authorization headers are not stored."]}
    if mode in {"demo-vulnerable", "demo-fixed"}:
        report["fixture_id"] = "tenantbreak-ledgercloud-v1"
    # Configuration strings can themselves accidentally contain credential values.
    return _scrub(report, sorted(set(tokens.values()), key=len, reverse=True))


def exit_code(report):
    if any(not i["valid"] for i in report["identities"]) or any(not c["valid"] for c in report["controls"]):
        return 2
    if any(c["status"] in {"error", "inconclusive"} for c in report["cases"]):
        return 2
    return 1 if any(c["status"] == "confirmed-leak" for c in report["cases"]) else 0
