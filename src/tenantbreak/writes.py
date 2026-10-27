"""Explicit disposable-fixture mutations, independent observations and verified reset."""

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import json
import math

from . import __version__
from .config import PolicyError, _object, _matches, fingerprint, request_path, validate
from .evidence import assertions, evidence, matched, _scrub
from .selection import case_fingerprint, select
from .transport import Response, Transport


def validate_write(policy):
    _object(policy, {"kind", "disposable", "version", "name", "base_url", "identity_check", "identities", "resources"},
            {"kind", "disposable", "version", "name", "base_url", "identity_check", "identities", "resources"}, "write policy")
    if policy["kind"] != "write" or policy["disposable"] is not True:
        raise PolicyError("write policies must declare kind=write and disposable=true")
    if not isinstance(policy["resources"], list) or not 1 <= len(policy["resources"]) <= 8:
        raise PolicyError("write policies require 1 to 8 disposable fixtures")
    projected = {key: value for key, value in policy.items() if key not in {"kind", "disposable"}}
    projected["resources"] = [{key: value for key, value in resource.items() if key != "write"} if isinstance(resource, dict) else resource for resource in policy["resources"]]
    validate(projected)
    seen = set()
    for resource in policy["resources"]:
        if "collection" in resource or "leak_match" in resource:
            raise PolicyError("write fixtures cannot contain collection or leak_match definitions")
        if resource["path"] in seen:
            raise PolicyError("each write fixture needs a distinct observation path")
        seen.add(resource["path"])
        spec = resource.get("write")
        _object(spec, {"scope", "fixture_pointer", "guard", "before", "after", "request", "reset"},
                {"scope", "fixture_pointer", "guard", "before", "after", "request", "reset"}, "write fixture")
        scope = request_path(spec["scope"])
        if not scope.endswith("/") or len([part for part in scope.split("/") if part]) < 2:
            raise PolicyError("write scope must be a concrete disposable namespace ending in / with at least two path segments")
        def scoped(path):
            request_path(path)
            if not path.startswith(scope) or any(c in path for c in "%?{}") or any(part in {".", ".."} for part in path.split("/")):
                raise PolicyError("write paths must stay inside the concrete scope without queries, escapes or traversal")
        scoped(resource["path"])
        marker = spec["fixture_pointer"]
        if not isinstance(marker, str) or marker not in resource["match"] or not isinstance(resource["match"][marker], str) or len(resource["match"][marker]) < 12:
            raise PolicyError("fixture_pointer must name a specific disposable marker string in resource match (at least 12 characters)")
        if len(resource["match"]) < 3:
            raise PolicyError("write fixture match requires at least three identifying assertions")
        guard = spec["guard"]
        _object(guard, {"path", "match", "disposable_pointer"}, {"path", "match", "disposable_pointer"}, "write guard")
        scoped(guard["path"])
        if guard["path"] == resource["path"]:
            raise PolicyError("the disposable namespace guard must be separate from the mutated fixture")
        _matches(guard["match"], "guard match")
        if not isinstance(guard["disposable_pointer"], str) or len(guard["match"]) < 3 or guard["match"].get(guard["disposable_pointer"]) is not True:
            raise PolicyError("guard match requires three assertions including an explicit disposable=true field")
        for key in ("before", "after"):
            state = spec[key]
            _object(state, {"status", "match"}, {"status"}, "write state")
            if type(state["status"]) is not int or state["status"] not in {200, 404}:
                raise PolicyError("observed write states must use HTTP 200 or 404")
            if state["status"] == 200:
                _matches(state.get("match"), "observed state match")
                for pointer, value in state["match"].items():
                    if pointer in resource["match"] and (type(value) is not type(resource["match"][pointer]) or value != resource["match"][pointer]):
                        raise PolicyError("observed state cannot change the fixture identity")
                if len(set(state["match"]) | set(resource["match"])) > 16:
                    raise PolicyError("combined fixture/state assertions must not exceed 16")
            elif "match" in state:
                raise PolicyError("an absent state must not include match assertions")
        before, after = spec["before"], spec["after"]
        if before["status"] == after["status"] and (before["status"] == 404 or not any(
                key in after["match"] and ((type(value) is bool) != (type(after["match"][key]) is bool) or value != after["match"][key]) for key, value in before["match"].items())):
            raise PolicyError("before and after states must be mutually exclusive")
        for key in ("request", "reset"):
            action = spec[key]
            _object(action, {"method", "path", "json"}, {"method", "path"}, "write request")
            if not isinstance(action["method"], str) or action["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
                raise PolicyError("write methods must be POST, PUT, PATCH or DELETE")
            scoped(action["path"])
            if action["path"] == guard["path"]:
                raise PolicyError("write actions cannot target the disposable namespace guard")
            if action["path"] != resource["path"]:
                if (action["method"] != "POST" or action["path"] != resource["path"].rsplit("/", 1)[0]
                        or not matched(assertions(action.get("json"), resource["match"]))):
                    raise PolicyError("mutations must target the fixture path; parent POST requires explicit matching fixture identifiers in its JSON body")
            try:
                payload = json.dumps(action.get("json"), allow_nan=False, ensure_ascii=True)
            except (ValueError, TypeError, RecursionError) as exc:
                raise PolicyError("write request needs a bounded JSON body") from exc
            if len(payload.encode()) > 16384:
                raise PolicyError("write request JSON exceeds 16 KiB")
    guards = {resource["write"]["guard"]["path"] for resource in policy["resources"]}
    if any(resource["path"] in guards or any(resource["write"][key]["path"] in guards for key in ("request", "reset")) for resource in policy["resources"]):
        raise PolicyError("a fixture or mutation cannot target another fixture's namespace guard")
    return policy


def observe(transport, path, headers, expected):
    response = transport.get(path, headers)
    return response, evidence(response, assertions(response.data, expected))


def good(item, status=200):
    return bool(item and not item["transport_error"] and item["http_status"] == status and (status == 404 or matched(item["assertions"])))


def state_match(resource, state):
    return {**resource["match"], **state.get("match", {})} if state["status"] == 200 else {}


def state_evidence(response, resource, state):
    item = evidence(response, assertions(response.data, state_match(resource, state)))
    if state["status"] == 404 and item["transport_error"] == "non-json":
        item["transport_error"] = None
    return item


def assess_trial(trial, allowed):
    if not trial:
        return "inconclusive", "write-not-run"
    before_status, after_status = trial["before_status"], trial["after_status"]
    if not all(good(trial.get(key)) for key in ("guard_before", "observer_before", "actor_before")) or not good(trial.get("before"), before_status):
        return "inconclusive", "write-precondition-failed"
    if not trial.get("request"):
        return "inconclusive", "write-not-run"
    identities = all(good(trial.get(key)) for key in ("actor_after", "observer_after", "guard_after"))
    changed = identities and good(trial.get("after"), after_status)
    if changed and not allowed:
        return "confirmed-write", "forbidden-state-change-observed"
    if trial["interrupted"]:
        return "error", "run-interrupted"
    if not identities:
        return "inconclusive", "post-write-identity-or-guard-failed"
    request = trial["request"]
    if request["transport_error"] or request["http_status"] is None or request["http_status"] == 401 or request["http_status"] >= 500:
        return "error", request["transport_error"] or "write-request-failed"
    if changed and allowed:
        return "allowed", "expected-state-change-observed"
    if not allowed and request["http_status"] in {403, 404} and good(trial.get("unchanged"), before_status):
        return "denied", "write-denied-state-unchanged"
    return "inconclusive", "write-effect-not-established"


def cleanup_good(trial):
    if not trial.get("request"):
        return True
    cleanup = trial["cleanup"]
    # A timed-out/interrupted mutation can still be executing on the server.
    # Perform best-effort reset, but never claim verified cleanup or continue.
    if trial["request"]["transport_error"]:
        return False
    reset = (cleanup or {}).get("reset")
    if reset and (reset["transport_error"] or reset["http_status"] is None or not 200 <= reset["http_status"] < 300):
        return False
    return bool(cleanup and all(good(cleanup.get(key)) for key in ("identity", "guard", "final_identity", "final_guard"))
                and good(cleanup.get("final"), trial["before_status"]))


def complete(trial):
    request = trial.get("request")
    return bool(request and not request["transport_error"] and request["http_status"] is not None
                and request["http_status"] != 401 and request["http_status"] < 500 and cleanup_good(trial)
                and all(good(trial.get(key)) for key in ("actor_before", "actor_after", "observer_after", "guard_before", "guard_after")))


def attempt(policy, resource, actor, tokens, transport, base_url, timeout, cleanup_seconds):
    spec = resource["write"]
    owner = next(identity for identity in policy["identities"] if identity["id"] == resource["control_identity"])
    owner_headers, actor_headers = tokens[owner["id"]].headers, tokens[actor["id"]].headers
    trial = {key: None for key in ("observer_before", "guard_before", "before", "actor_before", "request", "actor_after", "observer_after", "guard_after", "after", "unchanged", "cleanup")}
    trial.update(before_status=spec["before"]["status"], after_status=spec["after"]["status"], interrupted=False)
    def identity_check(channel, identity, headers):
        return observe(channel, policy["identity_check"]["path"], headers, identity["verify"])[1]
    def guard_check(channel):
        return observe(channel, spec["guard"]["path"], owner_headers, spec["guard"]["match"])[1]
    try:
        trial["observer_before"] = identity_check(transport, owner, owner_headers)
        trial["guard_before"] = guard_check(transport)
        response = transport.get(resource["path"], owner_headers)
        trial["before"] = state_evidence(response, resource, spec["before"])
        trial["actor_before"] = identity_check(transport, actor, actor_headers)
        if not good(trial["observer_before"]) or not good(trial["guard_before"]) or not good(trial["before"], trial["before_status"]) or not good(trial["actor_before"]):
            return trial
        # Mark dispatch before I/O: a timeout or interrupt may follow a real mutation.
        trial["request"] = evidence(Response(error="write-no-response"), [])
        trial["request"] = evidence(transport.write(spec["request"], actor_headers), [])
        trial["actor_after"] = identity_check(transport, actor, actor_headers)
        trial["observer_after"] = identity_check(transport, owner, owner_headers)
        trial["guard_after"] = guard_check(transport)
        response = transport.get(resource["path"], owner_headers)
        trial["after"] = state_evidence(response, resource, spec["after"])
        trial["unchanged"] = state_evidence(response, resource, spec["before"])
    except KeyboardInterrupt:
        trial["interrupted"] = True
    finally:
        if trial["request"] is not None:
            cleanup = {key: None for key in ("identity", "guard", "current", "reset", "final_identity", "final_guard", "final")}
            trial["cleanup"] = cleanup
            channel = Transport(base_url, min(timeout, cleanup_seconds), cleanup_seconds)
            try:
                cleanup["identity"] = identity_check(channel, owner, owner_headers)
                cleanup["guard"] = guard_check(channel)
                current = channel.get(resource["path"], owner_headers)
                cleanup["current"] = state_evidence(current, resource, {"status": 200, "match": {}})
                if current.status == 404 and current.error == "non-json":
                    cleanup["current"]["transport_error"] = None
                owned = good(cleanup["current"]) or (current.status == 404 and current.error in {None, "non-json"})
                if good(cleanup["identity"]) and good(cleanup["guard"]) and owned:
                    already = state_evidence(current, resource, spec["before"])
                    if not good(already, trial["before_status"]):
                        cleanup["reset"] = evidence(channel.write(spec["reset"], owner_headers), [])
                    cleanup["final_identity"] = identity_check(channel, owner, owner_headers)
                    cleanup["final_guard"] = guard_check(channel)
                    response = channel.get(resource["path"], owner_headers)
                    cleanup["final"] = state_evidence(response, resource, spec["before"])
            except KeyboardInterrupt:
                trial["interrupted"] = True
    return trial


def aggregate(trial):
    return deepcopy(trial.get("after") or trial.get("before") or evidence(Response(error="write-not-run"), []))


def run_writes(policy, tokens, *, enable_writes=False, base_url=None, timeout=5.0, max_seconds=120.0,
               cleanup_seconds=10.0, allow_http=False, identity_ids=None, resource_ids=None, case_ids=None,
               refresh_auth=False, refresh_sink=None, mode="run"):
    from .engine import prepare
    validate_write(policy)
    if not enable_writes:
        raise PolicyError("write testing requires --enable-writes and a disposable fixture policy")
    if type(cleanup_seconds) not in (int, float) or not math.isfinite(cleanup_seconds) or not 1 <= cleanup_seconds <= 120:
        raise PolicyError("cleanup_seconds must be between 1 and 120")
    if mode not in {"run", "demo-vulnerable", "demo-fixed"}:
        raise PolicyError("unsupported write run mode")
    selected = select(policy, identity_ids=identity_ids, resource_ids=resource_ids, case_ids=case_ids)
    base_url, channel, tokens, identities, verified = prepare(policy, tokens, selected, base_url=base_url, timeout=timeout,
        max_seconds=max_seconds, allow_http=allow_http, refresh_auth=refresh_auth, refresh_sink=refresh_sink)
    controls, cases, halted, interrupted = [], [], False, False
    for resource in policy["resources"]:
        if not any(case.startswith(resource["id"] + ":") for case in selected):
            continue
        controller = resource["control_identity"]
        owner = next(identity for identity in policy["identities"] if identity["id"] == controller)
        control = {"resource": resource["id"], "identity": controller, "valid": False, **evidence(Response(error="write-not-run"), [])}
        if verified[controller] and not halted:
            trial = attempt(policy, resource, owner, tokens, channel, base_url, timeout, cleanup_seconds)
            control.update(aggregate(trial), write=trial, cleanup_verified=cleanup_good(trial))
            control["valid"] = assess_trial(trial, True)[0] == "allowed" and complete(trial)
            interrupted |= trial["interrupted"]
            halted |= not cleanup_good(trial) or interrupted or not good(trial.get("before"), trial["before_status"])
        controls.append(control)
        for identity in policy["identities"]:
            key = f"{resource['id']}:{identity['id']}"
            if key not in selected:
                continue
            allowed = identity["id"] in resource["allow"]
            case = {"id": key, "resource": resource["id"], "label": resource["label"], "resource_tenant": resource["tenant"],
                    "identity": identity["id"], "identity_tenant": identity["tenant"], "role": identity["role"],
                    "method": resource["write"]["request"]["method"], "path": resource["write"]["request"]["path"],
                    "expected": "allow" if allowed else "deny", "identity_valid": verified[identity["id"]],
                    "control_valid": control["valid"], "definition_sha256": case_fingerprint(policy, resource, identity)}
            if halted or not control["valid"] or not verified[identity["id"]]:
                reason = "writes-stopped" if halted else "owner-control-failed" if not control["valid"] else "identity-unverified"
                case.update(evidence(Response(error=reason), []), status="inconclusive", reason=reason, cleanup_verified=not halted)
            else:
                trial = attempt(policy, resource, identity, tokens, channel, base_url, timeout, cleanup_seconds)
                status, reason = assess_trial(trial, allowed)
                case.update(aggregate(trial), write=trial, status=status, reason=reason,
                            cleanup_verified=cleanup_good(trial), execution_complete=complete(trial))
                interrupted |= trial["interrupted"]
                halted |= not cleanup_good(trial) or interrupted or not good(trial.get("before"), trial["before_status"])
            cases.append(case)
    report = {"schema_version": 2, "kind": "write", "tool": "TenantBreak", "version": __version__, "name": policy["name"],
              "created_at": datetime.now(timezone.utc).isoformat(), "mode": mode, "base_url": base_url,
              "policy_sha256": fingerprint(policy), "limits": {"timeout": timeout, "max_seconds": max_seconds},
              "write_limits": {"cleanup_seconds": cleanup_seconds}, "authentication": {"refresh_requested": bool(refresh_auth)},
              "scope": {"total_cases": len(policy["identities"]) * len(policy["resources"]), "selected_cases": selected},
              "identities": identities, "controls": controls, "cases": cases, "interrupted": interrupted,
              "counts": dict(Counter(case["status"] for case in cases)),
              "notes": ["Only the configured disposable fixture operations and observed state assertions were tested.",
                        "Write effects are verified through independent reads as the control account.",
                        "Cleanup has a separate bounded budget. Unverified cleanup stops subsequent writes.",
                        "Request bodies, response bodies and credential values are omitted."]}
    if mode.startswith("demo-"):
        report["fixture_id"] = "tenantbreak-ledgercloud-v1"
    return _scrub(report, sorted({value for credential in tokens.values() for value in credential.secrets}, key=len, reverse=True))


def validate_trial(trial, check, require):
    fields = {"observer_before", "guard_before", "before", "actor_before", "request", "actor_after", "observer_after", "guard_after", "after", "unchanged", "cleanup", "before_status", "after_status", "interrupted"}
    _object(trial, fields, fields, "saved write trial")
    require(type(trial["interrupted"]) is bool)
    for key in ("before_status", "after_status"):
        require(type(trial[key]) is int and trial[key] in {200, 404})
    require(trial["before_status"] != 404 or trial["after_status"] != 404)
    keys = {"http_status", "response_sha256", "response_bytes", "elapsed_ms", "assertions", "transport_error"}
    def item(value):
        if value is not None:
            _object(value, keys, keys, "saved write observation")
            check(value)
    for key in fields - {"cleanup", "interrupted", "before_status", "after_status"}:
        item(trial[key])
    for key in ("observer_before", "actor_before", "actor_after", "observer_after", "guard_before", "guard_after"):
        if trial[key] is not None:
            require(len(trial[key]["assertions"]) >= (3 if key.startswith("guard") else 2))
    for key, status in (("before", trial["before_status"]), ("after", trial["after_status"]), ("unchanged", trial["before_status"])):
        if trial[key] is not None:
            require(len(trial[key]["assertions"]) >= 3 if status == 200 else not trial[key]["assertions"])
    if trial["request"] is not None:
        require(not trial["request"]["assertions"])
        require(all(good(trial[key]) for key in ("observer_before", "guard_before", "actor_before")) and good(trial["before"], trial["before_status"]))
        cleanup = trial["cleanup"]
        names = {"identity", "guard", "current", "reset", "final_identity", "final_guard", "final"}
        _object(cleanup, names, names, "saved cleanup")
        for value in cleanup.values():
            item(value)
        for key in ("identity", "guard", "current", "final_identity", "final_guard", "final"):
            if cleanup[key] is not None:
                minimum = 2 if key in {"identity", "final_identity"} else 0 if key == "final" and trial["before_status"] == 404 else 3
                require(len(cleanup[key]["assertions"]) >= minimum)
        if cleanup["reset"] is not None:
            require(not cleanup["reset"]["assertions"])
            require(good(cleanup["identity"]) and good(cleanup["guard"]))
            require(good(cleanup["current"]) or good(cleanup["current"], 404))
    else:
        require(trial["cleanup"] is None and all(trial[key] is None for key in ("actor_after", "observer_after", "guard_after", "after", "unchanged")))
    require((trial["after"] is None) == (trial["unchanged"] is None))
    if trial["after"] is not None:
        for key in keys - {"assertions"}:
            require(trial["after"][key] == trial["unchanged"][key])
        require(not (good(trial["after"], trial["after_status"]) and good(trial["unchanged"], trial["before_status"])))
        if trial["before_status"] == trial["after_status"] == 200 and good(trial["after"]):
            require(trial["before"]["response_sha256"] != trial["after"]["response_sha256"])
    return trial
