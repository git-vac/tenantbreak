"""Strict, bounded JSON policies. Secrets are resolved separately at run time."""

import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


class PolicyError(ValueError):
    pass


def _object(value, keys, required, label):
    if not isinstance(value, dict) or set(value) - set(keys) or set(required) - set(value):
        raise PolicyError(f"{label}: missing or unsupported fields")


def _string(value, label, maximum=256):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise PolicyError(f"{label}: expected a nonempty string up to {maximum} characters")
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise PolicyError(f"{label}: control characters are not allowed")
    return value


def _slug(value, label):
    _string(value, label, 64)
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", value):
        raise PolicyError(f"{label}: use a lowercase identifier")


def request_path(value):
    _string(value, "request path", 2048)
    parts = urlsplit(value)
    if not value.startswith("/") or value.startswith("//") or "\\" in value or parts.scheme or parts.netloc or parts.fragment:
        raise PolicyError("request path: expected an absolute path on the configured origin")
    if any(c.isspace() for c in value) or "#" in value:
        raise PolicyError("request path: encode spaces and omit fragments")
    return value


def origin(value, allow_http=False):
    _string(value, "base_url", 2048)
    try:
        parts = urlsplit(value)
        port = parts.port
        hostname = parts.hostname
    except ValueError as exc:
        raise PolicyError("base_url: invalid address or port") from exc
    if (parts.scheme not in {"http", "https"} or not hostname or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment or parts.path not in {"", "/"}
            or any(c.isspace() for c in value) or "\\" in value or "%" in parts.netloc
            or (port is not None and not 1 <= port <= 65535)):
        raise PolicyError("base_url: use an HTTP(S) origin without credentials, a path, query or fragment")
    try:
        loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname.lower() == "localhost"
    if parts.scheme == "http" and not loopback and not allow_http:
        raise PolicyError("non-loopback HTTP requires --allow-http; prefer HTTPS")
    return f"{parts.scheme}://{parts.netloc}"


def _matches(value, label):
    if not isinstance(value, dict) or not 1 <= len(value) <= 16:
        raise PolicyError(f"{label}: supply 1 to 16 JSON Pointer equality assertions")
    for pointer, expected in value.items():
        _string(pointer, f"{label} pointer", 256)
        if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
            raise PolicyError(f"{label}: invalid JSON Pointer escape")
        if expected is None or isinstance(expected, (dict, list)) or not isinstance(expected, (str, int, float, bool)):
            raise PolicyError(f"{label}: assertion values must be non-null JSON scalars")
        if isinstance(expected, str):
            _string(expected, label, 1024)
        if isinstance(expected, float) and not math.isfinite(expected):
            raise PolicyError(f"{label}: non-finite numbers are not supported")


def validate(policy):
    _object(policy, {"version", "name", "base_url", "identity_check", "identities", "resources"},
            {"version", "name", "base_url", "identity_check", "identities", "resources"}, "policy")
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise PolicyError("policy: version must be 1")
    _string(policy["name"], "name", 100)
    # Permit explicitly opted-in HTTP later, but still validate its shape now.
    origin(policy["base_url"], allow_http=True)
    check = policy["identity_check"]
    _object(check, {"path"}, {"path"}, "identity_check")
    request_path(check["path"])
    identities = policy["identities"]
    if not isinstance(identities, list) or not 2 <= len(identities) <= 32:
        raise PolicyError("identities: supply 2 to 32 test identities")
    ids = set()
    from .auth import validate_accounts, validate_auth
    for identity in identities:
        _object(identity, {"id", "tenant", "role", "token_env", "auth", "verify"},
                {"id", "tenant", "role", "verify"}, "identity")
        _slug(identity["id"], "identity id")
        if identity["id"] in ids:
            raise PolicyError("identity ids must be unique")
        ids.add(identity["id"])
        _string(identity["tenant"], "tenant", 100)
        _string(identity["role"], "role", 100)
        validate_auth(identity)
        _matches(identity["verify"], "identity verify")
        if len(identity["verify"]) < 2:
            raise PolicyError("identity verify: assert both the subject and tenant (at least two fields)")
    validate_accounts(identities)
    if len({json.dumps(i["verify"], sort_keys=True) for i in identities}) != len(identities):
        raise PolicyError("identity verification assertions must distinguish the test identities")
    resources = policy["resources"]
    if not isinstance(resources, list) or not 1 <= len(resources) <= 64:
        raise PolicyError("resources: supply 1 to 64 explicit read-only resources")
    resource_ids = set()
    for resource in resources:
        _object(resource, {"id", "label", "tenant", "path", "allow", "control_identity", "match"},
                {"id", "label", "tenant", "path", "allow", "control_identity", "match"}, "resource")
        _slug(resource["id"], "resource id")
        if resource["id"] in resource_ids:
            raise PolicyError("resource ids must be unique")
        resource_ids.add(resource["id"])
        _string(resource["label"], "resource label", 120)
        _string(resource["tenant"], "resource tenant", 100)
        request_path(resource["path"])
        allowed = resource["allow"]
        if (not isinstance(allowed, list) or not allowed or any(not isinstance(x, str) or x not in ids for x in allowed)
                or len(set(allowed)) != len(allowed)):
            raise PolicyError("resource allow: supply distinct configured identity ids")
        if resource["control_identity"] not in allowed:
            raise PolicyError("control_identity must be explicitly allowed for its resource")
        _matches(resource["match"], "resource match")
        if len(resource["match"]) < 2:
            raise PolicyError("resource match: assert at least two identifying fields, such as id and tenant")
    if all(len(r["allow"]) == len(ids) for r in resources):
        raise PolicyError("policy must contain at least one expected denial")
    return policy


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON keys are not allowed")
        result[key] = value
    return result


def decode_json(data):
    return json.loads(data, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(PolicyError("non-finite JSON number")))


def load(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise PolicyError("policy exceeds 1 MiB")
        policy = decode_json(data)
        if isinstance(policy, dict) and "draft_version" in policy:
            raise PolicyError("this is a policy draft; complete it and use tenantbreak finalize before running")
        return validate(policy)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("cannot load policy: expected bounded, valid UTF-8 JSON") from exc


def credentials(policy, environment=None, identity_ids=None, refresh_auth=False):
    from .auth import resolve
    environment = os.environ if environment is None else environment
    return resolve(policy, environment, identity_ids, refresh_auth)


def fingerprint(policy):
    # Origins may vary for disposable lab ports; credentials never enter a policy.
    definition = {key: value for key, value in policy.items() if key != "base_url"}
    return hashlib.sha256(json.dumps(definition, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
