"""Explicit per-account credentials and bounded, opt-in OAuth refresh."""

from dataclasses import dataclass, field
import json
import re

from .config import PolicyError, _object, request_path

NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")
ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
RESERVED = {"host", "cookie", "content-length", "content-type", "transfer-encoding", "connection",
            "proxy-authorization", "proxy-connection", "te", "trailer", "upgrade", "accept", "accept-encoding", "user-agent"}


@dataclass(repr=False)
class Credential:
    headers: dict = field(repr=False)
    values: dict = field(repr=False)
    kind: str = "bearer"
    refresh: dict | None = field(default=None, repr=False)
    secrets: set = field(default_factory=set, repr=False)


def definition(identity):
    return identity.get("auth", {"type": "bearer", "token_env": identity.get("token_env")})


def _env(value):
    if not isinstance(value, str) or not ENV.fullmatch(value):
        raise PolicyError("authentication: expected an environment variable name")


def validate_auth(identity):
    if ("token_env" in identity) == ("auth" in identity):
        raise PolicyError("identity: supply token_env or auth, but not both")
    auth = definition(identity)
    if not isinstance(auth, dict) or auth.get("type") not in {"bearer", "headers", "cookies"}:
        raise PolicyError("authentication type must be bearer, headers or cookies")
    if auth["type"] == "bearer":
        _object(auth, {"type", "token_env", "refresh"}, {"type", "token_env"}, "bearer auth")
        _env(auth["token_env"])
        if "refresh" in auth:
            refresh = auth["refresh"]
            _object(refresh, {"path", "refresh_token_env", "client_id_env", "client_secret_env", "client_auth"},
                    {"path", "refresh_token_env"}, "refresh")
            request_path(refresh["path"])
            if "?" in refresh["path"]:
                raise PolicyError("refresh path must not contain a query string")
            for key in ("refresh_token_env", "client_id_env", "client_secret_env"):
                if key in refresh:
                    _env(refresh[key])
            client_auth = refresh.get("client_auth", "none")
            if client_auth not in {"none", "basic", "body"}:
                raise PolicyError("refresh client_auth must be none, basic or body")
            if client_auth != "none" and not {"client_id_env", "client_secret_env"} <= set(refresh):
                raise PolicyError("refresh client authentication requires client_id_env and client_secret_env")
            if client_auth == "none" and "client_secret_env" in refresh:
                raise PolicyError("refresh client_secret_env requires explicit basic or body client authentication")
    else:
        _object(auth, {"type", "values"}, {"type", "values"}, "header/cookie auth")
        values = auth["values"]
        if not isinstance(values, dict) or not 1 <= len(values) <= 8:
            raise PolicyError("header/cookie auth needs 1 to 8 name-to-environment entries")
        seen = set()
        for name, env in values.items():
            if not isinstance(name, str) or not NAME.fullmatch(name):
                raise PolicyError("invalid authentication header or cookie name")
            normalized = name.lower() if auth["type"] == "headers" else name
            if normalized in seen or (auth["type"] == "headers" and (normalized in RESERVED or normalized.startswith("proxy-"))):
                raise PolicyError("duplicate or reserved authentication header name")
            seen.add(normalized)
            _env(env)
    return auth


def validate_accounts(identities):
    # Refresh snapshots must never overwrite another account or an OAuth client secret.
    access, refresh, clients = [], [], set()
    for identity in identities:
        auth = definition(identity)
        if auth["type"] == "bearer":
            access.append(auth["token_env"])
            if "refresh" in auth:
                spec = auth["refresh"]
                refresh.append(spec["refresh_token_env"])
                clients.update(spec[key] for key in ("client_id_env", "client_secret_env") if key in spec)
        else:
            clients.update(auth["values"].values())
    if len(set(access + refresh)) != len(access + refresh) or set(access + refresh) & clients:
        raise PolicyError("account token/refresh environment names must be distinct and separate from other credentials")


def secret(value, *, cookie=False, spaces=False):
    if (not isinstance(value, str) or not 1 <= len(value) <= 8192
            or any(ord(c) < (32 if spaces else 33) or ord(c) > 126 for c in value)
            or (cookie and any(c in '\",;\\' or c.isspace() for c in value))):
        raise PolicyError("missing or invalid authentication credential; check the configured environment variables")
    return value


def guard_secrets(policy, values):
    public = json.dumps(policy, ensure_ascii=False) + " TenantBreak GET run demo-vulnerable demo-fixed allowed denied confirmed-leak inconclusive error"
    if any(value in public for value in values):
        raise PolicyError("credential values must be separate from policy text and evidence labels; use opaque credentials")


def distinct(credentials):
    seen = set()
    for credential in credentials.values():
        if not credential.headers:
            continue
        key = tuple(sorted((name.lower(), value) for name, value in credential.headers.items()))
        if key in seen:
            raise PolicyError("test identities must have distinct authentication credentials")
        seen.add(key)


def resolve(policy, environment, identity_ids=None, refresh_auth=False):
    result = {}
    for identity in policy["identities"]:
        if identity_ids is not None and identity["id"] not in identity_ids:
            continue
        auth = definition(identity)
        kind, values, headers = auth["type"], {}, {}
        refresh = auth.get("refresh") if refresh_auth else None
        def read(name, **options):
            value = secret(environment.get(name, ""), **options)
            values[name] = value
            return value
        if refresh:
            for key in ("refresh_token_env", "client_id_env", "client_secret_env"):
                if key in refresh:
                    read(refresh[key])
        elif kind == "bearer":
            headers["Authorization"] = "Bearer " + read(auth["token_env"])
        elif kind == "headers":
            headers = {name: read(env, spaces=True) for name, env in auth["values"].items()}
        else:
            headers["Cookie"] = "; ".join(name + "=" + read(env, cookie=True) for name, env in auth["values"].items())
        if sum(len(value) for value in values.values()) > 32768:
            raise PolicyError("authentication credentials exceed the per-account size limit")
        guard_secrets(policy, values.values())
        result[identity["id"]] = Credential(headers, values, kind, refresh, set(values.values()))
    if refresh_auth and not any(value.refresh for value in result.values()):
        raise PolicyError("no selected account has a refresh configuration")
    refresh_tokens = [value.values[value.refresh["refresh_token_env"]] for value in result.values() if value.refresh]
    if len(set(refresh_tokens)) != len(refresh_tokens):
        raise PolicyError("test identities must have distinct refresh tokens")
    distinct(result)
    return result


def supplied(policy, credentials, needed, refresh_auth=False):
    environment = {}
    for identity in policy["identities"]:
        if identity["id"] not in needed:
            continue
        value = credentials.get(identity["id"])
        if isinstance(value, Credential):
            for name, item in value.values.items():
                if name in environment and environment[name] != item:
                    raise PolicyError("conflicting supplied environment credentials")
                environment[name] = item
        elif definition(identity)["type"] == "bearer" and isinstance(value, str):
            environment[definition(identity)["token_env"]] = value
    return resolve(policy, environment, needed, refresh_auth)


def refresh_one(transport, identity, credential, save):
    """Exactly one exchange. No retries, discovery, scope changes or resource credentials."""
    spec = credential.refresh
    form = {"grant_type": "refresh_token", "refresh_token": credential.values[spec["refresh_token_env"]]}
    client_id = credential.values.get(spec.get("client_id_env"))
    client_secret = credential.values.get(spec.get("client_secret_env"))
    response = transport.refresh(spec["path"], form, client_id, client_secret, spec.get("client_auth", "none"))
    if response.error or response.status != 200 or not isinstance(response.data, dict):
        return "refresh-" + (response.error or "rejected")
    body = response.data
    auth = definition(identity)
    updates = {}
    # Persist rotated refresh tokens before any further HTTP request, including
    # malformed success responses. This is private credential state, not evidence.
    try:
        if "refresh_token" in body:
            updates[spec["refresh_token_env"]] = secret(body["refresh_token"])
        if "access_token" in body:
            updates[auth["token_env"]] = secret(body["access_token"])
    except PolicyError:
        if updates:
            save(identity["id"], updates)
        return "refresh-invalid-credentials"
    if updates:
        save(identity["id"], updates)
        credential.secrets.update(updates.values())
        credential.values.update(updates)
    if ("access_token" not in body or not isinstance(body.get("token_type"), str)
            or body["token_type"].lower() != "bearer" or "error" in body):
        return "refresh-invalid-response"
    credential.headers = {"Authorization": "Bearer " + body["access_token"]}
    return None
