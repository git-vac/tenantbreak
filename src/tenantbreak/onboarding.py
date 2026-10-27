"""Offline policy scaffolds: no target discovery, credential examples or guessed permissions."""

from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
from urllib.parse import urlencode

from .config import PolicyError, _object, _string, decode_json, origin, request_path, validate

MAX_SPEC = 8 * 1024 * 1024
REVIEW = [
    "Set the target origin and the authenticated identity endpoint.",
    "Replace identity subject, tenant and role values with your test-account expectations.",
    "Resolve path parameters and required query parameters using known disposable resource identifiers.",
    "Declare every resource's allowed identities and one allowed control identity.",
    "Replace resource assertions with specific identifying evidence; do not put credentials in the policy.",
    "Use finalize to validate the edited draft and produce a runnable policy. No API requests are made by setup commands.",
]


def _resource(identifier="resource-1", path="/__SET_RESOURCE_PATH__", label="Protected resource"):
    return {"id": identifier, "label": label, "tenant": "__SET_RESOURCE_TENANT__", "path": path,
            "allow": [], "control_identity": "user-a",
            "match": {"/id": "__SET_RESOURCE_ID__", "/tenant": "__SET_RESOURCE_TENANT__"}}


def starter(*, base_url="https://api.example.invalid", name="API authorization policy"):
    _string(name, "policy name", 100)
    base_url = origin(base_url, allow_http=True)
    policy = {"version": 1, "name": name, "base_url": base_url,
              "identity_check": {"path": "/__SET_IDENTITY_ENDPOINT__"}, "identities": [], "resources": [_resource()]}
    for letter in ("a", "b"):
        policy["identities"].append({"id": "user-" + letter, "tenant": f"__SET_TENANT_{letter.upper()}__", "role": "member",
                                     "token_env": f"TB_USER_{letter.upper()}_TOKEN",
                                     "verify": {"/id": f"__SET_SUBJECT_{letter.upper()}__", "/tenant": f"__SET_TENANT_{letter.upper()}__"}})
    return {"draft_version": 1, "policy": policy, "review": list(REVIEW), "source": {"kind": "starter"}}


def _bounded_tree(value):
    pending, visited = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > 50000 or depth > 64:
            raise PolicyError("OpenAPI input exceeds the supported nesting or node limit")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise PolicyError("OpenAPI object keys must be strings")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif not isinstance(item, (str, int, float, bool, type(None))) or (isinstance(item, float) and not math.isfinite(item)):
            raise PolicyError("OpenAPI input must contain finite JSON-compatible values")


def _yaml(data):
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError("YAML import requires PyYAML; install this checkout with python -m pip install '.[openapi]'. JSON needs no extra package") from exc

    class BoundedSafeLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.depth = self.nodes = 0

        def compose_node(self, parent, index):
            if self.check_event(yaml.events.AliasEvent):
                raise PolicyError("YAML aliases and merge keys are unsupported; expand them before importing")
            self.depth += 1
            self.nodes += 1
            if self.depth > 64 or self.nodes > 50000:
                raise PolicyError("OpenAPI YAML exceeds the supported nesting or node limit")
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_object(self, node, deep=False):
            allowed = {"str", "int", "float", "bool", "null", "seq", "map"}
            if node.tag not in {"tag:yaml.org,2002:" + name for name in allowed}:
                raise PolicyError("OpenAPI YAML contains an unsupported tag")
            return super().construct_object(node, deep=deep)

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=True)
                # Unquoted numeric HTTP response keys are common in YAML specs.
                if type(key) is int:
                    key = str(key)
                if not isinstance(key, str) or key in result or key == "<<":
                    raise PolicyError("OpenAPI YAML requires unique string object keys and no merge keys")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        return yaml.load(data.decode("utf-8-sig"), Loader=BoundedSafeLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise PolicyError("invalid OpenAPI YAML input") from exc


def read_spec(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_SPEC + 1)
        if len(data) > MAX_SPEC:
            raise PolicyError("OpenAPI input exceeds 8 MiB")
        stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
        document = decode_json(data) if stripped.startswith((b"{", b"[")) else _yaml(data)
        _bounded_tree(document)
        return document, hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("cannot load OpenAPI input: expected bounded JSON or safe YAML") from exc


def _resolve(document, item):
    seen = set()
    for _ in range(16):
        if not isinstance(item, dict):
            raise PolicyError("OpenAPI path items, operations and parameters must be objects")
        if "$ref" not in item:
            return item
        reference = item["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise PolicyError("external OpenAPI references are unsupported; bundle the specification locally")
        if reference in seen or set(item) - {"$ref", "summary", "description"}:
            raise PolicyError("cyclic or ambiguous OpenAPI reference")
        seen.add(reference)
        current = document
        for part in reference[2:].split("/"):
            if re.search(r"~(?![01])", part):
                raise PolicyError("invalid local OpenAPI reference")
            key = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or key not in current:
                raise PolicyError("unresolved local OpenAPI reference")
            current = current[key]
        item = current
    raise PolicyError("OpenAPI reference chain is too long")


def _from_openapi(document, *, base_url, name="API authorization policy", path_prefix="", operation_ids=None, path_filters=None):
    _bounded_tree(document)
    if not isinstance(document, dict) or not isinstance(document.get("openapi"), str) or not re.fullmatch(r"3\.[012]\.\d+", document["openapi"]):
        raise PolicyError("expected an OpenAPI 3.0, 3.1 or 3.2 document")
    paths = document.get("paths")
    if not isinstance(paths, dict) or len(paths) > 2048:
        raise PolicyError("OpenAPI paths must be an object with at most 2048 entries")
    if path_filters is not None and (not path_filters or any(path not in paths for path in path_filters)):
        raise PolicyError("path selection contains an unknown or empty OpenAPI path")
    if path_prefix:
        request_path(path_prefix)
        if "?" in path_prefix or "{" in path_prefix or "}" in path_prefix:
            raise PolicyError("path prefix must be a concrete path without a query")
        path_prefix = path_prefix.rstrip("/")
    draft = starter(base_url=base_url, name=name)
    draft["policy"]["resources"] = []
    operations, seen_ids, selected_ids = [], set(), set(operation_ids or [])
    skipped_methods = 0
    methods = {"put", "post", "delete", "options", "head", "patch", "trace", "query"}
    for path, raw_item in sorted(paths.items()):
        if path.startswith("x-"):
            continue
        request_path(path)
        if "?" in path:
            raise PolicyError("OpenAPI path keys must not contain query strings")
        if path_filters is not None and path not in path_filters:
            continue
        item = _resolve(document, raw_item)
        skipped_methods += sum(method in item for method in methods)
        if "get" not in item:
            continue
        operation = _resolve(document, item["get"])
        operation_id = operation.get("operationId")
        if operation_id is not None:
            _string(operation_id, "operationId", 256)
            if operation_id in seen_ids:
                raise PolicyError("GET operationId values must be unique")
            seen_ids.add(operation_id)
        if operation_ids is not None and operation_id not in selected_ids:
            continue
        parameters = {}
        for group in (item.get("parameters", []), operation.get("parameters", [])):
            if not isinstance(group, list) or len(group) > 64:
                raise PolicyError("OpenAPI parameter lists must contain at most 64 entries")
            group_seen = set()
            for raw_parameter in group:
                parameter = _resolve(document, raw_parameter)
                parameter_name = _string(parameter.get("name"), "parameter name", 128)
                location = parameter.get("in")
                if location not in {"path", "query", "header", "cookie", "querystring"}:
                    raise PolicyError("unsupported OpenAPI parameter location")
                key = location, parameter_name
                if key in group_seen or type(parameter.get("required", False)) is not bool:
                    raise PolicyError("duplicate or malformed OpenAPI parameters")
                group_seen.add(key)
                parameters[key] = parameter
        query = [(key[1], "__SET_QUERY_VALUE__") for key, parameter in parameters.items() if key[0] == "query" and parameter.get("required", False)]
        unsupported_required = [key[0] for key, parameter in parameters.items() if key[0] in {"header", "cookie", "querystring"} and parameter.get("required", False)]
        concrete_path = path_prefix + path + ("?" + urlencode(query) if query else "")
        request_path(concrete_path)
        suffix = hashlib.sha256(path.encode()).hexdigest()[:8]
        stem = re.sub(r"[^a-z0-9]+", "-", (operation_id or "get-resource").lower()).strip("-")[:40]
        identifier = "get-" + (stem or "resource") + "-" + suffix
        label = "GET " + path
        if len(label) > 120:
            label = label[:117] + "..."
        draft["policy"]["resources"].append(_resource(identifier, concrete_path, label))
        operations.append({"resource": identifier, "method": "GET", "operation_id": operation_id,
                           "path_parameters": re.findall(r"\{([^{}]+)\}", path),
                           "required_query_parameters": [key for key, _ in query],
                           "unsupported_required_parameter_locations": unsupported_required})
    if operation_ids is not None and (not selected_ids or selected_ids - seen_ids):
        raise PolicyError("operation selection contains an unknown or empty GET operationId")
    count = len(draft["policy"]["resources"])
    if not 1 <= count <= 64:
        raise PolicyError("select 1 to 64 GET operations; use --operation to narrow a larger specification")
    draft["source"] = {"kind": "openapi", "openapi_version": document["openapi"], "operations": operations,
                       "skipped_non_get_operations": skipped_methods}
    draft["review"].extend([
        "Only GET routes were extracted. Server URLs, credentials, response examples and access rules were not copied.",
        "Use --path-prefix for API version prefixes; per-operation server overrides are not applied.",
        "Configure required authentication headers or cookies explicitly. Other required headers and querystring bodies are not generated.",
        "Configure collection arrays, fixture identification and pagination explicitly; route import does not infer these fields or write fixtures.",
    ])
    return draft


def from_openapi(document, **options):
    try:
        return _from_openapi(document, **options)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("unsupported or malformed OpenAPI structure") from exc


def finalize(draft):
    _object(draft, {"draft_version", "policy", "review", "source"}, {"draft_version", "policy", "review", "source"}, "policy draft")
    if type(draft["draft_version"]) is not int or draft["draft_version"] != 1:
        raise PolicyError("unsupported policy draft version")
    policy = deepcopy(draft["policy"])
    encoded = json.dumps(policy, ensure_ascii=True)
    if "__SET_" in encoded:
        raise PolicyError("draft still contains __SET_ placeholders; replace them with your account, resource and evidence values")
    validate(policy)
    if any("{" in resource["path"] or "}" in resource["path"] for resource in policy["resources"]):
        raise PolicyError("draft still contains unresolved path parameters")
    return policy


def load_draft(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise PolicyError("policy draft exceeds 1 MiB")
        return decode_json(data)
    except (OSError, ValueError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("cannot read policy draft: expected bounded JSON") from exc
