"""Read known fixture records from bounded collections; never combine different rows."""

from copy import deepcopy
import hashlib
from urllib.parse import urlsplit

from .config import PolicyError, _object, _matches, request_path
from .evidence import assertions, evidence, matched


def pointer(data, path):
    if path == "":
        return True, data
    current = data
    for part in path[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None
    return True, current


def validate_read(resource):
    if "leak_match" in resource:
        _matches(resource["leak_match"], "leak_match")
        if len(resource["leak_match"]) < 2 or any(key not in resource["match"] or type(value) is not type(resource["match"][key]) or value != resource["match"][key]
                                                for key, value in resource["leak_match"].items()):
            raise PolicyError("leak_match must contain at least two exact assertions from match")
    if "collection" not in resource:
        return
    spec = resource["collection"]
    _object(spec, {"items", "next", "max_pages", "max_items", "identify"}, {"items", "max_pages", "max_items", "identify"}, "collection")
    _matches(spec["identify"], "collection identify")
    if len(spec["identify"]) < 2 or any(key not in resource["match"] or type(value) is not type(resource["match"][key]) or value != resource["match"][key] for key, value in spec["identify"].items()):
        raise PolicyError("collection identify must contain at least two exact assertions from match")
    for key in ("items", "next"):
        if key in spec:
            if not isinstance(spec[key], str):
                raise PolicyError("collection pointers must be strings")
            if spec[key] == "" and key == "items":
                continue
            _matches({spec[key]: True}, "collection pointer")
    for key, maximum in (("max_pages", 20), ("max_items", 5000)):
        if type(spec[key]) is not int or not 1 <= spec[key] <= maximum:
            raise PolicyError("collection limits: max_pages must be 1..20 and max_items 1..5000")
    if "next" not in spec and spec["max_pages"] != 1:
        raise PolicyError("an unpaginated collection must use max_pages=1")


def rank(item):
    return (matched(item["assertions"]), matched(item.get("leak_assertions", [])), matched(item.get("identify_assertions", [])),
            sum(check["matched"] for check in item["assertions"]))


def summary(collection):
    pages = collection["pages"]
    best = max(pages, key=rank)
    result = {key: deepcopy(best[key]) for key in ("http_status", "response_sha256", "response_bytes", "elapsed_ms", "assertions", "transport_error", "leak_assertions", "identify_assertions")}
    error = next((page["transport_error"] for page in pages if page["transport_error"]), None)
    complete = not error and pages[-1]["next_state"] == "end"
    result["transport_error"] = error
    result["coverage_complete"] = complete
    result["collection"] = collection
    return result


def read(transport, resource, headers):
    spec = resource["collection"]
    path, seen, pages, total = resource["path"], set(), [], 0
    for number in range(spec["max_pages"]):
        seen.add(path)
        response = transport.get(path, headers)
        checks, leak, index, count, next_state, following = assertions(None, resource["match"]), [], None, 0, "end", None
        if "leak_match" in resource:
            leak = assertions(None, resource["leak_match"])
        error = response.error
        identify = assertions(None, spec["identify"])
        if response.status in {200, 403, 404} and not error:
            exists, items = pointer(response.data, spec["items"])
            if not exists and number == 0 and response.status in {403, 404}:
                items = []
            elif not exists or not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
                error = "collection-invalid-items"
            if not error:
                count = min(len(items), spec["max_items"] - total)
                candidates = [{"assertions": assertions(row, resource["match"]),
                               "leak_assertions": assertions(row, resource["leak_match"]) if "leak_match" in resource else [],
                               "identify_assertions": assertions(row, spec["identify"]),
                               "index": i} for i, row in enumerate(items[:count])]
                if candidates:
                    best = max(candidates, key=rank)
                    checks, leak, index = best["assertions"], best["leak_assertions"], best["index"]
                    identify = best["identify_assertions"]
                total += count
                if len(items) > count:
                    error = "collection-item-limit"
                elif "next" in spec and response.status == 200:
                    exists, following = pointer(response.data, spec["next"])
                    if not exists:
                        error = "pagination-next-missing"
                    elif following not in (None, ""):
                        try:
                            request_path(following)
                            if urlsplit(following).path != urlsplit(resource["path"]).path:
                                raise PolicyError("pagination changed endpoint")
                            if following in seen:
                                error = "pagination-cycle"
                            elif total >= spec["max_items"]:
                                error = "collection-item-limit"
                            elif number + 1 == spec["max_pages"]:
                                error = "collection-page-limit"
                            else:
                                next_state = "more"
                        except (PolicyError, TypeError, ValueError):
                            error = "pagination-next-invalid"
        elif number > 0 and not error:
            error = "pagination-page-rejected"
        elif response.status not in {403, 404} and not error:
            error = "collection-unexpected-status"
        # A first-page explicit non-JSON denial remains usable by status.
        if number == 0 and response.status in {403, 404} and error == "non-json":
            error = None
        if number > 0 and response.status != 200 and not error:
            error = "pagination-page-rejected"
        page = evidence(response, checks)
        page.update(transport_error=error, leak_assertions=leak, identify_assertions=identify, items_seen=count, record_index=index,
                    next_state="error" if error else next_state,
                    path_sha256=hashlib.sha256(path.encode()).hexdigest())
        pages.append(page)
        if page["next_state"] != "more":
            break
        path = following
    return summary({"max_pages": spec["max_pages"], "max_items": spec["max_items"], "pages": pages})


def assess_read(*, allowed, identity_valid, control_valid, item):
    from .engine import assess
    if not identity_valid or not control_valid:
        return assess(allowed=allowed, identity_valid=identity_valid, control_valid=control_valid,
                      http_status=item["http_status"], checks=item["assertions"], transport_error=item["transport_error"])
    # Complete matching records from an earlier page remain evidence when a later
    # page fails. Coverage still makes the overall run incomplete.
    proof = [page for page in item["collection"]["pages"] if page["http_status"] is not None and page["response_sha256"]
             and (not page["transport_error"] or page["transport_error"].startswith(("collection-", "pagination-")))] if "collection" in item else [item] if not item["transport_error"] else []
    if not allowed and any(matched(page["assertions"]) or matched(page.get("leak_assertions", [])) for page in proof):
        return "confirmed-leak", "protected-fields-returned" if not matched(item["assertions"]) else "protected-resource-returned"
    if "collection" in item:
        if not item["coverage_complete"]:
            return "error", item["transport_error"] or "collection-incomplete"
        if allowed and item["http_status"] == 200 and matched(item["assertions"]):
            return "allowed", "expected-resource-returned"
        if not allowed and item["http_status"] == 200 and not matched(item["identify_assertions"]):
            return "denied", "protected-record-absent-from-collection"
    return assess(allowed=allowed, identity_valid=True, control_valid=True, http_status=item["http_status"],
                  checks=item["assertions"], transport_error=item["transport_error"])


def validate_evidence(item, check, require, digest):
    """Rebuild aggregate evidence from bounded per-page records."""
    spec = item["collection"]
    _object(spec, {"max_pages", "max_items", "pages"}, {"max_pages", "max_items", "pages"}, "saved collection")
    require(type(spec["max_pages"]) is int and 1 <= spec["max_pages"] <= 20)
    require(type(spec["max_items"]) is int and 1 <= spec["max_items"] <= 5000)
    require(isinstance(spec["pages"], list) and 1 <= len(spec["pages"]) <= spec["max_pages"])
    seen, total = set(), 0
    for index, page in enumerate(spec["pages"]):
        fields = {"http_status", "response_sha256", "response_bytes", "elapsed_ms", "assertions", "transport_error", "leak_assertions", "identify_assertions", "items_seen", "record_index", "next_state", "path_sha256"}
        _object(page, fields, fields, "saved collection page")
        check(page)
        check({**page, "assertions": page["leak_assertions"]})
        check({**page, "assertions": page["identify_assertions"]})
        require(len(page["identify_assertions"]) >= 2)
        digest(page["path_sha256"])
        require(page["path_sha256"] not in seen)
        seen.add(page["path_sha256"])
        require(type(page["items_seen"]) is int and 0 <= page["items_seen"] <= spec["max_items"])
        total += page["items_seen"]
        require(total <= spec["max_items"])
        require(page["record_index"] is None or (type(page["record_index"]) is int and 0 <= page["record_index"] < page["items_seen"]))
        require(page["next_state"] in {"end", "more", "error"})
        require((page["next_state"] == "error") == bool(page["transport_error"]))
        if index + 1 < len(spec["pages"]):
            require(page["next_state"] == "more" and page["http_status"] == 200)
        else:
            require(page["next_state"] != "more")
        if page["record_index"] is None:
            require(not any(c["present"] for c in page["assertions"] + page["leak_assertions"] + page["identify_assertions"]))
        require({c["pointer"] for c in page["assertions"]} == {c["pointer"] for c in item["assertions"]})
        require({c["pointer"] for c in page["leak_assertions"]} == {c["pointer"] for c in item["leak_assertions"]})
        full = {c["pointer"]: c for c in page["assertions"]}
        require(all(c == full.get(c["pointer"]) for c in page["leak_assertions"] + page["identify_assertions"]))
    rebuilt = summary(spec)
    require(type(item["coverage_complete"]) is bool)
    for key, value in rebuilt.items():
        require(item[key] == value)
    return rebuilt
