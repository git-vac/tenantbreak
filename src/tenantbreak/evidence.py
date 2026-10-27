"""JSON equality evidence without response values."""

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
