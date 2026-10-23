"""Bounded GET requests to one configured origin; no redirects or ambient proxies."""

from dataclasses import dataclass, field
import base64
import hashlib
from http.client import HTTPException
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from urllib.parse import quote_plus, urlencode

from .config import decode_json, request_path
from . import __version__

MAX_BODY = 1024 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int | None = None
    data: object = field(default=None, repr=False)
    digest: str | None = None
    size: int = 0
    error: str | None = None
    elapsed_ms: int = 0


class Transport:
    def __init__(self, base_url, timeout=5.0, max_seconds=120.0):
        self.base_url = base_url
        self.timeout = timeout
        self.deadline = time.monotonic() + max_seconds
        self.opener = build_opener(ProxyHandler({}), NoRedirects())

    def get(self, path, token):
        headers = {"Authorization": "Bearer " + token} if isinstance(token, str) else token
        return self._request(path, headers)

    def refresh(self, path, form, client_id=None, client_secret=None, client_auth="none"):
        form = dict(form)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if client_auth == "basic":
            pair = quote_plus(client_id) + ":" + quote_plus(client_secret)
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode("ascii")).decode("ascii")
        else:
            if client_id is not None:
                form["client_id"] = client_id
            if client_auth == "body":
                form["client_secret"] = client_secret
        return self._request(path, headers, urlencode(form).encode("ascii"), 65536)

    def _request(self, path, headers, data=None, maximum=MAX_BODY):
        request_path(path)
        started = time.monotonic()
        remaining = self.deadline - started
        if remaining <= 0:
            return Response(error="run-budget-exhausted")
        request = Request(self.base_url + path, data=data, headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "TenantBreak/" + __version__,
            **headers,
        }, method="POST" if data is not None else "GET")
        response = None
        result = Response()
        try:
            try:
                response = self.opener.open(request, timeout=min(self.timeout, remaining))
            except HTTPError as exc:
                response = exc
            result.status = response.status
            # Redirect bodies are unnecessary and can contain credential-bearing URLs.
            if 300 <= result.status < 400:
                result.error = "redirect-refused"
                return result
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if encoding != "identity":
                result.error = "unsupported-content-encoding"
                return result
            chunks = []
            while True:
                if time.monotonic() >= self.deadline:
                    result.error = "run-budget-exhausted"
                    return result
                chunk = response.read1(min(65536, maximum + 1 - result.size))
                if not chunk:
                    break
                result.size += len(chunk)
                if result.size > maximum:
                    result.error = "response-too-large"
                    return result
                chunks.append(chunk)
            body = b"".join(chunks)
            result.digest = hashlib.sha256(body).hexdigest()
            try:
                result.data = decode_json(body)
            except (ValueError, UnicodeError, RecursionError):
                media_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                claims_json = media_type == "application/json" or media_type.endswith("+json") or body.lstrip().startswith((b"{", b"["))
                result.error = "invalid-json" if claims_json else "non-json"
        except (TimeoutError, socket.timeout):
            result.error = "request-timeout"
        except (URLError, ssl.SSLError, OSError, ValueError, HTTPException):
            result.error = "connection-failed"
        finally:
            if response is not None:
                response.close()
            result.elapsed_ms = round((time.monotonic() - started) * 1000)
        return result
