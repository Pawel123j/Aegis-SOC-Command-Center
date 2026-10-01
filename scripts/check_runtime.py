"""Check the deployed PHASE 2 path using only Python's standard library.

The full check needs an existing Admin account. Supply --username and a secure
password prompt, or AEGIS_CHECK_USERNAME/AEGIS_CHECK_PASSWORD. No secret is printed.
It retains one synthetic event and its audit history, disables only its new source,
and logs out its own session. --health-only checks dependencies without logging in.
"""

from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

MAX_RESPONSE_BYTES = 262144


class CheckFailed(Exception):
    """Only messages written by this script may reach the terminal."""


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise CheckFailed("The API redirected the request; check --url and --origin")


def origin(value: str) -> str:
    """Restrict authentication to this machine, including Docker's host bridge."""
    try:
        parsed = urllib.parse.urlsplit(value)
        valid = (
            parsed.scheme in {"http", "https"}
            and parsed.hostname in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
            and parsed.port != 0
        )
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError(
            "Use a local HTTP(S) origin without credentials, a path or query"
        )
    return value.rstrip("/")


@dataclass(repr=False)
class Api:
    url: str
    public_origin: str
    timeout: float = 10.0

    def __post_init__(self) -> None:
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            NoRedirects(),
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: int,
        label: str,
        payload: dict[str, Any] | None = None,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        if not path.startswith("/") or path.startswith("//"):
            raise CheckFailed(f"{label}: invalid API path")
        request_headers = {"Accept": "application/json", **(headers or {})}
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif method in {"POST", "PATCH", "PUT"}:
            data = b""
            # urllib otherwise supplies form encoding even for an empty body.
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.url + path, data=data, headers=request_headers, method=method
        )
        try:
            with self.opener.open(request, timeout=timeout or self.timeout) as response:
                if response.status != expected:
                    raise CheckFailed(f"{label}: unexpected HTTP status {response.status}")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                response_headers = {key.lower(): value for key, value in response.headers.items()}
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            raise CheckFailed(f"{label}: HTTP {status}") from None
        except (urllib.error.URLError, OSError, TimeoutError):
            raise CheckFailed(f"{label}: service unavailable or request timed out") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise CheckFailed(f"{label}: response exceeded the size limit")
        if expected == 204:
            return {}, response_headers
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise CheckFailed(f"{label}: response was not valid JSON") from None
        if not isinstance(body, dict):
            raise CheckFailed(f"{label}: unexpected response shape")
        return body, response_headers


def text_field(body: dict[str, Any], name: str, label: str) -> str:
    value = body.get(name)
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise CheckFailed(f"{label}: missing or invalid response field")
    return value


def identity(body: dict[str, Any], name: str, label: str) -> str:
    try:
        return str(UUID(text_field(body, name, label)))
    except ValueError:
        raise CheckFailed(f"{label}: invalid resource identity") from None


def read_credentials(args: argparse.Namespace) -> tuple[str, str]:
    username = args.username or os.environ.pop("AEGIS_CHECK_USERNAME", None)
    if not username:
        if args.password_stdin:
            raise CheckFailed(
                "--username or AEGIS_CHECK_USERNAME is required with --password-stdin"
            )
        username = input("Existing Admin username: ").strip()
    password = os.environ.pop("AEGIS_CHECK_PASSWORD", None)
    if args.password_stdin:
        if sys.stdin.isatty():
            raise CheckFailed(
                "Use the secure password prompt when running in an interactive terminal"
            )
        password = sys.stdin.readline(130).rstrip("\r\n")
    elif password is None:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Existing Admin password: ")
    if not 3 <= len(username) <= 64 or not 15 <= len(password) <= 128:
        raise CheckFailed("Admin username/password do not meet the application requirements")
    return username, password


def check_ready(api: Api) -> None:
    for path, status in (("/health", "ok"), ("/ready", "ready")):
        body, _ = api.request("GET", path, expected=200, label=path)
        if body.get("status") != status:
            raise CheckFailed(f"{path}: service did not report the expected state")


def check_ingestion(api: Api, username: str, password: str, timeout: float) -> None:
    access: str | None = None
    csrf: str | None = None
    source_id: str | None = None
    failure: CheckFailed | None = None
    try:
        preauth, _ = api.request("GET", "/api/v1/auth/csrf", expected=200, label="Pre-auth CSRF")
        preauth_csrf = text_field(preauth, "csrf_token", "Pre-auth CSRF")
        tokens, _ = api.request(
            "POST",
            "/api/v1/auth/login",
            expected=200,
            label="Admin login",
            payload={"username": username, "password": password},
            headers={"Origin": api.public_origin, "X-CSRF-Token": preauth_csrf},
        )
        access = text_field(tokens, "access_token", "Admin login")
        csrf = text_field(tokens, "csrf_token", "Admin login")
        profile, _ = api.request(
            "GET", "/api/v1/auth/me", expected=200, label="Admin identity", token=access
        )
        if profile.get("role") != "admin":
            raise CheckFailed("The full runtime check requires an Admin account")
        created, _ = api.request(
            "POST",
            "/api/v1/sources",
            expected=201,
            label="Synthetic source creation",
            token=access,
            payload={
                "name": f"runtime-check-{uuid4().hex}",
                "source_types": ["generic_json"],
                "timezone": "UTC",
            },
        )
        source = created.get("source")
        credential = created.get("credential")
        if not isinstance(source, dict):
            raise CheckFailed("Synthetic source creation: missing source metadata")
        source_id = identity(source, "id", "Synthetic source creation")
        if not isinstance(credential, dict):
            raise CheckFailed("Synthetic source creation: missing credential")
        source_token = text_field(credential, "token", "Synthetic source creation")
        if not re.fullmatch(r"aegis_ingest_[A-Za-z0-9_-]{43}", source_token):
            raise CheckFailed("Synthetic source creation: invalid credential shape")
        event = {
            "source_type": "generic_json",
            "source_event_id": f"runtime-check-{uuid4().hex}",
            "raw_event": {
                "message": "Synthetic normalization runtime check",
                "synthetic": True,
            },
        }
        intake_headers = {"Idempotency-Key": uuid4().hex}
        receipt, _ = api.request(
            "POST",
            "/api/v1/events",
            expected=202,
            label="Durable intake",
            token=source_token,
            payload=event,
            headers=intake_headers,
        )
        repeated, _ = api.request(
            "POST",
            "/api/v1/events",
            expected=202,
            label="Idempotent intake",
            token=source_token,
            payload=event,
            headers=intake_headers,
        )
        if repeated != receipt or (
            receipt.get("accepted_count"),
            receipt.get("created_count"),
            receipt.get("duplicate_count"),
        ) != (1, 1, 0):
            raise CheckFailed("Durable intake did not preserve the idempotent receipt")
        batch_id = identity(receipt, "batch_id", "Durable intake")
        # Derive the path locally rather than trusting an arbitrary response URL.
        status_path = f"/api/v1/events/batches/{batch_id}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, _ = api.request(
                "GET",
                status_path,
                expected=200,
                label="Processing status",
                token=source_token,
                timeout=min(3.0, max(0.1, deadline - time.monotonic())),
            )
            records = status.get("records")
            if (
                not isinstance(records, list)
                or len(records) != 1
                or not isinstance(records[0], dict)
            ):
                raise CheckFailed("Processing status: unexpected receipt records")
            state = records[0].get("state")
            if state == "staged":
                pipeline = records[0].get("pipeline_state")
                if pipeline == "projected":
                    event_id = identity(records[0], "event_id", "Processed event")
                    found, _ = api.request(
                        "GET",
                        f"/api/v1/events/{event_id}",
                        expected=200,
                        label="Normalized archive lookup",
                        token=access,
                        timeout=min(3.0, max(0.1, deadline - time.monotonic())),
                    )
                    if found.get("event_id") != event_id or found.get("source_id") != source_id:
                        raise CheckFailed("Normalized archive lookup returned unexpected identity")
                    break
                if pipeline in {"quarantined", "projection_failed"}:
                    raise CheckFailed("Synthetic event processing failed; check processor status")
            if state == "quarantined":
                raise CheckFailed("Synthetic event entered quarantine; check relay/worker status")
            if state not in {"pending", "processing", "staged"}:
                raise CheckFailed("Processing status: unexpected event state")
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        else:
            raise CheckFailed("Event did not reach projected before the deadline; check processor")
    except CheckFailed as error:
        failure = error
    finally:
        cleanup_errors: list[str] = []
        if source_id is not None and access is not None:
            # Processing may outlive a short access token. Refresh only the session
            # this check created, so source cleanup still has Admin authorization.
            if csrf is not None:
                try:
                    refreshed, _ = api.request(
                        "POST",
                        "/api/v1/auth/refresh",
                        expected=200,
                        label="Check session refresh",
                        headers={"Origin": api.public_origin, "X-CSRF-Token": csrf},
                    )
                    access = text_field(refreshed, "access_token", "Check session refresh")
                    csrf = text_field(refreshed, "csrf_token", "Check session refresh")
                except CheckFailed as error:
                    cleanup_errors.append(str(error))
            try:
                _, headers = api.request(
                    "GET",
                    f"/api/v1/sources/{source_id}",
                    expected=200,
                    label="Synthetic source inspection",
                    token=access,
                )
                etag = headers.get("etag", "")
                if not re.fullmatch(r'"[1-9][0-9]*"', etag):
                    raise CheckFailed("Synthetic source inspection: missing resource version")
                api.request(
                    "PATCH",
                    f"/api/v1/sources/{source_id}",
                    expected=200,
                    label="Synthetic source disable",
                    token=access,
                    payload={"enabled": False},
                    headers={"If-Match": etag},
                )
            except CheckFailed as error:
                cleanup_errors.append(str(error))
        if csrf is not None:
            try:
                api.request(
                    "POST",
                    "/api/v1/auth/logout",
                    expected=204,
                    label="Check session logout",
                    headers={"Origin": api.public_origin, "X-CSRF-Token": csrf},
                )
            except CheckFailed as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            cleanup_message = "Runtime check cleanup failed: " + "; ".join(cleanup_errors)
            if failure is not None:
                cleanup_message = f"{failure}; {cleanup_message}"
            failure = CheckFailed(cleanup_message)
    if failure is not None:
        raise failure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", "--base-url", type=origin, default="http://localhost:8080")
    parser.add_argument(
        "--origin", type=origin, help="Configured AEGIS_PUBLIC_ORIGIN, if different"
    )
    parser.add_argument("--username", help="Existing Admin username")
    parser.add_argument(
        "--password-stdin", action="store_true", help="Read a piped password from stdin"
    )
    parser.add_argument("--timeout", type=int, default=60, choices=range(1, 301), metavar="1..300")
    parser.add_argument(
        "--health-only",
        action="store_true",
        help="Check health/readiness without Admin",
    )
    args = parser.parse_args(argv)
    try:
        api = Api(args.url, args.origin or args.url)
        check_ready(api)
        if args.health_only:
            print("PASS: API and dependency readiness. Relay/worker processing was not checked.")
        else:
            username, password = read_credentials(args)
            check_ingestion(api, username, password, args.timeout)
            print(
                "PASS: readiness, Admin login, durable/idempotent intake, normalization and archive lookup."
            )
            print(
                "Synthetic source disabled and check session closed; event/audit history retained."
            )
        return 0
    except CheckFailed as error:
        print(f"FAIL: {error}", file=sys.stderr)
    except getpass.GetPassWarning:
        print("FAIL: use a secure terminal or AEGIS_CHECK_PASSWORD", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("Runtime check cancelled", file=sys.stderr)
    except Exception:  # noqa: BLE001 - redact unexpected exceptions at the CLI boundary
        # URLs, headers, bodies and driver exceptions may contain credentials.
        print(
            "FAIL: runtime check could not complete; verify configuration and service status",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
