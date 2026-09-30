"""Stdlib tests for runtime-check credential safety and owned-resource cleanup."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import threading
import unittest
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from unittest.mock import patch

from scripts import check_runtime as runtime

SOURCE_ID = "58a7f271-5ec7-44bb-8e1c-45c7064fcfa9"
BATCH_ID = "05909190-9fb6-42ed-a208-6f1e747683ff"
SOURCE_TOKEN = "aegis_ingest_" + "a" * 43
PRIVATE_TEXT = "private-test-password-token-cookie"


class Handler(BaseHTTPRequestHandler):
    visited: ClassVar[list[str]] = []

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        self.visited.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/private")
            self.end_headers()
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(json.dumps({"private": PRIVATE_TEXT}).encode())

    def do_POST(self) -> None:
        self.send_response(204 if self.headers.get("Content-Type") == "application/json" else 415)
        self.end_headers()


@contextlib.contextmanager
def local_server() -> Iterator[str]:
    Handler.visited = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class FakeApi:
    public_origin = "http://localhost:8080"

    def __init__(
        self,
        state: str = "staged",
        *,
        fail_cleanup: bool = False,
        expired_access: bool = False,
    ) -> None:
        self.state = state
        self.fail_cleanup = fail_cleanup
        self.expired_access = expired_access
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(
        self, method: str, path: str, **kwargs: Any
    ) -> tuple[dict[str, Any], dict[str, str]]:
        self.calls.append((method, path, kwargs))
        if path == "/api/v1/auth/csrf":
            return {"csrf_token": "preauth-csrf"}, {}
        if path == "/api/v1/auth/login":
            return {"access_token": "test-access", "csrf_token": "session-csrf"}, {}
        if path == "/api/v1/auth/refresh":
            return {"access_token": "refreshed-test-access", "csrf_token": "refreshed-csrf"}, {}
        if path == "/api/v1/auth/me":
            return {"role": "admin"}, {}
        if path == "/api/v1/sources":
            return {
                "source": {"id": SOURCE_ID},
                "credential": {"token": SOURCE_TOKEN},
            }, {}
        if path == "/api/v1/events":
            return {
                "batch_id": BATCH_ID,
                "accepted_count": 1,
                "created_count": 1,
                "duplicate_count": 0,
            }, {}
        if path == f"/api/v1/events/batches/{BATCH_ID}":
            return {"records": [{"state": self.state}]}, {}
        if path == f"/api/v1/sources/{SOURCE_ID}":
            if self.expired_access and kwargs.get("token") != "refreshed-test-access":
                raise runtime.CheckFailed("Synthetic source inspection: HTTP 401")
            if method == "GET":
                return {}, {"etag": '"1"'}
            if self.fail_cleanup:
                raise runtime.CheckFailed("Synthetic source disable: HTTP 503")
            return {}, {}
        if path == "/api/v1/auth/logout":
            return {}, {}
        raise AssertionError("Unexpected API call")


class RuntimeTests(unittest.TestCase):
    def test_origin_accepts_only_local_credential_free_origins(self) -> None:
        for value in (
            "http://localhost:8080/",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://host.docker.internal:8080",
            "https://localhost",
        ):
            with self.subTest(value=value):
                self.assertEqual(runtime.origin(value), value.rstrip("/"))
        for value in (
            "https://example.invalid",
            "http://localhost:0",
            "http://user:secret@localhost:8080",
            "http://localhost:8080/private",
            "http://localhost?token=secret",
            "http://[broken",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                runtime.origin(value)

    def test_http_failure_does_not_echo_the_response_body(self) -> None:
        with local_server() as url:
            api = runtime.Api(url, url)
            with self.assertRaises(runtime.CheckFailed) as caught:
                api.request(
                    "GET",
                    "/private",
                    expected=200,
                    label="Identity",
                    token=PRIVATE_TEXT,
                )
        self.assertEqual(str(caught.exception), "Identity: HTTP 401")
        self.assertNotIn(PRIVATE_TEXT, str(caught.exception))

    def test_redirect_cannot_forward_authentication_to_another_path(self) -> None:
        with local_server() as url:
            api = runtime.Api(url, url)
            with self.assertRaises(runtime.CheckFailed):
                api.request(
                    "GET",
                    "/redirect",
                    expected=200,
                    label="Identity",
                    token=PRIVATE_TEXT,
                )
            self.assertEqual(Handler.visited, ["/redirect"])

    def test_success_disables_only_owned_source_and_logs_out_owned_session(
        self,
    ) -> None:
        api = FakeApi()
        runtime.check_ingestion(api, "admin", PRIVATE_TEXT, timeout=1)
        intakes = [call for call in api.calls if call[1] == "/api/v1/events"]
        self.assertEqual(len(intakes), 2)
        self.assertEqual(intakes[0][2]["headers"], intakes[1][2]["headers"])
        mutations = [call for call in api.calls if call[0] == "PATCH"]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][1], f"/api/v1/sources/{SOURCE_ID}")
        self.assertEqual(mutations[0][2]["payload"], {"enabled": False})
        self.assertEqual(api.calls[-1][1], "/api/v1/auth/logout")

    def test_empty_refresh_logout_body_still_uses_json_content_type(self) -> None:
        with local_server() as url:
            api = runtime.Api(url, url)
            response, _ = api.request("POST", "/logout", expected=204, label="Logout")
        self.assertEqual(response, {})

    def test_processing_failure_still_revokes_the_source_and_session(self) -> None:
        api = FakeApi(state="quarantined")
        with self.assertRaisesRegex(runtime.CheckFailed, "quarantine"):
            runtime.check_ingestion(api, "admin", PRIVATE_TEXT, timeout=1)
        self.assertEqual(api.calls[-2][0], "PATCH")
        self.assertEqual(api.calls[-1][1], "/api/v1/auth/logout")

    def test_cleanup_refreshes_owned_session_after_short_access_token_expires(self) -> None:
        api = FakeApi(expired_access=True)
        runtime.check_ingestion(api, "admin", PRIVATE_TEXT, timeout=1)
        owned_source_calls = [
            call for call in api.calls if call[1] == f"/api/v1/sources/{SOURCE_ID}"
        ]
        self.assertEqual(len(owned_source_calls), 2)
        self.assertTrue(
            all(call[2]["token"] == "refreshed-test-access" for call in owned_source_calls)
        )
        self.assertEqual(api.calls[-1][2]["headers"]["X-CSRF-Token"], "refreshed-csrf")

    def test_deadline_does_not_modify_or_retry_the_event(self) -> None:
        api = FakeApi(state="pending")
        with (
            patch.object(runtime.time, "monotonic", side_effect=[0.0, 2.0]),
            self.assertRaisesRegex(runtime.CheckFailed, "deadline"),
        ):
            runtime.check_ingestion(api, "admin", PRIVATE_TEXT, timeout=1)
        self.assertFalse(any("/retry" in call[1] for call in api.calls))
        self.assertEqual(api.calls[-1][1], "/api/v1/auth/logout")

    def test_failed_source_cleanup_does_not_prevent_session_logout(self) -> None:
        api = FakeApi(fail_cleanup=True)
        with self.assertRaisesRegex(runtime.CheckFailed, "cleanup failed"):
            runtime.check_ingestion(api, "admin", PRIVATE_TEXT, timeout=1)
        self.assertEqual(api.calls[-1][1], "/api/v1/auth/logout")

    def test_stdin_password_requires_username_and_is_never_prompted(self) -> None:
        args = argparse.Namespace(username="admin", password_stdin=True)
        with patch.object(runtime.sys, "stdin", io.StringIO(PRIVATE_TEXT + "\n")):
            self.assertEqual(runtime.read_credentials(args), ("admin", PRIVATE_TEXT))
        args.username = None
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(runtime.CheckFailed, "username"),
        ):
            runtime.read_credentials(args)

    def test_original_safe_failure_is_preserved_when_cleanup_also_fails(self) -> None:
        api = FakeApi(state="quarantined", fail_cleanup=True)
        with self.assertRaises(runtime.CheckFailed) as caught:
            runtime.check_ingestion(api, "admin", PRIVATE_TEXT, timeout=1)
        message = str(caught.exception)
        self.assertIn("quarantine", message)
        self.assertIn("cleanup failed", message)
        self.assertIn("HTTP 503", message)
        self.assertNotIn(SOURCE_TOKEN, message)
        self.assertNotIn(PRIVATE_TEXT, message)

    def test_cli_unexpected_error_is_redacted(self) -> None:
        output = io.StringIO()
        with (
            patch.object(runtime, "check_ready", side_effect=RuntimeError(PRIVATE_TEXT)),
            contextlib.redirect_stderr(output),
        ):
            result = runtime.main(["--health-only"])
        self.assertEqual(result, 1)
        self.assertNotIn(PRIVATE_TEXT, output.getvalue())


if __name__ == "__main__":
    unittest.main()
