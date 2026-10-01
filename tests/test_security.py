"""Security regression tests for MarkMyPaper.

Run with:  python -m unittest discover -s tests -v
"""
import io
import os
import re
import unittest

# Configure the app before importing it so tests never touch the real database
# and never run without a key.
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-1234")
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import app as app_module  # noqa: E402
from app import app, db, limiter  # noqa: E402


class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        # Rate limits are exercised in a separate concern; disable here so the
        # suite is not throttled.
        limiter.enabled = False
        self.ctx = app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        self.ctx.pop()

    # -- helpers ------------------------------------------------------------
    def _register(self, email="user@example.com", password="password123"):
        return self.client.post(
            "/api/register",
            json={"name": "Test User", "email": email, "password": password},
        )

    # -- 404 handling -------------------------------------------------------
    def test_unknown_page_returns_html_404(self):
        res = self.client.get("/this-page-does-not-exist")
        self.assertEqual(res.status_code, 404)
        self.assertIn(b"could not be found", res.data)
        self.assertEqual(res.mimetype, "text/html")

    def test_unknown_api_route_returns_json_404(self):
        res = self.client.get("/api/this-does-not-exist")
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.get_json(), {"error": "Not found"})

    def test_404_does_not_leak_paths(self):
        res = self.client.get("/etc/passwd")
        self.assertNotIn(b"Traceback", res.data)
        self.assertNotIn(b"/etc/passwd", res.data)

    # -- security headers ---------------------------------------------------
    def test_security_headers_present(self):
        res = self.client.get("/")
        self.assertIn("Content-Security-Policy", res.headers)
        self.assertEqual(res.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(res.headers["X-Frame-Options"], "DENY")
        self.assertIn("Referrer-Policy", res.headers)
        self.assertIn("Permissions-Policy", res.headers)

    def test_csp_nonce_matches_script_tag(self):
        res = self.client.get("/upload.html")
        header = res.headers["Content-Security-Policy"]
        nonce = re.search(r"nonce-([A-Za-z0-9_-]+)", header).group(1)
        match = re.search(
            r'<script src="/static/js/upload\.js" nonce="([^"]+)"', res.data.decode()
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), nonce)

    def test_csp_blocks_inline_scripts(self):
        res = self.client.get("/")
        header = res.headers["Content-Security-Policy"]
        script_src = re.search(r"script-src ([^;]+)", header).group(1)
        self.assertNotIn("unsafe-inline", script_src)

    def test_static_assets_are_cached(self):
        res = self.client.get("/static/site.css")
        self.assertEqual(res.status_code, 200)
        self.assertIn("max-age", res.headers.get("Cache-Control", ""))

    # -- password handling --------------------------------------------------
    def test_password_is_stored_as_strong_hash(self):
        self._register()
        user = db.session.execute(
            db.select(app_module.User).filter_by(email="user@example.com")
        ).scalar_one()
        self.assertTrue(
            user.password.startswith(("scrypt:", "pbkdf2:")),
            "password must use a slow, salted hash",
        )

    # -- enumeration --------------------------------------------------------
    def test_login_does_not_reveal_whether_email_exists(self):
        self._register()
        wrong_pw = self.client.post(
            "/api/login", json={"email": "user@example.com", "password": "nope"}
        )
        unknown = self.client.post(
            "/api/login", json={"email": "ghost@example.com", "password": "nope"}
        )
        self.assertEqual(wrong_pw.status_code, unknown.status_code)
        self.assertEqual(wrong_pw.get_json(), unknown.get_json())

    def test_duplicate_registration_is_generic(self):
        self._register()
        dup = self._register()
        self.assertEqual(dup.status_code, 400)
        self.assertNotIn("already registered", dup.get_json()["message"].lower())

    # -- password reset -----------------------------------------------------
    def test_reset_request_never_returns_a_token(self):
        self._register()
        res = self.client.post(
            "/api/reset-password-request", json={"email": "user@example.com"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("reset_token", res.get_json())

    def test_reset_request_same_response_for_unknown_email(self):
        known = self.client.post(
            "/api/reset-password-request", json={"email": "user@example.com"}
        )
        unknown = self.client.post(
            "/api/reset-password-request", json={"email": "ghost@example.com"}
        )
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known.get_json(), unknown.get_json())

    def test_session_token_cannot_be_used_to_reset_password(self):
        token = self._register().get_json()["token"]
        res = self.client.post(
            "/api/reset-password",
            json={"token": token, "new_password": "brandnewpass1"},
        )
        self.assertEqual(res.status_code, 401)

    # -- authorization ------------------------------------------------------
    def test_history_requires_authentication(self):
        self.assertEqual(self.client.get("/api/history").status_code, 401)

    def test_history_accessible_with_token(self):
        token = self._register().get_json()["token"]
        res = self.client.get(
            "/api/history", headers={"Authorization": "Bearer " + token}
        )
        self.assertEqual(res.status_code, 200)

    def test_invalid_token_message_is_generic(self):
        res = self.client.get(
            "/api/user", headers={"Authorization": "Bearer not-a-real-token"}
        )
        self.assertEqual(res.status_code, 401)
        self.assertNotIn("error", res.get_json())

    # -- input validation ---------------------------------------------------
    def test_malformed_json_body_is_handled(self):
        res = self.client.post(
            "/api/login", data="not-json", content_type="text/plain"
        )
        self.assertEqual(res.status_code, 400)

    def test_upload_rejects_content_that_does_not_match_extension(self):
        res = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(b"hello world"), "fake.pdf"),
                "answers": ["x"],
                "weights": ["1"],
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("does not match", res.get_json()["error"])

    def test_upload_rejects_unsupported_extension(self):
        res = self.client.post(
            "/upload",
            data={"file": (io.BytesIO(b"%PDF-1.4"), "bad.exe")},
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 400)


if __name__ == "__main__":
    unittest.main()
