import importlib.util
import json
import subprocess
import sys
import unittest
import warnings
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent


def load_module(filename: str, module_name: str) -> ModuleType:
    path = ROOT / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class TestPythonExamples(unittest.TestCase):
    def test_broken_access_control_flask_owner_allowed(self):
        module = load_module("02_broken_access_control_flask.py", "broken_access_flask")
        payload, status = module.get_account(module.USERS[1], 1)
        self.assertEqual(status, 200)
        self.assertEqual(payload["email"], "alice@example.com")

    def test_broken_access_control_flask_other_user_forbidden(self):
        module = load_module("02_broken_access_control_flask.py", "broken_access_flask_forbidden")
        payload, status = module.get_account(module.USERS[1], 2)
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "Forbidden")

    def test_cryptographic_failures_python_hash_and_verify(self):
        module = load_module("04_cryptographic_failures_python.py", "crypto_python")
        stored = module.hash_password("StrongPassword!123")
        self.assertTrue(module.verify_password("StrongPassword!123", stored))
        self.assertFalse(module.verify_password("wrong-password", stored))

    def test_insecure_design_password_reset_one_time_token(self):
        module = load_module("07_insecure_design_password_reset.py", "password_reset")
        token = module.issue_reset_token("alice@example.com")
        self.assertIsNotNone(token)

        first_payload, first_status = module.reset_password(token, "NewStrongPassword!123")
        second_payload, second_status = module.reset_password(token, "AnotherStrongPassword!123")

        self.assertEqual(first_status, 200)
        self.assertEqual(first_payload["message"], "Password updated successfully.")
        self.assertEqual(second_status, 400)
        self.assertEqual(second_payload["error"], "Invalid or expired reset token.")

    def test_ssrf_protection_rejects_non_https(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            module = load_module("09_ssrf_protection.py", "ssrf_protection")
        with self.assertRaises(ValueError):
            module.fetch_url("http://api.example.com/data")

    def test_ssrf_protection_allows_allowlisted_host(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            module = load_module("09_ssrf_protection.py", "ssrf_protection_ok")

        class Response:
            text = '{"ok": true}'

            def raise_for_status(self):
                return None

        with patch.object(module, "_resolve_public_ips", return_value=["93.184.216.34"]):
            with patch.object(module.requests, "get", return_value=Response()) as mocked_get:
                response_text = module.fetch_url("https://api.example.com/data")

        self.assertEqual(response_text, '{"ok": true}')
        self.assertTrue(mocked_get.called)


class TestJavaScriptExamples(unittest.TestCase):
    def _run_node(self, script: str):
        result = subprocess.run(
            ["node", "-e", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def test_express_access_control_success(self):
        output = self._run_node(
            """
            const { getProfile } = require('./01_broken_access_control_express.js');
            const res = {
              status(code) { this.code = code; return this; },
              json(body) { console.log(JSON.stringify({ code: this.code || 200, body })); }
            };
            getProfile(
              { params: { userId: '507f1f77bcf86cd799439011' }, user: { id: '507f1f77bcf86cd799439011', role: 'user' } },
              res
            );
            """
        )
        payload = json.loads(output)
        self.assertEqual(payload["code"], 200)
        self.assertEqual(payload["body"]["email"], "alice@example.com")

    def test_express_access_control_forbidden(self):
        output = self._run_node(
            """
            const { getProfile } = require('./01_broken_access_control_express.js');
            const res = {
              status(code) { this.code = code; return this; },
              json(body) { console.log(JSON.stringify({ code: this.code || 200, body })); }
            };
            getProfile(
              { params: { userId: '507f191e810c19729de860ea' }, user: { id: '507f1f77bcf86cd799439011', role: 'user' } },
              res
            );
            """
        )
        payload = json.loads(output)
        self.assertEqual(payload["code"], 403)
        self.assertEqual(payload["body"]["error"], "Forbidden.")

    def test_nosql_injection_valid_username(self):
        output = self._run_node(
            """
            const { getUser } = require('./06_injection_nosql_javascript.js');
            const res = {
              status(code) { this.code = code; return this; },
              json(body) { console.log(JSON.stringify({ code: this.code || 200, body })); }
            };
            getUser({ query: { username: 'alice_01' } }, res);
            """
        )
        payload = json.loads(output)
        self.assertEqual(payload["code"], 200)
        self.assertEqual(payload["body"]["username"], "alice_01")

    def test_nosql_injection_rejects_operator_object(self):
        output = self._run_node(
            """
            const { getUser } = require('./06_injection_nosql_javascript.js');
            const res = {
              status(code) { this.code = code; return this; },
              json(body) { console.log(JSON.stringify({ code: this.code || 200, body })); }
            };
            getUser({ query: { username: { '$ne': '' } } }, res);
            """
        )
        payload = json.loads(output)
        self.assertEqual(payload["code"], 400)
        self.assertEqual(payload["body"]["error"], "Invalid username.")


class TestProjectChecks(unittest.TestCase):
    def test_java_examples_compile(self):
        result = subprocess.run(
            [
                "javac",
                "03_cryptographic_failures_java.java",
                "05_injection_sql_java.java",
                "10_authentication_failures_java.java",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_html_integrity_example_contains_security_controls(self):
        html = (ROOT / "08_software_data_integrity_failures.html").read_text()
        self.assertIn("integrity=", html)
        self.assertIn("Content-Security-Policy", html)


if __name__ == "__main__":
    unittest.main()
