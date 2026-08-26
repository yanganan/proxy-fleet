import base64
import contextlib
import json
import shlex
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import fleet  # noqa: E402


class FleetArgsTest(unittest.TestCase):
    def test_build_inbound_args_preserves_spaces_and_shell_specials(self):
        args = fleet.build_inbound_args(
            port=443,
            remark="DMIT LAX Pro",
            panel_port=9453,
            username="admin",
            password="p@ss word",
            sni="www.microsoft.com",
        )

        self.assertEqual(
            shlex.split(args),
            [
                "443",
                "DMIT LAX Pro",
                "9453",
                "admin",
                "p@ss word",
                "www.microsoft.com",
            ],
        )

    def test_3x_ui_login_scripts_support_csrf_protected_panels(self):
        for script in (fleet.REMOTE_INBOUND_SCRIPT, fleet.REMOTE_QUERY_SCRIPT):
            self.assertIn("/csrf-token", script)
            self.assertIn("X-CSRF-Token", script)

    def test_inbound_mutations_forward_csrf_token(self):
        script = fleet.REMOTE_INBOUND_SCRIPT
        self.assertIn('mutation_headers["X-CSRF-Token"]', script)

    def test_ssh_defaults_to_host_identity_verification(self):
        args = fleet.ssh_args("node-ts", "true")
        self.assertIn("StrictHostKeyChecking=accept-new", args)
        self.assertNotIn("StrictHostKeyChecking=no", args)

    def test_inbound_parse_errors_do_not_echo_private_key_material(self):
        script = fleet.REMOTE_INBOUND_SCRIPT
        self.assertIn('"Failed to parse x25519 output"', script)
        self.assertNotIn('f"Failed to parse x25519 output: {kv}"', script)

    def test_inbound_replacement_is_scoped_to_managed_remark(self):
        script = fleet.REMOTE_INBOUND_SCRIPT
        self.assertIn('ib.get("remark") == remark', script)
        self.assertIn("is already in use", script)

    def test_query_response_removes_private_keys_before_serialization(self):
        script = fleet.REMOTE_QUERY_SCRIPT
        self.assertIn('ib.pop("private_key", None)', script)

    def test_vless_client_tgid_is_numeric_for_new_3x_ui(self):
        script = fleet.REMOTE_INBOUND_SCRIPT
        self.assertIn('"tgId": 0', script)
        self.assertNotIn('"tgId": ""', script)

    def test_new_vless_client_has_a_nonempty_unique_email(self):
        script = fleet.REMOTE_INBOUND_SCRIPT
        self.assertIn('"email": f"vless-{port}"', script)
        self.assertNotIn('"email": ""', script)

    def test_query_supports_object_fields_from_new_3x_ui(self):
        script = fleet.REMOTE_QUERY_SCRIPT
        self.assertIn("def json_object(value):", script)
        self.assertIn("stream = json_object(ib.get(\"streamSettings\", {}))", script)
        self.assertIn("settings = json_object(ib.get(\"settings\", {}))", script)

    def test_query_failures_are_reported_instead_of_counted_as_empty(self):
        self.assertEqual(
            fleet.format_query_result("node-ts", {"error": "SSH failed"}),
            "  [node-ts] ❌ Query failed: SSH failed",
        )

    def test_status_prints_subscription_host_without_runtime_error(self):
        cfg = {
            "credentials": {"username": "u", "password": "p", "panel_port": 9453},
            "subscription": {
                "domain": "example.test",
                "url_path": "/s/token/",
                "file_path": "/var/www/sub/token",
                "ssh_host": "sub-host",
            },
            "nodes": [{
                "ssh_host": "node-ts", "server": "192.0.2.10", "port": 443,
                "name": "Test", "emoji": "🌐",
            }],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(json.dumps(cfg), encoding="utf-8")
            output = StringIO()
            with patch.object(fleet, "CONFIG_PATH", config_path), \
                    patch.object(fleet, "query_node", return_value={"inbounds": []}), \
                    patch.object(fleet, "verify_port", return_value=True), \
                    contextlib.redirect_stdout(output):
                fleet.cmd_status()

        self.assertIn("Hosted on: sub-host (/var/www/sub/token)", output.getvalue())

    def test_subscription_urls_use_token_path_and_vless_artifact(self):
        cfg = {
            "defaults": {"sni": "www.microsoft.com", "fingerprint": "chrome"},
            "subscription": {
                "domain": "example.test",
                "url_path": "/s/token/",
                "file_path": "/var/www/sub/token",
                "ssh_host": "sub-host",
            },
            "nodes": [{
                "ssh_host": "dmit", "server": "179.255.102.172", "port": 443,
                "name": "美国-DMIT-LAX", "emoji": "🇺🇸",
            }],
        }
        details = {"dmit": {"inbounds": [{
            "protocol": "vless", "uuid": "00000000-0000-0000-0000-000000000000",
            "public_key": "public-key", "short_id": "deadbeef", "sni": "www.microsoft.com",
        }]}}
        self.assertEqual(
            fleet.subscription_url(cfg, "config.yaml"),
            "https://example.test/s/token/config.yaml",
        )
        decoded = base64.b64decode(fleet.generate_vless_subscription(cfg, details)).decode()
        self.assertIn("vless://00000000-0000-0000-0000-000000000000@179.255.102.172:443", decoded)
        self.assertIn("#%F0%9F%87%BA%F0%9F%87%B8%20%E7%BE%8E%E5%9B%BD-DMIT-LAX", decoded)

    def test_sync_aborts_without_upload_when_a_node_query_fails(self):
        cfg = {
            "credentials": {"username": "u", "password": "p", "panel_port": 9453},
            "subscription": {
                "domain": "example.test",
                "url_path": "/s/token/",
                "file_path": "/var/www/sub/token",
                "ssh_host": "sub-host",
            },
            "defaults": {"sni": "www.microsoft.com", "fingerprint": "chrome"},
            "nodes": [{
                "ssh_host": "node-ts", "server": "192.0.2.10", "port": 443,
                "name": "Test", "emoji": "🌐",
            }],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(json.dumps(cfg), encoding="utf-8")
            with patch.object(fleet, "CONFIG_PATH", config_path), \
                    patch.object(fleet, "query_node", return_value={"error": "SSH failed", "inbounds": []}), \
                    patch.object(fleet.time, "sleep"), \
                    patch.object(fleet, "upload_subscription_file") as upload, \
                    contextlib.redirect_stdout(StringIO()):
                result = fleet.cmd_sync()

        self.assertFalse(result)
        upload.assert_not_called()

    def test_mihomo_subscription_keeps_whitelist_rule_providers(self):
        cfg = {
            "defaults": {"sni": "www.cloudflare.com", "fingerprint": "chrome"},
            "nodes": [{
                "ssh_host": "dmit", "server": "192.0.2.10", "port": 443,
                "name": "美国-DMIT-LAX", "emoji": "🇺🇸",
            }],
        }
        details = {"dmit": {"inbounds": [{
            "protocol": "vless", "uuid": "00000000-0000-0000-0000-000000000000",
            "public_key": "public-key", "short_id": "deadbeef", "sni": "www.cloudflare.com",
        }]}}

        rendered = fleet.generate_subscription(cfg, details)

        self.assertIn("rule-providers:", rendered)
        self.assertIn("RULE-SET,applications,DIRECT", rendered)
        self.assertIn("RULE-SET,cncidr,DIRECT,no-resolve", rendered)
        self.assertIn("MATCH,🐟 Final", rendered)
        self.assertNotIn('name: "🎬 Streaming"', rendered)


if __name__ == "__main__":
    unittest.main()
