import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch
from http.server import ThreadingHTTPServer

import server


class ApplicationFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path_patch = patch.object(server, "DB_PATH", os.path.join(self.temp_dir.name, "app.sqlite3"))
        self.db_path_patch.start()
        server.initialize_db()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.AppHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.public_url_patch = patch.dict(os.environ, {"APP_PUBLIC_URL": self.base_url})
        self.public_url_patch.start()
        self.login_patch = patch.object(server, "usergate_login", side_effect=self.fake_login)
        self.login_patch.start()

    def tearDown(self):
        if self.login_patch:
            self.login_patch.stop()
        self.public_url_patch.stop()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)
        self.db_path_patch.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def fake_login(username, password):
        return {
            "id": f"user-{username}",
            "username": username,
            "email": f"{username}@example.test",
            "full_name": username.title(),
        }

    def request(self, path, method="GET", payload=None, cookie=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            response = urllib.request.urlopen(request, timeout=3)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8")), error.headers
        with response:
            return response.status, json.loads(response.read().decode("utf-8")), response.headers

    def test_superadmin_activation_and_device_collection_flow(self):
        status, admin_result, headers = self.request(
            "/api/login", "POST", {"username": "admin", "password": "secret"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(admin_result["user"]["role"], "SUPERADMIN")
        admin_cookie = headers["Set-Cookie"].split(";", 1)[0]

        status, link_result, _ = self.request(
            "/api/admin/links", "POST", {"label": "Kantor"}, admin_cookie
        )
        self.assertEqual(status, 201)
        token = link_result["link"]["url"].rsplit("/", 1)[-1]
        status, _, _ = self.request(
            f"/api/collect/{token}",
            "POST",
            {
                "device_name": "Laptop A",
                "platform": "Windows",
                "browser": "Firefox",
                "local_ips": ["192.168.1.22", "8.8.8.8", "not-an-ip"],
                "public_ip": "8.8.8.8",
                "hostname": "LAPTOP-A",
                "windows_user": "DOMAIN\\alice",
                "mac_addresses": [
                    {"adapter": "Wi-Fi", "mac": "01-23-45-67-89-ab"},
                    {"adapter": "bad", "mac": "not-a-mac"},
                ],
                "tcp_ports": [443, "80", 70000, "bad"],
                "udp_ports": [53, 5353, 0],
                "details": {
                    "screen": "1920x1080",
                    "collector": "PowerShell",
                    "scanned_at": "2026-10-16 12:00:00",
                    "errors": ["No warning"],
                    "unknown_field": "ignored",
                },
            },
        )
        self.assertEqual(status, 201)
        status, result, _ = self.request("/api/admin/devices", cookie=admin_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(result["devices"][0]["local_ips"], ["192.168.1.22"])
        self.assertEqual(result["devices"][0]["public_ip"], "8.8.8.8")
        self.assertEqual(result["devices"][0]["hostname"], "LAPTOP-A")
        self.assertEqual(result["devices"][0]["windows_user"], "DOMAIN\\alice")
        self.assertEqual(
            result["devices"][0]["mac_addresses"],
            [{"adapter": "Wi-Fi", "mac": "01:23:45:67:89:AB"}],
        )
        self.assertEqual(result["devices"][0]["tcp_ports"], [80, 443])
        self.assertEqual(result["devices"][0]["udp_ports"], [53, 5353])
        self.assertEqual(result["devices"][0]["details"]["collector"], "PowerShell")

        collector_request = urllib.request.Request(
            link_result["link"]["url"] + "/collector.ps1"
        )
        with urllib.request.urlopen(collector_request, timeout=3) as response:
            collector_script = response.read().decode("utf-8-sig")
            self.assertEqual(response.status, 200)
            self.assertEqual(
                response.headers.get("Content-Disposition"),
                'attachment; filename="me-device-collector.ps1"',
            )
        self.assertIn(f"/api/collect/{token}", collector_script)
        self.assertNotIn("__COLLECTION_URL__", collector_script)

        launcher_request = urllib.request.Request(
            link_result["link"]["url"] + "/collector.cmd"
        )
        with urllib.request.urlopen(launcher_request, timeout=3) as response:
            launcher_script = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertEqual(
                response.headers.get("Content-Disposition"),
                'attachment; filename="me-device-collector.cmd"',
            )
        self.assertIn(f"/collect/{token}/collector.ps1", launcher_script)
        self.assertIn("-ExecutionPolicy Bypass", launcher_script)
        self.assertNotIn("__COLLECTOR_URL__", launcher_script)
        status, pending_result, _ = self.request(
            "/api/login", "POST", {"username": "second", "password": "secret"}
        )
        self.assertEqual(status, 403)
        self.assertIn("menunggu aktivasi", pending_result["error"])
        status, users_result, _ = self.request("/api/admin/users", cookie=admin_cookie)
        self.assertEqual(status, 200)
        pending_user = next(user for user in users_result["users"] if user["username"] == "second")

        status, _, _ = self.request(
            f"/api/admin/users/{pending_user['id']}",
            "PATCH",
            {"status": "ACTIVE"},
            admin_cookie,
        )
        self.assertEqual(status, 200)
        status, active_result, headers = self.request(
            "/api/login", "POST", {"username": "second", "password": "secret"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(active_result["user"]["role"], "USER")
        user_cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.assertEqual(self.request("/api/admin/devices", cookie=user_cookie)[0], 200)
        self.assertEqual(self.request("/api/admin/users", cookie=user_cookie)[0], 403)
        self.assertEqual(
            self.request(
                f"/api/admin/users/{pending_user['id']}",
                "PATCH",
                {"role": "SUPERADMIN"},
                user_cookie,
            )[0],
            403,
        )

        status, _, _ = self.request(
            f"/api/admin/users/{pending_user['id']}",
            "PATCH",
            {"role": "SUPERADMIN", "status": "ACTIVE"},
            admin_cookie,
        )
        self.assertEqual(status, 200)
        with server.db_connection() as connection:
            promoted = connection.execute(
                "SELECT role, status FROM users WHERE id = ?", (pending_user["id"],)
            ).fetchone()
        self.assertEqual(tuple(promoted), ("SUPERADMIN", "ACTIVE"))

        status, _, _ = self.request(
            f"/api/admin/users/{admin_result['user']['id']}",
            "PATCH",
            {"role": "USER"},
            admin_cookie,
        )
        self.assertEqual(status, 400)

        status, _, _ = self.request(
            f"/api/admin/users/{pending_user['id']}",
            "PATCH",
            {"role": "USER", "status": "ACTIVE"},
            admin_cookie,
        )
        self.assertEqual(status, 200)

    def test_first_valid_login_becomes_active_even_if_pending_local_user_exists(self):
        with server.db_connection() as connection:
            connection.execute(
                """
                INSERT INTO users
                    (id, external_id, username, role, status, created_at)
                VALUES ('old-pending', 'old-external', 'old-user', 'USER', 'PENDING', ?)
                """,
                (server.utc_now(),),
            )

        status, result, _ = self.request(
            "/api/login", "POST", {"username": "first-valid", "password": "secret"}
        )

        self.assertEqual(status, 200)
        self.assertEqual(result["user"]["role"], "SUPERADMIN")
        self.assertEqual(result["user"]["status"], "ACTIVE")

    def test_usergate_request_uses_application_user_agent(self):
        self.login_patch.stop()
        self.login_patch = None
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {
                "status": True,
                "data": {
                    "user": {
                        "id": "user-1",
                        "username": "first",
                    }
                },
            }
        ).encode()
        with (
            patch.object(server, "USERGATE_API_KEY", "test-api-key"),
            patch("server.urllib.request.urlopen", return_value=response) as urlopen,
        ):
            server.usergate_login("first", "password")

        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"), "ME-Device-Management/1.0")

    def test_initialize_db_migrates_existing_device_table(self):
        migration_dir = tempfile.TemporaryDirectory()
        old_db_path = os.path.join(migration_dir.name, "old.sqlite3")
        connection = sqlite3.connect(old_db_path)
        try:
            connection.execute(
                """
                CREATE TABLE devices (
                    id TEXT PRIMARY KEY,
                    link_id TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    device_name TEXT NOT NULL DEFAULT '',
                    platform TEXT NOT NULL DEFAULT '',
                    browser TEXT NOT NULL DEFAULT '',
                    local_ips TEXT NOT NULL DEFAULT '[]',
                    public_ip TEXT NOT NULL DEFAULT '',
                    server_ip TEXT NOT NULL DEFAULT '',
                    details TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.commit()
        finally:
            connection.close()
        with patch.object(server, "DB_PATH", old_db_path):
            server.initialize_db()
            with server.db_connection() as connection:
                columns = {row["name"] for row in connection.execute("PRAGMA table_info(devices)")}
        migration_dir.cleanup()

        self.assertTrue(
            {"hostname", "windows_user", "mac_addresses", "tcp_ports", "udp_ports"}.issubset(columns)
        )


if __name__ == "__main__":
    unittest.main()
