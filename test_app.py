import base64
import hashlib
import io
import os
import tempfile
import unittest
from email.message import Message
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


_test_database_directory = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_test_database_directory.name) / "monitoring.sqlite3")

import app as dashboard_app


class _FakeBackendResponse:
    def __init__(self, body, status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers if headers is not None else Message()

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeStreamingResponse:
    status = 201

    def read(self, _size=None):
        return b'{"id":91}'


class _FakeStreamingConnection:
    def __init__(self):
        self.headers = {}
        self.chunks = []
        self.path = None

    def putrequest(self, method, path):
        self.method = method
        self.path = path

    def putheader(self, name, value):
        self.headers[name.lower()] = value

    def endheaders(self):
        pass

    def send(self, chunk):
        self.chunks.append(chunk)

    def getresponse(self):
        return _FakeStreamingResponse()

    def close(self):
        pass


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.database_directory = tempfile.TemporaryDirectory()
        dashboard_app.DATABASE_PATH = Path(self.database_directory.name) / "monitoring.sqlite3"
        dashboard_app._initialize_database()
        self.admin_token_patch = patch.object(dashboard_app, "ADMIN_API_TOKEN", "test-admin-token")
        self.base_url_patch = patch.object(dashboard_app, "PUBLIC_BASE_URL", "https://updates.example.com")
        self.admin_token_patch.start()
        self.base_url_patch.start()
        self.addCleanup(self.admin_token_patch.stop)
        self.addCleanup(self.base_url_patch.stop)
        self.addCleanup(self.database_directory.cleanup)
        dashboard_app.app.config.update(TESTING=True)
        self.client = dashboard_app.app.test_client()
        self.admin_headers = {"Authorization": "Bearer test-admin-token"}

    def test_dashboard_relative_styles_and_script_routes_are_served(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'href="./styles.css"', page.data)
        self.assertIn(b'src="./app.js"', page.data)
        page.close()
        styles = self.client.get("/styles.css")
        self.assertIn(b"background: var(--canvas)", styles.data)
        styles.close()
        script = self.client.get("/app.js")
        self.assertIn(b"/api/admin/shops", script.data)
        script.close()

    def _create_shop(self, shop_id):
        response = self.client.post(
            "/api/admin/shops",
            headers=self.admin_headers,
            json={"shopId": shop_id, "shopName": f"Shop {shop_id}"},
        )
        self.assertEqual(response.status_code, 201)
        return response.get_json()["shopToken"]

    def _create_release(self):
        manifest = dashboard_app.yaml.safe_dump({
            "version": "1.1.0",
            "path": "Billing-Setup.exe",
            "sha512": "installer-hash",
            "files": [{"url": "Billing-Setup.exe", "sha512": "installer-hash", "size": 20}],
        })
        with dashboard_app._database() as db:
            cursor = db.execute(
                """
                INSERT INTO releases
                    (version, tag_name, notes, github_release_id, github_html_url,
                     installer_name, installer_asset_id, installer_sha512,
                     installer_size, manifest_text, published_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "1.1.0", "v1.1.0", "Fixes", 15,
                    "https://github.com/example/repo/releases/tag/v1.1.0",
                    "Billing-Setup.exe", 99, "installer-hash", 20,
                    manifest, dashboard_app._now(),
                ),
            )
            return cursor.lastrowid

    def test_dotenv_loading_preserves_os_values_and_fills_missing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text(
                "COPILOT_DOTENV_SYSTEM_VALUE=file-value\n"
                "COPILOT_DOTENV_FILE_VALUE=loaded-value\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"COPILOT_DOTENV_SYSTEM_VALUE": "system-value"},
                clear=False,
            ):
                dashboard_app._load_environment(env_file)
                self.assertEqual(os.environ["COPILOT_DOTENV_SYSTEM_VALUE"], "system-value")
                self.assertEqual(os.environ["COPILOT_DOTENV_FILE_VALUE"], "loaded-value")

    def test_local_public_url_and_invalid_port_fallback_are_supported(self):
        self.assertEqual(dashboard_app._server_port("5001"), 5001)
        self.assertEqual(dashboard_app._server_port("not-a-port"), 5001)
        self.assertEqual(dashboard_app._server_port("70000"), 5001)
        self.assertEqual(
            dashboard_app._resolve_public_base_url("", 5001),
            "http://127.0.0.1:5001",
        )
        self.assertTrue(dashboard_app._usable_public_base_url("http://127.0.0.1:5001"))
        self.assertTrue(dashboard_app._usable_public_base_url("https://updates.example.com"))
        self.assertFalse(dashboard_app._usable_public_base_url("http://updates.example.com"))
        self.assertFalse(dashboard_app._usable_public_base_url("http://127.0.0.1:invalid"))

    def test_missing_optional_configuration_logs_warnings_without_secrets(self):
        with patch.object(dashboard_app, "ADMIN_API_TOKEN", ""), \
                patch.object(dashboard_app, "GITHUB_TOKEN", ""), \
                patch.object(dashboard_app, "GITHUB_REPOSITORY", ""), \
                patch.object(dashboard_app, "_configured_public_base_url", ""):
            with self.assertLogs(dashboard_app.app.logger, level="WARNING") as startup_logs:
                dashboard_app._log_startup_configuration()
        messages = "\n".join(startup_logs.output)
        self.assertIn("ADMIN_API_TOKEN is not configured", messages)
        self.assertIn("GITHUB_TOKEN is not configured", messages)
        self.assertIn("GITHUB_REPOSITORY is not configured", messages)
        self.assertIn("using local development URL", messages)

    def test_missing_github_token_disables_publish_without_crashing(self):
        with patch.object(dashboard_app, "GITHUB_REPOSITORY", "owner/repo"), \
                patch.object(dashboard_app, "GITHUB_TOKEN", ""), \
                patch.object(dashboard_app, "PUBLIC_BASE_URL", "http://127.0.0.1:5001"):
            response = self.client.post(
                "/api/admin/releases",
                headers=self.admin_headers,
                data={
                    "version": "1.2.0",
                    "notes": "Release notes",
                    "installer": (io.BytesIO(b"installer"), "Billing-Setup.exe"),
                },
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("GITHUB_TOKEN", response.get_json()["error"])

    def test_missing_admin_token_returns_service_unavailable_instead_of_crashing(self):
        with patch.object(dashboard_app, "ADMIN_API_TOKEN", ""):
            response = self.client.post(
                "/api/admin/shops",
                json={"shopId": "SHOP-001", "shopName": "Shop SHOP-001"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("ADMIN_API_TOKEN", response.get_json()["error"])

    def test_shop_tokens_are_required_and_heartbeats_update_shop_status(self):
        unauthorized = self.client.get("/api/admin/shops")
        self.assertEqual(unauthorized.status_code, 401)

        token = self._create_shop("SHOP-001")
        with dashboard_app._database() as db:
            row = db.execute("SELECT token_hash FROM shops WHERE shop_id = ?", ("SHOP-001",)).fetchone()
        self.assertNotEqual(row["token_hash"], token)
        with self.assertLogs(dashboard_app.app.logger, level="WARNING") as mismatch_logs:
            mismatched_shop = self.client.post(
                "/api/heartbeat",
                headers={"Authorization": f"Bearer {token}"},
                json={"shopId": "SHOP-002", "version": "1.0.0"},
            )
        self.assertEqual(mismatched_shop.status_code, 400)
        mismatch_log_output = "\n".join(mismatch_logs.output)
        self.assertIn('submittedShopId="SHOP-002"', mismatch_log_output)
        self.assertIn('authenticatedShopId="SHOP-001"', mismatch_log_output)
        self.assertIn('registeredShopIds=["SHOP-001"]', mismatch_log_output)
        with dashboard_app._database() as db:
            row = db.execute("SELECT last_seen FROM shops WHERE shop_id = ?", ("SHOP-001",)).fetchone()
        self.assertIsNone(row["last_seen"])

        offline_shops = self.client.get("/api/admin/shops", headers=self.admin_headers).get_json()
        self.assertEqual((offline_shops["online"], offline_shops["offline"]), (0, 1))

        heartbeat_debug_output = io.StringIO()
        with self.assertLogs(dashboard_app.app.logger, level="INFO") as heartbeat_logs:
            with redirect_stdout(heartbeat_debug_output):
                response = self.client.post(
                    "/api/heartbeat",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "shopId": "SHOP-001",
                        "shopName": "Shop SHOP-001",
                        "status": "online",
                        "version": "1.0.0",
                    },
                )
        self.assertEqual(response.status_code, 200)
        log_output = "\n".join(heartbeat_logs.output)
        expected_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.assertIn(f"incomingTokenHash={expected_token_hash}", log_output)
        self.assertIn(
            'rawBody={"shopId":"SHOP-001","shopName":"Shop SHOP-001","status":"online","version":"1.0.0"}',
            log_output,
        )
        self.assertIn("Shop heartbeat committed", log_output)
        self.assertNotIn(token, log_output)
        heartbeat_result = response.get_json()
        self.assertEqual(heartbeat_result["status"], "success")
        self.assertIsNone(heartbeat_result["update"])
        self.assertIn(
            f"--> [DEBUG] Heartbeat successfully committed for shop_id: SHOP-001 at {heartbeat_result['serverTime']}",
            heartbeat_debug_output.getvalue(),
        )
        self.assertIn(
            f"--> [DEBUG] SQLite last_seen for shop_id: SHOP-001 is {heartbeat_result['serverTime']}",
            heartbeat_debug_output.getvalue(),
        )
        with dashboard_app._database() as db:
            updated_shop = db.execute(
                "SELECT current_version, last_seen FROM shops WHERE shop_id = ?",
                ("SHOP-001",),
            ).fetchone()
        self.assertEqual(updated_shop["current_version"], "1.0.0")
        self.assertEqual(updated_shop["last_seen"], heartbeat_result["serverTime"])

        shops = self.client.get("/api/admin/shops", headers=self.admin_headers).get_json()
        self.assertEqual((shops["total"], shops["online"], shops["offline"]), (1, 1, 0))
        self.assertEqual(shops["shops"][0]["currentVersion"], "1.0.0")

        rotated = self.client.post(
            "/api/admin/shops/SHOP-001/rotate-token",
            headers=self.admin_headers,
            json={},
        ).get_json()["clientConfig"]["shopToken"]
        old_token_response = self.client.post(
            "/api/heartbeat",
            headers={"Authorization": f"Bearer {token}"},
            json={"shopId": "SHOP-001", "version": "1.0.0"},
        )
        new_token_response = self.client.post(
            "/api/heartbeat",
            headers={"Authorization": f"Bearer {rotated}"},
            json={"shopId": "SHOP-001", "version": "1.0.0"},
        )
        self.assertEqual(old_token_response.status_code, 401)
        self.assertEqual(new_token_response.status_code, 200)

    def test_authenticated_token_for_deleted_shop_does_not_succeed_silently(self):
        with patch.object(dashboard_app, "_shop_from_token", return_value={"shop_id": "MISSING"}):
            response = self.client.post(
                "/api/heartbeat",
                headers={"Authorization": "Bearer test-token"},
                json={"shopId": "MISSING", "version": "1.0.0"},
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.get_json()["error"],
            "Registered shop was not found while updating heartbeat.",
        )

    def test_unknown_token_logs_received_and_registered_shop_ids(self):
        self._create_shop("SHOP-001")
        unknown_token = "unknown-shop-token"
        with self.assertLogs(dashboard_app.app.logger, level="WARNING") as heartbeat_logs:
            response = self.client.post(
                "/api/heartbeat",
                headers={"Authorization": f"Bearer {unknown_token}"},
                json={"shopId": "SHOP-OTHER", "version": "1.0.0"},
            )
        self.assertEqual(response.status_code, 401)
        log_output = "\n".join(heartbeat_logs.output)
        expected_token_hash = hashlib.sha256(unknown_token.encode("utf-8")).hexdigest()
        self.assertIn(f"incomingTokenHash={expected_token_hash}", log_output)
        self.assertIn('submittedShopId="SHOP-OTHER"', log_output)
        self.assertIn('registeredShopIds=["SHOP-001"]', log_output)
        self.assertNotIn(unknown_token, log_output)

    def test_update_feed_is_only_available_to_a_shop_assigned_that_release(self):
        first_token = self._create_shop("SHOP-001")
        second_token = self._create_shop("SHOP-002")
        release_id = self._create_release()
        response = self.client.post(
            "/api/admin/push",
            headers=self.admin_headers,
            json={"releaseId": release_id, "shopIds": ["SHOP-001"]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["assigned"], 1)

        first_heartbeat = self.client.post(
            "/api/heartbeat",
            headers={"Authorization": f"Bearer {first_token}"},
            json={"shopId": "SHOP-001", "version": "1.0.0"},
        ).get_json()
        second_heartbeat = self.client.post(
            "/api/heartbeat",
            headers={"Authorization": f"Bearer {second_token}"},
            json={"shopId": "SHOP-002", "version": "1.0.0"},
        ).get_json()
        self.assertEqual(first_heartbeat["update"]["version"], "1.1.0")
        self.assertIsNone(second_heartbeat["update"])

        feed = self.client.get(
            "/api/update-feed/SHOP-001/latest.yml",
            headers={"Authorization": f"Bearer {first_token}"},
        )
        self.assertEqual(feed.status_code, 200)
        self.assertIn("https://updates.example.com/api/update-assets/", feed.get_data(as_text=True))
        installer_bytes = b"installer payload"
        with patch.object(
            dashboard_app,
            "_asset_by_id",
            return_value={
                "browser_download_url": "https://downloads.example.com/Billing-Setup.exe",
                "size": len(installer_bytes),
            },
        ), patch("app.urllib.request.urlopen", return_value=io.BytesIO(installer_bytes)):
            downloaded = self.client.get(
                f"/api/update-assets/{release_id}/Billing-Setup.exe",
                headers={"Authorization": f"Bearer {first_token}"},
            )
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.data, installer_bytes)
        denied_asset = self.client.get(
            f"/api/update-assets/{release_id}/Billing-Setup.exe",
            headers={"Authorization": f"Bearer {second_token}"},
        )
        self.assertEqual(denied_asset.status_code, 401)

        denied_feed = self.client.get(
            "/api/update-feed/SHOP-002/latest.yml",
            headers={"Authorization": f"Bearer {second_token}"},
        )
        self.assertEqual(denied_feed.status_code, 404)

    def test_release_publish_generates_a_hash_manifest_and_rejects_non_installers(self):
        rejected = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            data={
                "version": "1.2.0",
                "notes": "Release notes",
                "installer": (io.BytesIO(b"not an installer"), "package.zip"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(rejected.status_code, 400)

        with patch.object(dashboard_app, "GITHUB_REPOSITORY", "owner/repo"), \
                patch.object(dashboard_app, "_github_request") as github_request, \
                patch.object(dashboard_app, "_upload_github_asset") as upload_asset:
            github_request.side_effect = [
                {"id": 15, "upload_url": "https://uploads.github.com/release/assets{?name,label}"},
                {"id": 15, "html_url": "https://github.com/owner/repo/releases/tag/v1.2.0"},
            ]
            upload_asset.side_effect = [{"id": 91}, {"id": 92}]
            response = self.client.post(
                "/api/admin/releases",
                headers={**self.admin_headers, "X-Upload-Id": "publish-release-test-123"},
                data={
                    "version": "v1.2.0",
                    "notes": "Release notes",
                    "installer": (io.BytesIO(b"validated installer bytes"), "Billing-Setup.exe"),
                },
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 201, response.get_json())
        progress = self.client.get(
            "/api/admin/releases/progress/publish-release-test-123",
            headers=self.admin_headers,
        ).get_json()
        self.assertEqual(progress["phase"], "complete")
        self.assertEqual(progress["percent"], 100)
        manifest_call = upload_asset.call_args_list[1]
        self.assertEqual(manifest_call.args[1], "latest.yml")
        manifest = dashboard_app.yaml.safe_load(manifest_call.args[2])
        self.assertEqual(manifest["version"], "1.2.0")
        self.assertEqual(manifest["files"][0]["url"], "Billing-Setup.exe")
        self.assertEqual(
            manifest["sha512"],
            base64.b64encode(hashlib.sha512(b"validated installer bytes").digest()).decode("ascii"),
        )

    def test_github_installer_upload_streams_chunks_and_reports_progress(self):
        content = b"x" * (dashboard_app.UPLOAD_CHUNK_SIZE + 17)
        fake_connection = _FakeStreamingConnection()
        progress_updates = []
        with patch.object(dashboard_app, "GITHUB_TOKEN", "test-github-token"), patch.object(
            dashboard_app.http.client,
            "HTTPSConnection",
            return_value=fake_connection,
        ) as connection_factory:
            result = dashboard_app._upload_github_asset(
                "https://uploads.github.com/release/assets{?name,label}",
                "Billing Setup.exe",
                io.BytesIO(content),
                "application/vnd.microsoft.portable-executable",
                content_length=len(content),
                progress_callback=lambda sent, total: progress_updates.append((sent, total)),
            )
        self.assertEqual(result, {"id": 91})
        connection_factory.assert_called_once()
        self.assertEqual(fake_connection.method, "POST")
        self.assertIn("name=Billing%20Setup.exe", fake_connection.path)
        self.assertEqual(fake_connection.headers["content-length"], str(len(content)))
        self.assertEqual(b"".join(fake_connection.chunks), content)
        self.assertEqual(progress_updates[0], (0, len(content)))
        self.assertEqual(progress_updates[-1], (len(content), len(content)))
        self.assertGreater(len(fake_connection.chunks), 1)

    def test_release_upload_progress_requires_admin_and_reports_transfer_metrics(self):
        upload_id = "upload-job-id-1234"
        unauthorized = self.client.get(f"/api/admin/releases/progress/{upload_id}")
        self.assertEqual(unauthorized.status_code, 401)

        dashboard_app._initialize_upload_progress(upload_id, 1000)
        dashboard_app._set_upload_progress(
            upload_id,
            "uploading_to_github",
            500,
            1000,
            "Uploading installer to GitHub.",
        )
        response = self.client.get(
            f"/api/admin/releases/progress/{upload_id}",
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 200)
        progress = response.get_json()
        self.assertEqual(progress["phase"], "uploading_to_github")
        self.assertEqual(progress["percent"], 50)
        self.assertEqual(progress["bytesSent"], 500)
        self.assertEqual(progress["totalBytes"], 1000)
        self.assertEqual(progress["message"], "Uploading installer to GitHub.")
        self.assertIn("speedBytesPerSecond", progress)
        self.assertIn("etaSeconds", progress)

    def test_lan_heartbeat_proxy_forwards_session_and_adds_cors_headers(self):
        backend_headers = Message()
        backend_headers["Content-Type"] = "application/json"
        backend_headers.add_header("Set-Cookie", "session=refreshed; Path=/")
        fake = _FakeBackendResponse(b'{"ok": true, "lan_mode": true}', 200, backend_headers)
        self.client.set_cookie("session", "abc")
        with patch.object(dashboard_app.urllib.request, "urlopen", return_value=fake) as urlopen:
            response = self.client.post(
                "/api/lan/heartbeat",
                headers={
                    "Origin": dashboard_app.LAN_HEARTBEAT_ALLOWED_ORIGIN,
                    "Content-Type": "text/plain;charset=UTF-8",
                },
                data=b"",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True, "lan_mode": True})
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"],
            dashboard_app.LAN_HEARTBEAT_ALLOWED_ORIGIN,
        )
        self.assertEqual(response.headers["Access-Control-Allow-Credentials"], "true")
        self.assertIn("session=refreshed", response.headers.getlist("Set-Cookie")[0])
        forwarded = urlopen.call_args.args[0]
        self.assertEqual(forwarded.full_url, dashboard_app.LAN_HEARTBEAT_BACKEND_URL)
        self.assertEqual(forwarded.get_header("Cookie"), "session=abc")

    def test_lan_heartbeat_proxy_handles_preflight_rejection_and_backend_errors(self):
        origin = dashboard_app.LAN_HEARTBEAT_ALLOWED_ORIGIN
        preflight = self.client.open(
            "/api/lan/heartbeat", method="OPTIONS", headers={"Origin": origin}
        )
        self.assertEqual(preflight.status_code, 204)
        self.assertEqual(preflight.headers["Access-Control-Allow-Methods"], "POST, OPTIONS")
        self.assertEqual(preflight.headers["Access-Control-Allow-Credentials"], "true")

        rejected = self.client.post(
            "/api/lan/heartbeat", headers={"Origin": "https://evil.example"}
        )
        self.assertEqual(rejected.status_code, 403)
        self.assertNotIn("Access-Control-Allow-Origin", rejected.headers)

        unauthorized = _FakeBackendResponse(b'{"ok": false}', 401)
        with patch.object(dashboard_app.urllib.request, "urlopen", return_value=unauthorized):
            forwarded_error = self.client.post(
                "/api/lan/heartbeat", headers={"Origin": origin}
            )
        self.assertEqual(forwarded_error.status_code, 401)
        self.assertEqual(forwarded_error.get_json(), {"ok": False})
        self.assertEqual(forwarded_error.headers["Access-Control-Allow-Origin"], origin)

        with patch.object(
            dashboard_app.urllib.request,
            "urlopen",
            side_effect=dashboard_app.urllib.error.URLError("connection refused"),
        ):
            unavailable = self.client.post(
                "/api/lan/heartbeat", headers={"Origin": origin}
            )
        self.assertEqual(unavailable.status_code, 502)
        self.assertEqual(unavailable.headers["Access-Control-Allow-Origin"], origin)

    def test_offline_report_marks_shop_offline_immediately(self):
        token = self._create_shop("SHOP-003")
        headers = {"Authorization": f"Bearer {token}"}
        online = self.client.post(
            "/api/heartbeat",
            headers=headers,
            json={
                "shopId": "SHOP-003",
                "shopName": "Shop SHOP-003",
                "status": "online",
                "version": "1.0.0",
            },
        )
        self.assertEqual(online.status_code, 200)
        shops = self.client.get("/api/admin/shops", headers=self.admin_headers).get_json()
        self.assertEqual((shops["online"], shops["offline"]), (1, 0))

        offline = self.client.post(
            "/api/heartbeat",
            headers=headers,
            json={
                "shopId": "SHOP-003",
                "shopName": "Shop SHOP-003",
                "status": "offline",
                "version": "1.0.0",
            },
        )
        self.assertEqual(offline.status_code, 200)
        self.assertIsNone(offline.get_json()["serverTime"])
        with dashboard_app._database() as db:
            row = db.execute(
                "SELECT last_seen FROM shops WHERE shop_id = ?", ("SHOP-003",)
            ).fetchone()
        self.assertIsNone(row["last_seen"])
        shops = self.client.get("/api/admin/shops", headers=self.admin_headers).get_json()
        self.assertEqual((shops["online"], shops["offline"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
