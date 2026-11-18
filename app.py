import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

import yaml
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename


ROOT = Path(__file__).resolve().parent
DEFAULT_SERVER_PORT = 5001


def _load_environment(env_file=None):
    return load_dotenv(dotenv_path=env_file or ROOT / ".env", override=False)


def _valid_server_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def _server_port(value):
    return int(value) if _valid_server_port(value) else DEFAULT_SERVER_PORT


def _resolve_public_base_url(configured_url, port):
    return configured_url or f"http://127.0.0.1:{port}"


def _usable_public_base_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed.port
    except ValueError:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}


_load_environment()
SERVER_PORT = _server_port(os.environ.get("PORT", str(DEFAULT_SERVER_PORT)))
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", ROOT / "data" / "monitoring.sqlite3"))
ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN", "").strip()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "").strip()
_configured_public_base_url = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
PUBLIC_BASE_URL = _resolve_public_base_url(_configured_public_base_url, SERVER_PORT)
ONLINE_WINDOW_SECONDS = max(30, int(os.environ.get("ONLINE_WINDOW_SECONDS", "180")))
MAX_UPLOAD_MB = max(1, int(os.environ.get("MAX_UPLOAD_MB", "500")))
GITHUB_API = "https://api.github.com"
LAN_HEARTBEAT_BACKEND_URL = os.environ.get(
    "LAN_HEARTBEAT_BACKEND_URL", "http://127.0.0.1:8000/api/lan/heartbeat"
).strip()
LAN_HEARTBEAT_ALLOWED_ORIGIN = "http://127.0.0.1:8000"
TAG_PATTERN = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")
SHOP_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024 + 2 * 1024 * 1024
UPLOAD_PROGRESS = {}
UPLOAD_PROGRESS_LOCK = threading.Lock()
UPLOAD_PROGRESS_RETENTION_SECONDS = 900
UPLOAD_CHUNK_SIZE = 1024 * 1024


def _log_startup_configuration():
    if not _valid_server_port(os.environ.get("PORT", str(DEFAULT_SERVER_PORT))):
        app.logger.warning("PORT is invalid; defaulting the dashboard server to port %s.", SERVER_PORT)
    if not ADMIN_API_TOKEN:
        app.logger.warning(
            "ADMIN_API_TOKEN is not configured; protected admin API operations are disabled. "
            "Set it in the process environment or admin-dashboard/.env."
        )
    if not GITHUB_TOKEN:
        app.logger.warning(
            "GITHUB_TOKEN is not configured; GitHub release publishing is disabled until it is set."
        )
    if not GITHUB_REPOSITORY:
        app.logger.warning(
            "GITHUB_REPOSITORY is not configured; release publishing is disabled until it is set."
        )
    if not _configured_public_base_url:
        app.logger.warning(
            "PUBLIC_BASE_URL is not configured; using local development URL %s. "
            "Set a public HTTPS URL for remote shops.",
            PUBLIC_BASE_URL,
        )
    elif not _usable_public_base_url(PUBLIC_BASE_URL):
        app.logger.warning(
            "PUBLIC_BASE_URL must use HTTPS, except for loopback HTTP during local development."
        )


def _connect():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def _database():
    db = _connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def _initialize_database():
    with _database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS shops (
                shop_id TEXT PRIMARY KEY,
                shop_name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                current_version TEXT NOT NULL DEFAULT '',
                last_seen TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS releases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL UNIQUE,
                tag_name TEXT NOT NULL UNIQUE,
                notes TEXT NOT NULL,
                github_release_id INTEGER NOT NULL,
                github_html_url TEXT NOT NULL,
                installer_name TEXT NOT NULL,
                installer_asset_id INTEGER NOT NULL,
                installer_sha512 TEXT NOT NULL,
                installer_size INTEGER NOT NULL,
                manifest_text TEXT NOT NULL,
                published_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assignments (
                shop_id TEXT PRIMARY KEY REFERENCES shops(shop_id) ON DELETE CASCADE,
                release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
                assigned_at TEXT NOT NULL
            );
            """
        )


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _bearer_token():
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return ""
    return header[7:].strip()


def _admin_authorized():
    supplied = _bearer_token()
    return bool(ADMIN_API_TOKEN) and hmac.compare_digest(supplied, ADMIN_API_TOKEN)


def _require_admin():
    if not ADMIN_API_TOKEN:
        return jsonify(error="Admin API is unavailable until ADMIN_API_TOKEN is configured."), 503
    if not _admin_authorized():
        return jsonify(error="Admin authorization required"), 401
    return None


def _shop_from_token(supplied=None):
    supplied = _bearer_token() if supplied is None else supplied
    if not supplied:
        return None
    supplied_hash = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
    with _database() as db:
        row = db.execute("SELECT * FROM shops WHERE token_hash = ?", (supplied_hash,)).fetchone()
    return row if row and hmac.compare_digest(row["token_hash"], supplied_hash) else None


def _heartbeat_registered_shop_ids():
    with _database() as db:
        rows = db.execute("SELECT shop_id FROM shops ORDER BY shop_id LIMIT 51").fetchall()
    shop_ids = [row["shop_id"] for row in rows[:50]]
    if len(rows) > 50:
        shop_ids.append("... (additional shop IDs omitted)")
    return shop_ids


def _heartbeat_log_json(value, max_length=2048):
    serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    if len(serialized) > max_length:
        return f"{serialized[:max_length]}... [truncated]"
    return serialized


def _heartbeat_log_value(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:256]
    return f"<{type(value).__name__}>"


def _github_request(method, path, payload=None, data=None, content_type="application/json"):
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN is not configured on the dashboard server.")
    url = path if path.startswith("https://") else f"{GITHUB_API}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "KGS-Billing-Release-Dashboard",
    }
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = content_type
    elif data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        detail = error.read(2048).decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API returned HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach GitHub API: {error.reason}") from error


def _upload_github_asset(upload_url, filename, content, content_type, content_length=None, progress_callback=None):
    quoted_name = urllib.parse.quote(filename, safe="")
    upload_endpoint = upload_url.split("{", 1)[0] + "?name=" + quoted_name
    if not hasattr(content, "read"):
        return _github_request("POST", upload_endpoint, data=content, content_type=content_type)
    if content_length is None:
        raise ValueError("A content length is required to stream a GitHub release asset.")

    parsed_url = urllib.parse.urlsplit(upload_endpoint)
    if parsed_url.scheme != "https" or not parsed_url.hostname:
        raise ValueError("GitHub release assets must be uploaded over HTTPS.")
    connection = http.client.HTTPSConnection(
        parsed_url.hostname,
        parsed_url.port or 443,
        timeout=60,
        context=ssl.create_default_context(),
    )
    request_path = urllib.parse.urlunsplit(("", "", parsed_url.path, parsed_url.query, ""))
    try:
        connection.putrequest("POST", request_path)
        connection.putheader("Accept", "application/vnd.github+json")
        connection.putheader("Authorization", f"Bearer {GITHUB_TOKEN}")
        connection.putheader("Content-Type", content_type)
        connection.putheader("Content-Length", str(content_length))
        connection.putheader("User-Agent", "KGS-Billing-Release-Dashboard")
        connection.putheader("X-GitHub-Api-Version", "2022-11-28")
        connection.endheaders()
        sent = 0
        if progress_callback:
            progress_callback(sent, content_length)
        while True:
            chunk = content.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            connection.send(chunk)
            sent += len(chunk)
            if progress_callback:
                progress_callback(sent, content_length)
        response = connection.getresponse()
        response_body = response.read(8192)
        if response.status < 200 or response.status >= 300:
            detail = response_body.decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub asset upload returned HTTP {response.status}: {detail}")
        return json.loads(response_body) if response_body else {}
    finally:
        connection.close()


def _initialize_upload_progress(upload_id, total_bytes=0):
    now = time.monotonic()
    with UPLOAD_PROGRESS_LOCK:
        expired = [
            key for key, value in UPLOAD_PROGRESS.items()
            if now - value["updated_at"] > UPLOAD_PROGRESS_RETENTION_SECONDS
        ]
        for key in expired:
            del UPLOAD_PROGRESS[key]
        UPLOAD_PROGRESS[upload_id] = {
            "phase": "preparing",
            "bytesSent": 0,
            "totalBytes": total_bytes,
            "percent": 0,
            "speedBytesPerSecond": 0,
            "etaSeconds": None,
            "message": "Preparing installer upload.",
            "updated_at": now,
            "last_sample_at": now,
            "last_sample_bytes": 0,
        }


def _set_upload_progress(upload_id, phase, bytes_sent=0, total_bytes=0, message=""):
    now = time.monotonic()
    with UPLOAD_PROGRESS_LOCK:
        state = UPLOAD_PROGRESS.get(upload_id)
        if state is None:
            return
        if phase != state["phase"]:
            state["speedBytesPerSecond"] = 0
            state["last_sample_at"] = now
            state["last_sample_bytes"] = bytes_sent
        if phase == "uploading_to_github":
            elapsed = now - state["last_sample_at"]
            byte_delta = bytes_sent - state["last_sample_bytes"]
            if elapsed > 0 and byte_delta > 0:
                state["speedBytesPerSecond"] = byte_delta / elapsed
                state["last_sample_at"] = now
                state["last_sample_bytes"] = bytes_sent
        else:
            state["speedBytesPerSecond"] = 0
        speed = state["speedBytesPerSecond"]
        eta = (total_bytes - bytes_sent) / speed if speed > 0 and total_bytes >= bytes_sent else None
        percent = min(100, round(bytes_sent * 100 / total_bytes)) if total_bytes else 0
        state.update({
            "phase": phase,
            "bytesSent": bytes_sent,
            "totalBytes": total_bytes,
            "percent": percent,
            "etaSeconds": max(0, round(eta)) if eta is not None else None,
            "message": message,
            "updated_at": now,
        })


def _get_upload_progress(upload_id):
    with UPLOAD_PROGRESS_LOCK:
        state = UPLOAD_PROGRESS.get(upload_id)
        if not state:
            return {
                "phase": "waiting",
                "bytesSent": 0,
                "totalBytes": 0,
                "percent": 0,
                "speedBytesPerSecond": 0,
                "etaSeconds": None,
                "message": "Waiting for the upload to start.",
            }
        return {key: value for key, value in state.items() if not key.endswith("_at") and key != "last_sample_bytes"}


def _asset_by_id(release_id, asset_id):
    data = _github_request(
        "GET",
        f"/repos/{GITHUB_REPOSITORY}/releases/{release_id}/assets",
    )
    for asset in data:
        if asset["id"] == asset_id:
            return asset
    raise RuntimeError("The published installer asset could not be found on GitHub.")


def _read_upload(upload, upload_id=None):
    digest = hashlib.sha512()
    stream = upload.stream
    stream.seek(0, os.SEEK_END)
    total_bytes = stream.tell()
    stream.seek(0)
    if total_bytes > MAX_UPLOAD_MB * 1024 * 1024:
        raise ValueError(f"An upload exceeds the {MAX_UPLOAD_MB} MB limit.")
    size = 0
    if upload_id:
        _set_upload_progress(upload_id, "verifying", 0, total_bytes, "Verifying installer and calculating SHA-512.")
    while True:
        chunk = stream.read(UPLOAD_CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_UPLOAD_MB * 1024 * 1024:
            raise ValueError(f"An upload exceeds the {MAX_UPLOAD_MB} MB limit.")
        digest.update(chunk)
        if upload_id:
            _set_upload_progress(upload_id, "verifying", size, total_bytes, "Verifying installer and calculating SHA-512.")
    stream.seek(0)
    return digest.digest(), size


@app.get("/")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/styles.css")
def dashboard_styles():
    return send_from_directory(app.static_folder, "styles.css")


@app.get("/app.js")
def dashboard_script():
    return send_from_directory(app.static_folder, "app.js")


@app.get("/api/health")
def health():
    return jsonify(ok=True)


def _lan_proxy_headers():
    origin = request.headers.get("Origin", "")
    headers = {"Vary": "Origin"}
    if origin == LAN_HEARTBEAT_ALLOWED_ORIGIN:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
    return headers


@app.route("/api/lan/heartbeat", methods=["POST", "OPTIONS"])
def lan_heartbeat_proxy():
    headers = _lan_proxy_headers()
    origin = request.headers.get("Origin", "")
    if origin and origin != LAN_HEARTBEAT_ALLOWED_ORIGIN:
        return jsonify(ok=False, message="Origin not allowed"), 403, headers
    if request.method == "OPTIONS":
        headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type"
        headers["Access-Control-Max-Age"] = "600"
        return Response(status=204, headers=headers)

    forwarded = {}
    cookie = request.headers.get("Cookie")
    if cookie:
        forwarded["Cookie"] = cookie
    content_type = request.headers.get("Content-Type")
    if content_type:
        forwarded["Content-Type"] = content_type
    backend_request = urllib.request.Request(
        LAN_HEARTBEAT_BACKEND_URL,
        data=request.get_data(),
        headers=forwarded,
        method="POST",
    )
    try:
        with urllib.request.urlopen(backend_request, timeout=10) as backend_response:
            body = backend_response.read()
            status = backend_response.status
            backend_headers = backend_response.headers
    except urllib.error.HTTPError as error:
        body = error.read()
        status = error.code
        backend_headers = error.headers
    except urllib.error.URLError as error:
        response = jsonify(ok=False, message=f"Billing backend unavailable: {error.reason}")
        response.status_code = 502
        response.headers.extend(headers)
        return response

    response = Response(body, status=status, content_type=backend_headers.get("Content-Type", "application/json"))
    for value in backend_headers.get_all("Set-Cookie") or []:
        response.headers.add("Set-Cookie", value)
    response.headers.extend(headers)
    return response


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/api/admin/shops")
def list_shops():
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized
    cutoff = datetime.now(timezone.utc).timestamp() - ONLINE_WINDOW_SECONDS
    with _database() as db:
        rows = db.execute(
            """
            SELECT s.shop_id, s.shop_name, s.current_version, s.last_seen,
                   a.release_id, r.version AS assigned_version
            FROM shops s
            LEFT JOIN assignments a ON a.shop_id = s.shop_id
            LEFT JOIN releases r ON r.id = a.release_id
            ORDER BY s.shop_name COLLATE NOCASE
            """
        ).fetchall()
    shops = []
    for row in rows:
        try:
            seen = datetime.fromisoformat(row["last_seen"]).timestamp() if row["last_seen"] else 0
        except ValueError:
            seen = 0
        shops.append({
            "shopId": row["shop_id"],
            "shopName": row["shop_name"],
            "currentVersion": row["current_version"],
            "lastSeen": row["last_seen"],
            "online": seen >= cutoff,
            "assignedVersion": row["assigned_version"],
        })
    return jsonify(
        shops=shops,
        total=len(shops),
        online=sum(1 for shop in shops if shop["online"]),
        offline=sum(1 for shop in shops if not shop["online"]),
        onlineWindowSeconds=ONLINE_WINDOW_SECONDS,
    )


@app.post("/api/admin/shops")
def create_shop():
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized
    if not _usable_public_base_url(PUBLIC_BASE_URL):
        return jsonify(error="Set PUBLIC_BASE_URL to HTTPS, or use a loopback HTTP URL for local development."), 503
    body = request.get_json(silent=True) or {}
    shop_id = str(body.get("shopId", "")).strip()
    shop_name = str(body.get("shopName", "")).strip()
    if not SHOP_ID_PATTERN.fullmatch(shop_id) or not shop_name or len(shop_name) > 120:
        return jsonify(error="Provide a valid Shop ID (up to 64 safe characters) and Shop Name."), 400
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    try:
        with _database() as db:
            db.execute(
                "INSERT INTO shops (shop_id, shop_name, token_hash, created_at) VALUES (?, ?, ?, ?)",
                (shop_id, shop_name, token_hash, _now()),
            )
    except sqlite3.IntegrityError:
        return jsonify(error="That Shop ID already exists."), 409
    return jsonify(
        shopId=shop_id,
        shopName=shop_name,
        shopToken=token,
        clientConfig={
            "apiUrl": PUBLIC_BASE_URL,
            "shopId": shop_id,
            "shopName": shop_name,
            "shopToken": token,
        },
        warning="Copy this token now. It cannot be retrieved later.",
    ), 201


@app.post("/api/admin/shops/<shop_id>/rotate-token")
def rotate_shop_token(shop_id):
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _database() as db:
        cursor = db.execute(
            "UPDATE shops SET token_hash = ? WHERE shop_id = ?",
            (token_hash, shop_id),
        )
        shop = db.execute(
            "SELECT shop_name FROM shops WHERE shop_id = ?",
            (shop_id,),
        ).fetchone()
    if cursor.rowcount != 1 or not shop:
        return jsonify(error="Shop ID not found."), 404
    return jsonify(
        shopId=shop_id,
        shopName=shop["shop_name"],
        clientConfig={
            "apiUrl": PUBLIC_BASE_URL,
            "shopId": shop_id,
            "shopName": shop["shop_name"],
            "shopToken": token,
        },
        warning="The previous token is now invalid. Copy this token; it cannot be retrieved later.",
    )


@app.get("/api/admin/releases")
def list_releases():
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized
    with _database() as db:
        rows = db.execute(
            """
            SELECT r.id, r.version, r.tag_name, r.notes, r.github_html_url, r.published_at,
                   COUNT(a.shop_id) AS target_count
            FROM releases r LEFT JOIN assignments a ON a.release_id = r.id
            GROUP BY r.id ORDER BY r.id DESC
            """
        ).fetchall()
    return jsonify(releases=[dict(row) for row in rows])


@app.get("/api/admin/releases/progress/<upload_id>")
def release_upload_progress(upload_id):
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", upload_id):
        return jsonify(error="Invalid upload ID."), 400
    return jsonify(_get_upload_progress(upload_id))


@app.post("/api/admin/releases")
def publish_release():
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized

    upload_id = request.headers.get("X-Upload-Id", "")
    if upload_id and not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", upload_id):
        return jsonify(error="Invalid upload ID."), 400
    if upload_id:
        _initialize_upload_progress(upload_id)

    version = request.form.get("version", "").strip()
    if version.startswith("v"):
        version = version[1:]
    notes = request.form.get("notes", "").strip()
    installer = request.files.get("installer")
    if not TAG_PATTERN.fullmatch(version):
        return jsonify(error="Version must be semantic, such as 1.1.0 or 1.1.0-beta.1."), 400
    if not installer or not installer.filename.lower().endswith(".exe"):
        return jsonify(error="Select the Windows NSIS installer (.exe). Arbitrary ZIP files are not accepted."), 400
    if not notes or len(notes) > 20000:
        return jsonify(error="Release notes are required and must be at most 20,000 characters."), 400
    if not GITHUB_REPOSITORY or not REPOSITORY_PATTERN.fullmatch(GITHUB_REPOSITORY):
        return jsonify(error="Set GITHUB_REPOSITORY as owner/repository on the dashboard server."), 503
    if not GITHUB_TOKEN:
        return jsonify(error="Set GITHUB_TOKEN on the dashboard server before publishing releases."), 503
    if not _usable_public_base_url(PUBLIC_BASE_URL):
        return jsonify(error="Set PUBLIC_BASE_URL to HTTPS, or use a loopback HTTP URL for local development."), 503

    try:
        installer_sha512, installer_size = _read_upload(installer, upload_id)
    except ValueError as error:
        return jsonify(error=str(error)), 413
    if not installer_size:
        return jsonify(error="Installer must not be empty."), 400

    installer_name = secure_filename(Path(installer.filename.replace("\\", "/")).name)
    if not installer_name.lower().endswith(".exe"):
        return jsonify(error="The installer filename is invalid."), 400
    tag_name = f"v{version}"
    manifest = {
        "version": version,
        "files": [{
            "url": installer_name,
            "sha512": base64.b64encode(installer_sha512).decode("ascii"),
            "size": installer_size,
        }],
        "path": installer_name,
        "sha512": base64.b64encode(installer_sha512).decode("ascii"),
        "releaseDate": _now(),
    }
    manifest_bytes = yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True).encode("utf-8")
    draft = None
    try:
        if upload_id:
            _set_upload_progress(upload_id, "creating_release", 0, installer_size, "Creating a GitHub draft release.")
        draft = _github_request("POST", f"/repos/{GITHUB_REPOSITORY}/releases", {
            "tag_name": tag_name,
            "name": tag_name,
            "body": notes,
            "draft": True,
            "prerelease": "-" in version,
        })
        upload_url = draft["upload_url"]
        def report_installer_progress(bytes_sent, total_bytes):
            _set_upload_progress(
                upload_id,
                "uploading_to_github",
                bytes_sent,
                total_bytes,
                "Uploading installer to GitHub.",
            )

        installer_asset = _upload_github_asset(
            upload_url,
            installer_name,
            installer.stream,
            "application/vnd.microsoft.portable-executable",
            content_length=installer_size,
            progress_callback=report_installer_progress if upload_id else None,
        )
        if upload_id:
            _set_upload_progress(upload_id, "publishing", installer_size, installer_size, "Publishing release metadata.")
        _upload_github_asset(upload_url, "latest.yml", manifest_bytes, "text/yaml")
        published = _github_request("PATCH", f"/repos/{GITHUB_REPOSITORY}/releases/{draft['id']}", {
            "draft": False,
        })
        with _database() as db:
            cursor = db.execute(
                """
                INSERT INTO releases
                    (version, tag_name, notes, github_release_id, github_html_url,
                     installer_name, installer_asset_id, installer_sha512, installer_size,
                     manifest_text, published_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version, tag_name, notes, published["id"], published["html_url"],
                    installer_name, installer_asset["id"],
                    manifest["sha512"], installer_size,
                    manifest_bytes.decode("utf-8"), _now(),
                ),
            )
            release_id = cursor.lastrowid
    except Exception as error:
        if upload_id:
            _set_upload_progress(upload_id, "failed", message="Release upload failed.")
        if draft and draft.get("id"):
            try:
                _github_request("DELETE", f"/repos/{GITHUB_REPOSITORY}/releases/{draft['id']}")
            except Exception:
                app.logger.exception("Failed to remove incomplete GitHub draft release %s", draft["id"])
        if isinstance(error, sqlite3.IntegrityError):
            return jsonify(error="That release version or tag has already been published."), 409
        app.logger.exception("GitHub release publishing failed")
        return jsonify(error=str(error)), 502

    if upload_id:
        _set_upload_progress(upload_id, "complete", installer_size, installer_size, "Release published successfully.")
    return jsonify(
        releaseId=release_id,
        version=version,
        githubUrl=published["html_url"],
        message="Release published. Select shops and use Push Update to target them.",
    ), 201


@app.post("/api/admin/push")
def push_update():
    unauthorized = _require_admin()
    if unauthorized:
        return unauthorized
    body = request.get_json(silent=True) or {}
    try:
        release_id = int(body.get("releaseId"))
    except (TypeError, ValueError):
        return jsonify(error="Select a valid release."), 400
    shop_ids = body.get("shopIds")
    if not isinstance(shop_ids, list) or not shop_ids or len(shop_ids) > 500:
        return jsonify(error="Select at least one shop (maximum 500 per push)."), 400
    if any(not isinstance(shop_id, str) for shop_id in shop_ids):
        return jsonify(error="Invalid Shop ID selection."), 400
    shop_ids = list(dict.fromkeys(shop_ids))
    with _database() as db:
        if not db.execute("SELECT 1 FROM releases WHERE id = ?", (release_id,)).fetchone():
            return jsonify(error="The selected release does not exist."), 404
        existing = {
            row["shop_id"] for row in db.execute(
                f"SELECT shop_id FROM shops WHERE shop_id IN ({','.join('?' for _ in shop_ids)})",
                shop_ids,
            )
        }
        missing = sorted(set(shop_ids) - existing)
        if missing:
            return jsonify(error=f"Unknown Shop ID(s): {', '.join(missing)}"), 404
        now = _now()
        db.executemany(
            """
            INSERT INTO assignments (shop_id, release_id, assigned_at) VALUES (?, ?, ?)
            ON CONFLICT(shop_id) DO UPDATE SET release_id = excluded.release_id, assigned_at = excluded.assigned_at
            """,
            [(shop_id, release_id, now) for shop_id in shop_ids],
        )
    return jsonify(assigned=len(shop_ids), shopIds=shop_ids)


@app.post("/api/heartbeat")
def heartbeat():
    raw_body = request.get_json(silent=True)
    body = raw_body if isinstance(raw_body, dict) else {}
    supplied_id_value = body.get("shopId")
    supplied_id = supplied_id_value.strip() if isinstance(supplied_id_value, str) else ""
    supplied_token = _bearer_token()
    token_hash = (
        hashlib.sha256(supplied_token.encode("utf-8")).hexdigest()
        if supplied_token
        else "(missing)"
    )
    app.logger.info(
        "Shop heartbeat request incomingTokenHash=%s rawBody=%s",
        token_hash,
        _heartbeat_log_json(raw_body),
    )

    shop = _shop_from_token(supplied_token)
    if not shop:
        app.logger.warning(
            "Shop heartbeat rejected: incomingTokenHash=%s submittedShopId=%s registeredShopIds=%s",
            token_hash,
            _heartbeat_log_json(supplied_id),
            _heartbeat_log_json(_heartbeat_registered_shop_ids()),
        )
        return jsonify(error="Unknown or invalid shop credential."), 401

    version_value = body.get("version")
    version = version_value.strip()[:64] if isinstance(version_value, str) else ""
    if supplied_id != shop["shop_id"] or not version:
        app.logger.warning(
            "Shop heartbeat rejected: submittedShopId=%s authenticatedShopId=%s registeredShopIds=%s versionPresent=%s",
            _heartbeat_log_json(supplied_id),
            _heartbeat_log_json(shop["shop_id"]),
            _heartbeat_log_json(_heartbeat_registered_shop_ids()),
            bool(version),
        )
        return jsonify(error="Heartbeat Shop ID or version is invalid."), 400

    reported_status = body.get("status")
    going_offline = (
        isinstance(reported_status, str)
        and reported_status.strip().lower() == "offline"
    )
    last_seen = None if going_offline else _now()

    with _database() as db:
        cursor = db.execute(
            "UPDATE shops SET current_version = ?, last_seen = ? WHERE shop_id = ?",
            (version, last_seen, shop["shop_id"]),
        )
        if cursor.rowcount != 1:
            db.rollback()
            app.logger.error(
                "Shop heartbeat update affected %s rows: submittedShopId=%s authenticatedShopId=%s registeredShopIds=%s",
                cursor.rowcount,
                _heartbeat_log_json(supplied_id),
                _heartbeat_log_json(shop["shop_id"]),
                _heartbeat_log_json(_heartbeat_registered_shop_ids()),
            )
            return jsonify(error="Registered shop was not found while updating heartbeat."), 404
        db.commit()
        print(
            f"--> [DEBUG] {'Offline report' if going_offline else 'Heartbeat'} successfully committed for shop_id: {shop['shop_id']} at {last_seen}",
            flush=True,
        )
        stored_heartbeat = db.execute(
            "SELECT last_seen FROM shops WHERE shop_id = ?",
            (shop["shop_id"],),
        ).fetchone()
        stored_last_seen = stored_heartbeat["last_seen"] if stored_heartbeat else None
        print(
            f"--> [DEBUG] SQLite last_seen for shop_id: {shop['shop_id']} is {stored_last_seen}",
            flush=True,
        )
        app.logger.info(
            "Shop %s committed shopId=%s last_seen=%s",
            "offline report" if going_offline else "heartbeat",
            json.dumps(shop["shop_id"]),
            last_seen,
        )
        assignment = db.execute(
            """
            SELECT r.id, r.version, r.notes
            FROM assignments a JOIN releases r ON r.id = a.release_id
            WHERE a.shop_id = ?
            """,
            (shop["shop_id"],),
        ).fetchone()

    update = None
    if not going_offline and assignment and assignment["version"] != version:
        update = {
            "releaseId": assignment["id"],
            "version": assignment["version"],
            "notes": assignment["notes"],
        }
    return jsonify(status="success", serverTime=last_seen, update=update), 200


def _shop_has_release(shop, release_id):
    with _database() as db:
        return db.execute(
            "SELECT 1 FROM assignments WHERE shop_id = ? AND release_id = ?",
            (shop["shop_id"], release_id),
        ).fetchone() is not None


@app.get("/api/update-feed/<shop_id>/latest.yml")
def update_feed(shop_id):
    shop = _shop_from_token()
    if not shop or shop["shop_id"] != shop_id:
        return jsonify(error="Invalid shop credential."), 401
    with _database() as db:
        row = db.execute(
            """
            SELECT r.id, r.version, r.manifest_text
            FROM assignments a JOIN releases r ON r.id = a.release_id
            WHERE a.shop_id = ?
            """,
            (shop_id,),
        ).fetchone()
    if not row:
        return jsonify(error="No update is assigned to this shop."), 404
    parsed = yaml.safe_load(row["manifest_text"])
    asset_url = f"{PUBLIC_BASE_URL}/api/update-assets/{row['id']}/{urllib.parse.quote(Path(parsed['path']).name, safe='')}"
    parsed["path"] = asset_url
    for file_info in parsed.get("files", []):
        file_info["url"] = asset_url
    return Response(
        yaml.safe_dump(parsed, sort_keys=False, allow_unicode=True),
        mimetype="text/yaml",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/update-assets/<int:release_id>/<path:filename>")
def update_asset(release_id, filename):
    shop = _shop_from_token()
    if not shop or not _shop_has_release(shop, release_id):
        return jsonify(error="Invalid shop credential or update assignment."), 401
    with _database() as db:
        release = db.execute(
            "SELECT github_release_id, installer_name, installer_asset_id FROM releases WHERE id = ?",
            (release_id,),
        ).fetchone()
    if not release or filename != release["installer_name"]:
        return jsonify(error="Release asset not found."), 404
    try:
        asset = _asset_by_id(release["github_release_id"], release["installer_asset_id"])
        req = urllib.request.Request(
            asset["browser_download_url"],
            headers={"User-Agent": "KGS-Billing-Update-Proxy", "Accept": "application/octet-stream"},
        )
        try:
            upstream = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code not in (401, 403, 404):
                raise
            req = urllib.request.Request(
                f"{GITHUB_API}/repos/{GITHUB_REPOSITORY}/releases/assets/{release['installer_asset_id']}",
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/octet-stream",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "KGS-Billing-Update-Proxy",
                },
            )
            upstream = urllib.request.urlopen(req, timeout=60)
    except (urllib.error.URLError, RuntimeError) as error:
        app.logger.exception("Unable to retrieve a GitHub update asset")
        return jsonify(error=f"Could not retrieve update asset: {error}"), 502

    def stream():
        try:
            while True:
                chunk = upstream.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            upstream.close()

    headers = {
        "Content-Disposition": f'attachment; filename="{release["installer_name"]}"',
        "Cache-Control": "no-store",
    }
    if isinstance(asset.get("size"), int) and asset["size"] > 0:
        headers["Content-Length"] = str(asset["size"])
    return Response(stream(), mimetype="application/octet-stream", headers=headers)


@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify(error=f"Upload exceeds the configured {MAX_UPLOAD_MB} MB limit."), 413


_initialize_database()
_log_startup_configuration()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=SERVER_PORT, debug=False)