import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_PATH = os.environ.get("DATABASE_PATH", "/data/me.sqlite3")
USERGATE_API_BASE = os.environ.get(
    "USERGATE_API_BASE", "https://usergate.sandalgurun.web.id/api/v1"
).rstrip("/")
USERGATE_API_KEY = os.environ.get("USERGATE_API_KEY", "")
TRUST_PROXY = os.environ.get("TRUST_PROXY", "false").lower() == "true"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
SESSION_DAYS = 7
MAX_BODY_SIZE = 1024 * 1024
DB_LOCK = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def db_connection():
    connection = connect_db()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                external_id TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                full_name TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL CHECK (role IN ('SUPERADMIN', 'USER')),
                status TEXT NOT NULL CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED')),
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS collection_links (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                created_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                link_id TEXT NOT NULL REFERENCES collection_links(id),
                collected_at TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT '',
                browser TEXT NOT NULL DEFAULT '',
                local_ips TEXT NOT NULL DEFAULT '[]',
                public_ip TEXT NOT NULL DEFAULT '',
                server_ip TEXT NOT NULL DEFAULT '',
                hostname TEXT NOT NULL DEFAULT '',
                windows_user TEXT NOT NULL DEFAULT '',
                mac_addresses TEXT NOT NULL DEFAULT '[]',
                tcp_ports TEXT NOT NULL DEFAULT '[]',
                udp_ports TEXT NOT NULL DEFAULT '[]',
                details TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_devices_collected ON devices(collected_at);
            """
        )
        existing_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(devices)")
        }
        for column, definition in (
            ("hostname", "TEXT NOT NULL DEFAULT ''"),
            ("windows_user", "TEXT NOT NULL DEFAULT ''"),
            ("mac_addresses", "TEXT NOT NULL DEFAULT '[]'"),
            ("tcp_ports", "TEXT NOT NULL DEFAULT '[]'"),
            ("udp_ports", "TEXT NOT NULL DEFAULT '[]'"),
        ):
            if column not in existing_columns:
                connection.execute(f"ALTER TABLE devices ADD COLUMN {column} {definition}")


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def raise_usergate_error(status, message="", error_data=None):
    normalized_message = message.casefold()
    error_data = error_data if isinstance(error_data, dict) else {}
    if error_data.get("cloudflare_error") or error_data.get("error_name") == "browser_signature_banned":
        raise RuntimeError(
            "Cloudflare UserGate memblokir koneksi aplikasi (Error 1010). "
            "Jika ini tetap terjadi, minta administrator UserGate mengizinkan akses API dari server aplikasi."
        )
    if status == 429:
        raise BlockingIOError("Terlalu banyak percobaan login. Coba lagi beberapa saat.")
    if "api key" in normalized_message:
        raise RuntimeError("API key UserGate tidak valid atau tidak aktif.")
    if status == 401 or "invalid credentials" in normalized_message:
        raise PermissionError(
            "UserGate menolak kredensial. Pastikan memakai username UserGate "
            "(bukan email), password benar, dan akun berstatus ACTIVE."
        )
    if status == 403:
        raise RuntimeError(f"UserGate menolak permintaan login: {message[:160] or 'HTTP 403'}.")
    description = message or str(error_data.get("detail") or error_data.get("title") or "")
    raise RuntimeError(f"UserGate gagal memverifikasi login: {description[:160] or 'respons autentikasi tidak valid'}.")


def usergate_login(username, password):
    if not USERGATE_API_KEY:
        raise RuntimeError("USERGATE_API_KEY belum dikonfigurasi.")
    request = urllib.request.Request(
        f"{USERGATE_API_BASE}/auth/login",
        data=json.dumps({"username": username, "password": password}).encode("utf-8"),
        headers={
            "X-API-Key": USERGATE_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ME-Device-Management/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(body)
        except json.JSONDecodeError:
            error_data = {}
        message = error_data.get("message", "") if isinstance(error_data, dict) else ""
        try:
            raise_usergate_error(error.code, message, error_data)
        except (BlockingIOError, PermissionError, RuntimeError) as classified_error:
            raise classified_error from error
        raise ConnectionError(f"UserGate menolak permintaan (HTTP {error.code}).") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ConnectionError("Tidak dapat menghubungi UserGate.") from error
    if not isinstance(result, dict):
        raise RuntimeError("UserGate mengembalikan format respons yang tidak dikenal.")
    if not result.get("status"):
        raise_usergate_error(None, str(result.get("message") or ""), result)
    data = result.get("data")
    user = data.get("user") if isinstance(data, dict) else None
    if not isinstance(user, dict) or not user.get("id") or not user.get("username"):
        raise RuntimeError("Respons login UserGate tidak berisi profil user yang valid.")
    return user

def register_or_find_user(external_user):
    external_id = str(external_user["id"])
    now = utc_now()
    with DB_LOCK, db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        has_superadmin = connection.execute(
            "SELECT EXISTS(SELECT 1 FROM users WHERE role = 'SUPERADMIN')"
        ).fetchone()[0]
        user = connection.execute(
            "SELECT * FROM users WHERE external_id = ?", (external_id,)
        ).fetchone()
        if user is None:
            user_id = secrets.token_hex(16)
            connection.execute(
                """
                INSERT INTO users
                    (id, external_id, username, email, full_name, role, status, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    external_id,
                    str(external_user["username"])[:100],
                    str(external_user.get("email") or "")[:254],
                    str(external_user.get("full_name") or "")[:150],
                    "SUPERADMIN" if not has_superadmin else "USER",
                    "ACTIVE" if not has_superadmin else "PENDING",
                    now,
                    now,
                ),
            )
            user = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        else:
            connection.execute(
                """
                UPDATE users
                SET username = ?, email = ?, full_name = ?, last_login_at = ?,
                    role = CASE WHEN ? THEN 'SUPERADMIN' ELSE role END,
                    status = CASE WHEN ? THEN 'ACTIVE' ELSE status END
                WHERE id = ?
                """,
                (
                    str(external_user["username"])[:100],
                    str(external_user.get("email") or "")[:254],
                    str(external_user.get("full_name") or "")[:150],
                    now,
                    not has_superadmin,
                    not has_superadmin,
                    user["id"],
                ),
            )
            user = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
        return dict(user)


def valid_ip(value):
    if not isinstance(value, str):
        return ""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


class AppHandler(BaseHTTPRequestHandler):
    server_version = "DeviceInventory/1.0"

    def log_message(self, format_string, *args):
        path = urlsplit(self.path).path
        if path.startswith("/api/collect/"):
            path = "/api/collect/[token]"
        elif path.startswith("/collect/"):
            path = "/collect/[token]"
        print(f"{self.client_address[0]} {self.command} {path}")

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_page(self, filename):
        try:
            body = (STATIC / filename).read_bytes()
        except OSError:
            self.send_json(500, {"error": "Halaman aplikasi tidak tersedia."})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self' https://api.ipify.org; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Ukuran permintaan tidak valid.")
        if length < 0 or length > MAX_BODY_SIZE:
            raise ValueError("Ukuran permintaan terlalu besar.")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Format JSON tidak valid.") from error
        if not isinstance(value, dict):
            raise ValueError("Format permintaan tidak valid.")
        return value

    def get_session_user(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookies.get("me_session")
        if morsel is None:
            return None
        with db_connection() as connection:
            user = connection.execute(
                """
                SELECT users.* FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash(morsel.value), utc_now()),
            ).fetchone()
        return dict(user) if user and user["status"] == "ACTIVE" else None

    def require_admin(self):
        user = self.get_session_user()
        if user is None:
            self.send_json(401, {"error": "Silakan login kembali."})
            return None
        if user["role"] != "SUPERADMIN":
            self.send_json(403, {"error": "Hanya superadmin lokal yang dapat mengelola aplikasi."})
            return None
        return user

    def require_user(self):
        user = self.get_session_user()
        if user is None:
            self.send_json(401, {"error": "Silakan login kembali."})
        return user

    def client_ip(self):
        if TRUST_PROXY:
            forwarded = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            address = valid_ip(forwarded)
            if address:
                return address
        return valid_ip(self.client_address[0])

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self.send_page("index.html")
        elif re.fullmatch(r"/collect/[A-Za-z0-9_-]{30,100}/collector\.(ps1|cmd)", path):
            self.download_collector(path.split("/")[2])
        elif path.startswith("/collect/") and len(path.split("/")) == 3:
            self.send_page("collect.html")
        elif path == "/health":
            self.send_json(200, {"status": "ok", "usergate_configured": bool(USERGATE_API_KEY)})
        elif path == "/api/me":
            user = self.get_session_user()
            if user is None:
                self.send_json(401, {"error": "Silakan login."})
            else:
                self.send_json(200, {"user": self.public_user(user)})
        elif path.startswith("/api/admin/"):
            if path == "/api/admin/users":
                if self.require_admin() is None:
                    return
                self.admin_users()
            elif path == "/api/admin/links":
                if self.require_user() is None:
                    return
                self.admin_links()
            elif path == "/api/admin/devices":
                if self.require_user() is None:
                    return
                self.admin_devices()
            else:
                self.send_json(404, {"error": "Endpoint tidak ditemukan."})
        else:
            self.send_json(404, {"error": "Halaman tidak ditemukan."})

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            payload = self.read_json()
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        if path == "/api/login":
            self.login(payload)
        elif path == "/api/logout":
            self.logout()
        elif path == "/api/admin/links":
            user = self.require_admin()
            if user:
                self.create_link(user, payload)
        elif path.startswith("/api/collect/"):
            self.collect_device(path.removeprefix("/api/collect/"), payload)
        else:
            self.send_json(404, {"error": "Endpoint tidak ditemukan."})

    def do_PATCH(self):
        path = urlsplit(self.path).path
        user = self.require_admin()
        if user is None:
            return
        try:
            payload = self.read_json()
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        match = re.fullmatch(r"/api/admin/users/([a-f0-9]+)", path)
        if match:
            self.update_user(match.group(1), payload, user)
        else:
            self.send_json(404, {"error": "Endpoint tidak ditemukan."})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if self.require_admin() is None:
            return
        match = re.fullmatch(r"/api/admin/links/([a-f0-9]+)", path)
        if not match:
            self.send_json(404, {"error": "Endpoint tidak ditemukan."})
            return
        with db_connection() as connection:
            result = connection.execute(
                "UPDATE collection_links SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (utc_now(), match.group(1)),
            )
        if result.rowcount == 0:
            self.send_json(404, {"error": "Link tidak ditemukan atau sudah dicabut."})
        else:
            self.send_json(200, {"message": "Link berhasil dicabut."})

    @staticmethod
    def public_user(user):
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "status": user["status"],
            "created_at": user["created_at"],
            "last_login_at": user["last_login_at"],
        }

    def login(self, payload):
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not username.strip() or not isinstance(password, str) or not password:
            self.send_json(400, {"error": "Username dan password wajib diisi."})
            return
        try:
            external_user = usergate_login(username.strip(), password)
        except PermissionError as error:
            self.send_json(401, {"error": str(error)})
            return
        except BlockingIOError as error:
            self.send_json(429, {"error": str(error)})
            return
        except (ConnectionError, RuntimeError) as error:
            self.send_json(502, {"error": str(error)})
            return
        try:
            user = register_or_find_user(external_user)
        except sqlite3.Error:
            self.send_json(500, {"error": "Gagal menyimpan akun lokal. Coba lagi."})
            return
        if user["status"] == "PENDING":
            self.send_json(403, {"error": "Akun berhasil diverifikasi UserGate, tetapi menunggu aktivasi superadmin lokal."})
            return
        if user["status"] != "ACTIVE":
            self.send_json(403, {"error": "Akun dinonaktifkan oleh superadmin lokal."})
            return
        session_token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        with db_connection() as connection:
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash(session_token), user["id"], expires_at),
            )
        cookie = f"me_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS * 86400}"
        if COOKIE_SECURE:
            cookie += "; Secure"
        self.send_json(200, {"user": self.public_user(user)}, {"Set-Cookie": cookie})

    def logout(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            cookies = SimpleCookie()
        morsel = cookies.get("me_session")
        if morsel:
            with db_connection() as connection:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(morsel.value),))
        self.send_json(
            200,
            {"message": "Berhasil logout."},
            {"Set-Cookie": "me_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"},
        )

    def admin_users(self):
        with db_connection() as connection:
            users = connection.execute(
                "SELECT * FROM users ORDER BY CASE status WHEN 'PENDING' THEN 0 ELSE 1 END, created_at"
            ).fetchall()
        self.send_json(200, {"users": [self.public_user(user) for user in users]})

    def update_user(self, user_id, payload, actor):
        if not payload or set(payload) - {"status", "role"}:
            self.send_json(400, {"error": "Perubahan hanya boleh memuat status dan/atau peran lokal."})
            return
        status = payload.get("status")
        role = payload.get("role")
        if "status" in payload and status not in ("PENDING", "ACTIVE", "DISABLED"):
            self.send_json(400, {"error": "Status harus PENDING, ACTIVE, atau DISABLED."})
            return
        if "role" in payload and role not in ("USER", "SUPERADMIN"):
            self.send_json(400, {"error": "Peran lokal harus USER atau SUPERADMIN."})
            return
        with DB_LOCK, db_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            target = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if target is None:
                self.send_json(404, {"error": "User tidak ditemukan."})
                return
            new_role = role if "role" in payload else target["role"]
            new_status = status if "status" in payload else target["status"]
            if target["id"] == actor["id"] and (new_role != target["role"] or new_status != target["status"]):
                self.send_json(400, {"error": "Superadmin tidak dapat mengubah peran atau status akunnya sendiri."})
                return
            if target["role"] == "SUPERADMIN" and target["status"] == "ACTIVE":
                other_active_admins = connection.execute(
                    """
                    SELECT COUNT(*) FROM users
                    WHERE id != ? AND role = 'SUPERADMIN' AND status = 'ACTIVE'
                    """,
                    (user_id,),
                ).fetchone()[0]
                if other_active_admins == 0 and (new_role != "SUPERADMIN" or new_status != "ACTIVE"):
                    self.send_json(400, {"error": "Tidak dapat menonaktifkan atau menurunkan peran superadmin aktif terakhir."})
                    return
            connection.execute(
                "UPDATE users SET role = ?, status = ? WHERE id = ?",
                (new_role, new_status, user_id),
            )
            if new_status != "ACTIVE":
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        self.send_json(200, {"message": "Akses lokal user diperbarui."})

    def admin_links(self):
        with db_connection() as connection:
            links = connection.execute(
                """
                SELECT collection_links.id, collection_links.label, collection_links.created_at,
                       collection_links.revoked_at, users.username,
                       (SELECT COUNT(*) FROM devices WHERE devices.link_id = collection_links.id) AS device_count
                FROM collection_links JOIN users ON users.id = collection_links.created_by
                ORDER BY collection_links.created_at DESC
                """
            ).fetchall()
        self.send_json(200, {"links": [dict(link) for link in links]})

    def create_link(self, user, payload):
        label = payload.get("label")
        if not isinstance(label, str) or not label.strip() or len(label.strip()) > 100:
            self.send_json(400, {"error": "Nama link wajib diisi (maksimal 100 karakter)."})
            return
        base = os.environ.get("APP_PUBLIC_URL", "").rstrip("/")
        if not base:
            scheme = "http"
            host = self.headers.get("Host", "")
            if TRUST_PROXY and self.headers.get("X-Forwarded-Proto", "").lower() == "https":
                scheme = "https"
            try:
                parsed_host = urlsplit(f"//{host}")
                parsed_host.port
            except ValueError:
                self.send_json(400, {"error": "Host aplikasi tidak valid. Atur APP_PUBLIC_URL."})
                return
            if not parsed_host.hostname or parsed_host.username or parsed_host.password:
                self.send_json(400, {"error": "Host aplikasi tidak valid. Atur APP_PUBLIC_URL."})
                return
            base = f"{scheme}://{host}"
        try:
            parsed_base = urlsplit(base)
            parsed_base.port
        except ValueError:
            self.send_json(500, {"error": "APP_PUBLIC_URL tidak valid."})
            return
        if (
            parsed_base.scheme not in ("http", "https")
            or not parsed_base.netloc
            or parsed_base.username
            or parsed_base.password
            or parsed_base.path not in ("", "/")
            or parsed_base.query
            or parsed_base.fragment
        ):
            self.send_json(500, {"error": "APP_PUBLIC_URL tidak valid."})
            return
        token = secrets.token_urlsafe(32)
        link_id = secrets.token_hex(12)
        try:
            with db_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO collection_links (id, token_hash, label, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (link_id, token_hash(token), label.strip(), user["id"], utc_now()),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Gagal menyimpan link. Coba lagi."})
            return
        self.send_json(
            201,
            {"link": {"id": link_id, "label": label.strip(), "url": f"{base}/collect/{token}"}},
        )

    def admin_devices(self):
        query = parse_qs(urlsplit(self.path).query)
        try:
            page = max(1, int(query.get("page", ["1"])[0]))
            per_page = min(100, max(1, int(query.get("per_page", ["50"])[0])))
        except ValueError:
            self.send_json(400, {"error": "Parameter halaman tidak valid."})
            return
        with db_connection() as connection:
            total = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            devices = connection.execute(
                """
                SELECT devices.*, collection_links.label AS link_label
                FROM devices JOIN collection_links ON collection_links.id = devices.link_id
                ORDER BY devices.collected_at DESC LIMIT ? OFFSET ?
                """,
                (per_page, (page - 1) * per_page),
            ).fetchall()
        results = []
        for device in devices:
            item = dict(device)
            item["local_ips"] = json.loads(item["local_ips"])
            item["mac_addresses"] = json.loads(item["mac_addresses"])
            item["tcp_ports"] = json.loads(item["tcp_ports"])
            item["udp_ports"] = json.loads(item["udp_ports"])
            item["details"] = json.loads(item["details"])
            results.append(item)
        self.send_json(
            200,
            {
                "devices": results,
                "meta": {"page": page, "per_page": per_page, "total": total, "total_pages": max(1, (total + per_page - 1) // per_page)},
            },
        )

    def download_collector(self, token):
        with db_connection() as connection:
            link = connection.execute(
                "SELECT id FROM collection_links WHERE token_hash = ? AND revoked_at IS NULL",
                (token_hash(token),),
            ).fetchone()
        if link is None:
            self.send_json(404, {"error": "Link tidak ditemukan atau sudah dicabut."})
            return

        public_base = os.environ.get("APP_PUBLIC_URL", "").rstrip("/")
        if not public_base:
            forwarded_proto = self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
            scheme = "https" if TRUST_PROXY and forwarded_proto == "https" else "http"
            host = self.headers.get("Host", "")
            try:
                parsed_host = urlsplit(f"//{host}")
                parsed_host.port
            except ValueError:
                self.send_json(400, {"error": "Host aplikasi tidak valid. Atur APP_PUBLIC_URL."})
                return
            if not parsed_host.hostname or parsed_host.username or parsed_host.password:
                self.send_json(400, {"error": "Host aplikasi tidak valid. Atur APP_PUBLIC_URL."})
                return
            public_base = f"{scheme}://{host}"
        try:
            parsed_base = urlsplit(public_base)
            parsed_base.port
        except ValueError:
            self.send_json(500, {"error": "APP_PUBLIC_URL tidak valid."})
            return
        if (
            parsed_base.scheme not in ("http", "https")
            or not parsed_base.netloc
            or parsed_base.username
            or parsed_base.password
            or parsed_base.path not in ("", "/")
            or parsed_base.query
            or parsed_base.fragment
        ):
            self.send_json(500, {"error": "APP_PUBLIC_URL tidak valid."})
            return

        collection_url = f"{public_base}/api/collect/{token}"
        extension = urlsplit(self.path).path.rsplit(".", 1)[-1].lower()
        if extension == "ps1":
            try:
                script = (STATIC / "collector.ps1").read_text(encoding="utf-8")
            except OSError:
                self.send_json(500, {"error": "Skrip pengumpul Windows tidak tersedia."})
                return
            body = script.replace(
                "__COLLECTION_URL__", collection_url.replace("'", "''")
            ).encode("utf-8-sig")
            filename = "me-device-collector.ps1"
            content_type = "text/plain; charset=utf-8"
        elif extension == "cmd":
            # The batch file passes this URL to PowerShell as a single-quoted literal.
            safe_netloc = re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", parsed_base.netloc)
            if safe_netloc is None:
                self.send_json(
                    500,
                    {"error": "Host APP_PUBLIC_URL berisi karakter yang tidak aman untuk file CMD."},
                )
                return
            try:
                script = (STATIC / "collector.cmd").read_text(encoding="utf-8")
            except OSError:
                self.send_json(500, {"error": "Peluncur pengumpul Windows tidak tersedia."})
                return
            body = script.replace("__COLLECTOR_URL__", f"{public_base}/collect/{token}/collector.ps1").encode("ascii")
            filename = "me-device-collector.cmd"
            content_type = "text/plain; charset=utf-8"
        else:
            self.send_json(404, {"error": "Format kolektor tidak tersedia."})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def collect_device(self, token, payload):
        if not re.fullmatch(r"[A-Za-z0-9_-]{30,100}", token):
            self.send_json(404, {"error": "Link pengumpulan tidak valid."})
            return
        with db_connection() as connection:
            link = connection.execute(
                "SELECT id FROM collection_links WHERE token_hash = ? AND revoked_at IS NULL",
                (token_hash(token),),
            ).fetchone()
        if link is None:
            self.send_json(404, {"error": "Link tidak ditemukan atau sudah dicabut."})
            return
        local_ips = []
        for address in payload.get("local_ips", [])[:20] if isinstance(payload.get("local_ips"), list) else []:
            parsed = valid_ip(address)
            if parsed and ipaddress.ip_address(parsed).is_private and parsed not in local_ips:
                local_ips.append(parsed)
        public_ip = valid_ip(payload.get("public_ip"))
        if public_ip and (ipaddress.ip_address(public_ip).is_private or ipaddress.ip_address(public_ip).is_loopback):
            public_ip = ""
        mac_addresses = []
        raw_mac_addresses = payload.get("mac_addresses")
        if isinstance(raw_mac_addresses, list):
            for entry in raw_mac_addresses[:30]:
                if not isinstance(entry, dict):
                    continue
                mac = re.sub(r"[^0-9A-Fa-f]", "", str(entry.get("mac") or ""))
                if len(mac) != 12:
                    continue
                formatted_mac = ":".join(mac[index:index + 2].upper() for index in range(0, 12, 2))
                adapter = str(entry.get("adapter") or "")[:100]
                if not any(item["mac"] == formatted_mac for item in mac_addresses):
                    mac_addresses.append({"adapter": adapter, "mac": formatted_mac})

        def valid_ports(value):
            if not isinstance(value, list):
                return []
            ports = set()
            for port in value[:4096]:
                try:
                    number = int(port)
                except (TypeError, ValueError):
                    continue
                if 1 <= number <= 65535:
                    ports.add(number)
            return sorted(ports)

        details = payload.get("details", {})
        if not isinstance(details, dict):
            details = {}
        clean_details = {
            key: (
                [str(item)[:250] for item in value[:20]]
                if isinstance(value, list)
                else json.dumps(value, ensure_ascii=False)[:2000]
                if isinstance(value, dict)
                else str(value)[:250]
            )
            for key, value in details.items()
            if key in {
                "user_agent", "language", "timezone", "screen", "cores",
                "memory", "touch", "connection", "scanned_at", "collector", "errors",
            }
            and isinstance(value, (str, int, float, list, dict))
        }
        device_name = payload.get("device_name", "")
        platform = payload.get("platform", "")
        browser = payload.get("browser", "")
        hostname = payload.get("hostname", "")
        windows_user = payload.get("windows_user", "")
        device_id = secrets.token_hex(16)
        try:
            with db_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO devices
                        (id, link_id, collected_at, device_name, platform, browser,
                         local_ips, public_ip, server_ip, hostname, windows_user,
                         mac_addresses, tcp_ports, udp_ports, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        link["id"],
                        utc_now(),
                        str(device_name)[:100],
                        str(platform)[:100],
                        str(browser)[:100],
                        json.dumps(local_ips),
                        public_ip,
                        self.client_ip(),
                        str(hostname)[:100],
                        str(windows_user)[:150],
                        json.dumps(mac_addresses),
                        json.dumps(valid_ports(payload.get("tcp_ports"))),
                        json.dumps(valid_ports(payload.get("udp_ports"))),
                        json.dumps(clean_details),
                    ),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Data tidak berhasil disimpan. Silakan coba lagi."})
            return
        self.send_json(201, {"message": "Data perangkat berhasil disimpan.", "id": device_id})


def main():
    initialize_db()
    address = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    print(f"Aplikasi berjalan pada http://{address}:{port}")
    ThreadingHTTPServer((address, port), AppHandler).serve_forever()


if __name__ == "__main__":
    main()
