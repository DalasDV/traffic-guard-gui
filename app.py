"""Single-admin TrafficGuard dashboard and its local setup commands."""

import argparse
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import urlsplit
from urllib.request import urlopen

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, g, jsonify, request, send_file, send_from_directory
import pyotp
import qrcode
from qrcode.image.svg import SvgPathFillImage
from waitress import serve
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from collector import Collector, load_key, ssh_fingerprint
from storage import Store, as_int, query_events, timezone_for

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PANEL_DATA", "/data")) / "panel.sqlite3"
KEY_PATH = Path(os.environ.get("PANEL_KEY", "/keys/master.key"))
COOKIE = "trafficguard_session"
ENROLL_COOKIE = "trafficguard_enrollment"
ENROLL_SECONDS = 600
BOOTSTRAP_LOGIN = "guard"
BOOTSTRAP_PASSWORD = "guard"
SESSION_SECONDS = 8 * 3600
MAX_CONFIG = 500
PASS_MIN = 8
USERNAME = re.compile(r"[A-Za-z0-9_.@-]{1,80}\Z")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def secrets_box(path):
    return Fernet(path.read_bytes().strip())


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def clean_text(value, limit, required=True):
    if not isinstance(value, str):
        raise ValueError("Введите текст.")
    value = value.strip()
    if len(value) > limit or (required and not value) or any(ord(char) < 32 for char in value):
        raise ValueError(f"Ожидается текст длиной до {limit} символов без переносов.")
    return value


def ssh_address(value):
    value = clean_text(value, 253).strip("[]").rstrip(".")
    if "%" in value:
        raise ValueError("Зона IPv6 в адресе SSH не поддерживается.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    candidate = value.encode("idna").decode().lower()
    if not candidate or not all(LABEL.fullmatch(item) for item in candidate.split(".")):
        raise ValueError("Введите имя хоста, IPv4 или IPv6. Порт указывается отдельно.")
    return candidate


def require_mode(value):
    if value not in ("direct", "sudo"):
        raise ValueError("Выберите способ доступа к журналу.")
    return value


def host_input(data):
    return dict(alias=clean_text(data.get("alias"), 80), address=ssh_address(data.get("address")),
                port=as_int(data.get("port", 22), 1, 65535), mode=require_mode(data.get("mode", "direct")))


def api_error(message, status):
    return jsonify(error=message), status


def totp_step(seed, code, now, last_step=-1):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None
    totp = pyotp.TOTP(seed)
    current = now // 30
    return next((slot for slot in (current, current - 1, current + 1)
                 if slot > last_step and hmac.compare_digest(totp.generate_otp(slot), code)), None)


def new_password(data):
    password = data.get("new_password")
    if not isinstance(password, str) or not PASS_MIN <= len(password) <= 512:
        raise ValueError(f"Новый пароль должен содержать от {PASS_MIN} до 512 символов.")
    if password != data.get("confirm_password"):
        raise ValueError("Пароли не совпадают.")
    return password


def build_app(store, box, origin):
    parsed = urlsplit(origin)
    if (not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username
            or (parsed.scheme != "https" and
                not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}))):
        raise ValueError("PANEL_ORIGIN должен быть HTTPS-адресом или локальным адресом HTTP.")
    secure = parsed.scheme == "https"
    app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")
    app.config.update(MAX_CONTENT_LENGTH=512 * 1024, TRUSTED_HOSTS=[parsed.hostname])
    collector = Collector(store, lambda value: json.loads(box.decrypt(value)))
    app.extensions["collector"] = collector
    with store.connect(write=True) as db:
        admin = db.execute("SELECT username,password_hash FROM admin WHERE id=1").fetchone()
        if (admin and admin["username"] == BOOTSTRAP_LOGIN
                and check_password_hash(admin["password_hash"], BOOTSTRAP_PASSWORD)):
            db.execute("DELETE FROM sessions")

    @app.before_request
    def authorize():
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("Origin") != origin or request.headers.get("X-Panel-Request") != "1":
                return api_error("Источник запроса не совпадает с адресом панели.", 403)
        if not request.path.startswith("/api/") or request.path in (
            "/api/auth/status", "/api/login", "/api/enroll", "/api/enroll/qr", "/api/enroll/password", "/api/enroll/login"
        ):
            return None
        value = request.cookies.get(COOKIE, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            return api_error("Войдите в панель.", 401)
        g.session = token_hash(value)
        with store.connect() as db:
            session = db.execute("""SELECT 1 FROM sessions
                JOIN admin ON admin.id=1 AND length(admin.totp)>0 WHERE token_hash=? AND expires_at>?""",
                                 (g.session, int(time.time()))).fetchone()
        if not session:
            return api_error("Войдите в панель.", 401)
        return None

    @app.after_request
    def response_headers(response):
        response.headers.update({
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        if secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return api_error("Запрос не выполнен.", exc.code)

    @app.errorhandler(ValueError)
    def invalid(exc):
        return api_error(str(exc), 400)

    @app.errorhandler(TypeError)
    @app.errorhandler(KeyError)
    @app.errorhandler(OverflowError)
    def malformed(_exc):
        return api_error("Проверьте значения полей.", 400)

    @app.errorhandler(sqlite3.IntegrityError)
    def conflict(_exc):
        return api_error("Запись уже существует или используется другим хостом.", 409)

    def body():
        data = request.get_json()
        if not isinstance(data, dict):
            raise ValueError("Ожидается объект JSON.")
        return data

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/health")
    def health():
        with store.connect() as db:
            db.execute("SELECT id FROM config").fetchone()
        return {"status":"ok"}

    def new_session(db, now):
        db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
        old = request.cookies.get(COOKIE)
        if old:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(old),))
        value = secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions VALUES (?,?)", (token_hash(value), now + SESSION_SECONDS))
        store.audit(db, "login")
        response = jsonify(ok=True)
        response.set_cookie(COOKIE, value, httponly=True, secure=secure, samesite="Strict",
                            max_age=SESSION_SECONDS, path="/")
        return response

    def enrollment(db, now):
        token = request.cookies.get(ENROLL_COOKIE, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        return db.execute("""SELECT * FROM admin_enrollment WHERE id=1
            AND token_hash=? AND expires_at>?""",
                          (token_hash(token), now)).fetchone()

    def require_setup(db, now, password_first=False, login_step=False):
        token = secrets.token_urlsafe(32)
        seed = b"login" if login_step else b"" if password_first else box.encrypt(pyotp.random_base32().encode())
        db.execute("""INSERT OR REPLACE INTO admin_enrollment(id,token_hash,totp,expires_at)
            VALUES (1,?,?,?)""", (token_hash(token), seed, now + ENROLL_SECONDS))
        response = jsonify(password_change_required=True) if password_first else jsonify(enrollment_required=True)
        if login_step:
            response = jsonify(totp_required=True)
        response.set_cookie(ENROLL_COOKIE, token, httponly=True, secure=secure, samesite="Strict",
                            max_age=ENROLL_SECONDS, path="/api/enroll")
        return response

    def finish_setup(db, now):
        db.execute("DELETE FROM admin_enrollment WHERE id=1")
        response = new_session(db, now)
        response.delete_cookie(ENROLL_COOKIE, httponly=True, secure=secure, samesite="Strict", path="/api/enroll")
        return response

    @app.get("/api/auth/status")
    def auth_status():
        with store.connect() as db:
            admin = db.execute("SELECT totp FROM admin WHERE id=1").fetchone()
            configured = bool(admin and admin["totp"])
        return {"configured": configured, "enrollment_available": not configured and (admin is not None or not secure)}

    @app.post("/api/login")
    def login():
        data = body()
        name = clean_text(data.get("username"), 80)
        password = data.get("password")
        if not isinstance(password, str) or not 1 <= len(password) <= 512:
            return api_error("Введите пароль.", 400)
        now = int(time.time())
        with store.connect(write=True) as db:
            admin = db.execute("SELECT * FROM admin WHERE id=1").fetchone()
            if admin is None:
                if secure:
                    return api_error("Для первой настройки откройте панель по локальному адресу.", 403)
                if name != BOOTSTRAP_LOGIN or password != BOOTSTRAP_PASSWORD:
                    return api_error("Проверьте имя пользователя и пароль.", 401)
                return require_setup(db, now, password_first=True)
            if admin["locked_until"] > now:
                return api_error("Слишком много попыток. Повторите через несколько минут.", 429)
            if not (check_password_hash(admin["password_hash"], password)
                    and hmac.compare_digest(name.encode(), admin["username"].encode())):
                return failed_login(db, admin, now, "Проверьте имя пользователя и пароль.")
            if not admin["totp"]:
                return require_setup(db, now)
            return require_setup(db, now, login_step=True)

    def failed_login(db, admin, now, message):
        failures = admin["failures"] + 1
        db.execute("UPDATE admin SET failures=?,locked_until=? WHERE id=1",
                   (0 if failures >= 8 else failures, now+300 if failures >= 8 else 0))
        return api_error(message, 401)

    @app.post("/api/enroll/login")
    def verify_login():
        code = body().get("totp")
        now = int(time.time())
        with store.connect(write=True) as db:
            pending = enrollment(db, now)
            admin = db.execute("SELECT * FROM admin WHERE id=1").fetchone()
            if not pending or pending["totp"] != b"login" or not admin or not admin["totp"]:
                return api_error("Войдите снова, чтобы получить новый запрос кода.", 410)
            if admin["locked_until"] > now:
                return api_error("Слишком много попыток. Повторите через несколько минут.", 429)
            step = totp_step(box.decrypt(admin["totp"]).decode(), code, now, admin["last_step"])
            if step is None:
                return failed_login(db, admin, now, "Код не совпал. Используйте свежий код.")
            db.execute("UPDATE admin SET last_step=?,failures=0,locked_until=0 WHERE id=1", (step,))
            if admin["username"] == BOOTSTRAP_LOGIN and check_password_hash(admin["password_hash"], BOOTSTRAP_PASSWORD):
                db.execute("DELETE FROM sessions")
                return require_setup(db, now, password_first=True)
            return finish_setup(db, now)

    @app.post("/api/enroll/password")
    def setup_password():
        data = body()
        now = int(time.time())
        with store.connect(write=True) as db:
            pending = enrollment(db, now)
            admin = db.execute("SELECT totp FROM admin WHERE id=1").fetchone()
            if not pending or pending["totp"] or (admin and not admin["totp"]) or (secure and not admin):
                return api_error("Настройка завершилась или истекла. Войдите снова.", 410)
            password_hash = generate_password_hash(new_password(data))
            if admin:
                db.execute("UPDATE admin SET password_hash=? WHERE id=1", (password_hash,))
                db.execute("DELETE FROM sessions")
                store.audit(db, "admin.password_changed")
                return finish_setup(db, now)
            # The password is durable even if the browser closes before TOTP is confirmed.
            db.execute("INSERT INTO admin(id,username,password_hash,totp) VALUES (1,?,?,?)",
                       (BOOTSTRAP_LOGIN, password_hash, b""))
            return require_setup(db, now, password_first=False)

    def totp_enrollment(db, now):
        pending = enrollment(db, now)
        admin = db.execute("SELECT totp,username FROM admin WHERE id=1").fetchone()
        if pending and pending["totp"] not in (b"", b"login") and admin and not admin["totp"]:
            return pending, admin["username"]
        return None

    @app.get("/api/enroll/qr")
    def enrollment_qr():
        with store.connect() as db:
            setup = totp_enrollment(db, int(time.time()))
        if not setup:
            return api_error("Начните настройку заново.", 410)
        pending, username = setup
        totp = pyotp.TOTP(box.decrypt(pending["totp"]).decode())
        uri = totp.provisioning_uri(name=username, issuer_name="TrafficGuard")
        image = qrcode.make(uri, image_factory=SvgPathFillImage)
        return Response(image.to_string(encoding="utf-8"), mimetype="image/svg+xml")

    @app.post("/api/enroll")
    def confirm_enrollment():
        code = body().get("totp")
        now = int(time.time())
        with store.connect(write=True) as db:
            setup = totp_enrollment(db, now)
            if not setup:
                return api_error("Настройка завершилась или истекла. Войдите снова.", 410)
            pending, _ = setup
            step = totp_step(box.decrypt(pending["totp"]).decode(), code, now)
            if step is None:
                if pending["failures"] >= 7:
                    db.execute("DELETE FROM admin_enrollment WHERE id=1")
                    return api_error("Слишком много попыток. Войдите снова и отсканируйте новый QR-код.", 410)
                db.execute("UPDATE admin_enrollment SET failures=failures+1 WHERE id=1")
                return api_error("Код не совпал. Введите текущий код из приложения.", 401)
            db.execute("UPDATE admin SET totp=?,last_step=?,failures=0,locked_until=0 WHERE id=1", (pending["totp"], step))
            store.audit(db, "admin.created")
            return finish_setup(db, now)

    @app.post("/api/account/password")
    def change_password():
        data = body()
        password = new_password(data)
        current = data.get("current_password")
        if not isinstance(current, str) or not 1 <= len(current) <= 512:
            raise ValueError("Введите текущий пароль.")
        now = int(time.time())
        with store.connect(write=True) as db:
            if not db.execute("SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?", (g.session, now)).fetchone():
                return api_error("Войдите в панель.", 401)
            admin = db.execute("SELECT password_hash FROM admin WHERE id=1").fetchone()
            if not check_password_hash(admin["password_hash"], current):
                return api_error("Текущий пароль неверен.", 400)
            if password == current:
                return api_error("Новый пароль должен отличаться от текущего.", 400)
            db.execute("UPDATE admin SET password_hash=? WHERE id=1", (generate_password_hash(password),))
            db.execute("DELETE FROM sessions")
            store.audit(db, "admin.password_changed")
            return finish_setup(db, now)

    @app.post("/api/logout")
    def logout():
        with store.connect(write=True) as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (g.session,))
            store.audit(db, "logout")
        response = jsonify(ok=True)
        response.delete_cookie(COOKIE,httponly=True,secure=secure,samesite="Strict",path="/")
        return response

    @app.get("/api/state")
    def state():
        hosts = store.hosts()
        with collector.lock:
            for host in hosts:
                host["collecting"] = host["id"] in collector.active
                host["diagnostics"] = json.loads(host["diagnostics"]) if host["diagnostics"] else None
                for key in ("revision","cursor","cursor_ms","fingerprint"):
                    host.pop(key)
        with store.connect() as db:
            credentials = [dict(row) for row in db.execute(
                "SELECT id,name,kind,username,fingerprint FROM credentials ORDER BY name COLLATE NOCASE"
            )]
        return {"hosts":hosts,"credentials":credentials,"settings":store.settings()}

    @app.get("/api/reader")
    def download_reader():
        return send_file(ROOT / "traffic-guard-reader", as_attachment=True)

    @app.get("/api/audit")
    def audit():
        with store.connect() as db:
            return {"rows":[dict(row) for row in db.execute(
                "SELECT stamp,action,detail FROM audit ORDER BY id DESC LIMIT 100"
            )]}

    @app.post("/api/credentials")
    @app.put("/api/credentials/<int:credential_id>")
    def save_credential(credential_id=None):
        data = body()
        name = clean_text(data.get("name"),80)
        username = clean_text(data.get("username"),80)
        kind = data.get("kind")
        if not USERNAME.fullmatch(username) or kind not in ("password","key"):
            raise ValueError("Проверьте SSH-пользователя и тип учётных данных.")
        with store.connect(write=True) as db:
            old = db.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
            if credential_id and not old:
                return api_error("Запись не найдена.",404)
            value = data.get("value","")
            if not isinstance(value,str) or len(value)>32768:
                raise ValueError("Слишком длинное значение учётных данных.")
            if value:
                passphrase = data.get("passphrase","")
                if not isinstance(passphrase,str) or len(passphrase)>1024:
                    raise ValueError("Слишком длинная парольная фраза.")
                fingerprint = ssh_fingerprint(load_key(value,passphrase)) if kind=="key" else None
                secret = box.encrypt(json.dumps({"value":value,"passphrase":passphrase if kind=="key" else ""}).encode())
            elif old and old["kind"] == kind:
                secret,fingerprint = old["secret"],old["fingerprint"]
            else:
                raise ValueError("Введите приватный ключ или пароль.")
            if old:
                db.execute("""UPDATE credentials SET name=?,username=?,kind=?,secret=?,fingerprint=? WHERE id=?""",
                           (name,username,kind,secret,fingerprint,credential_id))
                db.execute("UPDATE hosts SET revision=revision+1 WHERE credential_id=?",(credential_id,))
            else:
                if db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] >= MAX_CONFIG:
                    raise ValueError("Достигнут лимит учётных данных.")
                credential_id = db.execute("""INSERT INTO credentials(name,username,kind,secret,fingerprint)
                    VALUES (?,?,?,?,?)""",(name,username,kind,secret,fingerprint)).lastrowid
            store.audit(db, "credential.updated" if old else "credential.created", f"#{credential_id} {name}")
        return {"id":credential_id}

    @app.delete("/api/credentials/<int:credential_id>")
    def delete_credential(credential_id):
        with store.connect(write=True) as db:
            if db.execute("DELETE FROM credentials WHERE id=?", (credential_id,)).rowcount:
                store.audit(db,"credential.deleted",f"#{credential_id}")
        return {"ok":True}

    @app.post("/api/hosts")
    @app.put("/api/hosts/<int:host_id>")
    def save_host(host_id=None):
        data = body()
        item = host_input(data)
        cred = None if data.get("credential_id") is None else as_int(data["credential_id"],1,2**53)
        enabled = data.get("enabled",False)
        if not isinstance(enabled,bool):
            raise ValueError("Проверьте состояние опроса.")
        if enabled and not cred:
            raise ValueError("Для опроса нужны учётные данные.")
        fields = (*item.values(),cred,int(enabled))
        with store.connect(write=True) as db:
            if host_id is not None:
                old = db.execute("SELECT * FROM hosts WHERE id=?",(host_id,)).fetchone()
                if not old:
                    return api_error("Хост не найден.",404)
                endpoint_changed = any(old[key]!=item[key] for key in ("address","port"))
                if endpoint_changed and db.execute("SELECT 1 FROM events WHERE host_id=? LIMIT 1", (host_id,)).fetchone():
                    return api_error("У хоста есть история. Добавьте новый хост для другого адреса или порта.",409)
                reset = ", cursor=NULL,cursor_ms=NULL,success_at=NULL,checked_at=NULL,error=NULL,journal_gap=0" if endpoint_changed else ""
                db.execute("""UPDATE hosts SET alias=?,address=?,port=?,mode=?,credential_id=?,
                    enabled=?,revision=revision+1,credential_hint=CASE WHEN ? IS NULL THEN credential_hint ELSE NULL END"""
                           + reset + " WHERE id=?", (*fields,cred,host_id))
                store.audit(db,"host.updated",f"#{host_id} {item['alias']}")
            else:
                if db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] >= MAX_CONFIG:
                    raise ValueError("Достигнут лимит хостов.")
                host_id = db.execute("""INSERT INTO hosts(alias,address,port,mode,credential_id,enabled,fingerprint)
                    VALUES (?,?,?,?,?,?,'')""", fields).lastrowid
                store.audit(db,"host.created",f"#{host_id} {item['alias']}")
        return {"id":host_id}

    @app.post("/api/hosts/bulk")
    def bulk_hosts():
        data = body()
        action = data.get("action")
        ids = data.get("ids")
        if action not in ("delete","enable","disable","credential"):
            raise ValueError("Выберите действие.")
        if not isinstance(ids,list) or not 1 <= len(ids) <= MAX_CONFIG:
            raise ValueError("Выберите хосты.")
        ids = list(dict.fromkeys(as_int(host_id,1,2**53) for host_id in ids))
        targets = ",".join("?" for _ in ids)
        with store.connect(write=True) as db:
            hosts = db.execute(f"SELECT alias,credential_id FROM hosts WHERE id IN ({targets})",ids).fetchall()
            if len(hosts) != len(ids):
                return api_error("Некоторые хосты уже удалены. Обновите список.",409)
            if action == "delete":
                db.execute(f"DELETE FROM hosts WHERE id IN ({targets})",ids)
            elif action == "credential":
                credential = as_int(data.get("credential_id"),1,2**53)
                if not db.execute("SELECT 1 FROM credentials WHERE id=?",(credential,)).fetchone():
                    return api_error("Учётные данные больше недоступны.",409)
                db.execute(f"""UPDATE hosts SET credential_id=?,credential_hint=NULL,revision=revision+1
                    WHERE id IN ({targets}) AND credential_id IS NOT ?""",(credential,*ids,credential))
            else:
                enabled = int(action == "enable")
                missing = [host["alias"] for host in hosts if not host["credential_id"]]
                if enabled and missing:
                    raise ValueError("Сначала назначьте учётные данные: " + ", ".join(missing))
                db.execute(f"""UPDATE hosts SET enabled=?,revision=revision+1
                    WHERE id IN ({targets}) AND enabled<>?""",(enabled,*ids,enabled))
            store.audit(db,"hosts.bulk",f"{action} · {len(ids)}")
        with collector.lock:
            for host_id in ids:
                collector.due.pop(host_id,None)
        return {"count":len(ids)}

    @app.delete("/api/hosts/<int:host_id>")
    def delete_host(host_id):
        with store.connect(write=True) as db:
            if db.execute("DELETE FROM hosts WHERE id=?", (host_id,)).rowcount:
                store.audit(db,"host.deleted",f"#{host_id}")
        return {"ok":True}

    @app.post("/api/hosts/<int:host_id>/check")
    def check_host(host_id):
        host = store.entry(host_id)
        if not host:
            return api_error("Хост не найден.",404)
        if not host["credential_id"]:
            raise ValueError("Добавьте учётные данные.")
        return {"queued":collector.enqueue(host_id,probe=True)}

    @app.post("/api/collect")
    def collect_hosts():
        count = sum(collector.enqueue(host["id"]) for host in store.hosts()
                    if host["enabled"] and host["credential_id"])
        return {"queued":count}

    @app.get("/api/hosts/export")
    def export_hosts():
        records = [{**{key:host[key] for key in ("alias","address","port","mode")},
                    "credential_name":host["credential_name"] or host["credential_hint"]}
                   for host in store.hosts()]
        response = jsonify(version=1,hosts=records)
        response.headers["Content-Disposition"] = 'attachment; filename="trafficguard-hosts.json"'
        with store.connect(write=True) as db:
            store.audit(db,"hosts.exported",str(len(records)))
        return response

    @app.post("/api/hosts/import")
    def import_hosts():
        data = body()
        bundle = data.get("bundle")
        if not isinstance(bundle,dict) or bundle.get("version")!=1 or not isinstance(bundle.get("hosts"),list):
            raise ValueError("Выберите JSON-файл экспорта хостов версии 1.")
        if len(bundle["hosts"])>MAX_CONFIG:
            raise ValueError("В файле слишком много хостов.")
        commit = data.get("confirm") is True
        choices = data.get("credentials", {})
        if not isinstance(choices,dict):
            raise ValueError("Проверьте привязки учётных данных.")
        with store.connect(write=commit) as db:
            known_hosts = db.execute("SELECT alias,address,port FROM hosts").fetchall()
            known_credentials = {row["name"].casefold():row["id"] for row in db.execute("SELECT id,name FROM credentials")}
            aliases = {row["alias"].casefold() for row in known_hosts}
            endpoints = {(row["address"],row["port"]) for row in known_hosts}
            result = []
            for index, raw in enumerate(bundle["hosts"]):
                if not isinstance(raw,dict):
                    raise ValueError("Некорректная запись хоста.")
                record = host_input(raw)
                name = clean_text(raw.get("credential_name") or "",80,required=False)
                key = record["alias"].casefold()
                endpoint = (record["address"],record["port"])
                status = "conflict" if key in aliases or endpoint in endpoints else "ready"
                credential = known_credentials.get(name.casefold())
                if status == "ready" and str(index) in choices:
                    choice = choices[str(index)]
                    credential = as_int(choice,1,2**53) if choice is not None else None
                    if credential is not None and credential not in known_credentials.values():
                        raise ValueError(f"Учётные данные для хоста «{record['alias']}» больше недоступны.")
                if status == "ready":
                    aliases.add(key)
                    endpoints.add(endpoint)
                    if len(endpoints)>MAX_CONFIG:
                        raise ValueError("Достигнут лимит хостов.")
                    if commit:
                        db.execute("""INSERT INTO hosts(alias,address,port,mode,credential_id,credential_hint,enabled,fingerprint)
                            VALUES (?,?,?,?,?,?,0,'')""",(*record.values(),credential,None if credential else name or None))
                result.append({**record,"status":status,"credential_name":name,"credential_found":bool(credential),
                               "index":index,"credential_id":credential})
            if commit:
                store.audit(db,"hosts.imported",str(sum(item["status"]=="ready" for item in result)))
        return {"rows":result}

    @app.put("/api/settings")
    def settings():
        data = body()
        poll = as_int(data.get("poll_seconds"),10,3600)
        days = as_int(data.get("retention_days"),1,365)
        with store.connect(write=True) as db:
            db.execute("UPDATE config SET poll_seconds=?,retention_days=? WHERE id=1",(poll,days))
            store.audit(db,"settings.updated")
        with collector.lock:
            collector.due.clear()
            collector.last_prune = 0
        return {"ok":True}

    @app.put("/api/settings/timezone")
    def set_timezone():
        zone = timezone_for(body().get("timezone"))
        with store.connect(write=True) as db:
            db.execute("INSERT OR REPLACE INTO preferences VALUES (1,?)", (zone.key,))
        return {"ok":True}

    @app.post("/api/events")
    @app.post("/api/events/detail",defaults={"detail":True})
    def events(detail=False):
        return query_events(store,body(),detail)

    return app


def init():
    if not KEY_PATH.exists():
        if DB_PATH.exists():
            raise SystemExit("Файл ключа отсутствует. Восстановите том ключей из резервной копии.")
        with KEY_PATH.open("xb") as file:
            file.write(Fernet.generate_key() + b"\n")
    box = secrets_box(KEY_PATH)
    store = Store(DB_PATH)
    check_admin(store, box)
    return store, box


def check_admin(store, box):
    with store.connect() as db:
        admin = db.execute("SELECT totp FROM admin WHERE id=1").fetchone()
        if admin and admin["totp"]:
            try:
                box.decrypt(admin["totp"])
            except InvalidToken:
                raise SystemExit("Ключ шифрования не соответствует базе.")


def reset_admin(store):
    password = getpass.getpass("Новый пароль администратора: ")
    confirmation = getpass.getpass("Повторите пароль: ")
    if not PASS_MIN <= len(password) <= 512 or confirmation != password:
        raise SystemExit(f"Требуется совпадающий пароль от {PASS_MIN} до 512 символов.")
    password_hash = generate_password_hash(password)
    with store.connect(write=True) as db:
        db.execute("""INSERT INTO admin(id,username,password_hash,totp) VALUES (1,?,?,?)
            ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash,
            totp=excluded.totp,last_step=-1,failures=0,locked_until=0""",
                   (BOOTSTRAP_LOGIN, password_hash, b""))
        db.execute("DELETE FROM sessions")
        db.execute("DELETE FROM admin_enrollment")
        store.audit(db, "admin.reset")
        username = db.execute("SELECT username FROM admin WHERE id=1").fetchone()[0]
    print(f"Войдите как {username} с новым паролем и настройте TOTP по QR-коду.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("command",choices=("init","reset-admin","serve","health"))
    args = parser.parse_args()
    if args.command in ("init","reset-admin"):
        store, box = init()
        if args.command == "reset-admin":
            reset_admin(store)
        return
    origin = os.environ.get("PANEL_ORIGIN","http://127.0.0.1:4090").rstrip("/")
    if args.command=="health":
        from urllib.request import Request
        with urlopen(Request("http://127.0.0.1:4090/health",headers={"Host":urlsplit(origin).netloc}),timeout=3):
            return
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    box = secrets_box(KEY_PATH)
    store = Store(DB_PATH)
    check_admin(store, box)
    app = build_app(store,box,origin)
    threading.Thread(target=app.extensions["collector"].loop,daemon=True).start()
    serve(app,host="0.0.0.0",port=4090,threads=6,max_request_body_size=512*1024,channel_timeout=20,
          expose_tracebacks=False)


if __name__ == "__main__":
    main()
