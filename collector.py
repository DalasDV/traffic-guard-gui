"""Read only TrafficGuard data over SSH."""

import base64
import csv
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import io
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shlex
import socket
import threading
import time

import paramiko

from storage import ts_ms

LOG = logging.getLogger(__name__)
JOURNAL = "/usr/bin/journalctl"
AGGREGATE = "/var/log/iptables-scanners-aggregate.csv"
READER = "/usr/local/sbin/traffic-guard-reader"
PREFIX = r"ANTISCAN-v[46]: "
CURSOR = re.compile(r"[a-zA-Z0-9_=;:+/-]{1,512}\Z")
MAX_OUTPUT = 4 * 1024 * 1024
PAGE_SIZE = 1000


class CollectError(ValueError):
    pass


def ssh_fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def load_key(value, passphrase):
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(value), password=passphrase or None)
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    raise CollectError("Не удалось прочитать SSH-ключ. Проверьте формат или парольную фразу.")


def allowed_ip(address, extra):
    ip = ipaddress.ip_address(address)
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        return False
    return ip.is_global or any(ip in network for network in extra)


def dial(address, port, extra):
    # Connect to the exact address that was checked, including for DNS names.
    try:
        candidates = socket.getaddrinfo(address, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise CollectError("DNS: не удалось разрешить адрес хоста.") from exc
    allowed = [entry for entry in candidates if allowed_ip(entry[4][0], extra)]
    if not allowed:
        raise CollectError("Адрес SSH запрещён политикой соединений панели.")
    deadline = time.monotonic() + 15
    for family, kind, proto, _, endpoint in allowed[:6]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(remaining)
            sock.connect(endpoint)
            return sock
        except OSError:
            sock.close()
    raise CollectError("TCP: не удалось подключиться к SSH-порту. Лимит 15 с.")


@contextmanager
def transport_for(host, secret, extra):
    with dial(host["address"], host["port"], extra) as sock:
        with paramiko.Transport(sock) as transport:
            transport.banner_timeout = 20
            transport.auth_timeout = 20
            try:
                transport.start_client(timeout=20)
                if not transport.initial_kex_done:
                    raise CollectError("SSH: не завершился обмен ключами за 20 с.")
            except (paramiko.SSHException, OSError, EOFError) as exc:
                raise CollectError("SSH: сбой при установлении сессии. Лимит 20 с.") from exc
            try:
                if host["kind"] == "key":
                    transport.auth_publickey(host["username"], load_key(secret["value"], secret.get("passphrase")))
                else:
                    transport.auth_password(host["username"], secret["value"], fallback=False)
            except (paramiko.SSHException, OSError, EOFError) as exc:
                reason = ("истёк таймаут 20 с" if "timeout" in str(exc).lower()
                          else "сервер не принял учётные данные или оборвал соединение")
                raise CollectError(f"SSH-аутентификация: {reason}.") from exc
            if not transport.is_authenticated():
                raise CollectError("SSH не принял учётные данные.")
            yield transport


def command(transport, args, max_lines=None):
    deadline = time.monotonic() + 30
    output, errors = bytearray(), bytearray()
    lines = 0
    try:
        channel = transport.open_session(timeout=15)
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise CollectError("SSH-канал: не удалось открыть канал команды. Лимит 15 с.") from exc
    with channel:
        channel.settimeout(15)
        expired = threading.Event()

        def abort_request():
            expired.set()
            channel.close()

        timer = threading.Timer(max(0, deadline-time.monotonic()), abort_request)
        timer.daemon = True
        timer.start()
        try:
            channel.exec_command(shlex.join(args))
        except (paramiko.SSHException, OSError, EOFError) as exc:
            reason = "превышен лимит 30 с" if expired.is_set() else "сервер отклонил запуск"
            raise CollectError(f"Запуск команды: {reason}.") from exc
        finally:
            timer.cancel()
        while time.monotonic() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(65536)
                output.extend(chunk)
                if max_lines is not None:
                    lines += chunk.count(b"\n")
                    if lines >= max_lines:
                        batch = b"\n".join(output.split(b"\n", max_lines)[:max_lines])
                        return 0, batch.decode("utf-8", errors="replace"), ""
            if channel.recv_stderr_ready():
                errors.extend(channel.recv_stderr(4096))
            if len(output) > MAX_OUTPUT or len(errors) > 8192:
                raise CollectError("Ответ SSH превышает лимит размера.")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                return channel.recv_exit_status(), output.decode("utf-8", errors="replace"), errors.decode("utf-8", errors="replace")
            time.sleep(.015)
    raise CollectError("Чтение результата команды: превышен лимит 30 с.")


def journal_args(host, cursor, since, probe=False):
    if cursor and not CURSOR.fullmatch(cursor):
        raise CollectError("Некорректная позиция журнала.")
    since = str(max(0, int(since)))
    if host["mode"] == "sudo":
        return ["/usr/bin/sudo", "-n", READER, "probe" if probe else "journal", cursor or "-", since]
    args = ["/usr/bin/env", "LC_ALL=C", JOURNAL, "_TRANSPORT=kernel",
            f"--grep={PREFIX}", "--no-pager", "--output=json", "--output-fields=MESSAGE"]
    if probe:
        return [*args, "--lines=1"]
    return [*args, f"--cursor={cursor}" if cursor else f"--since=@{since}"]


def journal_rows(text):
    for line in text.splitlines():
        try:
            row = json.loads(line)
            cursor = row["__CURSOR"]
            if not CURSOR.fullmatch(cursor):
                continue
            stamp = int(row["__REALTIME_TIMESTAMP"]) // 1000
            if not 0 < stamp < 253402300800000:
                continue
            yield cursor, stamp, row.get("MESSAGE")
        except (ValueError, TypeError, KeyError):
            continue


def parse_event(cursor, stamp, message):
    if not isinstance(message, str) or not re.search(PREFIX, message):
        return None
    # The first LEN is the IP packet length; UDP adds a second LEN.
    fields = {}
    for name, value in re.findall(r"(?:^|\s)([A-Z]+)=([^\s]+)", message):
        fields.setdefault(name, value)
    try:
        source = ipaddress.ip_address(fields["SRC"])
    except (ValueError, KeyError):
        return None
    try:
        dest = str(ipaddress.ip_address(fields["DST"]))
    except (ValueError, KeyError):
        dest = None

    def number(key, upper):
        value = fields.get(key, "")
        return int(value) if value.isascii() and value.isdecimal() and len(value) <= 10 and int(value) <= upper else None

    proto = fields.get("PROTO", "OTHER").upper()[:20]
    words = set(message.split())
    flags = " ".join(flag for flag in ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR") if flag in words)
    return dict(cursor=cursor, stamp=stamp, src=str(source), dst=dest,
                family=source.version, proto=proto, sport=number("SPT", 65535), dport=number("DPT", 65535),
                iface=fields.get("IN", "")[:64] or None, tcp_flags=flags or None,
                packet_length=number("LEN", 2**32-1), ttl=number("HOPLIMIT" if source.version == 6 else "TTL", 255),
                icmp_type=number("TYPE", 255) if proto.startswith("ICMP") else None,
                icmp_code=number("CODE", 255) if proto.startswith("ICMP") else None)


def parse_metadata(text):
    reader = csv.DictReader(io.StringIO(text), delimiter="|")
    if reader.fieldnames != ["IP_TYPE", "IP_ADDRESS", "ASN", "NETNAME", "COUNT", "LAST_SEEN"]:
        raise CollectError("У CSV TrafficGuard неожиданный формат.")
    result = []
    for row in reader:
        try:
            ip = str(ipaddress.ip_address(row["IP_ADDRESS"]))
        except (ValueError, TypeError):
            continue
        asn = row["ASN"] or ""
        netname = row["NETNAME"] or ""
        result.append((ip, asn if re.fullmatch(r"AS[0-9]{1,12}", asn) else None,
                       netname[:180] if netname and netname.upper() != "UNKNOWN" else None))
    return result


class Collector:
    def __init__(self, store, decrypt):
        self.store = store
        self.decrypt = decrypt
        self.extra = tuple(ipaddress.ip_network(part.strip()) for part in
                           os.environ.get("PANEL_SSH_CIDRS", "").split(",") if part.strip())
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="traffic-guard")
        self.lock = threading.Lock()
        self.active = set()
        self.due = {}
        self.last_prune = 0

    def enqueue(self, host_id, probe=False):
        with self.lock:
            if host_id in self.active or len(self.active) >= 8:
                return False
            self.active.add(host_id)
            self.pool.submit(self.run, host_id, probe)
            return True

    def tick(self):
        now = time.monotonic()
        settings = self.store.settings()
        hosts = self.store.hosts()
        ids = {host["id"] for host in hosts}
        with self.lock:
            for host_id in list(self.due):
                if host_id not in ids:
                    self.due.pop(host_id)
        for host in hosts:
            with self.lock:
                due = self.due.get(host["id"], 0)
            if host["enabled"] and host["credential_id"] is not None and now >= due:
                self.enqueue(host["id"])
        if not self.last_prune or now - self.last_prune > 300:
            self.store.prune(settings["retention_days"])
            self.last_prune = now

    def loop(self):
        while True:
            try:
                self.tick()
            except Exception:
                LOG.exception("Ошибка планировщика.")
            time.sleep(2)

    def run(self, host_id, probe=False):
        started = time.monotonic()
        delay = 30
        host = None
        try:
            delay = self.store.settings()["poll_seconds"]
            host = self.store.entry(host_id)
            if not host or not host["credential_id"] or (not probe and not host["enabled"]):
                return
            with transport_for(host, self.decrypt(host["secret"]), self.extra) as transport:
                if probe:
                    report = self.diagnose(host, transport)
                    self.store.report_diagnostics(host, {**report,"elapsed_ms":round((time.monotonic()-started)*1000)})
                    return
                delay = self.fetch(host, transport, delay)
        except (CollectError, paramiko.AuthenticationException, paramiko.SSHException, OSError) as exc:
            if isinstance(exc, CollectError):
                reason = str(exc)
            elif isinstance(exc, paramiko.AuthenticationException):
                reason = "SSH не принял учётные данные."
            else:
                reason = "SSH-соединение прервалось или сервер недоступен."
            LOG.info("Сбор host_id=%s: %s", host_id, reason)
            if host:
                if probe:
                    self.store.report_diagnostics(host, {"ssh_error": reason,"elapsed_ms":round((time.monotonic()-started)*1000)})
                else:
                    self.store.report_error(host, reason)
        except Exception:
            LOG.error("Внутренняя ошибка сборщика host_id=%s", host_id)
            if host:
                if probe:
                    self.store.report_diagnostics(host, {"ssh_error": "Внутренняя ошибка проверки."})
                else:
                    self.store.report_error(host, "Внутренняя ошибка сборщика.")
        finally:
            with self.lock:
                if not probe:
                    self.due[host_id] = time.monotonic() + delay
                self.active.discard(host_id)

    @staticmethod
    def diagnose(host, transport):
        sudo = ["/usr/bin/sudo", "-n", READER] if host["mode"] == "sudo" else []
        report = {"installed": None, "logging": {"v4": None, "v6": None},
                  "journal": "unavailable", "csv": "unavailable"}
        if sudo:
            args = [*sudo, "diagnose"]
        else:
            reader = Path(__file__).with_name("traffic-guard-reader").read_text()
            args = ["/usr/bin/python3", "-I", "-c", reader, "diagnose"]
        try:
            code, data, _ = command(transport, args)
            if code == 0:
                evidence = json.loads(data)
                report["installed"] = evidence.get("installed")
                for family in report["logging"]:
                    report["logging"][family] = evidence["logging"].get(family)
            else:
                report["rules_error"] = "Не удалось получить состояние правил через выбранный режим доступа."
        except (CollectError, paramiko.SSHException, OSError) as exc:
            report["rules_error"] = str(exc) if isinstance(exc, CollectError) else "SSH: сбой канала проверки правил."
        except (AttributeError, KeyError, TypeError, json.JSONDecodeError):
            report["rules_error"] = "Неожиданный ответ проверки правил."
        try:
            rows = Collector.read_journal(transport, host, None, 0, probe=True)
            report["journal"] = "events" if rows else "empty"
        except (CollectError, paramiko.SSHException, OSError) as exc:
            report["journal_error"] = str(exc) if isinstance(exc, CollectError) else "SSH: сбой канала чтения журнала."
        try:
            code, data, _ = command(transport, [*sudo, "csv"] if sudo else ["/usr/bin/cat", AGGREGATE])
            if code == 0:
                parse_metadata(data)
                report["csv"] = "readable"
        except (CollectError, paramiko.SSHException, OSError) as exc:
            report["csv_error"] = str(exc) if isinstance(exc, CollectError) else "SSH: сбой канала чтения CSV."
        return report

    @staticmethod
    def read_journal(transport, host, cursor, since, probe=False):
        code, data, stderr = command(transport, journal_args(host, cursor, since, probe),
                                     max_lines=None if probe else PAGE_SIZE + 1)
        error = stderr.lower()
        if any(word in error for word in ("permission denied", "insufficient permissions", "currently not seeing", "a password is required",
                                           "not allowed", "not in the sudoers", "a terminal is required", "not found")):
            raise CollectError("У SSH-пользователя нет доступа к журналу или программе чтения.")
        if code not in (0, 1) or (code == 1 and stderr.strip()):
            if cursor and "cursor" in error:
                return None
            raise CollectError("Сервер не смог прочитать journalctl TrafficGuard.")
        return list(journal_rows(data))

    def fetch(self, host, transport, delay):
        cursor, stamp = host["cursor"], host["cursor_ms"]
        since = (stamp // 1000 if stamp else (ts_ms() - 86400000) // 1000)
        rows = self.read_journal(transport, host, cursor, since)
        gap = bool(cursor and (not rows or rows[0][0] != cursor))
        if gap:
            rows = self.read_journal(transport, host, None, since)
        if cursor and rows and rows[0][0] == cursor:
            rows = rows[1:]
        events = [event for row in rows if (event := parse_event(*row)) is not None]
        if rows:
            cursor, stamp, _ = rows[-1]

        read = ["/usr/bin/sudo", "-n", READER, "csv"] if host["mode"] == "sudo" else ["/usr/bin/cat", AGGREGATE]
        warning = None
        try:
            code, data, _ = command(transport, read)
            metadata = parse_metadata(data) if code == 0 else []
            if code:
                warning = "Журнал прочитан. CSV для ASN и NETNAME пока недоступен."
        except CollectError as exc:
            metadata, warning = [], str(exc)
        self.store.collect(host, events, cursor, stamp, metadata, warning, gap)
        return 2 if len(rows) >= PAGE_SIZE else delay
