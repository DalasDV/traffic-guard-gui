"""Persistent configuration, journal checkpoints and event queries."""

from contextlib import contextmanager
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import ipaddress
import json
from pathlib import Path
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password_hash TEXT NOT NULL,
    totp BLOB NOT NULL, last_step INTEGER NOT NULL DEFAULT -1, failures INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS admin_enrollment (
    id INTEGER PRIMARY KEY CHECK(id=1), token_hash TEXT NOT NULL, totp BLOB NOT NULL,
    expires_at INTEGER NOT NULL, failures INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, kind TEXT NOT NULL,
    username TEXT NOT NULL, secret BLOB NOT NULL, fingerprint TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, alias TEXT NOT NULL UNIQUE COLLATE NOCASE,
    address TEXT NOT NULL, port INTEGER NOT NULL, credential_id INTEGER REFERENCES credentials(id),
    credential_hint TEXT, mode TEXT NOT NULL, fingerprint TEXT NOT NULL, enabled INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0, cursor TEXT, cursor_ms INTEGER,
    checked_at INTEGER, success_at INTEGER, error TEXT, journal_gap INTEGER NOT NULL DEFAULT 0,
    UNIQUE(address, port)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cursor TEXT NOT NULL, stamp INTEGER NOT NULL, src TEXT NOT NULL, dst TEXT,
    family INTEGER NOT NULL, proto TEXT NOT NULL, sport INTEGER, dport INTEGER, iface TEXT,
    tcp_flags TEXT, packet_length INTEGER, ttl INTEGER, icmp_type INTEGER, icmp_code INTEGER,
    UNIQUE(host_id, cursor)
);
CREATE TABLE IF NOT EXISTS host_diagnostics (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL, report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_stamp ON events(stamp, id);
CREATE INDEX IF NOT EXISTS events_host_stamp ON events(host_id, stamp);
CREATE INDEX IF NOT EXISTS events_src_stamp ON events(src, stamp);
CREATE INDEX IF NOT EXISTS events_dport_stamp ON events(dport, stamp);
CREATE TABLE IF NOT EXISTS networks (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, ip TEXT NOT NULL,
    asn TEXT, netname TEXT, PRIMARY KEY(host_id, ip)
);
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK(id=1), poll_seconds INTEGER NOT NULL, retention_days INTEGER NOT NULL
);
INSERT OR IGNORE INTO config VALUES (1,30,30);
CREATE TABLE IF NOT EXISTS preferences (
    id INTEGER PRIMARY KEY CHECK(id=1), timezone TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, stamp INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL
);
"""

GROUP_FIELDS = {
    "host": "e.host_id",
    "src": "e.src",
    "dport": "e.dport",
    "proto": "e.proto",
    "family": "e.family",
    "asn": "n.asn",
    "netname": "n.netname",
    "hour": "(e.stamp / 3600000 * 3600000)",
    "day": "(e.stamp / 86400000 * 86400000)",
    "dst": "e.dst",
    "sport": "e.sport",
    "iface": "e.iface",
    "tcp_flags": "e.tcp_flags",
    "packet_length": "e.packet_length",
    "ttl": "e.ttl",
    "icmp_type": "e.icmp_type",
    "icmp_code": "e.icmp_code",
    "time": "e.stamp",
}
DEFAULT_GROUPS = ("src",)
JOINS = """FROM events e JOIN hosts h ON h.id=e.host_id
LEFT JOIN networks n ON n.host_id=e.host_id AND n.ip=e.src"""
EVENT_COLUMNS = (
    "cursor", "stamp", "src", "dst", "family", "proto", "sport", "dport", "iface",
    "tcp_flags", "packet_length", "ttl", "icmp_type", "icmp_code"
)
INSERT_EVENT = f"""INSERT INTO events (host_id,{','.join(EVENT_COLUMNS)})
VALUES ({','.join('?' for _ in range(len(EVENT_COLUMNS)+1))})
ON CONFLICT(host_id,cursor) DO NOTHING"""


def ts_ms():
    return time.time_ns() // 1_000_000


def contains(cidr, ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
    except ValueError:
        return False


class Store:
    def __init__(self, path):
        self.path = Path(path)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=8)
        db.row_factory = sqlite3.Row
        db.create_function("ip_in", 2, contains, deterministic=True)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def settings(self):
        with self.connect() as db:
            return dict(db.execute("""SELECT c.poll_seconds,c.retention_days,p.timezone FROM config c
                LEFT JOIN preferences p ON p.id=c.id WHERE c.id=1""").fetchone())

    def hosts(self):
        with self.connect() as db:
            rows = db.execute("""SELECT h.*, c.name AS credential_name,d.report AS diagnostics FROM hosts h
                LEFT JOIN credentials c ON c.id=h.credential_id
                LEFT JOIN host_diagnostics d ON d.host_id=h.id AND d.revision=h.revision
                ORDER BY h.alias COLLATE NOCASE""")
            return [dict(row) for row in rows]

    def entry(self, host_id):
        with self.connect() as db:
            row = db.execute("""SELECT h.*, c.kind,c.username,c.secret FROM hosts h
                LEFT JOIN credentials c ON c.id=h.credential_id WHERE h.id=?""", (host_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def audit(db, action, detail=""):
        db.execute("INSERT INTO audit(stamp,action,detail) VALUES (?,?,?)", (ts_ms(), action, detail))

    def collect(self, host, events, next_cursor, cursor_ms, metadata, warning, gap):
        with self.connect(write=True) as db:
            current = db.execute("SELECT revision,enabled FROM hosts WHERE id=?", (host["id"],)).fetchone()
            if not current or current["revision"] != host["revision"] or not current["enabled"]:
                return False
            db.executemany(INSERT_EVENT, (
                (host["id"], *(event[field] for field in EVENT_COLUMNS)) for event in events
            ))
            db.executemany("""INSERT INTO networks(host_id,ip,asn,netname) VALUES (?,?,?,?)
                ON CONFLICT(host_id,ip) DO UPDATE SET asn=COALESCE(excluded.asn,networks.asn),
                netname=COALESCE(excluded.netname,networks.netname)""",
                ((host["id"], ip, asn, netname) for ip, asn, netname in metadata))
            db.execute("""UPDATE hosts SET cursor=?,cursor_ms=?,checked_at=?,success_at=?,error=?,
                journal_gap=MAX(journal_gap,?) WHERE id=?""",
                (next_cursor, cursor_ms, ts_ms(), ts_ms(), warning, int(gap), host["id"]))
            return True

    def report_error(self, host, reason):
        with self.connect(write=True) as db:
            db.execute("UPDATE hosts SET checked_at=?,error=? WHERE id=? AND revision=?",
                       (ts_ms(), reason, host["id"], host["revision"]))

    def report_diagnostics(self, host, report):
        with self.connect(write=True) as db:
            db.execute("""INSERT INTO host_diagnostics(host_id,revision,report)
                SELECT id,revision,? FROM hosts WHERE id=? AND revision=?
                ON CONFLICT(host_id) DO UPDATE SET revision=excluded.revision,report=excluded.report""",
                       (json.dumps({**report, "checked_at": ts_ms()}), host["id"], host["revision"]))

    def prune(self, days):
        cutoff = ts_ms() - days * 86400000
        with self.connect(write=True) as db:
            db.execute("DELETE FROM events WHERE stamp<?", (cutoff,))
            db.execute("""DELETE FROM networks WHERE NOT EXISTS (
                SELECT 1 FROM events WHERE events.host_id=networks.host_id AND events.src=networks.ip)""")
            db.execute("DELETE FROM audit WHERE stamp<?", (ts_ms() - 90 * 86400000,))
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (int(time.time()),))


def as_int(value, minimum, maximum):
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError("Ожидается целое число.")
    result = int(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"Допустимый диапазон — {minimum}–{maximum}.")
    return result


def timezone_for(name):
    if not isinstance(name, str) or not name or len(name)>100:
        raise ValueError("Укажите часовой пояс.")
    try:
        return ZoneInfo(name)
    except (ValueError, ZoneInfoNotFoundError):
        raise ValueError("Неизвестный часовой пояс.") from None


def date_ms(value, zone=timezone.utc):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        aware = parsed.replace(tzinfo=zone)
        if aware.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) != parsed:
            raise ValueError("Это местное время пропущено при переводе часов.")
        parsed = aware
    return int(parsed.timestamp() * 1000)


def parse_filters(payload):
    now = ts_ms()
    zone = timezone_for(payload["timezone"]) if payload.get("timezone") else timezone.utc
    since = None if payload.get("all_time") is True else now - 86400000
    if payload.get("since"):
        since = date_ms(payload["since"],zone)
    end = date_ms(payload["until"],zone) if payload.get("until") else None
    if end is not None and since is not None and since >= end:
        raise ValueError("Начало периода должно быть раньше окончания.")
    clauses, params = ["1=1"], []
    if since is not None:
        clauses.append("e.stamp>=?")
        params.append(since)
    if end is not None:
        clauses.append("e.stamp<?")
        params.append(end)
    filters = payload.get("filters", [])
    if not isinstance(filters, list) or len(filters) > 40:
        raise ValueError("Допустимо до 40 фильтров.")
    includes = {}
    for item in filters:
        field = item["field"]
        if field not in GROUP_FIELDS or item["op"] not in ("in", "out"):
            raise ValueError("Неизвестный фильтр.")
        value = item["value"]
        if isinstance(value, str) and len(value) > 220:
            raise ValueError("Значение фильтра слишком длинное.")
        expression = GROUP_FIELDS[field]
        if value is None:
            condition, args = f"{expression} IS NULL", ()
        elif field in ("src", "dst"):
            if "/" in value:
                condition, args = f"ip_in(?,{expression})", (str(ipaddress.ip_network(value, strict=False)),)
            else:
                condition, args = f"{expression}=?", (str(ipaddress.ip_address(value)),)
        elif field in ("host", "sport", "dport", "family", "hour", "day", "packet_length", "ttl", "icmp_type", "icmp_code", "time"):
            limits = {"sport": (0,65535), "dport": (0,65535), "ttl": (0,255),
                      "packet_length": (0,2**32), "icmp_type": (0,255), "icmp_code": (0,255),
                      "family": (4,6), "host": (1,2**53), "time": (0,2**53),
                      "hour": (0,2**53), "day": (0,2**53)}
            condition, args = f"{expression}=?", (as_int(value, *limits[field]),)
        else:
            if not isinstance(value, str) or not value:
                raise ValueError("Введите значение фильтра.")
            condition, args = f"{expression}=? COLLATE NOCASE", (value,)
        if item["op"] == "in":
            includes.setdefault(field, []).append((condition, args))
        else:
            clauses.append(f"NOT COALESCE(({condition}),0)")
            params.extend(args)
    for alternatives in includes.values():
        clauses.append("(" + " OR ".join(condition for condition, _ in alternatives) + ")")
        for _, args in alternatives:
            params.extend(args)
    return clauses, params


def query_events(store, payload, detail=False):
    clauses, params = parse_filters(payload)
    page = as_int(payload.get("page", 1), 1, 100000)
    limit = 50
    groups = payload.get("groups", list(DEFAULT_GROUPS))
    if (not isinstance(groups, list) or len(groups)>len(GROUP_FIELDS)
            or any(field not in GROUP_FIELDS for field in groups)
            or len(set(groups)) != len(groups)):
        raise ValueError("Неизвестное поле группировки.")
    if detail:
        keys = payload.get("keys", {})
        if not isinstance(keys, dict) or set(keys) != set(groups):
            raise ValueError("Некорректные параметры раскрытия группы.")
        for field in groups:
            clauses.append(f"{GROUP_FIELDS[field]} IS ?")
            params.append(keys[field])
    where = " WHERE " + " AND ".join(clauses)
    sort = payload.get("sort")
    direction = payload.get("direction", "desc")
    if direction not in ("asc", "desc"):
        raise ValueError("Некорректное направление сортировки.")
    if detail or not groups:
        sql = """SELECT e.id,e.stamp,e.host_id,h.alias,e.src,e.dst,e.family,e.proto,e.sport,e.dport,
                 e.iface,e.tcp_flags,e.packet_length,e.ttl,e.icmp_type,e.icmp_code,n.asn,n.netname """
        sortable = {**GROUP_FIELDS, "host": "h.alias COLLATE NOCASE"}
        if sort is not None and sort not in sortable:
            raise ValueError("Поле недоступно для сортировки.")
        order = f"{sortable[sort]} {direction}, " if sort else ""
        sql = sql + JOINS + where + f" ORDER BY {order}e.stamp DESC,e.id DESC"
    else:
        selects = ",".join(f'{GROUP_FIELDS[field]} AS "{field}"' for field in groups)
        if "asn" not in groups:
            selects += (",CASE WHEN COUNT(n.asn)=COUNT(*) AND COUNT(DISTINCT n.asn)=1 "
                        "THEN MIN(n.asn) END AS asn,COUNT(DISTINCT n.asn)>1 AS asn_mixed")
        if "netname" not in groups:
            selects += (",CASE WHEN COUNT(n.netname)=COUNT(*) AND COUNT(DISTINCT n.netname)=1 "
                        "THEN MIN(n.netname) END AS netname,COUNT(DISTINCT n.netname)>1 AS netname_mixed")
        grouping = ",".join(GROUP_FIELDS[field] for field in groups)
        sortable = {field: f'"{field}"' for field in (*groups, "netname", "count", "first_seen", "last_seen")}
        if "host" in groups:
            sortable["host"] = "MIN(h.alias) COLLATE NOCASE"
        if sort is not None and sort not in sortable:
            raise ValueError("Поле недоступно для сортировки.")
        order = f"{sortable[sort]} {direction}, " if sort else ""
        sql = (f"SELECT {selects},COUNT(*) AS count,MIN(e.stamp) AS first_seen,MAX(e.stamp) AS last_seen "
               f"{JOINS}{where} GROUP BY {grouping} ORDER BY {order}count DESC,last_seen DESC,{grouping}")
    with store.connect() as db:
        rows = [dict(row) for row in db.execute(
            sql + " LIMIT ? OFFSET ?", (*params,limit+1,(page-1)*limit)
        )]
        total = None if detail else db.execute("SELECT COUNT(*) " + JOINS + where, params).fetchone()[0]
    return {"rows":rows[:limit],"more":len(rows)>limit,"page":page,"total":total}
