"""Local checks for the TrafficGuard panel; no connections to real nodes."""

import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
import paramiko
import pyotp
import qrcode
from werkzeug.security import check_password_hash, generate_password_hash

from app import COOKIE, ENROLL_COOKIE, build_app, reset_admin, ssh_address, token_hash
from collector import CollectError, Collector, allowed_ip, command, parse_event, parse_metadata, transport_for
from storage import Store, ts_ms

ORIGIN = "http://127.0.0.1:4090"
HEADERS = {"Origin": ORIGIN, "X-Panel-Request": "1"}
NAME = "tester"
PASSWORD = "test-only secure credentials"
NEW_PASSWORD = "a different test password"
CHANGE = {"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD}
FINGERPRINT = "SHA256:" + "A"*43


class EnrollmentTests(unittest.TestCase):
    credentials = {"username": "guard", "password": "guard"}

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = Store(Path(directory.name) / "events.sqlite3")
        self.box = Fernet(Fernet.generate_key())
        self.client = self.create_client(ORIGIN)

    def create_client(self, origin):
        app = build_app(self.store, self.box, origin)
        app.testing = True
        self.addCleanup(app.extensions["collector"].pool.shutdown)
        return app.test_client()

    def call(self, method, path, data=None, client=None, origin=ORIGIN):
        return (client or self.client).open("/api/" + path, method=method, json=data,
                                           headers={**HEADERS, "Origin": origin}, base_url=origin)

    def pending_totp(self):
        with self.store.connect() as db:
            pending = db.execute("SELECT totp FROM admin_enrollment").fetchone()
        return pyotp.TOTP(self.box.decrypt(pending["totp"]).decode())

    def test_first_login_requires_qr_confirmation_and_starts_a_session(self):
        self.assertEqual(self.call("GET", "auth/status").json,
                         {"configured": False, "enrollment_available": True})
        self.assertEqual(self.call("GET", "enroll/qr").status_code, 410)
        self.assertEqual(self.call("POST", "login", {**self.credentials, "password": "wrong"}).status_code, 401)
        login = self.call("POST", "login", self.credentials)
        self.assertEqual(login.json, {"password_change_required": True})
        self.assertIsNotNone(self.client.get_cookie(ENROLL_COOKIE, domain="127.0.0.1", path="/api/enroll"))
        self.assertIsNone(self.client.get_cookie(COOKIE, domain="127.0.0.1"))
        self.assertEqual(self.call("GET", "state").status_code, 401)
        self.assertEqual(self.call("GET", "enroll/qr").status_code, 410)
        self.assertEqual(self.call("POST", "enroll", {"totp": "123456"}).status_code, 410)
        self.assertEqual(self.call("POST", "enroll/password", {**CHANGE, "confirm_password": "other"}).status_code, 400)
        self.assertEqual(self.call("POST", "enroll/password", CHANGE).json, {"enrollment_required": True})
        self.assertEqual(self.call("POST", "enroll/password", CHANGE).status_code, 410)
        with patch("app.qrcode.make", wraps=qrcode.make) as make_qr:
            qr = self.call("GET", "enroll/qr")
        self.assertEqual(qr.mimetype, "image/svg+xml")
        self.assertIn(b"<svg", qr.data)
        uri = make_qr.call_args.args[0]
        self.assertEqual(pyotp.parse_uri(uri).secret, self.pending_totp().secret)
        self.assertEqual(qr.headers["Cache-Control"], "no-store")
        self.assertEqual(self.call("POST", "enroll", {"totp": "invalid"}).status_code, 401)
        self.assertEqual(self.call("GET", "hosts/export").status_code, 401)
        code = self.pending_totp().now()
        self.assertEqual(self.call("POST", "enroll", {"totp": code}).status_code, 200)
        self.assertIsNone(self.client.get_cookie(ENROLL_COOKIE, domain="127.0.0.1", path="/api/enroll"))
        self.assertEqual(self.call("GET", "state").status_code, 200)
        self.assertEqual(self.call("GET", "auth/status").json,
                         {"configured": True, "enrollment_available": False})
        self.assertEqual(self.call("POST", "logout", {}).status_code, 200)
        updated = {**self.credentials, "password": NEW_PASSWORD}
        self.assertEqual(self.call("POST", "enroll/login", {"totp": code}).status_code, 410)
        self.assertEqual(self.call("POST", "login", updated).json, {"totp_required": True})
        self.assertEqual(self.call("GET", "state").status_code, 401)
        self.assertEqual(self.call("POST", "enroll/login", {"totp": code}).status_code, 401)

    def test_interrupted_enrollment_can_restart_and_invalidates_the_old_qr(self):
        other = self.client.application.test_client()
        self.call("POST", "login", self.credentials)
        self.call("POST", "enroll/password", CHANGE)
        self.assertEqual(self.call("POST", "login", self.credentials, client=other).status_code, 401)
        updated = {**self.credentials, "password": NEW_PASSWORD}
        self.assertEqual(self.call("POST", "login", updated, client=other).json, {"enrollment_required": True})
        self.assertEqual(self.call("GET", "enroll/qr").status_code, 410)
        code = self.pending_totp().now()
        self.assertEqual(self.call("POST", "enroll", {"totp": code}).status_code, 410)
        self.assertEqual(self.call("POST", "enroll", {"totp": code}, client=other).status_code, 200)
        self.assertEqual(self.call("POST", "enroll", {"totp": code}, client=other).status_code, 410)

    def test_bootstrap_is_blocked_on_public_origin(self):
        public = "https://trafficguard.example"
        client = self.create_client(public)
        self.assertEqual(self.call("GET", "auth/status", client=client, origin=public).json,
                         {"configured": False, "enrollment_available": False})
        self.assertEqual(self.call("POST", "login", self.credentials, client=client, origin=public).status_code, 403)

    def test_old_default_admin_changes_password_and_keeps_totp(self):
        public = "https://trafficguard.example"
        totp = pyotp.TOTP(pyotp.random_base32())
        encrypted = self.box.encrypt(totp.secret.encode())
        old_cookie = "a" * 43
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO admin(id,username,password_hash,totp) VALUES (1,'guard',?,?)",
                       (generate_password_hash("guard"), encrypted))
            db.execute("INSERT INTO sessions VALUES (?, ?)", (token_hash(old_cookie), 9999999999))
        client = self.create_client(public)
        client.set_cookie(COOKIE, old_cookie, domain="trafficguard.example")
        self.assertEqual(self.call("GET", "state", client=client, origin=public).status_code, 401)
        login = self.call("POST", "login", self.credentials, client=client, origin=public)
        self.assertEqual(login.json, {"totp_required": True})
        self.assertIn("Secure", login.headers["Set-Cookie"])
        result = self.call("POST", "enroll/login", {"totp": totp.now()}, client=client, origin=public)
        self.assertEqual(result.json, {"password_change_required": True})
        self.assertEqual(self.call("GET", "state", client=client, origin=public).status_code, 401)
        self.assertEqual(self.call("POST", "enroll/password", CHANGE, client=client, origin=public).json, {"ok": True})
        self.assertEqual(self.call("GET", "state", client=client, origin=public).status_code, 200)
        with self.store.connect() as db:
            admin = db.execute("SELECT * FROM admin").fetchone()
        self.assertEqual(admin["totp"], encrypted)
        self.assertTrue(check_password_hash(admin["password_hash"], NEW_PASSWORD))


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(Path(self.directory.name) / "events.sqlite3")
        self.box = Fernet(Fernet.generate_key())
        self.otp = pyotp.TOTP(pyotp.random_base32())
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO admin(id,username,password_hash,totp) VALUES (1,?,?,?)",
                       (NAME,generate_password_hash(PASSWORD),self.box.encrypt(self.otp.secret.encode())))
        self.app = build_app(self.store,self.box,ORIGIN)
        self.app.testing=True
        self.client=self.app.test_client()
        self.addCleanup(self.app.extensions["collector"].pool.shutdown)

    def call(self, method, path, data=None, headers=HEADERS, client=None):
        return (client or self.client).open("/api/"+path, method=method, json=data,
                                          headers=headers, base_url=ORIGIN)

    def login(self, client=None):
        response = self.call("POST","login",dict(username=NAME,password=PASSWORD),client=client)
        self.assertEqual(response.json, {"totp_required": True})
        return self.call("POST","enroll/login",{"totp":self.otp.now()},client=client)

    def create_host(self):
        self.assertEqual(self.login().status_code,200)
        secret = "test-only SSH secret"
        result = self.call("POST","credentials",dict(name="Lab",username="reader",kind="password",value=secret))
        self.assertEqual(result.status_code,200,result.json)
        cred = result.json["id"]
        result = self.call("POST","hosts",dict(alias="JP-1",address="Node.Example.com.",credential_id=cred,
                                               mode="sudo",enabled=True))
        self.assertEqual(result.status_code,200,result.json)
        return result.json["id"], cred, secret

    def test_login_requires_totp_origin_and_blocks_replays(self):
        self.assertEqual(self.call("GET","state").status_code,401)
        self.assertEqual(self.call("POST","login",headers={"Origin":"http://bad.invalid"}).status_code,403)
        response=self.login()
        self.assertEqual(response.status_code,200,response.json)
        self.assertIn("HttpOnly",response.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict",response.headers["Set-Cookie"])
        self.assertEqual(self.login(self.app.test_client()).status_code,401)
        self.assertEqual(self.call("GET","state").status_code,200)
        self.assertEqual(self.call("POST","logout",{}).status_code,200)
        self.assertIsNone(self.client.get_cookie(COOKIE,domain="127.0.0.1"))
        self.assertEqual(self.call("GET","state").status_code,401)

    def test_https_cookies_and_login_limit(self):
        https = "https://panel.example.com"
        app = build_app(self.store,self.box,https)
        self.addCleanup(app.extensions["collector"].pool.shutdown)
        sample = app.test_client()
        auth = dict(username=NAME,password=PASSWORD)
        headers=dict(Origin=https,**{"X-Panel-Request":"1"})
        self.assertEqual(sample.post("/api/login",base_url=https,headers=headers,json=auth).json, {"totp_required":True})
        result=sample.post("/api/enroll/login",base_url=https,headers=headers,json={"totp":self.otp.now()})
        self.assertEqual(result.status_code,200)
        self.assertIn("Secure",result.headers["Set-Cookie"])
        with self.store.connect(write=True) as db:
            db.execute("UPDATE admin SET failures=7")
        auth["password"]="incorrect"
        self.assertEqual(sample.post("/api/login",base_url=https,headers=headers,json=auth).status_code,401)
        self.assertEqual(sample.post("/api/login",base_url=https,headers=headers,json=auth).status_code,429)

    def test_ssh_secrets_and_export_import(self):
        host,cred,secret=self.create_host()
        with self.store.connect() as db:
            encrypted=db.execute("SELECT secret FROM credentials").fetchone()["secret"]
            self.assertNotIn(secret.encode(),encrypted)
            self.assertEqual(json.loads(self.box.decrypt(encrypted))["value"],secret)
        state=self.call("GET","state")
        self.assertNotIn(secret,state.get_data(as_text=True))
        export=self.call("GET","hosts/export").json
        self.assertEqual(export["hosts"][0]["address"],"node.example.com")
        self.assertEqual(export["hosts"][0]["credential_name"],"Lab")
        self.assertNotIn("fingerprint", export["hosts"][0])
        self.assertNotIn(secret,json.dumps(export))
        incoming=dict(alias="IPv6",address="[2001:db8::1]",port=222,mode="direct",credential_name="Missing",
                      fingerprint=FINGERPRINT)
        bundle={"version":1,"hosts":[export["hosts"][0],incoming]}
        result=self.call("POST","hosts/import",{"bundle":bundle})
        self.assertEqual([row["status"] for row in result.json["rows"]],["conflict","ready"])
        self.assertEqual(len(self.store.hosts()),1)
        self.assertEqual(self.call("POST","hosts/import",{"bundle":bundle,"confirm":True}).status_code,200)
        saved=next(row for row in self.store.hosts() if row["id"]!=host)
        self.assertEqual((saved["address"],saved["credential_hint"],saved["enabled"]),("2001:db8::1","Missing",0))
        self.assertEqual(self.call("DELETE",f"credentials/{cred}").status_code,409)

    def test_password_change_keeps_credentials_and_revokes_other_sessions(self):
        host, cred, _ = self.create_host()
        stamp = ts_ms()
        event = parse_event("old-cursor", stamp, "ANTISCAN-v4: IN=eth0 SRC=203.0.113.42 PROTO=TCP DPT=443")
        self.store.collect(self.store.entry(host), [event], "old-cursor", stamp, [], None, False)
        other = self.app.test_client()
        other_cookie = "b" * 43
        other.set_cookie(COOKIE, other_cookie, domain="127.0.0.1")
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO sessions VALUES (?, ?)", (token_hash(other_cookie), 9999999999))
            db.execute("UPDATE hosts SET fingerprint=? WHERE id=?", (FINGERPRINT, host))
            previous = db.execute("SELECT secret FROM credentials WHERE id=?", (cred,)).fetchone()["secret"]
        payload = {**CHANGE, "current_password": PASSWORD}
        self.assertEqual(self.call("POST", "account/password", payload, client=self.app.test_client()).status_code, 401)
        self.assertEqual(self.call("POST", "account/password", {**payload, "current_password": "wrong"}).status_code, 400)
        self.assertEqual(self.call("POST", "account/password", payload).status_code, 200)
        self.assertEqual(self.call("GET", "state", client=other).status_code, 401)
        state = self.call("GET", "state")
        self.assertEqual(state.json["hosts"][0]["id"], host)
        self.assertNotIn("fingerprint", state.json["hosts"][0])
        self.assertEqual(self.store.entry(host)["cursor"], "old-cursor")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT secret FROM credentials WHERE id=?", (cred,)).fetchone()["secret"], previous)
            self.assertEqual(db.execute("SELECT host_id,dport FROM events").fetchone()[:], (host, 443))
            admin = db.execute("SELECT password_hash,totp FROM admin").fetchone()
        self.assertEqual(self.box.decrypt(admin["totp"]).decode(), self.otp.secret)
        self.assertTrue(check_password_hash(admin["password_hash"], NEW_PASSWORD))

    def test_cli_reset_preserves_username_and_starts_qr_enrollment(self):
        host, _, _ = self.create_host()
        with patch("app.getpass.getpass", side_effect=[NEW_PASSWORD, NEW_PASSWORD]), patch("builtins.print"):
            reset_admin(self.store)
        self.assertEqual(self.call("GET","state").status_code,401)
        self.assertEqual(self.call("POST","login",{"username":NAME,"password":PASSWORD}).status_code,401)
        self.assertEqual(self.call("POST","login",{"username":NAME,"password":NEW_PASSWORD}).json,
                         {"enrollment_required":True})
        self.assertEqual(self.call("GET","enroll/qr").mimetype,"image/svg+xml")
        with self.store.connect() as db:
            encrypted = db.execute("SELECT totp FROM admin_enrollment").fetchone()[0]
        otp = pyotp.TOTP(self.box.decrypt(encrypted).decode())
        self.assertEqual(self.call("POST","enroll",{"totp":otp.now()}).status_code,200)
        self.assertEqual(self.call("GET","state").json["hosts"][0]["id"],host)

    def test_import_override_and_timezone_aware_event_sorting(self):
        host, credential, _ = self.create_host()
        bundle = {"version":1,"hosts":[{"alias":"import","address":"example.net","credential_name":"Unknown"}]}
        self.assertEqual(self.call("POST","hosts/import",{"bundle":bundle,"confirm":True,
                         "credentials":{"0":credential}}).json["rows"][0]["credential_id"], credential)
        self.assertEqual(self.call("PUT","settings/timezone",{"timezone":"Asia/Ho_Chi_Minh"}).status_code,200)
        self.assertEqual(self.call("GET","state").json["settings"]["timezone"],"Asia/Ho_Chi_Minh")
        stamp = 1767225600000  # 2026-01-01 00:00 UTC
        events = [parse_event(f"s={i}",stamp+i,message) for i,message in enumerate((
            "ANTISCAN-v4: IN=eth0 SRC=203.0.113.42 PROTO=TCP DPT=443",
            "ANTISCAN-v4: IN=eth0 SRC=203.0.113.43 PROTO=TCP DPT=80",
        ))]
        self.store.collect(self.store.entry(host),events,"s=1",stamp,[],None,False)
        all_rows = self.call("POST","events",{"all_time":True,"sort":"src","direction":"desc"}).json["rows"]
        self.assertEqual([row["src"] for row in all_rows],["203.0.113.43","203.0.113.42"])
        window = self.call("POST","events",{"since":"2026-01-01T07:00","until":"2026-01-01T07:01",
                                           "timezone":"Asia/Ho_Chi_Minh"}).json
        self.assertEqual(window["total"],2)
        self.assertEqual(self.call("POST","events",{"sort":"unknown"}).status_code,400)

    def test_grouping_filters_details_late_asn_and_duplicate_cursor(self):
        host_id,_,_=self.create_host()
        host=self.store.entry(host_id)
        stamp=ts_ms()-5000
        base="ANTISCAN-v4: IN=eth0 SRC=203.0.113.42 DST=192.0.2.1 LEN=60 TTL=61 PROTO=TCP SPT=1200 DPT="
        batch=[parse_event(f"s={i}",stamp+i,base+("443" if i<2 else "80")+" SYN") for i in range(3)]
        self.store.collect(host,batch,"s=2",stamp+2,[],None,False)
        self.store.collect(host,batch,"s=2",stamp+2,[("203.0.113.42","AS64500","TEST")],None,False)
        query=dict(groups=["host","src","dport"],filters=[
            dict(field="src",op="in",value="203.0.113.0/24"),
            dict(field="asn",op="in",value="AS64500"),dict(field="dport",op="out",value=80)])
        result=self.call("POST","events",query)
        self.assertEqual(result.status_code,200,result.json)
        row=result.json["rows"][0]
        self.assertEqual(result.json["total"],2)
        self.assertEqual((row["host"],row["dport"],row["count"]),(host_id,443,2))
        self.assertEqual((row["asn"],row["asn_mixed"]),("AS64500",0))
        detail=self.call("POST","events/detail",{**query,"keys":{field:row[field] for field in query["groups"]}})
        self.assertEqual([packet["stamp"] for packet in detail.json["rows"]],[stamp+1,stamp])
        self.assertEqual(detail.json["rows"][0]["tcp_flags"],"SYN")
        other = parse_event("s=other", stamp, base.replace("203.0.113.42", "203.0.113.43")+"443")
        self.store.collect(host,[other],"s=other",stamp,[("203.0.113.43","AS64501","OTHER")],None,False)
        combined=self.call("POST","events",{"groups":["host","dport"]}).json["rows"][0]
        self.assertEqual((combined["count"],combined["asn"],combined["asn_mixed"]),(3,None,1))
        grouped_asn=self.call("POST","events",{"groups":["asn"]}).json["rows"]
        self.assertEqual({row["asn"] for row in grouped_asn},{"AS64500","AS64501"})

    def test_old_collection_cannot_commit_after_host_or_credential_edit(self):
        host_id,cred,_=self.create_host()
        prior=self.store.entry(host_id)
        self.store.report_diagnostics(prior, {"installed":True})
        self.assertTrue(self.call("GET","state").json["hosts"][0]["diagnostics"]["installed"])
        self.assertEqual(self.call("PUT",f"credentials/{cred}",dict(name="Lab",kind="password",username="newuser")).status_code,200)
        self.assertFalse(self.store.collect(prior,[],"s=1",ts_ms(),[],None,False))
        self.store.report_diagnostics(prior, {"installed":True})
        self.assertIsNone(self.call("GET","state").json["hosts"][0]["diagnostics"])
        self.assertIsNone(self.store.entry(host_id)["cursor"])

    def test_reader_download_requires_login(self):
        self.assertEqual(self.call("GET","reader").status_code,401)
        self.assertEqual(self.login().status_code,200)
        with self.call("GET","reader") as result:
            self.assertIn("attachment",result.headers["Content-Disposition"])
            self.assertIn(b"def diagnose",result.get_data())

    def test_bulk_hosts_assign_toggle_and_delete_selected_hosts(self):
        first, credential, _ = self.create_host()
        created = self.call("POST","hosts",{"alias":"Second","address":"second.example.net"})
        second = created.json["id"]
        ids = [first,second]
        def bulk(action, **fields):
            return self.call("POST","hosts/bulk",{"action":action,"ids":ids,**fields})
        self.assertEqual(bulk("enable").status_code,400)
        self.assertEqual(bulk("credential",credential_id=credential).status_code,200)
        self.assertEqual(bulk("enable").status_code,200)
        self.assertTrue(all(host["enabled"] for host in self.store.hosts()))
        stamp = ts_ms()
        event = parse_event("s=bulk",stamp,"ANTISCAN-v4: IN=eth0 SRC=203.0.113.42 PROTO=TCP DPT=443")
        self.store.collect(self.store.entry(first),[event],"s=bulk",stamp,[],None,False)
        self.assertEqual(bulk("disable").status_code,200)
        self.assertTrue(all(not host["enabled"] for host in self.store.hosts()))
        self.assertEqual(self.call("POST","events",{"groups":[]}).json["rows"][0]["stamp"],stamp)
        self.assertEqual(self.call("POST","hosts/bulk",{"action":"delete","ids":[second]}).status_code,200)
        self.assertEqual([host["id"] for host in self.store.hosts()],[first])


class CollectorTests(unittest.TestCase):
    def test_unanswered_ssh_command_reports_the_request_timeout(self):
        transport = paramiko.Transport
        with patch.object(transport, "open_session") as open_session, patch("collector.threading.Timer") as timer:
            channel = open_session.return_value
            channel.exec_command.side_effect = paramiko.SSHException("Channel closed")
            timer.return_value.start.side_effect = lambda: timer.call_args.args[1]()
            with self.assertRaisesRegex(CollectError,"Запуск команды: превышен лимит 30 с"):
                command(transport, ["journalctl"])
            channel.close.assert_called_once()

    def test_diagnostics_reports_empty_journal_independently_of_csv(self):
        results = [(0,'{"installed":true,"logging":{"v4":true,"v6":null}}',''),
                   (1,'',''),(1,'','No such file or directory')]
        with patch("collector.command", side_effect=results) as command:
            result = Collector.diagnose({"mode":"sudo"}, object())
        self.assertEqual(result, {"installed":True,"logging":{"v4":True,"v6":None},
                                  "journal":"empty","csv":"unavailable"})
        self.assertEqual([call.args[1][3] for call in command.call_args_list],
                         ["diagnose","probe","csv"])

    def test_metadata_and_journal_fields(self):
        row=parse_event("s=1",1,"ANTISCAN-v6: IN=ens3 SRC=2001:0db8::1 DST=2001:db8::2 LEN=60 HOPLIMIT=57 PROTO=UDP SPT=123 DPT=443 LEN=20")
        self.assertEqual((row["src"],row["family"],row["packet_length"],row["ttl"],row["dport"]),("2001:db8::1",6,60,57,443))
        csv="IP_TYPE|IP_ADDRESS|ASN|NETNAME|COUNT|LAST_SEEN\nv6|2001:0db8::1|AS64500|SAMPLE|4|today\n"
        self.assertEqual(parse_metadata(csv),[("2001:db8::1","AS64500","SAMPLE")])

    def test_dns_and_destination_allowlist(self):
        self.assertEqual(ssh_address("Example.COM."),"example.com")
        self.assertEqual(ssh_address("[2001:db8::1]"),"2001:db8::1")
        self.assertFalse(allowed_ip("169.254.169.254",()))
        self.assertFalse(allowed_ip("::ffff:127.0.0.1",()))
        with self.assertRaises(ValueError):
            ssh_address("example.net:22")

    def test_ssh_authenticates_without_a_configured_host_fingerprint(self):
        key=paramiko.RSAKey.generate(2048)
        seen=threading.Event()

        class Server(paramiko.ServerInterface):
            def check_auth_password(self, _user, _password):
                seen.set()
                return paramiko.AUTH_SUCCESSFUL

        client_sock, server_sock = socket.socketpair()
        with client_sock, server_sock, paramiko.Transport(server_sock) as server:
            server.add_server_key(key)
            worker=threading.Thread(target=server.start_server,kwargs={"server":Server()},daemon=True)
            worker.start()
            with patch("collector.dial",return_value=client_sock):
                host={"address":"unused","port":22,"username":"test","kind":"password"}
                with transport_for(host,{"value":"synthetic"},()) as transport:
                    self.assertTrue(transport.is_authenticated())
            worker.join(timeout=3)
            self.assertTrue(seen.is_set())


if __name__=="__main__":
    unittest.main()
