#!/usr/bin/env python3
"""Text that is not UTF-8 passes through unchanged (plan section 13).

    export DPMA_SLOT=<n>
    python3 dev/sim/mkpki.py && dev/sim/install-conf.sh
    dev/tests/raw-bytes/setup.sh
    cargo build && cargo build -p res_dpma_rs --features devtest
    dev/tools/ast.sh install && dev/tools/ast.sh start
    python3 -I dev/tests/raw-bytes/run.py [-v]

The configuration (fixtures.py) has Latin-1 text in phone, line,
network, application, translation, alert, page, ringtone, and contact
names and values, and a voicemail message with a Latin-1 caller id; a
second phone has the same kinds of text in UTF-8.  The simulator sends a
Latin-1 user agent, origination network, and message bodies, and AMI
clients send Latin-1 action headers.  Checked, byte for byte: the
configuration document, the user list, the default contacts, file
requests, echoes, events and reconfigures sent to the simulator, CLI
output, AMI responses and events, AstDB, and the log.  Where the original
hands such text to jansson (the user list, the method responses, the
JSON error documents, DPMAMessageResponse), the request fails the way
jansson makes the original fail; where it hands it to libxml2 (an XML
request, the display rules merge), libxml2 refuses it as it does for the
original.  Exit status 0 when every check passes.
"""
import base64
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
import xml.dom.minidom

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fixtures as fx  # noqa: E402

ROOT = fx.ROOT
sys.path.insert(0, os.path.join(ROOT, "dev", "sim"))
from dpma_sim import Options, Phone, method_request  # noqa: E402

if not fx.SLOT:
    sys.exit("DPMA_SLOT is not set (never run this against the shared install)")
AST = os.path.join(ROOT, "dev", "tools", "ast.sh")
MSGLOG = os.path.join(fx.INST, "var", "log", "asterisk", "messages.log")
AMI_PORT = 15038 + 100 * fx.SLOT
VERBOSE = "-v" in sys.argv
HTTP = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n"

checks = 0
failures = []
sessions = []       # session ids to forget at the end


def s(b):
    """Bytes as the simulator's header text (bytes that are not UTF-8
    travel as lone surrogates)."""
    return b.decode("utf-8", "surrogateescape")


def b(text):
    return text.encode("utf-8", "surrogateescape") if text is not None else None


def check(name, ok, detail=""):
    global checks
    checks += 1
    print(("ok   %s" if ok else "FAIL %s") % name)
    if not ok:
        failures.append(name)
        if detail:
            print("     " + detail.replace("\n", "\n     "))


def contains(name, data, *parts):
    missing = [p for p in parts if p not in (data or b"")]
    check(name, not missing, "missing %r\nin %r" % (missing, (data or b"")[:3000]))


def same(name, got, want):
    check(name, got == want, "got:  %r\nwant: %r" % (got, want))


def cli(cmd):
    r = subprocess.run([AST, "cli", cmd], capture_output=True, env=dict(os.environ, DPMA_SLOT=str(fx.SLOT)))
    return r.stdout


def log_mark():
    return os.path.getsize(MSGLOG) if os.path.exists(MSGLOG) else 0


def log_since(mark):
    time.sleep(0.5)
    with open(MSGLOG, "rb") as f:
        f.seek(mark)
        return f.read()


# ---------------------------------------------------------------------------
# A byte-exact AMI client
# ---------------------------------------------------------------------------

class Ami:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", AMI_PORT), timeout=10)
        self.buf = b""
        self.msgs = []
        self.seq = 0
        self._read_until(lambda: b"\r\n" in self.buf, 5)
        self.buf = self.buf.split(b"\r\n", 1)[1]      # the banner
        r = self.action([(b"Username", b"test"), (b"Secret", b"test"), (b"Events", b"on")], b"Login")
        if not r or not r[0].startswith(b"Response: Success"):
            sys.exit("AMI login failed: %r" % r)

    def _read_until(self, done, timeout):
        deadline = time.time() + timeout
        while not done():
            left = deadline - time.time()
            if left <= 0:
                return False
            self.sock.settimeout(left)
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                return False
            if not data:
                return False
            self.buf += data
            while b"\r\n\r\n" in self.buf:
                msg, self.buf = self.buf.split(b"\r\n\r\n", 1)
                self.msgs.append(msg + b"\r\n\r\n")
        return True

    def action(self, fields, action, action_id=None, list_action=False, timeout=5):
        """Send an action; return its response message (and, for list
        actions, the events up to "EventList: Complete") as raw bytes."""
        self.seq += 1
        action_id = action_id or b"raw-%d" % self.seq
        data = b"Action: " + action + b"\r\nActionID: " + action_id + b"\r\n"
        data += b"".join(k + b": " + v + b"\r\n" for k, v in fields) + b"\r\n"
        self.sock.sendall(data)
        tag = b"ActionID: " + action_id + b"\r\n"

        def mine():
            return [m for m in self.msgs if tag in m]

        def complete():
            got = mine()
            if not got:
                return False
            return not list_action or any(b"EventList: Complete" in m for m in got)
        self._read_until(complete, timeout)
        got = mine()
        self.msgs = [m for m in self.msgs if tag not in m]
        return got

    def event(self, name, timeout=5):
        """The first event `name` received (and drop it)."""
        head = b"Event: " + name + b"\r\n"

        def find():
            return next((m for m in self.msgs if m.startswith(head) or (b"\r\n" + head) in m), None)
        self._read_until(lambda: find() is not None, timeout)
        m = find()
        if m is not None:
            self.msgs.remove(m)
        return m


def header(msg, name):
    for line in (msg or b"").split(b"\r\n"):
        if line.startswith(name + b": "):
            return line[len(name) + 2:]
    return None


# ---------------------------------------------------------------------------
# The simulator
# ---------------------------------------------------------------------------

def phone(mac, **kw):
    opts = Options(slot=fx.SLOT, mac=mac, user_agent=s(fx.USER_AGENT), origination_network=s(fx.ORIGINATION), **kw)
    p = Phone(opts, out=sys.stdout if VERBOSE else io.StringIO())
    p.start()
    ex = p.handshake()
    if not ex.ok:
        sys.exit("handshake failed:\n" + ex.describe())
    sessions.append(b(p.session))
    return p


def reply_of(name, ex):
    r = ex.reply
    check(name + " (reply)", r is not None and not r.problems, ex.describe())
    return r


def asterisk(p, doc, auth=None):
    """AsteriskRequest; the reply payload (bytes)."""
    auth = s(fx.PHONE + b":" + fx.PIN) if auth is None else auth
    r = p.asterisk(doc if isinstance(doc, str) else s(doc), auth=auth).reply
    return r.payload if r is not None else None


def json_error(method, code, text, detail):
    doc = {"response": {"method": method, "errors": {"error": {"code": code, "message": "%s: %s " % (text, detail)}}}}
    return HTTP + json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode() + b"\r\n\r\n"


PARSE = (10002, "Error parsing request")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_cli():
    print("\n== CLI")
    contains("show phones", cli("digium_phones show phones"), fx.PHONE + b"\n", fx.U_PHONE + b"\n")
    out = cli(b"digium_phones show phone " + fx.PHONE)
    contains("show phone", out, b"Name: " + fx.PHONE + b"\n", b"Full Name: " + fx.FULL_NAME + b"\n",
             b"Application: Status, " + fx.STATUS_APP + b"\n", b"Application: Custom, " + fx.CUSTOM_APP + b"\n",
             b"Contact: " + fx.CONTACT_FILE + b"\n", b"Alert: " + fx.ALERT + b"\n",
             b"Contacts Display Items: " + fx.RULES_FILE + b"\n")
    contains("show phone (UTF-8)", cli(b"digium_phones show phone " + fx.U_PHONE),
             b"Full Name: " + fx.U_FULL_NAME + b"\n")
    contains("show line", cli(b"digium_phones show line " + fx.LINE), b"Line Label: " + fx.LINE_LABEL + b"\n",
             b"First Name: " + fx.FIRST_NAME + b"\n", b"Last Name: " + fx.LAST_NAME + b"\n",
             b"Location: " + fx.LOCATION + b"\n")
    contains("show networks", cli("digium_phones show networks"), b"    " + fx.NETWORK + b"\n")
    contains("show network", cli(b"digium_phones show network " + fx.NETWORK),
             b"Name: " + fx.NETWORK + b"\n", b"Alias: " + fx.NET_ALIAS + b"\n")
    contains("show applications", cli("digium_phones show applications"), fx.STATUS_APP, fx.CUSTOM_APP, fx.VM_APP)
    contains("show application (status)", cli(b"digium_phones show application " + fx.STATUS_APP),
             b"Substatuses:\n    " + fx.SUBSTATUS + b"\n")
    contains("show application (custom)", cli(b"digium_phones show application " + fx.CUSTOM_APP), fx.CUSTOM_NAME)
    contains("show alerts", cli("digium_phones show alerts"), b"    " + fx.ALERT + b"\n")
    contains("show alert", cli(b"digium_phones show alert " + fx.ALERT), b"Alert Info: " + fx.ALERT_INFO + b"\n")
    contains("show multicastpage", cli(b"digium_phones show multicastpage " + fx.PAGE),
             b"Alias: " + fx.PAGE_ALIAS + b"\n")
    contains("show translations", cli("digium_phones show translations"), b"    " + fx.TRANSLATION + b"\n")
    contains("show translation", cli(b"digium_phones show translation " + fx.TRANSLATION),
             b"--- " + fx.TRANSLATION + b" ---\n", b"    INBOX ==> " + fx.INBOX_FR + b"\n")
    contains("show status", cli(b"digium_phones show status " + fx.PHONE), b" - " + fx.SUBSTATUS + b"\n")


def check_phone(ami):
    print("\n== Phone requests (Latin-1 phone)")
    p = phone(fx.MAC)
    try:
        # Echo: the body and the origination network come back unchanged.
        body = b"\xc9cho: Jos\xe9 \xff\xfe"
        r = reply_of("Echo", p.echo(body))
        if r:
            same("Echo body", r.payload, body)
            same("Echo X-Origination-Network", b(r.first.get("X-Origination-Network")), fx.ORIGINATION)

        mark = log_mark()
        ex = p.get_token()
        r = reply_of("TokenRequest", ex)
        token = b(p.token)
        check("token names the phone", (token or b"").startswith(fx.PHONE + b"/" + fx.MAC.encode() + b"/"), repr(token))
        contains("log: now connected", log_since(mark), b"Phone user '" + fx.PHONE + b"' now connected from '")

        # The configuration document.
        mark = log_mark()
        r = reply_of("ConfigRequest", p.config())
        doc = r.payload if r else b""
        same("ConfigRequest document = dpmadev config", doc, cli(b"dpmadev config " + fx.PHONE + b" D65"))
        contains("configuration document", doc, b'first_name="' + fx.FIRST_NAME + b'"',
                 b'last_name="' + fx.LAST_NAME + b'"', b'line_label="' + fx.LINE_LABEL + b'"',
                 b'caller_id="&quot;Jos\xe9&quot; &lt;1001&gt;"',
                 b'<network id="' + fx.NETWORK + b'" display_name="' + fx.NET_ALIAS + b'" cidr="0.0.0.0/0" />',
                 b'<setting id="idle_company_text" value="' + fx.IDLE_TEXT + b'" />',
                 b'label1="' + fx.CUSTOM_NAME + b'"', b'<contacts url="file://' + fx.CONTACT_FILE + b'"',
                 b'alert_info="' + fx.ALERT_INFO + b'"', fx.PAGE_ALIAS,
                 b'display="' + fx.RINGTONE_ALIAS + b'" url="' + fx.FILE_URL + b'sonnerie.raw"')
        # The display rules merge: libxml2 refuses the Latin-1 document, so
        # it goes out unmerged.
        check("display rules: document not merged", doc.startswith(b"<config>"), repr(doc[:80]))
        contains("display rules: libxml2 refused the document", log_since(mark),
                 b"Error Parsing phone user config, phone configuration may be invalid.")

        # Files: a Latin-1 name, and the default contacts.
        r = reply_of("FileRequest (Latin-1 name)", p.file(s(fx.CONTACT_FILE)))
        if r:
            same("FileRequest (Latin-1 name) contents", r.payload, fx.CONTACT_XML)
        r = reply_of("FileRequest file://default", p.file("default"))
        if r:
            contains("default contacts", r.payload, b'<contact first_name="' + fx.FIRST_NAME + b'" ',
                     b'last_name="' + fx.LAST_NAME + b'" ', b'location="' + fx.LOCATION + b'" ',
                     b'<contact first_name="' + fx.U_FULL_NAME + b'" ')
            same("default contacts = dpmadev contacts", r.payload, cli("dpmadev contacts"))

        # The user list goes through jansson: the UTF-8 phone's group pin
        # lists it byte for byte; the Latin-1 phone's makes jansson fail,
        # which the original answers as a bad configuration password.
        r = reply_of("UserlistRequest (UTF-8 phone)", p.userlist(config_password=s(fx.U_GROUP_PIN)))
        if r:
            # "assigned" is "1" when the phone has a session id (a run
            # before this one may have left one in AstDB).
            info = cli(b"dpmadev token info " + fx.U_PHONE)
            assigned = b"0" if b"last_session_id='' " in info else b"1"
            want = b'{"users":[{"extension":"1002","name":"' + fx.U_FULL_NAME + b'","assigned":"' + assigned + b'"}]}'
            same("user list (UTF-8)", r.payload, want)
        for label, pin in (("Latin-1 phone", fx.GROUP_PIN), ("everybody", fx.GLOBALPIN)):
            r = p.userlist(config_password=s(pin)).reply
            check("UserlistRequest (%s): jansson fails, -198" % label, r is not None and r.error == "-198",
                  r.describe() if r else "no reply")
        out = cli(b"dpmadev userlist " + fx.GROUP_PIN)
        same("dpmadev userlist (Latin-1 phone)", out, b"Failed to build the user list\n")

        # Methods: jansson refuses the Latin-1 values the original packs.
        def call(method, params):
            return asterisk(p, method_request(method, params))
        same("presence.options.getList: Latin-1 sub-state",
             call("switchvox.users.presence.options.getList", {}),
             json_error("switchvox.users.presence.options.getList", *PARSE, "pack options array"))
        same("voicemail.getList INBOX: Latin-1 translation",
             call("switchvox.users.voicemail.getList", {"account_id": "1001", "folder": "INBOX"}),
             json_error("switchvox.users.voicemail.getList", *PARSE, "pack messages"))
        same("voicemail.getList Work: Latin-1 caller id",
             call("switchvox.users.voicemail.getList", {"account_id": "1001", "folder": "Work"}),
             json_error("switchvox.users.voicemail.getList", *PARSE, "message_entry"))
        same("voicemail.getFolderList: Latin-1 translation",
             call("switchvox.users.voicemail.getFolderList", {"account_id": "1001"}),
             json_error("switchvox.users.voicemail.getFolderList", *PARSE, "append folder"))
        got = call("switchvox.users.voicemail.getList", {"account_id": "1001", "folder": "Family"})
        contains("voicemail.getList Family: UTF-8 caller id", got,
                 b'"caller_id":"\\"Fr\xc3\xa9d\xc3\xa9ric\\" <300>"', b'"caller_id_name":"Fr\xc3\xa9d\xc3\xa9ric"')
        # A request body that is not UTF-8: jansson and libxml2 refuse it.
        same("JSON request with Latin-1", asterisk(p, b'{"request":{"method":"x","parameters":{"n":"Jos\xe9"}}}'),
             json_error("NA", *PARSE, "json body"))
        xml_err = (b'<response method="NA">\r\n<errors>\r\n<error code="10002" message="Error parsing request" />'
                   b'\r\n</errors>\r\n</response>\r\n')
        same("XML request with Latin-1", asterisk(p, b'<request method="x"><parameters>Jos\xe9</parameters></request>'),
             HTTP + xml_err + b"\r\n\r\n")
        # Latin-1 credentials that fail: the error document cannot be
        # built (jansson), so the reply is the bare HTTP header.
        mark = log_mark()
        same("Latin-1 credentials: no error document", asterisk(p, method_request("x", {}), auth=s(b"nob\xf6dy:x")),
             HTTP)
        contains("log: Unable to generate JSON for error response", log_since(mark),
                 b"Unable to generate JSON for error response")

        check_ami_phone(ami, p)
        check_astdb(p)
    finally:
        p.close()


def check_ami_phone(ami, p):
    print("\n== AMI (Latin-1 headers)")
    msgs = ami.action([], b"DPMAShowPhones", action_id=b"raw-\xe9", list_action=True)
    mac = b"MAC: " + fx.MAC.encode() + b"\r\n"
    ev = next((m for m in msgs if m.startswith(b"Event: DPMAShowPhonesList") and mac in m), b"")
    contains("DPMAShowPhones", ev, b"ActionID: raw-\xe9\r\n", b"UserAgent: " + fx.USER_AGENT + b"\r\n",
             b"Username: " + fx.PHONE + b"\r\n", b"MAC: " + fx.MAC.encode() + b"\r\n")

    # DPMAMessageSend: event name and body reach the phone unchanged.
    method, message = b"\xe9v\xe9nement.test", b"Corps du message: \xe9\xe8\xe0"
    r = ami.action([(b"PhoneName", fx.PHONE), (b"Method", method), (b"Message", message)], b"DPMAMessageSend",
                   action_id=b"send-\xe9")
    same("DPMAMessageSend response", r[:1], [b"Response: Success\r\nActionID: send-\xe9\r\n\r\n"])
    e = p.next_event()
    check("DPMAMessageSend event arrived", e is not None)
    if e is not None:
        same("event name", b(e.event), method)
        same("event body", e.payload, message)

    # Reconfigure by a Latin-1 phone name.
    r = ami.action([(b"PhoneName", fx.PHONE)], b"DigiumPhoneReconfigure")
    contains("DigiumPhoneReconfigure", r[0] if r else b"", b"Response: Success\r\n",
             b"Message: Reconfigure message successfully sent\r\n")
    e = p.next_event(name="digium.config.update")
    check("reconfigure reached the phone", e is not None and e.payload == b"<config></config>")

    # Latin-1 method names register; the registry shows them as they came.
    r = ami.action([(b"Method", b"p18.m\xe9thode")], b"DPMAMessageRegister")
    same("DPMAMessageRegister (Latin-1)", r[:1], [b"Response: Success\r\nActionID: raw-%d\r\n\r\n" % ami.seq])
    contains("dpmadev method list", cli("dpmadev method list"), b"  p18.m\xe9thode\n")

    # Requests forwarded to AMI: the XML answer passes as bytes; a JSON
    # answer that is not UTF-8 fails (jansson), and the request waits.
    ami.action([(b"Method", b"p18.raw")], b"DPMAMessageRegister")
    ex = p.asterisk(method_request("p18.raw", "Ren&#xE9;", fmt="xml"), auth=s(fx.PHONE + b":" + fx.PIN), wait=False)
    ev = ami.event(b"DPMAMessage")
    contains("DPMAMessage (XML)", ev, b"Method: p18.raw\r\n", b"Format: XML\r\n",
             b"Parameters: Ren\xc3\xa9\r\n")
    rid = header(ev, b"RequestID")
    r = ami.action([(b"RequestID", rid or b"?"), (b"Format", b"XML"), (b"Response", b"<r>\xe9</r>")],
                   b"DPMAMessageResponse")
    contains("DPMAMessageResponse XML", r[0] if r else b"", b"Response: Success\r\n")
    rep = p.wait_reply(ex).reply
    same("forwarded XML answer", rep.payload if rep else None,
         HTTP + b'\r\n\r\n<response method="p18.raw">\r\n<result><r>\xe9</r></result>\r\n</response>\r\n')

    ex = p.asterisk(method_request("p18.raw", {"a": "\xe9"}), auth=s(fx.PHONE + b":" + fx.PIN), wait=False)
    ev = ami.event(b"DPMAMessage")
    contains("DPMAMessage (JSON)", ev, b'Parameters: {"a":"\xc3\xa9"}\r\n')
    rid = header(ev, b"RequestID") or b"?"
    r = ami.action([(b"RequestID", rid), (b"Format", b"JSON"), (b"Response", b'"\xe9"')], b"DPMAMessageResponse")
    contains("DPMAMessageResponse JSON, Latin-1: jansson fails", r[0] if r else b"", b"Response: Failure\r\n")
    r = ami.action([(b"RequestID", rid), (b"Format", b"JSON"), (b"Response", b'Ren\xc3\xa9')], b"DPMAMessageResponse")
    contains("DPMAMessageResponse JSON, UTF-8", r[0] if r else b"", b"Response: Success\r\n")
    rep = p.wait_reply(ex).reply
    same("forwarded JSON answer", rep.payload if rep else None,
         HTTP + b'\r\n\r\n{"response":{"method":"p18.raw","result":"Ren\xc3\xa9"}}\r\n')


def check_astdb(p):
    print("\n== AstDB")
    out = cli("database show DigiumPhoneUsers")
    m = re.search(rb"/DigiumPhoneUsers/" + re.escape(fx.PHONE) + rb" +: last_mac=([^;]*);last_uri=([^;]*;transport=[^;]*)"
                  rb";last_session_id=(\S*)", out)
    check("DigiumPhoneUsers/<Latin-1 phone>", m is not None and m.group(1) == fx.MAC.encode()
          and m.group(3) == b(p.session), repr(out))
    out = cli(b"database get DigiumPhoneSessions " + b(p.session))
    contains("DigiumPhoneSessions: origination network", out, b";origination_network=" + fx.ORIGINATION)
    m = re.search(rb";ua=([A-Za-z0-9+/=]*);", out)
    same("DigiumPhoneSessions: user agent (base64)", base64.b64decode(m.group(1)) if m else None, fx.USER_AGENT)


def check_incident(ami):
    print("\n== Auth incident (Latin-1 user agent)")
    for m in ami.action([], b"DPMAShowIncidents", list_action=True):
        ip = header(m, b"IPAddress")
        if ip:
            ami.action([(b"IPAddress", ip)], b"DPMARemoveIncident")
    opts = Options(slot=fx.SLOT, mac="000fd30018ff", user_agent=s(fx.USER_AGENT))
    p = Phone(opts, out=sys.stdout if VERBOSE else io.StringIO())
    p.start()
    try:
        p.handshake(bundle="rogue")
    finally:
        p.close()
    msgs = ami.action([], b"DPMAShowIncidents", list_action=True)
    ev = next((m for m in msgs if m.startswith(b"Event: DPMAShowIncidentsList")), b"")
    contains("DPMAShowIncidents", ev, b"UserAgent: " + fx.USER_AGENT + b"\r\n", b"MAC: 000fd30018ff\r\n")


def check_utf8_phone():
    print("\n== The UTF-8 phone (display rules merged by libxml2)")
    p = phone(fx.U_MAC)
    try:
        p.get_token()
        r = reply_of("ConfigRequest", p.config())
        doc = r.payload if r else b""
        same("ConfigRequest document = dpmadev config", doc, cli(b"dpmadev config " + fx.U_PHONE + b" D65"))
        check("display rules merged", doc.startswith(b"<?xml"), repr(doc[:80]))
        try:
            dom = xml.dom.minidom.parseString(doc)
            labels = [a.getAttribute("line_label") for a in dom.getElementsByTagName("account")
                      if a.hasAttribute("line_label")]
            same("line_label", labels[:1], [fx.U_LINE_LABEL.decode()])
        except Exception as e:  # noqa: BLE001
            check("document parses", False, repr(e))
    finally:
        p.close()


def cleanup():
    """Forget the test phones' sessions and locations in AstDB, so that
    later suites do not restore them."""
    for sid in sessions:
        cli(b"database del DigiumPhoneSessions " + sid)
    for name in (fx.PHONE, fx.U_PHONE):
        cli(b"database del DigiumPhoneUsers " + name)


def main():
    ami = Ami()
    try:
        check_cli()
        check_phone(ami)
        check_incident(ami)
        check_utf8_phone()
    finally:
        cleanup()
    print("\n%d checks, %d failed" % (checks, len(failures)))
    for f in failures:
        print("  " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
