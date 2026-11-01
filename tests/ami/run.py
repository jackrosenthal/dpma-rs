#!/usr/bin/env python3
"""End-to-end checks for package P13 (DPMAMessageRegister,
DPMAMessageResponse, DPMAMessageSend, the queued AMI requests, and the AMI
scheduler) and for the phone users runtime's messages to phones
(reconfigure from the CLI, AMI, and reloads; events), against a private
Asterisk instance with the phone simulator.

    DPMA_SLOT=<n> python3 -I dev/tests/ami/run.py [-v] [--via phone|hook] [--expiry]

Prerequisites: the simulator setup (dev/sim/mkpki.py,
dev/sim/install-conf.sh), the P13 phones (dev/tests/ami/setup.sh), a
devtest build installed in the instance (cargo build -p res_digium_phone
--features devtest), and Asterisk running.

--via phone (the default) drives everything from the simulator: the
TokenRequest records where the phone is, and an AsteriskRequest for an
AMI-registered method is forwarded to AMI by the request handler.
--via hook replaces those two steps with "dpmadev token build" and
"dpmadev ami forward" (for a tree without the request handlers).

AMI responses and events are compared byte for byte with what the
original's phone_ami.c and phone_request.c write; replies and events are
checked as the simulated phone decrypts them.

--expiry also checks the 300 s expiry (takes about five minutes): as in the
original, nothing runs the AMI scheduler, so the request is still queued
afterwards; "dpmadev ami runq" then expires it.

Exit status 0 when every check passes.
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../.."))
sys.path.insert(0, os.path.join(ROOT, "dev/sim"))
from dpma_sim import Exchange, Options, Phone, method_request  # noqa: E402

SLOT = os.environ.get("DPMA_SLOT")
if not SLOT:
    sys.exit("DPMA_SLOT is not set")
AMI_PORT = 15038 + 100 * int(SLOT)
INST = os.path.join(ROOT, "dev/run/slot" + SLOT)
ETC = os.path.join(INST, "etc/asterisk")
LOG = os.path.join(INST, "var/log/asterisk/messages.log")
CONF = "res_digium_phone_p13.conf"
GLOBALPIN = "344486"
PREAMBLE = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n"
DELETE_TOKEN_BODY = b'<config>\t<section id="all"/>\t<option id="delete_token" value="true"/></config>'

ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
ap.add_argument("-v", "--verbose", action="store_true")
ap.add_argument("--via", choices=("phone", "hook"), default="phone")
ap.add_argument("--expiry", action="store_true", help="also wait out the 300 s expiry")
ARGS = ap.parse_args()
failures = 0


def check(name, ok, detail=""):
    global failures
    if ok:
        print("ok   " + name)
    else:
        failures += 1
        print("FAIL " + name + ("\n     " + detail if detail else ""))
    if ARGS.verbose and detail and ok:
        print("     " + detail)


def same(name, got, want):
    check(name, got == want, "got  %r\n     want %r" % (got, want))


def cli(cmd):
    r = subprocess.run([os.path.join(ROOT, "dev/tools/ast.sh"), "cli", cmd], capture_output=True, text=True)
    return r.stdout


def quote(text):
    """Escape for the Asterisk CLI parser."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace(" ", "\\ ")


def log_size():
    return os.path.getsize(LOG) if os.path.exists(LOG) else 0


def log_since(pos):
    with open(LOG, "rb") as f:
        f.seek(pos)
        return f.read().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# A byte-exact AMI client
# ---------------------------------------------------------------------------

class RawAmi:
    """Keeps every message as the raw bytes Asterisk sent (up to the blank
    line), so responses can be compared byte for byte."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.cond = threading.Condition()
        self.responses = []
        self.events = []
        self.closed = False
        f = self.sock.makefile("rb")
        self.banner = f.readline()
        self.sock.settimeout(None)
        threading.Thread(target=self._reader, args=(f,), daemon=True).start()
        r = self.send(b"Action: Login\r\nUsername: test\r\nSecret: test\r\n\r\n")
        if not r.startswith(b"Response: Success"):
            raise SystemExit("AMI login failed: %r" % r)

    def _reader(self, f):
        buf = b""
        while True:
            data = f.read1(65536)
            if not data:
                break
            buf += data
            while b"\r\n\r\n" in buf:
                msg, buf = buf.split(b"\r\n\r\n", 1)
                msg += b"\r\n\r\n"
                with self.cond:
                    (self.events if msg.startswith(b"Event:") else self.responses).append(msg)
                    self.cond.notify_all()
        with self.cond:
            self.closed = True
            self.cond.notify_all()

    def send(self, data, timeout=10):
        """Send raw action text and return the next response."""
        with self.cond:
            self.responses.clear()
        self.sock.sendall(data)
        deadline = time.time() + timeout
        with self.cond:
            while not self.responses:
                left = deadline - time.time()
                if left <= 0 or self.closed:
                    return None
                self.cond.wait(left)
            return self.responses.pop(0)

    def action(self, name, *fields, action_id=None):
        """`fields` are (key, value) pairs; values may be bytes."""
        text = b"Action: " + name.encode() + b"\r\n"
        if action_id is not None:
            text += b"ActionID: " + (action_id if isinstance(action_id, bytes) else action_id.encode()) + b"\r\n"
        for k, v in fields:
            text += k.encode() + b": " + (v if isinstance(v, bytes) else v.encode()) + b"\r\n"
        return self.send(text + b"\r\n")

    def command(self, cmd):
        r = self.action("Command", ("Command", cmd)) or b""
        return "\n".join(v for k, v in parse(r) if k == "Output")

    def clear_events(self):
        with self.cond:
            self.events.clear()

    def wait_event(self, name, pred=None, timeout=10):
        deadline = time.time() + timeout
        with self.cond:
            while True:
                for ev in self.events:
                    f = parse(ev)
                    if f and f[0] == ("Event", name) and (pred is None or pred(dict(f))):
                        self.events.remove(ev)
                        return ev
                left = deadline - time.time()
                if left <= 0 or self.closed:
                    return None
                self.cond.wait(left)


def parse(raw):
    out = []
    for line in raw.decode("utf-8", "replace").split("\r\n"):
        if line:
            k, _, v = line.partition(": ")
            out.append((k, v))
    return out


def resp(result, action_id=None):
    """The original's reply: "Response: %s\\r\\n%s\\r\\n" with the ActionID
    line (or nothing)."""
    idtext = b"ActionID: " + action_id.encode() + b"\r\n" if action_id else b""
    return b"Response: " + result.encode() + b"\r\n" + idtext + b"\r\n"


# ---------------------------------------------------------------------------
# Phones
# ---------------------------------------------------------------------------

def new_phone(mac):
    p = Phone(Options(slot=SLOT, mac=mac, timeout=5.0), out=sys.stdout).start()
    ex = p.handshake()
    if not ex.ok:
        raise SystemExit("handshake failed for %s:\n%s" % (mac, ex.describe()))
    return p


def uri_of(phone):
    """The Response-URI the module derives for this phone's messages."""
    host, port = phone.sip.local_addr
    return "pjsip:%s:%d;transport=%s" % (host, port, phone.opts.transport)


def authenticate(phone, name):
    """Record where the phone is (TokenRequest, or the token hook)."""
    if ARGS.via == "phone":
        ex = phone.get_token(user=name, config_password=GLOBALPIN)
        return ex.ok, ex.describe()
    out = cli("dpmadev token build %s %s %s %s" % (name, phone.mac, phone.session, uri_of(phone)))
    return out.startswith("token: %s/" % name), out


def drain(phone):
    while phone.next_event(timeout=0.2) is not None:
        pass


def params_text(fmt, params):
    """What the DPMAMessage event carries as Parameters: the compact JSON of
    the parameters, or the text content of the <parameters> element."""
    if fmt == "json":
        return json.dumps(params, separators=(",", ":"), ensure_ascii=False)
    return "".join(ET.fromstring("<parameters>%s</parameters>" % params).itertext())


def forward(phone, method, fmt, params, auth, timeout=None):
    """A request for an AMI-registered method; returns (exchange, RequestID,
    Parameters)."""
    ptext = params_text(fmt, params)
    if ARGS.via == "phone":
        ex = phone.asterisk(method_request(method, params, fmt), auth=auth, wait=False)
    else:
        txid = phone.new_id()
        ex = Exchange("AsteriskRequest", txid)
        with phone._lock:
            phone._waiting[txid] = ex
        out = cli("dpmadev ami forward %s %s %s %s %s %s" % (
            phone.session, uri_of(phone), txid, fmt.upper(), method, quote(ptext)))
        if not out.startswith("Queued"):
            print("     dpmadev ami forward: " + out.strip())
    return ex, "%s-%s" % (ex.id, phone.mac), ptext


def dpma_message(ami, key, method, fmt, ptext, label):
    ev = ami.wait_event("DPMAMessage", lambda f: f.get("RequestID") == key)
    want = (b"Event: DPMAMessage\r\nPrivilege: agent,all\r\nRequestID: %s\r\nMethod: %s\r\nFormat: %s\r\n"
            b"Parameters: %s\r\n\r\n" % (key.encode(), method.encode(), fmt.upper().encode(), ptext.encode()))
    same(label + ": DPMAMessage event", ev, want)


def queued():
    out = cli("dpmadev ami queue")
    return re.findall(r"^RequestID: (\S+)  Method: (\S*)  Session: (\S*)  SchedID: (-?\d+)", out, re.M)


def reply_of(phone, ex, timeout=5):
    ex = phone.wait_reply(ex, timeout)
    return ex.reply


def check_reply(label, r, ex, body, session):
    if r is None:
        check(label + ": reply reaches the phone", False, "no reply")
        return
    same(label + ": reply type", r.response_type, "AsteriskResponse")
    same(label + ": reply id", r.id, ex.id)
    same(label + ": reply session", r.session, session)
    check(label + ": reply encrypted, no error", r.encrypted and r.error is None and not r.problems,
          "encrypted=%s error=%r problems=%r" % (r.encrypted, r.error, r.problems))
    same(label + ": reply body", r.body, body)


def json_doc(obj):
    return b"\r\n\r\n" + json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\r\n"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_actions(ami):
    out = cli("manager show command DPMAMessageRegister DPMAMessageResponse DPMAMessageSend")
    check("actions registered with privilege call",
          len(re.findall(r"Privilege: call,all", out)) == 3, out)

    same("Register: Success", ami.action("DPMAMessageRegister", ("Method", "com.p13.hello"), action_id="r1"),
         resp("Success", "r1"))
    same("Register: no ActionID", ami.action("DPMAMessageRegister", ("Method", "com.p13.hello")),
         resp("Success"))
    same("Register: empty Method", ami.action("DPMAMessageRegister", ("Method", ""), action_id="r2"),
         resp("Failure", "r2"))
    same("Register: no Method", ami.action("DPMAMessageRegister", action_id="r3"), resp("Failure", "r3"))
    same("Register: second name", ami.action("DPMAMessageRegister", ("Method", "com.p13.Other"), action_id="r4"),
         resp("Success", "r4"))
    out = cli("dpmadev method list")
    check("Register: names in the AMI registry", "com.p13.hello" in out and "com.p13.Other" in out, out)
    # snprintf(idtext, 0x100, "ActionID: %s\r\n"): 243 characters fit; with
    # 244 the "\n" is cut, so the response runs into the next one.
    a243 = "a" * 243
    same("ActionID of 243 characters", ami.action("DPMAMessageRegister", ("Method", "com.p13.hello"),
                                                  action_id=a243), resp("Success", a243))
    a244 = "b" * 244
    ami.sock.sendall(b"Action: DPMAMessageRegister\r\nActionID: " + a244.encode() + b"\r\nMethod: x\r\n\r\n")
    got = ami.action("DPMAMessageRegister", ("Method", "com.p13.hello"), action_id="r5")
    same("ActionID of 244 characters (truncated, unterminated)", got,
         b"Response: Success\r\nActionID: " + a244.encode() + b"\r\r\n" + resp("Success", "r5"))

    same("Response: no RequestID", ami.action("DPMAMessageResponse", ("Format", "json"), ("Response", "x"),
                                              action_id="n1"), resp("Failure", "n1"))
    same("Response: unknown RequestID", ami.action("DPMAMessageResponse", ("RequestID", "1-000000000000"),
                                                   ("Format", "json"), ("Response", "x")), resp("Failure"))

    pos = log_size()
    same("Send: unknown phone", ami.action("DPMAMessageSend", ("PhoneName", "nobody"), ("Method", "e"),
                                           action_id="s1"), resp("Failure", "s1"))
    same("Send: no PhoneName", ami.action("DPMAMessageSend", ("Method", "e"), action_id="s2"), resp("Failure", "s2"))
    same("Send: no Method", ami.action("DPMAMessageSend", ("PhoneName", "p13phone"), ("Message", "m"),
                                       action_id="s3"), resp("Failure", "s3"))
    pos2 = log_size()
    same("Send: phone that never contacted the server",
         ami.action("DPMAMessageSend", ("PhoneName", "p13phone3"), ("Method", "e"), action_id="s4"),
         resp("Failure", "s4"))
    time.sleep(0.3)
    text = log_since(pos)
    check("Send: logs", "Phone 'nobody' could not be found." in text and "Phone '' could not be found." in text
          and "Message not supplied." in text, text)
    check("Send: no uri logged", "Unable to send event to 'p13phone3' with no uri" in log_since(pos2))


def check_forwarding(ami, a):
    s = a.session
    auth = "p13phone:1313"

    # JSON request answered with a JSON result.
    ex, key, pt = forward(a, "com.p13.hello", "json", {"a": 1, "b": "two words"}, auth)
    dpma_message(ami, key, "com.p13.hello", "json", pt, "JSON request")
    q = queued()
    check("JSON request: queued with an expiry", len(q) == 1 and q[0][0] == key and q[0][1] == "com.p13.hello"
          and q[0][2] == s and q[0][3] != "-1", repr(q))
    out = cli("dpmadev ami runq")
    check("JSON request: nothing is due yet", out.startswith("0 scheduled entries ran"), out)
    same("JSON result: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "json"),
                                                 ("Response", 'hello "world"'), action_id="j1"),
         resp("Success", "j1"))
    check_reply("JSON result", reply_of(a, ex), ex, PREAMBLE + json_doc(
        {"response": {"method": "com.p13.hello", "result": 'hello "world"'}}), s)
    same("JSON result: no longer queued", queued(), [])
    same("JSON result: second response fails", ami.action("DPMAMessageResponse", ("RequestID", key),
                                                          ("Format", "json"), ("Response", "x")), resp("Failure"))

    # JSON error; RequestID and Format ignore case.
    ex, key, pt = forward(a, "com.p13.hello", "json", {"x": [1, 2]}, auth)
    dpma_message(ami, key, "com.p13.hello", "json", pt, "JSON error")
    same("JSON error: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key.upper()),
                                                ("Format", "Json"), ("ErrorNum", "42"),
                                                ("ErrorMsg", "it <failed>")), resp("Success"))
    check_reply("JSON error", reply_of(a, ex), ex, PREAMBLE + json_doc(
        {"response": {"method": "com.p13.hello", "errors": {"error": {"code": 42, "message": "it <failed>"}}}}), s)

    # JSON with neither a result nor a whole error: Failure, still queued.
    ex, key, pt = forward(a, "com.p13.Other", "json", {}, auth)
    dpma_message(ami, key, "com.p13.Other", "json", pt, "JSON incomplete")
    same("JSON incomplete: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "JSON"),
                                                     ("ErrorNum", "7"), action_id="j3"), resp("Failure", "j3"))
    same("JSON incomplete: invalid UTF-8 result fails",
         ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "JSON"), ("Response", b"\xff\xfe")),
         resp("Failure"))
    check("JSON incomplete: still queued", [k for k, *_ in queued()] == [key], repr(queued()))
    # ... and then answered in XML with neither: an empty response element.
    same("XML empty: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "xml")),
         resp("Success"))
    check_reply("XML empty", reply_of(a, ex), ex,
                PREAMBLE + b'\r\n\r\n<response method="com.p13.Other">\r\n</response>\r\n', s)

    # XML request answered with an XML result (not escaped), then an error.
    xml_params = "<id>17</id><name>x &amp; y</name>"
    ex, key, pt = forward(a, "com.p13.hello", "xml", xml_params, auth)
    dpma_message(ami, key, "com.p13.hello", "xml", pt, "XML request")
    same("XML result: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "XML"),
                                                ("Response", "<ok a='1'/> & more"), ("ErrorNum", "9"),
                                                ("ErrorMsg", "ignored")), resp("Success"))
    check_reply("XML result", reply_of(a, ex), ex, PREAMBLE + (
        b"\r\n\r\n<response method=\"com.p13.hello\">\r\n<result><ok a='1'/> & more</result>\r\n</response>\r\n"), s)
    ex, key, pt = forward(a, "com.p13.hello", "xml", "<z/>", auth)
    dpma_message(ami, key, "com.p13.hello", "xml", pt, "XML error")
    same("XML error: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "xml"),
                                               ("ErrorNum", "abc"), ("ErrorMsg", "bad \"thing\"")),
         resp("Success"))
    check_reply("XML error", reply_of(a, ex), ex, PREAMBLE + (
        b"\r\n\r\n<response method=\"com.p13.hello\">\r\n<errors>\r\n"
        b"<error code=\"abc\" message=\"bad \"thing\"\" />\r\n</errors>\r\n</response>\r\n"), s)

    # Any other Format: only the preamble.
    ex, key, pt = forward(a, "com.p13.hello", "json", {"f": None}, auth)
    dpma_message(ami, key, "com.p13.hello", "json", pt, "other format")
    same("other format: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "text"),
                                                  ("Response", "r")), resp("Success"))
    check_reply("other format", reply_of(a, ex), ex, PREAMBLE, s)

    # Two queued at once, answered out of order; a long result is chunked.
    ex1, key1, pt1 = forward(a, "com.p13.hello", "json", {"n": 1}, auth)
    ex2, key2, pt2 = forward(a, "com.p13.Other", "json", {"n": 2}, auth)
    dpma_message(ami, key1, "com.p13.hello", "json", pt1, "first of two")
    dpma_message(ami, key2, "com.p13.Other", "json", pt2, "second of two")
    check("two queued", sorted(k for k, *_ in queued()) == sorted([key1, key2]), repr(queued()))
    # (AMI refuses header lines over 1024 bytes.)
    long = "L" * 900
    same("second answered first", ami.action("DPMAMessageResponse", ("RequestID", key2), ("Format", "json"),
                                             ("Response", long)), resp("Success"))
    r2 = reply_of(a, ex2)
    check_reply("long result", r2, ex2, PREAMBLE + json_doc(
        {"response": {"method": "com.p13.Other", "result": long}}), s)
    check("long result: several chunks", r2 is not None and len(r2.parts) > 1,
          "chunks=%s" % (len(r2.parts) if r2 else None))
    same("first answered second", ami.action("DPMAMessageResponse", ("RequestID", key1), ("Format", "json"),
                                             ("Response", "1")), resp("Success"))
    check_reply("first of two", reply_of(a, ex1), ex1, PREAMBLE + json_doc(
        {"response": {"method": "com.p13.hello", "result": "1"}}), s)

    # The phone gives up waiting; the answer still arrives later.
    ex, key, pt = forward(a, "com.p13.hello", "json", {"late": True}, auth)
    dpma_message(ami, key, "com.p13.hello", "json", pt, "late answer")
    r = reply_of(a, ex, timeout=1.5)
    check("late answer: phone times out first", r is None, repr(r))
    drain(a)
    same("late answer: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "json"),
                                                 ("Response", "late")), resp("Success"))
    r = a.next_event(timeout=5)
    check("late answer: reply arrives unsolicited", r is not None and r.id == ex.id
          and r.response_type == "AsteriskResponse" and r.body == PREAMBLE + json_doc(
              {"response": {"method": "com.p13.hello", "result": "late"}}),
          r.describe() if r else "no message")
    same("queue empty", queued(), [])


def check_send(ami, a):
    drain(a)
    same("Send: event", ami.action("DPMAMessageSend", ("PhoneName", "P13PHONE"), ("Method", "com.p13.event"),
                                   ("Message", "<hello/>"), action_id="e1"), resp("Success", "e1"))
    r = a.next_event(timeout=5)
    check("Send: event reaches the phone", r is not None and r.event == "com.p13.event" and r.id is None
          and r.error is None and r.encrypted and r.payload == b"<hello/>" and r.body == b"Command: <hello/>"
          and r.session == a.session, r.describe() if r else "no message")
    same("Send: empty body", ami.action("DPMAMessageSend", ("PhoneName", "p13phone"), ("Method", "com.p13.empty")),
         resp("Success"))
    r = a.next_event(timeout=5)
    check("Send: empty body is 'empty body'", r is not None and r.event == "com.p13.empty"
          and r.payload == b"empty body", r.describe() if r else "no message")
    same("Send: digium.assignment.update", ami.action("DPMAMessageSend", ("PhoneName", "p13phone"),
                                                      ("Method", "digium.assignment.update"),
                                                      ("Message", "<assign/>")), resp("Success"))
    r = a.next_event(timeout=5)
    check("Send: assignment update as bootcReset / -398", r is not None and r.event is None
          and r.id == "bootcReset" and r.error == "-398" and r.response_type is None and r.encrypted
          and r.payload == b'<assign/><error msg="Session Timeout" />', r.describe() if r else "no message")
    same("Send: event name is case sensitive", ami.action("DPMAMessageSend", ("PhoneName", "p13phone"),
                                                          ("Method", "Digium.Assignment.Update"),
                                                          ("Message", "x")), resp("Success"))
    r = a.next_event(timeout=5)
    check("Send: other case is a plain event", r is not None and r.event == "Digium.Assignment.Update"
          and r.id is None and r.error is None, r.describe() if r else "no message")


def expect_reconfigure(phone, label, body=b"<config></config>"):
    r = phone.next_event(timeout=5)
    check(label + ": digium.config.update reaches the phone", r is not None and r.event == "digium.config.update"
          and r.id is None and r.error is None and r.encrypted and r.payload == body
          and r.session == phone.session, r.describe() if r else "no message")


def check_reconfigure(ami, a, b):
    drain(a)
    drain(b)
    out = cli("digium_phones reconfigure phone p13phone")
    same("CLI reconfigure phone", out, "Phone 'P13 Phone' will reconfigure shortly.\n")
    expect_reconfigure(a, "CLI reconfigure phone")
    out = cli("digium_phones reconfigure phone p13phone3")
    same("CLI reconfigure phone, not contacted", out,
         "Phone 'p13phone3' has not contacted the server.  The server is unaware of the location of this device "
         "and can not reconfigure it at this time.\n")
    out = cli("digium_phones reconfigure all")
    same("CLI reconfigure all", out, "Reconfigure message successfully sent to all known device locations.\n")
    expect_reconfigure(a, "CLI reconfigure all (p13phone)")
    expect_reconfigure(b, "CLI reconfigure all (p13phone2)")

    same("AMI DigiumPhoneReconfigure", ami.action("DigiumPhoneReconfigure", ("PhoneName", "p13phone"),
                                                  action_id="c1"),
         b"Response: Success\r\nActionID: c1\r\nMessage: Reconfigure message successfully sent\r\n\r\n")
    expect_reconfigure(a, "AMI DigiumPhoneReconfigure")
    same("AMI DigiumPhoneReconfigure: empty", ami.action("DigiumPhoneReconfigure", action_id="c2"),
         b"Response: Error\r\nActionID: c2\r\nMessage: PhoneName argument is empty.\r\n\r\n")
    same("AMI DigiumPhoneReconfigure: unknown", ami.action("DigiumPhoneReconfigure", ("PhoneName", "nobody"),
                                                           action_id="c3"),
         b"Response: Error\r\nActionID: c3\r\nMessage: Could not find user to reconfigure.\r\n\r\n")
    same("AMI DigiumPhoneReconfigure: not contacted",
         ami.action("DigiumPhoneReconfigure", ("PhoneName", "p13phone3"), action_id="c4"),
         b"Response: Error\r\nActionID: c4\r\nMessage: Phone has not contacted the server.  The server is unaware "
         b"of the location of this device and can not reconfigure it at this time.\n\r\n\r\n")
    same("AMI DigiumPhoneReconfigureAll", ami.action("DigiumPhoneReconfigureAll", action_id="c5"),
         b"Response: Success\r\nActionID: c5\r\nMessage: Reconfigure message successfully sent to all known "
         b"device locations.\r\n\r\n")
    expect_reconfigure(a, "AMI DigiumPhoneReconfigureAll (p13phone)")
    expect_reconfigure(b, "AMI DigiumPhoneReconfigureAll (p13phone2)")

    # The two bodies of phone_user_send_reconfigure (the delete-token one has
    # no caller in the original).
    uri = "pjsip:%s:%d" % a.sip.local_addr
    out = cli("dpmadev token reconfigure %s %s" % (a.session, uri))
    expect_reconfigure(a, "plain body (%s)" % out.strip())
    out = cli("dpmadev token reconfigure %s %s delete" % (a.session, uri))
    expect_reconfigure(a, "delete-token body (%s)" % out.strip(), DELETE_TOKEN_BODY)


def write_conf(text):
    with open(os.path.join(ETC, CONF), "w") as f:
        f.write(text)


def check_reload(a, b):
    with open(os.path.join(HERE, CONF)) as f:
        orig = f.read()
    try:
        drain(a)
        drain(b)
        pos = log_size()
        write_conf(orig.replace("full_name=P13 Phone\nline=p13line\n", "full_name=P13 Phone\nline=p13line4\n"))
        cli("module reload res_digium_phone.so")
        expect_reconfigure(a, "reload, lines changed")
        time.sleep(0.3)
        text = log_since(pos)
        check("reload, lines changed: logs", "Phone user 'p13phone' setting reconfigure due to change in lines"
              in text and "Sending reconfigure to user p13phone" in text, text[-2000:])
        r = b.next_event(timeout=1)
        check("reload, lines changed: other phones untouched", r is None, r.describe() if r else "")

        write_conf(orig.replace("full_name=P13 Phone\nline=p13line\n", "full_name=P13 Phone\nline=p13line4\n")
                   .replace("[p13phone2]\ntype=phone\n", "[p13phone2-gone]\ntype=phone\n"))
        cli("module reload res_digium_phone.so")
        expect_reconfigure(b, "reload, phone removed")
        r = a.next_event(timeout=1)
        check("reload, phone removed: other phones untouched", r is None, r.describe() if r else "")
    finally:
        write_conf(orig)
        cli("module reload res_digium_phone.so")


def check_session_gone(ami, b):
    """A queued request and an event for a phone whose session was replaced
    by a new handshake from the same MAC."""
    ok, detail = authenticate(b, "p13phone2")
    check("p13phone2 located again", ok, detail)
    ex, key, pt = forward(b, "com.p13.hello", "json", {"gone": 1}, "p13phone2:2323")
    dpma_message(ami, key, "com.p13.hello", "json", pt, "session gone")
    b2 = new_phone(b.mac)                   # prunes b's session
    try:
        same("session gone: AMI response", ami.action("DPMAMessageResponse", ("RequestID", key),
                                                      ("Format", "json"), ("Response", "x")), resp("Failure"))
        same("session gone: no longer queued", queued(), [])
        r = reply_of(b, ex, timeout=1)
        check("session gone: nothing sent", r is None, r.describe() if r else "")
        pos = log_size()
        same("Send: session gone", ami.action("DPMAMessageSend", ("PhoneName", "p13phone2"), ("Method", "e")),
             resp("Failure"))
        time.sleep(0.3)
        text = log_since(pos)
        check("Send: session gone logged", "Unable to send event to 'p13phone2' without session" in text, text)
    finally:
        b2.close()


def check_expiry(ami, a):
    ex, key, pt = forward(a, "com.p13.hello", "json", {"expire": 1}, "p13phone:1313")
    dpma_message(ami, key, "com.p13.hello", "json", pt, "expiry")
    print("     waiting 305 s for the expiry to be due ...", flush=True)
    for _ in range(61):
        time.sleep(5)
        a.ping()                            # keep the session active
    check("expiry: nothing runs the scheduler (still queued)", [k for k, *_ in queued()] == [key], repr(queued()))
    pos = log_size()
    out = cli("dpmadev ami runq")
    check("expiry: runq runs it", out.startswith("1 scheduled entries ran"), out)
    time.sleep(0.3)
    text = log_since(pos)
    check("expiry: logged", "No response to request (%s), expired." % key in text, text)
    same("expiry: no longer queued", queued(), [])
    same("expiry: later response fails", ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "json"),
                                                    ("Response", "x")), resp("Failure"))
    r = reply_of(a, ex, timeout=1)
    check("expiry: nothing sent", r is None, r.describe() if r else "")


def main():
    if not shutil.which("python3"):
        sys.exit("python3 not found")
    if "dpmadev ami queue" not in cli("core show help dpmadev ami"):
        sys.exit("needs a devtest build of res_digium_phone running in slot %s" % SLOT)
    ami = RawAmi(AMI_PORT)
    # Requests left queued by an earlier run never expire; answer them.
    for key, *_ in queued():
        ami.action("DPMAMessageResponse", ("RequestID", key), ("Format", "flush"))
    a = new_phone("000fd3001301")
    b = new_phone("000fd3001302")
    try:
        for phone, name in ((a, "p13phone"), (b, "p13phone2")):
            ok, detail = authenticate(phone, name)
            check("%s located (%s)" % (name, ARGS.via), ok, detail)
        check_actions(ami)
        check_forwarding(ami, a)
        check_send(ami, a)
        check_reconfigure(ami, a, b)
        check_reload(a, b)
        check_session_gone(ami, b)
        if ARGS.expiry:
            check_expiry(ami, a)
    finally:
        a.close()
        b.close()
    print("%d failure(s)" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
