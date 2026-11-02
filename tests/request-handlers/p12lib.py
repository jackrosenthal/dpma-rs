"""Shared plumbing of the P12 (request handlers) end-to-end scripts:
checks, the simulator, AMI, the instance's log and configuration, and
the documents the decompile builds (message errors, XML and JSON request
errors, the HTTP wrapper of AsteriskResponse)."""
import io
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "sim"))
from ami import AmiClient  # noqa: E402
from dpma_sim import Options, Phone, method_request  # noqa: E402

SLOT = int(os.environ.get("DPMA_SLOT", "0"))
if not SLOT:
    sys.exit("DPMA_SLOT is not set")
INST = os.path.join(ROOT, "dev", "run", "slot%d" % SLOT)
CONF = os.path.join(INST, "etc", "asterisk", "res_digium_phone.conf")
MSGLOG = os.path.join(INST, "var", "log", "asterisk", "messages.log")
FILES = os.path.join(INST, "var", "lib", "asterisk", "p12_files")
VERBOSE = "-v" in sys.argv

GLOBALPIN = "344486"
MAC_A = "000fd3001201"
MAC_BAD = "000fd30012ff"
HTTP = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n"

USER, PIN, GLOBAL, MAC, ULGLOBAL = 1, 2, 4, 8, 16
MODES = {
    "mac": MAC, "pin": USER | PIN, "globalpin": USER | GLOBAL, "mac_pin": USER | PIN | MAC,
    "mac_globalpin": USER | GLOBAL | MAC, "disabled": USER,
}

MSG_TEXT = {
    -98: "The file requested was not found",
    -192: "User Config token presented is invalid",
    -195: "Specfied user not found",
    -198: "An Invalid configuration password was provided",
}
RQ_TEXT = {
    10001: "Your request was empty",
    10002: "Error parsing request",
    10003: "Missing method name",
    10005: "Method not found",
    10011: "Parameters not found",
    99999: "Authentication failed for this request",
}

ami = None
checks = 0
failures = []


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

def check(name, ok, detail=""):
    global checks
    checks += 1
    if ok:
        print("ok   %s" % name)
    else:
        failures.append(name)
        print("FAIL %s%s" % (name, ("\n     " + detail.replace("\n", "\n     ")) if detail else ""))


def same(name, got, want):
    check(name, got == want, "got:  %r\nwant: %r" % (got, want))


def cli(cmd):
    return "\n".join(ami.command(cmd))


def log_mark():
    return os.path.getsize(MSGLOG) if os.path.exists(MSGLOG) else 0


def log_since(mark):
    """The log written since `mark` (all of it when the file was started
    again, as "ast.sh start" does)."""
    time.sleep(0.2)
    with open(MSGLOG, errors="replace") as f:
        if os.path.getsize(MSGLOG) >= mark:
            f.seek(mark)
        return f.read()


def logged(name, mark, text):
    log = log_since(mark)
    check(name, text in log, "not in the log: %r" % text)


def set_general(**kv):
    """Rewrite [general] of res_digium_phone.conf with `kv` (None removes a
    key) and reload the module.  Sessions keep the flags they were created
    with, so callers handshake again afterwards."""
    with open(CONF) as f:
        lines = f.read().split("\n")
    out, in_general = [], False
    for ln in lines:
        s = ln.strip()
        if s.startswith("["):
            in_general = s.lower().startswith("[general]")
            out.append(ln)
            if in_general:
                out += ["%s=%s" % (k, v) for k, v in kv.items() if v is not None]
            continue
        key = s.split("=", 1)[0].strip().lower()
        if in_general and "=" in s and key in kv:
            continue
        out.append(ln)
    with open(CONF, "w") as f:
        f.write("\n".join(out))
    cli("module reload res_dpma_rs.so")
    time.sleep(0.5)


def phone(mac=MAC_A, **kw):
    """A simulated phone with a fresh session."""
    p = Phone(Options(slot=SLOT, mac=mac, **kw), out=sys.stdout if VERBOSE else io.StringIO())
    p.start()
    ex = p.handshake()
    if not ex.ok:
        raise SystemExit("handshake failed:\n" + ex.describe())
    return p


def msg_error_body(code):
    return ('<error msg="%s" />' % MSG_TEXT[code]).encode()


def expect(name, ex, rtype, error=None, body=None):
    """Check a reply: its response type, Error-ID (a message error code or
    None), and payload (bytes, a compiled regex, or None for any)."""
    r = ex.reply
    if r is None:
        check(name, False, "no reply")
        return None
    problems = list(r.problems)
    if r.response_type != rtype:
        problems.append("type %r, wanted %r" % (r.response_type, rtype))
    got_err = None if r.error in (None, "", "0") else int(r.error)
    if got_err != error:
        problems.append("error %r, wanted %r" % (got_err, error))
    if not r.encrypted:
        problems.append("reply not encrypted")
    want = msg_error_body(error) if error is not None and body is None else body
    if isinstance(want, bytes) and r.payload != want:
        problems.append("payload %r\n     wanted  %r" % (r.payload[:600], want[:600]))
    elif isinstance(want, re.Pattern) and not want.search(r.payload):
        problems.append("payload %r does not match %r" % (r.payload[:600], want.pattern))
    check(name, not problems, "\n".join(problems))
    return r


def json_error(method, code, detail):
    doc = {"response": {"method": method, "errors": {"error": {
        "code": code, "message": "%s: %s " % (RQ_TEXT[code], detail)}}}}
    return json.dumps(doc, separators=(",", ":")).encode()


def xml_error(method, code):
    return ('<response method="%s">\r\n<errors>\r\n<error code="%d" message="%s" />\r\n'
            '</errors>\r\n</response>\r\n' % (method, code, RQ_TEXT[code])).encode()


def http(doc):
    return HTTP + (doc + b"\r\n\r\n" if doc else b"")


def token_hash(s):
    h = 5381
    for c in (s or "blah").encode():
        h = ((h * 33) ^ c) & 0xffffffff
    return h & 0x7fffffff


def session_line(sid):
    for ln in cli("digium_phones show sessions").splitlines():
        if ln.startswith("SessionID:%s " % sid):
            return ln
    return ""


def configured(sid):
    m = re.search(r"Configured: (\w+)", session_line(sid))
    return m.group(1) if m else None


def incidents():
    res = ami.action("DPMAShowIncidents")
    return {e.get("IPAddress"): e for e in res.events if e.get("Event") == "DPMAShowIncidentsList"}


def clear_incidents():
    for ip in incidents():
        ami.action("DPMARemoveIncident", IPAddress=ip)



def connect():
    global ami
    ami = AmiClient(slot=SLOT)
    ami.connect()
    return ami


def summary():
    print("\n%d checks, %d failed" % (checks, len(failures)))
    for f in failures:
        print("  " + f)
    return 1 if failures else 0
