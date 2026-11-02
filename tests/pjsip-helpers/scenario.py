#!/usr/bin/env python3
"""Scenarios for the module's PJSIP side (the original's two helper
modules), run against a private instance ($DPMA_SLOT) prepared with
setup.sh and res_dpma_rs built with the `devtest` feature.  Prints a
transcript that does not depend on ports, addresses, tags, thread ids, or
times, so it can be compared with the expected one (check.sh).

    scenario.py identifier [--no-aor-update]
        The endpoint identifier side (res_pjsip_endpoint_identifier_dpma):
        lines filled from pjsip.conf, res_pjsip reloads, ARI-driven
        endpoint/auth/AOR observers, REGISTER handling, the
        endpoint-is-dphone function, SIP INFO, MESSAGE identification and
        pjsip_message_context changes (config hook), unload/load cycles,
        and, last, an AOR update while a line has no endpoint (crashes the
        original; --no-aor-update skips it).
    scenario.py dialog-info
        The dialog-info supplement
        (res_pjsip_dialog_info_digium_body_supplement): NOTIFY bodies for
        dialog subscriptions from Digium and other user agents while calls
        ring (early) and ring while in use, with plain and restricted
        caller ID.
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SLOT = int(os.environ.get("DPMA_SLOT", "0"))
if not SLOT:
    sys.exit("set DPMA_SLOT (never use the shared install)")
INST = os.path.join(ROOT, "dev", "run", "slot%d" % SLOT)
ETC = os.path.join(INST, "etc", "asterisk")
LOG = os.path.join(INST, "var", "log", "asterisk", "messages.log")
SIP_PORT = 15060 + 100 * SLOT
HTTP_PORT = 15088 + 100 * SLOT
AST = os.path.join(ROOT, "tools", "ast.sh")
SIPUA = [sys.executable, "-I", os.path.join(HERE, "sipua.py"), "127.0.0.1", str(SIP_PORT)]
DIGIUM_UA = "Digium D65 2_9_17"
DPMA = "res_dpma_rs.so"


def out(text=""):
    print(text, flush=True)


def step(title):
    out()
    out("== " + title)


def norm(text):
    text = re.sub(r"0x[0-9a-f]{6,}", "0xADDR", text)
    text = re.sub(r"127\.0\.0\.1:\d+", "127.0.0.1:PORT", text)
    text = re.sub(r"(PJSIP|Local)/([\w@-]+?)-[0-9a-f]{8}(;\d)?", r"\1/\2-ID\3", text)
    return text


def ast(cmd, quiet=False):
    r = subprocess.run([AST, "cli", cmd], capture_output=True, text=True, env=dict(os.environ, DPMA_SLOT=str(SLOT)))
    text = norm(r.stdout.rstrip("\n"))
    if not quiet:
        out("> " + cmd)
        for line in text.split("\n"):
            if line:
                out("  " + line)
    return text


def alive():
    r = subprocess.run([AST, "cli", "core show uptime"], capture_output=True, text=True,
                       env=dict(os.environ, DPMA_SLOT=str(SLOT)))
    return "uptime" in r.stdout.lower()


class Log:
    """New lines of messages.log, filtered and normalized."""

    KEEP = re.compile(r"res_pjsip_endpoint_identifier_dpma|res_pjsip_dialog_info_digium|Reconfiguring triggered|P11 probe")

    def __init__(self):
        self.pos = 0
        self.mark()

    def mark(self):
        try:
            self.pos = os.path.getsize(LOG)
        except OSError:
            self.pos = 0

    def show(self, keep=None):
        time.sleep(0.3)
        try:
            with open(LOG, errors="replace") as f:
                f.seek(self.pos)
                lines = f.read().split("\n")
        except OSError:
            lines = []
        self.mark()
        keep = keep or self.KEEP
        for line in lines:
            if not keep.search(line):
                continue
            line = re.sub(r"^\[[^\]]*\] (\w+)\[\d+\](\[[^\]]*\])? ", r"\1 ", line)
            line = re.sub(r"(\w+\.(c|rs)):\d+ ", r"\1 ", line)
            out("  log: " + norm(line))


def sipua(*args, timeout=30):
    r = subprocess.run(SIPUA + list(args), capture_output=True, text=True, timeout=timeout)
    for line in (r.stdout + r.stderr).strip().split("\n"):
        if line:
            out("  " + norm(line))


def background(*args):
    return subprocess.Popen(SIPUA + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def collect(p, label):
    try:
        text, _ = p.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        p.kill()
        text, _ = p.communicate()
    for line in text.strip().split("\n"):
        if line:
            out("  %s: %s" % (label, norm(line)))


def lines(*names):
    for n in names:
        text = ast("dpmadev pjsip line %s" % n, quiet=True)
        out("line %s:" % n)
        for line in text.split("\n"):
            # The object's own reference count depends on who holds it.
            line = re.sub(r"^object 0xADDR name ", "name ", line)
            if line:
                out("  " + line)


def ari(method, path, fields=None):
    url = "http://127.0.0.1:%d/ari/asterisk/config/dynamic/res_pjsip/%s" % (HTTP_PORT, path)
    data = json.dumps({"fields": [{"attribute": k, "value": v} for k, v in fields]}).encode() if fields else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Basic " + base64.b64encode(b"p11:p11test").decode())
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except OSError as e:
        code = "error %s" % e
    out("  ARI %s %s: %s" % (method, path, code))
    time.sleep(1)


def edit(path, old, new):
    with open(path) as f:
        text = f.read()
    with open(path, "w") as f:
        f.write(text.replace(old, new))


def set_message_context(context):
    path = os.path.join(ETC, "res_digium_phone.conf")
    with open(path) as f:
        text = f.read()
    text = re.sub(r"\npjsip_message_context=dpma-p11-test\n", "\n", text)
    if context:
        text = text.replace("[general]\n", "[general]\npjsip_message_context=%s\n" % context, 1)
    with open(path, "w") as f:
        f.write(text)


def channel(prefix):
    text = subprocess.run([AST, "cli", "core show channels concise"], capture_output=True, text=True,
                          env=dict(os.environ, DPMA_SLOT=str(SLOT))).stdout
    for line in text.split("\n"):
        name = line.split("!", 1)[0]
        if name.startswith(prefix):
            return name
    return None


def forget_contacts():
    """Drop the contacts earlier runs left in AstDB (they survive restarts)."""
    ast("database deltree registrar", quiet=True)


def identifier(aor_update=True):
    log = Log()
    log.pos = 0
    forget_contacts()
    step("load")
    ast("module show like %s" % DPMA)
    log.show()
    lines("2001", "2002", "2003", "2004", "2005")

    step("res_pjsip reload with changed endpoint and auth")
    conf = os.path.join(ETC, "pjsip_p11.conf")
    edit(conf, 'callerid="Phone One" <2001>', 'callerid="Phone One B" <2001>')
    edit(conf, "password=pw2001\n", "password=pw2001b\n")
    ast("module reload res_pjsip.so")
    time.sleep(2)
    log.show()
    lines("2001")
    edit(conf, 'callerid="Phone One B" <2001>', 'callerid="Phone One" <2001>')
    edit(conf, "password=pw2001b\n", "password=pw2001\n")
    ast("module reload res_pjsip.so")
    time.sleep(2)
    log.show()
    lines("2001")

    step("observers through ARI push configuration")
    ari("PUT", "endpoint/2005", [("context", "p11-phones"), ("allow", "!all,ulaw"), ("aors", "2005"),
                                 ("auth", "2005-auth"), ("callerid", '"ARI Five" <2005>')])
    log.show()
    lines("2005")
    ari("PUT", "auth/2005-auth", [("auth_type", "userpass"), ("username", "ari5"), ("password", "pw2005")])
    log.show()
    lines("2005")
    ari("PUT", "endpoint/2005", [("callerid", '"ARI Five B" <2005>')])
    log.show()
    lines("2005")
    ari("PUT", "auth/2005-auth", [("password", "pw2005b")])
    log.show()
    lines("2005")
    ari("PUT", "aor/2005", [("mailboxes", "2005@default")])
    log.show()
    lines("2005")
    ari("PUT", "endpoint/2005", [("mailboxes", "")])
    log.show()
    lines("2005")
    ari("DELETE", "auth/2005-auth")
    log.show()
    lines("2005")
    ari("DELETE", "endpoint/2005")
    log.show()
    lines("2005")

    step("REGISTER")
    ast("core set debug 2 res_dpma_rs", quiet=True)
    ast("dpmadev pjsip lastinfo clear", quiet=True)
    sipua("register", "2001", "pw2001", DIGIUM_UA)
    sipua("register", "2002", "pw2002", "Acme Phone 1.0")
    time.sleep(1)
    log.show()
    ast("dpmadev pjsip lastinfo")
    for e in ("2001", "2002", "2003", "2004", "nonexistent"):
        ast("dpmadev pjsip isdphone %s" % e)
    # Phone 2001 again (contact replaced); 2002 is not a phone but now has
    # a Sangoma contact as well.
    sipua("register", "2001", "pw2001", "Sangoma P370 2.0")
    sipua("register", "2002", "pw2002", "Sangoma P330 1.0")
    time.sleep(1)
    log.show()
    ast("dpmadev pjsip lastinfo")
    ast("dpmadev pjsip isdphone 2002")
    ast("core set debug 0 res_dpma_rs", quiet=True)

    step("SIP INFO")
    p = background("uas", "2001", "pw2001", DIGIUM_UA, "8", "--answer", "1")
    time.sleep(1.5)
    ast("channel originate PJSIP/2001 application Wait 5")
    time.sleep(1)
    chan = channel("PJSIP/2001-")
    out("  channel: %s" % norm(str(chan)))
    if chan:
        ast('dpmadev pjsip info %s {"location":5}' % chan)
        ast("dpmadev pjsip info %s" % chan)
    ast("channel originate Local/2002@p11-phones application Wait 2")
    time.sleep(0.5)
    local = channel("Local/2002@p11-phones-")
    if local:
        ast("dpmadev pjsip info %s {}" % local)
    collect(p, "uas")
    ast("hangup request all", quiet=True)

    step("MESSAGE identification and pjsip_message_context")
    for exten in ("proxy", "probe"):
        sipua("message", exten, "--digium-ua", DIGIUM_UA)
        sipua("message", exten)
    log.show()
    set_message_context("dpma-p11-test")
    ast("module reload %s" % DPMA)
    time.sleep(1)
    for exten in ("proxy", "probe"):
        sipua("message", exten, "--digium-ua", DIGIUM_UA)
    log.show()
    set_message_context(None)
    ast("module reload %s" % DPMA)
    time.sleep(1)
    sipua("message", "probe", "--digium-ua", DIGIUM_UA)
    log.show()

    for i in (1, 2):
        step("unload and load %d" % i)
        ast("module unload %s" % DPMA)
        ast("module show like %s" % DPMA)
        ast("module load %s" % DPMA)
        ast("module show like %s" % DPMA)
        log.show()
        lines("2001", "2002")

    if aor_update:
        step("AOR update while line 2004 has no endpoint")
        ari("PUT", "endpoint/2005", [("context", "p11-phones"), ("allow", "!all,ulaw"), ("aors", "2005")])
        ari("PUT", "aor/2005", [("mailboxes", "2005@other")])
        time.sleep(1)
        out("  asterisk running: %s" % ("yes" if alive() else "NO"))
        if alive():
            log.show()
            lines("2005")
            ari("DELETE", "aor/2005")
            ari("DELETE", "endpoint/2005")


def dialog_info():
    log = Log()
    forget_contacts()
    step("dialog-info supplement")
    ast("core set debug 3 res_dpma_rs", quiet=True)
    uas = background("uas", "2002", "pw2002", "Acme Phone 1.0", "16", "--answer", "2")
    time.sleep(1)
    # (The supplement's "No domain in local uri" case cannot happen with
    # Asterisk 24: a subscription's local URI is the Request-URI with the
    # resource as its user.)
    subs = [
        ("digium", background("subscribe", "2001", "pw2001", DIGIUM_UA, "2002", "15")),
        ("other", background("subscribe", "2001", "pw2001", "Acme Phone 1.0", "2002", "15")),
    ]
    time.sleep(1.5)
    out("-- ringing (early), Carol Caller <3003>")
    ast("channel originate Local/3002@p11-phones application Wait 3")
    time.sleep(1.5)
    ast("hangup request all", quiet=True)
    time.sleep(1.5)
    out("-- answered (in use), then a restricted call rings (ringing while in use)")
    ast("channel originate Local/3002@p11-phones application Wait 8")
    time.sleep(1.5)
    ast("channel originate Local/3012@p11-phones application Wait 3")
    time.sleep(2)
    ast("hangup request all", quiet=True)
    for label, p in subs:
        collect(p, label)
    collect(uas, "uas")
    log.show()
    ast("core set debug 0 res_dpma_rs", quiet=True)


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else ""
    if what == "identifier":
        identifier("--no-aor-update" not in sys.argv)
    elif what == "dialog-info":
        dialog_info()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
