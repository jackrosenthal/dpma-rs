#!/usr/bin/env python3
"""Compare the CLI and AMI output of dpma-rs's res_digium_phone with the
original binary's, byte for byte, for every command and action that
needs no connected phone.

    DPMA_SLOT=<n> python3 -I dev/tests/parity/run.py [-v] [--keep DIR]
        [--original DIR] [--capture ours|original] [--compare A B]

Without --capture or --compare, the script stops the instance, gives it a
fresh configuration (ast.sh reset-conf) and the test configuration below,
and then, for each module: installs it (ours: "ast.sh install"; the
original: res_digium_phone.so and its two PJSIP helpers copied from
--original, default res_digium_phone-24.0_3.6.13-x86_64/), starts
Asterisk, captures, and stops Asterisk.  It ends by installing ours again
and comparing the captures.  The original binaries go into the private
instance only (DPMA_SLOT is required); never into the shared install.

The test configuration is dev/tests/config-xml's (phones, lines,
external lines, networks, applications, alerts, ringtones, firmware
profiles, multicast pages, and a firmware package file) plus two
translation tables.

Captured, each to its own file in the capture directory:
- "core show help digium_phones" and every command's usage;
- every digium_phones command: each list, each object of the
  configuration by name, an unknown name, and wrong argument counts;
  show status for every phone; reconfigure for a phone without a
  session, an unknown phone, and all;
- "manager show command" for each AMI action, and each action's raw
  response and events (DPMAShowPhones, DPMAShowIncidents,
  DPMARemoveIncident, DigiumPhoneReconfigure(All), and the DPMAMessage*
  actions where no phone is involved).

Each item is reported as "same", "DIFF" (with both outputs),
"deviation" (a documented difference, plan section 8: show version and
license status), or "not in the original".  The original without a
license (no licenses under <astvardir>/licenses) loads disabled: it
registers only show settings, show version, and license status, and its
show settings crashes Asterisk because no configuration is loaded, so
that capture skips everything else ("not in the original").  Exit status
0 when nothing differs.

--capture ours|original captures the module currently running in the
instance into --keep DIR (no install, start, or configuration change);
--compare A B compares two capture directories.
"""
import argparse
import difflib
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../.."))
AST = os.path.join(ROOT, "dev/tools/ast.sh")
SLOT = os.environ.get("DPMA_SLOT")
if not SLOT:
    sys.exit("DPMA_SLOT is not set (never run this against the shared install)")
INST = os.path.join(ROOT, "dev/run/slot" + SLOT)
ETC = os.path.join(INST, "etc/asterisk")
MODDIR = os.path.join(INST, "lib/asterisk/modules")
AMI_PORT = 15038 + 100 * int(SLOT)
MODULES = ("res_digium_phone.so", "res_pjsip_endpoint_identifier_dpma.so",
           "res_pjsip_dialog_info_digium_body_supplement.so")

TRANSLATIONS = """
[p15-trans]
type=translation
INBOX=Neue
Old=Alte
Work=Arbeit

[p15-empty]
type=translation
"""

# Items that differ by design (plan section 8).
DEVIATIONS = {
    "cli: digium_phones show version": "section 8, item 5",
    "cli: digium_phones license status": "section 8, item 1",
    "help: digium_phones license status": "section 8, item 1",
}

ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
ap.add_argument("-v", "--verbose", action="store_true")
ap.add_argument("--keep", help="keep the captures in this directory")
ap.add_argument("--original", default=os.path.join(ROOT, "res_digium_phone-24.0_3.6.13-x86_64"))
ap.add_argument("--capture", choices=("ours", "original"))
ap.add_argument("--compare", nargs=2, metavar=("A", "B"))
ARGS = ap.parse_args()


def ast(*args, check=True):
    r = subprocess.run([AST] + list(args), capture_output=True, env=dict(os.environ, DPMA_SLOT=SLOT))
    if check and r.returncode != 0 and args[0] != "stop":
        sys.exit("ast.sh %s failed: %s" % (" ".join(args), r.stderr.decode(errors="replace")))
    return r.stdout


def cli(cmd):
    return ast("cli", cmd, check=False)


# ---------------------------------------------------------------------------
# A raw AMI client
# ---------------------------------------------------------------------------

class RawAmi:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", AMI_PORT), timeout=10)
        self.cond = threading.Condition()
        self.msgs = []
        f = self.sock.makefile("rb")
        f.readline()
        self.sock.settimeout(None)
        threading.Thread(target=self._reader, args=(f,), daemon=True).start()
        self.seq = 0
        r = self.action("Login", [("Username", "test"), ("Secret", "test")])
        if not r.startswith(b"Response: Success"):
            sys.exit("AMI login failed: %r" % r)

    def _reader(self, f):
        buf = b""
        while True:
            data = f.read1(65536)
            if not data:
                break
            buf += data
            while b"\r\n\r\n" in buf:
                msg, buf = buf.split(b"\r\n\r\n", 1)
                with self.cond:
                    self.msgs.append(msg + b"\r\n\r\n")
                    self.cond.notify_all()

    def action(self, name, fields=(), timeout=3.0):
        """The raw response and, for list actions, the events up to the
        one with "EventList: Complete" (messages tagged with our
        ActionID)."""
        self.seq += 1
        aid = b"parity-%d" % self.seq
        text = b"Action: " + name.encode() + b"\r\nActionID: " + aid + b"\r\n"
        for k, v in fields:
            text += k.encode() + b": " + v.encode() + b"\r\n"
        self.sock.sendall(text + b"\r\n")
        tag = b"ActionID: " + aid + b"\r\n"
        got = []
        deadline = time.time() + timeout
        with self.cond:
            while time.time() < deadline:
                mine = [m for m in self.msgs if tag in m]
                for m in mine:
                    self.msgs.remove(m)
                    got.append(m)
                if got and b"EventList: start" not in got[0]:
                    break
                if any(b"EventList: Complete" in m for m in got):
                    break
                self.cond.wait(0.2)
        return b"".join(got)

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------------------
# Configuration and items
# ---------------------------------------------------------------------------

def install_config():
    ast("stop")
    ast("reset-conf")
    r = subprocess.run([os.path.join(ROOT, "dev/tests/config-xml/setup.sh")], capture_output=True,
                       env=dict(os.environ, DPMA_SLOT=SLOT))
    if r.returncode:
        sys.exit("config-xml/setup.sh failed")
    with open(os.path.join(ETC, "res_digium_phone.conf"), "a") as f:
        f.write(TRANSLATIONS)


def sections():
    """{type: [names]} of the instance's res_digium_phone.conf."""
    out, name = {}, None
    with open(os.path.join(ETC, "res_digium_phone.conf")) as f:
        for line in f:
            line = line.split(";", 1)[0].strip()
            m = re.match(r"^\[([^\]]+)\]", line)
            if m:
                name = m.group(1)
            elif name and name != "general" and re.match(r"^type\s*=", line):
                out.setdefault(line.split("=", 1)[1].strip(), []).append(name)
    return out


COMMANDS = ["show phones", "show lines", "show networks", "show alerts", "show multicastpages",
            "show applications", "show firmwares", "show sessions", "show tokens", "show translations",
            "show settings", "show version", "license status"]
PER_OBJECT = {"phone": ["phone"], "line": ["line", "external_line"], "network": ["network"],
              "alert": ["alert"], "multicastpage": ["multicastpage"], "application": ["application"],
              "firmware": ["firmware"], "translation": ["translation"], "status": ["phone"]}


def cli_items():
    s = sections()
    items = [("help: core show help digium_phones", "core show help digium_phones")]
    usage = sorted(set(COMMANDS) | {"show " + k for k in PER_OBJECT} | {"reconfigure phone", "reconfigure all"})
    items += [("help: digium_phones " + c, "core show help digium_phones " + c) for c in usage]
    items += [("cli: digium_phones " + c, "digium_phones " + c) for c in COMMANDS]
    for cmd, types in PER_OBJECT.items():
        names = [n for t in types for n in s.get(t, [])]
        if cmd == "network":
            names += s.get("phone", [])       # the networks named after phones
        for n in names + ["p15-nosuch"]:
            items.append(("cli: digium_phones show %s %s" % (cmd, n), "digium_phones show %s %s" % (cmd, n)))
        items.append(("cli: digium_phones show %s (no name)" % cmd, "digium_phones show %s" % cmd))
    items += [
        ("cli: digium_phones show phones extra", "digium_phones show phones extra"),
        ("cli: digium_phones show lines extra", "digium_phones show lines extra"),
        ("cli: digium_phones show phone two names", "digium_phones show phone minphone extra"),
        ("cli: digium_phones reconfigure phone minphone", "digium_phones reconfigure phone minphone"),
        ("cli: digium_phones reconfigure phone p15-nosuch", "digium_phones reconfigure phone p15-nosuch"),
        ("cli: digium_phones reconfigure phone (no name)", "digium_phones reconfigure phone"),
        ("cli: digium_phones reconfigure all", "digium_phones reconfigure all"),
    ]
    return items


AMI_ACTIONS = ["DPMAShowPhones", "DPMAShowIncidents", "DPMARemoveIncident", "DigiumPhoneReconfigure",
               "DigiumPhoneReconfigureAll", "DPMAMessageRegister", "DPMAMessageResponse", "DPMAMessageSend"]


def ami_items():
    items = [("ami-help: " + a, "manager show command " + a) for a in AMI_ACTIONS]
    items += [
        ("ami: DPMAShowPhones", "DPMAShowPhones", []),
        ("ami: DPMAShowIncidents", "DPMAShowIncidents", []),
        ("ami: DPMARemoveIncident (none)", "DPMARemoveIncident", []),
        ("ami: DPMARemoveIncident unknown", "DPMARemoveIncident", [("IPAddress", "192.0.2.99")]),
        ("ami: DigiumPhoneReconfigure minphone", "DigiumPhoneReconfigure", [("PhoneName", "minphone")]),
        ("ami: DigiumPhoneReconfigure unknown", "DigiumPhoneReconfigure", [("PhoneName", "p15-nosuch")]),
        ("ami: DigiumPhoneReconfigure (none)", "DigiumPhoneReconfigure", []),
        ("ami: DigiumPhoneReconfigureAll", "DigiumPhoneReconfigureAll", []),
        ("ami: DPMAMessageRegister (none)", "DPMAMessageRegister", []),
        ("ami: DPMAMessageRegister", "DPMAMessageRegister", [("Method", "com.p15.parity")]),
        ("ami: DPMAMessageResponse unknown", "DPMAMessageResponse",
         [("RequestID", "p15-nosuch"), ("Format", "json"), ("Response", "x")]),
        ("ami: DPMAMessageSend no session", "DPMAMessageSend",
         [("PhoneName", "minphone"), ("Method", "p15.event"), ("Message", "hello")]),
        ("ami: DPMAMessageSend unknown", "DPMAMessageSend", [("PhoneName", "p15-nosuch"), ("Method", "x")]),
    ]
    return items


def fname(item):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", item)


def capture(outdir, which):
    os.makedirs(outdir, exist_ok=True)
    help_text = cli("core show help digium_phones").decode(errors="replace")
    licensed = "digium_phones show phones" in help_text
    if not licensed:
        print("%s: only %d digium_phones commands registered (the original without a license)"
              % (which, help_text.count("digium_phones ") // 2))
    results = {}
    for item, cmd in cli_items():
        if not licensed and (item.startswith("cli: digium_phones show settings")
                             or not item.startswith(("help:", "cli: digium_phones show version",
                                                     "cli: digium_phones license status"))):
            results[item] = None
            continue
        results[item] = cli(cmd)
    ami = RawAmi()
    try:
        for it in ami_items():
            if len(it) == 2:
                results[it[0]] = cli(it[1])
            else:
                results[it[0]] = ami.action(it[1], it[2])
    finally:
        ami.close()
    for item, data in results.items():
        if data is not None:
            with open(os.path.join(outdir, fname(item)), "wb") as f:
                f.write(data)
    with open(os.path.join(outdir, "ITEMS"), "w") as f:
        f.write("\n".join(results) + "\n")
    with open(os.path.join(outdir, "LICENSED"), "w") as f:
        f.write("yes\n" if licensed else "no\n")


def unavailable(data, item=""):
    """Not captured, or the command or action does not exist ("manager
    show command" prints nothing for an unknown action)."""
    if item.startswith("ami-help:") and data == b"":
        return True
    return data is None or re.match(rb"No such command '|No manager action |Response: Error\r\n"
                                    rb"(ActionID: [^\r]*\r\n)?Message: Invalid/unknown command", data) is not None


def compare(a, b):
    with open(os.path.join(a, "ITEMS")) as f:
        items = [l for l in f.read().split("\n") if l]
    licensed = open(os.path.join(b, "LICENSED")).read().strip() == "yes"
    diffs = 0
    for item in items:
        ours, orig = (open(os.path.join(d, fname(item)), "rb").read()
                      if os.path.exists(os.path.join(d, fname(item))) else None for d in (a, b))
        subset = False
        if item == "help: core show help digium_phones" and not licensed and ours and orig:
            # Compare the commands the original registers without a
            # license (license status aside, section 8, item 1).
            have = {l.split(b" -- ")[0].strip() for l in orig.split(b"\n")}
            ours = b"\n".join(l for l in ours.split(b"\n") if l.split(b" -- ")[0].strip() in have)
            orig = b"\n".join(l for l in orig.split(b"\n") if not l.startswith(b"digium_phones license status"))
            subset = True
        if ours == orig:
            status = "same (registered subset)" if subset else "same"
        elif item in DEVIATIONS:
            status = "deviation (%s)" % DEVIATIONS[item]
        elif unavailable(orig, item):
            status = "not in the original"
        else:
            status = "DIFF"
            diffs += 1
        note = status.partition(" (")[2].rstrip(")")
        print("%-20s %s" % (status.split(" (")[0], item) + (" (%s)" % note if note else ""))
        if status == "DIFF" or (ARGS.verbose and status != "same"):
            for l in difflib.unified_diff((orig or b"").decode("utf-8", "replace").splitlines(True),
                                          (ours or b"").decode("utf-8", "replace").splitlines(True),
                                          "original", "ours", n=2):
                print("     " + l.rstrip("\n").replace("\r", "\\r"))
    print("%d difference(s)" % diffs)
    return diffs


def install_original():
    for m in MODULES:
        src = os.path.join(ARGS.original, m)
        dst = os.path.join(MODDIR, m)
        shutil.copyfile(src, dst + ".new")
        os.chmod(dst + ".new", 0o755)
        os.replace(dst + ".new", dst)


def main():
    if ARGS.compare:
        return 1 if compare(*ARGS.compare) else 0
    keep = ARGS.keep or tempfile.mkdtemp(prefix="dpma-parity.")
    if ARGS.capture:
        capture(os.path.join(keep, ARGS.capture), ARGS.capture)
        return 0
    install_config()
    try:
        for which in ("ours", "original"):
            ast("stop")
            if which == "ours":
                ast("install")
            else:
                install_original()
            ast("start")
            time.sleep(1)
            capture(os.path.join(keep, which), which)
            ast("stop")
    finally:
        ast("stop")
        ast("install")
    print("captures in %s" % keep)
    return 1 if compare(os.path.join(keep, "ours"), os.path.join(keep, "original")) else 0


if __name__ == "__main__":
    sys.exit(main())
