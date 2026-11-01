#!/usr/bin/env python3
"""End-to-end checks of P14: the dialplan applications DigiumControlPlayback
and DigiumVoicemailPlayback, `digium_phones show settings`, and the mDNS
announcement.

Needs a private instance prepared with dev/tests/apps-discovery/setup.sh,
a devtest build of res_digium_phone installed, and Asterisk running.  The
mDNS checks run only inside the private network namespace of netns.sh
(an instance whose only interface is lo), so that no announcement reaches
a real network; run.sh does all of this.  Exit status 0 when every check
passes.

- Applications: Local channels into extensions running each application
  (extensions_dpma_apps.conf), with DTMF sent from the other half; the
  result variables (CPLAYBACKSTATUS, CPLAYBACKSTOPKEY, CPLAYBACKOFFSET,
  VOICEMAIL_PLAYBACKSTATUS) are read back from AstDB.  DigiumControlPlayback
  is compared with Asterisk's own ControlPlayback on the same cases.
- `digium_phones show settings` for several [general] configurations,
  compared with the original's format strings.
- mDNS: the service, port, TXT records, and address for several
  configurations; announcements and goodbyes at reload, disable, unload,
  load, Asterisk shutdown, and startup (this restarts Asterisk); queries
  are legacy unicast (mdns_probe.py).
"""
import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "dev", "sim"))
sys.path.insert(0, HERE)
from ami import AmiClient  # noqa: E402
import mdns_probe  # noqa: E402

SLOT = int(os.environ.get("DPMA_SLOT", "0"))
if not SLOT:
    sys.exit("DPMA_SLOT is not set")
INST = os.path.join(ROOT, "dev", "run", "slot%d" % SLOT)
CONF = os.path.join(INST, "etc", "asterisk", "res_digium_phone.conf")
SPOOL = os.path.join(INST, "var", "spool", "asterisk", "voicemail")
MSGLOG = os.path.join(INST, "var", "log", "asterisk", "messages.log")
AST = os.path.join(ROOT, "dev", "tools", "ast.sh")
TONE = "dpma-apps-tone"
SERVICE = "_digiumproxy._udp.local"

ami = None
failures = []
checks = 0


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


def cli_raw(cmd):
    """A CLI command's exact output (through the control socket)."""
    env = dict(os.environ, DPMA_SLOT=str(SLOT))
    out = subprocess.run([AST, "cli", cmd], env=env, capture_output=True, text=True).stdout
    # The remote console's own notice inside a namespace without ethernet.
    return re.sub(r"(?m)^No ethernet interface found for seeding global EID.*\n", "", out)


def cli(cmd):
    return ami.command(cmd)


def log_mark():
    return os.path.getsize(MSGLOG) if os.path.exists(MSGLOG) else 0


def log_since(mark):
    with open(MSGLOG, errors="replace") as f:
        f.seek(mark)
        return f.read()


def esc(s):
    """An AMI Variable value: commas separate variables unless escaped."""
    return s.replace("\\", "\\\\").replace(",", "\\,")


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

def originate(app, tid, args, keys="", gap="1"):
    cli("database del dpma-apps %s" % tid)
    fields = [("Channel", "Local/%s@dpma-apps" % app), ("Context", "dpma-apps-keys"), ("Exten", "keys"),
              ("Priority", "1"), ("Async", "true"), ("Variable", "P14ID=%s" % tid),
              ("Variable", "P14ARGS=%s" % esc(args)), ("Variable", "P14KEYS=%s" % keys),
              ("Variable", "P14GAP=%s" % gap)]
    res = ami.action("Originate", fields)
    if res.response is None or res.response.get("Response") != "Success":
        check("originate %s" % tid, False, res.response.text() if res.response else "no response")


def results(tids, timeout=20):
    """{tid: (status, stopkey, offset, vm status)} once every test stored its result."""
    out, deadline = {}, time.time() + timeout
    while time.time() < deadline and len(out) < len(tids):
        for t in tids:
            if t in out:
                continue
            lines = cli("database get dpma-apps %s" % t)
            m = re.match(r"Value: (.*)", lines[0]) if lines else None
            if m:
                out[t] = tuple(m.group(1).split("|"))
        time.sleep(0.3)
    for t in tids:
        out.setdefault(t, None)
    return out


# (id, arguments, DTMF keys, gap between keys, comparable with ControlPlayback)
CPB_CASES = [
    ("play", TONE, "", "1", True),
    ("stop", TONE + ",,,,5", "5", "0.7", True),
    ("offset", TONE + ",,,,5,,,o(1500)", "5", "0.7", True),
    ("ff", TONE + ",1000,,,5", "#5", "0.5", True),
    ("rew", TONE + ",1000,,,5,,,o(2000)", "*5", "0.5", True),
    ("customkeys", TONE + ",1000,1,2,5", "15", "0.5", True),
    ("stopdefault", TONE + ",,,,#", "#", "0.7", True),
    ("stopinvalidff", TONE + ",,x,,#", "#", "0.7", True),
    ("restart", TONE + ",,,,5,,0", "05", "0.7", True),
    ("skipzero", TONE + ",abc,,,5", "#5", "0.3", True),
    ("missing", "dpma-apps-no-such-file", "", "1", True),
    ("noargs", "", "", "1", True),
    ("invalid", TONE + ",,x,y,z,w,v", "", "1", True),
    ("callback", TONE + ",1000,,,5,,,u", "#*5", "0.4", False),
]


def near(a, b, tol=120):
    try:
        return abs(int(a) - int(b)) <= tol
    except ValueError:
        return a == b


def test_controlplayback():
    cli("core set debug 1 res_digium_phone")
    mark = log_mark()
    for tid, args, keys, gap, _ in CPB_CASES:
        originate("dcp", "dcp-" + tid, args, keys, gap)
        originate("acp", "acp-" + tid, args, keys, gap)
    res = results(["dcp-" + c[0] for c in CPB_CASES] + ["acp-" + c[0] for c in CPB_CASES])
    log = log_since(mark)
    cli("core set debug 0 res_digium_phone")
    for tid, _, _, _, comparable in CPB_CASES:
        d, a = res["dcp-" + tid], res["acp-" + tid]
        check("DigiumControlPlayback %s ran" % tid, d is not None)
        if comparable and d is not None and a is not None:
            check("DigiumControlPlayback %s like ControlPlayback" % tid,
                  d[:2] == a[:2] and near(d[2], a[2]), "Digium: %r\nAsterisk: %r" % (d, a))
    want = {
        "play": ("SUCCESS", "", "-1", ""),
        "stop": ("USERSTOPPED", "5", None, ""),
        "stopdefault": ("USERSTOPPED", "#", None, ""),
        "stopinvalidff": ("USERSTOPPED", "#", None, ""),
        "missing": ("ERROR", "", "-1", ""),
        "noargs": ("", "", "", ""),
        "invalid": ("SUCCESS", "", "-1", ""),
        "callback": ("USERSTOPPED", "5", None, ""),
    }
    for tid, w in want.items():
        d = res["dcp-" + tid]
        got = None if d is None else tuple(x if w[i] is not None else None for i, x in enumerate(d))
        same("DigiumControlPlayback %s variables" % tid, got, w)
    d = res["dcp-offset"]
    check("DigiumControlPlayback o(1500) starts at 1.5 s", d is not None and 1500 < int(d[2]) < 2700, repr(d))
    same("usage logged without arguments",
         re.search(r"DPMA\[\d+\](\[[^]]*\])? apps.rs: DigiumControlPlayback requires an argument \(filename\)", log)
         is not None, True)
    # "invalid" has five invalid keys, "stopinvalidff" an invalid forward key.
    for what, count in (("Invalid fast forward key specified.", 2), ("Invalid rewind key specified.", 1),
                        ("Invalid stop specified.", 1), ("Invalid pause key specified.", 1),
                        ("Invalid restart key specified.", 1)):
        same("logged: %s" % what, log.count(what), count)
    same("debug: default keys", "Forward key = #, Rewind key = *" in log, True)
    same("debug: '#' used as the stop key: the empty forward key stays",
         "Forward key = , Rewind key = *" in log, True)
    same("debug: '#' used as the stop key: the invalid forward key stays NULL",
         "Forward key = (null), Rewind key = *" in log, True)
    same("debug: custom keys", "Forward key = 1, Rewind key = 2" in log, True)
    same("no panics", "Internal error (panic)" in log, False)


def leave_message():
    """Leave a message in 1001@default (the P9 dialplan); returns its id."""
    box = os.path.join(SPOOL, "default", "1001", "INBOX")
    before = set(os.listdir(box)) if os.path.isdir(box) else set()
    ami.action("Originate", Channel="Local/1001@dpma-vm-leave", Context="dpma-vm-source", Exten="tone",
               Priority="1", CallerID='"P14" <5551234>', Async="true")
    deadline = time.time() + 15
    while time.time() < deadline:
        now = set(os.listdir(box)) if os.path.isdir(box) else set()
        new = sorted(f for f in now - before if f.endswith(".txt"))
        for f in new:
            text = open(os.path.join(box, f), errors="replace").read()
            m = re.search(r"^msg_id=(.*)$", text, re.M)
            if m and "duration=" in text:
                return m.group(1)
        time.sleep(0.2)
    return None


def test_vm_playback():
    msg_id = leave_message()
    check("message left for 1001", msg_id is not None)
    if msg_id is None:
        return
    mark = log_mark()
    cases = [
        ("vm-noargs", "", ""),
        ("vm-nomsg", "1001@default,INBOX", ""),
        ("vm-emptyfolder", "1001@default,,%s" % msg_id, ""),
        ("vm-ok", "1001@default,INBOX,%s" % msg_id, ""),
        ("vm-nocontext", "1001,INBOX,%s" % msg_id, ""),
        ("vm-bad", "1001@default,INBOX,no-such-id", ""),
        ("vm-keys", "1001@default,INBOX,%s" % msg_id, "#*"),
        ("vm-pause", "1001@default,INBOX,%s" % msg_id, "00"),
    ]
    for tid, args, keys in cases:
        originate("vmp", tid, args, keys, "0.4")
    res = results([c[0] for c in cases])
    log = log_since(mark)
    want = {
        "vm-noargs": ("", "", "", ""),
        "vm-nomsg": ("", "", "", ""),
        "vm-emptyfolder": ("", "", "", ""),
        "vm-ok": ("", "", "", "SUCCESS"),
        "vm-nocontext": ("", "", "", "SUCCESS"),
        "vm-bad": ("", "", "", "FAILED"),
        "vm-keys": ("", "", "", "SUCCESS"),
        "vm-pause": ("", "", "", "SUCCESS"),
    }
    for tid, w in want.items():
        same("DigiumVoicemailPlayback %s" % tid, res[tid], w)
    same("usage logged three times",
         log.count("DigiumVoicemailPlayback requires arguments (mailbox|folder|message)"), 3)
    same("no panics", "Internal error (panic)" in log, False)


def test_applications_registered():
    for app in ("DigiumControlPlayback", "DigiumVoicemailPlayback"):
        out = cli_raw("core show application %s" % app)
        same("core show application %s" % app, "-= Info about Application '%s' =-" % app in out, True)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ORIGINAL_CONF = None


def set_general(options):
    """Replace the [general] section of res_digium_phone.conf and reload."""
    text = ORIGINAL_CONF
    body = "".join("%s=%s\n" % kv for kv in options)
    text = re.sub(r"(?ms)^\[general\]\n.*?(?=^\[)", "[general]\n" + body + "\n", text, count=1)
    with open(CONF, "w") as f:
        f.write(text)
    cli("module reload res_digium_phone.so")


def restore_conf():
    with open(CONF, "w") as f:
        f.write(ORIGINAL_CONF)
    cli("module reload res_digium_phone.so")


FILE_DIR = os.path.join(INST, "var", "lib", "asterisk", "digium_phones")


def settings_text(uuid="<Not Set>", pin="<Set>", discovery="Disabled", name="Digium Phone Config Server",
                  addr="<Not Set>", port="5060", userlist="disabled", config="mac globalpin", fw="<Not Set>",
                  files=FILE_DIR, context="dpma_pjsip_message_context", delay="5"):
    return ("---- Digium Phone Module Global Settings ---- \n"
            "Server UUID: %s\nGlobalPin: %s\nService Discovery: %s\nService Disc. Name: %s\n"
            "Service Disc. Addr: %s\nService Disc. Port: %s\nUserlist Authentication: %s\n"
            "Config Authentication: %s\nFirmware Package Directory: %s\nFile Directory: %s\n"
            "PJSIP message context: %s\nMessage Delay: %s ms\n"
            % (uuid, pin, discovery, name, addr, port, userlist, config, fw, files, context, delay))


def test_show_settings(discovery_ok):
    base = [("globalpin", "344486"), ("userlist_auth", "disabled"), ("config_auth", "mac_globalpin"),
            ("service_discovery_enabled", "no")]
    set_general(base)
    same("show settings: test configuration", cli_raw("digium_phones show settings"), settings_text())
    same("show settings takes extra words", cli_raw("digium_phones show settings now"), settings_text())

    set_general([("server_uuid", "1c0ffee0-p14"), ("userlist_auth", "globalpin"), ("config_auth", "mac"),
                 ("mdns_address", "10.1.2.3"), ("mdns_port", "5070"), ("mdns_transport", "tcp"),
                 ("service_name", "P14 Settings"), ("firmware_package_directory", "/tmp/p14fw"),
                 ("file_directory", "/tmp/p14files"), ("pjsip_message_context", "p14ctx"),
                 ("message_delay", "25"), ("service_discovery_enabled", "yes" if discovery_ok else "no")])
    same("show settings: everything set, config_auth=mac", cli_raw("digium_phones show settings"),
         settings_text(uuid="1c0ffee0-p14", pin="<Not Set>", discovery="Enabled" if discovery_ok else "Disabled",
                       name="P14 Settings", addr="10.1.2.3", port="5070", userlist="globalpin", config="mac ",
                       fw="/tmp/p14fw/", files="/tmp/p14files", context="p14ctx", delay="25"))

    set_general([("config_auth", "pin"), ("registration_address", "10.9.9.9"), ("registration_port", "5099"),
                 ("mdns_port", "123456789012"), ("service_discovery_enabled", "no"), ("message_delay", "0")])
    same("show settings: config_auth=pin, registration address, long port", cli_raw("digium_phones show settings"),
         settings_text(pin="<Not Set>", addr="10.9.9.9", port="123456789", config="pin", delay="0"))

    set_general([("config_auth", "mac_pin"), ("registration_port", "5098"), ("service_name", ""),
                 ("service_discovery_enabled", "no")])
    same("show settings: config_auth=mac_pin, registration port", cli_raw("digium_phones show settings"),
         settings_text(pin="<Not Set>", port="5098", config="mac pin"))

    set_general([("config_auth", "disabled"), ("service_discovery_enabled", "no"), ("globalpin", "1")])
    same("show settings: config_auth=disabled", cli_raw("digium_phones show settings"),
         settings_text(config="disabled"))

    set_general([("config_auth", "globalpin"), ("service_discovery_enabled", "no")])
    same("show settings: config_auth=globalpin", cli_raw("digium_phones show settings"),
         settings_text(pin="<Not Set>", config="globalpin"))
    same("show version", cli_raw("digium_phones show version"), "dpma-rs version 0.1.0\n")


# ---------------------------------------------------------------------------
# mDNS
# ---------------------------------------------------------------------------

def isolated():
    """True inside a network namespace whose only interface is lo."""
    try:
        out = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True).stdout
    except OSError:
        return False
    names = [l.split(":")[1].strip() for l in out.splitlines() if ":" in l]
    return names == ["lo"] and "MULTICAST" in out


def host_name():
    return os.uname().nodename.split(".")[0] + "-dpma.local."


def wait_browse(pred, timeout=8.0):
    """Browse until pred(result) holds; returns the last result."""
    deadline, found = time.time() + timeout, {}
    while time.time() < deadline:
        found = mdns_probe.browse(SERVICE, wait=0.5)
        if pred(found):
            return found
        time.sleep(0.3)
    return found


def ptrs(records, ttl_zero):
    """Instance labels in PTR records for the service (goodbyes or not)."""
    return {mdns_probe.instance_label(r["target"], SERVICE) for r in records
            if r["type"] == "PTR" and r["name"].rstrip(".") == SERVICE and (r["ttl"] == 0) == ttl_zero}


def asterisk_mdns_sockets():
    out = subprocess.run(["ss", "-ulnp"], capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if ":5353 " in l and "asterisk" in l]


def test_mdns():
    global ami
    lst = mdns_probe.Listener()
    try:
        # Announce with every option set.
        mark = lst.mark()
        set_general([("service_discovery_enabled", "yes"), ("mdns_address", "10.1.2.3"), ("mdns_port", "5070"),
                      ("mdns_transport", "tcp"), ("service_name", "P14 Test Server")])
        found = wait_browse(lambda f: "P14 Test Server" in f)
        same("mDNS: one instance", sorted(found), ["P14 Test Server"])
        inst = found.get("P14 Test Server", {})
        same("mDNS: port", inst.get("port"), 5070)
        same("mDNS: TXT records", inst.get("txt"),
             ["serviceType=asterisk", "sipUrl=sip:proxy@10.1.2.3:5070;transport=tcp"])
        same("mDNS: SRV target", inst.get("target"), host_name())
        same("mDNS: target addresses (A, AAAA)", inst.get("addresses"), ["127.0.0.1", "::1"])
        time.sleep(1.5)
        same("mDNS: announced (unsolicited)", "P14 Test Server" in ptrs(lst.since(mark), False), True)
        types = mdns_probe.query("_services._dns-sd._udp.local", "PTR", wait=0.7)
        same("mDNS: service type enumeration", [r["target"] for r in types if r["type"] == "PTR"],
             [SERVICE + "."])
        same("mDNS: one responder socket set", len(asterisk_mdns_sockets()) > 0, True)

        # Reload with another name and no address: goodbye, then the new one.
        mark = lst.mark()
        set_general([("service_discovery_enabled", "yes"), ("service_name", "P14 Renamed")])
        found = wait_browse(lambda f: "P14 Renamed" in f)
        same("mDNS reload: only the new instance", sorted(found), ["P14 Renamed"])
        inst = found.get("P14 Renamed", {})
        same("mDNS reload: default port", inst.get("port"), 5060)
        same("mDNS reload: TXT without sipUrl", inst.get("txt"), ["serviceType=asterisk"])
        time.sleep(1.5)
        recs = lst.since(mark)
        same("mDNS reload: goodbye for the old name", "P14 Test Server" in ptrs(recs, True), True)
        same("mDNS reload: new name announced", "P14 Renamed" in ptrs(recs, False), True)

        # Same configuration again: withdrawn and announced again (as Avahi's group reset).
        mark = lst.mark()
        cli("module reload res_digium_phone.so")
        time.sleep(3)
        recs = lst.since(mark)
        same("mDNS unchanged reload: goodbye", "P14 Renamed" in ptrs(recs, True), True)
        same("mDNS unchanged reload: announced again", "P14 Renamed" in ptrs(recs, False), True)

        # Port arithmetic, registration address fallback, and a long sipUrl.
        long_addr = "h" * 300
        set_general([("service_discovery_enabled", "yes"), ("service_name", "P14 Port"),
                     ("registration_address", "10.7.7.7"), ("mdns_port", "70000")])
        found = wait_browse(lambda f: "P14 Port" in f)
        inst = found.get("P14 Port", {})
        same("mDNS: port 70000 & 0xffff", inst.get("port"), 70000 & 0xffff)
        same("mDNS: registration_address as mdns_address", inst.get("txt"),
             ["serviceType=asterisk", "sipUrl=sip:proxy@10.7.7.7:70000"])
        set_general([("service_discovery_enabled", "yes"), ("service_name", "P14 Long"),
                     ("mdns_address", long_addr), ("mdns_transport", "udp")])
        found = wait_browse(lambda f: "P14 Long" in f)
        txt = found.get("P14 Long", {}).get("txt") or []
        want = ("sipUrl=sip:proxy@%s:5060;transport=udp" % long_addr)[:255]
        same("mDNS: sipUrl cut to 255 bytes", txt, ["serviceType=asterisk", want])

        # Names Avahi refuses are not announced; 63 bytes is the limit.
        set_general([("service_discovery_enabled", "yes"), ("service_name", "N" * 64)])
        time.sleep(2)
        same("mDNS: 64-byte name not announced", mdns_probe.browse(SERVICE, wait=0.7), {})
        set_general([("service_discovery_enabled", "yes"), ("service_name", "N" * 63)])
        found = wait_browse(lambda f: "N" * 63 in f)
        same("mDNS: 63-byte name announced", sorted(found), ["N" * 63])
        set_general([("service_discovery_enabled", "yes"), ("service_name", "P14 dotted.name")])
        found = wait_browse(lambda f: "P14 dotted.name" in f)
        same("mDNS: name with a dot", sorted(found), ["P14 dotted.name"])

        # Disabled: goodbye, no answers, no socket.
        mark = lst.mark()
        set_general([("service_discovery_enabled", "no"), ("service_name", "P14 Off")])
        time.sleep(1.5)
        same("mDNS disabled: goodbye", "P14 dotted.name" in ptrs(lst.since(mark), True), True)
        same("mDNS disabled: nothing announced", mdns_probe.browse(SERVICE, wait=0.7), {})
        same("mDNS disabled: no responder socket", asterisk_mdns_sockets(), [])

        # Unload and load the module (with the PJSIP helpers that need it).
        set_general([("service_discovery_enabled", "yes"), ("service_name", "P14 Lifecycle")])
        wait_browse(lambda f: "P14 Lifecycle" in f)
        helpers = ["res_pjsip_dialog_info_digium_body_supplement.so", "res_pjsip_endpoint_identifier_dpma.so"]
        mark = lst.mark()
        # (AMI's Command refuses "module load" and "module unload".)
        for m in helpers + ["res_digium_phone.so"]:
            same("unload %s" % m, cli_raw("module unload %s" % m), "Unloaded %s\n" % m)
        time.sleep(1.5)
        same("mDNS unload: goodbye", "P14 Lifecycle" in ptrs(lst.since(mark), True), True)
        same("mDNS unload: nothing announced", mdns_probe.browse(SERVICE, wait=0.7), {})
        same("mDNS unload: no responder socket", asterisk_mdns_sockets(), [])
        mark = lst.mark()
        for m in ["res_digium_phone.so"] + helpers[::-1]:
            same("load %s" % m, cli_raw("module load %s" % m), "Loaded %s\n" % m)
        found = wait_browse(lambda f: "P14 Lifecycle" in f)
        same("mDNS load: announced again", sorted(found), ["P14 Lifecycle"])
        time.sleep(1)
        same("mDNS load: unsolicited announcement", "P14 Lifecycle" in ptrs(lst.since(mark), False), True)
        # Again: the responder was started from the AMI session's thread
        # (the reload above), which keeps the module's image mapped after
        # an unload; the loader's dlclose must still succeed every time
        # (crates/res_digium_phone/glue/module.c).
        pos = log_mark()
        for m in helpers + ["res_digium_phone.so"]:
            same("unload %s again" % m, cli_raw("module unload %s" % m), "Unloaded %s\n" % m)
        for m in ["res_digium_phone.so"] + helpers[::-1]:
            same("load %s again" % m, cli_raw("module load %s" % m), "Loaded %s\n" % m)
        wait_browse(lambda f: "P14 Lifecycle" in f)
        for m in helpers + ["res_digium_phone.so"]:
            cli_raw("module unload %s" % m)
        for m in ["res_digium_phone.so"] + helpers[::-1]:
            cli_raw("module load %s" % m)
        time.sleep(0.5)
        failed = [l for l in log_since(pos).split("\n") if "Failure in dlclose" in l]
        same("unload and load twice more: dlclose succeeds", failed, [])

        # Asterisk shutdown and startup (discovery enabled in the file).
        ami.close()
        env = dict(os.environ, DPMA_SLOT=str(SLOT))
        mark = lst.mark()
        subprocess.run([AST, "stop"], env=env, capture_output=True)
        time.sleep(2)
        same("mDNS shutdown: goodbye", "P14 Lifecycle" in ptrs(lst.since(mark), True), True)
        mark = lst.mark()
        subprocess.run([AST, "start"], env=env, capture_output=True)
        ami = AmiClient(slot=SLOT)
        ami.connect()
        found = wait_browse(lambda f: "P14 Lifecycle" in f, timeout=15)
        same("mDNS startup: announced", sorted(found), ["P14 Lifecycle"])
        time.sleep(1)
        same("mDNS startup: unsolicited announcement", "P14 Lifecycle" in ptrs(lst.since(mark), False), True)
    finally:
        lst.close()


def main():
    global ami, ORIGINAL_CONF
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-apps", action="store_true")
    ap.add_argument("--skip-mdns", action="store_true")
    a = ap.parse_args()
    discovery_ok = isolated()
    with open(CONF) as f:
        ORIGINAL_CONF = f.read()
    ami = AmiClient(slot=SLOT)
    ami.connect()
    try:
        test_applications_registered()
        if not a.skip_apps:
            test_controlplayback()
            test_vm_playback()
        test_show_settings(discovery_ok)
        if a.skip_mdns:
            pass
        elif discovery_ok:
            test_mdns()
        else:
            print("skip mDNS checks: not inside netns.sh's network namespace")
    finally:
        restore_conf()
        ami.close()
    print("\n%d checks, %d failed" % (checks, len(failures)))
    for f in failures:
        print("  " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
