#!/usr/bin/env python3
"""Line locking stress test for the module's PJSIP side (the original's
endpoint identifier helper) and the rest of res_dpma_rs (devtest build),
in a private instance ($DPMA_SLOT) prepared with setup.sh and running.

    stress.py [SECONDS]

Phase 1 (SECONDS): ARI updates of auth 2005-auth (password pwA/pwB) and
endpoint 2005 (caller ID A/B) make the PJSIP side's sorcery observers rewrite
line 2005 on their own threads (clear seven settings, then set them),
while `dpmadev config 2003` reads the line's account from phone 2003's
configuration document over and over.  The document must always show a
complete line: password pwA or pwB, authname ari5, caller ID A or B.
Before readers took the line's ao2 lock, a read could land between the
clearing and the setting.

Phase 2 (SECONDS): the same plus res_dpma_rs and res_pjsip reloads
(full processing passes, also from a sorcery thread).  A pass has its own
intermediate states (as in the original), so only deadlocks are checked:
every CLI command must answer within 20 seconds.

Exit status 0 when both phases pass.
"""
import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SLOT = int(os.environ.get("DPMA_SLOT", "0"))
if not SLOT:
    sys.exit("set DPMA_SLOT (never use the shared install)")
AST = os.path.join(ROOT, "dev", "tools", "ast.sh")
HTTP_PORT = 15088 + 100 * SLOT
ENV = dict(os.environ, DPMA_SLOT=str(SLOT))

stop = threading.Event()
lock = threading.Lock()
stats = {"reads": 0, "bad": 0, "updates": 0, "reloads": 0, "timeouts": 0, "samples": []}


def ast(cmd):
    try:
        r = subprocess.run([AST, "cli", cmd], capture_output=True, text=True, env=ENV, timeout=20)
        return r.stdout
    except subprocess.TimeoutExpired:
        with lock:
            stats["timeouts"] += 1
        return None


def ari(method, path, fields):
    url = "http://127.0.0.1:%d/ari/asterisk/config/dynamic/res_pjsip/%s" % (HTTP_PORT, path)
    data = json.dumps({"fields": [{"attribute": k, "value": v} for k, v in fields]}).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Basic " + base64.b64encode(b"p11:p11test").decode())
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except Exception as e:  # noqa: BLE001 - counted, not fatal
        with lock:
            stats["timeouts"] += 1
        return str(e)


def updater(kind):
    i = 0
    while not stop.is_set():
        i += 1
        if kind == "auth":
            ari("PUT", "auth/2005-auth", [("password", "pwA" if i % 2 else "pwB")])
        else:
            ari("PUT", "endpoint/2005", [("callerid", '"%s" <2005>' % ("A" if i % 2 else "B"))])
        with lock:
            stats["updates"] += 1


ACCOUNT = re.compile(r'<account \n(?:[^<]*?)account_id="2005"(?P<rest>[^<]*?)/?>', re.S)


def reader(check):
    while not stop.is_set():
        text = ast("dpmadev config 2003")
        if text is None:
            continue
        m = ACCOUNT.search(text)
        rest = m.group("rest") if m else ""
        password = re.search(r'password="([^"]*)"', rest)
        authname = re.search(r'authname="([^"]*)"', rest)
        caller = re.search(r'caller_id="([^"]*)"', rest)
        got = (password and password.group(1), authname and authname.group(1), caller and caller.group(1))
        ok = got[0] in ("pwA", "pwB") and got[1] == "ari5" and got[2] in ("&quot;A&quot; &lt;2005&gt;",
                                                                        "&quot;B&quot; &lt;2005&gt;")
        with lock:
            stats["reads"] += 1
            if check and not ok:
                stats["bad"] += 1
                if len(stats["samples"]) < 5:
                    stats["samples"].append(got)


def reloader():
    i = 0
    while not stop.is_set():
        i += 1
        ast("module reload res_dpma_rs.so" if i % 2 else "module reload res_pjsip.so")
        with lock:
            stats["reloads"] += 1
        time.sleep(0.5)


def run(seconds, check, reloads):
    stop.clear()
    for k in ("reads", "bad", "updates", "reloads", "timeouts"):
        stats[k] = 0
    stats["samples"] = []
    threads = [threading.Thread(target=updater, args=("auth",)), threading.Thread(target=updater, args=("endpoint",))]
    threads += [threading.Thread(target=reader, args=(check,)) for _ in range(3)]
    if reloads:
        threads.append(threading.Thread(target=reloader))
    for t in threads:
        t.start()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join(60)
    alive = ast("core show uptime")
    return alive is not None and "uptime" in alive.lower()


def main():
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 20
    ari("PUT", "auth/2005-auth", [("auth_type", "userpass"), ("username", "ari5"), ("password", "pwA")])
    ari("PUT", "endpoint/2005", [("context", "p11-phones"), ("allow", "!all,ulaw"), ("aors", "2005"),
                                 ("auth", "2005-auth"), ("callerid", '"A" <2005>')])
    time.sleep(1)
    failed = False

    alive = run(seconds, True, False)
    print("phase 1: %(reads)d reads, %(bad)d incomplete, %(updates)d updates, %(timeouts)d timeouts" % stats)
    for s in stats["samples"]:
        print("  incomplete: password=%r authname=%r caller_id=%r" % s)
    failed |= not alive or stats["bad"] > 0 or stats["timeouts"] > 0 or stats["reads"] == 0

    alive = run(seconds, False, True)
    print("phase 2: %(reads)d reads, %(updates)d updates, %(reloads)d reloads, %(timeouts)d timeouts" % stats)
    failed |= not alive or stats["timeouts"] > 0

    print("asterisk responsive: %s" % ("yes" if alive else "NO"))
    try:
        urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:%d/ari/asterisk/config/dynamic/res_pjsip/endpoint/2005" % HTTP_PORT, method="DELETE",
            headers={"Authorization": "Basic " + base64.b64encode(b"p11:p11test").decode()}), timeout=10)
    except Exception:  # noqa: BLE001
        pass
    print("FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
