#!/usr/bin/env python3
"""End-to-end checks of the switchvox.users.voicemail.* methods (P9).

Needs a private instance prepared with tests/methods-vm/setup.sh, a
devtest build of res_dpma_rs installed, and Asterisk running:

    export DPMA_SLOT=<n>
    tests/methods-vm/setup.sh
    tools/ast.sh install && tools/ast.sh start
    python3 tests/methods-vm/run.py [--via hook|phone]

The script empties the test mailboxes, leaves messages with the dialplan
(Local channels into VoiceMail()), adds a few hand-made spool messages
for unusual caller ids, and then calls every method through
"dpmadev method call" (over AMI).  Each response is compared, as text,
with the document the original builds (key order included), computed
here from the spool and a model of the decompile; the spool and the
message trackers ("dpmadev vm trackers") are checked after each change.
Exit status 0 when every check passes.

With "--via phone" (package P12) the methods are called the way phones
call them instead: encrypted AsteriskRequests from the phone simulator
(tests/sim; run mkpki.py for the instance first, and leave out the
simulator's test identify, "install-conf.sh --remove": it would also catch
vm_uas.py's REGISTER, and the PJSIP helper identifies the simulator), with
the phone's name and pin as the credentials.  The reply body must be the
HTTP wrapper around the same document; return codes are not visible
that way, and calls for phones that cannot authenticate are skipped.
This mode also checks that a phone's new session (a TokenRequest after a
new handshake) drops its message trackers, and lists a page of 50 of 55
messages (a reply of many chunks).
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "sim"))
from ami import AmiClient  # noqa: E402

# How methods are called: "hook" ("dpmadev method call") or "phone".
VIA = sys.argv[sys.argv.index("--via") + 1] if "--via" in sys.argv[:-1] else "hook"
if VIA not in ("hook", "phone"):
    sys.exit("usage: run.py [--via hook|phone]")

SLOT = int(os.environ.get("DPMA_SLOT", "0"))
if not SLOT:
    sys.exit("DPMA_SLOT is not set")
INST = os.path.join(ROOT, "dev", "run", "slot%d" % SLOT)
SPOOL = os.path.join(INST, "var", "spool", "asterisk", "voicemail")
MSGLOG = os.path.join(INST, "var", "log", "asterisk", "messages.log")
SIP_PORT = 15060 + 100 * SLOT
VM = "switchvox.users.voicemail."

FOLDERS = ["INBOX", "Old", "Work", "Family", "Friends", "Cust1", "Cust2", "Cust3", "Cust4", "Cust5",
           "Deleted", "Urgent"]
CANONICAL = ["INBOX", "INBOX", "Work", "Family", "Friends", "Cust1", "Cust2", "Cust3", "Cust4", "Cust5",
             "Deleted", "INBOX"]
DE = {"INBOX": "Posteingang", "Work": "Arbeit", "Family": "Familie", "Recordings": "Aufnahmen"}
ERRTEXT = {
    10002: "Error parsing request",
    10011: "Parameters not found",
    10012: "Call to phone event application failed to complete",
    27168: "Your account is not permitted to run this action",
    64125: "Invalid mailbox folder",
}

ami = None
failures = []
checks = 0


def dump(o):
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False)


def check(name, ok, detail=""):
    global checks
    checks += 1
    if ok:
        print("ok   %s" % name)
    else:
        failures.append(name)
        print("FAIL %s%s" % (name, ("\n     " + detail.replace("\n", "\n     ")) if detail else ""))


def same(name, got, want):
    check(name, got == want, "got:  %s\nwant: %s" % (got, want))


def cli(cmd):
    return ami.command(cmd)


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


# --via phone: the simulated phone, and the pins of the test phones.
PINS = {"vmphone": "1234", "vmphone2": "2222", "vmphone3": "3333", "nomboxphone": "4444", "ghostphone": "5555"}
HTTP = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n"
sim = None
replies = []


def start_phone():
    """Handshake as vmphone and get a token, so the session is authenticated
    (and never pruned while the checks run)."""
    global sim
    import io
    from dpma_sim import Options, Phone
    if sim is None:
        sim = Phone(Options(slot=SLOT, mac="000fd3vm0001"), out=io.StringIO())
        sim.start()
    ex = sim.handshake()
    if not ex.ok:
        raise SystemExit("handshake failed:\n" + ex.describe())
    ex = sim.get_token(user="vmphone", config_password="344486")
    if not ex.ok:
        raise SystemExit("token failed:\n" + ex.describe())


def call_phone(phone, method, params):
    text = params if isinstance(params, str) else dump(params)
    doc = '{"request": {"method": "%s", "parameters": %s}}' % (VM + method, text)
    ex = sim.asterisk(doc, auth="%s:%s" % (phone, PINS[phone]), timeout=10)
    r = ex.reply
    if r is None or not r.ok:
        return None, "(no reply or a bad one: %s)" % ex.describe()
    replies.append(r)
    body = r.payload
    if not body.startswith(HTTP) or not body.endswith(b"\r\n\r\n"):
        return None, "(not wrapped: %r)" % body
    return None, body[len(HTTP):-4].decode("utf-8", "replace")


def call(phone, method, params):
    """Invoke a JSON method; returns (return code, response text).  The
    return code is None with --via phone."""
    if VIA == "phone":
        return call_phone(phone, method, params)
    text = params if isinstance(params, str) else dump(params)
    out = cli("dpmadev method call %s %s %s" % (phone, VM + method, esc(text)))
    m = re.match(r"Return code: (-?\d+)", out[0]) if out else None
    return (int(m.group(1)) if m else None), (out[-1] if out else "")


def err_doc(method, code, detail):
    return dump({"response": {"method": VM + method, "errors": {"error": {
        "code": code, "message": "%s: %s " % (ERRTEXT[code], detail)}}}})


def ok_doc(method, result):
    return dump({"response": {"method": VM + method, "result": result}})


def skipped(name, phone):
    """With --via phone, a phone that cannot authenticate cannot call."""
    if VIA == "phone" and phone not in PINS:
        print("skip %s (no credentials for %s)" % (name, phone))
        return True
    return False


def expect_error(name, phone, method, params, code, detail):
    if skipped(name, phone):
        return
    rc, body = call(phone, method, params)
    if VIA == "hook":
        same(name + " (code)", rc, -1)
    same(name, body, err_doc(method, code, detail))


def expect_ok(name, phone, method, params, result):
    if skipped(name, phone):
        return
    rc, body = call(phone, method, params)
    if VIA == "hook":
        same(name + " (code)", rc, 0)
    same(name, body, ok_doc(method, result))


def log_mark():
    return os.path.getsize(MSGLOG) if os.path.exists(MSGLOG) else 0


def log_since(mark):
    # Asterisk's logger writes from its own thread: give it a moment.
    time.sleep(0.3)
    with open(MSGLOG, errors="replace") as f:
        f.seek(mark)
        return f.read()


# ---------------------------------------------------------------------------
# Spool
# ---------------------------------------------------------------------------

def read_txt(path):
    d = {}
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            if "=" in line and not line.startswith(";"):
                k, v = line.rstrip("\n").split("=", 1)
                d[k] = v
    return d


def spool(box):
    """Messages of a mailbox ("default/1001"): folder -> [(msg number, fields)]."""
    res = {}
    for path in sorted(glob.glob(os.path.join(SPOOL, box, "*", "msg*.txt"))):
        folder = os.path.basename(os.path.dirname(path))
        num = int(re.search(r"msg(\d+)\.txt$", path).group(1))
        res.setdefault(folder, []).append((num, read_txt(path)))
    return res


def all_ids(box):
    return {f: [m["msg_id"] for _, m in msgs] for f, msgs in spool(box).items()}


def leave(exten, cid, context="dpma-vm-leave", box=None):
    """Leave a 2 s message through VoiceMail(); waits for it to be saved."""
    box = box or "default/" + exten
    before = sum(len(v) for v in spool(box).values())
    ami.action("Originate", Channel="Local/%s@%s" % (exten, context), Context="dpma-vm-source",
               Exten="tone", Priority="1", CallerID=cid, Async="true")
    deadline = time.time() + 15
    while time.time() < deadline:
        msgs = [m for v in spool(box).values() for _, m in v]
        if len(msgs) > before and all("duration" in m for m in msgs):
            time.sleep(1.1)  # distinct origtimes
            return
        time.sleep(0.2)
    raise SystemExit("message for %s was not saved" % exten)


def craft(box, folder, num, msg_id, callerid, origtime, origdate="Sat Jan  1 12:00:00 AM UTC 2022"):
    """A hand-made message (copies the sound of an existing one)."""
    d = os.path.join(SPOOL, box, folder)
    os.makedirs(d, exist_ok=True)
    wav = sorted(glob.glob(os.path.join(SPOOL, "default", "1001", "*", "msg*.wav")))[0]
    shutil.copy(wav, os.path.join(d, "msg%04d.wav" % num))
    with open(os.path.join(d, "msg%04d.txt" % num), "wb") as f:
        f.write(b";\n; Message Information file\n;\n[message]\norigmailbox=1001\ncontext=dpma-vm-leave\n"
                b"exten=1001\nrdnis=unknown\npriority=1\ncallerchan=Local/1001@dpma-vm-leave-0;2\n")
        f.write(b"callerid=" + callerid + b"\n")
        f.write(("origdate=%s\norigtime=%d\ncategory=\nmsg_id=%s\nflag=\nduration=2\n"
                 % (origdate, origtime, msg_id)).encode())


# ---------------------------------------------------------------------------
# A model of the decompile
# ---------------------------------------------------------------------------

def snapshot(box, folder=None, descending=False, by_time=False, combine=True):
    """app_voicemail's vm_mailbox_snapshot_create: 12 lists of messages
    (fields plus 'folder_name')."""
    sp = spool(box)
    lists = [[] for _ in FOLDERS]
    only = FOLDERS.index(folder) if folder else -1
    for i, name in enumerate(FOLDERS):
        if not (only == -1 or only == i or (only == 0 and combine and i in (1, 11))):
            continue
        idx = 0 if combine and i in (1, 11) else i
        for num, m in sp.get(name, []):
            msg = dict(m, folder_name=name, msg_number=num)
            lst = lists[idx]
            if not by_time:
                if descending:
                    lst.insert(0, msg)
                else:
                    lst.append(msg)
                continue
            for j, cur in enumerate(lst):
                val = (msg["origtime"] > cur["origtime"]) - (msg["origtime"] < cur["origtime"])
                if (descending and val >= 0) or (not descending and val <= 0):
                    lst.insert(j, msg)
                    break
            else:
                lst.append(msg)
    return lists


def parse_callerid(cid):
    """getList's caller id parsing; returns (number, name)."""
    cid = cid[:255]
    q = cid.find('"')
    if q < 0:
        name, rest = "", cid
    else:
        after = cid[q + 1:]
        q2 = after.find('"')
        if q2 >= 0:
            name, rest = after[:q2], after[q2 + 1:]
        else:
            name, rest = after, None
    num = rest or ""
    if num:
        lt = num.find("<")
        if lt >= 0:
            num = num[lt + 1:]
        gt = num.rfind(">")
        if gt >= 0:
            num = num[:gt]
    return num, name


def canonical(name):
    for i, f in enumerate(FOLDERS):
        if f.lower() == name.lower():
            return CANONICAL[i]
    return None


def getlist_doc(box, folder, shown, per_page=50, page=1, descending=False, by_time=False):
    lists = snapshot(box, "Cust5" if folder == "Recordings" else folder, descending, by_time)
    total = sum(len(x) for x in lists)
    on_page, cur, msgs, ids = 0, 1, [], []
    for m in (m for lst in lists for m in lst):
        if on_page < per_page:
            on_page += 1
        else:
            cur += 1
            on_page = 1
        if cur != page:
            continue
        mid = "%s-%s" % (canonical(m["folder_name"]) or "(null)", m["msg_id"])
        num, name = parse_callerid(m.get("callerid", ""))
        msgs.append({"id": mid, "caller_id": m.get("callerid", ""), "caller_id_number": num,
                     "caller_id_name": name, "date": m.get("origdate", ""), "date_UTC": m.get("origdate", ""),
                     "duration": m.get("duration", ""),
                     "read": "No" if m["folder_name"].lower() in ("inbox", "urgent") else "Yes"})
        ids.append((mid, m["folder_name"]))
    result = {"messages": {"folder": shown, "page_number": str(page), "total_pages": str(int(total / per_page) + 1),
                           "items_per_page": str(per_page), "total_items": str(total), "message": msgs}}
    return ok_doc("getList", result), ids


def trackers(phone):
    """The message trackers of a phone: [(id, folder)], or None."""
    out = cli("dpmadev vm trackers %s" % phone)
    if len(out) < 2:
        return None
    return [tuple(line.strip().split(" => ")) for line in out[2:]]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def setup_messages():
    for b in ("default/1001", "default/1002", "default/1003", "other/2001"):
        shutil.rmtree(os.path.join(SPOOL, b), ignore_errors=True)
    leave("1001", '"Alice Caller" <2005551212>')
    leave("1001", "2125551234")
    leave("1001", '"Bob Urgent" <3035550000>', context="dpma-vm-urgent")
    leave("1001", '"Carol" <4045550000>')
    leave("1002", '"Dave" <5055550000>')
    leave("o2001", '"Eve" <6065550000>', box="other/2001")
    # Unusual caller ids, in Friends (the order of the list is by number).
    craft("default/1001", "Friends", 0, "1640995200-0000f001", b"Name Only <7075550000>", 1640995200)
    craft("default/1001", "Friends", 1, "1640995201-0000f002", b'"Unclosed <123>', 1640995201)
    craft("default/1001", "Friends", 2, "1640995202-0000f003", b'""', 1640995202)
    craft("default/1001", "Friends", 3, "1640995203-0000f004", b'"Q" 555', 1640995203)
    craft("default/1001", "Friends", 4, "1640995204-0000f005", b"<8085550000>", 1640995204)
    craft("default/1001", "Friends", 5, "1640995205-0000f006", b"", 1640995205)
    # A caller id that is not UTF-8 (jansson refuses it).
    craft("default/1001", "Cust3", 0, "1640995300-0000c301", b'"Ren\xe9" <100>', 1640995300)


def test_folder_list():
    # Translated names; Old and Urgent count in INBOX; Recordings is Cust5.
    snap = snapshot("default/1001")
    counts = [len(x) for x in snap]
    names = [("INBOX", 0), ("Work", 2), ("Family", 3), ("Friends", 4), ("Recordings", 9)]
    folders = [{"name": DE.get(n, n), "count": str(counts[i])} for n, i in names]
    expect_ok("getFolderList translated", "vmphone", "getFolderList", {"account_id": "1001"},
              {"folders": {"folder": folders}})
    snap = snapshot("default/1002")
    folders = [{"name": n, "count": str(len(snap[i]))} for n, i in names]
    expect_ok("getFolderList plain", "vmphone2", "getFolderList", {"account_id": "1002"},
              {"folders": {"folder": folders}})
    expect_ok("getFolderList other context", "vmphone3", "getFolderList", {"account_id": "2001"},
              {"folders": {"folder": [{"name": n, "count": "1" if i == 0 else "0"} for n, i in names]}})
    expect_error("getFolderList no account_id", "vmphone", "getFolderList", {}, 10011, "account_id")
    expect_error("getFolderList account_id not a string", "vmphone", "getFolderList", {"account_id": 1001},
                 10011, "account_id")
    expect_error("getFolderList params not an object", "vmphone", "getFolderList", ["1001"], 10011, "account_id")
    expect_error("getFolderList line of another phone", "vmphone", "getFolderList", {"account_id": "1002"},
                 27168, "must have line with mailbox")
    expect_error("getFolderList line without mailbox", "vmphone", "getFolderList", {"account_id": "1003"},
                 27168, "must have line with mailbox")
    expect_error("getFolderList external line", "vmphone", "getFolderList", {"account_id": "ext1"},
                 27168, "must have line with mailbox")
    expect_error("getFolderList unknown phone", "nosuchphone", "getFolderList", {"account_id": "1001"},
                 27168, "must have line with mailbox")
    expect_error("getFolderList mailbox unknown to app_voicemail", "ghostphone", "getFolderList",
                 {"account_id": "1005"}, 64125, "could not create snapshot of 1005@default")


def test_get_list():
    want, ids = getlist_doc("default/1001", "INBOX", "Posteingang")
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "Posteingang"})
    same("getList INBOX via translated name", body, want)
    same("getList trackers", trackers("vmphone"), [tuple(x) for x in ids])

    want, _ = getlist_doc("default/1001", "INBOX", "Posteingang")
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
    same("getList INBOX shows translated folder", body, want)

    want, _ = getlist_doc("default/1001", "INBOX", "Posteingang", descending=True, by_time=True)
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX", "sort_order": "desc",
                                           "sort_field": "DATE"})
    same("getList INBOX newest first", body, want)

    want, _ = getlist_doc("default/1001", "INBOX", "Posteingang", descending=True)
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX", "sort_order": "DESC"})
    same("getList INBOX by id descending", body, want)

    want, ids = getlist_doc("default/1001", "INBOX", "Posteingang", per_page=3, page=2)
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX", "items_per_page": 3,
                                           "page_number": " 2xyz"})
    same("getList page 2 of 3 per page", body, want)
    same("getList trackers hold only the page", trackers("vmphone"), [tuple(x) for x in ids])

    want, _ = getlist_doc("default/1001", "INBOX", "Posteingang", per_page=2, page=1)
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX", "items_per_page": 2,
                                           "page_number": 2})
    same("getList integer page_number is ignored", body, want)

    want, _ = getlist_doc("default/1001", "INBOX", "Posteingang", per_page=-1, page=3)
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX", "items_per_page": -1,
                                           "page_number": "3"})
    same("getList negative items_per_page", body, want)

    want, _ = getlist_doc("default/1001", "Friends", "Friends")
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "Friends"})
    same("getList caller id forms", body, want)

    want, _ = getlist_doc("default/1001", "Recordings", "Aufnahmen")
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "Aufnahmen"})
    same("getList Recordings (empty) via translation", body, want)

    rc, body = call("vmphone2", "getList", {"account_id": "1002", "folder": "INBOX"})
    want, _ = getlist_doc("default/1002", "INBOX", "INBOX")
    same("getList without translation", body, want)

    expect_error("getList bad folder", "vmphone", "getList", {"account_id": "1001", "folder": "Bogus"},
                 64125, "could not create snapshot of 1001@default Bogus")
    expect_error("getList Recordings maps to Cust5 in the error", "ghostphone", "getList",
                 {"account_id": "1005", "folder": "Recordings"}, 64125,
                 "could not create snapshot of 1005@default Cust5")
    expect_error("getList non-UTF-8 caller id", "vmphone", "getList", {"account_id": "1001", "folder": "Cust3"},
                 10002, "message_entry")
    expect_error("getList no account_id", "vmphone", "getList", {"folder": "INBOX"}, 10011, "account_id")
    expect_error("getList no mailbox", "nomboxphone", "getList", {"account_id": "1004", "folder": "INBOX"},
                 27168, "must have line with mailbox")
    # Deviations (the original crashes): no folder, zero items_per_page.
    expect_error("getList no folder (deviation)", "vmphone", "getList", {"account_id": "1001"}, 10011, "folder")
    expect_error("getList items_per_page 0 (deviation)", "vmphone", "getList",
                 {"account_id": "1001", "folder": "INBOX", "items_per_page": 0}, 10011, "items_per_page")
    expect_error("getList items_per_page string (deviation)", "vmphone", "getList",
                 {"account_id": "1001", "folder": "INBOX", "items_per_page": "10"}, 10011, "items_per_page")


def inbox_ids(box="default/1001"):
    """(id as getList shows it, msg_id, real folder) of the combined INBOX, by number."""
    return [("INBOX-" + m["msg_id"], m["msg_id"], m["folder_name"]) for m in snapshot(box, "INBOX")[0]]


def test_mark():
    call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
    msgs = inbox_ids()
    plain = [x for x in msgs if x[2] == "INBOX"]
    urgent = [x for x in msgs if x[2] == "Urgent"][0]
    first = plain[0]

    expect_ok("markRead", "vmphone", "markRead", {"account_id": "1001", "message_ids": [first[0], 7, None]},
              {"success": {}})
    same("markRead moved the message to Old", first[1] in all_ids("default/1001").get("Old", []), True)
    tr = dict(trackers("vmphone"))
    same("markRead updated the tracker", tr.get(first[0]), "Old")
    expect_ok("markRead again (already Old)", "vmphone", "markRead",
              {"account_id": "1001", "message_ids": [first[0]]}, {"success": {}})
    expect_ok("markUnread", "vmphone", "markUnread", {"account_id": "1001", "message_ids": [first[0]]},
              {"success": {}})
    same("markUnread moved it back", first[1] in all_ids("default/1001").get("INBOX", []), True)
    same("markUnread updated the tracker", dict(trackers("vmphone")).get(first[0]), "INBOX")

    expect_ok("markRead an Urgent message", "vmphone", "markRead",
              {"account_id": "1001", "message_ids": [urgent[0]]}, {"success": {}})
    same("Urgent message is now Old", urgent[1] in all_ids("default/1001").get("Old", []), True)

    # An id with the translated folder name: tracker made from a snapshot.
    second = plain[1]
    alias = "Posteingang-" + second[1]
    expect_ok("markRead with a translated folder in the id", "vmphone", "markRead",
              {"account_id": "1001", "message_ids": [alias]}, {"success": {}})
    same("translated id moved", second[1] in all_ids("default/1001").get("Old", []), True)
    same("tracker for the translated id", dict(trackers("vmphone")).get(alias), "Old")
    expect_ok("markUnread with a translated folder in the id", "vmphone", "markUnread",
              {"account_id": "1001", "message_ids": [alias]}, {"success": {}})

    friends = all_ids("default/1001")["Friends"][0]
    mark = log_mark()
    expect_ok("markRead on Friends is refused but succeeds", "vmphone", "markRead",
              {"account_id": "1001", "message_ids": ["Friends-" + friends]}, {"success": {}})
    same("markRead on Friends logs", "Attempted to mark read/unread on Friends folder" in log_since(mark), True)
    same("Friends message not moved", friends in all_ids("default/1001")["Friends"], True)

    expect_error("markRead unknown message", "vmphone", "markRead",
                 {"account_id": "1001", "message_ids": ["INBOX-1-2"]}, 10002, "failed to find message")
    expect_error("markRead lower-case folder does not match", "vmphone", "markRead",
                 {"account_id": "1001", "message_ids": ["inbox-" + plain[2][1]]}, 10002, "failed to find message")
    expect_error("markRead id without dash", "vmphone", "markRead",
                 {"account_id": "1001", "message_ids": ["INBOX"]}, 10011, "message id")
    expect_error("markRead id ending in dash", "vmphone", "markRead",
                 {"account_id": "1001", "message_ids": ["INBOX-"]}, 10011, "message id")
    expect_error("markRead empty list", "vmphone", "markRead", {"account_id": "1001", "message_ids": []},
                 10011, "total_msgs")
    expect_error("markRead string instead of list", "vmphone", "markRead",
                 {"account_id": "1001", "message_ids": first[0]}, 10011, "total_msgs")
    expect_error("markRead no message_ids", "vmphone", "markRead", {"account_id": "1001"}, 10011, "message_ids")
    expect_error("markUnread no account_id", "vmphone", "markUnread", {"message_ids": []}, 10011, "account_id")
    expect_error("markRead null message_ids, no line", "nomboxphone", "markRead",
                 {"account_id": "1004", "message_ids": None}, 27168, "must have line with mailbox")


def test_move():
    call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
    msgs = [x for x in inbox_ids() if x[2] == "INBOX"]
    a, b = msgs[0], msgs[1]
    # Two messages to Work (translated as Arbeit).  The response ids come
    # from the original's reused buffer: the first gets the folder of the
    # last id parsed, the rest "(null)".
    expect_ok("move two to Arbeit", "vmphone", "move",
              {"account_id": "1001", "folder_from": "Posteingang", "folder_to": "Arbeit",
               "message_ids": [a[0], b[0]]},
              {"messages": {"message": [{"id": "INBOX-" + a[1], "old_id": "INBOX-" + a[1]},
                                        {"id": "(null)-" + b[1], "old_id": "(null)-" + b[1]}]}})
    work = all_ids("default/1001").get("Work", [])
    same("move: both in Work", sorted(work), sorted([a[1], b[1]]))
    same("move leaves trackers alone", dict(trackers("vmphone")).get(a[0]), "INBOX")

    # Stale trackers: the same ids now fail to move from INBOX.
    mark = log_mark()
    expect_error("move with stale trackers", "vmphone", "move",
                 {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Family", "message_ids": [a[0]]},
                 10011, "could not move message")
    same("move failure logs", "Could not move msgs from INBOX to Family" in log_since(mark), True)

    # getList of Work, then move one to Recordings (Cust5).
    call("vmphone", "getList", {"account_id": "1001", "folder": "Arbeit"})
    expect_ok("move to Recordings", "vmphone", "move",
              {"account_id": "1001", "folder_from": "Work", "folder_to": "Recordings",
               "message_ids": ["Work-" + a[1]]},
              {"messages": {"message": [{"id": "Work-" + a[1], "old_id": "Work-" + a[1]}]}})
    same("move: in Cust5", a[1] in all_ids("default/1001").get("Cust5", []), True)
    rc, body = call("vmphone", "getFolderList", {"account_id": "1001"})
    same("getFolderList counts the recording", '{"name":"Aufnahmen","count":"1"}' in body, True)
    want, _ = getlist_doc("default/1001", "Recordings", "Aufnahmen")
    rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "Aufnahmen"})
    same("getList Recordings", body, want)
    # "Recordings" is not a folder name, so the rebuilt id gets "(null)".
    expect_ok("move Recordings back to INBOX", "vmphone", "move",
              {"account_id": "1001", "folder_from": "Aufnahmen", "folder_to": "INBOX",
               "message_ids": ["Recordings-" + a[1]]},
              {"messages": {"message": [{"id": "(null)-" + a[1], "old_id": "(null)-" + a[1]}]}})
    expect_ok("move Work back to INBOX", "vmphone", "move",
              {"account_id": "1001", "folder_from": "Work", "folder_to": "INBOX",
               "message_ids": ["Work-" + b[1]]},
              {"messages": {"message": [{"id": "Work-" + b[1], "old_id": "Work-" + b[1]}]}})
    same("move: Work empty again", all_ids("default/1001").get("Work", []), [])

    mark = log_mark()
    call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
    c = [x for x in inbox_ids() if x[2] == "INBOX"][0]
    expect_error("move to an unknown folder", "vmphone", "move",
                 {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Bogus", "message_ids": [c[0]]},
                 10011, "could not move message")
    mark = log_mark()
    expect_error("move id without dash", "vmphone", "move",
                 {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": ["xyz"]},
                 10011, "id decode")
    same("move decode error logs", "ERROR decoding message id xyz" in log_since(mark), True)
    expect_error("move unknown message", "vmphone", "move",
                 {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": ["Work-1-2"]},
                 10002, "failed to find message")
    expect_error("move no folder_from", "vmphone", "move", {"account_id": "1001"}, 10011, "folder_from")
    expect_error("move no folder_to", "vmphone", "move", {"account_id": "1001", "folder_from": "INBOX"},
                 10011, "folder_to")
    expect_error("move no message_ids", "vmphone", "move",
                 {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work"}, 10011, "message_ids")
    expect_error("move empty list", "vmphone", "move",
                 {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": []},
                 10011, "total_msgs")
    expect_error("move line of another phone", "vmphone", "move",
                 {"account_id": "1002", "folder_from": "INBOX", "folder_to": "Work", "message_ids": []},
                 27168, "must have line with mailbox")
    expect_ok("move list of non-strings", "vmphone", "move",
              {"account_id": "1001", "folder_from": "INBOX", "folder_to": "Work", "message_ids": [1, {}]},
              {"messages": {"message": []}})


def test_forward():
    call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
    src = [x for x in inbox_ids() if x[2] == "INBOX"][0]
    before = len(all_ids("default/1002").get("INBOX", []))
    expect_ok("forward to another phone's line", "vmphone", "forward",
              {"account_from": "1001", "account_to": "1002", "folder": "INBOX", "message_ids": [src[0]]},
              {"success": {}})
    after = spool("default/1002").get("INBOX", [])
    same("forward: copy in 1002", len(after), before + 1)
    same("forward: original stays", src[1] in all_ids("default/1001")["INBOX"], True)
    same("forward: copy has the caller id", after[-1][1].get("callerid") if after else None,
         dict((m["msg_id"], m) for _, m in spool("default/1001")["INBOX"])[src[1]].get("callerid"))
    expect_ok("forward across contexts", "vmphone", "forward",
              {"account_from": "1001", "account_to": "2001", "folder": "x", "message_ids": [src[0]]},
              {"success": {}})
    same("forward: copy in other/2001", len(all_ids("other/2001").get("INBOX", [])), 2)
    expect_error("forward to a line without mailbox", "vmphone", "forward",
                 {"account_from": "1001", "account_to": "1003", "folder": "INBOX", "message_ids": [src[0]]},
                 27168, "to_mailbox")
    expect_error("forward to an unknown line", "vmphone", "forward",
                 {"account_from": "1001", "account_to": "nosuch", "folder": "INBOX", "message_ids": [src[0]]},
                 27168, "to_mailbox")
    mark = log_mark()
    expect_error("forward to a mailbox app_voicemail does not know", "vmphone", "forward",
                 {"account_from": "1001", "account_to": "1005", "folder": "INBOX", "message_ids": [src[0]]},
                 10011, "could not forward message")
    same("forward failure logs", "Could not forward msgs from 1001@default to 1005@default" in log_since(mark),
         True)
    expect_error("forward from a line of another phone", "vmphone", "forward",
                 {"account_from": "1002", "account_to": "1001", "folder": "INBOX", "message_ids": []},
                 27168, "must have line with mailbox")
    expect_error("forward no account_from", "vmphone", "forward", {}, 10011, "account_from")
    expect_error("forward no account_to", "vmphone", "forward", {"account_from": "1001"}, 10011, "account_to")
    expect_error("forward no folder", "vmphone", "forward", {"account_from": "1001", "account_to": "1002"},
                 10011, "folder")
    expect_error("forward no message_ids", "vmphone", "forward",
                 {"account_from": "1001", "account_to": "1002", "folder": "INBOX"}, 10011, "message_ids")
    expect_error("forward bad id", "vmphone", "forward",
                 {"account_from": "1001", "account_to": "1002", "folder": "INBOX", "message_ids": ["-"]},
                 10011, "message id")
    expect_error("forward empty list", "vmphone", "forward",
                 {"account_from": "1001", "account_to": "1002", "folder": "INBOX", "message_ids": []},
                 10011, "total_msgs")


def test_remove():
    call("vmphone2", "getList", {"account_id": "1002", "folder": "INBOX"})
    ids = inbox_ids("default/1002")
    expect_ok("remove", "vmphone2", "remove", {"account_id": "1002", "folder": "INBOX", "message_ids": [ids[0][0]]},
              {"success": {}})
    same("remove: gone from the spool", ids[0][1] in all_ids("default/1002").get("INBOX", []), False)
    same("remove: messages renumbered", [n for n, _ in spool("default/1002").get("INBOX", [])],
         list(range(len(ids) - 1)))
    expect_error("remove again (stale tracker)", "vmphone2", "remove",
                 {"account_id": "1002", "folder": "INBOX", "message_ids": [ids[0][0]]}, 10011,
                 "could not remove message")
    expect_error("remove unknown", "vmphone2", "remove",
                 {"account_id": "1002", "folder": "INBOX", "message_ids": ["INBOX-9-9"]}, 10002,
                 "failed to find message")
    expect_error("remove no folder", "vmphone2", "remove", {"account_id": "1002", "message_ids": []}, 10011,
                 "folder")
    expect_error("remove no message_ids", "vmphone2", "remove", {"account_id": "1002", "folder": "INBOX"},
                 10011, "message_ids")
    expect_error("remove empty list", "vmphone2", "remove",
                 {"account_id": "1002", "folder": "INBOX", "message_ids": []}, 10011, "total_msgs")
    expect_error("remove bad id", "vmphone2", "remove",
                 {"account_id": "1002", "folder": "INBOX", "message_ids": ["INBOX-"]}, 10011, "message id")
    expect_error("remove no account_id", "vmphone2", "remove", {}, 10011, "account_id")
    # Remove from Friends by id only (the folder parameter is only logged).
    f = all_ids("default/1001")["Friends"]
    expect_ok("remove ignores the folder parameter", "vmphone", "remove",
              {"account_id": "1001", "folder": "Familie", "message_ids": ["Friends-" + f[-1]]}, {"success": {}})
    same("remove: Friends message gone", f[-1] in all_ids("default/1001")["Friends"], False)


def run_uas(seconds, reject=False, dtmf=""):
    args = [sys.executable, os.path.join(HERE, "vm_uas.py"), "127.0.0.1", str(SIP_PORT), "1001", "secret1001",
            str(seconds)] + (["--reject"] if reject else []) + (["--dtmf", dtmf] if dtmf else [])
    p = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
    line = p.stdout.readline().strip()
    return p, line


def test_play():
    call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
    m = [x for x in inbox_ids() if x[2] == "INBOX"][0]
    cli("core set verbose 3")  # for file.c's "Playing" line
    p, first = run_uas(6, dtmf="#*")
    same("UAS registered", first, "registered")
    mark = log_mark()
    expect_ok("play", "vmphone", "play", {"account_id": "1001", "message_id": m[0]}, {"success": {}})
    out = p.communicate()[0].split("\n")
    cli("core set verbose 0")
    same("play: INVITE carries the event header", "invite X-Event-Name=digium.incomingCall.voicemail" in out, True)
    same("play: answered, then hung up", ["answered" in out, "bye" in out], [True, True])
    log = log_since(mark)
    # DigiumVoicemailPlayback (P14) plays the message with # and * as fast
    # forward and rewind, and reports each new position with an INFO.
    same("play: DigiumVoicemailPlayback runs on answer",
         "Could not find application (DigiumVoicemailPlayback)" in log, False)
    same("play: plays the message", "Playing '%s/default/1001/INBOX/msg" % SPOOL in log, True)
    keys = [x for x in out if x.startswith(("dtmf ", "info "))]
    same("play: fast forward and rewind keys sent", [x for x in keys if x.startswith("dtmf ")], ["dtmf #", "dtmf *"])
    infos = [x for x in keys if x.startswith("info ")]
    same("play: a location INFO for each key",
         [re.fullmatch(r"info X-Event-Name=digium\.voicemail\.play\.location\.change body=\{'location':\d+\}", x)
          is not None for x in infos], [True, True])

    p, first = run_uas(6, reject=True)
    mark = log_mark()
    expect_ok("play, phone busy", "vmphone", "play", {"account_id": "1001", "message_id": m[0]}, {"success": {}})
    p.communicate()
    time.sleep(0.5)
    want = "for DigiumVoicemailPlayback,1001@default,INBOX,%s was not answered" % m[1]
    same("play, busy: logged as not answered", want in log_since(mark), True)

    mark = log_mark()
    expect_error("play, phone not registered", "vmphone", "play", {"account_id": "1001", "message_id": m[0]},
                 10012, "channel could not run")
    same("play prerun failure logs", "Failed dialing to PJSIP/1001 (prerun)" in log_since(mark), True)
    expect_error("play Recordings id is not mapped", "vmphone", "play",
                 {"account_id": "1001", "message_id": "Recordings-" + m[1]}, 10002, "failed to find message")
    expect_error("play bad id", "vmphone", "play", {"account_id": "1001", "message_id": "INBOX"}, 10011,
                 "msg_id_decode")
    expect_error("play no message_id", "vmphone", "play", {"account_id": "1001"}, 10011, "message_id")
    expect_error("play no account_id", "vmphone", "play", {}, 10011, "account_id")
    expect_error("play not own line", "vmphone", "play", {"account_id": "1002", "message_id": m[0]}, 27168,
                 "must have line with mailbox")


def test_tracker_lifecycle():
    call("vmphone3", "getList", {"account_id": "2001", "folder": "INBOX"})
    same("vmphone3 has trackers", trackers("vmphone3") is not None and len(trackers("vmphone3")) == 2, True)
    conf = os.path.join(INST, "etc", "asterisk", "res_digium_phone.conf")
    text = open(conf).read()
    stripped = re.sub(r"\n; A mailbox in another voicemail context\.\n\[vmphone3\]\n(?:[^\[\n].*\n)*", "\n", text)
    with open(conf, "w") as f:
        f.write(stripped)
    try:
        cli("module reload res_dpma_rs.so")
        time.sleep(1)
        same("tracker removed with its phone", trackers("vmphone3"), None)
        same("other trackers kept", trackers("vmphone") is not None, True)
    finally:
        with open(conf, "w") as f:
            f.write(text)
        cli("module reload res_dpma_rs.so")
        time.sleep(1)
    cli("dpmadev vm forget vmphone")
    same("dpmadev vm forget", trackers("vmphone"), None)
    if VIA == "phone":
        # A new session for the phone (P8's phone_user_token_set_last_info)
        # drops its trackers.
        call("vmphone", "getList", {"account_id": "1001", "folder": "INBOX"})
        same("trackers before a new session", trackers("vmphone") is not None, True)
        start_phone()
        same("a new session drops the phone's trackers", trackers("vmphone"), None)


def test_big_list():
    """55 messages: getList pages of 50 (with --via phone, replies of many
    chunks)."""
    for i in range(55):
        craft("default/1001", "Cust2", i, "1641000000-0000b%03d" % i, b'"Big %d" <%d>' % (i, 9000 + i),
              1641000000 + i)
    try:
        before = len(replies)
        for page in (1, 2):
            want, ids = getlist_doc("default/1001", "Cust2", "Cust2", page=page)
            rc, body = call("vmphone", "getList", {"account_id": "1001", "folder": "Cust2",
                                                   "page_number": str(page)})
            same("getList 55 messages, page %d" % page, body, want)
            same("getList 55 messages, page %d trackers" % page, trackers("vmphone"), [tuple(x) for x in ids])
        if VIA == "phone":
            chunks = [len(r.parts) for r in replies[before:]]
            check("getList pages came in many chunks", len(chunks) == 2 and chunks[0] > 10, repr(chunks))
    finally:
        shutil.rmtree(os.path.join(SPOOL, "default", "1001", "Cust2"), ignore_errors=True)


def main():
    global ami
    ami = AmiClient(slot=SLOT)
    ami.connect()
    if VIA == "phone":
        start_phone()
    try:
        setup_messages()
        test_folder_list()
        test_get_list()
        test_mark()
        test_move()
        test_forward()
        test_remove()
        test_play()
        test_tracker_lifecycle()
        test_big_list()
    finally:
        ami.close()
        if sim is not None:
            sim.close()
    print("\n%d checks, %d failed" % (checks, len(failures)))
    for f in failures:
        print("  " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
