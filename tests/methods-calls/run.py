#!/usr/bin/env python3
"""Checks for the P10 call methods (queues, parking, recording, phonebook,
echo) against a private Asterisk instance.

    DPMA_SLOT=<n> python3 -I dev/tests/methods-calls/run.py [-v]

Prerequisites: a devtest build installed in the instance
(cargo build -p res_digium_phone --features devtest), the test setup
(dev/tests/methods-calls/setup.sh --original-helper), and Asterisk
running.  The methods are invoked through "dpmadev method call" (JSON)
and "dpmadev calls xml" (XML); the expected documents are the ones the
original's phone_method_internal_api.c builds.  Recording INFOs and the
parked call MESSAGE are checked with phone.py registered as 1001 (needs the
PJSIP helper for dpma_info_send and dpma_pjsip_endpoint_is_dphone).

Exit status 0 when every check passes.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../.."))
SLOT = os.environ.get("DPMA_SLOT")
if not SLOT:
    sys.exit("DPMA_SLOT is not set")
SIP_PORT = 15060 + 100 * int(SLOT)
INST = os.path.join(ROOT, "dev/run/slot" + SLOT)
FILES = os.path.join(INST, "var/lib/asterisk/digium_phones")
VERBOSE = "-v" in sys.argv
failures = 0


def cli(cmd):
    r = subprocess.run([os.path.join(ROOT, "dev/tools/ast.sh"), "cli", cmd], capture_output=True, text=True)
    return r.stdout


def quote(text):
    """Escape for the Asterisk CLI parser (backslashes and double quotes)."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace(" ", "\\ ")


def call(phone, method, params):
    out = cli(f"dpmadev method call {phone} {method} {quote(json.dumps(params))}")
    m = re.match(r"Return code: (-?\d+)\n(?:\(empty response body.*\n)?(.*)", out, re.S)
    if not m:
        return None, out
    body = "" if "(empty response body" in out else m.group(2).strip()
    return int(m.group(1)), body


def call_xml(phone, method, params):
    out = cli(f"dpmadev calls xml {phone} {method} {quote(params)}")
    m = re.match(r"Return code: (-?\d+)\n(.*)", out, re.S)
    if not m:
        return None, out
    return int(m.group(1)), m.group(2).rstrip("\n").replace("\\r", "\r").replace("\\n", "\n")


def check(name, ok, detail=""):
    global failures
    if ok:
        print("ok   " + name)
    else:
        failures += 1
        print("FAIL " + name + ("\n     " + detail if detail else ""))
    if VERBOSE and detail and ok:
        print("     " + detail)


def expect(name, got, code, doc):
    """`doc` is the expected compact JSON (a Python object) or a string."""
    rc, body = got
    want = doc if isinstance(doc, str) else json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    check(name, rc == code and body == want, f"return {rc} (want {code})\n     got  {body}\n     want {want}")


def ok(method, result):
    return {"response": {"method": method, "result": result}}


def err(method, code, message):
    return {"response": {"method": method, "errors": {"error": {"code": code, "message": message}}}}


def xml_err(method, code, text):
    return (f'<response method="{method}">\r\n<errors>\r\n<error code="{code}" message="{text}" />\r\n'
            "</errors>\r\n</response>\r\n")


def xml_ok(method):
    return f'<response method="{method}">\r\n<result>\r\n<success />\r\n</result>\r\n</response>\r\n'


def messages_since(mark):
    path = os.path.join(INST, "var/log/asterisk/messages.log")
    with open(path, errors="replace") as f:
        f.seek(mark)
        return f.read()


def log_mark():
    return os.path.getsize(os.path.join(INST, "var/log/asterisk/messages.log"))


Q = "switchvox.users.callQueues."
NOT_FOUND = "Parameters not found: %s "
SUCCESS = {"success": {}}


def reset():
    cli("channel request hangup all")
    for q, iface in (("p10sales", "Local/agent@p10test"), ("p10support", "Local/1001@p10test")):
        cli(f"queue remove member {iface} from {q}")
    cli("queue reset stats")
    for f in ("p10contacts.xml", "p10contacts2.xml"):
        shutil.copy(os.path.join(HERE, "conf", f), os.path.join(FILES, f))
    time.sleep(1)


def queues():
    m = Q + "getList"
    expect("getList: account_id required", call("p10phone", m, {}), -1, err(m, 10011, NOT_FOUND % "account_id"))
    mark = log_mark()
    expect("getList: nobody logged in", call("p10phone", m, {"account_id": "1001"}), 0, ok(m, {"callQueues": {"callQueue": [
        {"name": "p10sales", "account_id": "p10sales", "total_members": "0", "members_logged_in": "0", "callers_waiting": "0", "loggedin_status": "logged_out"},
        {"name": "p10support", "account_id": "p10support", "total_members": 0, "loggedin_status": "logged_out"},
        {"name": "p10static", "account_id": "p10static", "loggedin_status": "manager"},
        {"name": "p10ghost", "account_id": "p10ghost", "loggedin_status": "logged_out"}]}}))
    check("getList: missing application logged", "Failed to find application 'p10-nosuchapp'" in messages_since(mark))
    expect("getList: static member", call("p10phone2", m, {"account_id": "1002"}), 0, ok(m, {"callQueues": {"callQueue": [
        {"name": "p10static", "account_id": "p10static", "loggedin_status": "permanent", "total_members": "1", "members_logged_in": "1", "callers_waiting": "0"}]}}))

    m = Q + "login"
    expect("login: account_id required", call("p10phone", m, {"call_queue_account_id": "all"}), -1, err(m, 10011, NOT_FOUND % "account_id"))
    expect("login: call_queue_account_id required", call("p10phone", m, {"account_id": "1001"}), -1, err(m, 10011, NOT_FOUND % "call_queue_account_id"))
    mark = log_mark()
    expect("login all", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "ALL"}), 0, ok(m, SUCCESS))
    time.sleep(1)
    log = messages_since(mark)
    check("login: failure only logged", "Failed to add queue member Local/ghost@p10test to queue p10ghost" in log, log)
    show = cli("queue show")
    check("login: QueueAdd with member name", re.search(r"Alice P10 \(Local/agent@p10test\).*\(dynamic\)", show) is not None, show)
    check("login: login_exten dialed", "Local/1001@p10test" in show.split("p10support", 1)[1], show)

    m = Q + "pause"
    expect("pause: reason required", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "p10sales"}), -1, err(m, 10011, NOT_FOUND % "reason"))
    expect("pause p10sales", call("p10phone", m, {"account_id": "1001", "reason": "Lunch", "call_queue_account_id": "p10sales"}), 0, ok(m, SUCCESS))
    check("pause: reason sent", "paused:Lunch" in cli("queue show p10sales"))
    m = Q + "getList"
    rc, body = call("p10phone", m, {"account_id": "1001"})
    check("getList: paused member", rc == 0 and '{"name":"p10sales","account_id":"p10sales","paused_time":"1","loggedin_status":"logged_in","total_members":"1","members_logged_in":"0","callers_waiting":"0"}' in body, body)
    m = Q + "resume"
    expect("resume: call_queue_account_id required", call("p10phone", m, {"account_id": "1001"}), -1, err(m, 10011, NOT_FOUND % "call_queue_account_id"))
    expect("resume p10sales", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "p10sales"}), 0, ok(m, SUCCESS))
    check("resume: unpaused", "paused" not in cli("queue show p10sales"))

    # One caller connected to the agent, one waiting.
    cli("channel originate Local/caller@p10test application Wait 100")
    time.sleep(2)
    cli("channel originate Local/caller2@p10test application Wait 100")
    time.sleep(2)
    m = Q + "getTodaysStatus"
    rc, body = call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "P10SALES"})
    try:
        cq = json.loads(body)["response"]["result"]["callQueue"]
        member = cq["detailed_view"]["queue_members"]["queue_member"][0]
        caller = cq["detailed_view"]["waiting_callers"]["waiting_caller"][0]
        good = (rc == 0 and list(cq) == ["account_id", "name", "overview", "my_status", "detailed_view"]
                and cq["account_id"] == "P10SALES"
                and cq["overview"] == {"total_members": "1", "logged_in_count": "1", "members_on_call": "1", "callers_waiting": "1",
                                       "total_calls": "0", "completed_calls_today": "0", "abandoned_calls": "0",
                                       "redirected_calls": "0", "longest_queue_length": "0", "avg_entry_position": "0"}
                and cq["my_status"] == {"login_status": ""}
                and list(member) == ["loggedin_status", "call_duration", "fullname"] and member["fullname"] == "Alice P10"
                and int(member["call_duration"]) >= 1
                and list(caller) == ["talking_to_number", "talking_to_name", "position", "waiting_duration"]
                and caller["talking_to_number"] == "5552000" and caller["position"] == "1")
    except (ValueError, KeyError, IndexError, TypeError):
        good = False
    check("getTodaysStatus: details with a call and a waiting caller", good, body)
    expect("getTodaysStatus: overview permission", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "p10support"}), 0, ok(m, {"callQueue": {
        "account_id": "p10support", "name": "p10support", "overview": {"total_members": "1", "logged_in_count": "1", "members_on_call": "0",
        "callers_waiting": "0", "total_calls": "0", "completed_calls_today": "0", "abandoned_calls": "0", "redirected_calls": "0",
        "longest_queue_length": "0", "avg_entry_position": "0"}, "my_status": {"login_status": ""}}}))
    expect("getTodaysStatus: no application, no answer", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "nosuch"}), 0, "")
    expect("getTodaysStatus: no queue, no answer", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "p10ghost"}), 0, "")
    expect("getTodaysStatus: call_queue_account_id required", call("p10phone", m, {"account_id": "1001"}), -1, err(m, 10011, NOT_FOUND % "call_queue_account_id"))
    rc, body = call("p10phone", Q + "getList", {"account_id": "1001"})
    check("getList: callers waiting", '"callers_waiting":"1"' in body, body)

    # Abandon the waiting caller, complete the call.
    chans = cli("core show channels concise")
    for line in chans.splitlines():
        if line.startswith("Local/caller2@p10test") and ";2!" in line:
            cli("channel request hangup " + line.split("!")[0])
    time.sleep(1)
    cli("channel request hangup all")
    time.sleep(1)
    rc, body = call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "p10sales"})
    check("getTodaysStatus: completed and abandoned", '"total_calls":"2","completed_calls_today":"1","abandoned_calls":"1"' in body, body)

    m = Q + "logout"
    expect("logout: static member stays", call("p10phone2", m, {"account_id": "1002", "call_queue_account_id": "p10static"}), 0, ok(m, SUCCESS))
    check("logout: static member still there", "Static Bob" in cli("queue show p10static"))
    expect("logout all", call("p10phone", m, {"account_id": "1001", "call_queue_account_id": "all"}), 0, ok(m, SUCCESS))
    time.sleep(1)
    show = cli("queue show")
    check("logout: QueueRemove and logout_exten", "Local/agent@p10test" not in show and "Local/1001@p10test" not in show, show)
    mark = log_mark()
    call("p10phone", Q + "pause", {"account_id": "1001", "reason": "x", "call_queue_account_id": "p10sales"})
    check("pause: failure only logged", "Failed to pause queue member Local/agent@p10test on queue p10sales" in messages_since(mark))


def parking(phone_log):
    m = "switchvox.users.parkingLots.getList"
    lots = {"parking_lots": {"parking_lot": [
        {"account_id": "default", "parked_calls": {"parked_call": []}, "parking_lot_stop": "720", "timeout": "45", "parking_lot_start": "701"},
        {"account_id": "p10lot", "parked_calls": {"parked_call": []}, "parking_lot_stop": "810", "timeout": "300", "parking_lot_start": "801"}]}}
    expect("parkingLots.getList: empty lots", call("p10phone", m, {}), 0, ok(m, lots))
    cli("channel originate Local/parklot@p10test application Wait 100")
    cli("channel originate Local/park@p10test application Wait 100")
    time.sleep(3)
    rc, body = call("p10phone", m, {})
    try:
        got = json.loads(body)["response"]["result"]["parking_lots"]["parking_lot"]
        call0 = got[1]["parked_calls"]["parked_call"][0]
        good = (rc == 0 and got[0]["parked_calls"]["parked_call"] == []
                and list(call0) == ["from_caller_id_name", "from_caller_id_number", "duration", "lotnum", "current_call_id"]
                and call0["from_caller_id_name"] == "Lot Caller" and call0["from_caller_id_number"] == "5554000"
                and call0["lotnum"] == "801" and call0["current_call_id"].startswith("Local/parklot@p10test-"))
    except (ValueError, KeyError, IndexError, TypeError):
        good = False
    check("parkingLots.getList: only the lots of the phone's parking application", good, body)
    rc, body = call("p10phone2", m, {})
    check("parkingLots.getList: no parking application sees every lot",
          rc == 0 and '"lotnum":"701"' in body and '"lotnum":"801"' in body, body)
    with open(phone_log) as f:
        log = f.read()
    check("parked call event sent to the parker's phone",
          "X-Event-Name: digium.parkingLot.parked" in log and 'body: {"lotnumber":"701"}' in log, log)
    for args in ("PJSIP/1001 705 1", "SIP/1001 706", "PJSIP/1002 707"):
        cli("dpmadev calls parked " + args)
    time.sleep(1)
    with open(phone_log) as f:
        log = f.read()
    check("parked call event: only PARKED_CALL, only PJSIP", log.count("digium.parkingLot.parked") == 1, log)
    cli("channel request hangup all")


def recording(phone_log):
    cli("channel originate PJSIP/1001 application Wait 30")
    time.sleep(2)
    with open(phone_log) as f:
        ids = re.findall(r"INVITE call-id=(\S+)", f.read())
    if not ids:
        check("recording: call to PJSIP/1001 answered", False)
        return
    cid = ids[-1]
    m = "switchvox.users.currentCalls.startRecording"
    s = "switchvox.users.currentCalls.stopRecording"
    p = {"requested_account_id": "1001", "call_id": cid}
    expect("startRecording: requested_account_id required", call("p10phone", m, {"call_id": cid}), -1, err(m, 10011, NOT_FOUND % "requested_account_id"))
    expect("startRecording: call_id required", call("p10phone", m, {"requested_account_id": "1001"}), -1, err(m, 10011, NOT_FOUND % "call_id"))
    expect("startRecording: line without mailbox", call("p10phone", m, {"requested_account_id": "1002", "call_id": cid}), -1, err(m, 27168, "Your account is not permitted to run this action: mailbox "))
    expect("startRecording: no such call", call("p10phone", m, {"requested_account_id": "1001", "call_id": "nope"}), -1, err(m, 27168, "Your account is not permitted to run this action: channel "))
    expect("stopRecording: nothing recording", call("p10phone", s, p), -1, err(s, 27168, "Your account is not permitted to run this action: MixMonitor "))
    mark = log_mark()
    # The original reads "Success" into an 8-byte buffer: always an error.
    expect("startRecording: MixMonitor started, error reported", call("p10phone", m, p), -1, err(m, 27168, "Your account is not permitted to run this action: MixMonitor "))
    check("startRecording: logged", "Failed to start MixMonitor. \n" in messages_since(mark))
    chan = [l.split("!")[0] for l in cli("core show channels concise").splitlines() if l.startswith("PJSIP/1001-")]
    check("startRecording: MixMonitor running", bool(chan) and "MIXMONITOR_FILENAME" in cli("core show channel " + chan[0]))
    expect("stopRecording", call("p10phone", s, p), 0, ok(s, SUCCESS))
    time.sleep(1)
    with open(phone_log) as f:
        log = f.read()
    check("stopRecording: INFO sent", "X-Event-Type: digium.stopRecording.success" in log, log)
    check("startRecording: no INFO", "digium.startRecording.success" not in log, log)
    x = f"<parameters><requested_account_id>1001</requested_account_id><call_id>{cid}</call_id></parameters>"
    expect("startRecording (XML)", call_xml("p10phone", m, x), -1, xml_err(m, 27168, "Your account is not permitted to run this action"))
    expect("stopRecording (XML)", call_xml("p10phone", s, x), 0, xml_ok(s))
    expect("stopRecording (XML): nothing recording", call_xml("p10phone", s, x), -1, xml_err(s, 27168, "Your account is not permitted to run this action"))
    expect("stopRecording (XML): call_id required", call_xml("p10phone", s, "<parameters><requested_account_id>1001</requested_account_id></parameters>"), -1, xml_err(s, 10011, "Parameters not found"))
    expect("startRecording (XML): mailbox before call_id", call_xml("p10phone", m, "<parameters><requested_account_id>1002</requested_account_id></parameters>"), -1, xml_err(m, 27168, "Your account is not permitted to run this action"))
    cli("channel request hangup all")


def phonebook():
    m = "switchvox.users.phonebooks.entries.add"
    full = {"account_id": "1001", "phonebook_id": "coworkers", "extension": "1005", "name": "Dave & <Co>"}
    for key in ("account_id", "phonebook_id", "extension", "name"):
        p = {k: v for k, v in full.items() if k != key}
        expect("phonebook: %s required" % key, call("p10phone", m, p), -1, err(m, 10011, NOT_FOUND % key))
    expect("phonebook: entry exists", call("p10phone", m, dict(full, extension="1002")), -1, err(m, 15688, "Phonebook entry already exists: contact_list_entry_exists "))
    expect("phonebook: add", call("p10phone", m, full), 0, ok(m, SUCCESS))
    expect("phonebook: add to an empty list", call("p10phone", m, dict(full, phonebook_id="empty", extension="1006", name="Erin")), 0, ok(m, SUCCESS))
    expect("phonebook: second file", call("p10phone", m, dict(full, phonebook_id="second", extension="1007", name="Frank")), 0, ok(m, SUCCESS))
    expect("phonebook: no such list", call("p10phone", m, dict(full, phonebook_id="nosuch")), -1, err(m, 51141, "Invalid phonebook_id: contact not found "))
    with open(os.path.join(FILES, "p10contacts.xml")) as f:
        doc = f.read()
    check("phonebook: contact written", '<contact first_name="Dave &amp; &lt;Co&gt;" last_name="" contact_type="sip|external" subscribe_to="1005">'
          '<numbers><number dial="1005" label="Extension" primary="1"/></numbers></contact></contacts>' in doc, doc)
    os.chmod(os.path.join(FILES, "p10contacts2.xml"), 0o444)
    expect("phonebook: unwritable file", call("p10phone", m, dict(full, phonebook_id="second", extension="1009")), -1, err(m, 15688, "Phonebook entry already exists: contact_list_entry_add "))
    os.chmod(os.path.join(FILES, "p10contacts2.xml"), 0o644)


def echo():
    m = "test.dpma.api.echo"
    p = {"a": "b", "n": [1, 2.5, None, True], "o": {"x": "é\u0001/"}}
    rc, body = call("p10phone", m, p)
    want = '{"response":{"method":"test.dpma.api.echo","result":{"a":"b","n":[1,2.5,null,true],"o":{"x":"é\\u0001/"}}}}'
    check("echo", rc == 0 and body == want, body)


def main():
    if "Return code" not in cli("dpmadev method call p10phone test.dpma.api.echo {}"):
        sys.exit("dpmadev hooks not available (devtest build installed and Asterisk running?)")
    reset()
    echo()
    queues()
    phonebook()
    tmp = tempfile.mkdtemp(prefix="p10-", dir=os.environ.get("TMPDIR"))
    phone_log = os.path.join(tmp, "phone.log")
    with open(phone_log, "w") as log:
        phone = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "phone.py"), "127.0.0.1", str(SIP_PORT),
                                  "1001", "secret1001", "Digium D65 2_9_17", "60"], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(2)
        if "= 1" not in cli("dpmadev exports isdphone 1001"):
            check("phone registered as a Digium phone (PJSIP helper loaded?)", False)
        else:
            parking(phone_log)
            recording(phone_log)
    finally:
        phone.terminate()
        phone.wait()
        shutil.rmtree(tmp, ignore_errors=True)
    reset()
    print("%d failure(s)" % failures)
    sys.exit(1 if failures else 0)


main()
