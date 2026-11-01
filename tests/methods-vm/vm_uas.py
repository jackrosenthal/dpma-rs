#!/usr/bin/env python3
"""A minimal SIP UA for the voicemail play test (dev/tests/methods-vm).

Registers as a PJSIP endpoint (digest auth), then answers (or, with
--reject, refuses with 486) INVITEs, printing one line per event:

    registered
    invite X-Event-Name=<value or ->
    answered | rejected
    dtmf <key>                      (with --dtmf, sent as SIP INFO)
    info X-Event-Name=<value or -> body=<body>
    bye

Usage: vm_uas.py <host> <port> <user> <password> <seconds> [--reject]
                 [--dtmf KEYS]

--dtmf sends each key of KEYS in the answered call as an INFO
(application/dtmf-relay), the first 0.5 s after the ACK and the others
0.5 s apart.
"""
import hashlib
import random
import re
import socket
import sys
import time

host, port, user, password, secs = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], float(sys.argv[5])
reject = "--reject" in sys.argv[6:]
dtmf = sys.argv[sys.argv.index("--dtmf") + 1] if "--dtmf" in sys.argv[6:] else ""
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.3)
lport = s.getsockname()[1]
callid = "%x@127.0.0.1" % random.getrandbits(64)
tag = "%x" % random.getrandbits(32)


def send(text):
    s.sendto(text.encode(), (host, port))


def say(line):
    print(line, flush=True)


def register(cseq, expires, auth=None):
    lines = [f"REGISTER sip:{host}:{port} SIP/2.0",
             f"Via: SIP/2.0/UDP 127.0.0.1:{lport};branch=z9hG4bK{random.getrandbits(48):x};rport",
             "Max-Forwards: 70", f"From: <sip:{user}@{host}>;tag={tag}", f"To: <sip:{user}@{host}>",
             f"Call-ID: {callid}", f"CSeq: {cseq} REGISTER",
             f"Contact: <sip:{user}@127.0.0.1:{lport};transport=udp>", "User-Agent: Digium D65 2_9_17",
             f"Expires: {expires}"]
    if auth:
        lines.append(auth)
    send("\r\n".join(lines + ["Content-Length: 0", "", ""]))


def reply(req, code, reason, body="", extra=()):
    hdrs = [f"SIP/2.0 {code} {reason}"]
    for h in req.split("\r\n")[1:]:
        if re.match(r"(Via|From|Call-ID|CSeq):", h, re.I):
            hdrs.append(h)
        elif re.match(r"To:", h, re.I):
            hdrs.append(h if ";tag=" in h else h + ";tag=uas" + tag)
    hdrs.append(f"Contact: <sip:{user}@127.0.0.1:{lport}>")
    hdrs.extend(extra)
    hdrs.append(f"Content-Length: {len(body)}")
    send("\r\n".join(hdrs) + "\r\n\r\n" + body)


def header(msg, name):
    m = re.search(r"^%s:\s*(.*)$" % re.escape(name), msg, re.I | re.M)
    return m.group(1).strip() if m else None


def authorization(challenge):
    """The Authorization header answering a 401 to a REGISTER."""
    params = dict(re.findall(r'(\w+)="?([^",]*)"?', header(challenge, "WWW-Authenticate").split(None, 1)[1]))
    uri = f"sip:{host}:{port}"
    ha1 = hashlib.md5(f"{user}:{params['realm']}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
    nc, cn = "00000001", "%x" % random.getrandbits(32)
    resp = hashlib.md5(f"{ha1}:{params['nonce']}:{nc}:{cn}:auth:{ha2}".encode()).hexdigest()
    return (f'Authorization: Digest username="{user}", realm="{params["realm"]}", nonce="{params["nonce"]}", '
            f'uri="{uri}", response="{resp}", algorithm=MD5, qop=auth, nc={nc}, cnonce="{cn}"'
            + (f', opaque="{params["opaque"]}"' if "opaque" in params else ""))


def send_dtmf(dialog, key, cseq):
    """An in-dialog INFO with one DTMF key (application/dtmf-relay)."""
    body = "Signal=%s\r\nDuration=250\r\n" % key
    lines = [f"INFO {dialog['target']} SIP/2.0",
             f"Via: SIP/2.0/UDP 127.0.0.1:{lport};branch=z9hG4bK{random.getrandbits(48):x};rport",
             "Max-Forwards: 70", f"From: {dialog['local']}", f"To: {dialog['remote']}",
             f"Call-ID: {dialog['callid']}", f"CSeq: {cseq} INFO", f"Contact: <sip:{user}@127.0.0.1:{lport}>",
             "Content-Type: application/dtmf-relay", f"Content-Length: {len(body)}", "", body]
    send("\r\n".join(lines))


cseq = 1
expires = 120
register(cseq, expires)
end = time.time() + secs
dialog, pending, info_cseq = None, [], 100
while time.time() < end:
    while pending and pending[0][0] <= time.time() and dialog:
        _, key = pending.pop(0)
        info_cseq += 1
        send_dtmf(dialog, key, info_cseq)
        say("dtmf %s" % key)
    try:
        data = s.recv(65535).decode(errors="replace")
    except socket.timeout:
        continue
    first = data.split("\r\n", 1)[0]
    if first.startswith("SIP/2.0 401") and "REGISTER" in data:
        cseq += 1
        register(cseq, expires, authorization(data))
    elif first.startswith("SIP/2.0 200") and "REGISTER" in data:
        if expires:
            say("registered")
        else:
            say("unregistered")
            break
    elif first.startswith("INVITE"):
        say("invite X-Event-Name=%s" % (header(data, "X-Event-Name") or "-"))
        if reject:
            reply(data, 486, "Busy Here")
            say("rejected")
        else:
            sdp = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
                   "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
            reply(data, 200, "OK", sdp, ["Content-Type: application/sdp"])
            say("answered")
            to = header(data, "To")
            contact = re.search(r"<([^>]*)>", header(data, "Contact") or "")
            dialog = {"callid": header(data, "Call-ID"), "remote": header(data, "From"),
                      "local": to if ";tag=" in to else to + ";tag=uas" + tag,
                      "target": contact.group(1) if contact else f"sip:{host}:{port}"}
    elif first.startswith("ACK"):
        if dtmf and dialog and not pending:
            pending = [(time.time() + 0.5 * (i + 1), k) for i, k in enumerate(dtmf)]
    elif first.startswith("BYE"):
        reply(data, 200, "OK")
        say("bye")
    elif first.startswith("INFO"):
        body = data.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in data else ""
        say("info X-Event-Name=%s body=%s" % (header(data, "X-Event-Name") or "-", body))
        reply(data, 200, "OK")
    elif first.startswith(("OPTIONS", "NOTIFY")):
        reply(data, 200, "OK")
# Unregister so the next test starts without a contact.
if expires:
    expires = 0
    cseq += 1
    register(cseq, 0)
    end = time.time() + 2
    while time.time() < end:
        try:
            data = s.recv(65535).decode(errors="replace")
        except socket.timeout:
            continue
        if data.startswith("SIP/2.0 401"):
            cseq += 1
            register(cseq, 0, authorization(data))
        elif data.startswith("SIP/2.0 200"):
            say("unregistered")
            break
