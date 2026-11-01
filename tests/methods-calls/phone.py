#!/usr/bin/env python3
"""A minimal SIP phone for the P10 method tests.

    phone.py HOST PORT USER PASSWORD USER_AGENT SECONDS

Registers USER (digest auth, UDP) with USER_AGENT, answers every INVITE
with 200 OK (printing "INVITE call-id=<Call-ID>"), and answers and prints
every INFO and MESSAGE it receives (headers and body), until SECONDS have
passed.  With a Digium user agent, the DPMA PJSIP helper reports the
endpoint as a Digium phone (dpma_pjsip_endpoint_is_dphone).
"""
import hashlib
import random
import re
import socket
import sys
import time

host, port, user, password, ua, secs = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], float(sys.argv[6])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.5)
lport = s.getsockname()[1]
callid = "%x@127.0.0.1" % random.getrandbits(64)
tag = "%x" % random.getrandbits(32)


def out(*a):
    print(*a, flush=True)


def register(cseq, auth=None):
    lines = [f"REGISTER sip:{host}:{port} SIP/2.0",
             f"Via: SIP/2.0/UDP 127.0.0.1:{lport};branch=z9hG4bK{random.getrandbits(48):x};rport",
             "Max-Forwards: 70", f"From: <sip:{user}@{host}>;tag={tag}", f"To: <sip:{user}@{host}>",
             f"Call-ID: {callid}", f"CSeq: {cseq} REGISTER",
             f"Contact: <sip:{user}@127.0.0.1:{lport};transport=udp>", f"User-Agent: {ua}",
             f"Expires: {int(secs) + 5}"]
    if auth:
        lines.append(auth)
    s.sendto("\r\n".join(lines + ["Content-Length: 0", "", ""]).encode(), (host, port))


def reply(req, addr, code, reason, body="", extra=()):
    hdrs = [f"SIP/2.0 {code} {reason}"]
    for h in req.split("\r\n")[1:]:
        if re.match(r"(Via|From|Call-ID|CSeq):", h, re.I):
            hdrs.append(h)
        elif re.match(r"To:", h, re.I):
            hdrs.append(h if ";tag=" in h else h + ";tag=uas" + tag)
    hdrs.append(f"Contact: <sip:{user}@127.0.0.1:{lport}>")
    hdrs.extend(extra)
    hdrs.append(f"Content-Length: {len(body)}")
    s.sendto(("\r\n".join(hdrs) + "\r\n\r\n" + body).encode(), addr)


def header(data, name):
    m = re.search(r"^" + name + r":\s*(.*?)\r?$", data, re.I | re.M)
    return m.group(1) if m else ""


register(1)
end = time.time() + secs
cseq = 1
while time.time() < end:
    try:
        raw, addr = s.recvfrom(65535)
    except socket.timeout:
        continue
    data = raw.decode(errors="replace")
    first = data.split("\r\n", 1)[0]
    if first.startswith("SIP/2.0 401") and "REGISTER" in data:
        params = dict(re.findall(r'(\w+)="?([^",]*)"?', re.search(r'WWW-Authenticate:\s*Digest\s+(.*)', data, re.I).group(1)))
        uri = f"sip:{host}:{port}"
        ha1 = hashlib.md5(f"{user}:{params['realm']}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
        nc, cn = "00000001", "%x" % random.getrandbits(32)
        resp = hashlib.md5(f"{ha1}:{params['nonce']}:{nc}:{cn}:auth:{ha2}".encode()).hexdigest()
        cseq += 1
        register(cseq, f'Authorization: Digest username="{user}", realm="{params["realm"]}", nonce="{params["nonce"]}", '
                       f'uri="{uri}", response="{resp}", algorithm=MD5, qop=auth, nc={nc}, cnonce="{cn}"'
                       + (f', opaque="{params["opaque"]}"' if "opaque" in params else ""))
    elif first.startswith("SIP/2.0 200") and "REGISTER" in data:
        out("registered")
    elif first.startswith("INVITE"):
        sdp = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
               "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
        reply(data, addr, 200, "OK", sdp, ["Content-Type: application/sdp"])
        out("INVITE call-id=" + header(data, "Call-ID"))
    elif first.startswith(("INFO", "MESSAGE")):
        head, _, body = data.partition("\r\n\r\n")
        out(first.split()[0] + " received:")
        out("\n".join("  " + l for l in head.split("\r\n")[1:] if l))
        out("  body: " + body)
        reply(data, addr, 200, "OK")
    elif first.startswith(("BYE", "OPTIONS", "NOTIFY", "CANCEL")):
        reply(data, addr, 200, "OK")
        if first.startswith("BYE"):
            out("BYE")
