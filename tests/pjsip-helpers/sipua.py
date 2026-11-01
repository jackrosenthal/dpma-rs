#!/usr/bin/env python3
"""A minimal SIP user agent (UDP, 127.0.0.1) for the PJSIP helper tests.

    sipua.py HOST PORT register USER PASSWORD UA [--expires N]
        Digest-authenticated REGISTER; prints each final status line.
    sipua.py HOST PORT message EXTEN [--digium-ua UA] [--ua UA] [--body TEXT]
        Out-of-dialog MESSAGE to sip:EXTEN@HOST:PORT, with an
        X-Digium-User-Agent header when --digium-ua is given; prints the
        final status line.
    sipua.py HOST PORT uas USER PASSWORD UA SECONDS [--answer N,...]
        Register, then handle INVITEs for SECONDS: those numbered in
        --answer (from 1) are answered (200 with SDP), the others are left
        ringing (180, never answered); every INFO is printed and answered
        200.
    sipua.py HOST PORT subscribe USER PASSWORD UA EXTEN SECONDS [--to URI]
        SUBSCRIBE (Event: dialog) to EXTEN as USER; prints the body of every
        NOTIFY (one line, whitespace between elements removed) and answers
        200.  --to sets the To URI (default sip:EXTEN@HOST:PORT).

Output lines are stable across runs (no ports, tags, or branches).
"""
import argparse
import hashlib
import random
import re
import socket
import sys
import time


class UA:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.s.settimeout(0.5)
        self.lport = self.s.getsockname()[1]
        self.tag = "%x" % random.getrandbits(32)
        self.cseq = 0

    def send(self, text):
        self.s.sendto(text.encode(), (self.host, self.port))

    def recv(self):
        try:
            return self.s.recv(65535).decode(errors="replace")
        except socket.timeout:
            return None

    def request(self, method, ruri, to, callid, extra=(), body="", ctype=None, from_user="dpma-test"):
        self.cseq += 1
        lines = [
            f"{method} {ruri} SIP/2.0",
            f"Via: SIP/2.0/UDP 127.0.0.1:{self.lport};branch=z9hG4bK{random.getrandbits(48):x};rport",
            "Max-Forwards: 70",
            f"From: <sip:{from_user}@{self.host}>;tag={self.tag}",
            f"To: {to}",
            f"Call-ID: {callid}",
            f"CSeq: {self.cseq} {method}",
            f"Contact: <sip:{from_user}@127.0.0.1:{self.lport};transport=udp>",
        ]
        lines += list(extra)
        if ctype:
            lines.append(f"Content-Type: {ctype}")
        lines.append(f"Content-Length: {len(body.encode())}")
        self.send("\r\n".join(lines) + "\r\n\r\n" + body)

    def reply(self, req, code, reason, body="", extra=()):
        hdrs = [f"SIP/2.0 {code} {reason}"]
        for h in req.split("\r\n")[1:]:
            if re.match(r"(Via|From|Call-ID|CSeq):", h, re.I):
                hdrs.append(h)
            elif re.match(r"To:", h, re.I):
                hdrs.append(h if ";tag=" in h else h + ";tag=uas" + self.tag)
        hdrs.append(f"Contact: <sip:ua@127.0.0.1:{self.lport}>")
        hdrs.extend(extra)
        hdrs.append(f"Content-Length: {len(body.encode())}")
        self.send("\r\n".join(hdrs) + "\r\n\r\n" + body)

    def final(self, method, timeout=5):
        """The next final response to `method` (None on timeout)."""
        end = time.time() + timeout
        while time.time() < end:
            data = self.recv()
            if not data or not data.startswith("SIP/2.0"):
                continue
            if not re.search(r"^CSeq:\s*\d+\s+" + method, data, re.I | re.M):
                continue
            if re.match(r"SIP/2.0 1\d\d", data):
                continue
            return data
        return None


def digest(data, user, password, method, uri):
    m = re.search(r"(WWW|Proxy)-Authenticate:\s*Digest\s+(.*)", data, re.I)
    params = dict(re.findall(r'(\w+)="?([^",]*)"?', m.group(2)))
    ha1 = hashlib.md5(f"{user}:{params['realm']}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    nc, cnonce = "00000001", "%x" % random.getrandbits(32)
    resp = hashlib.md5(f"{ha1}:{params['nonce']}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
    hdr = "Authorization" if m.group(1).upper() == "WWW" else "Proxy-Authorization"
    v = (f'{hdr}: Digest username="{user}", realm="{params["realm"]}", nonce="{params["nonce"]}", '
         f'uri="{uri}", response="{resp}", algorithm=MD5, qop=auth, nc={nc}, cnonce="{cnonce}"')
    if "opaque" in params:
        v += f', opaque="{params["opaque"]}"'
    return v


def status(data):
    return data.split("\r\n", 1)[0] if data else "no response"


def register(ua, user, password, agent, expires):
    uri = f"sip:{ua.host}:{ua.port}"
    callid = "%x@127.0.0.1" % random.getrandbits(64)
    to = f"<sip:{user}@{ua.host}>"
    extra = [f"User-Agent: {agent}", f"Expires: {expires}"]
    ua.request("REGISTER", uri, to, callid, extra, from_user=user)
    data = ua.final("REGISTER")
    if data and " 401 " in status(data):
        ua.request("REGISTER", uri, to, callid, extra + [digest(data, user, password, "REGISTER", uri)], from_user=user)
        data = ua.final("REGISTER")
    return status(data)


def cmd_register(a):
    ua = UA(a.host, a.port)
    print("REGISTER", a.user, status_text(register(ua, a.user, a.password, a.ua, a.expires)), flush=True)


def status_text(s):
    return s.replace("SIP/2.0 ", "")


def cmd_message(a):
    ua = UA(a.host, a.port)
    ruri = f"sip:{a.exten}@{a.host}:{a.port}"
    extra = [f"User-Agent: {a.ua}"]
    if a.digium_ua:
        extra.append(f"X-Digium-User-Agent: {a.digium_ua}")
    ua.request("MESSAGE", ruri, f"<{ruri}>", "%x@127.0.0.1" % random.getrandbits(64), extra, a.body, "text/plain")
    print("MESSAGE", a.exten, "X-Digium-User-Agent" if a.digium_ua else "plain", status_text(status(ua.final("MESSAGE"))), flush=True)


def cmd_uas(a):
    ua = UA(a.host, a.port)
    print("REGISTER", a.user, status_text(register(ua, a.user, a.password, a.ua, 120)), flush=True)
    end = time.time() + a.seconds
    invites = 0
    while time.time() < end:
        data = ua.recv()
        if not data:
            continue
        first = data.split("\r\n", 1)[0]
        if first.startswith("INVITE"):
            if re.search(r"^To:.*;tag=", data, re.I | re.M):
                ua.reply(data, 200, "OK")  # re-INVITE
                continue
            invites += 1
            if invites not in a.answer:
                ua.reply(data, 180, "Ringing")
                print("INVITE", invites, "ringing", flush=True)
            else:
                sdp = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
                       "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
                ua.reply(data, 200, "OK", sdp, ["Content-Type: application/sdp"])
                print("INVITE", invites, "answered", flush=True)
        elif first.startswith("CANCEL"):
            ua.reply(data, 200, "OK")
        elif first.startswith("INFO"):
            print("INFO received:", flush=True)
            head, _, body = data.partition("\r\n\r\n")
            for h in head.split("\r\n")[1:]:
                if re.match(r"(X-|Content-Type|Content-Length)", h, re.I):
                    print("  " + h, flush=True)
            print("  body: " + body, flush=True)
            ua.reply(data, 200, "OK")
        elif first.startswith(("BYE", "OPTIONS", "NOTIFY")):
            ua.reply(data, 200, "OK")


def cmd_subscribe(a):
    ua = UA(a.host, a.port)
    ruri = f"sip:{a.exten}@{a.host}:{a.port}"
    to = f"<{a.to or ruri}>"
    callid = "%x@127.0.0.1" % random.getrandbits(64)
    extra = [f"User-Agent: {a.ua}", "Event: dialog", "Accept: application/dialog-info+xml", f"Expires: {int(a.seconds) + 30}"]
    ua.request("SUBSCRIBE", ruri, to, callid, extra, from_user=a.user)
    end = time.time() + a.seconds
    authed = False
    while time.time() < end:
        data = ua.recv()
        if not data:
            continue
        first = data.split("\r\n", 1)[0]
        if first.startswith("SIP/2.0") and "SUBSCRIBE" in data:
            if (" 401 " in first or " 407 " in first) and not authed:
                authed = True
                ua.request("SUBSCRIBE", ruri, to, callid, extra + [digest(data, a.user, a.password, "SUBSCRIBE", ruri)],
                           from_user=a.user)
            elif not re.match(r"SIP/2.0 1\d\d", first):
                print("SUBSCRIBE", status_text(first), flush=True)
        elif first.startswith("NOTIFY"):
            body = data.partition("\r\n\r\n")[2]
            body = re.sub(r">\s+<", "><", body.strip())
            body = re.sub(r' version="\d+"', ' version="N"', body)
            print("NOTIFY", body, flush=True)
            ua.reply(data, 200, "OK")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("host")
    p.add_argument("port", type=int)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("register")
    r.add_argument("user")
    r.add_argument("password")
    r.add_argument("ua")
    r.add_argument("--expires", type=int, default=300)
    m = sub.add_parser("message")
    m.add_argument("exten")
    m.add_argument("--digium-ua")
    m.add_argument("--ua", default="dpma-test")
    m.add_argument("--body", default="test")
    u = sub.add_parser("uas")
    u.add_argument("user")
    u.add_argument("password")
    u.add_argument("ua")
    u.add_argument("seconds", type=float)
    u.add_argument("--answer", type=lambda v: [int(x) for x in v.split(",") if x], default=[])
    s = sub.add_parser("subscribe")
    s.add_argument("user")
    s.add_argument("password")
    s.add_argument("ua")
    s.add_argument("exten")
    s.add_argument("seconds", type=float)
    s.add_argument("--to")
    a = p.parse_args()
    {"register": cmd_register, "message": cmd_message, "uas": cmd_uas, "subscribe": cmd_subscribe}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
