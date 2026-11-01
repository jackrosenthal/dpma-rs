#!/usr/bin/env python3
"""Register as a user (digest), answer one INVITE, print any INFO received."""
import hashlib, random, re, socket, sys, time

host, port, user, password, ua, secs = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], float(sys.argv[6])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.5)
lport = s.getsockname()[1]
callid = "%x@127.0.0.1" % random.getrandbits(64)
tag = "%x" % random.getrandbits(32)

def send(text):
    s.sendto(text.encode(), (host, port))

def register(cseq, auth=None):
    lines = [f"REGISTER sip:{host}:{port} SIP/2.0",
             f"Via: SIP/2.0/UDP 127.0.0.1:{lport};branch=z9hG4bK{random.getrandbits(48):x};rport",
             "Max-Forwards: 70", f"From: <sip:{user}@{host}>;tag={tag}", f"To: <sip:{user}@{host}>",
             f"Call-ID: {callid}", f"CSeq: {cseq} REGISTER",
             f"Contact: <sip:{user}@127.0.0.1:{lport};transport=udp>", f"User-Agent: {ua}", "Expires: 120"]
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

register(1)
end = time.time() + secs
cseq = 1
while time.time() < end:
    try:
        data = s.recv(65535).decode(errors="replace")
    except socket.timeout:
        continue
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
        print("registered", flush=True)
    elif first.startswith("INVITE"):
        sdp = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
               "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n")
        reply(data, 200, "OK", sdp, ["Content-Type: application/sdp"])
        print("answered", flush=True)
    elif first.startswith("INFO"):
        print("INFO received:", flush=True)
        print("\n".join("  " + l for l in data.split("\r\n") if l), flush=True)
        reply(data, 200, "OK")
    elif first.startswith(("BYE", "OPTIONS", "NOTIFY")):
        reply(data, 200, "OK")
