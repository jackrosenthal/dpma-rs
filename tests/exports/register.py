#!/usr/bin/env python3
"""Send a digest-authenticated REGISTER (UDP) and print the final status."""
import hashlib, random, re, socket, sys

host, port, user, password, ua = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(3)
lport = s.getsockname()[1]
callid = "%x@127.0.0.1" % random.getrandbits(64)
tag = "%x" % random.getrandbits(32)

def req(cseq, auth=None):
    branch = "z9hG4bK%x" % random.getrandbits(48)
    lines = [
        f"REGISTER sip:{host}:{port} SIP/2.0",
        f"Via: SIP/2.0/UDP 127.0.0.1:{lport};branch={branch};rport",
        "Max-Forwards: 70",
        f"From: <sip:{user}@{host}>;tag={tag}",
        f"To: <sip:{user}@{host}>",
        f"Call-ID: {callid}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{user}@127.0.0.1:{lport};transport=udp>",
        f"User-Agent: {ua}",
        "Expires: 300",
    ]
    if auth:
        lines.append(auth)
    lines += ["Content-Length: 0", "", ""]
    s.sendto("\r\n".join(lines).encode(), (host, port))
    while True:
        data = s.recv(65535).decode(errors="replace")
        status = data.split("\r\n", 1)[0]
        if " 100 " not in status:
            return status, data

st, data = req(1)
print(st)
m = re.search(r'WWW-Authenticate:\s*Digest\s+(.*)', data, re.I)
if m:
    params = dict(re.findall(r'(\w+)="?([^",]*)"?', m.group(1)))
    realm, nonce = params["realm"], params["nonce"]
    uri = f"sip:{host}:{port}"
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()
    qop = params.get("qop")
    if qop:
        nc, cnonce = "00000001", "%x" % random.getrandbits(32)
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        auth = (f'Authorization: Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                f'response="{resp}", algorithm=MD5, qop=auth, nc={nc}, cnonce="{cnonce}"')
        if "opaque" in params:
            auth += f', opaque="{params["opaque"]}"'
    else:
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        auth = f'Authorization: Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}", algorithm=MD5'
    st, data = req(2, auth)
    print(st)
