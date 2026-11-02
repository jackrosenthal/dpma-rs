#!/usr/bin/env python3
"""Digium phone simulator for testing res_digium_phone (DPMA) without phones.

It plays the phone side of the DPMA AppServer protocol over SIP MESSAGE
(UDP or TCP) against an Asterisk instance: handshake with a locally
generated certificate (legacy or chain form), AES-128-CBC encryption,
chunking and reassembly, every request type, event listening, and a
scripted mode for automated checks.  See dev/sim/README.md.

Written from the decompile of the original module (phone side of
phone_message.c, phone_crypto.c, and phone_request.c), independently of the
Rust code.  Standard library plus `cryptography`.

  dpma_sim.py [global options] COMMAND [command options]

Commands: handshake, ping, echo, config, token, userlist, file, verify,
asterisk, raw, listen, script, selftest.  `dpma_sim.py COMMAND -h` for
details.  Exit status: 0 on success, 1 on a failed check, 2 on usage or
setup errors.

Python use (from dev/sim):

  from dpma_sim import Phone, Options
  with Phone(Options(slot=5)) as phone:
      phone.handshake()
      ex = phone.ping()
      print(ex.describe())
"""
import argparse
import base64
import binascii
import ctypes
import ctypes.util
import datetime
import hashlib
import json
import os
import queue
import random
import re
import secrets
import shlex
import signal
import socket
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Text from Asterisk and from phones can hold bytes that are not UTF-8,
# kept as lone surrogates ("surrogateescape"); print them as those bytes
# instead of failing.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="surrogateescape")

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

DEFAULT_MAC = "000fd3000001"
DEFAULT_UA = "Digium D65 2_9_17"
DEFAULT_PKI = os.path.join(HERE, "pki")

# --------------------------------------------------------------------------
# Protocol constants (section 4.2 of dev/notes/port-plan.md)

P = "X-Digium-AppServer-"
H_ID = P + "ID"
H_SESSION = P + "Session"
H_REQUEST_TYPE = P + "RequestType"
H_RESPONSE_TYPE = P + "ResponseType"
H_MAC = P + "MACAddress"
H_SALT = P + "Message-Salt"
H_SEQUENCE = P + "Message-Sequence"
H_FINISHED = P + "Message-Finished"
H_PASSWORD = P + "Password"
H_CONFIG_PASSWORD = P + "ConfigPassword"
H_CONFIG_TOKEN = P + "Config-Token"
H_USERNAME = P + "Username"
H_ERROR = P + "Error-ID"
H_HANDSHAKE_VERSION = P + "Handshake-Version"
H_EVENT = "X-Event-Name"
H_ORIGINATION = "X-Origination-Network"

# Request types that need no session (validate_message).
NO_SESSION_TYPES = ("handshake", "echo", "preconfig")

RESPONSE_FOR = {
    "Echo": "EchoResponse",
    "Handshake": "HandshakeResponse",
    "HTTPRequest": "HTTPResponse",
    "AsteriskRequest": "AsteriskResponse",
    "UserlistRequest": "UserlistResponse",
    "TokenRequest": "TokenResponse",
    "ConfigRequest": "ConfigResponse",
    "FileRequest": "FileResponse",
    "VerifyRequest": "VerifyResponse",
    "PingRequest": "PingResponse",
}

# The server prefixes every chunk of events and error replies with this.
COMMAND_PREFIX = b"Command: "

# Message error codes (X-Digium-AppServer-Error-ID) and the texts of the
# server's "<error msg=... />" bodies (the original's table at 0x5bcce8;
# other codes print "Unknown error").
MSG_ERROR_TEXT = {
    -1: "An Unknown Error has occurred",
    -98: "The file requested was not found",
    -192: "User Config token presented is invalid",
    -195: "Specfied user not found",
    -198: "An Invalid configuration password was provided",
    -199: "An invalid password was provided",
    -200: "The requested credentials where not provided",
    -398: "Session Timeout",
    -400: "Invalid Certificate",
}


def error_body(code):
    """The body phone_msg_outgoing_send appends for a non-zero error."""
    return '<error msg="%s" />' % MSG_ERROR_TEXT.get(code, "Unknown error")


# The server's per-chunk plaintext limits (phone_msg_outgoing_send): UDP
# plaintext, UDP encrypted, and TCP (response URI contains transport=tcp).
SERVER_UDP_PLAIN_LIMIT = 0x267
SERVER_UDP_ENCRYPTED_LIMIT = 0x1a4
SERVER_TCP_LIMIT = 0x384


class SimError(Exception):
    """A setup or protocol error that ends the current command."""


# --------------------------------------------------------------------------
# Crypto (phone_crypto.c)

def evp_bytes_to_key(password, salt, key_len=16, iv_len=16):
    """EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, password, 1)."""
    out = b""
    prev = b""
    while len(out) < key_len + iv_len:
        prev = hashlib.sha1(prev + password + salt).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


class StreamEncryptor:
    """One AES-128-CBC stream with PKCS#7 padding, as init_encryption,
    encrypt_data, and encrypt_final: update() returns whole blocks only."""

    def __init__(self, password, salt):
        key, iv = evp_bytes_to_key(password, salt)
        self._enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        self._pad = sym_padding.PKCS7(128).padder()

    def update(self, data):
        return self._enc.update(self._pad.update(data))

    def finish(self):
        return self._enc.update(self._pad.finalize()) + self._enc.finalize()


def encrypt(password, salt, plain):
    e = StreamEncryptor(password, salt)
    return e.update(plain) + e.finish()


def decrypt(password, salt, data):
    if len(data) % 16:
        raise SimError("ciphertext length %d is not a multiple of 16" % len(data))
    key, iv = evp_bytes_to_key(password, salt)
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = d.update(data) + d.finalize()
    u = sym_padding.PKCS7(128).unpadder()
    try:
        return u.update(padded) + u.finalize()
    except ValueError:
        raise SimError("bad padding after decryption (wrong key or salt?)") from None


def b64encode(data):
    """ast_base64encode: standard alphabet, '=' padding, no line breaks."""
    return base64.b64encode(data).decode("ascii")


def b64decode_strict(text):
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (ValueError, binascii.Error) as e:
        raise SimError("invalid base64 %r: %s" % (text[:40], e)) from None


_B2A = {c: i for i, c in enumerate(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


def ast_base64decode(text, max_len=1 << 30):
    """Asterisk's ast_base64decode, quirks included: stops at NUL or '=',
    maps characters outside the alphabet to 63, drops leftover bits."""
    out = bytearray()
    byte = bits = 0
    for ch in text:
        if ch in ("\0", "=") or len(out) >= max_len:
            break
        byte = ((byte << 6) | (_B2A.get(ch, 0xff) & 0x3f)) & 0xffffffff
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((byte >> bits) & 0xff)
    return bytes(out)


def salt_hex(salt):
    return "".join("%02X" % b for b in salt)


def set_hex(text, size=8):
    """The original's set_hex: at most 2*size hex digits, either case, the
    rest zero filled."""
    if len(text) > 2 * size:
        raise SimError("hex string is too long")
    out = bytearray(size)
    for i, ch in enumerate(text):
        try:
            v = int(ch, 16)
        except ValueError:
            raise SimError("Invalid character in hex string '%s'" % ch) from None
        if i % 2 == 0:
            out[i // 2] = v << 4
        else:
            out[i // 2] |= v
    return bytes(out)


def encrypt_field(password, salt, value):
    """A header field (send_encrypt_hdr_helper): its own CBC stream with the
    message's key and IV, base64 encoded."""
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogateescape")
    return b64encode(encrypt(password, salt, value))


def decrypt_field(password, salt, text):
    return decrypt(password, salt, b64decode_strict(text))


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)


def rsa_decrypt_common_password(key, text):
    """X-Digium-AppServer-Password of a HandshakeResponse: base64 of the
    40-byte common password, RSA PKCS#1 v1.5 encrypted to the phone key."""
    try:
        return key.decrypt(b64decode_strict(text), asym_padding.PKCS1v15())
    except ValueError as e:
        raise SimError("cannot decrypt the common password: %s" % e) from None


# --------------------------------------------------------------------------
# Framing (phone_msg_outgoing_send, incoming_add_msg, incoming_check_finalize)

def split_bytes(data, size):
    if size < 1:
        raise SimError("chunk size must be positive")
    return [data[i:i + size] for i in range(0, len(data), size)] or [b""]


def split_plain(data, size):
    """Split plaintext into pieces of at most `size` bytes such that no
    piece but the last ends in CR or LF: res_pjsip_messaging's print_body
    strips trailing CR/LF from every MESSAGE body, so a line break at the
    end of a chunk would be lost in the server's reassembly."""
    out = []
    pos = 0
    while pos < len(data):
        end = min(pos + size, len(data))
        if end < len(data):
            cut = end
            while cut > pos and data[cut - 1:cut] in (b"\r", b"\n"):
                cut -= 1
            if cut > pos:
                end = cut
        out.append(data[pos:end])
        pos = end
    return out or [b""]


PEM_MARKER_LINE = re.compile(rb"-----(?:BEGIN|END) [^\r\n-]*-----(?:\r?\n)?")


def pem_segments(data):
    """Cut `data` before and after every PEM BEGIN and END line (its line
    break included).  Chunks cut there end right after a BEGIN or END line
    or right before one, so res_pjsip_messaging's CR/LF stripping removes
    exactly the line breaks at the PEM boundaries (dpma-rs restores them,
    port plan section 8, item 12)."""
    cuts = {0, len(data)}
    for m in PEM_MARKER_LINE.finditer(data):
        cuts.update((m.start(), m.end()))
    cuts = sorted(cuts)
    return [data[a:b] for a, b in zip(cuts, cuts[1:])]


def asterisk_print_body(body):
    """What res_pjsip_messaging makes of a MESSAGE body: trailing CR/LF
    removed, at most 1023 bytes (MAX_BODY_SIZE)."""
    return body[:1023].rstrip(b"\r\n")


def frame_request_body(body, size, password=None, salt=None, style="split",
                       pem_cuts=False):
    """Wire bodies for a phone-to-server request.

    Plaintext: the body split into pieces of at most `size` bytes, never
    ending a piece (but the last) in CR or LF (see split_plain).  With
    `pem_cuts`, pieces also end right before and right after every PEM
    BEGIN and END line, line break included (see pem_segments), so the
    server loses those line breaks.

    Encrypted, style "split" (default): the whole body is encrypted as one
    CBC stream, base64 encoded, and the text split into pieces of `size`
    characters.  The server concatenates the chunk bodies and base64 decodes
    the result once (incoming_check_finalize), so this is the form it can
    reassemble.

    Encrypted, style "stream": mirrors how the server sends: the plaintext
    is split into pieces of `size` bytes, fed to one CBC stream, and each
    piece's ciphertext is base64 encoded separately.  The server cannot
    reassemble this when a piece's base64 ends in '=' padding (its
    ast_base64decode stops at the first '='), i.e., when a piece's
    ciphertext length is not a multiple of 3."""
    if size < 1:
        raise SimError("chunk size must be positive")
    if password is None:
        if pem_cuts:
            return [piece for seg in pem_segments(body)
                    for piece in split_plain(seg, size)] or [b""]
        return split_plain(body, size)
    if not body:
        return [b""]
    if style == "split":
        text = b64encode(encrypt(password, salt, body)).encode("ascii")
        return split_bytes(text, size)
    if style == "stream":
        enc = StreamEncryptor(password, salt)
        pieces = split_bytes(body, size)
        out = []
        for i, piece in enumerate(pieces):
            data = enc.update(piece)
            if i == len(pieces) - 1:
                data += enc.finish()
            out.append(b64encode(data).encode("ascii"))
        return out
    raise SimError("unknown chunk style %r" % style)


def server_frame(body, limit, password=None, salt=None, prefix=b"",
                 handshake_response=False):
    """Emulation of the server's phone_msg_outgoing_send framing, used by
    the self-test to check this simulator's reassembly against the
    decompile: chunks of at most `limit` plaintext bytes including
    `prefix`, one CBC stream with each chunk's output base64 encoded on its
    own, Message-Sequence on every chunk except the only chunk of a
    HandshakeResponse, and Message-Finished on the last.  Returns a list of
    (headers dict, wire body)."""
    if not body:
        body = b"empty body"
    enc = StreamEncryptor(password, salt) if password is not None else None
    out = []
    pos = 0
    seq = 0
    while True:
        take = min(len(body) - pos, limit - len(prefix))
        plain = prefix + body[pos:pos + take]
        pos += take
        last = pos >= len(body)
        if enc is not None:
            data = enc.update(plain)
            if last:
                data += enc.finish()
            wire = b64encode(data).encode()
        else:
            wire = plain
        headers = {}
        if enc is not None:
            headers[H_SALT] = salt_hex(salt)
        if not (last and seq == 0 and handshake_response):
            headers[H_SEQUENCE] = str(seq)
            if last:
                headers[H_FINISHED] = "1"
        out.append((headers, wire))
        seq += 1
        if last:
            return out


# --------------------------------------------------------------------------
# SIP

COMPACT = {"i": "Call-ID", "m": "Contact", "e": "Content-Encoding", "l": "Content-Length",
           "c": "Content-Type", "f": "From", "s": "Subject", "k": "Supported", "t": "To",
           "v": "Via", "o": "Event", "u": "Allow-Events", "r": "Refer-To", "b": "Referred-By",
           "x": "Session-Expires"}


class SipMessage:
    def __init__(self, first_line, headers, body=b"", source=None):
        self.first_line = first_line
        self.headers = headers          # list of (name, value)
        self.body = body
        self.source = source            # (host, port) it came from
        self.transport = None           # "udp" or "tcp" (incoming messages)
        self.received = time.time()
        parts = first_line.split(" ", 2)
        if first_line.startswith("SIP/2.0 "):
            self.is_request = False
            self.status = int(parts[1])
            self.reason = parts[2] if len(parts) > 2 else ""
            self.method = None
        else:
            self.is_request = True
            self.method = parts[0]
            self.uri = parts[1] if len(parts) > 1 else ""
            self.status = None

    def get(self, name, default=None):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def getall(self, name):
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def encode(self):
        # Header values are text whose bytes that are not UTF-8 travel as
        # lone surrogates ("surrogateescape"), so any bytes can be sent.
        lines = [self.first_line] + ["%s: %s" % kv for kv in self.headers]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "surrogateescape") + self.body

    def text(self):
        return self.encode().decode("utf-8", "replace")


def parse_sip(data, source=None):
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
    lines = head.decode("utf-8", "surrogateescape").replace("\r\n", "\n").split("\n")
    while lines and lines[0] == "":
        lines.pop(0)
    if not lines:
        raise ValueError("empty SIP message")
    headers = []
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and headers:
            k, v = headers[-1]
            headers[-1] = (k, v + " " + line.strip())
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        headers.append((COMPACT.get(k.lower(), k) if len(k) == 1 else k, v.strip()))
    msg = SipMessage(lines[0].strip(), headers, body, source)
    cl = msg.get("Content-Length")
    if cl is not None and cl.isdigit():
        msg.body = body[:int(cl)]
    return msg


def new_tag():
    return secrets.token_hex(6)


class SipEndpoint:
    """A tiny SIP user agent: sends out-of-dialog requests and waits for the
    final response (UDP retransmissions as RFC 3261 timer E), and answers
    every incoming request with 200 OK, queueing MESSAGEs."""

    def __init__(self, server, local=("127.0.0.1", 0), transport="udp", log=None,
                 timeout=5.0):
        self.server = server
        self.local = local
        self.transport = transport
        self.log = log or (lambda level, text: None)
        self.timeout = timeout
        self.incoming = queue.Queue()
        self._pending = {}              # Via branch -> [event, response]
        self._seen = {}                 # incoming request key -> response bytes
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._cseq = random.randint(1, 10000)
        self._sock = None
        self._udp_side = None
        self._closed = False
        self._thread = None

    def start(self):
        if self.transport == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(self.local)
            self._sock = s
            self._thread = threading.Thread(target=self._udp_loop, daemon=True)
        elif self.transport == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(self.local)
            s.settimeout(self.timeout)
            try:
                s.connect(self.server)
            except OSError as e:
                raise SimError("TCP connect to %s:%d failed: %s" % (self.server + (e,))) from None
            s.settimeout(None)
            self._sock = s
            self._thread = threading.Thread(target=self._tcp_loop, daemon=True)
            # Also listen for UDP on the same port, as phones do.  The
            # original server answers a session that fails validation
            # ("Session Timeout", phone_msg_send_timeout) at the bare
            # Response-URI, without ";transport=tcp", i.e., over UDP;
            # dpma-rs answers over TCP (the "transport" condition tells
            # them apart).
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.bind(s.getsockname())
                self._udp_side = u
                threading.Thread(target=self._udp_side_loop, daemon=True).start()
            except OSError as e:
                self.log(1, "--- no UDP listener next to the TCP connection: %s" % e)
        else:
            raise SimError("unknown transport %r" % self.transport)
        self._thread.start()
        return self

    @property
    def local_addr(self):
        return self._sock.getsockname()

    def close(self):
        self._closed = True
        if self._udp_side is not None:
            try:
                self._udp_side.close()
            except OSError:
                pass
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)     # wakes the reader
            except OSError:
                pass
            self._sock.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(2)

    # Sending -----------------------------------------------------------

    def _send_raw(self, data, addr=None):
        with self._send_lock:
            if self.transport == "udp":
                self._sock.sendto(data, addr or self.server)
            else:
                self._sock.sendall(data)

    def via(self, branch):
        host, port = self.local_addr
        return "SIP/2.0/%s %s:%d;rport;branch=%s" % (self.transport.upper(), host, port, branch)

    def request(self, method, ruri, headers, body=b"", from_uri=None, to_uri=None,
                timeout=None):
        """Send a request and return the final response (None on timeout)."""
        timeout = self.timeout if timeout is None else timeout
        branch = "z9hG4bK" + secrets.token_hex(8)
        with self._lock:
            self._cseq += 1
            cseq = self._cseq
        host = self.local_addr[0]
        hdrs = [
            ("Via", self.via(branch)),
            ("Max-Forwards", "70"),
            ("From", "<%s>;tag=%s" % (from_uri or "sip:sim@%s" % host, new_tag())),
            ("To", "<%s>" % (to_uri or ruri)),
            ("Call-ID", "%s@%s" % (secrets.token_hex(10), host)),
            ("CSeq", "%d %s" % (cseq, method)),
        ] + list(headers) + [("Content-Length", str(len(body)))]
        msg = SipMessage("%s %s SIP/2.0" % (method, ruri), hdrs, body)
        data = msg.encode()
        slot = [threading.Event(), None]
        with self._lock:
            self._pending[branch] = slot
        self.log(2, ">>> SIP to %s:%d\n%s" % (self.server + (msg.text(),)))
        self.log(1, ">>> %s %s (%d body bytes)" % (method, ruri, len(body)))
        deadline = time.time() + timeout
        interval = 0.5
        try:
            self._send_raw(data)
            while True:
                wait = min(interval, deadline - time.time())
                if wait <= 0:
                    return None
                if slot[0].wait(wait):
                    return slot[1]
                if self.transport == "udp":
                    self._send_raw(data)
                    interval = min(interval * 2, 4.0)
        finally:
            with self._lock:
                self._pending.pop(branch, None)

    # Receiving ---------------------------------------------------------

    def _udp_loop(self):
        while not self._closed:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                return
            if data.strip():
                self._handle(data, addr)

    def _udp_side_loop(self):
        sock = self._udp_side
        while not self._closed:
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                return
            if data.strip():
                self._handle(data, addr, reply=lambda d, a: sock.sendto(d, a))

    def _tcp_loop(self):
        buf = b""
        while not self._closed:
            try:
                data = self._sock.recv(65535)
            except OSError:
                return
            if not data:
                if not self._closed:
                    self.log(1, "--- TCP connection closed by the server")
                return
            buf += data
            while True:
                stripped = buf.lstrip(b"\r\n")
                if len(stripped) != len(buf):
                    if buf.startswith(b"\r\n\r\n"):
                        try:
                            self._send_raw(b"\r\n")         # keepalive pong
                        except OSError:
                            pass
                    buf = stripped
                end = buf.find(b"\r\n\r\n")
                if end < 0:
                    break
                m = re.search(rb"(?im)^(?:content-length|l)[ \t]*:[ \t]*(\d+)", buf[:end])
                total = end + 4 + (int(m.group(1)) if m else 0)
                if len(buf) < total:
                    break
                self._handle(buf[:total], self.server)
                buf = buf[total:]

    def _handle(self, data, addr, reply=None):
        send = reply or self._send_raw
        try:
            msg = parse_sip(data, addr)
        except ValueError as e:
            self.log(1, "--- unparsable SIP data from %s: %s" % (addr, e))
            return
        msg.transport = "udp" if reply is not None or self.transport == "udp" else "tcp"
        self.log(2, "<<< SIP from %s:%d\n%s" % (addr + (msg.text(),)))
        via = msg.get("Via") or ""
        m = re.search(r"branch=([^;,\s]+)", via)
        if not msg.is_request:
            if msg.status < 200 or not m:
                return
            with self._lock:
                slot = self._pending.get(m.group(1))
            if slot is not None and slot[1] is None:
                slot[1] = msg
                slot[0].set()
            return
        if msg.method == "ACK":
            return
        key = (msg.get("Call-ID"), msg.get("CSeq"), m.group(1) if m else via)
        with self._lock:
            old = self._seen.get(key)
        if old is not None:
            self.log(1, "<<< retransmitted %s, answered again" % msg.method)
            send(old, addr)
            return
        resp = self._response(msg, 200, "OK")
        with self._lock:
            self._seen[key] = resp
            if len(self._seen) > 2000:
                for k in list(self._seen)[:1000]:
                    del self._seen[k]
        send(resp, addr)
        self.log(1, "<<< %s from %s:%d%s (%d body bytes), answered 200 OK" % (
            (msg.method,) + tuple(addr) + (" (UDP)" if reply else "", len(msg.body))))
        if msg.method == "MESSAGE":
            self.incoming.put(msg)

    def _response(self, req, status, reason):
        hdrs = [("Via", v) for v in req.getall("Via")]
        to = req.get("To") or ""
        if ";tag=" not in to:
            to += ";tag=" + new_tag()
        hdrs += [("From", req.get("From") or ""), ("To", to),
                 ("Call-ID", req.get("Call-ID") or ""), ("CSeq", req.get("CSeq") or ""),
                 ("Server", "dpma_sim"), ("Content-Length", "0")]
        return SipMessage("SIP/2.0 %d %s" % (status, reason), hdrs).encode()


# --------------------------------------------------------------------------
# PKI

class Pki:
    def __init__(self, directory):
        self.dir = directory
        path = os.path.join(directory, "bundles.json")
        if not os.path.exists(path):
            raise SimError("no test PKI in %s; run dev/sim/mkpki.py first" % directory)
        with open(path) as f:
            self.manifest = json.load(f)

    def bundle(self, name):
        b = self.manifest["bundles"].get(name)
        if b is None:
            raise SimError("unknown bundle %r (have: %s)" % (
                name, ", ".join(self.manifest["bundles"])))
        body = b""
        for c in b["certs"]:
            with open(os.path.join(self.dir, c), "rb") as f:
                body += f.read()
        return body, load_private_key(os.path.join(self.dir, b["key"]))

    def check_appserver(self, body):
        """Verify the certificate in a HandshakeResponse body against the
        test AppServer CA.  Returns (ok, description)."""
        m = re.search(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", body, re.S)
        if not m:
            return False, "no certificate in the HandshakeResponse body"
        try:
            cert = x509.load_pem_x509_certificate(m.group(0))
        except ValueError as e:
            return False, "unparsable AppServer certificate: %s" % e
        with open(os.path.join(self.dir, self.manifest["appserver_ca"]), "rb") as f:
            ca = x509.load_pem_x509_certificate(f.read())
        subject = cert.subject.rfc4514_string()
        try:
            cert.verify_directly_issued_by(ca)
        except Exception as e:      # ValueError, TypeError, InvalidSignature
            return False, "%s is not signed by the test AppServer CA (%s)" % (
                subject, str(e) or type(e).__name__)
        now = time.time()
        if not (_utc_timestamp(cert, "not_valid_before") <= now
                <= _utc_timestamp(cert, "not_valid_after")):
            return False, "%s is outside its validity period" % subject
        return True, subject


def _utc_timestamp(cert, name):
    """The certificate's validity bound `name` as a POSIX timestamp.
    cryptography 42 added the time-zone aware not_valid_*_utc; older
    versions (Ubuntu 24.04 has 41) only have the naive not_valid_*, in
    UTC."""
    t = getattr(cert, name + "_utc", None)
    if t is None:
        t = getattr(cert, name).replace(tzinfo=datetime.timezone.utc)
    return t.timestamp()


# --------------------------------------------------------------------------
# AppServer messages

class Reply:
    """One complete incoming AppServer message (all of its chunks)."""

    def __init__(self, parts):
        self.parts = parts                      # SipMessages in sequence order
        first = parts[0]
        self.first = first
        self.id = first.get(H_ID)
        self.response_type = first.get(H_RESPONSE_TYPE)
        self.request_type = first.get(H_REQUEST_TYPE)
        self.event = first.get(H_EVENT)
        self.session = first.get(H_SESSION)
        self.error = first.get(H_ERROR)
        self.salt = first.get(H_SALT)
        self.encrypted = bool(self.salt)
        self.raw_body = b"".join(p.body for p in parts)
        self.body = self.raw_body
        self.payload = self.raw_body
        self.fields = {}            # decrypted header fields
        self.problems = []
        self.appserver_ok = None
        self.appserver_info = None

    @property
    def transports(self):
        """The transports the chunks arrived on, e.g., "tcp" or "tcp,udp"."""
        return ",".join(sorted({p.transport for p in self.parts if p.transport})) or None

    @property
    def type(self):
        return self.response_type or self.request_type or self.event or (
            "Error" if self.error else None)

    @property
    def ok(self):
        return not self.problems and self.error in (None, "", "0")

    def header(self, name):
        v = self.first.get(name)
        if v is None and not name.lower().startswith("x-"):
            v = self.first.get(P + name)
        return v

    def decode(self, password):
        """Decrypt (when salted) and strip the "Command: " prefixes."""
        if self.encrypted:
            if password is None:
                self.problems.append("encrypted message but no common password")
                return
            try:
                salt = set_hex(self.salt)
                data = b"".join(b64decode_strict(p.body.decode("ascii", "replace"))
                                for p in self.parts)
                self.body = decrypt(password, salt, data)
                for name in (H_PASSWORD, H_CONFIG_TOKEN):
                    v = self.first.get(name)
                    if v:
                        self.fields[name] = decrypt_field(password, salt, v).decode(
                            "utf-8", "surrogateescape")
            except SimError as e:
                self.problems.append(str(e))
                return
        prefixed = self.event is not None or self.error not in (None, "", "0")
        self.payload = self._strip_prefix() if prefixed else self.body

    def _strip_prefix(self):
        body = self.body
        if not body.startswith(COMMAND_PREFIX):
            return body
        if len(self.parts) == 1:
            return body[len(COMMAND_PREFIX):]
        if not self.encrypted:
            return b"".join(p.body[len(COMMAND_PREFIX):] if p.body.startswith(COMMAND_PREFIX)
                            else p.body for p in self.parts)
        # Encrypted chunk boundaries are not visible after decryption; the
        # server cut the plaintext at a fixed limit, so find it.
        for limit in (SERVER_UDP_ENCRYPTED_LIMIT, SERVER_TCP_LIMIT, SERVER_UDP_PLAIN_LIMIT):
            starts = range(0, len(body), limit)
            if len(starts) == len(self.parts) and all(
                    body[s:s + len(COMMAND_PREFIX)] == COMMAND_PREFIX for s in starts):
                return b"".join(body[s + len(COMMAND_PREFIX):s + limit] for s in starts)
        self.problems.append("could not locate the chunk prefixes")
        return body[len(COMMAND_PREFIX):]

    def describe(self, verbose=0):
        err = self.error if self.error is not None else "-"
        lines = ["<< %s id=%s error=%s chunks=%d %s%s" % (
            self.type, self.id, err, len(self.parts),
            "encrypted" if self.encrypted else "plaintext",
            " session=%s" % self.session if self.session else "")]
        skip = {"via", "from", "to", "call-id", "cseq", "content-length", "max-forwards",
                "content-type"}
        for k, v in self.first.headers:
            if verbose or (k.lower().startswith("x-") and k not in (H_SEQUENCE, H_FINISHED)):
                if verbose > 1 or k.lower() not in skip:
                    lines.append("   %s: %s" % (k, v))
        for k, v in self.fields.items():
            lines.append("   %s (decrypted): %s" % (k, v))
        if self.appserver_info is not None:
            lines.append("   AppServer certificate: %s%s" % (
                "verified, " if self.appserver_ok else "NOT VERIFIED: ", self.appserver_info))
        for p in self.problems:
            lines.append("   PROBLEM: %s" % p)
        text = self.payload.decode("utf-8", "replace")
        lines.append("   body (%d bytes)%s" % (len(self.payload), ":" if text else ""))
        if text:
            lines += ["   | " + ln for ln in text.splitlines()]
        return "\n".join(lines)


class Exchange:
    """A request sent by the phone and the reply it got."""

    def __init__(self, request_type, txid):
        self.request_type = request_type
        self.id = txid
        self.sip_statuses = []
        self.chunks = 0
        self.encrypted = False
        self.reply = None
        self.sent_at = time.time()
        self.problems = []
        self.expected = RESPONSE_FOR.get(request_type)
        self.waited = False
        self._done = threading.Event()

    @property
    def sip_ok(self):
        return bool(self.sip_statuses) and all(
            s is not None and 200 <= s < 300 for s in self.sip_statuses)

    @property
    def ok(self):
        return (self.sip_ok and not self.problems and self.reply is not None
                and self.reply.ok
                and (self.expected is None or self.reply.response_type == self.expected))

    def describe(self, verbose=0):
        st = ",".join(str(s) if s is not None else "timeout" for s in self.sip_statuses)
        lines = [">> %s id=%s chunks=%d %s sip=%s" % (
            self.request_type, self.id, self.chunks,
            "encrypted" if self.encrypted else "plaintext", st or "-")]
        lines += ["   PROBLEM: %s" % p for p in self.problems]
        if self.reply is not None:
            lines.append(self.reply.describe(verbose))
        elif self.waited or self.problems:
            lines.append("<< (no reply)")
        else:
            lines.append("<< (not waited for)")
        return "\n".join(lines)


class Options:
    """Simulator settings; the command-line options map onto these."""

    def __init__(self, **kw):
        slot = kw.pop("slot", None) or os.environ.get("DPMA_SLOT")
        self.slot = slot
        self.server = "127.0.0.1"
        self.sip_port = 15060 + 100 * int(slot) if slot else 15060
        self.local_host = "127.0.0.1"
        self.local_port = 0
        self.transport = "udp"
        self.mac = DEFAULT_MAC
        self.user_agent = DEFAULT_UA
        self.digium_ua_header = True
        self.contact = None
        self.origination_network = None
        self.form = "chain"
        self.bundle = None
        self.pki = DEFAULT_PKI
        self.appserver_check = True
        self.chunk_size = None
        self.chunk_style = "split"
        self.chunk_delay = 5
        self.timeout = 5.0
        self.plain = False
        self.verbose = 0
        self.auto_handshake = True
        self.state = None
        for k, v in kw.items():
            if not hasattr(self, k):
                raise TypeError("unknown option %r" % k)
            setattr(self, k, v)

    @property
    def ami_port(self):
        return 15038 + 100 * int(self.slot) if self.slot else 15038


class Phone:
    """The simulated phone: protocol state plus a SIP endpoint."""

    def __init__(self, opts=None, out=None):
        self.opts = opts or Options()
        self.out = out or sys.stdout
        o = self.opts
        self.sip = SipEndpoint((o.server, o.sip_port), (o.local_host, o.local_port),
                               o.transport, self._log, o.timeout)
        self.session = None
        self.common_password = None
        self.token = None
        self.key = None
        self.handshake_version = None
        self._next_id = random.randint(1, 50000)
        self._partial = {}
        self._waiting = {}                  # transaction id -> Exchange
        self.events = queue.Queue()         # messages nobody waited for
        self._lock = threading.Lock()
        self._pki = None
        self._thread = None
        self._stop = False

    # Setup -------------------------------------------------------------

    def start(self):
        self.sip.start()
        self._thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._thread.start()
        if self.opts.state:
            self.load_state(self.opts.state)
        host, port = self.sip.local_addr
        self._log(1, "--- phone %s at %s:%d/%s, server %s:%d" % (
            self.mac, host, port, self.opts.transport, self.opts.server, self.opts.sip_port))
        return self

    def close(self):
        if self.opts.state:
            self.save_state(self.opts.state)
        self._stop = True
        self.sip.close()
        self.sip.incoming.put(None)                 # wakes the dispatcher
        if self._thread is not None:
            self._thread.join(2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()

    @property
    def pki(self):
        if self._pki is None:
            self._pki = Pki(self.opts.pki)
        return self._pki

    @property
    def mac(self):
        return self.opts.mac

    @property
    def contact_uri(self):
        if self.opts.contact:
            return self.opts.contact
        host, port = self.sip.local_addr
        t = ";transport=tcp" if self.opts.transport == "tcp" else ""
        return "sip:%s@%s:%d%s" % (self.mac, host, port, t)

    @property
    def server_uri(self):
        t = ";transport=tcp" if self.opts.transport == "tcp" else ""
        return "sip:proxy@%s:%d%s" % (self.opts.server, self.opts.sip_port, t)

    @property
    def chunk_size(self):
        if self.opts.chunk_size:
            return self.opts.chunk_size
        return 900 if self.opts.transport == "tcp" else 600

    def _log(self, level, text):
        if self.opts.verbose >= level:
            print(text, file=self.out, flush=True)

    def save_state(self, path):
        state = {"mac": self.mac, "session": self.session, "token": self.token,
                 "common_password": b64encode(self.common_password)
                 if self.common_password else None,
                 "local_port": self.sip.local_addr[1], "contact": self.contact_uri}
        with open(path, "w") as f:
            json.dump(state, f, indent=2)
            f.write("\n")

    def load_state(self, path):
        if not os.path.exists(path):
            return
        with open(path) as f:
            state = json.load(f)
        if state.get("mac") and state["mac"] != self.mac:
            self._log(0, "--- state file is for MAC %s, not %s; ignored" % (state["mac"], self.mac))
            return
        self.session = state.get("session")
        self.token = state.get("token")
        cp = state.get("common_password")
        self.common_password = base64.b64decode(cp) if cp else None
        if state.get("contact") and state["contact"] != self.contact_uri:
            self._log(0, "--- warning: the saved contact %s differs from %s; the server "
                         "will not validate the session (use --local-port %s)" % (
                             state["contact"], self.contact_uri, state.get("local_port")))

    # Incoming ----------------------------------------------------------

    def _dispatch_loop(self):
        while not self._stop:
            try:
                msg = self.sip.incoming.get(timeout=0.5)
            except queue.Empty:
                self._expire_partial()
                continue
            if msg is None:
                return
            try:
                self._add_part(msg)
            except Exception as e:          # never let the dispatcher die
                self._log(0, "--- error handling an incoming message: %r" % e)

    def _expire_partial(self):
        now = time.time()
        with self._lock:
            for key, parts in list(self._partial.items()):
                if now - parts[-1][2].received > 40:
                    del self._partial[key]
                    self._log(0, "--- discarded incomplete message %r (%d chunks)" % (
                        key, len(parts)))

    def _add_part(self, msg):
        """incoming_add_msg on the phone side: group chunks by transaction
        id, salt, and type; a chunk without a sequence, or the chunk with
        Message-Finished once all chunks before it are in, completes it."""
        seq_text = msg.get(H_SEQUENCE)
        finished = bool(msg.get(H_FINISHED))
        key = (msg.get(H_ID) or "", msg.get(H_SALT) or "",
               msg.get(H_RESPONSE_TYPE) or msg.get(H_REQUEST_TYPE) or msg.get(H_EVENT) or
               msg.get(H_ERROR) or "")
        try:
            seq = int(seq_text) if seq_text else None
        except ValueError:
            seq = None
        with self._lock:
            parts = self._partial.setdefault(key, [])
            if seq is not None and any(p[0] == seq for p in parts):
                self._log(1, "--- duplicate chunk %d of %r ignored" % (seq, key))
                return
            parts.append((seq if seq is not None else 0, finished or seq is None, msg))
            parts.sort(key=lambda p: p[0])
            done = [p for p in parts if p[1]]
            if not done or (seq is not None and done[0][0] != len(parts) - 1):
                return
            del self._partial[key]
        self._complete(Reply([p[2] for p in parts]))

    def _complete(self, reply):
        if not (reply.response_type == "HandshakeResponse" and not reply.encrypted):
            reply.decode(self.common_password)
        with self._lock:
            ex = self._waiting.pop(reply.id, None) if reply.id else None
        if ex is not None:
            ex.reply = reply
            ex._done.set()
        else:
            self._log(1, "--- unsolicited %s queued" % reply.type)
            self.events.put(reply)

    # Requests ----------------------------------------------------------

    def new_id(self):
        with self._lock:
            self._next_id = self._next_id % 100000 + 1
            return str(self._next_id)

    def request(self, rtype, body=b"", encrypt=None, session=None, username=None,
                password=None, config_password=None, config_token=None, headers=(),
                wait=True, timeout=None, chunk_size=None, chunk_style=None, txid=None,
                mac=None, contact=None, pem_cuts=False):
        """Send one request (in as many chunks as needed) and, unless `wait`
        is false, wait for the reply with the same transaction id.  `mac`
        and `contact` override the phone's MAC header and Contact URI for
        this request only.  `pem_cuts` ends plaintext chunks at PEM
        BEGIN and END lines (see frame_request_body)."""
        if isinstance(body, str):
            body = body.encode("utf-8", "surrogateescape")
        needs_session = rtype.lower() not in NO_SESSION_TYPES
        if session is None:
            session = self.session if needs_session else None
        if encrypt is None:
            encrypt = (needs_session and self.common_password is not None
                       and not self.opts.plain)
        if encrypt and self.common_password is None:
            raise SimError("cannot encrypt without a common password (no handshake)")
        txid = txid or self.new_id()
        ex = Exchange(rtype, txid)
        ex.encrypted = bool(encrypt)
        salt = os.urandom(8) if encrypt else None
        pw = self.common_password if encrypt else None

        base = [(H_REQUEST_TYPE, rtype), (H_ID, txid), (H_MAC, mac or self.mac)]
        if session:
            base.append((H_SESSION, session))
        if self.opts.origination_network:
            base.append((H_ORIGINATION, self.opts.origination_network))
        if username:
            base.append((H_USERNAME, username))
        for name, value in ((H_PASSWORD, password), (H_CONFIG_PASSWORD, config_password),
                            (H_CONFIG_TOKEN, config_token)):
            if value:
                base.append((name, encrypt_field(pw, salt, value) if encrypt else value))
        if encrypt:
            base.append((H_SALT, salt_hex(salt)))
        base += list(headers)

        chunks = frame_request_body(body, chunk_size or self.chunk_size, pw, salt,
                                    chunk_style or self.opts.chunk_style, pem_cuts)
        ex.chunks = len(chunks)
        with self._lock:
            self._waiting[txid] = ex
        common = [("Contact", "<%s>" % (contact or self.contact_uri)),
                  ("Content-Type", "text/plain")]
        # An empty user agent sends neither header.
        if self.opts.user_agent:
            common.insert(1, ("User-Agent", self.opts.user_agent))
            if self.opts.digium_ua_header:
                # Phones send it; the PJSIP helper identifies them by it.
                common.insert(2, ("X-Digium-User-Agent", self.opts.user_agent))
        # (An empty MAC, for tests of phones without one, still needs a
        # valid From user.)
        from_uri = "sip:%s@%s" % (self.mac or "phone", self.sip.local_addr[0])
        for i, chunk in enumerate(chunks):
            hdrs = common + base + [(H_SEQUENCE, str(i))]
            if i == len(chunks) - 1:
                hdrs.append((H_FINISHED, "1"))
            resp = self.sip.request("MESSAGE", self.server_uri, hdrs, chunk, from_uri=from_uri)
            status = resp.status if resp is not None else None
            ex.sip_statuses.append(status)
            if status is None or not 200 <= status < 300:
                ex.problems.append("SIP MESSAGE %d/%d: %s" % (
                    i + 1, len(chunks), "no response" if status is None
                    else "%d %s" % (status, resp.reason)))
                break
            if i < len(chunks) - 1 and self.opts.chunk_delay:
                time.sleep(self.opts.chunk_delay / 1000.0)
        if ex.problems:
            with self._lock:
                self._waiting.pop(txid, None)
            ex.waited = True
            return ex
        if not wait:
            return ex
        return self.wait_reply(ex, timeout)

    def wait_reply(self, ex, timeout=None):
        """Wait for the reply to `ex` (sent with wait=False, or still
        pending)."""
        timeout = self.opts.timeout if timeout is None else timeout
        ex._done.wait(timeout)
        with self._lock:
            self._waiting.pop(ex.id, None)
        ex.waited = True
        return ex

    def next_event(self, timeout=None, name=None):
        """The next unsolicited message (with `name`, only events of that
        X-Event-Name; others are skipped), or None on timeout."""
        deadline = time.time() + (self.opts.timeout if timeout is None else timeout)
        while True:
            left = deadline - time.time()
            if left <= 0:
                return None
            try:
                r = self.events.get(timeout=left)
            except queue.Empty:
                return None
            if name is None or r.event == name:
                return r
            self._log(0, "--- skipped %s while waiting for %s" % (r.type, name))

    # Request types ------------------------------------------------------

    def handshake(self, bundle=None, **kw):
        """Handshake with a bundle of the test PKI (default from --form):
        recovers the common password with the bundle's key and checks the
        AppServer certificate."""
        name = bundle or self.opts.bundle or self.opts.form
        body, key = self.pki.bundle(name)
        ex = self.request("Handshake", body, encrypt=False, session="", **kw)
        r = ex.reply
        if r is None:
            return ex
        if r.response_type != "HandshakeResponse":
            r.problems.append("expected a HandshakeResponse")
            return ex
        if not r.ok:
            return ex
        if r.encrypted:
            r.problems.append("HandshakeResponse is encrypted")
            return ex
        pw_text = r.first.get(H_PASSWORD)
        if not pw_text or not r.session:
            r.problems.append("HandshakeResponse without %s" % (
                "a password" if not pw_text else "a session"))
            return ex
        try:
            pw = rsa_decrypt_common_password(key, pw_text)
        except SimError as e:
            r.problems.append(str(e))
            return ex
        r.fields["common password"] = "%d bytes %s" % (len(pw), pw.hex())
        r.appserver_ok, r.appserver_info = self.pki.check_appserver(r.raw_body)
        if not r.appserver_ok and self.opts.appserver_check:
            r.problems.append("AppServer certificate check failed")
        self.session = r.session
        self.common_password = pw
        self.key = key
        self.handshake_version = r.first.get(H_HANDSHAKE_VERSION)
        self.token = None
        return ex

    def ensure_session(self):
        if self.session is None and self.opts.auto_handshake:
            ex = self.handshake()
            print(ex.describe(self.opts.verbose), file=self.out, flush=True)
            if not ex.ok or self.session is None:
                raise SimError("automatic handshake failed")

    def ping(self, **kw):
        return self.request("PingRequest", **kw)

    def echo(self, body="", **kw):
        return self.request("Echo", body, **kw)

    def config(self, token=None, **kw):
        return self.request("ConfigRequest", config_token=token or self.token, **kw)

    def get_token(self, user=None, pin=None, config_password=None, **kw):
        ex = self.request("TokenRequest", username=user, password=pin,
                          config_password=config_password, **kw)
        if ex.reply is not None and ex.reply.fields.get(H_CONFIG_TOKEN):
            self.token = ex.reply.fields[H_CONFIG_TOKEN]
        return ex

    def userlist(self, config_password=None, **kw):
        return self.request("UserlistRequest", config_password=config_password, **kw)

    def file(self, name, **kw):
        return self.request("FileRequest", "file://%s" % name, **kw)

    def verify(self, token=None, **kw):
        return self.request("VerifyRequest", config_token=token or self.token, **kw)

    def asterisk(self, request_body, auth=None, rtype="AsteriskRequest", **kw):
        """AsteriskRequest (or HTTPRequest): the credentials line
        X-Digium-AppServer-Digest-Auth=USER:SECRET, then the request
        document."""
        body = ""
        if auth is not None:
            body += "X-Digium-AppServer-Digest-Auth=%s\r\n" % auth
        body += request_body
        return self.request(rtype, body, **kw)


def method_request(method, params=None, fmt="json"):
    """An AsteriskRequest method call document.  `params` is a JSON value
    (json format) or an XML fragment (xml format)."""
    if fmt == "json":
        doc = {"request": {"method": method}}
        if params is not None:
            doc["request"]["parameters"] = params
        return json.dumps(doc)
    return '<request method="%s"><parameters>%s</parameters></request>' % (method, params or "")


# --------------------------------------------------------------------------
# Self-test

def libcrypto_bytes_to_key(password, salt):
    """EVP_BytesToKey through OpenSSL's libcrypto, as an independent check;
    None when libcrypto cannot be loaded."""
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so")
        lib.EVP_aes_128_cbc.restype = ctypes.c_void_p
        lib.EVP_sha1.restype = ctypes.c_void_p
        lib.EVP_BytesToKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_char_p, ctypes.c_char_p]
    except (OSError, AttributeError):
        return None
    key = ctypes.create_string_buffer(16)
    iv = ctypes.create_string_buffer(16)
    lib.EVP_BytesToKey(lib.EVP_aes_128_cbc(), lib.EVP_sha1(), salt, password, len(password),
                       1, key, iv)
    return key.raw, iv.raw


# Known-answer vectors.  Key and IV were computed with OpenSSL's
# EVP_BytesToKey (through ctypes) and agree with the plan's formula
# D1 = SHA1(pass + salt), D2 = SHA1(D1 + pass + salt), key = D1[0:16],
# iv = D1[16:20] + D2[0:12].  The ciphertext comes from `openssl enc
# -aes-128-cbc -K <key> -iv <iv>` (PKCS#7 padding).
KAT_PASSWORD = bytes(range(40))
KAT_SALT = bytes(range(1, 9))
KAT_KEY = bytes.fromhex("600d4ffb274b57fc61281e5709e7f660")
KAT_IV = bytes.fromhex("1886e7fef5d8004f796243b3de6a68aa")
KAT_PLAIN = b"<config></config>"
KAT_CIPHER_B64 = "AUjOV390vW2DtV+JXPqenXE+oRcQpCc41+4TU6Vr6MA="


class FakeServer:
    """A minimal in-process stand-in for the module, for the self-test only:
    it receives MESSAGEs on a UDP socket and processes them the way the
    decompile does (transactions keyed "<ID>-<MAC>", completion when the
    finishing chunk's sequence equals the chunk count minus one, bodies
    concatenated and decoded once with ast_base64decode, header fields
    decrypted with the same salt), then answers with server_frame framing.
    It verifies chains with signatures only (no OpenSSL policy) and knows
    Handshake, PingRequest, TokenRequest, and events."""

    def __init__(self, pki_dir):
        self.pki_dir = pki_dir
        with open(os.path.join(pki_dir, "root-ca.pem"), "rb") as f:
            self.root = x509.load_pem_x509_certificate(f.read())
        with open(os.path.join(pki_dir, "appserver.pem"), "rb") as f:
            self.appserver_pem = f.read()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sessions = {}          # id -> (password, mac, contact)
        self.partial = {}
        self.seen = []              # completed transactions (headers, body)
        self.counter = 0
        self.stop = False
        self.phone_addr = None
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def close(self):
        self.stop = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        self.thread.join(2)

    def loop(self):
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            if not data.strip():
                continue
            msg = parse_sip(data, addr)
            if not msg.is_request:
                continue
            resp = SipMessage("SIP/2.0 202 Accepted", [
                ("Via", msg.get("Via")), ("From", msg.get("From")),
                ("To", msg.get("To") + ";tag=x"), ("Call-ID", msg.get("Call-ID")),
                ("CSeq", msg.get("CSeq")), ("Content-Length", "0")])
            self.sock.sendto(resp.encode(), addr)
            self.phone_addr = addr
            self.add(msg)

    def add(self, msg):
        txid = msg.get(H_ID) or ""
        key = "%s-%s" % (txid, msg.get(H_MAC) or "unknown") if txid else secrets.token_hex(4)
        t = self.partial.setdefault(key, {"parts": [], "fin": None})
        seq_text = msg.get(H_SEQUENCE)
        seq = int(seq_text) if seq_text else 0
        msg.body = asterisk_print_body(msg.body)
        t["parts"].append((seq, msg))
        t["parts"].sort(key=lambda p: p[0])
        if seq_text is None or seq_text == "" or msg.get(H_FINISHED):
            t["fin"] = seq
        if t["fin"] is None or t["fin"] != len(t["parts"]) - 1:
            return
        del self.partial[key]
        first = t["parts"][0][1]
        body = b"".join(p[1].body for p in t["parts"])
        salt_text = first.get(H_SALT)
        fields = {}
        session = self.sessions.get(first.get(H_SESSION) or "")
        if salt_text and session is not None:
            salt = set_hex(salt_text)
            if body:
                body = decrypt(session[0], salt, ast_base64decode(body.decode()))
            for name in (H_PASSWORD, H_CONFIG_PASSWORD, H_CONFIG_TOKEN):
                if first.get(name):
                    fields[name] = decrypt(session[0], salt, ast_base64decode(
                        first.get(name))).decode()
        self.seen.append((first, body, fields))
        self.handle(first, body, fields)

    def send(self, headers, frames):
        for h, wire in frames:
            hdrs = [("Via", "SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%s" % (
                        self.port, secrets.token_hex(6))),
                    ("From", "<sip:server@127.0.0.1>;tag=s"), ("To", "<sip:phone@127.0.0.1>"),
                    ("Call-ID", secrets.token_hex(8)), ("CSeq", "1 MESSAGE")]
            hdrs += list(headers.items()) + list(h.items())
            hdrs.append(("Content-Length", str(len(wire))))
            self.sock.sendto(SipMessage("MESSAGE sip:phone@127.0.0.1 SIP/2.0", hdrs,
                                        wire).encode(), self.phone_addr)

    def handle(self, first, body, fields):
        rtype = first.get(H_REQUEST_TYPE)
        base = {H_ID: first.get(H_ID)}
        if rtype == "Handshake":
            certs = [x509.load_pem_x509_certificate(c) for c in re.findall(
                rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", body, re.S)]
            try:
                if len(certs) == 1:
                    certs[0].verify_directly_issued_by(self.root)
                elif len(certs) == 3:
                    certs[2].verify_directly_issued_by(certs[1])
                    certs[1].verify_directly_issued_by(self.root)
                else:
                    return
            except Exception:
                return              # no reply, as the module
            pw = os.urandom(40)
            sid = str(random.randint(1, 2 ** 31))
            self.sessions[sid] = (pw, first.get(H_MAC), first.get("Contact"))
            base.update({H_RESPONSE_TYPE: "HandshakeResponse", H_SESSION: sid,
                         H_PASSWORD: b64encode(certs[-1].public_key().encrypt(
                             pw, asym_padding.PKCS1v15())),
                         P + "Token-Auth-Requirements": "mac,configpass",
                         P + "Userlist-Auth-Requirements": "disabled"})
            if len(certs) == 3:
                base[H_HANDSHAKE_VERSION] = "1"
            self.send(base, server_frame(self.appserver_pem, SERVER_UDP_PLAIN_LIMIT,
                                         handshake_response=True))
            return
        sid = first.get(H_SESSION) or ""
        if sid not in self.sessions:
            base.update({H_RESPONSE_TYPE: "HandshakeResponse", H_ERROR: "-398"})
            self.send(base, [({}, b"")])
            return
        pw = self.sessions[sid][0]
        salt = os.urandom(8)
        base[H_SESSION] = sid
        if rtype == "PingRequest":
            base[H_RESPONSE_TYPE] = "PingResponse"
            self.send(base, server_frame(b"", SERVER_UDP_ENCRYPTED_LIMIT, pw, salt))
        elif rtype == "TokenRequest":
            base[H_RESPONSE_TYPE] = "TokenResponse"
            base[H_CONFIG_TOKEN] = encrypt_field(pw, salt, "token-for-%s-%s" % (
                fields.get(H_CONFIG_PASSWORD), first.get(H_MAC)))
            self.send(base, server_frame(body, SERVER_UDP_ENCRYPTED_LIMIT, pw, salt))
        elif rtype == "ConfigRequest":
            base[H_RESPONSE_TYPE] = "ConfigResponse"
            doc = ("<config token=%r>" % fields.get(H_CONFIG_TOKEN)).encode() + body + \
                b"x" * 1500 + b"</config>"
            self.send(base, server_frame(doc, SERVER_UDP_ENCRYPTED_LIMIT, pw, salt))

    def event(self, sid, name, body):
        pw = self.sessions[sid][0]
        salt = os.urandom(8)
        self.send({H_EVENT: name, H_SESSION: sid},
                  server_frame(body, SERVER_UDP_ENCRYPTED_LIMIT, pw, salt, COMMAND_PREFIX))


def loopback_test(check, pki_dir):
    """Run the simulator against FakeServer over real UDP sockets."""
    server = FakeServer(pki_dir)
    try:
        for form in ("legacy", "chain"):
            opts = Options(sip_port=server.port, pki=pki_dir, form=form, timeout=3,
                           verbose=-1, chunk_delay=0)
            with Phone(opts, out=open(os.devnull, "w")) as phone:
                ex = phone.handshake()
                r = ex.reply
                check("loopback %s handshake (%d request chunks, %d reply chunks)" % (
                    form, ex.chunks, len(r.parts) if r else 0),
                    ex.ok and phone.common_password is not None and r.appserver_ok
                    and (phone.handshake_version == "1") == (form == "chain"),
                    ex.describe())
                sid = phone.session
                ex = phone.ping()
                check("loopback %s encrypted ping" % form,
                      ex.ok and ex.encrypted and ex.reply.encrypted
                      and ex.reply.body == b"empty body", ex.describe())
                ex = phone.get_token(user="simphone", pin="1234", config_password="344486",
                                     chunk_size=40)
                seen = server.seen[-1]
                check("loopback %s TokenRequest fields and token" % form,
                      ex.ok and seen[2].get(H_PASSWORD) == "1234"
                      and seen[2].get(H_CONFIG_PASSWORD) == "344486"
                      and phone.token == "token-for-344486-%s" % phone.mac, ex.describe())
                big = ("<request>" + "q" * 2000 + "</request>").encode()
                ex = phone.request("ConfigRequest", big, config_token=phone.token)
                check("loopback %s multi-chunk request and reply (%d up, %d down)" % (
                    form, ex.chunks, len(ex.reply.parts) if ex.reply else 0),
                      ex.ok and ex.chunks > 1 and len(ex.reply.parts) > 1
                      and server.seen[-1][1] == big and big in ex.reply.body, ex.describe())
                server.event(sid, "digium.config.update",
                             b"<config>" + b"e" * 900 + b"</config>")
                ev = phone.next_event(timeout=3)
                check("loopback %s multi-chunk encrypted event" % form,
                      ev is not None and ev.event == "digium.config.update"
                      and ev.payload == b"<config>" + b"e" * 900 + b"</config>"
                      and not ev.problems, ev.describe() if ev else "no event")
                phone.session = "12345"
                ex = phone.ping()
                check("loopback %s unknown session gets HandshakeResponse -398" % form,
                      ex.reply is not None and ex.reply.response_type == "HandshakeResponse"
                      and ex.reply.error == "-398" and not ex.ok, ex.describe())
        opts = Options(sip_port=server.port, pki=pki_dir, bundle="rogue", timeout=1,
                       verbose=-1)
        with Phone(opts) as phone:
            ex = phone.handshake()
            check("loopback rogue certificate gets no reply", ex.reply is None and not ex.ok)
    finally:
        server.close()


def selftest(out=sys.stdout, pki_dir=DEFAULT_PKI, show_vectors=False):
    failures = []

    def check(label, cond, detail=""):
        print("%-4s %s%s" % ("ok" if cond else "FAIL", label,
                             (": %s" % (detail,)) if detail and not cond else ""), file=out)
        if not cond:
            failures.append(label)

    # Key and IV derivation.
    key, iv = evp_bytes_to_key(KAT_PASSWORD, KAT_SALT)
    check("EVP_BytesToKey known answer", (key, iv) == (KAT_KEY, KAT_IV),
          "%s %s" % (key.hex(), iv.hex()))
    d1 = hashlib.sha1(KAT_PASSWORD + KAT_SALT).digest()
    d2 = hashlib.sha1(d1 + KAT_PASSWORD + KAT_SALT).digest()
    check("key/IV equal the plan's D1/D2 formula", (key, iv) == (d1[:16], d1[16:20] + d2[:12]))
    if libcrypto_bytes_to_key(b"x", b"12345678") is None:
        print("skip EVP_BytesToKey against libcrypto (not loadable)", file=out)
    else:
        same = all(libcrypto_bytes_to_key(pw, salt) == evp_bytes_to_key(pw, salt)
                   for pw, salt in ((os.urandom(40), os.urandom(8)) for _ in range(20)))
        check("EVP_BytesToKey equals libcrypto's (20 random inputs)", same)

    # AES-128-CBC known answer.
    ct = encrypt(KAT_PASSWORD, KAT_SALT, KAT_PLAIN)
    check("AES-128-CBC known answer", b64encode(ct) == KAT_CIPHER_B64, b64encode(ct))
    check("decrypt known answer", decrypt(KAT_PASSWORD, KAT_SALT, ct) == KAT_PLAIN)
    check("empty plaintext encrypts to one padding block",
          len(encrypt(KAT_PASSWORD, KAT_SALT, b"")) == 16)

    # Stream encryption: chunked updates equal one-shot encryption.
    data = os.urandom(2000)
    whole = encrypt(KAT_PASSWORD, KAT_SALT, data)
    ok = True
    for cuts in ([420], [1, 15, 16, 17], [0x1a4] * 4, [900, 900], [7] * 100):
        e = StreamEncryptor(KAT_PASSWORD, KAT_SALT)
        pieces = []
        pos = 0
        for c in cuts:
            pieces.append(e.update(data[pos:pos + c]))
            pos += c
        pieces.append(e.update(data[pos:]) + e.finish())
        ok &= all(len(p) % 16 == 0 for p in pieces) and b"".join(pieces) == whole
    check("stream updates give whole blocks and equal one-shot encryption", ok)

    # Header fields and salts.
    salt = os.urandom(8)
    pw = os.urandom(40)
    ok = all(decrypt_field(pw, salt, encrypt_field(pw, salt, v)).decode() == v
             for v in ("1234", "", "x" * 100, "päss"))
    check("encrypted header fields round trip", ok)
    check("salt hex is 16 uppercase digits",
          re.fullmatch(r"[0-9A-F]{16}", salt_hex(salt)) is not None)
    check("set_hex parses both cases",
          set_hex(salt_hex(salt)) == salt and set_hex(salt_hex(salt).lower()) == salt)
    check("set_hex zero fills short strings", set_hex("ABC") == b"\xab\xc0" + b"\0" * 6)
    try:
        set_hex("0" * 17)
        check("set_hex rejects more than 16 digits", False)
    except SimError:
        check("set_hex rejects more than 16 digits", True)

    # ast_base64decode quirks.
    check("ast_base64decode stops at '='", ast_base64decode("QUJD=QUJD") == b"ABC")
    check("ast_base64decode maps non-alphabet characters to 63",
          ast_base64decode("QU*D") == base64.b64decode("QU/D"))

    # Phone-to-server framing: what the server's reassembly sees.
    body = os.urandom(1500)
    salt = os.urandom(8)
    ok = True
    for size in (600, 100, 4):
        wire = frame_request_body(body, size, pw, salt, "split")
        joined = b"".join(wire).decode()
        ok &= (all(len(w) <= size for w in wire)
               and decrypt(pw, salt, ast_base64decode(joined)) == body)
    check("split framing reassembles as the server does (concatenate, decode once)", ok)
    wire = frame_request_body(body, 420, pw, salt, "stream")
    joined = b"".join(wire).decode()
    check("stream framing: a single server-side decode stops at mid-stream '=' padding",
          "=" in joined[:-4] and len(ast_base64decode(joined)) < len(body))
    check("stream framing decodes chunk by chunk",
          decrypt(pw, salt, b"".join(b64decode_strict(w.decode()) for w in wire)) == body)
    check("plaintext framing splits at the size",
          [len(c) for c in frame_request_body(b"a" * 1300, 600)] == [600, 600, 100])
    text = b"line one\r\nline two\nline three\n" * 30
    for size in (9, 10, 11, 50, 600):
        pieces = frame_request_body(text, size)
        if b"".join(asterisk_print_body(p) for p in pieces) != text.rstrip(b"\r\n"):
            check("plaintext chunks survive print_body's CR/LF stripping (size %d)" % size,
                  False)
            break
    else:
        check("plaintext chunks survive print_body's CR/LF stripping", True)
    pem = (b"-----BEGIN CERTIFICATE-----\n" + b"QUJD" * 16 + b"\n" + b"REVG" * 5 + b"\n"
           b"-----END CERTIFICATE-----\n") * 2
    pieces = frame_request_body(pem, 50, pem_cuts=True)
    check("PEM cuts: chunks end at BEGIN and END lines, at most the size",
          b"".join(pieces) == pem and all(len(p) <= 50 for p in pieces)
          and b"".join(asterisk_print_body(p) for p in pieces) == pem.replace(
              b"-----\n", b"-----").replace(b"\n-----", b"-----"))

    # Server-to-phone framing, emulating phone_msg_outgoing_send, against
    # this simulator's reassembly (chunks delivered in random order).
    def via_reassembly(frames, extra):
        phone = Phone(Options(verbose=-1))
        phone.common_password = pw
        order = list(frames)
        random.shuffle(order)
        for hdrs, wire in order:
            h = [(H_ID, "77")] + list(extra.items()) + list(hdrs.items())
            phone._add_part(SipMessage("MESSAGE sip:x@y SIP/2.0", h, wire))
        return phone.events.get_nowait() if not phone.events.empty() else None

    cases = [
        ("encrypted UDP reply", os.urandom(1000), SERVER_UDP_ENCRYPTED_LIMIT, True, b"",
         {H_RESPONSE_TYPE: "ConfigResponse"}),
        ("encrypted TCP reply", os.urandom(1000), SERVER_TCP_LIMIT, True, b"",
         {H_RESPONSE_TYPE: "ConfigResponse"}),
        ("encrypted event, prefix in every chunk", b"<config>" + b"y" * 900 + b"</config>",
         SERVER_UDP_ENCRYPTED_LIMIT, True, COMMAND_PREFIX, {H_EVENT: "digium.config.update"}),
        ("encrypted error reply", b'<error msg="Session Timeout" />',
         SERVER_UDP_ENCRYPTED_LIMIT, True, COMMAND_PREFIX,
         {H_RESPONSE_TYPE: "ConfigResponse", H_ERROR: "-398"}),
        ("plaintext event over UDP", b"e" * 1000, SERVER_UDP_PLAIN_LIMIT, False, COMMAND_PREFIX,
         {H_EVENT: "x"}),
        ("plaintext HandshakeResponse, UDP", b"z" * 700, SERVER_UDP_PLAIN_LIMIT, False, b"",
         {H_RESPONSE_TYPE: "HandshakeResponse"}),
        ("plaintext HandshakeResponse, TCP", b"z" * 700, SERVER_TCP_LIMIT, False, b"",
         {H_RESPONSE_TYPE: "HandshakeResponse"}),
        ("empty body is sent as 'empty body'", b"", SERVER_UDP_ENCRYPTED_LIMIT, True, b"",
         {H_RESPONSE_TYPE: "PingResponse"}),
    ]
    for label, payload, limit, enc, prefix, extra in cases:
        s = os.urandom(8) if enc else None
        hs = extra.get(H_RESPONSE_TYPE) == "HandshakeResponse"
        frames = server_frame(payload, limit, pw if enc else None, s, prefix, hs)
        if hs and len(frames) == 1:
            ok = H_SEQUENCE not in frames[0][0]
        else:
            ok = ([f[0].get(H_SEQUENCE) for f in frames] == [str(i) for i in range(len(frames))]
                  and [H_FINISHED in f[0] for f in frames]
                  == [False] * (len(frames) - 1) + [True])
        ok &= all(len(f[1]) <= limit for f in frames) if not enc else True
        r = via_reassembly(frames, extra)
        ok = ok and r is not None and r.payload == (payload or b"empty body") and not r.problems
        check("server framing: %s (%d chunks)" % (label, len(frames)), ok,
              r.problems if r else "no message")

    # RSA common password and AppServer check with the test PKI.
    try:
        pki = Pki(pki_dir)
        for name in ("legacy", "chain", "weak"):
            if name not in pki.manifest["bundles"]:
                continue
            body, key = pki.bundle(name)
            certs = re.findall(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
                               body, re.S)
            pub = x509.load_pem_x509_certificate(certs[-1]).public_key()
            common = os.urandom(40)
            enc_pw = b64encode(pub.encrypt(common, asym_padding.PKCS1v15()))
            check("common password round trip with the %s key (%d bits)" % (
                name, key.key_size), rsa_decrypt_common_password(key, enc_pw) == common)
        with open(os.path.join(pki_dir, "appserver.pem"), "rb") as f:
            ok, info = pki.check_appserver(f.read())
        check("the test AppServer certificate verifies against the test AppServer CA",
              ok, info)
        with open(os.path.join(pki_dir, "phone.pem"), "rb") as f:
            ok, info = pki.check_appserver(f.read())
        check("a phone certificate is not accepted as the AppServer", not ok, info)
        loopback_test(check, pki_dir)
    except SimError as e:
        print("skip PKI checks: %s" % e, file=out)

    path = os.path.join(HERE, "vectors.json")
    if os.path.exists(path):
        with open(path) as f:
            check("vectors.json matches this implementation", json.load(f) == make_vectors())
    if os.path.exists(PROTO_VECTORS):
        check_proto_vectors(check)
    else:
        print("skip proto_vectors.json (not found: %s)" % PROTO_VECTORS, file=out)
    if show_vectors:
        print(json.dumps(make_vectors(), indent=2), file=out)
    print("%d failure(s)" % len(failures), file=out)
    return not failures


PROTO_VECTORS = os.path.join(HERE, "..", "..", "crates", "dpma-proto", "tests", "fixtures",
                             "proto_vectors.json")


def check_proto_vectors(check, path=PROTO_VECTORS):
    """Cross-check this implementation against the Rust crate's vectors
    (crates/dpma-proto/tests/fixtures/proto_vectors.json, written by
    dpma-proto's tests/vectors.rs)."""
    with open(path) as f:
        v = json.load(f)
    ok = all(evp_bytes_to_key(bytes.fromhex(c["password_hex"]), set_hex(c["salt_hex"]))
             == (bytes.fromhex(c["key_hex"]), bytes.fromhex(c["iv_hex"])) for c in v["kdf"])
    check("proto_vectors: key and IV (%d)" % len(v["kdf"]), ok)
    ok = True
    for c in v["encrypt_field"]:
        pw, salt = bytes.fromhex(c["password_hex"]), set_hex(c["salt_hex"])
        ok &= encrypt_field(pw, salt, c["plain"]) == c["b64"]
        ok &= decrypt_field(pw, salt, c["b64"]) == c["plain"].encode()
    check("proto_vectors: header fields (%d)" % len(v["encrypt_field"]), ok)
    ok = True
    for c in v["salt_from_hex"]:
        try:
            got = set_hex(c["hex"])
            ok &= not c.get("error") and got.hex() == c["bytes_hex"]
        except SimError:
            ok &= bool(c.get("error"))
    check("proto_vectors: set_hex (%d)" % len(v["salt_from_hex"]), ok)
    ok = all(ast_base64decode(c["text"], c["max"] if c["max"] is not None else 1 << 30).hex()
             == c["bytes_hex"] for c in v["base64_decode"])
    check("proto_vectors: ast_base64decode (%d)" % len(v["base64_decode"]), ok)
    ok = True
    for c in v["split"]:
        frames = server_frame(c["body"].encode(), c["limit"], prefix=c["prefix"].encode(),
                              handshake_response=c["handshake_response"])
        got = [{"sequence": int(h[H_SEQUENCE]) if H_SEQUENCE in h else None,
                "finished": H_FINISHED in h, "plain": w.decode()} for h, w in frames]
        ok &= got == c["chunks"]
    check("proto_vectors: chunking (%d)" % len(v["split"]), ok)
    ok = True
    for c in v["outgoing_encrypted"]:
        pw, salt = bytes.fromhex(c["password_hex"]), set_hex(c["salt_hex"])
        frames = server_frame(c["body"].encode(), c["limit"], pw, salt, c["prefix"].encode())
        got = [{"sequence": int(h[H_SEQUENCE]), "finished": H_FINISHED in h, "b64": w.decode()}
               for h, w in frames]
        ok &= got == c["chunks"]
        plain = decrypt(pw, salt, b"".join(b64decode_strict(w["b64"]) for w in c["chunks"]))
        ok &= plain == b"".join(c["prefix"].encode() + p for p in split_bytes(
            c["body"].encode(), c["limit"] - len(c["prefix"])))
    check("proto_vectors: server-to-phone encrypted chunks (%d)" % len(v["outgoing_encrypted"]),
          ok)
    ok = True
    for c in v["incoming_from_phone"]:
        pw, salt = bytes.fromhex(c["password_hex"]), set_hex(c["salt_hex"])
        parts = frame_request_body(c["body"].encode(), c["chunk_len"], pw, salt, "split")
        ok &= [p.decode() for p in parts] == c["parts"]
        ok &= decrypt(pw, salt, ast_base64decode("".join(c["parts"]))) == c["body"].encode()
    check("proto_vectors: phone-to-server encrypted chunks (%d)" % len(v["incoming_from_phone"]),
          ok)
    r = v["rsa_common_password"]
    key = serialization.load_pem_private_key(r["private_key_pem"].encode(), None)
    check("proto_vectors: RSA common password",
          rsa_decrypt_common_password(key, r["password_b64"]).hex() == r["common_password_hex"])
    ok = all(error_body(c["code"]) == c["body"] and MSG_ERROR_TEXT.get(c["code"], "Unknown error")
             == c["text"] for c in v["error_bodies"])
    check("proto_vectors: error bodies (%d)" % len(v["error_bodies"]), ok)


def make_vectors():
    """Deterministic vectors for cross-checking other implementations
    (dpma-proto), saved in dev/sim/vectors.json: key and IV derivation, a
    body, a header field, and the server's framing of an encrypted event
    over UDP (prefix in every chunk, one CBC stream, each chunk's
    ciphertext base64 encoded on its own), all with a fixed password and
    salt."""
    pw, salt = KAT_PASSWORD, KAT_SALT
    body = ("<config>" + "0123456789" * 100 + "</config>").encode()
    frames = server_frame(body, SERVER_UDP_ENCRYPTED_LIMIT, pw, salt, COMMAND_PREFIX)
    return {
        "password_hex": pw.hex(),
        "salt_hex": salt_hex(salt),
        "key_hex": KAT_KEY.hex(),
        "iv_hex": KAT_IV.hex(),
        "plain": KAT_PLAIN.decode(),
        "cipher_b64": b64encode(encrypt(pw, salt, KAT_PLAIN)),
        "field_1234_b64": encrypt_field(pw, salt, "1234"),
        "event_body": body.decode(),
        "event_frames_udp": [{"headers": h, "body": w.decode()} for h, w in frames],
    }


# --------------------------------------------------------------------------
# Command line

def add_request_options(p):
    p.add_argument("--no-wait", action="store_true",
                   help="send without waiting for the reply (scripts: wait-reply)")
    p.add_argument("--timeout", dest="cmd_timeout", type=float, metavar="SECONDS",
                   help="reply timeout in seconds (default: the global --timeout)")
    p.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'",
                   help="extra header for every chunk (repeatable)")
    p.add_argument("--chunk-size", dest="cmd_chunk_size", type=int, metavar="BYTES",
                   help="max body bytes per MESSAGE for this request")
    p.add_argument("--pem-cuts", action="store_true",
                   help="end plaintext chunks right before and after every PEM BEGIN and "
                        "END line, so the server loses those line breaks")


class ScriptParser(argparse.ArgumentParser):
    def error(self, message):
        raise SimError(message)

    def exit(self, status=0, message=None):
        raise SimError(message or "exit")


def build_parser(script=False):
    if script:
        ap = ScriptParser(prog="script", add_help=False)
    else:
        ap = argparse.ArgumentParser(
            description="Simulate a Digium phone against res_digium_phone.",
            epilog="See dev/sim/README.md for the test configuration and scripts.")
        g = ap.add_argument_group("connection")
        g.add_argument("--slot", help="instance slot: SIP port 15060+100*slot, AMI port "
                                      "15038+100*slot (default: $DPMA_SLOT)")
        g.add_argument("--server", default="127.0.0.1", help="Asterisk address")
        g.add_argument("--sip-port", type=int, help="Asterisk SIP port (overrides --slot)")
        g.add_argument("--local-host", default="127.0.0.1")
        g.add_argument("--local-port", type=int, default=0,
                       help="local SIP port (default: any; reused from --state)")
        g.add_argument("--transport", choices=("udp", "tcp"), default="udp")
        g = ap.add_argument_group("phone")
        g.add_argument("--mac", default=DEFAULT_MAC, help="default %(default)s")
        g.add_argument("--user-agent", default=DEFAULT_UA,
                       help="default %(default)r; '' sends no User-Agent headers")
        g.add_argument("--no-digium-ua-header", action="store_true",
                       help="do not send X-Digium-User-Agent (by which the PJSIP helper "
                            "res_pjsip_endpoint_identifier_dpma identifies phones)")
        g.add_argument("--contact", help="Contact URI (default sip:<mac>@<local address>)")
        g.add_argument("--origination-network", help="send X-Origination-Network")
        g.add_argument("--form", choices=("legacy", "chain"), default="chain",
                       help="certificate form for the handshake (default chain)")
        g.add_argument("--bundle", help="handshake bundle from pki/bundles.json "
                                        "(overrides --form)")
        g.add_argument("--pki", default=DEFAULT_PKI, help="test PKI directory")
        g.add_argument("--no-appserver-check", action="store_true",
                       help="do not fail when the AppServer certificate does not verify")
        g.add_argument("--no-auto-handshake", action="store_true",
                       help="do not handshake before a request that needs a session")
        g.add_argument("--state", help="load and save the session in this JSON file")
        g = ap.add_argument_group("framing")
        g.add_argument("--chunk-size", type=int,
                       help="max body bytes per MESSAGE (default 600 UDP, 900 TCP)")
        g.add_argument("--chunk-style", choices=("split", "stream"), default="split",
                       help="encrypted chunking (see README; default split)")
        g.add_argument("--chunk-delay", type=float, default=5,
                       help="ms between chunks (default 5)")
        g.add_argument("--plain", action="store_true",
                       help="send requests unencrypted even with a session")
        g.add_argument("--timeout", type=float, default=5.0,
                       help="reply timeout in seconds (default 5)")
        g.add_argument("-v", "--verbose", action="count", default=0,
                       help="-v: SIP summary, -vv: full SIP messages")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    p = sub.add_parser("handshake", help="handshake (legacy or chain certificate form)")
    p.add_argument("--bundle", dest="cmd_bundle", help="bundle (default from --form)")
    add_request_options(p)

    p = sub.add_parser("ping", help="PingRequest")
    add_request_options(p)

    p = sub.add_parser("echo", help="Echo (unencrypted, no session)")
    p.add_argument("body", nargs="?", default="hello from dpma_sim")
    add_request_options(p)

    p = sub.add_parser("config", help="ConfigRequest with the configuration token")
    p.add_argument("--token", help="token (default: from the last TokenRequest)")
    add_request_options(p)

    p = sub.add_parser("token", help="TokenRequest")
    p.add_argument("--user", help="X-Digium-AppServer-Username (phone name)")
    p.add_argument("--pin", help="X-Digium-AppServer-Password (phone pin)")
    p.add_argument("--config-pass",
                   help="X-Digium-AppServer-ConfigPassword (global or group pin)")
    add_request_options(p)

    p = sub.add_parser("userlist", help="UserlistRequest")
    p.add_argument("--config-pass", help="X-Digium-AppServer-ConfigPassword")
    add_request_options(p)

    p = sub.add_parser("file", help="FileRequest for file://NAME")
    p.add_argument("name", help="default, null, or a file in file_directory")
    add_request_options(p)

    p = sub.add_parser("verify", help="VerifyRequest with the configuration token")
    p.add_argument("--token", help="token (default: from the last TokenRequest)")
    add_request_options(p)

    p = sub.add_parser("asterisk", help="AsteriskRequest or HTTPRequest (method call)")
    p.add_argument("--auth", help="credentials USER:SECRET (phone name and pin, or line "
                                  "and secret) for X-Digium-AppServer-Digest-Auth")
    p.add_argument("--type", default="AsteriskRequest",
                   choices=("AsteriskRequest", "HTTPRequest"))
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--method", help="method name (with --params and --format)")
    g.add_argument("--xml", help="a complete <request method=...> document")
    g.add_argument("--json", help='a complete {"request": ...} document')
    g.add_argument("--body", help="the complete body (credentials included), sent as is")
    p.add_argument("--params", help="JSON value (json) or XML fragment (xml)")
    p.add_argument("--format", choices=("json", "xml"), default="json")
    add_request_options(p)

    p = sub.add_parser("raw", help="any request type, for negative tests")
    p.add_argument("type", help="X-Digium-AppServer-RequestType")
    p.add_argument("--body", default="", help="body text, or @FILE")
    p.add_argument("--encrypt", choices=("auto", "yes", "no"), default="auto")
    p.add_argument("--session", help="session id to send (default: the current one; "
                                     "'' for none)")
    p.add_argument("--username")
    p.add_argument("--password")
    p.add_argument("--config-password")
    p.add_argument("--config-token")
    p.add_argument("--id", help="transaction id")
    p.add_argument("--mac", dest="raw_mac", metavar="MAC", help="MAC header for this request")
    p.add_argument("--contact", dest="raw_contact", metavar="URI",
                   help="Contact URI for this request")
    add_request_options(p)

    p = sub.add_parser("listen", help="print incoming messages (events)")
    p.add_argument("--seconds", type=float, default=None,
                   help="stop after SECONDS (default: forever; in scripts --timeout)")
    p.add_argument("--count", type=int, help="stop after COUNT messages")
    p.add_argument("--event", help="only this X-Event-Name (others are skipped)")

    if not script:
        p = sub.add_parser("script", help="run a script (see README); exit 1 on failure")
        p.add_argument("file", help="script file, or - for stdin")
        p.add_argument("--keep-going", action="store_true", help="run to the end on failure")
        p = sub.add_parser("selftest", help="crypto and framing self-test (no server needed)")
        p.add_argument("--vectors", action="store_true", help="also print test vectors (JSON)")
    else:
        p = sub.add_parser("wait-reply")
        p.add_argument("--timeout", dest="cmd_timeout", type=float)
        p = sub.add_parser("expect")
        p.add_argument("conditions", nargs="+")
        p = sub.add_parser("set")
        p.add_argument("assignment")
        p = sub.add_parser("capture")
        p.add_argument("name")
        p.add_argument("source")
        p.add_argument("regex", nargs="?")
        p = sub.add_parser("sleep")
        p.add_argument("seconds", type=float)
        p = sub.add_parser("print")
        p.add_argument("text", nargs="*")
        sub.add_parser("forget")
        p = sub.add_parser("ami")
        p.add_argument("action")
        p.add_argument("fields", nargs="*")
        p.add_argument("--timeout", dest="cmd_timeout", type=float)
        p = sub.add_parser("ami-event")
        p.add_argument("event")
        p.add_argument("match", nargs="*")
        p.add_argument("--timeout", dest="cmd_timeout", type=float)
        p = sub.add_parser("cli")
        p.add_argument("words", nargs="+")
        p = sub.add_parser("expect-ami")
        p.add_argument("conditions", nargs="+")
    return ap


def options_from_args(a):
    kw = {}
    if a.sip_port:
        kw["sip_port"] = a.sip_port
    return Options(
        slot=a.slot, server=a.server, local_host=a.local_host, local_port=a.local_port,
        transport=a.transport, mac=a.mac.replace(":", "").lower(),
        user_agent=a.user_agent, digium_ua_header=not a.no_digium_ua_header,
        contact=a.contact, origination_network=a.origination_network,
        form=a.form, bundle=a.bundle, pki=a.pki, appserver_check=not a.no_appserver_check,
        chunk_size=a.chunk_size, chunk_style=a.chunk_style, chunk_delay=a.chunk_delay,
        timeout=a.timeout, plain=a.plain, verbose=a.verbose,
        auto_handshake=not a.no_auto_handshake, state=a.state, **kw)


def parse_header_args(items):
    out = []
    for it in items:
        if ":" not in it:
            raise SimError("bad --header %r (use 'Name: Value')" % it)
        k, v = it.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out


def run_request_command(phone, a):
    """Run one request subcommand and return its Exchange."""
    kw = {"headers": parse_header_args(a.header), "wait": not a.no_wait}
    if a.cmd_timeout is not None:
        kw["timeout"] = a.cmd_timeout
    if a.cmd_chunk_size:
        kw["chunk_size"] = a.cmd_chunk_size
    if a.pem_cuts:
        kw["pem_cuts"] = True
    c = a.command
    if c not in ("handshake", "echo") and not (c == "raw" and (
            a.type.lower() in NO_SESSION_TYPES or a.session is not None)):
        phone.ensure_session()
    if c == "handshake":
        return phone.handshake(a.cmd_bundle, **kw)
    if c == "ping":
        return phone.ping(**kw)
    if c == "echo":
        return phone.echo(a.body, **kw)
    if c == "config":
        return phone.config(a.token, **kw)
    if c == "token":
        return phone.get_token(a.user, a.pin, a.config_pass, **kw)
    if c == "userlist":
        return phone.userlist(a.config_pass, **kw)
    if c == "file":
        return phone.file(a.name, **kw)
    if c == "verify":
        return phone.verify(a.token, **kw)
    if c == "asterisk":
        if a.body is not None:
            return phone.request(a.type, a.body, **kw)
        if a.method:
            params = a.params
            if params is not None and a.format == "json":
                params = json.loads(params)
            doc = method_request(a.method, params, a.format)
        else:
            doc = a.xml or a.json
        return phone.asterisk(doc, a.auth, a.type, **kw)
    if c == "raw":
        body = a.body
        if body.startswith("@"):
            with open(body[1:], "rb") as f:
                body = f.read()
        enc = {"auto": None, "yes": True, "no": False}[a.encrypt]
        return phone.request(a.type, body, encrypt=enc, session=a.session,
                             username=a.username, password=a.password,
                             config_password=a.config_password, config_token=a.config_token,
                             txid=a.id, mac=a.raw_mac, contact=a.raw_contact, **kw)
    raise SimError("unknown command %s" % c)


def command_ok(c, ex):
    """Success of a request command: for raw, any decodable reply;
    otherwise the expected response type without an error."""
    if c == "raw":
        return ex.sip_ok and not ex.problems and ex.reply is not None and not ex.reply.problems
    return ex.ok


def run_listen(phone, a, default_seconds=None):
    seconds = a.seconds if a.seconds is not None else default_seconds
    deadline = time.time() + seconds if seconds is not None else None
    got = []
    while a.count is None or len(got) < a.count:
        if deadline is not None and time.time() >= deadline:
            break
        left = 3600 if deadline is None else deadline - time.time()
        r = phone.next_event(timeout=left, name=a.event)
        if r is None:
            continue
        got.append(r)
        print(r.describe(phone.opts.verbose), flush=True)
    return got


# --------------------------------------------------------------------------
# Scripts

class Script:
    """Runs a script: one command per line (shell-like quoting, # comments).
    See README.md for the commands and conditions."""

    def __init__(self, phone, keep_going=False):
        self.phone = phone
        self.keep_going = keep_going
        self.parser = build_parser(script=True)
        self.vars = {}
        self.last = None            # last Exchange
        self.last_reply = None      # last Reply (of an exchange or listen)
        self.pending = None         # last --no-wait Exchange
        self.ami = None
        self.last_ami = None
        self.failures = 0

    def expand(self, text):
        def sub(m):
            v = self.variable(m.group(1))
            if v is None:
                raise SimError("undefined variable ${%s}" % m.group(1))
            return v
        return re.sub(r"\$\{([^}]+)\}", sub, text)

    def variable(self, name):
        if name in self.vars:
            return self.vars[name]
        p = self.phone
        r = self.last_reply
        if name.startswith("ami.") and self.last_ami is not None:
            return self.last_ami.get(name[4:])
        if name.startswith("env."):
            return os.environ.get(name[4:])
        return {
            "session": p.session, "token": p.token, "mac": p.mac, "contact": p.contact_uri,
            "transport": p.opts.transport,
            "id": self.last.id if self.last else None,
            "body": r.body.decode("utf-8", "replace") if r else None,
            "payload": r.payload.decode("utf-8", "replace") if r else None,
            "error": (r.error or "") if r else None,
            "type": r.type if r else None,
        }.get(name)

    def run_file(self, path):
        if path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(path) as f:
                lines = f.read().splitlines()
        name = "stdin" if path == "-" else os.path.basename(path)
        for n, line in enumerate(lines, 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            print("## %s:%d: %s" % (name, n, text), flush=True)
            try:
                ok = self.run_line(text)
            except SimError as e:
                print("FAIL: %s" % e, flush=True)
                ok = False
            if not ok:
                self.failures += 1
                print("FAILED at %s:%d" % (name, n), flush=True)
                if not self.keep_going:
                    return False
        if self.failures:
            print("%d failure(s)" % self.failures)
            return False
        print("script passed")
        return True

    def run_line(self, text):
        tolerant = text.startswith("try ")
        if tolerant:
            text = text[4:]
        a = self.parser.parse_args([self.expand(w) for w in shlex.split(text)])
        c = a.command
        p = self.phone
        if c == "expect":
            return self.expect(a.conditions)
        if c == "set":
            if "=" not in a.assignment:
                raise SimError("set NAME=VALUE")
            k, v = a.assignment.split("=", 1)
            self.vars[k] = v
            return True
        if c == "capture":
            return self.capture(a.name, a.source, a.regex)
        if c == "sleep":
            time.sleep(a.seconds)
            return True
        if c == "print":
            print(" ".join(a.text))
            return True
        if c == "forget":
            p.session = p.common_password = p.token = None
            return True
        if c == "wait-reply":
            if self.pending is None:
                raise SimError("no request sent with --no-wait")
            ex = p.wait_reply(self.pending, a.cmd_timeout)
            self.pending = None
            self.last, self.last_reply = ex, ex.reply
            print(ex.describe(p.opts.verbose))
            return tolerant or command_ok(ex.request_type, ex)
        if c in ("ami", "ami-event", "cli", "expect-ami"):
            return self.ami_command(a, tolerant)
        if c == "listen":
            got = run_listen(p, a, default_seconds=p.opts.timeout)
            self.last_reply = got[-1] if got else None
            if not got:
                print("(no message)")
            return tolerant or len(got) >= (a.count or 1)
        ex = run_request_command(p, a)
        self.last = ex
        self.last_reply = ex.reply
        print(ex.describe(p.opts.verbose))
        if a.no_wait:
            self.pending = ex
            return tolerant or ex.sip_ok
        return tolerant or command_ok(c, ex)

    def capture(self, name, source, regex):
        value = self.source_value(source)
        if value is None:
            raise SimError("nothing to capture from %s" % source)
        if regex:
            m = re.search(regex, value, re.S)
            if not m:
                raise SimError("%s does not match %r" % (source, regex))
            value = m.group(1) if m.groups() else m.group(0)
        self.vars[name] = value
        print("%s = %s" % (name, value))
        return True

    def source_value(self, source):
        if source.startswith("ami:"):
            if self.last_ami is None:
                return None
            vals = self.last_ami.getall(source[4:])
            return "\n".join(vals) if vals else None
        r = self.last_reply
        if source in ("body", "payload") or source.startswith(("header:", "field:")):
            if r is None:
                return None
            if source == "body":
                return r.body.decode("utf-8", "replace")
            if source == "payload":
                return r.payload.decode("utf-8", "replace")
            if source.startswith("header:"):
                return r.header(source[7:])
            name = source[6:].lower()
            for k, v in r.fields.items():
                if k.lower() in (name, (P + name).lower()):
                    return v
            return None
        return self.variable(source)

    def expect(self, conditions):
        ok = True
        for cond in conditions:
            good, detail = self.check(cond)
            print("  %s %s%s" % ("ok  " if good else "FAIL", cond,
                                 "" if good else "  (%s)" % detail))
            ok &= good
        return ok

    def check(self, cond):
        m = re.match(r"^([A-Za-z_][\w.-]*(?::[\w.-]+)?)(!=|=|~|\?|!)(.*)$", cond, re.S)
        if not m:
            raise SimError("bad condition %r" % cond)
        key, op, want = m.groups()
        r = self.last_reply
        ex = self.last
        if key == "reply":
            return self.compare("none" if r is None else "yes", op, want)
        if key == "status":
            if ex is None:
                return False, "no request"
            have = ",".join(str(s) for s in ex.sip_statuses)
            if op == "=":
                return all(str(s) == want for s in ex.sip_statuses), "SIP %s" % have
            return self.compare(have, op, want)
        if key == "session":
            return self.compare("none" if self.phone.session is None else "set", op, want)
        if r is None:
            return False, "no reply"
        if key == "type":
            have = r.type
        elif key == "event":
            have = r.event
        elif key == "error":
            have = r.error if r.error is not None else "none"
        elif key == "chunks":
            have = str(len(r.parts))
        elif key == "transport":
            have = r.transports
        elif key == "encrypted":
            have = "yes" if r.encrypted else "no"
        elif key == "appserver":
            have = {True: "ok", False: "fail", None: "none"}[r.appserver_ok]
        elif key == "problems":
            have = "; ".join(r.problems) or "none"
        elif key in ("body", "payload") or key.startswith(("header:", "field:")):
            have = self.source_value(key)
        else:
            raise SimError("unknown condition key %r" % key)
        return self.compare(have, op, want)

    @staticmethod
    def compare(have, op, want):
        if op == "?":
            return have is not None, "absent"
        if op == "!":
            return have is None, "present: %r" % (have,)
        if have is None:
            return False, "absent"
        if op == "=":
            return have == want, "is %r" % (have,)
        if op == "!=":
            return have != want, "is %r" % (have,)
        return re.search(want, have, re.S) is not None, "is %r" % (
            have if len(have) < 300 else have[:300] + "...",)

    # AMI ----------------------------------------------------------------

    def ami_client(self):
        if self.ami is None:
            from ami import AmiClient
            self.ami = AmiClient(port=self.phone.opts.ami_port).connect()
        return self.ami

    def ami_command(self, a, tolerant):
        from ami import parse_fields
        if a.command == "expect-ami":
            ok = True
            for cond in a.conditions:
                mm = re.match(r"^([\w-]+)(!=|=|~|\?|!)(.*)$", cond, re.S)
                if not mm:
                    raise SimError("bad condition %r" % cond)
                key, op, want = mm.groups()
                vals = self.last_ami.getall(key) if self.last_ami is not None else []
                good, detail = self.compare("\n".join(vals) if vals else None, op, want)
                print("  %s %s%s" % ("ok  " if good else "FAIL", cond,
                                     "" if good else "  (%s)" % detail))
                ok &= good
            return ok
        ami = self.ami_client()
        if a.command == "ami":
            res = ami.action(a.action, parse_fields(a.fields), timeout=a.cmd_timeout)
            # For list actions, conditions see the response and every event
            # (repeated keys are matched joined by newlines).
            self.last_ami = res.response
            if res.response is not None and res.events:
                self.last_ami = type(res.response)(
                    list(res.response) + [kv for ev in res.events for kv in ev])
            print(res.text(), end="")
            return tolerant or res.success
        if a.command == "cli":
            res = ami.action("Command", [("Command", " ".join(a.words))])
            self.last_ami = res.response
            if res.response is not None:
                for line in res.response.getall("Output"):
                    print("  | " + line)
            return tolerant or res.success
        # ami-event
        match = {}
        for f in a.match:
            mm = re.match(r"^([^=~]+)(=|~)(.*)$", f)
            if not mm:
                raise SimError("bad event match %r" % f)
            match[mm.group(1)] = mm.group(3) if mm.group(2) == "=" else re.compile(mm.group(3))
        ev = ami.wait_event(a.event, timeout=a.cmd_timeout or self.phone.opts.timeout,
                            match=match)
        if ev is None:
            print("(no %s event)" % a.event)
            return tolerant
        self.last_ami = ev
        print(ev.text(), end="")
        return True

    def close(self):
        if self.ami is not None:
            self.ami.close()


def main(argv=None):
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    a = build_parser().parse_args(argv)
    if a.command == "selftest":
        return 0 if selftest(pki_dir=a.pki, show_vectors=a.vectors) else 1
    opts = options_from_args(a)
    if a.state and not a.local_port and os.path.exists(a.state):
        try:
            with open(a.state) as f:
                opts.local_port = json.load(f).get("local_port") or 0
        except (OSError, ValueError):
            pass
    try:
        phone = Phone(opts).start()
    except (SimError, OSError) as e:
        print("dpma_sim: %s" % e, file=sys.stderr)
        return 2
    try:
        if a.command == "script":
            s = Script(phone, a.keep_going)
            try:
                return 0 if s.run_file(a.file) else 1
            finally:
                s.close()
        if a.command == "listen":
            try:
                got = run_listen(phone, a)
            except KeyboardInterrupt:
                return 0
            return 0 if (a.count is None or len(got) >= a.count) else 1
        ex = run_request_command(phone, a)
        print(ex.describe(opts.verbose))
        if a.no_wait:
            return 0 if ex.sip_ok else 1
        return 0 if command_ok(a.command, ex) else 1
    except SimError as e:
        print("dpma_sim: %s" % e, file=sys.stderr)
        return 1
    finally:
        phone.close()


if __name__ == "__main__":
    sys.exit(main())
