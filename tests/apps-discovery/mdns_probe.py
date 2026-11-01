#!/usr/bin/env python3
"""A small mDNS client for the P14 discovery tests (standard library only).

    mdns_probe.py browse [--type T] [--iface-addr A] [--wait S]
    mdns_probe.py listen [--seconds S] [--iface-addr A]

"browse" sends one-shot (legacy unicast) queries to 224.0.0.251:5353:
PTR for the service type (default _digiumproxy._udp.local), then SRV and
TXT for every instance found, then A and AAAA for every SRV target, and
prints what it found as JSON.  "listen" joins the mDNS group and prints
every response it sees (announcements, goodbyes) for S seconds, one JSON
object per record.  Queries and the group membership use the interface of
--iface-addr (default 127.0.0.1), so nothing leaves the loopback
interface.  Python: query(), browse(), Listener.
"""
import argparse
import json
import random
import socket
import struct
import sys
import threading
import time

GROUP = "224.0.0.251"
PORT = 5353
TYPES = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
CODES = {v: k for k, v in TYPES.items()}


def split_name(name):
    """The labels of a dotted name ("\\." is a dot inside a label)."""
    labels, cur, i = [], "", 0
    while i < len(name):
        if name[i] == "\\" and i + 1 < len(name):
            cur += name[i + 1]
            i += 2
            continue
        if name[i] == ".":
            labels.append(cur)
            cur = ""
        else:
            cur += name[i]
        i += 1
    if cur:
        labels.append(cur)
    return labels


def encode_name(name):
    out = b""
    for label in split_name(name):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\0"


def build_query(name, qtype, qid=None):
    qid = random.getrandbits(16) if qid is None else qid
    return struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", CODES[qtype], 1)


def read_name(data, off):
    """(name, offset after it); follows compression pointers."""
    labels, jumped, end = [], False, None
    for _ in range(128):
        n = data[off]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        if n == 0:
            off += 1
            break
        labels.append(data[off + 1:off + 1 + n].decode("utf-8", "replace").replace(".", "\\."))
        off += 1 + n
    return ".".join(labels) + ".", (end if jumped else off)


def parse(data):
    """A DNS message: {"id", "flags", "questions", "records"}; each record
    has section, name, type, cache_flush, ttl, and its data."""
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off, questions, records = 12, [], []
    for _ in range(qd):
        name, off = read_name(data, off)
        qtype, qclass = struct.unpack("!HH", data[off:off + 4])
        off += 4
        questions.append({"name": name, "type": TYPES.get(qtype, qtype)})
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, off = read_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            rec = {"section": section, "name": name, "type": TYPES.get(rtype, rtype),
                   "cache_flush": bool(rclass & 0x8000), "ttl": ttl}
            if rtype == 12:
                rec["target"] = read_name(data, off)[0]
            elif rtype == 33:
                rec["priority"], rec["weight"], rec["port"] = struct.unpack("!HHH", rd[:6])
                rec["target"] = read_name(data, off + 6)[0]
            elif rtype == 16:
                strings, i = [], 0
                while i < len(rd):
                    n = rd[i]
                    strings.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
                    i += 1 + n
                rec["txt"] = strings
            elif rtype == 1:
                rec["address"] = socket.inet_ntop(socket.AF_INET, rd)
            elif rtype == 28:
                rec["address"] = socket.inet_ntop(socket.AF_INET6, rd)
            off += rdlen
            records.append(rec)
    return {"id": qid, "flags": flags, "questions": questions, "records": records}


def query(name, qtype, iface_addr="127.0.0.1", wait=1.0):
    """Send a legacy unicast query; return the records of every reply that
    arrives within `wait` seconds."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_addr))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.bind((iface_addr, 0))
    qid = random.getrandbits(16)
    s.sendto(build_query(name, qtype, qid), (GROUP, PORT))
    records, end = [], time.time() + wait
    while True:
        left = end - time.time()
        if left <= 0:
            break
        s.settimeout(left)
        try:
            data, _ = s.recvfrom(9000)
        except socket.timeout:
            break
        try:
            msg = parse(data)
        except (IndexError, struct.error):
            continue
        if msg["flags"] & 0x8000 and msg["id"] == qid:
            records += msg["records"]
    s.close()
    return records


def unescape(name):
    return name.replace("\\.", ".")


def instance_label(fullname, service_type):
    suffix = "." + service_type.rstrip(".") + "."
    return unescape(fullname[:-len(suffix)]) if fullname.endswith(suffix) else fullname


def browse(service_type="_digiumproxy._udp.local", iface_addr="127.0.0.1", wait=1.0):
    """{instance: {"port", "target", "txt", "addresses"}} for every live
    (TTL > 0) instance of `service_type`."""
    found = {}
    ptrs = [r for r in query(service_type, "PTR", iface_addr, wait)
            if r["type"] == "PTR" and r["ttl"] > 0 and r["name"].rstrip(".") == service_type.rstrip(".")]
    for p in ptrs:
        full = p["target"]
        inst = {"port": None, "target": None, "txt": None, "addresses": []}
        for r in query(full, "SRV", iface_addr, wait) + query(full, "TXT", iface_addr, wait):
            if r["name"] != full:
                continue
            if r["type"] == "SRV":
                inst["port"], inst["target"] = r["port"], r["target"]
            elif r["type"] == "TXT":
                inst["txt"] = r["txt"]
        if inst["target"]:
            for t in ("A", "AAAA"):
                for r in query(inst["target"], t, iface_addr, wait):
                    if r["type"] == t and r["name"].lower() == inst["target"].lower() and r["ttl"] > 0:
                        if r["address"] not in inst["addresses"]:
                            inst["addresses"].append(r["address"])
        found[instance_label(full, service_type)] = inst
    return found


class Listener:
    """Collects the records of every mDNS response multicast on the
    interface of `iface_addr` (port 5353, shared with the responders)."""

    def __init__(self, iface_addr="127.0.0.1"):
        self.records = []
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(("", PORT))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                             socket.inet_aton(GROUP) + socket.inet_aton(iface_addr))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = parse(data)
            except (IndexError, struct.error):
                continue
            if not msg["flags"] & 0x8000:
                continue
            now = time.time()
            with self.lock:
                for r in msg["records"]:
                    self.records.append(dict(r, time=now, source=addr[0]))

    def mark(self):
        with self.lock:
            return len(self.records)

    def since(self, mark):
        with self.lock:
            return list(self.records[mark:])

    def close(self):
        self.running = False
        self.thread.join()
        self.sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["browse", "listen"])
    ap.add_argument("--type", default="_digiumproxy._udp.local")
    ap.add_argument("--iface-addr", default="127.0.0.1")
    ap.add_argument("--wait", type=float, default=1.0)
    ap.add_argument("--seconds", type=float, default=10.0)
    a = ap.parse_args()
    if a.command == "browse":
        print(json.dumps(browse(a.type, a.iface_addr, a.wait), indent=2, sort_keys=True))
        return 0
    lst = Listener(a.iface_addr)
    end, mark = time.time() + a.seconds, 0
    try:
        while time.time() < end:
            time.sleep(0.2)
            for r in lst.since(mark):
                print(json.dumps(r, sort_keys=True), flush=True)
                mark += 1
    finally:
        lst.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
