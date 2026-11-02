#!/usr/bin/env python3
"""Session layer (package P7): reassembly of incoming chunks
(incoming_add_msg, incoming_check_finalize, prune_inactive in
FUN_0014f280): chunks out of order, a duplicate key from another MAC, and
incomplete transactions dropped after 40 s.  Sends hand-made chunks with
the simulator's SIP layer.  Needs a devtest build (dpmadev session prune)
and the setup of session.sim; takes about 50 s.

    DPMA_SLOT=<n> tests/sim/scripts/session-reassembly.py
"""

import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from dpma_sim import (H_FINISHED, H_ID, H_MAC, H_REQUEST_TYPE, H_SEQUENCE,  # noqa: E402
                      Exchange, Options, Phone)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
failures = []


def check(label, cond, detail=""):
    print("%-4s %s%s" % ("ok" if cond else "FAIL", label, ": %s" % detail if detail and not cond else ""))
    if not cond:
        failures.append(label)


def cli(command):
    subprocess.run([os.path.join(ROOT, "tools", "ast.sh"), "cli", command],
                   check=False, capture_output=True)


def send_parts(phone, txid, parts, mac=None):
    """Send Echo chunks: parts is a list of (sequence, finished, body)."""
    common = [("Contact", "<%s>" % phone.contact_uri), ("User-Agent", phone.opts.user_agent),
              ("Content-Type", "text/plain")]
    from_uri = "sip:%s@%s" % (phone.mac, phone.sip.local_addr[0])
    for seq, fin, body in parts:
        hdrs = common + [(H_REQUEST_TYPE, "Echo"), (H_ID, txid), (H_MAC, mac or phone.mac),
                         (H_SEQUENCE, str(seq))]
        if fin:
            hdrs.append((H_FINISHED, "1"))
        resp = phone.sip.request("MESSAGE", phone.server_uri, hdrs, body.encode(),
                                 from_uri=from_uri)
        if resp is None or resp.status >= 300:
            raise SystemExit("MESSAGE failed: %r" % (resp and resp.status))


def send_and_wait(phone, txid, parts, mac=None, timeout=3):
    """Send the parts and return the body of the reply with ID txid (None
    when there is none)."""
    ex = Exchange("Echo", txid)
    with phone._lock:
        phone._waiting[txid] = ex
    send_parts(phone, txid, parts, mac)
    phone.wait_reply(ex, timeout)
    return ex.reply.body if ex.reply is not None else None


def main():
    opts = Options(slot=os.environ.get("DPMA_SLOT"), verbose=-1)
    with Phone(opts) as phone:
        base = random.randint(100000, 900000)

        # Out of order: the finishing chunk first.
        r = send_and_wait(phone, str(base), [(2, True, "CCCC"), (0, False, "AAAA"), (1, False, "BBBB")])
        check("chunks out of order reassemble in sequence order", r == b"AAAABBBBCCCC", r)

        # The same ID from two MACs: two transactions ("<ID>-<MAC>").
        txid = str(base + 1)
        send_parts(phone, txid, [(0, False, "mac1-")])
        send_parts(phone, txid, [(0, False, "mac2-")], mac="000fd3000002")
        r = send_and_wait(phone, txid, [(1, True, "end")])
        check("transactions are keyed by ID and MAC", r == b"mac1-end", r)
        r = send_and_wait(phone, txid, [(1, True, "END")], mac="000fd3000002")
        check("the other MAC's transaction completes on its own", r == b"mac2-END", r)

        # Incomplete transactions are dropped after 40 s.
        txid = str(base + 2)
        send_parts(phone, txid, [(0, False, "early-")])
        time.sleep(42)
        cli("dpmadev session prune")
        r = send_and_wait(phone, str(base + 3), [(0, True, "cycle")])
        check("a new read cycle runs", r == b"cycle", r)
        r = send_and_wait(phone, txid, [(1, True, "late")], timeout=2)
        check("an incomplete transaction is dropped after 40 s", r is None, r)
        # The late chunk alone (sequence 1 of a new transaction) completes
        # once a sequence 0 arrives.
        r = send_and_wait(phone, txid, [(0, False, "again-")])
        check("the late chunk started a new transaction", r == b"again-late", r)
    print("%d failure(s)" % len(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
