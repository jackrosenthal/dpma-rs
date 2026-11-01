#!/usr/bin/env python3
"""Small Asterisk Manager Interface client for testing res_digium_phone.

Command line:

  ami.py [options] ACTION [Key=Value | "Key: Value"]...
  ami.py [options] --listen SECONDS

logs in to 127.0.0.1:<AMI port> as test/test, sends the action, and prints
the response and the events that follow it.  For list actions (the response
has "EventList: start"), it waits for the event with "EventList: Complete";
otherwise it prints events for --events seconds (default 1).  The exit
status is 0 when the response is "Success" (or "Follows" or "Goodbye").

The port defaults to the private instance of $DPMA_SLOT (15038 + 100 * slot,
as in dev/tools/ast.sh), or 15038 without it; --slot and --port override.

Examples:

  DPMA_SLOT=5 dev/sim/ami.py DPMAShowPhones
  dev/sim/ami.py --slot 5 Command Command="digium_phones show sessions"
  dev/sim/ami.py --slot 5 --wait-event DPMAMessage --events 60 \\
      DPMAMessageRegister Method=com.example.test

Python:

  from ami import AmiClient
  with AmiClient(slot=5) as ami:
      res = ami.action("DPMAShowPhones")
      print(res.response.get("Response"), len(res.events))
      ev = ami.wait_event("DPMAMessage", timeout=30)
"""
import argparse
import os
import re
import socket
import sys
import threading
import time
from collections import deque

DEFAULT_HOST = "127.0.0.1"


def default_port(slot=None):
    slot = slot if slot is not None else os.environ.get("DPMA_SLOT")
    if slot:
        return 15038 + 100 * int(slot)
    return 15038


class AmiMessage(list):
    """One AMI message: an ordered list of (key, value) pairs.  Keys may
    repeat (for example, "Output" in a Command response)."""

    def get(self, key, default=None):
        k = key.lower()
        for name, value in self:
            if name.lower() == k:
                return value
        return default

    def getall(self, key):
        k = key.lower()
        return [v for n, v in self if n.lower() == k]

    def __contains__(self, key):
        return self.get(key) is not None

    @property
    def is_event(self):
        return self.get("Event") is not None

    def text(self):
        return "".join("%s: %s\n" % (k, v) for k, v in self)

    def to_dict(self):
        """Keys to values; repeated keys become lists."""
        out = {}
        for k, v in self:
            if k in out:
                if not isinstance(out[k], list):
                    out[k] = [out[k]]
                out[k].append(v)
            else:
                out[k] = v
        return out


class AmiResult:
    """The response to an action and the events collected with it."""

    def __init__(self, response, events):
        self.response = response
        self.events = events

    @property
    def success(self):
        return (self.response is not None
                and (self.response.get("Response") or "").lower() in ("success", "follows",
                                                                     "goodbye"))

    def text(self):
        parts = [self.response.text() if self.response is not None else "(no response)\n"]
        parts += [e.text() for e in self.events]
        return "\n".join(parts)


class AmiError(Exception):
    pass


class AmiClient:
    def __init__(self, host=DEFAULT_HOST, port=None, username="test", secret="test",
                 events=True, timeout=10.0, slot=None):
        self.host = host
        self.port = port or default_port(slot)
        self.username = username
        self.secret = secret
        self.events_enabled = events
        self.timeout = timeout
        self.sock = None
        self.banner = None
        self._cond = threading.Condition()
        self._responses = {}           # ActionID -> AmiMessage
        self._events = deque(maxlen=20000)
        self._closed = False
        self._seq = 0
        self._reader = None

    # Connection --------------------------------------------------------

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        f = self.sock.makefile("rb")
        self.banner = f.readline().decode("utf-8", "replace").strip()
        if not self.banner.startswith("Asterisk Call Manager"):
            raise AmiError("unexpected AMI banner %r" % self.banner)
        self.sock.settimeout(None)
        self._reader = threading.Thread(target=self._read_loop, args=(f,), daemon=True)
        self._reader.start()
        res = self.action("Login", Username=self.username, Secret=self.secret,
                          Events="on" if self.events_enabled else "off")
        if not res.success:
            raise AmiError("AMI login failed: %s" % (res.response.get("Message")
                                                    if res.response else "no response"))
        return self

    def close(self):
        if self.sock is None:
            return
        try:
            self.action("Logoff", timeout=2)
        except Exception:
            pass
        self._closed = True
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    def _read_loop(self, f):
        msg = AmiMessage()
        try:
            for raw in f:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    if msg:
                        self._dispatch(msg)
                        msg = AmiMessage()
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    msg.append((k.strip(), v.strip()))
                else:
                    # Old-style command output without "Output:" keys.
                    msg.append(("Output", line))
        except (OSError, ValueError):
            pass
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def _dispatch(self, msg):
        with self._cond:
            if msg.is_event:
                msg.received = time.time()
                self._events.append(msg)
            else:
                self._responses[msg.get("ActionID", "")] = msg
            self._cond.notify_all()

    # Actions -----------------------------------------------------------

    def send(self, action, fields=None, **kw):
        """Send an action without waiting; returns its ActionID."""
        self._seq += 1
        action_id = "sim-%d-%d" % (os.getpid(), self._seq)
        items = [("Action", action), ("ActionID", action_id)]
        for src in (fields or {}), kw:
            items += list(src.items()) if isinstance(src, dict) else list(src)
        data = "".join("%s: %s\r\n" % (k, v) for k, v in items) + "\r\n"
        self.sock.sendall(data.encode())
        return action_id

    def action(self, action, fields=None, timeout=None, list_timeout=None, **kw):
        """Send an action and wait for its response.  For list actions also
        collect the events up to "EventList: Complete"."""
        timeout = self.timeout if timeout is None else timeout
        action_id = self.send(action, fields, **kw)
        deadline = time.time() + timeout
        with self._cond:
            while action_id not in self._responses:
                left = deadline - time.time()
                if left <= 0 or self._closed:
                    return AmiResult(None, [])
                self._cond.wait(left)
            resp = self._responses.pop(action_id)
        events = []
        if (resp.get("EventList") or "").lower() == "start":
            deadline = time.time() + (list_timeout or timeout)
            while True:
                ev = self.wait_event(timeout=max(0, deadline - time.time()),
                                     match={"ActionID": action_id})
                if ev is None:
                    break
                events.append(ev)
                if (ev.get("EventList") or "").lower() == "complete":
                    break
        return AmiResult(resp, events)

    def command(self, cli, timeout=None):
        """Run a CLI command through the Command action; returns its output
        lines."""
        res = self.action("Command", Command=cli, timeout=timeout)
        if res.response is None:
            raise AmiError("no response to Command %r" % cli)
        return res.response.getall("Output")

    # Events ------------------------------------------------------------

    def wait_event(self, name=None, timeout=10.0, match=None):
        """Remove and return the oldest received event named `name` (any
        event when None) whose fields equal `match` (values may be compiled
        regular expressions); None on timeout."""
        deadline = time.time() + timeout
        with self._cond:
            while True:
                for ev in list(self._events):
                    if name and (ev.get("Event") or "").lower() != name.lower():
                        continue
                    if match and not all(_field_matches(ev.get(k), v) for k, v in match.items()):
                        continue
                    self._events.remove(ev)
                    return ev
                left = deadline - time.time()
                if left <= 0 or self._closed:
                    return None
                self._cond.wait(left)

    def drain_events(self):
        with self._cond:
            evs = list(self._events)
            self._events.clear()
        return evs


def _field_matches(value, want):
    if value is None:
        return False
    if isinstance(want, re.Pattern):
        return want.search(value) is not None
    return value == want


def parse_fields(items):
    """Turn "Key=Value" or "Key: Value" arguments into (key, value) pairs."""
    out = []
    for it in items:
        m = re.match(r"^([^:=\s]+)\s*(?::\s?|=)(.*)$", it)
        if not m:
            raise SystemExit("ami.py: bad field %r (use Key=Value or 'Key: Value')" % it)
        out.append((m.group(1), m.group(2)))
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Send an AMI action and print the response and events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__[__doc__.index("Examples:"):__doc__.index("Python:")])
    ap.add_argument("action", nargs="?", help="action name")
    ap.add_argument("fields", nargs="*", help="Key=Value or 'Key: Value'")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, help="AMI port (default: from --slot or $DPMA_SLOT)")
    ap.add_argument("--slot", type=int, help="instance slot")
    ap.add_argument("--user", default="test")
    ap.add_argument("--secret", default="test")
    ap.add_argument("--events", type=float, default=1.0,
                    help="seconds to print events after a non-list response (default 1)")
    ap.add_argument("--wait-event", metavar="NAME",
                    help="after the response, wait (up to --events seconds) for this event, "
                         "print it, and exit; exit status 1 if it does not come")
    ap.add_argument("--listen", type=float, metavar="SECONDS",
                    help="print all events for SECONDS (no action needed)")
    args = ap.parse_args()
    if not args.action and args.listen is None:
        ap.error("an action or --listen is required")

    ami = AmiClient(args.host, args.port or default_port(args.slot), args.user, args.secret)
    try:
        ami.connect()
    except (OSError, AmiError) as e:
        print("ami.py: %s:%d: %s" % (args.host, ami.port, e), file=sys.stderr)
        return 2
    status = 0
    ami.drain_events()          # FullyBooted, SuccessfulAuth, ... from the login
    try:
        if args.action:
            res = ami.action(args.action, parse_fields(args.fields))
            print(res.text(), end="")
            status = 0 if res.success else 1
            if args.wait_event:
                ev = ami.wait_event(args.wait_event, timeout=args.events)
                if ev is None:
                    print("ami.py: no %s event within %g s" % (args.wait_event, args.events),
                          file=sys.stderr)
                    status = 1
                else:
                    print("\n" + ev.text(), end="")
            elif not res.events and args.events > 0:
                time.sleep(args.events)
                for ev in ami.drain_events():
                    print("\n" + ev.text(), end="")
        if args.listen is not None:
            deadline = time.time() + args.listen
            while time.time() < deadline:
                ev = ami.wait_event(timeout=deadline - time.time())
                if ev is not None:
                    print(ev.text(), flush=True)
    finally:
        ami.close()
    return status


if __name__ == "__main__":
    sys.exit(main())
