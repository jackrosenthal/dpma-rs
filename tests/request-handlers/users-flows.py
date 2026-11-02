#!/usr/bin/env python3
"""End-to-end checks of the phone users' runtime (package P8) over real
sessions, now that the request handlers (P12) exist: reconfigure messages
reaching the phone (CLI, AMI, reload, deleted phone, MAC mismatch, the
delete-token form), events (including digium.assignment.update),
sessions marked authenticated and inactive by token builds and lookups,
orphaned and stale phones, the response URI following a phone that
moves, and the phones' sessions restored after an Asterisk restart.

Same setup as run.py (tests/request-handlers/setup.sh, a devtest
build installed, Asterisk running):

    python3 tests/request-handlers/users-flows.py [-v] [SECTION...]

Sections: reconfigure, reload, mismatch, stale, uri, events, marks,
restore (default: all; "restore" restarts Asterisk and waits about 70 s
for the idle pruning).  The script first deletes the test phones' AstDB
entries and restarts Asterisk so the runtime state starts out empty.
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p12lib as L  # noqa: E402
from p12lib import *  # noqa: E402,F401,F403

AST = os.path.join(ROOT, "tools", "ast.sh")
P12CONF = os.path.join(INST, "etc", "asterisk", "res_digium_phone_p12.conf")
UPDATE = "digium.config.update"
PLAIN = b"<config></config>"
DELETE_TOKEN = b'<config>\t<section id="all"/>\t<option id="delete_token" value="true"/></config>'
PHONES = ("p12a", "p12b", "p12c", "p12tmp")


def restart():
    L.ami.close()
    subprocess.run([AST, "stop"], capture_output=True)
    subprocess.run([AST, "start"], capture_output=True)
    time.sleep(2)
    L.connect()


def token_for(p, user):
    ex = p.get_token(user=user, config_password=GLOBALPIN)
    return expect("token for %s from %s" % (user, p.mac), ex, "TokenResponse")


def last_info(phone_name):
    """(last_mac, last_uri, last_session_id) and the AstDB value."""
    out = cli("dpmadev token info %s" % phone_name)
    m = re.search(r"last_mac='([^']*)' last_uri='([^']*)' last_session_id='([^']*)'", out)
    db = re.search(r"AstDB: (.*)", out)
    return (m.groups() if m else None), (db.group(1).strip() if db else None)


def uri_of(p):
    return "pjsip:127.0.0.1:%d;transport=udp" % p.sip.local_addr[1]


def flags(sid):
    ln = session_line(sid)
    m = re.search(r"Auth:(\w+)\s+Inactive:(\w+)", ln)
    return m.groups() if m else None


def expect_event(name, p, body, event=UPDATE, timeout=5):
    r = p.next_event(timeout=timeout)
    if r is None:
        check(name, False, "no event")
        return None
    problems = []
    if r.event != event:
        problems.append("event %r, wanted %r" % (r.event, event))
    if r.id is not None:
        problems.append("events carry no X-Digium-AppServer-ID (got %r)" % r.id)
    if not r.encrypted:
        problems.append("not encrypted")
    if r.payload != body:
        problems.append("payload %r, wanted %r" % (r.payload, body))
    check(name, not problems, "\n".join(problems))
    return r


def no_event(name, p, timeout=1.5):
    r = p.next_event(timeout=timeout)
    check(name, r is None, r.describe() if r else "")


def edit_p12conf(extra="", drop=None):
    """Append `extra` to the P12 phones (and drop lines matching `drop`)
    and reload."""
    with open(os.path.join(HERE, "res_digium_phone_p12.conf")) as f:
        text = f.read()
    if drop:
        text = "\n".join(ln for ln in text.split("\n") if not re.match(drop, ln))
    with open(P12CONF, "w") as f:
        f.write(text + extra)
    cli("module reload res_dpma_rs.so")
    time.sleep(0.5)


# ---------------------------------------------------------------------------

def test_reconfigure():
    print("\n== Reconfigure from the CLI and AMI")
    p = phone(MAC_A)
    try:
        token_for(p, "p12a")
        out = cli("digium_phones reconfigure phone p12a")
        same("CLI reconfigure output (full name)", out.strip(), "Phone 'P12 Phone A' will reconfigure shortly.")
        expect_event("CLI reconfigure reaches the phone", p, PLAIN)
        out = cli("digium_phones reconfigure phone p12c")
        check("CLI reconfigure of a phone never seen",
              out.startswith("Phone 'p12c' has not contacted the server."), out)
        res = L.ami.action("DigiumPhoneReconfigure", PhoneName="p12a")
        same("AMI DigiumPhoneReconfigure", (res.response.get("Response"), res.response.get("Message")),
             ("Success", "Reconfigure message successfully sent"))
        expect_event("AMI DigiumPhoneReconfigure reaches the phone", p, PLAIN)
        res = L.ami.action("DigiumPhoneReconfigure", PhoneName="p12c")
        same("AMI DigiumPhoneReconfigure of a phone never seen", res.response.get("Response"), "Error")
        res = L.ami.action("DigiumPhoneReconfigureAll")
        same("AMI DigiumPhoneReconfigureAll", res.response.get("Response"), "Success")
        expect_event("AMI DigiumPhoneReconfigureAll reaches the phone", p, PLAIN)
        no_event("one reconfigure per phone", p)
        out = cli("dpmadev token reconfigure %s %s delete" % (p.session, uri_of(p)))
        expect_event("reconfigure with delete_token", p, DELETE_TOKEN)
    finally:
        p.close()


def test_reload():
    print("\n== Reconfigure on reload: changed lines, deleted phone")
    p = phone(MAC_A)
    t = None
    try:
        token_for(p, "p12a")
        mark = log_mark()
        edit_p12conf("\n[p12a-line2]\ntype=line\n", drop=None)
        # Adding a line section alone changes nothing for p12a.
        no_event("unrelated change: no reconfigure", p)
        edit_p12conf("\n[p12a-line2]\ntype=line\n[p12a](+)\nline=p12a-line2\n")
        expect_event("lines changed: reconfigure", p, PLAIN)
        logged("lines changed (log)", mark, "Phone user 'p12a' setting reconfigure due to change in lines")
        logged("lines changed: sending (log)", mark, "Sending reconfigure to user p12a")
        edit_p12conf()
        expect_event("lines changed back: reconfigure", p, PLAIN)

        edit_p12conf("\n[p12tmp]\ntype=phone\nmac=000fd30012aa\nline=p12tmp-line\n[p12tmp-line]\ntype=line\n")
        t = phone("000fd30012aa")
        token_for(t, "p12tmp")
        _, db = last_info("p12tmp")
        check("p12tmp in AstDB", db is not None and db.startswith("last_mac=000fd30012aa;"), repr(db))
        same("p12tmp's session active", flags(t.session), ("Yes", "No"))
        edit_p12conf()
        expect_event("deleted phone: reconfigure", t, PLAIN)
        out = cli("database get DigiumPhoneUsers p12tmp")
        check("deleted phone: AstDB entry removed", "not found" in out.lower(), out)
        same("deleted phone: session inactive", flags(t.session), ("Yes", "Yes"))
        no_event("deleted phone: others not reconfigured", p)
    finally:
        p.close()
        if t:
            t.close()
        edit_p12conf()


def test_mismatch():
    print("\n== MAC mismatch and orphaned phones")
    set_general(config_auth="disabled", userlist_auth="disabled", globalpin=GLOBALPIN)
    a, b = phone(MAC_A), phone(MAC_BAD)
    try:
        token_for(a, "p12a")
        same("p12a at A", last_info("p12a")[0], (MAC_A, uri_of(a), a.session))
        mark = log_mark()
        token_for(b, "p12a")
        logged("MAC mismatch (log)", mark, "Phone user 'p12a' reconfigure due to mac mismatch - was '%s' now '%s'"
               % (MAC_A, MAC_BAD))
        logged("now connected (log)", mark, "Phone user 'p12a' now connected from '%s' mac '%s'"
               % (uri_of(b), MAC_BAD))
        expect_event("MAC mismatch: the old location is reconfigured", a, PLAIN)
        no_event("MAC mismatch: the new location is not", b)
        same("p12a at B", last_info("p12a")[0], (MAC_BAD, uri_of(b), b.session))
        same("A's session marked inactive", flags(a.session), ("Yes", "Yes"))
        same("B's session authenticated", flags(b.session), ("Yes", "No"))

        mark = log_mark()
        token_for(b, "p12b")
        logged("orphaned (log)", mark, "Phone user 'p12a' configuration orphaned by mac '%s'" % MAC_BAD)
        same("orphaned phone forgets its location", last_info("p12a"), (("", "", ""), "(none)"))
        same("p12b at B", last_info("p12b")[0], (MAC_BAD, uri_of(b), b.session))
        same("B's session still authenticated and active", flags(b.session), ("Yes", "No"))
    finally:
        a.close()
        b.close()
        set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)


def test_stale():
    print("\n== Stale phones at the same address")
    set_general(config_auth="disabled", userlist_auth="disabled", globalpin=GLOBALPIN)
    p = phone(MAC_A, contact=None)
    try:
        token_for(p, "p12a")
        old = p.session
        # Another phone behind the same address (the same socket here):
        # a new session with another MAC.
        p.opts.mac = MAC_BAD
        p.opts.contact = "sip:%s@127.0.0.1:%d" % (MAC_BAD, p.sip.local_addr[1])
        ex = p.handshake()
        check("second handshake", ex.ok, ex.describe())
        mark = log_mark()
        token_for(p, "p12b")
        logged("stale phone removed (log)", mark, "Removing stale user 'p12a' from '%s'" % uri_of(p))
        same("stale phone forgets its location", last_info("p12a"), (("", "", ""), "(none)"))
        same("stale phone's session inactive", flags(old), ("Yes", "Yes"))
    finally:
        p.close()
        set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)


def test_uri():
    print("\n== The session follows a phone that moves")
    p = phone(MAC_A)
    q = None
    try:
        p.opts.contact = p.contact_uri
        token_for(p, "p12a")
        old_uri = uri_of(p)
        # The same phone (contact, session, key, token) from another port.
        q = Phone(Options(slot=SLOT, mac=MAC_A, contact=p.contact_uri), out=io.StringIO())
        q.start()
        q.session, q.common_password, q.token = p.session, p.common_password, p.token
        mark = log_mark()
        expect("config from the new address", q.config(), "ConfigResponse", None, re.compile(rb"\A<config>"))
        logged("now connected (log)", mark, "Phone user 'p12a' now connected from '%s' mac '%s'"
               % (uri_of(q), MAC_A))
        logged("session update (log)", mark, "Phone user 'p12a' session update due to uri change - was '%s' now '%s'"
               % (old_uri, uri_of(q)))
        same("last info follows", last_info("p12a")[0], (MAC_A, uri_of(q), p.session))
        check("show sessions: the new URI", ("URI:%s " % uri_of(q)) in session_line(p.session),
              session_line(p.session))
        cli("digium_phones reconfigure phone p12a")
        expect_event("reconfigure goes to the new address", q, PLAIN)
        no_event("not to the old one", p)
    finally:
        p.close()
        if q:
            q.close()


def test_events():
    print("\n== Events (phone_user_send_event)")
    p = phone(MAC_A)
    try:
        token_for(p, "p12a")
        out = cli("dpmadev token event p12a digium.p12.test hello <b>world</b>")
        same("send_event result", out.strip(), "send_event: Ok(())")
        expect_event("event reaches the phone", p, b"hello <b>world</b>", event="digium.p12.test")
        out = cli("dpmadev token event p12a digium.assignment.update <assign/>")
        r = p.next_event(timeout=5)
        check("assignment update arrives", r is not None)
        if r is not None:
            same("assignment update: id", r.id, "bootcReset")
            same("assignment update: no event name", r.event, None)
            same("assignment update: Error-ID", r.error, "-398")
            same("assignment update: body", r.payload, b'<assign/><error msg="Session Timeout" />')
        out = cli("dpmadev token event p12c digium.p12.test x")
        same("event to a phone never seen", out.strip(), 'send_event: Err("Phone has not contacted server")')
    finally:
        p.close()


def test_marks():
    print("\n== Sessions marked authenticated by tokens")
    p = phone(MAC_A)
    try:
        same("new session: not authenticated", flags(p.session), ("No", "No"))
        token_for(p, "p12a")
        same("token build authenticates the session", flags(p.session), ("Yes", "No"))
        old, token = p.session, p.token
        mark = log_mark()
        ex = p.handshake()            # a reboot: same MAC, new session
        check("handshake again", ex.ok)
        logged("old session pruned (log)", mark, "on new handshake from mac '%s'" % MAC_A)
        same("old session gone", session_line(old), "")
        same("new session: not authenticated", flags(p.session), ("No", "No"))
        p.token = token
        expect("config with the old token", p.config(), "ConfigResponse", None, re.compile(rb"\A<config>"))
        same("token lookup authenticates the new session", flags(p.session), ("Yes", "No"))
        same("phone's session follows", last_info("p12a")[0][2], p.session)
    finally:
        p.close()


def test_restore():
    print("\n== Sessions restored after a restart")
    port = 16290 + SLOT
    opts = dict(slot=SLOT, mac=MAC_A, local_port=port)
    p = Phone(Options(**opts), out=io.StringIO())
    p.start()
    try:
        ex = p.handshake()
        check("handshake", ex.ok)
        token_for(p, "p12a")
        sid, pw, token = p.session, p.common_password, p.token
    finally:
        p.close()
    # Another session that never authenticates is not saved.
    x = phone("000fd30012bb")
    xsid = x.session
    x.close()
    restart()
    same("phone's session restored authenticated and active", flags(sid), ("Yes", "No"))
    same("unauthenticated session not restored", session_line(xsid), "")
    same("last info restored", last_info("p12a")[0], (MAC_A, "pjsip:127.0.0.1:%d;transport=udp" % port, sid))
    p = Phone(Options(**opts), out=io.StringIO())
    p.start()
    try:
        p.session, p.common_password, p.token = sid, pw, token
        expect("restored session: ping", p.ping(), "PingResponse", None, b"empty body")
        expect("restored session: config with the token", p.config(), "ConfigResponse", None,
               re.compile(rb"\A<config>"))
        cli("digium_phones reconfigure phone p12a")
        expect_event("restored session: reconfigure", p, PLAIN)
        print("     (waiting 65 s: the idle pruning removes inactive sessions after 59 s)")
        time.sleep(65)
        same("restored session survives the idle pruning", flags(sid), ("Yes", "No"))
    finally:
        p.close()


SECTIONS = {
    "reconfigure": test_reconfigure, "reload": test_reload, "mismatch": test_mismatch, "stale": test_stale,
    "uri": test_uri, "events": test_events, "marks": test_marks, "restore": test_restore,
}


def main():
    wanted = [a for a in sys.argv[1:] if not a.startswith("-")] or list(SECTIONS)
    L.connect()
    for name in PHONES:
        cli("database del DigiumPhoneUsers %s" % name)
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)
    restart()
    try:
        for name in wanted:
            SECTIONS[name]()
    finally:
        edit_p12conf()
        L.ami.close()
    return L.summary()


if __name__ == "__main__":
    sys.exit(main())
