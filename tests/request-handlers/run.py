#!/usr/bin/env python3
"""End-to-end checks of the phone request handlers (package P12,
phone_request.c) with the phone simulator.

Needs a private instance with the simulator's PKI and configuration, the
P12 test phones (setup.sh), a devtest build of res_digium_phone
installed, and Asterisk running:

    export DPMA_SLOT=<n>
    python3 dev/sim/mkpki.py && dev/sim/install-conf.sh
    dev/tests/request-handlers/setup.sh
    cargo build -p res_digium_phone --features devtest
    dev/tools/ast.sh install && dev/tools/ast.sh start
    python3 dev/tests/request-handlers/run.py [-v] [SECTION...]

Sections: token, config, userlist, file, asterisk, xml, ami, handshake
(default: all).  The script rewrites [general] of the instance's
res_digium_phone.conf for each authentication mode (and a test
file_directory), reloads the module, and restores the file at the end.
Replies are compared byte for byte with what the decompile builds:
message errors (Error-ID and `<error msg="..." />`), XML and JSON request
errors, the HTTP wrapper of AsteriskResponse and HTTPResponse, tokens,
the user list, files, and the DPMAMessage AMI event; log lines, auth
incidents (DPMAShowIncidents), AstDB, and the session's Configured flag
are checked too.  Exit status 0 when every check passes.
"""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p12lib as L  # noqa: E402
from p12lib import *  # noqa: E402,F401,F403


# ---------------------------------------------------------------------------
# TokenRequest
# ---------------------------------------------------------------------------

def expected_token_error(flags, mac_ok, pin, cfgpass):
    cp_ok = cfgpass in (GLOBALPIN, "7777")
    if flags & GLOBAL and not cp_ok:
        return -198
    if (flags & MAC and not mac_ok) or (flags & PIN and pin != "4321"):
        return -195
    return None


def test_token():
    print("\n== TokenRequest in every config_auth mode")
    combos = [("4321", GLOBALPIN), ("4321", "7777"), ("bad", "bad"), ("", ""), ("4321", "bad"),
              ("bad", GLOBALPIN)]
    for mode, flags in MODES.items():
        set_general(config_auth=mode, userlist_auth="disabled", globalpin=GLOBALPIN)
        good, bad = phone(MAC_A), phone(MAC_BAD)
        try:
            for p, mac_ok in ((good, True), (bad, False)):
                for pin, cfgpass in combos:
                    err = expected_token_error(flags, mac_ok, pin, cfgpass)
                    name = "token %s mac=%s pin=%r configpass=%r" % (
                        mode, "ok" if mac_ok else "bad", pin, cfgpass)
                    ex = p.get_token(user="p12a", pin=pin, config_password=cfgpass)
                    r = expect(name, ex, "TokenResponse", err,
                               b"empty body" if err is None else None)
                    if r is None:
                        continue
                    want = ("p12a/%s/%d/%d" % (p.mac, token_hash(""), token_hash(GLOBALPIN))
                            if err is None else None)
                    same(name + " (token)", r.fields.get("X-Digium-AppServer-Config-Token"), want)
        finally:
            good.close()
            bad.close()

    print("\n== TokenRequest: selecting the phone, side effects")
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)
    p = phone(MAC_A)
    try:
        sid = p.session
        same("new session is not configured", configured(sid), "No")
        # By the primary line's name and extension, and by MAC alone.
        for user in ("p12a-line", "5201", "P12A-LINE", None):
            ex = p.get_token(user=user, config_password=GLOBALPIN)
            r = expect("token for user %r" % user, ex, "TokenResponse")
            if r is not None:
                same("token for user %r (token)" % user, r.fields.get("X-Digium-AppServer-Config-Token"),
                     "p12a/%s/%d/%d" % (MAC_A, token_hash(""), token_hash(GLOBALPIN)))
        same("token marks the session configured", configured(sid), "Yes")
        info = cli("dpmadev token info p12a")
        same("token records the last info (AstDB)", re.search(r"AstDB: (.*)", info).group(1).strip(),
             "last_mac=%s;last_uri=pjsip:127.0.0.1:%d;transport=udp;last_session_id=%s"
             % (MAC_A, p.sip.local_addr[1], sid))
        ex = p.get_token(user="nosuchphone", config_password=GLOBALPIN)
        expect("token for an unknown user", ex, "TokenResponse", -195)
        # A MAC no phone has and no user name.
        q = phone("000fd30012ee")
        try:
            expect("token by an unknown MAC", q.get_token(config_password=GLOBALPIN),
                   "TokenResponse", -195)
        finally:
            q.close()
    finally:
        p.close()
    # Neither a MAC nor a user name (the phone handshakes without a MAC).
    q = phone("", contact="sip:nomac@127.0.0.1:5999")
    try:
        mark = log_mark()
        expect("token without MAC and user name", q.get_token(config_password=GLOBALPIN),
               "TokenResponse", -195)
        logged("token without MAC and user name (log)", mark,
               "The MAC and USERNAME headers are required in a token request. \n")
    finally:
        q.close()


# ---------------------------------------------------------------------------
# ConfigRequest and VerifyRequest
# ---------------------------------------------------------------------------

def test_config():
    print("\n== ConfigRequest and VerifyRequest")
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN,
                file_directory=FILES)
    p = phone(MAC_A)
    try:
        sid = p.session
        expect("config without a token", p.request("ConfigRequest"), "ConfigResponse", -192)
        expect("config with a bad token", p.config(token="p12a/000fd3999999/1/2"), "ConfigResponse", -192)
        same("failed config leaves the session unconfigured", configured(sid), "No")
        mark = log_mark()
        expect("verify without a token", p.request("VerifyRequest"), "VerifyResponse", -192)
        logged("verify without a token (log)", mark, "Verify request with null token\n")
        same("verify without a token leaves the session unconfigured", configured(sid), "No")
        expect("verify with a bad token", p.verify(token="nobody/x"), "VerifyResponse", -192)
        same("verify with a bad token marks the session configured", configured(sid), "Yes")
        cli("dpmadev session mark %s unconfigured" % sid)

        expect("token", p.get_token(user="p12a", config_password=GLOBALPIN), "TokenResponse")
        cli("dpmadev session mark %s unconfigured" % sid)
        want = "\n".join(L.ami.command("dpmadev config p12a D65")).encode()
        r = expect("config with the token", p.config(), "ConfigResponse", None,
                   re.compile(rb"\A<config>"))
        if r is not None:
            same("config document = get_config(p12a, D65)", r.payload.rstrip(b"\n"), want.rstrip(b"\n"))
        same("config marks the session configured", configured(sid), "Yes")
        # The prefix <phone><sep><last MAC> is all that is compared.
        expect("config with a '-' token", p.config(token="p12a-%s-anything" % MAC_A), "ConfigResponse",
               None, re.compile(rb"\A<config>"))
        cli("dpmadev session mark %s unconfigured" % sid)
        expect("verify with the token", p.verify(), "VerifyResponse", None, b"empty body")
        same("verify marks the session configured", configured(sid), "Yes")
    finally:
        p.close()

    # A phone with config_file: the file from file_directory instead.
    p = phone("000fd3001203")
    try:
        expect("token p12c", p.get_token(user="p12c", config_password="8888"), "TokenResponse")
        with open(os.path.join(FILES, "p12c-config.xml"), "rb") as f:
            want = f.read()
        expect("config_file is read from file_directory", p.config(), "ConfigResponse", None, want)
    finally:
        p.close()


# ---------------------------------------------------------------------------
# UserlistRequest
# ---------------------------------------------------------------------------

def users_of(payload):
    try:
        return [u["name"] for u in json.loads(payload)["users"]]
    except (ValueError, KeyError, TypeError):
        return None


def test_userlist():
    print("\n== UserlistRequest")
    all_names = None
    for mode in ("disabled", "globalpin"):
        set_general(config_auth="mac_globalpin", userlist_auth=mode, globalpin=GLOBALPIN)
        p = phone(MAC_A)
        try:
            sid = p.session
            cli("dpmadev session mark %s configured" % sid)
            want = "\n".join(L.ami.command("dpmadev userlist " + GLOBALPIN)).encode()
            r = expect("userlist (%s) with the global pin" % mode, p.userlist(config_password=GLOBALPIN),
                       "UserlistResponse")
            if r is not None:
                m = re.search(rb'\{"users":.*\}', want)
                same("userlist (%s) = build_userlist_json" % mode, r.payload, m.group(0) if m else want)
                all_names = users_of(r.payload)
            same("userlist marks the session unconfigured", configured(sid), "No")
            for cfgpass in ("7777", "8888", "", "wrong"):
                name = "userlist (%s) with config pass %r" % (mode, cfgpass)
                clear_incidents()
                mark = log_mark()
                ex = p.userlist(config_password=cfgpass)
                if mode == "disabled":
                    r = expect(name, ex, "UserlistResponse")
                    same(name + " lists everyone", users_of(r.payload) if r else None, all_names)
                    continue
                want_names = {"7777": ["P12 Phone A", "p12b"], "8888": ["p12c"]}.get(cfgpass)
                if want_names:
                    r = expect(name, ex, "UserlistResponse")
                    got = users_of(r.payload) if r else None
                    same(name + " lists the group", sorted(got) if got else got, want_names)
                    continue
                expect(name, ex, "UserlistResponse", -198)
                logged(name + " (log)", mark,
                       "Userlist request with invalid config password, or no users configured.\n")
                inc = incidents().get("127.0.0.1")
                check(name + " records an incident",
                      inc is not None and inc.get("Reason") == "invalid config pass"
                      and inc.get("MAC") == MAC_A and inc.get("IncidentCount") == "1",
                      repr(inc))
        finally:
            p.close()
    clear_incidents()


# ---------------------------------------------------------------------------
# FileRequest
# ---------------------------------------------------------------------------

def test_file():
    print("\n== FileRequest")
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN,
                file_directory=FILES)
    p = phone(MAC_A)
    try:
        want = "\n".join(L.ami.command("dpmadev contacts")).encode()
        for name in ("default", "DEFAULT"):
            r = expect("file://%s" % name, p.file(name), "FileResponse", None,
                       re.compile(rb'\A<contacts group_name="Internal Extensions" editable="0" >\n'))
            if r is not None:
                same("file://%s = default contacts" % name, r.payload.rstrip(b"\n"), want.rstrip(b"\n"))
        expect("file://null", p.file("Null"), "FileResponse", None,
               b'<contacts group_name="null" editable="0" />\n')
        for fname in ("p12-small.txt", "p12-big.bin"):
            with open(os.path.join(FILES, fname), "rb") as f:
                data = f.read()
            r = expect("file://%s (%d bytes)" % (fname, len(data)), p.file(fname), "FileResponse", None, data)
            if r is not None and fname == "p12-big.bin":
                check("file://%s came in several chunks" % fname, len(r.parts) > 1, "%d" % len(r.parts))
        ex = p.request("FileRequest", "some text\r\nfile://p12-small.txt\r\nmore text")
        with open(os.path.join(FILES, "p12-small.txt"), "rb") as f:
            expect("file:// inside the body, up to the line end", ex, "FileResponse", None, f.read())
        mark = log_mark()
        expect("file://missing.txt", p.file("missing.txt"), "FileResponse", -98)
        logged("file://missing.txt (log)", mark, "Failed to open file %s/missing.txt\n" % FILES)
        expect("body without file://", p.request("FileRequest", "default"), "FileResponse", -98)
        expect("empty body", p.request("FileRequest", ""), "FileResponse", -98)
        # An empty name opens the directory itself, which reads as nothing.
        expect("file:// with no name", p.request("FileRequest", "file://"), "FileResponse", None, b"empty body")
        # Subdirectories of file_directory are served; names that could
        # leave it are refused like a missing file (plan section 8, item
        # 14), although the files exist.  Absolute names are refused too,
        # although the original looks them up inside file_directory
        # ("<dir>//p12-small.txt").
        for fname in ("sub/p12-sub.txt", "./sub/./p12-sub.txt", "..p12-dots.txt", "sub/..p12-dots.txt"):
            with open(os.path.join(FILES, fname), "rb") as f:
                expect("file://%s" % fname, p.file(fname), "FileResponse", None, f.read())
        outside = os.path.join(os.path.dirname(FILES), "p12-outside.txt")
        for fname in ("../p12-outside.txt", "sub/../../p12-outside.txt", "sub/../p12-small.txt", "..", "sub/..",
                      outside, "/p12-small.txt", "//etc/hostname"):
            mark = log_mark()
            expect("file://%s refused" % fname, p.file(fname), "FileResponse", -98)
            logged("file://%s refused (log)" % fname, mark,
                   "File request for '%s' outside the file directory refused\n" % fname)
    finally:
        p.close()


# ---------------------------------------------------------------------------
# AsteriskRequest and HTTPRequest (JSON)
# ---------------------------------------------------------------------------

def call(p, auth, doc, rtype="AsteriskRequest", **kw):
    return p.asterisk(doc, auth=auth, rtype=rtype, **kw)


def test_asterisk():
    print("\n== AsteriskRequest / HTTPRequest (JSON)")
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)
    cli("dpmadev method register json p12.Who.Json")
    p = phone(MAC_A)
    try:
        echo = method_request("test.dpma.api.echo", {"x": 1, "y": "z"})
        want = http(b'{"response":{"method":"test.dpma.api.echo","result":{"x":1,"y":"z"}}}')
        expect("echo, phone pin", call(p, "simphone:1234", echo), "AsteriskResponse", None, want)
        expect("echo as HTTPRequest", call(p, "simphone:1234", echo, "HTTPRequest"), "HTTPResponse", None, want)
        # The credentials line after the request.
        ex = p.request("AsteriskRequest", echo + "\r\nX-Digium-AppServer-Digest-Auth=simphone:1234")
        expect("credentials after the request", ex, "AsteriskResponse", None, want)

        def who(auth, phone_name, name, method="p12.Who.Json"):
            doc = method_request(method, {"k": "v"})
            body = json.dumps({"response": {"method": method, "result": {
                "phone": phone_name, "registry": "json", "parameters": {"k": "v"}}}},
                separators=(",", ":")).encode()
            expect(name, call(p, auth, doc), "AsteriskResponse", None, http(body))

        who("p12a:4321", "p12a", "phone name and pin")
        who("  p12a :\t4321  ", "p12a", "blanks around the credentials")
        who("p12a-line:lsecret", "p12a", "line name and secret authenticate the line's phone")
        who("p12b", "p12b", "no colon: a phone without a pin")
        who("p12b-line", "p12b", "no colon: a line without a secret")
        who("p12a:4321", "p12a", "method name as requested", method="P12.WHO.JSON")
        who("P12A:4321", "p12a", "phone names match case insensitively")

        for auth in ("p12a:1234", "p12a", "p12a-line:wrong", "nosuch:1", ":4321", "p12a:4321x"):
            mark = log_mark()
            expect("bad credentials %r" % auth, call(p, auth, echo), "AsteriskResponse", None,
                   http(json_error("NA", 99999, "authentication failed for %s" % auth.strip())))
            logged("bad credentials %r (log)" % auth, mark,
                   "Authentication failed for user credentials: %s\n" % auth.strip())

        mark = log_mark()
        expect("no credentials", p.request("AsteriskRequest", echo), "AsteriskResponse", None,
               http(json_error("NA", 10002, "missing authentication credentials")))
        logged("no credentials (log)", mark, "No auth credentials found in phone msg\n")
        mark = log_mark()
        expect("no request", call(p, "simphone:1234", "hello"), "AsteriskResponse", None,
               http(json_error("NA", 10002, "empty json body")))
        logged("no request (log)", mark, "No xml request body found in phone msg:\n")
        cases = [
            ('{"request": {"method": "test.dpma.api.echo", "parameters": {}', "NA", 10002, "json body"),
            ('{"request": 5}', "NA", 10002, "no request in body"),
            ('{"request": {"parameters": {}}}', "NA", 10002, "no method in body"),
            ('{"request": {"method": 7, "parameters": {}}}', "NA", 10002, "no method in body"),
            ('{"request": {"method": "test.dpma.api.echo"}}', "test.dpma.api.echo", 10001,
             "request contains no parameters"),
            ('{"request": {"method": "no.such.method", "parameters": {}}}', "no.such.method", 10005,
             "no.such.method"),
            ('{"request": {"method": "", "parameters": {}}}', "NA", 10005, ""),
        ]
        for doc, method, code, detail in cases:
            expect("JSON %s" % doc, call(p, "simphone:1234", doc), "AsteriskResponse", None,
                   http(json_error(method, code, detail)))
        # A method that answers nothing (getTodaysStatus without a queue
        # application).
        doc = method_request("switchvox.users.callQueues.getTodaysStatus",
                             {"account_id": "1001", "call_queue_account_id": "nosuchqueue"})
        expect("empty method response", call(p, "simphone:1234", doc), "AsteriskResponse", None,
               http(json_error("switchvox.users.callQueues.getTodaysStatus", 10002, "empty response body")))
        # Multi-chunk request and reply.
        big = {"data": "x" * 3000, "n": list(range(200))}
        ex = call(p, "simphone:1234", method_request("test.dpma.api.echo", big))
        r = expect("multi-chunk echo", ex, "AsteriskResponse", None, http(json.dumps(
            {"response": {"method": "test.dpma.api.echo", "result": big}}, separators=(",", ":")).encode()))
        if r is not None:
            check("multi-chunk echo: request and reply in several chunks", ex.chunks > 1 and len(r.parts) > 1,
                  "%d / %d" % (ex.chunks, len(r.parts)))
    finally:
        p.close()
        cli("dpmadev method unregister json p12.Who.Json")


# ---------------------------------------------------------------------------
# XML requests
# ---------------------------------------------------------------------------

def test_xml():
    print("\n== AsteriskRequest (XML)")
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)
    cli("dpmadev method register xml p12.Who.Xml")
    p = phone(MAC_A)
    try:
        params = '<parameters><a x="1">t &amp; u</a><b/></parameters>'
        doc = '<request method="P12.who.xml">%s</request>' % params
        cli("core set debug 3 res_digium_phone")
        mark = log_mark()
        want = ('<response method="P12.who.xml"><result phone="p12a" registry="xml">%s</result></response>'
                % params).encode()
        expect("XML method gets phone, method, and <parameters>", call(p, "p12a:4321", doc),
               "AsteriskResponse", None, http(want))
        logged("XML debug log", mark, "Asterisk request method 'P12.who.xml' is using XML body\n")
        cli("core set debug 0 res_digium_phone")
        cases = [
            ('<request method="p12.who.xml"/>', "p12.who.xml", 10001),
            ('<request method=""><parameters/></request>', "NA", 10003),
            ('<request method="p12.who.xml"><params/></request>', "p12.who.xml", 10011),
            ('<request method="no.such.method"><parameters/></request>', "no.such.method", 10005),
            ('<request method="p12.who.xml"><parameters>', "NA", 10002),
        ]
        for d, method, code in cases:
            expect("XML %s" % d, call(p, "p12a:4321", d), "AsteriskResponse", None, http(xml_error(method, code)))
        # Text before the request element is ignored.
        ex = call(p, "p12a:4321", "junk " + doc)
        expect("XML after other text", ex, "AsteriskResponse", None, http(want))
        # A built-in XML method: startRecording without parameters.
        d = '<request method="switchvox.users.currentCalls.startRecording"><parameters/></request>'
        expect("built-in XML method", call(p, "p12a:4321", d), "AsteriskResponse", None,
               http(xml_error("switchvox.users.currentCalls.startRecording", 10011)))
        # JSON-only methods are not XML methods.
        d = '<request method="test.dpma.api.echo"><parameters/></request>'
        expect("JSON-only method requested as XML", call(p, "p12a:4321", d), "AsteriskResponse", None,
               http(xml_error("test.dpma.api.echo", 10005)))
    finally:
        p.close()
        cli("dpmadev method unregister xml p12.Who.Xml")


# ---------------------------------------------------------------------------
# Methods registered by AMI: the DPMAMessage event
# ---------------------------------------------------------------------------

def test_ami():
    print("\n== Methods registered by AMI (DPMAMessage)")
    set_general(config_auth="mac_globalpin", userlist_auth="disabled", globalpin=GLOBALPIN)
    # Registered with DPMAMessageRegister when that action exists (P13),
    # else with the test hook.
    res = L.ami.action("DPMAMessageRegister", Method="p12.ami.method")
    p13 = res.success
    if not p13:
        cli("dpmadev method register ami p12.ami.method")
    p = phone(MAC_A)
    try:
        L.ami.drain_events()
        for fmt, doc, params in (
                ("JSON", method_request("p12.AMI.method", {"a": [1, 2.5, "x"], "b": {"c": None}}),
                 '{"a":[1,2.5,"x"],"b":{"c":null}}'),
                ("XML", '<request method="p12.AMI.method"><parameters><a>one</a> <b>two</b></parameters></request>',
                 "one two")):
            ex = call(p, "p12a:4321", doc, wait=False)
            ev = L.ami.wait_event("DPMAMessage", timeout=5)
            check("%s: DPMAMessage raised" % fmt, ev is not None)
            if ev is None:
                continue
            same("%s: RequestID is the transaction key" % fmt, ev.get("RequestID"), "%s-%s" % (ex.id, MAC_A))
            same("%s: Method as requested" % fmt, ev.get("Method"), "p12.AMI.method")
            same("%s: Format" % fmt, ev.get("Format"), fmt)
            same("%s: Parameters" % fmt, ev.get("Parameters"), params)
            same("%s: Privilege (agent)" % fmt, (ev.get("Privilege") or "").split(",")[0], "agent")
            if p13:
                body = '{"ok":1}' if fmt == "JSON" else "<ok/>"
                L.ami.action("DPMAMessageResponse", RequestID=ev.get("RequestID"), Format=fmt.lower(),
                           Response=body)
                r = p.wait_reply(ex, 10).reply
                check("%s: answered through DPMAMessageResponse" % fmt,
                      r is not None and r.payload.startswith(HTTP) and b"ok" in r.payload,
                      repr(r and r.payload))
            else:
                # Without P13's queue the request cannot wait: the reply
                # goes out at once with just the HTTP header.
                expect("%s: without the AMI queue the reply is the bare header" % fmt,
                       p.wait_reply(ex, 5), "AsteriskResponse", None, HTTP)
        # Parameters that are not an object or array: no event.
        ex = call(p, "p12a:4321", method_request("p12.ami.method", "scalar"), wait=False)
        ev = L.ami.wait_event("DPMAMessage", timeout=2)
        check("JSON scalar parameters: no DPMAMessage", ev is None, repr(ev))
        if p13:
            # It still waits for DPMAMessageResponse (which nobody can
            # send without the event).
            check("JSON scalar parameters: queued, no reply", p.wait_reply(ex, 2).reply is None)
        else:
            expect("JSON scalar parameters: bare header", p.wait_reply(ex, 5), "AsteriskResponse", None, HTTP)
        # A built-in method shadows an AMI registration of the same name.
        cli("dpmadev method register ami test.dpma.api.echo")
        ex = call(p, "simphone:1234", method_request("test.dpma.api.echo", {"x": 1}))
        expect("built-in method wins over AMI", ex, "AsteriskResponse", None,
               http(b'{"response":{"method":"test.dpma.api.echo","result":{"x":1}}}'))
        cli("dpmadev method unregister ami test.dpma.api.echo")
    finally:
        p.close()
        cli("dpmadev method unregister ami p12.ami.method")


# ---------------------------------------------------------------------------
# Handshake without a user agent
# ---------------------------------------------------------------------------

def test_handshake():
    print("\n== Handshake without a User-Agent")
    clear_incidents()
    p = Phone(Options(slot=SLOT, mac=MAC_A, user_agent=""), out=io.StringIO())
    p.start()
    try:
        mark = log_mark()
        ex = p.handshake(timeout=2)
        check("no reply", ex.reply is None, ex.describe())
        log = log_since(mark)
        for text in ("User Agent allocation failed", "Session could not be created due to invalid credentials",
                     "Failed to create auth problem record"):
            check("log: %s" % text, text in log)
        same("no incident without a user agent", incidents().get("127.0.0.1"), None)
        # With an incident for the address already there, it counts.
        q = Phone(Options(slot=SLOT, mac=MAC_A), out=io.StringIO())
        q.start()
        try:
            q.handshake(bundle="rogue", timeout=2)
        finally:
            q.close()
        inc = incidents().get("127.0.0.1")
        same("rogue certificate: incident", inc and (inc.get("Reason"), inc.get("IncidentCount")),
             ("invalid credentials", "1"))
        p.handshake(timeout=2)
        inc = incidents().get("127.0.0.1")
        same("no user agent: the incident counts", inc and inc.get("IncidentCount"), "2")
    finally:
        p.close()
        clear_incidents()


# ---------------------------------------------------------------------------

def make_files():
    os.makedirs(FILES, exist_ok=True)
    with open(os.path.join(FILES, "p12-small.txt"), "wb") as f:
        f.write(b"line one\nline two\n")
    with open(os.path.join(FILES, "p12-big.bin"), "wb") as f:
        f.write(bytes(range(256)) * 20 + b"\0end")
    with open(os.path.join(FILES, "p12c-config.xml"), "wb") as f:
        f.write(b"<config>\n<!-- p12c's own configuration file -->\n</config>\n")
    os.makedirs(os.path.join(FILES, "sub"), exist_ok=True)
    for name, data in (("sub/p12-sub.txt", b"in a subdirectory\n"), ("..p12-dots.txt", b"two dots\n"),
                       ("sub/..p12-dots.txt", b"two dots in sub\n"), ("../p12-outside.txt", b"outside\n")):
        with open(os.path.join(FILES, name), "wb") as f:
            f.write(data)


SECTIONS = {
    "token": test_token, "config": test_config, "userlist": test_userlist, "file": test_file,
    "asterisk": test_asterisk, "xml": test_xml, "ami": test_ami, "handshake": test_handshake,
}


def main():
    wanted = [a for a in sys.argv[1:] if not a.startswith("-")] or list(SECTIONS)
    make_files()
    with open(CONF) as f:
        original = f.read()
    L.connect()
    try:
        for name in wanted:
            SECTIONS[name]()
    finally:
        with open(CONF, "w") as f:
            f.write(original)
        cli("module reload res_digium_phone.so")
        L.ami.close()
    return L.summary()


if __name__ == "__main__":
    sys.exit(main())
