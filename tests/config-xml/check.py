#!/usr/bin/env python3
"""Smoke checks for the P4 configuration documents in a private instance
prepared with setup.sh (devtest build installed, Asterisk running):

    DPMA_SLOT=<n> python3 -I tests/config-xml/check.py [-v]

No expected documents are recorded (P4 compared them with the decompile
by hand); this checks that every document setup.sh describes is produced
and well formed: the phones' configuration documents (the original does
not escape network aliases or idle_company_text, and the setup has markup
in network2's alias and fullphone's idle_company_text; those values are
escaped before the check), altphone's with the merged display rules (an XML
declaration), cfgphone's from its config_file, the contacts document,
and the user list with and without the global pin.  -v prints the
documents.  Exit status 0 when every check passes.
"""
import json
import os
import subprocess
import sys
import xml.dom.minidom

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
if not os.environ.get("DPMA_SLOT"):
    sys.exit("DPMA_SLOT is not set")
VERBOSE = "-v" in sys.argv
# Values the original writes unescaped (attribute text as in the document).
UNESCAPED = {"fullphone": ('display_name="Remote & <Other>"', 'value="ACME <Corp>"'),
             "nolinephone": ('display_name="Remote & <Other>"',)}
failures = 0


def cli(cmd):
    return subprocess.run([os.path.join(ROOT, "tools/ast.sh"), "cli", cmd],
                          capture_output=True, text=True).stdout


def check(name, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        failures += 1
        if detail:
            print("     " + detail)


def well_formed(text):
    try:
        xml.dom.minidom.parseString(text.encode())
        return None
    except Exception as e:  # noqa: BLE001 (expat raises several types)
        return str(e)


def document(cmd):
    out = cli(cmd)
    if VERBOSE:
        print(out)
    return out


if "No such command" in cli("dpmadev config"):
    sys.exit("dpmadev hooks not available (devtest build installed and Asterisk running?)")

for phone in ("fullphone", "minphone", "altphone", "nolinephone"):
    doc = document("dpmadev config %s D65" % phone)
    check("%s: a configuration document" % phone, "<config>" in doc and "</config>" in doc, doc[:200])
    for text in UNESCAPED.get(phone, ()):
        check("%s: unescaped %s" % (phone, text), text in doc)
        name, value = text.split("=", 1)
        value = value[1:-1].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        doc = doc.replace(text, '%s="%s"' % (name, value))
    err = well_formed(doc)
    check("%s: well formed" % phone, err is None, err or "")
    if phone == "altphone":
        check("altphone: display rules merged", doc.startswith('<?xml version="1.0"?>\n<config>'), doc[:80])

doc = document("dpmadev config cfgphone D65")
check("cfgphone: the config_file", doc == '<config>\n<setting id="x" value="1" />\n</config>\n', repr(doc))

doc = document("dpmadev contacts")
err = well_formed(doc)
check("contacts: well formed", doc.startswith("<contacts ") and err is None, err or doc[:200])

for args, count, line in (("", 0, "0 user(s), group pin filter on"),
                          (" 344486", 5, "5 user(s), group pin filter off")):
    out = document("dpmadev userlist" + args)
    head, _, body = out.partition("\n")
    try:
        users = json.loads(body)["users"]
    except (ValueError, KeyError, TypeError):
        users = None
    check("userlist%s: %d user(s)" % (args, count), head == line and users is not None and len(users) == count,
          out[:200])

print("%d failure(s)" % failures)
sys.exit(1 if failures else 0)
