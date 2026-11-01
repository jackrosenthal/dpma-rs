"""The raw-bytes test configuration: text in Latin-1 (bytes that are not
UTF-8) in every kind of user-visible field, plus a phone whose texts are
UTF-8 with non-ASCII characters.  Imported by run.py; run as a script
(by setup.sh) it writes the files into the instance."""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SLOT = int(os.environ.get("DPMA_SLOT", "0"))
INST = os.path.join(ROOT, "dev", "run", "slot%d" % SLOT)
ETC = os.path.join(INST, "etc", "asterisk")
VARLIB = os.path.join(INST, "var", "lib", "asterisk")
FILES = os.path.join(VARLIB, "digium_phones")
SPOOL = os.path.join(INST, "var", "spool", "asterisk", "voicemail")

GLOBALPIN = b"344486"

# The Latin-1 phone (the simulator's MAC) and its line.
PHONE = b"t\xe9l\xe9phone"
MAC = "000fd3001801"
PIN = b"4321"
GROUP_PIN = b"222"
FULL_NAME = b"Jos\xe9 M\xfcller"
LINE = b"1001"
LINE_LABEL = b"L\xednea \xe9"
FIRST_NAME = b"Jos\xe9"
LAST_NAME = b"M\xfcller"
CALLERID = b'"Jos\xe9" <1001>'
LOCATION = b"Bureau \xe0 Gen\xe8ve"
IDLE_TEXT = b"Soci\xe9t\xe9 G\xe9n\xe9rale"
CONTACT_FILE = b"contacts-\xe9.xml"
CONTACT_XML = b'<contacts group_name="Coll\xe8gues" editable="0">\n<contact first_name="Ren\xe9" />\n</contacts>\n'
RULES_FILE = b"r\xe8gles.xml"
RULES_XML = b"<display_rules />\n"

NETWORK = b"r\xe9seau"
NET_ALIAS = b"R\xe9seau principal"
FILE_URL = b"http://example.invalid/fichiers-\xe9/"
STATUS_APP = b"statut\xe9"
SUBSTATUS = b"D\xe9jeuner"
CUSTOM_APP = b"perso\xe9"
CUSTOM_NAME = b"Appli\xe9"
VM_APP = b"messagerie\xe9"
TRANSLATION = b"fran\xe7ais"
INBOX_FR = b"Bo\xeete de r\xe9ception"
ALERT = b"alerte\xe9"
ALERT_INFO = b"info-\xe9"
PAGE = b"page\xe9"
PAGE_ALIAS = b"Annonce g\xe9n\xe9rale"
RINGTONE = b"sonnerie\xe9"
RINGTONE_ALIAS = b"M\xe9lodie"

# The UTF-8 phone (a second simulator MAC) and its line.
U_PHONE = "téléphone-utf8".encode()
U_MAC = "000fd3001802"
U_PIN = b"8765"
U_GROUP_PIN = b"111"
U_FULL_NAME = "Zoë Ünal".encode()
U_LINE = b"1002"
U_LINE_LABEL = "Línea ü".encode()
U_NETWORK = "réseau-ü".encode()

# What the simulator sends.
USER_AGENT = b"Digium D65 2_9_17 r\xe9v"
ORIGINATION = b"r\xe9seau-\xe9tage"

# Voicemail (mailbox 1001@default, the Latin-1 phone's line): a message
# with a Latin-1 caller id in Work, one with a UTF-8 caller id in Family.
# (The phone's translation shows INBOX in Latin-1.)
VM_BOX = os.path.join("default", "1001")
VM_LATIN1 = ("Work", "1640995200-00000001", b'"Fran\xe7ois" <200>', 1640995200)
VM_UTF8 = ("Family", "1640995300-00000002", '"Frédéric" <300>'.encode(), 1640995300)


def conf():
    """res_digium_phone.conf."""
    lines = [
        b"; dpma-rs raw-bytes test (dev/tests/raw-bytes): Latin-1 text",
        b"[general]",
        b"globalpin=" + GLOBALPIN,
        b"userlist_auth=globalpin",
        b"config_auth=mac",
        b"service_discovery_enabled=no",
        b"",
        b"[" + PHONE + b"]",
        b"type=phone",
        b"mac=" + MAC.encode(),
        b"pin=" + PIN,
        b"group_pin=" + GROUP_PIN,
        b"full_name=" + FULL_NAME,
        b"line=" + LINE,
        b"network=" + NETWORK,
        b"application=" + STATUS_APP,
        b"application=" + CUSTOM_APP,
        b"application=" + VM_APP,
        b"contact=" + CONTACT_FILE,
        b"alert=" + ALERT,
        b"multicastpage=" + PAGE,
        b"ringtone=" + RINGTONE,
        b"idle_company_text=" + IDLE_TEXT,
        b"contacts_display_rules=" + RULES_FILE,
        b"",
        b"[" + U_PHONE + b"]",
        b"type=phone",
        b"mac=" + U_MAC.encode(),
        b"pin=" + U_PIN,
        b"group_pin=" + U_GROUP_PIN,
        b"full_name=" + U_FULL_NAME,
        b"line=" + U_LINE,
        b"network=" + U_NETWORK,
        b"contacts_display_rules=" + RULES_FILE,
        b"",
        b"[" + LINE + b"]",
        b"type=line",
        b"mailbox=1001@default",
        b"line_label=" + LINE_LABEL,
        b"first_name=" + FIRST_NAME,
        b"last_name=" + LAST_NAME,
        b"callerid=" + CALLERID,
        b"location=" + LOCATION,
        b"",
        b"[" + U_LINE + b"]",
        b"type=line",
        b"line_label=" + U_LINE_LABEL,
        b"",
        b"[" + NETWORK + b"]",
        b"type=network",
        b"alias=" + NET_ALIAS,
        b"cidr=0.0.0.0/0",
        b"registration_address=127.0.0.1",
        b"file_url_prefix=" + FILE_URL,
        b"",
        b"[" + U_NETWORK + b"]",
        b"type=network",
        b"alias=" + "Réseau ü".encode(),
        b"cidr=0.0.0.0/0",
        b"registration_address=127.0.0.1",
        b"",
        b"[" + STATUS_APP + b"]",
        b"type=application",
        b"application=status",
        b"status=away",
        b"substatus=" + SUBSTATUS,
        b"",
        b"[" + CUSTOM_APP + b"]",
        b"type=application",
        b"application=custom",
        b"name=" + CUSTOM_NAME,
        b"filename=appli.zip",
        b"idlescreen_softkey=yes",
        b"",
        b"[" + VM_APP + b"]",
        b"type=application",
        b"application=voicemail",
        b"translation=" + TRANSLATION,
        b"",
        b"[" + TRANSLATION + b"]",
        b"type=translation",
        b"INBOX=" + INBOX_FR,
        b"",
        b"[" + ALERT + b"]",
        b"type=alert",
        b"alert_info=" + ALERT_INFO,
        b"ring_type=normal",
        b"ringtone=Digium",
        b"",
        b"[" + PAGE + b"]",
        b"type=multicastpage",
        b"alias=" + PAGE_ALIAS,
        b"address=224.0.1.116",
        b"port=5004",
        b"",
        b"[" + RINGTONE + b"]",
        b"type=ringtone",
        b"alias=" + RINGTONE_ALIAS,
        b"filename=sonnerie.raw",
        b"",
    ]
    return b"\n".join(lines)


VOICEMAIL_CONF = b"""; dpma-rs raw-bytes test (dev/tests/raw-bytes)
[general]
format=wav

[default]
1001 => 1111,Jos\xe9 M\xfcller
"""


def wav():
    """A tenth of a second of silence (8 kHz, 16-bit mono)."""
    data = b"\0\0" * 800
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt "
            + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16) + b"data" + struct.pack("<I", len(data)) + data)


def message(num, folder, msg_id, callerid, origtime):
    """A voicemail message of 1001@default."""
    d = os.path.join(SPOOL, VM_BOX, folder)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "msg%04d.wav" % num), "wb") as f:
        f.write(wav())
    with open(os.path.join(d, "msg%04d.txt" % num), "wb") as f:
        f.write(b";\n; Message Information file\n;\n[message]\norigmailbox=1001\ncontext=default\n"
                b"exten=1001\nrdnis=unknown\npriority=1\ncallerchan=Local/1001@default-0;2\n")
        f.write(b"callerid=" + callerid + b"\n")
        f.write(("origdate=Sat Jan  1 12:00:00 AM UTC 2022\norigtime=%d\ncategory=\nmsg_id=%s\nflag=\n"
                 "duration=1\n" % (origtime, msg_id)).encode())


def install():
    with open(os.path.join(ETC, "res_digium_phone.conf"), "wb") as f:
        f.write(conf())
    with open(os.path.join(ETC, "voicemail.conf"), "wb") as f:
        f.write(VOICEMAIL_CONF)
    os.makedirs(FILES, exist_ok=True)
    for name, data in ((CONTACT_FILE, CONTACT_XML), (RULES_FILE, RULES_XML)):
        with open(os.path.join(FILES.encode(), name), "wb") as f:
            f.write(data)
    box = os.path.join(SPOOL, VM_BOX)
    if os.path.isdir(box):
        for dirpath, _, names in os.walk(box, topdown=False):
            for n in names:
                os.remove(os.path.join(dirpath, n))
            os.rmdir(dirpath)
    message(0, *VM_LATIN1)
    message(0, *VM_UTF8)
    print("installed into %s" % INST)


if __name__ == "__main__":
    if not SLOT:
        sys.exit("DPMA_SLOT is not set")
    if not os.path.isdir(ETC):
        sys.exit("no instance at %s" % INST)
    install()
