#!/usr/bin/env python3
"""Generate the test PKI for the DPMA phone simulator.

Everything here is generated locally; nothing comes from the original
binary.  The PKI has two independent halves:

* Phone side: a test root CA (the content of the module's `phone_ca_file`),
  an intermediate CA signed by it, a phone certificate signed by the
  intermediate (chain form), and a legacy phone certificate signed by the
  root (legacy form).  Negative variants: expired certificates, a
  certificate from an untrusted ("rogue") CA, and a 512-bit SHA-1 legacy
  certificate (made with the openssl command, since `cryptography` refuses
  such keys).
* AppServer side: a test AppServer CA and an AppServer certificate signed by
  it (the module's `appserver_certificate`).  The simulator checks the
  HandshakeResponse body against the AppServer CA.

Files (in --dir, default dev/sim/pki/): `<name>.key` and `<name>.pem` for
every entity, and `bundles.json`, which lists the handshake bodies the
simulator can send (`dpma_sim.py --bundle NAME`): the certificates in body
order and the key that decrypts the common password.

The instance install copies `root-ca.pem` to
`<instance>/etc/asterisk/dpma/phone_ca.pem` and `appserver.pem` to
`<instance>/etc/asterisk/dpma/appserver.pem` (the defaults of `phone_ca_file`
and `appserver_certificate`).  The instance is chosen like dev/tools/ast.sh
does: --instance DIR, else --slot N or $DPMA_SLOT (dev/run/slot<N>), else the
scratch install dev/asterisk-24.

Usage:
  mkpki.py                 generate (keeping existing files) and install
  mkpki.py --force         regenerate everything
  mkpki.py --no-install    generate only
  mkpki.py --check         verify every certificate with `openssl verify`
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

# Fixed serial number of the intermediate CA, so that the module's log line
# "Intermediate cert serial number: %ld" has a known value.
INTERMEDIATE_SERIAL = 4097

DEFAULT_MAC = "000fd3000001"

UTC = datetime.timezone.utc


def name(cn, org="DPMA Simulator Test PKI"):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


class Pki:
    def __init__(self, directory, force):
        self.dir = directory
        self.force = force
        os.makedirs(self.dir, exist_ok=True)
        self.now = datetime.datetime.now(UTC).replace(microsecond=0)

    def path(self, entity, ext):
        return os.path.join(self.dir, "%s.%s" % (entity, ext))

    def exists(self, entity):
        return (not self.force and os.path.exists(self.path(entity, "key"))
                and os.path.exists(self.path(entity, "pem")))

    def load(self, entity):
        with open(self.path(entity, "key"), "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
        with open(self.path(entity, "pem"), "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return key, cert

    def save(self, entity, key, cert):
        key_path = self.path(entity, "key")
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
        os.chmod(key_path, 0o600)
        with open(self.path(entity, "pem"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("  wrote %s.{key,pem}: %s" % (entity, cert.subject.rfc4514_string()))

    def make(self, entity, subject, issuer=None, ca=False, pathlen=None,
             serial=None, not_before=None, not_after=None, bits=2048):
        """Create (or load) `entity`, signed by the entity `issuer` (None:
        self-signed)."""
        if self.exists(entity):
            return self.load(entity)
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        if issuer is None:
            issuer_key, issuer_name, issuer_pub = key, subject, key.public_key()
        else:
            issuer_key, issuer_cert = self.load(issuer)
            issuer_name, issuer_pub = issuer_cert.subject, issuer_key.public_key()
        not_before = not_before or self.now - datetime.timedelta(days=1)
        not_after = not_after or self.now + datetime.timedelta(days=365 * (20 if ca else 10))
        b = (x509.CertificateBuilder()
             .subject_name(subject)
             .issuer_name(issuer_name)
             .public_key(key.public_key())
             .serial_number(serial or x509.random_serial_number())
             .not_valid_before(not_before)
             .not_valid_after(not_after)
             .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                            critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub),
                            critical=False))
        if ca:
            b = b.add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        else:
            b = b.add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        cert = b.sign(issuer_key, hashes.SHA256())
        self.save(entity, key, cert)
        return key, cert

    def make_weak(self, entity, cn, issuer):
        """A 512-bit, SHA-1 signed certificate, made with the openssl command
        (`cryptography` refuses both).  Returns False when openssl is missing
        or refuses."""
        if not self.force and os.path.exists(self.path(entity, "pem")):
            return True
        if shutil.which("openssl") is None:
            print("  skipped %s: no openssl command" % entity)
            return False
        with tempfile.TemporaryDirectory() as tmp:
            csr = os.path.join(tmp, "req.csr")
            ext = os.path.join(tmp, "ext.cnf")
            with open(ext, "w") as f:
                f.write("basicConstraints=critical,CA:FALSE\n"
                        "keyUsage=critical,digitalSignature,keyEncipherment\n")
            cmds = [
                ["openssl", "genrsa", "-traditional", "-out", self.path(entity, "key"), "512"],
                ["openssl", "req", "-new", "-key", self.path(entity, "key"), "-subj",
                 "/C=US/O=DPMA Simulator Test PKI/CN=%s" % cn, "-out", csr],
                ["openssl", "x509", "-req", "-in", csr, "-CA", self.path(issuer, "pem"),
                 "-CAkey", self.path(issuer, "key"), "-set_serial", "513", "-sha1",
                 "-days", "3650", "-extfile", ext, "-out", self.path(entity, "pem")],
            ]
            for cmd in cmds:
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode != 0:
                    print("  skipped %s: %s failed: %s" % (entity, cmd[1], r.stderr.strip()))
                    return False
        os.chmod(self.path(entity, "key"), 0o600)
        print("  wrote %s.{key,pem}: 512-bit RSA, SHA-1, issued by %s" % (entity, issuer))
        return True


def generate(directory, force, mac):
    p = Pki(directory, force)
    print("generating test PKI in %s" % directory)
    p.make("root-ca", name("DPMA Test Phone Root CA"), ca=True)
    p.make("intermediate-ca", name("DPMA Test Phone Intermediate CA"), issuer="root-ca",
           ca=True, pathlen=0, serial=INTERMEDIATE_SERIAL)
    p.make("phone", name("DPMA Sim Phone %s" % mac), issuer="intermediate-ca")
    p.make("legacy", name("DPMA Sim Legacy Phone %s" % mac), issuer="root-ca")
    old_before = datetime.datetime(2001, 1, 1, tzinfo=UTC)
    old_after = datetime.datetime(2002, 1, 1, tzinfo=UTC)
    p.make("phone-expired", name("DPMA Sim Expired Phone %s" % mac), issuer="intermediate-ca",
           not_before=old_before, not_after=old_after)
    p.make("legacy-expired", name("DPMA Sim Expired Legacy Phone %s" % mac), issuer="root-ca",
           not_before=old_before, not_after=old_after)
    p.make("rogue-ca", name("DPMA Untrusted Rogue CA", org="Rogue"), ca=True)
    p.make("rogue", name("DPMA Sim Rogue Phone %s" % mac, org="Rogue"), issuer="rogue-ca")
    weak = p.make_weak("weak", "DPMA Sim Weak Legacy Phone %s" % mac, "root-ca")
    p.make("appserver-ca", name("DPMA Test AppServer CA"), ca=True)
    p.make("appserver", name("DPMA Test AppServer"), issuer="appserver-ca")

    bundles = {
        "legacy": (["legacy"], "legacy", "legacy form: one certificate signed by the root CA"),
        "chain": (["legacy", "intermediate-ca", "phone"], "phone",
                  "chain form: legacy, intermediate, and phone certificates"),
        "chain-expired": (["legacy", "intermediate-ca", "phone-expired"], "phone-expired",
                          "chain form with an expired phone certificate (accepted)"),
        "legacy-expired": (["legacy-expired"], "legacy-expired",
                           "legacy form with an expired certificate (accepted)"),
        "rogue": (["rogue"], "rogue", "legacy form signed by an untrusted CA (rejected)"),
        "two": (["intermediate-ca", "phone"], "phone",
                "two certificates (rejected: 'Expected two certificates in the chain, found 1')"),
        "four": (["legacy", "intermediate-ca", "phone", "phone"], "phone",
                 "four certificates (rejected: '... found 3')"),
    }
    if weak:
        bundles["weak"] = (["weak"], "weak",
                           "legacy form, 512-bit RSA key with a SHA-1 signature (accepted)")
    manifest = {
        "appserver_ca": "appserver-ca.pem",
        "phone_ca": "root-ca.pem",
        "intermediate_serial": INTERMEDIATE_SERIAL,
        "bundles": {
            n: {"certs": ["%s.pem" % c for c in certs], "key": "%s.key" % key,
                "description": desc}
            for n, (certs, key, desc) in bundles.items()
        },
    }
    with open(os.path.join(directory, "bundles.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print("  wrote bundles.json: %s" % ", ".join(bundles))


def instance_dir(args):
    if args.instance:
        return args.instance
    slot = args.slot or os.environ.get("DPMA_SLOT")
    if slot:
        return os.path.join(REPO, "dev", "run", "slot%s" % slot)
    return os.path.join(REPO, "dev", "asterisk-24")


def install(directory, inst):
    etc = os.path.join(inst, "etc", "asterisk")
    if not os.path.isdir(etc):
        sys.exit("mkpki: %s is not an Asterisk instance (no etc/asterisk)" % inst)
    dest = os.path.join(etc, "dpma")
    os.makedirs(dest, exist_ok=True)
    for src, dst in (("root-ca.pem", "phone_ca.pem"), ("appserver.pem", "appserver.pem")):
        tmp = os.path.join(dest, ".%s.new" % dst)
        shutil.copyfile(os.path.join(directory, src), tmp)
        os.replace(tmp, os.path.join(dest, dst))
        print("installed %s as %s" % (src, os.path.join(dest, dst)))


def check(directory):
    """Verify every certificate with `openssl verify`; the expected outcome
    follows the module's rules (expiry ignored, 512-bit keys accepted)."""
    def d(f):
        return os.path.join(directory, f)
    cases = [
        ("legacy", ["-CAfile", d("root-ca.pem"), d("legacy.pem")], True),
        ("chain", ["-CAfile", d("root-ca.pem"), "-untrusted", d("intermediate-ca.pem"),
                   d("phone.pem")], True),
        ("intermediate", ["-CAfile", d("root-ca.pem"), d("intermediate-ca.pem")], True),
        ("chain-expired", ["-no_check_time", "-CAfile", d("root-ca.pem"), "-untrusted",
                           d("intermediate-ca.pem"), d("phone-expired.pem")], True),
        ("chain-expired (time checked)", ["-CAfile", d("root-ca.pem"), "-untrusted",
                                          d("intermediate-ca.pem"), d("phone-expired.pem")],
         False),
        ("legacy-expired", ["-no_check_time", "-CAfile", d("root-ca.pem"),
                            d("legacy-expired.pem")], True),
        ("rogue", ["-CAfile", d("root-ca.pem"), d("rogue.pem")], False),
        ("phone without intermediate", ["-CAfile", d("root-ca.pem"), d("phone.pem")], False),
        ("appserver", ["-CAfile", d("appserver-ca.pem"), d("appserver.pem")], True),
        ("appserver against phone CA", ["-CAfile", d("root-ca.pem"), d("appserver.pem")], False),
    ]
    if os.path.exists(d("weak.pem")):
        cases.append(("weak (auth level 0)", ["-auth_level", "0", "-CAfile", d("root-ca.pem"),
                                              d("weak.pem")], True))
    failures = 0
    for label, argv, want in cases:
        r = subprocess.run(["openssl", "verify"] + argv, capture_output=True, text=True)
        ok = r.returncode == 0
        reasons = [ln.split(":", 1)[-1].strip() for ln in (r.stdout + r.stderr).splitlines()
                   if re.search(r"error \d+ at \d+ depth", ln)]
        detail = reasons[0] if reasons else ("OK" if ok else "failed")
        good = ok == want
        failures += not good
        print("%-4s %-30s %s (%s)" % ("ok" if good else "FAIL", label,
                                      "verifies" if ok else "rejected", detail))
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default=os.path.join(HERE, "pki"),
                    help="PKI directory (default: %(default)s)")
    ap.add_argument("--force", action="store_true", help="regenerate existing files")
    ap.add_argument("--mac", default=DEFAULT_MAC, help="MAC used in the subject names")
    ap.add_argument("--slot", help="instance slot (default: $DPMA_SLOT)")
    ap.add_argument("--instance", help="instance directory (overrides --slot)")
    ap.add_argument("--no-install", action="store_true", help="do not install into an instance")
    ap.add_argument("--check", action="store_true",
                    help="verify the certificates with openssl and exit")
    args = ap.parse_args()
    directory = os.path.abspath(args.dir)
    if args.check:
        sys.exit(1 if check(directory) else 0)
    generate(directory, args.force, args.mac.replace(":", "").lower())
    if not args.no_install:
        install(directory, instance_dir(args))


if __name__ == "__main__":
    main()
