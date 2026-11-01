# dpma-rs

dpma-rs is an open-source, drop-in replacement for Digium's closed-source
Digium Phone Module for Asterisk (DPMA, `res_digium_phone`), written in
Rust.  It follows DPMA 24.0_3.6.13 for Asterisk 24: the same configuration
files, the same phone protocol, the same CLI commands and AMI actions and
events, and the same C API for the helper modules.  Digium and Sangoma
phones are meant to work with it just as with the original, without
changes on the phones, given the trust material described in "Phone trust
material" below.

This is version 0.1.0.  dpma-rs is an independent rewrite; it is not made
or endorsed by Digium or Sangoma.

It consists of three Asterisk modules, each replacing the module of the
same name in the original distribution:

| Module | Purpose |
|---|---|
| `res_digium_phone.so` | The phone module: phone configuration, sessions and encryption, phone requests, the phone methods (voicemail, queues, parking, recording, phonebook, presence), CLI commands, AMI actions and events, dialplan applications, and service discovery (mDNS). |
| `res_pjsip_endpoint_identifier_dpma.so` | PJSIP support: matches the phones' messages to the module, fills phone lines from the PJSIP configuration, records where phones register, and sends SIP INFO messages to phones during calls. |
| `res_pjsip_dialog_info_digium_body_supplement.so` | Adds the ringing caller's details to dialog-info (BLF) notifications sent to Digium and Sangoma phones. |

## Building

You need:

- A stable Rust toolchain with Cargo (dpma-rs is developed with Rust
  1.99) and a C compiler.
- The Asterisk 24 development headers (`asterisk.h` and the `asterisk/`
  directory).  Set `ASTERISK_INCLUDE_DIR` to the directory that holds
  `asterisk.h`; the default is `/usr/include`.
- For the two PJSIP modules, the pjproject headers Asterisk was built
  with.  Set `PJPROJECT_DIR` to either a pjproject source tree (for the
  pjproject bundled with Asterisk, `third-party/pjproject/source` in the
  Asterisk source tree) or a directory of installed pjproject headers
  (the one containing `pjsip.h`).
- The OpenSSL development files (headers and `pkg-config` data), for the
  `openssl` crate.

Then:

```
export ASTERISK_INCLUDE_DIR=/usr/include
export PJPROJECT_DIR=/usr/src/asterisk-24/third-party/pjproject/source
cargo build --release
```

The modules are built as `target/release/libres_digium_phone.so`,
`target/release/libres_pjsip_endpoint_identifier_dpma.so`, and
`target/release/libres_pjsip_dialog_info_digium_body_supplement.so`.  To
build only the phone module (without the pjproject headers), run
`cargo build --release -p res_digium_phone`.

At run time the modules use the OpenSSL libraries and the libxml2 that
Asterisk itself loads.

## Installing

Copy the modules into Asterisk's module directory (`astmoddir` in
`asterisk.conf`, often `/usr/lib/asterisk/modules`) without the `lib`
prefix, replacing the original modules of the same names:

```
MODDIR=/usr/lib/asterisk/modules
for m in res_digium_phone res_pjsip_endpoint_identifier_dpma res_pjsip_dialog_info_digium_body_supplement; do
    cp target/release/lib$m.so $MODDIR/$m.so.new && mv $MODDIR/$m.so.new $MODDIR/$m.so
done
```

Copy them in while Asterisk is stopped, or copy and rename as above:
writing over a loaded module crashes the running Asterisk.  Then restart
Asterisk; after an upgrade, `module unload` and `module load` do not
reliably pick up the new code of these modules, so restart instead.

The modules load with Asterisk's usual autoloading (or `load =>` lines in
`modules.conf`).  The PJSIP modules require `res_pjsip` and
`res_digium_phone` (the dialog-info supplement also `res_pjsip_pubsub`).
`res_digium_phone` uses `func_presencestate`, `app_voicemail`,
`res_parking`, and `app_queue` when they are loaded.

As with the original, `res_pjsip_endpoint_identifier_dpma` needs a PJSIP
endpoint named by `default_outbound_endpoint` in the `[global]` section of
`pjsip.conf` (default name `default_outbound_endpoint`).  Without it the
module fails to load, which stops Asterisk from starting.

The original `res_pjsip_endpoint_identifier_dpma.so` also works with
dpma-rs's `res_digium_phone.so`.  The original dialog-info supplement does
not: it refuses to load without a license check that dpma-rs does not
have (see "Differences from the original").

## Configuration

dpma-rs reads the same configuration as the original module, so an
existing setup carries over unchanged:

- `res_digium_phone.conf`: every section type and option of the original
  (`[general]`, phones, lines, external lines, networks, applications,
  alerts, ringtones, firmware, multicast pages, and translations).  The
  original's documentation and sample configuration apply.
- `digium_phones_firmware.conf` in the `firmware_package_directory`: the
  firmware package description, as shipped with Digium's firmware
  packages.
- `voicemail.conf` and the `users.conf` users with `hasvoicemail`, read
  through app_voicemail as the original does: they provide line mailboxes
  and voicemail pins (`pin=voicemail`).
- PJSIP lines get their settings from `pjsip.conf` through
  `res_pjsip_endpoint_identifier_dpma`.

chan_sip is not supported: no lines are read from `sip.conf` or from the
`users.conf` users with `hassip`.

dpma-rs adds two options to the `[general]` section of
`res_digium_phone.conf`, `appserver_certificate` and `phone_ca_file`,
described in the next section.  The original module has no such options;
it carries the equivalent material built in.

### Phone trust material

During the handshake each phone presents its factory certificate, and the
server answers with its own (AppServer) certificate.  The original module
has Digium's certificates built into its binary.  dpma-rs ships no Digium
certificates or keys; you must supply this material yourself, from your
own copy of the original distribution:

| Option (`[general]`) | Default | Contents |
|---|---|---|
| `phone_ca_file` | `<astetcdir>/dpma/phone_ca.pem` | PEM bundle of the CA certificates that the phones' certificates are verified against. |
| `appserver_certificate` | `<astetcdir>/dpma/appserver.pem` | PEM certificate sent to the phones in every handshake response; the phones check it against their own trust store. |

`<astetcdir>` is Asterisk's configuration directory, normally
`/etc/asterisk`.  Only certificates are needed: dpma-rs never uses a
server private key (the session key is encrypted with the phone's public
key).

When either file is missing, the module still loads and logs an error
that points here; phones then cannot complete a handshake.  A phone whose
certificate does not verify gets no answer and is recorded as an
authentication incident (`DPMAShowIncidents`).  Both files are read again
on `module reload res_digium_phone.so`; a file that cannot be read keeps
its previous contents.

For testing without phones, `dev/sim/mkpki.py` generates a self-made PKI
and installs it under these names; real phones do not accept its AppServer
certificate.

## Differences from the original

dpma-rs reproduces the original's behavior, quirks included, with these
deliberate exceptions:

1. No license handling.  There is no license check and nothing to
   license: no `digium_phones license status` command, no
   `DPMALicenseStatus` AMI action, and no `get_license_status` function
   for other modules.  The original dialog-info supplement module needs
   that function and so cannot load with dpma-rs; use dpma-rs's own.
2. When loading fails partway, everything already loaded is unloaded
   again.  The original leaves applications, thread pools, and dialplan
   contexts behind.
3. All AMI actions are unregistered when the module unloads.  The original
   leaves some registered, pointing into unloaded code.
4. Certificates come from files you supply (see "Phone trust material"),
   and other key material is generated locally, instead of being built
   in.
5. `digium_phones show version` prints `dpma-rs version 0.1.0` (the
   dpma-rs version) instead of a DPMA version number.
6. No chan_sip support: no phone messages or in-call notifications
   through chan_sip, no lines from `sip.conf` or from `users.conf` users
   with `hassip`, and no warnings about `sip.conf`.  `voicemail.conf` and
   `users.conf` voicemail users are still read.
7. Phone sessions saved in the Asterisk database
   (`DigiumPhoneSessions`) are encrypted with dpma-rs's own passphrase,
   not the original's.  Sessions saved by the original module are
   therefore not restored; those phones simply handshake again.
8. Service discovery (mDNS) uses a responder built into the module
   instead of Avahi, so it works without `avahi-daemon` or the Avahi
   libraries.  It announces the same `_digiumproxy._udp` service, with
   these small differences: the service's host name is
   `<hostname>-dpma.local` (Avahi uses `<hostname>.local`), and a service
   name that collides with another is renamed `name (2)` (Avahi:
   `name #2`).  Discovery is on unless `service_discovery_enabled=no`.
9. Authentication incidents from IPv6 phones are tracked per address.  The
   original cuts the address at its first colon, so all IPv6 phones share
   one incident record.  IPv4 behavior is unchanged.
10. Starting a call recording from a phone reports success when the
    recording starts.  The original always reports an error (and never
    sends the "recording started" notification) although the recording
    runs.
11. "Session Timeout" replies go back over the transport the request came
    in on.  The original sends them over UDP even to phones using TCP.
12. Handshake certificates whose line breaks were lost in transit are
    repaired before they are read.  Asterisk 24 strips trailing line
    breaks from each SIP MESSAGE body, which can break a certificate that
    a phone splits across messages.
13. Phone requests forwarded to AMI clients (methods registered with
    `DPMAMessageRegister`) expire after 300 seconds without a
    `DPMAMessageResponse`, with the log message "No response to request
    (...), expired."  The original never expires them.
14. File requests from phones cannot leave `file_directory`: paths with
    `..` components and absolute paths are answered as if the file did
    not exist (files in subdirectories are still served).  With `..`, the
    original serves any file the Asterisk process can read; it looks up
    absolute paths inside `file_directory`.

Beyond these, a number of inputs that crash the original modules (for
example, some NULL arguments to the C API, and PJSIP AOR changes while a
phone line has no PJSIP endpoint) are handled instead.

## License

dpma-rs is licensed under the GNU General Public License, version 2 or
(at your option) any later version (`GPL-2.0-or-later`), as declared in
`Cargo.toml` and in the C sources.

## Development

The development notes and tools live under `dev/`:

- `dev/notes/port-plan.md`: the plan of the port, the protocol and C API
  as reconstructed from the original, and every finding and decision made
  along the way.
- `dev/sim/README.md`: the phone simulator, test PKI, and AMI client used
  to test without phones.
- `dev/tests/README.md`: the test suites and how to run them against a
  private Asterisk instance.

Building with `--features devtest` adds `dpmadev ...` CLI commands that
the test suites use; never enable it in production builds.
