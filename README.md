# dpma-rs

dpma-rs is an open-source, drop-in replacement for Digium's closed-source
Digium Phone Module for Asterisk (DPMA, `res_digium_phone`), written in
Rust.  It follows DPMA 24.0_3.6.13 for Asterisk 24: the same configuration
files, the same phone protocol, and the same CLI commands, AMI actions and
events, and dialplan applications.  Digium and Sangoma phones are meant to
work with it just as with the original, without changes on the phones.

This is version 0.1.0.  dpma-rs is an independent rewrite; it is not made
or endorsed by Digium or Sangoma.

It is one Asterisk module, `res_dpma_rs.so`, which replaces the three
modules of the original distribution:

| Original module | What `res_dpma_rs.so` does in its place |
|---|---|
| `res_digium_phone.so` | The phone module: phone configuration, sessions and encryption, phone requests, the phone methods (voicemail, queues, parking, recording, phonebook, presence), CLI commands, AMI actions and events, dialplan applications, and service discovery (mDNS). |
| `res_pjsip_endpoint_identifier_dpma.so` | PJSIP support: matches the phones' messages to the module, fills phone lines from the PJSIP configuration, records where phones register, and sends SIP INFO messages to phones during calls. |
| `res_pjsip_dialog_info_digium_body_supplement.so` | Adds the ringing caller's details to dialog-info (BLF) notifications sent to Digium and Sangoma phones. |

It is written in Rust only: there is no C code to compile.

## Installation

### Requirements

- Asterisk 22, 23, or 24 with PJSIP (`res_pjsip`, `res_pjsip_session`,
  and `res_pjsip_pubsub`), on Linux.
- x86_64 or aarch64 (64-bit ARM).
- glibc 2.34 or newer (for example, Debian 12, Ubuntu 22.04, or RHEL 9
  and newer).

### Download

Each release has one module per Asterisk major version and
architecture:

| | x86_64 | aarch64 |
|---|---|---|
| Asterisk 22 | [res_dpma_rs-asterisk22-x86_64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk22-x86_64.so) | [res_dpma_rs-asterisk22-aarch64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk22-aarch64.so) |
| Asterisk 23 | [res_dpma_rs-asterisk23-x86_64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk23-x86_64.so) | [res_dpma_rs-asterisk23-aarch64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk23-aarch64.so) |
| Asterisk 24 | [res_dpma_rs-asterisk24-x86_64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk24-x86_64.so) | [res_dpma_rs-asterisk24-aarch64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk24-aarch64.so) |

[SHA256SUMS](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/SHA256SUMS)
lists their SHA-256 checksums.  To download and check the module for
Asterisk 24 on x86_64:

```
curl -fLO https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk24-x86_64.so
curl -fLO https://github.com/jackrosenthal/dpma-rs/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

`asterisk -V` prints Asterisk's version, and `uname -m` the
architecture.

### Installing the module

1. Copy the module into Asterisk's module directory (`astmoddir` in
   `asterisk.conf`, often `/usr/lib/asterisk/modules`) as
   `res_dpma_rs.so`.  Copy it in while Asterisk is stopped, or copy and
   rename as here: writing over a loaded module crashes the running
   Asterisk.

   ```
   MODDIR=/usr/lib/asterisk/modules
   cp res_dpma_rs-asterisk24-x86_64.so $MODDIR/res_dpma_rs.so.new && mv $MODDIR/res_dpma_rs.so.new $MODDIR/res_dpma_rs.so
   ```

2. Take the original modules out: `res_dpma_rs.so` does everything the
   three original modules do, so they must not be loaded with it
   (Asterisk would load both, and both would answer the phones).  Remove
   them:

   ```
   rm -f $MODDIR/res_digium_phone.so $MODDIR/res_pjsip_endpoint_identifier_dpma.so \
       $MODDIR/res_pjsip_dialog_info_digium_body_supplement.so
   ```

   or keep the files and add `noload` lines to `modules.conf`:

   ```
   noload => res_digium_phone.so
   noload => res_pjsip_endpoint_identifier_dpma.so
   noload => res_pjsip_dialog_info_digium_body_supplement.so
   ```

3. Restart Asterisk, or load the module (`module load res_dpma_rs.so`)
   when no earlier version of it is loaded: after an upgrade, `module
   unload` and `module load` do not reliably pick up the new code of the
   module, so restart instead.

The module loads with Asterisk's usual autoloading (or a
`load => res_dpma_rs.so` line in `modules.conf`, in place of the
original's `load =>` lines).  It requires `res_pjsip`,
`res_pjsip_session`, and `res_pjsip_pubsub`, and uses
`func_presencestate`, `app_voicemail`, `res_parking`, and `app_queue`
when they are loaded.  Where you reloaded the original with
`module reload res_digium_phone.so`, use `module reload res_dpma_rs.so`.

As with the original's `res_pjsip_endpoint_identifier_dpma`, the module
needs a PJSIP endpoint named by `default_outbound_endpoint` in the
`[global]` section of `pjsip.conf` (default name
`default_outbound_endpoint`).  Without it the module fails to load, which
stops Asterisk from starting.

At run time the module links only the C runtime (`libc` and `libgcc_s`)
and uses the libxml2 that Asterisk itself loads; it does not use
OpenSSL.  To build it yourself, see "Development".

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
- PJSIP lines get their settings from `pjsip.conf`, as the original's
  `res_pjsip_endpoint_identifier_dpma` gives them.

chan_sip is not supported: no lines are read from `sip.conf` or from the
`users.conf` users with `hassip`.

As in the original, text is used as the bytes in the files, whatever
their encoding: a name in Latin-1 reaches the phones, the CLI, AMI, and
the Asterisk database unchanged.  Where the original hands text to JSON
(the user list and the phone methods' answers), text that is not UTF-8
makes the request fail as it does in the original.

## Differences from the original

dpma-rs reproduces the original's behavior, quirks included, with these
deliberate exceptions:

1. No license handling.  There is no license check and nothing to
   license: no `digium_phones license status` command and no
   `DPMALicenseStatus` AMI action.
2. When loading fails partway, everything already loaded is unloaded
   again.  The original leaves applications, thread pools, and dialplan
   contexts behind.
3. All AMI actions are unregistered when the module unloads.  The original
   leaves some registered, pointing into unloaded code.
4. `digium_phones show version` prints `dpma-rs version 0.1.0` (the
   dpma-rs version) instead of a DPMA version number.
5. No chan_sip support: no phone messages or in-call notifications
   through chan_sip, no lines from `sip.conf` or from `users.conf` users
   with `hassip`, and no warnings about `sip.conf`.  `voicemail.conf` and
   `users.conf` voicemail users are still read.
6. A saved phone session (`DigiumPhoneSessions` in the Asterisk database)
   whose stored data cannot be decrypted is deleted, and the phone
   handshakes again.  The original keeps the entry and fails on it at
   every load.
7. Service discovery (mDNS) uses a responder built into the module
   instead of Avahi, so it works without `avahi-daemon` or the Avahi
   libraries.  It announces the same `_digiumproxy._udp` service, with
   these small differences: the service's host name is
   `<hostname>-dpma.local` (Avahi uses `<hostname>.local`), and a service
   name that collides with another is renamed `name (2)` (Avahi:
   `name #2`).  A service name that is not valid UTF-8 is not announced;
   an error is logged instead.  Discovery is on unless
   `service_discovery_enabled=no`.
8. Authentication incidents from IPv6 phones are tracked per address.  The
   original cuts the address at its first colon, so all IPv6 phones share
   one incident record.  IPv4 behavior is unchanged.
9. Starting a call recording from a phone reports success when the
   recording starts.  The original always reports an error (and never
   sends the "recording started" notification) although the recording
   runs.
10. "Session Timeout" replies go back over the transport the request came
    in on.  The original sends them over UDP even to phones using TCP.
11. Handshake certificates whose line breaks were lost in transit are
    repaired before they are read.  Asterisk 24 strips trailing line
    breaks from each SIP MESSAGE body, which can break a certificate that
    a phone splits across messages.
12. Phone requests forwarded to AMI clients (methods registered with
    `DPMAMessageRegister`) expire after 300 seconds without a
    `DPMAMessageResponse`, with the log message "No response to request
    (...), expired."  The original never expires them.
13. File requests from phones cannot leave `file_directory`: names with
    a `..` component are answered as if the file did not exist.  With
    `..`, the original serves any file the Asterisk process can read.
    Other names are served as by the original, files in subdirectories
    included; absolute names are looked up inside `file_directory`.
14. `digium_phones show line` shows the line's `authname` as `AuthName`,
    and `digium_phones show application` shows a queue application's
    `logout_exten` as `Logout Extension` and a status application's
    `send486=yes` as `Send486: Yes`.  The original shows the secondary
    server port, the login extension, and "No" there.
15. One module, `res_dpma_rs.so`, takes the place of the original's three
    (`res_digium_phone.so`, `res_pjsip_endpoint_identifier_dpma.so`, and
    `res_pjsip_dialog_info_digium_body_supplement.so`; see "Installing").
    So `module show`, `module load`, `module unload`, `module reload`, and
    `core set debug` name `res_dpma_rs` (whose debug level also governs
    the debug messages that the PJSIP helpers logged under their own
    names), and `config list` shows `res_dpma_rs` as the module that
    loaded `res_digium_phone.conf` (so `config reload` of that file
    reloads `res_dpma_rs`).  The module's use count does not include the
    helper modules that use the original.
16. No C API for other modules.  The original exports functions
    (`dpma_config_*`, `dpma_register_*_handler`, `phone_users_*`,
    `phone_utils_*`, and others) that its helper modules use; dpma-rs
    has no helper modules and exports none, so the original's helpers
    cannot be used with it.
17. Phone certificates are read and verified as by the original's
    built-in OpenSSL 1.1.1t, with the same checks and log messages,
    except for these, which the original's built-in CA certificates (RSA
    keys, SHA-1 and SHA-256 signatures) do not call for: certificates
    signed with algorithms other than RSA PKCS#1 v1.5 with MD5, SHA-1, or
    SHA-2 (for example, ECDSA or RSASSA-PSS) fail with "certificate
    signature failure"; a phone certificate with an RFC 3779 IP address or
    AS number extension fails with "Unsupported extension feature"; and an
    encrypted PEM block is unreadable (the original asks for a pass
    phrase on Asterisk's terminal or standard input).  The OpenSSL error
    that "Unable to read client cert" and the decryption failure messages
    show is the error of that failure; the original's can be an error left
    over from an earlier handshake on the same thread.  (dpma-rs used to
    log OpenSSL 3's error texts, which differ from the original's 1.1.1t
    texts.)

Beyond these, a number of inputs that crash the original modules (for
example, PJSIP AOR changes while a phone line has no PJSIP endpoint, or an
INFO on a channel that has just hung up) are handled instead.

## Development

dpma-rs is Rust throughout, its test tooling included:

- `crates/`: the module (`res_dpma_rs`) and its libraries.
- `tests/`: the crate `dpma-tests`, with the phone simulator
  (`dpma-sim`), the test PKI (`dpma-mkpki`), an AMI client
  (`dpma-ami`), the other test clients, the harness, and the test
  suites (`cargo doc -p dpma-tests --open` documents them).
- `tools/`: the crate `xtask`, run as `cargo xtask`, and the test image
  (`tools/Containerfile`).  Every suite runs in a container (podman or
  docker) that holds one pinned Asterisk release
  (`tools/asterisk-versions`), with the test configuration of
  `tools/asterisk-conf/`.  The xtask also is the CI job of
  `.github/workflows/ci.yml`, which runs the same way locally.

`tests/README.md` describes the tooling.

### Building from source

You need:

- Rust 1.99 or a newer stable toolchain, with Cargo.
- libclang (from LLVM/Clang; dpma-rs is developed with libclang 18): the
  build reads the Asterisk and pjproject headers with `bindgen`, which
  uses it.  If it is not found, set `LIBCLANG_PATH` to the directory
  that holds `libclang.so`.
- The configured headers of the Asterisk you build for (22, 23, or 24),
  in `ASTERISK_SOURCE_DIR`: its `include/` (with `autoconfig.h` from
  configure and `buildopts.h`) and the bundled pjproject's include
  directories (`third-party/pjproject/source/*/include`, with
  `pj/config_site.h`).  Either
  - `cargo xtask headers [--asterisk VERSION]` (podman or docker
    needed) copies them out of the test image of a pinned release
    (default: the newest) and prints their directory, or
  - use the source tree of the Asterisk you run, configured with the
    bundled pjproject (`./configure --with-pjproject-bundled`) and with
    `include/asterisk/buildopts.h` made (`make
    include/asterisk/buildopts.h`, or a full `make`).

Then:

```
export ASTERISK_SOURCE_DIR=$(cargo xtask headers --asterisk 24)
cargo build --release
```

The module is built as `target/release/libres_dpma_rs.so`; install it
as in "Installation".  The module carries no build options checksum (as
the original does not), so Asterisk loads it whatever its own build
options; build it with the headers of the major version you run.

Building with `--features devtest` adds `dpmadev ...` CLI commands that
the test suites use (`cargo xtask test` builds it); never enable it in
production builds.

### Testing

The crates' own tests run on the host; the suites run in the test
container:

```
cargo test --workspace --exclude res_dpma_rs
cargo xtask test                          # the default suites, newest Asterisk
cargo xtask test --asterisk 22 all        # every suite against Asterisk 22
cargo xtask ci --asterisk 23              # the CI job for Asterisk 23
```

### Releases

CI runs `cargo xtask ci` for every pinned major version on x86_64 and
aarch64; each job builds the module as it is published
(`res_dpma_rs-asterisk<major>-<arch>.so`, a release build without
devtest), checks its glibc baseline, and smoke-tests it in Asterisk.
Pushing a tag `vX.Y.Z` that names the workspace version (`version` in
`Cargo.toml`) publishes the GitHub Release of that tag with the six
modules, `SHA256SUMS`, and `LICENSE`, once every job has passed.
