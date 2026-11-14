# dpma-rs

dpma-rs is an open-source, drop-in replacement for Digium's closed-source
Digium Phone Module for Asterisk (DPMA, `res_digium_phone`), written in
Rust.  Existing configurations and phones work with it unchanged.

It also fixes several bugs and security issues in the official DPMA, e.g.,
phone file requests that can read any file on the server, and inputs
that crash Asterisk.

dpma-rs is an independent rewrite, not made or endorsed by Digium or
Sangoma.

## Installation

### Pre-built modules

The pre-built modules are for Asterisk 22, 23, and 24 on Linux, on x86_64
and aarch64, with glibc 2.34 or newer (e.g., Debian 12, Ubuntu 22.04, or
RHEL 9).  For anything else, see "Building".

| | x86_64 | aarch64 |
|---|---|---|
| Asterisk 22 | [res_dpma_rs-asterisk22-x86_64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk22-x86_64.so) | [res_dpma_rs-asterisk22-aarch64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk22-aarch64.so) |
| Asterisk 23 | [res_dpma_rs-asterisk23-x86_64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk23-x86_64.so) | [res_dpma_rs-asterisk23-aarch64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk23-aarch64.so) |
| Asterisk 24 | [res_dpma_rs-asterisk24-x86_64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk24-x86_64.so) | [res_dpma_rs-asterisk24-aarch64.so](https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk24-aarch64.so) |

To download and verify, e.g., for Asterisk 24 on x86_64:

```
curl -fLO https://github.com/jackrosenthal/dpma-rs/releases/latest/download/res_dpma_rs-asterisk24-x86_64.so
curl -fLO https://github.com/jackrosenthal/dpma-rs/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

### Installing the module

1. Copy the module into Asterisk's module directory (`astmoddir` in
   `asterisk.conf`) as `res_dpma_rs.so`.
2. If you had the official DPMA already installed, remove or `noload` its
   three modules: `res_digium_phone.so`,
   `res_pjsip_endpoint_identifier_dpma.so`, and
   `res_pjsip_dialog_info_digium_body_supplement.so`.
3. Restart Asterisk.

The module needs `res_pjsip`, `res_pjsip_session`, and `res_pjsip_pubsub`.
As with the official DPMA, `pjsip.conf` also needs the endpoint named by
`default_outbound_endpoint` in its `[global]` section; without it the
module fails to load, and Asterisk does not start.

## Configuration

Configure it as the official DPMA, in `res_digium_phone.conf`; the
official DPMA's documentation and sample configuration apply.

### Additions for Open DPhone

Phones that run the Open DPhone firmware take a few settings that the
stock firmware does not have.  A phone section (`type=phone`) can set
them; each is sent only when it is set, so a phone without them gets
none of them.  The stock firmware ignores them.

| Option | Meaning |
|---|---|
| `dphone_ssh_enabled=yes\|no` | Whether the phone's SSH server runs.  The phone's own default is no. |
| `dphone_ignore_provisioned_firmware=yes\|no` | With yes, the phone does not load the firmware this configuration offers it (for development).  The phone's own default is no. |
| `dphone_metrics_enabled=yes\|no` | Whether the phone serves `/metrics`.  The phone's own default is yes. |
| `dphone_ssh_authorized_key=<public key>` | An SSH public key that may log in to the phone, as a line of an `authorized_keys` file without options: `ssh-ed25519 AAAA... name`.  Repeat it for more keys.  A value that is not a public key is refused and reported like any invalid option. |

The phone's web configuration is the official DPMA's `web_ui_enabled`
phone option.  The phone's own default is yes, but as the official DPMA
does, the module sends this setting to every phone, as off unless the
option is set to yes; so set `web_ui_enabled=yes` for a phone that is to
have web configuration.

For example:

```
[phone101]
type=phone
dphone_ssh_enabled=yes
dphone_ssh_authorized_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa alice@laptop
```

adds this to the phone's configuration:

```xml
<setting id="dphone_ssh_enabled" value="1" />
<dphone_ssh_authorized_keys>
<key id="1" value="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa alice@laptop" />
</dphone_ssh_authorized_keys>
```

A phone keeps the keys the server gives it apart from the keys added on
the phone, and drops them when the server no longer sends them.

The module also states the checksum of each firmware file it can read.
Open DPhone decides whether to load offered firmware by checksum, not by
version, and with the checksum in the configuration it need not fetch the
start of the file to find out.  A `<firmware>` entry gets the attribute

```
checksum="<kernel CRC>-<kernel bytes>-<rootfs CRC>-<rootfs bytes>"
```

(the CRCs as eight lowercase hexadecimal digits, the sizes in decimal;
e.g., `checksum="297347df-1961984-69ddc1bc-30000456"`) when its file is a
firmware image found on the server: a firmware section's `file` in
`file_directory`, or a firmware package's file in
`firmware_package_directory`.  The file must be named plainly, not by a
URL or an absolute path, and what the network's `file_url_prefix` serves
under that name must be that file.  Any other entry, and every
`<public_firmware>` entry, is as the official DPMA writes it; a phone
without the attribute reads the checksum from the file's header.

### Differences from the official DPMA

Two things that the official DPMA gets wrong for the stock firmware are
done differently:

- A ConfigResponse and a VerifyResponse state the MD5 of the phone's
  configuration document in `X-Digium-AppServer-MD5`.  A phone keeps the
  value with the configuration it downloaded, and at its next start
  downloads again only when the VerifyResponse states another value.  The
  official DPMA never sends the header, so a phone downloads its
  configuration at every start.
- The `locale` setting is sent only for a phone with an `active_locale`.
  The official DPMA sends it with an empty value otherwise, on which the
  stock firmware's boot configuration fails (and logs "Initializing
  bootconfig language: fetched-config.xml does not exist").

## Development

- `crates/`: the module (`res_dpma_rs`) and its libraries.
- `tests/`: the test suites and their tools; see `tests/README.md`.
- `tools/`: `cargo xtask`, and the test image for each pinned Asterisk
  release.

### Building

You need Rust 1.99 or newer, libclang, and the configured headers of the
Asterisk version you build for, in `ASTERISK_SOURCE_DIR`.  `cargo xtask
headers` copies them out of a test image (podman or docker needed).

```
export ASTERISK_SOURCE_DIR=$(cargo xtask headers --asterisk 24)
cargo build --release
```

The module is `target/release/libres_dpma_rs.so`.  Never enable the
`devtest` feature in production; it adds CLI commands for the test suites.

### Testing

```
cargo test --workspace --exclude res_dpma_rs
cargo xtask test [--asterisk 22] [all]
cargo xtask ci --asterisk 23
```

The suites run in containers (podman or docker).  `cargo xtask ci` is
what each CI job runs.

### Releases

CI runs `cargo xtask ci` for each pinned Asterisk major version on x86_64
and aarch64.  Pushing a tag `vX.Y.Z` matching the workspace version
publishes a GitHub Release.
