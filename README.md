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
