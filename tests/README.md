# Tests

All test tooling is Rust:

- `tests/` is the crate `dpma-tests`, the test suites and their tools
  (`cargo doc -p dpma-tests --open` documents them).
- `tools/` is the crate `xtask`, run as `cargo xtask`, and the test
  image, `tools/Containerfile`: the suites run in a container that holds
  one pinned Asterisk release.

The crates' own tests run on the host with `cargo test --workspace
--exclude res_dpma_rs` (the module's test binary cannot link outside
Asterisk).  The suites are skipped there, since they need the test
container.

You need podman or docker, and Rust.  Asterisk and its build
dependencies are in the image.

## `cargo xtask`

| Command | What it does, and why it exists |
|---|---|
| `cargo xtask test [--asterisk VERSION] [-j N] [SUITE...\|all]` | Runs suites, each in a fresh container of the release's test image (below; built first if the engine does not have it), several at a time.  This is how the suites run: they need the container's Asterisk. |
| `cargo xtask ci [--asterisk VERSION] [-j N]` | The CI job of `.github/workflows/ci.yml`, in fresh containers of the release's image.  It exists so that CI is one command that also runs locally. |
| `cargo xtask headers [--asterisk VERSION]` | Copies the configured Asterisk headers out of the release's image into `target/container/<release>/asterisk-headers` (once per image) and prints that directory.  It exists because `cargo build` on the host needs headers for bindgen (`ASTERISK_SOURCE_DIR`), and these match the images exactly. |
| `cargo xtask majors` | Prints the pinned major versions as a JSON array.  It exists for the CI matrix. |

The options:

| Option | Why it exists |
|---|---|
| `--asterisk VERSION` | Selects the release: a major version (`22`) or a release (`22.11.0`) pinned in `tools/asterisk-versions`; the default is the newest.  Each release has its own image. |
| `-j N`, `--jobs N` | How many suites run at the same time, each in its own container (default: the number of CPUs).  It exists to limit the load of parallel containers. |
| `SUITE...` or `all` (`test`) | The suites to run (below); without any, or with `all`, every suite. |

`$DPMA_ENGINE` names the container engine (a command name or path);
without it the xtask uses `podman` when it is on the `PATH`, else
`docker`.  It exists for machines that have both.  `cargo xtask
<command> --help` describes each command.  (`cargo xtask inside` is the part of
`test` and `ci` that runs in the container; it is not for direct use.)

For example:

```
cargo xtask test                     # every suite against the newest release
cargo xtask test --asterisk 22 -j 2  # every suite against Asterisk 22, two at a time
cargo xtask test session ami         # two suites
```

Runs for different releases can run at the same time.

## The test image

`tools/Containerfile` builds one image per pinned release:

| Path | What it is |
|---|---|
| `/opt/asterisk` | Asterisk, installed with `--prefix=/opt/asterisk`: the test instance.  Writable by every user, since the tests run as the host user's user ID. |
| `/opt/asterisk-conf` | The scratch configuration: the samples with `tools/asterisk-conf/` on top.  Each suite's preparation copies it into `/opt/asterisk/etc/asterisk`. |
| `/opt/asterisk-headers` | The configured headers that bindgen reads (`ASTERISK_SOURCE_DIR`). |
| `/usr/local/rustup`, `/usr/local/cargo` | Rust. |

The menuselect option BUILD_NATIVE (`-march=native`) is off, so that an
image built on one machine runs on any CPU of its architecture.

The image's tag is `dpma-rs-asterisk:<release>-<hash>`, where the hash
covers the Containerfile, the pin, and `tools/asterisk-conf/`: a change
to any of them builds a new image, and anything else reuses the one the
engine has.  Remove old images with your engine's `image prune` or
`rmi`.

## The test container

`test` and `ci` start fresh containers of the image and remove each one
when it is done:

- **Network:** `--network none`, a network namespace of its own whose
  only interface is `lo`.  The tests and Asterisk run in it together, as
  on one machine; nothing reaches a real network, and runs for different
  releases never clash.  The xtask turns multicast on for `lo`, as root
  in the container (`--cap-add NET_ADMIN`), for the mDNS checks of
  `apps-discovery`.
- **Mounts:** the repository; `target/container/<release>/` for what
  the run writes; and `target/container/cargo/` as `CARGO_HOME`, the
  crates cache that the releases share.  The container has no network,
  so the xtask fetches the crates into that cache on the host first.
- **User:** the work runs as the container user that is you: the owner
  of `target/container/<release>/` as the container sees it.  That is
  root for a rootless engine and your own user and group IDs for a
  rootful one (or for a rootless podman with `--userns=keep-id`).  So
  every file it writes into the repository and `target/` is yours.
  `--cap-drop DAC_OVERRIDE` makes root, too, respect file permissions as
  your user would (`methods-calls` checks that a read-only phonebook
  file cannot be written).
- **SELinux:** `--security-opt label=disable`, so that the container can
  use the mounts without relabeling them.

A run has two steps.  First one container (`cargo xtask inside build`)
builds the devtest module and the suites' test binaries, and makes the
test PKI.  Then every suite runs in a fresh container of its own, up to
`-j` at a time: its prebuilt binary runs directly, not through Cargo, so
that the suites do not wait on the target directory's lock.

## Asterisk versions

The Asterisk releases that dpma-rs is built and tested against are
pinned, with their tarballs' SHA-256 checksums, in
`tools/asterisk-versions`; versions are bumped by hand there.

bindgen generates the same bindings from the headers of every pinned
release.  The module carries no build options checksum, as the
official DPMA does not, so Asterisk loads it whatever its build options.

On 22.11.0 and 23.5.0, `pjsip-helpers` expects no dialog-info
supplement and "Bail.  No Channel" in the supplement's log.  Those
releases have Asterisk bug #2186 ("extstate: Include causing device
channel details in legacy callbacks"): the new extension state API of
22.11.0, 23.5.0, and 24.0.0-rc1 leaves the ringing channel out of the
extension state data, so the supplement finds none, as the official
DPMA's would.  It is fixed in 22.12.0, 23.6.0, and 24.0.0-rc2.  The
suite picks the expectation by the release number (`asterisk -V`), so
moving a pin to a fixed release brings back the full check.

## The test instance

The suites reach Asterisk only through `dpma_tests::harness::Instance`,
the install in `/opt/asterisk`.  SIP listens on 127.0.0.1:15060 (UDP
and, with the simulator setup, TCP) and AMI on 127.0.0.1:15038 (user
`test`, secret `test`); the CLI goes through the control socket.
Asterisk's console output goes to `/opt/asterisk/ast-console.log`, its
log to `/opt/asterisk/var/log/asterisk/messages.log`.

## Suites

Most suites install their own configuration into the instance, and
several cannot share it, so each suite prepares the instance itself.

| Suite | Checks |
|---|---|
| `session` | Sessions and the phone protocol, with the phone simulator |
| `config-xml` | The configuration, contacts, and user list documents |
| `users-runtime` | Tokens, lookups, presence, and auth incidents |
| `methods-vm` | The voicemail methods |
| `methods-calls` | The queue, parking, recording, phonebook, and echo methods |
| `pjsip-helpers` | The module's PJSIP side: the endpoint identifier, the dialog-info supplement, and line locking |
| `request-handlers` | Every request type in every authentication mode, and the phone users' runtime over real sessions |
| `ami` | The DPMAMessage actions, requests forwarded to AMI, and reconfigure |
| `apps-discovery` | The dialplan applications, the mDNS responder, and unloading and loading the module |
| `bytes` | Latin-1 (not UTF-8) text comes out byte for byte, except on the JSON and XML paths, which fail on it as in the official DPMA |

Each suite is the test target of its name, and keeps its output in
`target/container/<release>/logs/<suite>.log`.  Each suite's rustdoc (at
the top of its `tests/suites/<suite>/main.rs`) describes what it checks.

Timing that the official DPMA defines is tested with test-only knobs of
the devtest build (`dpmadev`) rather than by waiting.  Otherwise the
suites wait for events rather than for fixed times, except where they
check that nothing happens.

## The module for publishing

After the suites pass, `cargo xtask ci` builds the module as it is
published (without devtest), checks that it needs no newer glibc than
the minimum that `README.md` states (`GLIBC_BASELINE` in
`tools/src/ci.rs`), and smoke-tests it in the container's Asterisk.

## The simulator, the test PKI, and AMI from the command line

The binaries of dpma-tests (`cargo run -p dpma-tests --bin <name> --
--help` describes their options):

| Binary | What it does |
|---|---|
| `dpma-sim` | The phone simulator (`dpma_tests::sim`) |
| `dpma-mkpki` | Makes the test PKI and installs its trust material into an instance (`dpma_tests::mkpki`) |
| `dpma-ami` | Sends an AMI action and prints the response and the events that follow it, or listens for events (`dpma_tests::ami`) |

Everything is written from the decompile of the official DPMA,
independently of the module's crates (the simulator shares only the
RustCrypto primitive crates with them), and nothing comes from the
official DPMA's binary: all certificates and keys are generated locally
(real phones do not accept the test AppServer certificate).  The module
defaults to the official DPMA's embedded trust material, so a setup that
uses the test PKI points `phone_ca_file` and `appserver_certificate` at
it (`dpma_tests::harness::fixtures::prepare` does this for the suites).

By default the binaries talk to the test instance, so they work inside
the test container.  `dpma-sim selftest` needs no server.

The rustdoc of `dpma_tests::harness::fixtures::SIM_CONF` describes the
simulator's test configuration and its phones.

## CI

`.github/workflows/ci.yml` runs `cargo xtask ci` for each pinned major
version, natively on x86_64 and aarch64, with the test images kept in
the Actions cache.  A pushed tag `vX.Y.Z` that names the workspace
version also publishes a GitHub Release.
