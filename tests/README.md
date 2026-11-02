# Tests

All test tooling is Rust:

- `tests/` is the crate `dpma-tests`: the phone simulator, the test PKI,
  an AMI client, a SIP user agent, an mDNS browser, the harness, and the
  test suites (`cargo doc -p dpma-tests --open` documents them).
- `tools/` is the crate `xtask`, run as `cargo xtask`, and the test
  image, `tools/Containerfile`: the suites run in a container that holds
  one pinned Asterisk release.  The xtask builds the image, runs the
  suites in a fresh container of it, and is the CI job.

The crates' own tests run on the host with `cargo test --workspace
--exclude res_dpma_rs` (the module's test binary cannot link outside
Asterisk).  They include the simulator's self-test against a throwaway
PKI; the suites are skipped there, since they need the test container.

You need podman or docker (either one, as you have configured it) and
Rust.  Nothing else of Asterisk's is installed on the host: Asterisk,
its build dependencies, Rust 1.99 with clippy, and libclang are in the
image.

## `cargo xtask`

| Command | What it does, and why it exists |
|---|---|
| `cargo xtask test [--asterisk VERSION] [--original DIR] [SUITE...\|all]` | Runs suites in a fresh container of the release's test image (below; built first if the engine does not have it).  This is how the suites run: they need the container's Asterisk. |
| `cargo xtask ci [--asterisk VERSION]` | The CI job of `.github/workflows/ci.yml`, in a fresh container of the release's image: `cargo build`, both clippy runs (`--all-targets`, and `-p res_dpma_rs --features devtest`) with warnings as errors, `cargo test --workspace --exclude res_dpma_rs`, every suite (`all`), and the module for publishing (below).  It exists so that CI is one command that also runs locally. |
| `cargo xtask headers [--asterisk VERSION]` | Copies the configured Asterisk headers out of the release's image into `target/container/<release>/asterisk-headers` (once per image) and prints that directory.  It exists because `cargo build` on the host needs headers for bindgen (`ASTERISK_SOURCE_DIR`), and these match the images exactly. |
| `cargo xtask majors` | Prints the pinned major versions as a JSON array.  It exists for the CI matrix. |

The options:

| Option | Why it exists |
|---|---|
| `--asterisk VERSION` | Selects the release: a major version (`22`) or a release (`22.11.0`) pinned in `tools/asterisk-versions`; the default is the newest.  Each release has its own image. |
| `--original DIR` (`test`) | The original binaries (`res_digium_phone.so` and its two PJSIP helpers, 24.0_3.6.13), which `parity` compares with and which are not distributed with dpma-rs.  `DIR` is mounted read-only into the container. |
| `SUITE...` or `all` (`test`) | The suites to run (below); without any, the default suites. |

`$DPMA_ENGINE` names the container engine (a command name or path);
without it the xtask uses `podman` when it is on the `PATH`, else
`docker`.  It exists for machines that have both (the CI workflow sets
it to `docker`, whose image cache it keeps).  `cargo xtask <command>
--help` describes each command.  (`cargo xtask inside` is the part of
`test` and `ci` that runs in the container; it is not for direct use.)

For example:

```
cargo xtask test                     # the default suites against the newest release
cargo xtask test --asterisk 22 all   # every suite against Asterisk 22
cargo xtask test session ami         # two suites
cargo xtask test --asterisk 24 --original ../res_digium_phone-24.0_3.6.13-x86_64 parity
```

Runs for different releases can run at the same time.

## The test image

`tools/Containerfile` builds one image per pinned release, from
`ubuntu:24.04`, with the release and its checksum as build arguments:

| Path | What it is |
|---|---|
| `/opt/asterisk` | Asterisk, downloaded (the SHA-256 checksum of the pin is verified), configured, built, and installed with `--prefix=/opt/asterisk`: the test instance.  Writable by every user, since the tests run as the host user's user ID. |
| `/opt/asterisk-conf` | The scratch configuration: the samples with `tools/asterisk-conf/` and a few edits on top (RTP ports 21000 to 21100, the mailbox `bob101` in `voicemail.conf`, and `asterisk.conf`'s `[directories]` made active).  Each suite's preparation copies it into `/opt/asterisk/etc/asterisk`. |
| `/opt/asterisk-headers` | The configured headers that bindgen reads (`ASTERISK_SOURCE_DIR`): `include/` with `autoconfig.h` and `buildopts.h`, and the bundled pjproject's include directories with `pj/config_site.h`. |
| `/usr/local/rustup`, `/usr/local/cargo` | Rust 1.99 with clippy (and libclang for bindgen, from Ubuntu). |

The configure options are `--with-pjproject-bundled
--with-jansson-bundled=no --without-pwlib --disable-xmldoc`, with the
menuselect option BUILD_NATIVE (`-march=native`) off, so that an image
built on one machine runs on any CPU of its architecture.  The source
tree and the debugging information are removed, which keeps the image
small.  Everything in the image is architecture-neutral: it builds
natively on x86_64 and aarch64.

The image's tag is `dpma-rs-asterisk:<release>-<hash>`, where the hash
covers the Containerfile, the pin, and `tools/asterisk-conf/`: a change
to any of them builds a new image, and anything else reuses the one the
engine has.  The first build takes a few minutes (most of it Asterisk's
`make`); remove old images with your engine's `image prune` or `rmi`.

## The test container

`test` and `ci` start a fresh container of the image and remove it
afterwards:

- **Network:** `--network none`, a network namespace of its own whose
  only interface is `lo`.  The tests and Asterisk run in it together, so
  SIP Contact and Via addresses, AMI, and mDNS work as on one machine,
  nothing reaches a real network, and runs for different releases never
  clash.  The xtask turns multicast on for `lo` and routes 224.0.0.0/4
  through it, as root in the container (`--cap-add NET_ADMIN`), for the
  mDNS checks of `apps-discovery`.
- **Mounts:** the repository; `target/container/<release>/` for the
  Cargo target directory (`target/`), the suites' logs (`logs/`), the
  test PKI (`pki/`), and in CI the module for publishing;
  `target/container/cargo/` as `CARGO_HOME`, the crates cache that the
  releases share; and `--original DIR`, read-only.  The container has no
  network, so the xtask fetches the crates into that cache on the host
  first (`cargo fetch --locked`).
- **User:** the work runs as the container user that the engine maps to
  your user (from `/proc/self/uid_map` in the container): root for a
  rootless engine, your own user and group IDs for a rootful one.  So
  every file it writes into the repository and `target/` is yours.
  `--cap-drop DAC_OVERRIDE` makes root, too, respect file permissions as
  your user would (`methods-calls` checks that a read-only phonebook
  file cannot be written).
- **SELinux:** `--security-opt label=disable`, so that the container can
  use the mounts without relabeling them.

Inside, `cargo xtask inside test` builds the devtest module (`cargo
build -p res_dpma_rs --features devtest`) and the suites' test binaries
with `ASTERISK_SOURCE_DIR` set to the image's headers, then runs the
suites one after another (each suite's preparation installs the module
into the container's Asterisk).

## Asterisk versions

dpma-rs is built and tested against Asterisk 22, 23, and 24.  The exact
releases are pinned in `tools/asterisk-versions`: one line per major
version with the release (a tarball in
`https://downloads.asterisk.org/pub/telephony/asterisk/releases/`) and
the tarball's SHA-256 checksum.  Versions are bumped by hand there; the
xtask, the Containerfile (through the xtask), and the CI workflow read
the file.

bindgen generates the same bindings from the headers of all three
pinned releases.  The module carries no build options checksum, as the
original does not, so Asterisk loads it whatever its build options.

On 22.11.0 and 23.5.0, `pjsip-helpers` expects no dialog-info
supplement and "Bail.  No Channel" in the supplement's log.  Those
releases have Asterisk bug #2186 ("extstate: Include causing device
channel details in legacy callbacks"): the new extension state API of
22.11.0, 23.5.0, and 24.0.0-rc1 leaves the ringing channel out of the
extension state data, so the supplement finds none, as the original's
would.  It is fixed in 22.12.0, 23.6.0, and 24.0.0-rc2.  The suite picks
the expectation by the release number (`core show version`), so moving
a pin to a fixed release brings back the full check.

## The test instance

The suites reach Asterisk only through `dpma_tests::harness::Instance`:
the install in `/opt/asterisk`, with its own configuration, AstDB,
spool, logs, and module directory.  SIP listens on 127.0.0.1:15060 (UDP
and, with the simulator setup, TCP) and AMI on 127.0.0.1:15038 (user
`test`, secret `test`); the CLI goes through the control socket.
Asterisk's console output goes to `/opt/asterisk/ast-console.log`, its
log to `/opt/asterisk/var/log/asterisk/messages.log`.

## Suites

Most suites install their own configuration into the instance, and
several cannot share it: `config-xml` and `methods-vm` replace
`res_digium_phone.conf`, `methods-calls` edits `pjsip.conf`, and the
simulator's test identify (`match=127.0.0.1`, which catches every SIP
request from 127.0.0.1, REGISTERs included) breaks the parking,
recording, and voicemail play checks and must not be there for
`pjsip-helpers`.  Where the simulator runs without it, the module's PJSIP
side (the original's endpoint identifier helper) identifies the simulator
by its `X-Digium-User-Agent` header.  So each suite prepares the instance
itself: it stops Asterisk, resets the configuration, installs its own
setup and the debug build, and starts Asterisk.

| Suite | Test target and options | Checks |
|---|---|---|
| `session` | `session` | Sessions, handshake, encryption, and framing with the phone simulator |
| `config-xml` | `config-xml` | The configuration, contacts, and user list documents are produced and well formed |
| `users-runtime` | `users-runtime` | Tokens, lookups, presence, and `show status` |
| `methods-vm` | `methods-vm` | The voicemail methods |
| `methods-vm-phone` | `methods-vm --via phone` | The voicemail methods called by the simulator (encrypted AsteriskRequests) |
| `methods-calls` | `methods-calls` | The queue, parking, recording, phonebook, and echo methods |
| `methods-calls-phone` | `methods-calls --via phone` | The call methods called by the simulator (AsteriskRequests) |
| `methods-calls-http` | `methods-calls --via http` | The call methods called by the simulator (HTTPRequests) |
| `pjsip-helpers` | `pjsip-helpers` | The module's PJSIP side (the original's two helper modules): the endpoint identifier against the expected transcript (the original helper's), the dialog-info supplement, and line locking |
| `request-handlers` | `request-handlers` | Every request type in every authentication mode, FileRequest paths, AsteriskRequest and HTTPRequest, AMI-registered methods; then the phone users' runtime over real sessions (reconfigure, events, tokens, stale phones, restore after a restart) |
| `ami` | `ami` | DPMAMessageRegister, DPMAMessageResponse, and DPMAMessageSend byte for byte, requests forwarded to AMI, reconfigure from the CLI, AMI, and reloads |
| `apps-discovery` | `apps-discovery` | DigiumControlPlayback, DigiumVoicemailPlayback, `show settings`, the mDNS responder (on the container's `lo`), and unloading and loading the module |
| `raw-bytes` | `raw-bytes` | Latin-1 (not UTF-8) text in the configuration, from the simulator, and in AMI headers comes out byte for byte in the configuration document, the user list, file requests, events, CLI and AMI output, AstDB, and the log; the JSON (jansson) and XML (libxml2) paths fail on it as in the original |
| `ami-expiry` (only in `all`) | `ami --expiry` | The `ami` checks, then a forwarded request that nobody answers expires after 300 s (about six minutes in all) |
| `parity` (only when named) | `parity --original /original` | Every CLI command and AMI action that needs no connected phone, from our module and from the original binaries (`--original DIR`; Asterisk 24 only; local testing only), compared byte for byte |

`cargo xtask test` runs the suites in the order of the table (without a
suite name: all of them up to `raw-bytes`; `all` adds `ami-expiry`;
`parity` only when named), each as `cargo test -p dpma-tests --test
<target> -- --ignored [OPTIONS]`.  It prints one line per suite (`ok` or
`FAIL`, with its time in seconds; a suite whose test target does not
exist fails without running) and keeps each suite's output in
`target/container/<release>/logs/<suite>.log`, which each run replaces.
The exit status is 0 when every suite passed (2 for an unknown suite
name).  Each suite's rustdoc (at the top of its
`tests/suites/<suite>/main.rs`) describes what it checks, its arguments,
and what it needs.

## The module for publishing

After the suites pass, `cargo xtask ci` builds the module as it is
published (`cargo build --release -p res_dpma_rs`, without devtest) in
the same container and:

1. checks that it needs no newer glibc symbol version than the baseline,
   GLIBC_2.34 (`GLIBC_BASELINE` in `tools/src/ci.rs`, from `objdump -T`),
   the minimum glibc that `README.md` states;
2. smoke-tests it: loaded into the container's Asterisk with the scratch
   configuration, `module show like res_dpma_rs` lists it and
   `digium_phones show version` answers with the dpma-rs version;
3. copies it to
   `target/container/<release>/res_dpma_rs-asterisk<major>-<arch>.so`
   (`<arch>`: `x86_64` or `aarch64`).

## The simulator, the test PKI, and AMI from the command line

dpma-tests has three binaries (`cargo run -p dpma-tests --bin <name> --
--help` describes their options):

| Binary | What it does |
|---|---|
| `dpma-sim` | The phone simulator: SIP MESSAGE over UDP or TCP, handshake (legacy and chain forms), encryption, chunking, every request type, events, and a self-test (`dpma_tests::sim`) |
| `dpma-mkpki` | Makes the test PKI in `dev/sim/pki` (`$DPMA_PKI`; existing files are kept, `--force` regenerates them) and installs its trust material into an instance (`--instance DIR`, default the test instance): `root-ca.pem` as `etc/asterisk/dpma/phone_ca.pem` and `appserver.pem` as `etc/asterisk/dpma/appserver.pem`.  `--check` verifies every certificate with `openssl verify` (`dpma_tests::mkpki`). |
| `dpma-ami` | Sends an AMI action and prints the response and the events that follow it, or listens for events (`dpma_tests::ami`) |

Everything is written from the decompile of the original module,
independently of the module's crates, and nothing comes from the
original binary: all certificates and keys are generated locally (real
phones do not accept the test AppServer certificate).  The module
defaults to the original's embedded trust material, so a setup that
uses the test PKI points `phone_ca_file` and `appserver_certificate` at
it (`dpma_tests::harness::fixtures::prepare` does this for the suites).

By default the binaries talk to the test instance's ports (SIP
127.0.0.1:15060, AMI 127.0.0.1:15038), so they work inside the test
container; `--server`, `--sip-port`, `--host`, and `--port` point them
elsewhere.  `dpma-sim selftest` needs no server.

The simulator's test configuration provides the test phones `simphone`
(MAC `000fd3000001`, the simulator's default; pin 1234; line 1001) and
`simphone2` (MAC `000fd3000002`; pin 5678; line 1002); the scratch
configuration's global pin is 344486.  The rustdoc of
`dpma_tests::harness::fixtures::SIM_CONF` describes the configuration,
that of `dpma_tests::mkpki` the PKI and the handshake bundles, and that
of `dpma_tests::sim` the protocol details the simulator implements.

## CI

`.github/workflows/ci.yml` runs on every push and pull request.  A first
job reads the major versions from the pin file (`cargo xtask majors`);
then one job per major version and architecture: x86_64 on
`ubuntu-24.04` and aarch64 on `ubuntu-24.04-arm`, natively, without
emulation.  Each job:

1. installs Rust 1.99, which runs only the xtask (the runner needs no
   Asterisk build dependencies);
2. restores the test image from the Actions cache, as a `docker save`
   archive keyed by the major version, the architecture, and the hash of
   what the image's tag covers (`tools/Containerfile`,
   `tools/asterisk-conf/`, `tools/asterisk-versions`, and
   `tools/src/container.rs`, which computes the tag), and loads it with
   `docker load`.  The xtask then finds the image's tag and does not
   build it.  On a miss the xtask builds the image, and the job saves it
   (`docker save`) even when the tests fail, so the next run reuses it.
   A cached image saves the several minutes of Asterisk's build per job;
3. runs `cargo xtask ci --asterisk <major>` with `DPMA_ENGINE=docker`;
4. uploads the suites' logs (always) and the module for publishing
   (`res_dpma_rs-asterisk<major>-<arch>.so`) as workflow artifacts.

A pushed tag `vX.Y.Z` runs the same matrix and then, only when every
job passed, a release job (the only one with `contents: write`): it
fails unless the tag names the workspace version (`version` in
`Cargo.toml`), and otherwise creates the GitHub Release of the tag with
the `gh` CLI, with the six modules and their `SHA256SUMS` attached.
Pushes and pull requests without a tag publish nothing.

The job runs the same way locally: `cargo xtask ci --asterisk
<version>`.
