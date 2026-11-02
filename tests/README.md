# Tests

All test tooling is Rust:

- `tests/` is the crate `dpma-tests`: the phone simulator, the test PKI,
  an AMI client, a SIP user agent, an mDNS browser, the harness, and the
  test suites (`cargo doc -p dpma-tests --open` documents them).
- `tools/` is the crate `xtask`, run as `cargo xtask`: it builds the
  pinned Asterisk releases, manages private Asterisk instances, runs the
  suites, and is the CI job.

The crates' own tests run with `cargo test --workspace --exclude
res_dpma_rs` (the module's test binary cannot link outside Asterisk).
They include the simulator's self-test against a throwaway PKI; the
suites are skipped there, since they need a private instance.

## `cargo xtask`

| Command | What it does |
|---|---|
| `cargo xtask asterisk build [-j N] [--install] <VERSION>` | Downloads the pinned tarball (unless already downloaded), checks its SHA-256 checksum, extracts and configures it in `<builds>/<release>/src`, and generates the headers a module build needs: the tree is then ready for `ASTERISK_SOURCE_DIR`.  With `--install` it also builds it (`make -jN`, N defaults to the number of CPUs) and installs it into `<builds>/<release>/prefix`, with the sample configuration and the scratch configuration of `tools/asterisk-conf/` on top.  Steps already done are skipped. |
| `cargo xtask asterisk info <VERSION>` | Prints `major=`, `version=`, `sha256=`, `src=`, and `prefix=` lines. |
| `cargo xtask asterisk majors` | Prints the pinned major versions as a JSON array (the CI matrix). |
| `cargo xtask instance init [N] [VERSION]` | Creates the private instance of slot N (default `$DPMA_SLOT`) for a release (default `$DPMA_AST_VERSION`, else the newest pinned release). |
| `cargo xtask instance install [debug\|release]` | Copies `target/<profile>/libres_dpma_rs.so` into the instance as `res_dpma_rs.so` (by rename, so a running Asterisk is not hurt; restart it to use the build) and removes the original `res_digium_phone.so` and its two PJSIP helpers. |
| `cargo xtask instance start` | (Re)starts Asterisk and waits until it is fully booted. |
| `cargo xtask instance stop` | Stops Asterisk and waits until it has exited. |
| `cargo xtask instance cli <COMMAND...>` | Runs a CLI command through the control socket and prints its output exactly as `asterisk -rx` does. |
| `cargo xtask instance reset-conf` | Replaces the instance's configuration with a fresh copy of the scratch configuration (test setups and trust material are gone afterwards). |
| `cargo xtask instance sim-setup [--remove]` | Installs the simulator setup: the test PKI's trust material (the PKI is made in `dev/sim/pki` if needed) and the simulator's test configuration, included from `pjsip.conf`, `extensions.conf`, and `res_digium_phone.conf`.  `--remove` takes the configuration out again.  Reload or restart Asterisk afterwards. |
| `cargo xtask instance info` | Prints the instance's directories, install and release, logs, and ports. |
| `cargo xtask test [SUITE...\|all]` | Builds the devtest module and runs suites against the instance (below). |
| `cargo xtask ci setup` | Prepares an Ubuntu machine for the CI job (as root, through `sudo` when needed; below). |
| `cargo xtask ci job <VERSION>` | The CI job for one release (below), run locally. |

A `VERSION` is a major version (`22`) or a release (`22.11.0`) pinned in
`tools/asterisk-versions`.  `cargo xtask <command> --help` describes
each command.

## Asterisk versions

dpma-rs is built and tested against Asterisk 22, 23, and 24.  The exact
releases are pinned in `tools/asterisk-versions`: one line per major
version with the release (a tarball in
`https://downloads.asterisk.org/pub/telephony/asterisk/releases/`) and the
tarball's SHA-256 checksum.  Versions are bumped by hand there; the xtask
and the CI workflow read the file.

Builds go under `$DPMA_AST_BUILDS`, default `dev/asterisk-builds`:
`downloads/` (the tarballs, and the bundled pjproject and the sounds
packages that Asterisk's own build downloads and checks),
`<release>/src` (the configured source tree), and `<release>/prefix`
(the installation).  Each step leaves a stamp (`src/.dpma-extracted`,
`src/.dpma-configured`, and `prefix/.dpma-installed`), so that a step
already done is skipped and a changed configuration starts over from a
fresh source tree.  The configure options are
`--with-pjproject-bundled --with-jansson-bundled=no --without-pwlib
--disable-xmldoc`, with the menuselect option BUILD_NATIVE
(`-march=native`) off so that a build cached on one CI runner also runs
on another.  A build needs Asterisk's build dependencies (`cargo xtask
ci setup` installs them on Ubuntu), `curl`, and `tar`; it takes about
a minute and a half with 16 CPUs, downloads included.

The module build takes the headers from a configured source tree
(`ASTERISK_SOURCE_DIR`); bindgen generates the same bindings from the
headers of all three pinned releases.  Build against the instance's
release: `instance install` copies whatever `target/debug` holds, and
Asterisk declines a module whose build options (`buildopts.h`) differ
from its own.

On 22.11.0 and 23.5.0, `pjsip-helpers` expects no dialog-info
supplement and "Bail.  No Channel" in the supplement's log.  Those
releases have Asterisk bug #2186 ("extstate: Include causing device
channel details in legacy callbacks"): the new extension state API of
22.11.0, 23.5.0, and 24.0.0-rc1 leaves the ringing channel out of the
extension state data, so the supplement finds none, as the original's
would.  It is fixed in 22.12.0, 23.6.0, and 24.0.0-rc2.  The suite picks
the expectation by the release number (`core show version`), so moving
a pin to a fixed release brings back the full check.

## Instances

Every suite runs against a private Asterisk instance, `dev/run/slot<N>`
(N from 1 to 50, `$DPMA_SLOT`), with a devtest build of `res_dpma_rs`
installed.  An instance has its own configuration, AstDB, spool, logs,
and module directory, and runs the binaries and libraries of its
release's install.  SIP listens on 127.0.0.1:15060+100·N (UDP and, with
the simulator setup, TCP) and AMI on 127.0.0.1:15038+100·N (user
`test`, secret `test`).  Asterisk's console output goes to
`dev/run/slot<N>/ast-console.log`, its log to
`dev/run/slot<N>/var/log/asterisk/messages.log`.

`init` copies the install's configuration and points it at the
instance: the directories of `asterisk.conf`, the SIP and AMI ports,
and `noload => pbx_dundi.so`.  Unix socket paths are limited to 108
bytes, so when the instance directory is longer than 70 bytes the
control socket goes into a short run directory,
`$TMPDIR/dpma-slot<N>-<uid>` or `/tmp/dpma-slot<N>-<uid>`, which
`reset-conf` keeps.

An instance records its release in `dev/run/slot<N>/asterisk-version`
and always runs that release.  `$DPMA_AST_VERSION`, when set, names the
release of a new instance and must agree with that of an existing one.
To switch releases, delete the instance and create it again:

```
cargo xtask instance stop
rm -rf dev/run/slot<n>
cargo xtask instance init <n> 22
```

`$DPMA_AST_HOME` names an install directory directly (binaries,
libraries, and the master configuration) and wins over the recorded
release, for an Asterisk that is not pinned.  There is no shared
instance: every command needs a slot.

The suites reach instances only through `dpma_tests::harness::Instance`,
which uses the same instance manager as `cargo xtask instance`
(`dpma_tests::asterisk`); the CLI goes through the control socket.

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
| `apps-discovery` | `apps-discovery` | DigiumControlPlayback, DigiumVoicemailPlayback, `show settings`, the mDNS responder (inside a private network namespace), and unloading and loading the module |
| `raw-bytes` | `raw-bytes` | Latin-1 (not UTF-8) text in the configuration, from the simulator, and in AMI headers comes out byte for byte in the configuration document, the user list, file requests, events, CLI and AMI output, AstDB, and the log; the JSON (jansson) and XML (libxml2) paths fail on it as in the original |
| `ami-expiry` (only in `all`) | `ami --expiry` | The `ami` checks, then a forwarded request that nobody answers expires after 300 s (about six minutes in all) |
| `parity` (only when named) | `parity` | Every CLI command and AMI action that needs no connected phone, from our module and from the original binaries in `res_digium_phone-24.0_3.6.13-x86_64/` (local testing only), compared byte for byte |

`apps-discovery` needs unprivileged user namespaces (`unshare -rn`).

### Running them all

```
export DPMA_SLOT=<n> CARGO_INCREMENTAL=0
eval "$(cargo xtask asterisk info 24)"   # src= and prefix= of the release
export ASTERISK_SOURCE_DIR=$src
cargo xtask asterisk build --install 24  # once (skipped when done)
cargo xtask instance init <n> 24         # once
cargo build && cargo test --workspace --exclude res_dpma_rs
cargo xtask test                         # or: cargo xtask test all, cargo xtask test session ami
```

`cargo xtask test` builds the devtest module (`cargo build -p
res_dpma_rs --features devtest`) and the suites' test binaries, then
runs the suites in the order of the table (without a suite name: all of
them up to `raw-bytes`; `all` adds `ami-expiry`; `parity` only when
named).  It prints one line per suite (`ok` or `FAIL`, with its time in
seconds) and keeps each suite's output in `$LOGDIR/<suite>.log`
(default `$LOGDIR`: a new directory `$TMPDIR/dpma-tests.XXXXXX`, printed
at the end).  At the end it stops Asterisk and puts the simulator setup
back (fresh configuration, test PKI, and the simulator's test
configuration).  The exit status is 0 when every suite passed (2 for an
unknown suite name).

### Running one suite by hand

A suite is a test target (`harness = false`) that runs only with
`--ignored`:

```
cargo build -p res_dpma_rs --features devtest
cargo test -p dpma-tests --test methods-calls -- --ignored --via http
```

| Argument | Meaning |
|---|---|
| `PART...` | Run only the parts whose name contains it (`--exact`: equals it) |
| `--list` | List the parts |
| `--no-prepare` | Do not prepare the instance (it already is) |
| `-v`, `--verbose` | Print details of passing checks and the simulator's diagnostics |

A suite prints each check, then a summary with the check counts per
part, and exits nonzero when a check failed.  Each suite's rustdoc (at
the top of its `tests/suites/<suite>/main.rs`) describes what it checks
and what it needs.  Back to the simulator setup afterwards:

```
cargo xtask instance reset-conf && cargo xtask instance sim-setup && cargo xtask instance start
```

## The simulator, the test PKI, and AMI from the command line

dpma-tests has three binaries (`cargo run -p dpma-tests --bin <name> --
--help` describes their options):

| Binary | What it does |
|---|---|
| `dpma-sim` | The phone simulator: SIP MESSAGE over UDP or TCP, handshake (legacy and chain forms), encryption, chunking, every request type, events, and a self-test (`dpma_tests::sim`) |
| `dpma-mkpki` | Makes the test PKI in `dev/sim/pki` (`$DPMA_PKI`; existing files are kept, `--force` regenerates them) and installs its trust material into the instance: `root-ca.pem` as `etc/asterisk/dpma/phone_ca.pem` and `appserver.pem` as `etc/asterisk/dpma/appserver.pem`, the defaults of `phone_ca_file` and `appserver_certificate`.  `--check` verifies every certificate with `openssl verify` (`dpma_tests::mkpki`). |
| `dpma-ami` | Sends an AMI action and prints the response and the events that follow it, or listens for events (`dpma_tests::ami`) |

Everything is written from the decompile of the original module,
independently of the module's crates, and nothing comes from the
original binary: all certificates and keys are generated locally (real
phones do not accept the test AppServer certificate).

For example, against the instance of `$DPMA_SLOT`:

```
cargo xtask instance sim-setup && cargo xtask instance install && cargo xtask instance start
alias dpma-sim='cargo run -q -p dpma-tests --bin dpma-sim --'
dpma-sim selftest                         # no server needed
dpma-sim handshake                        # chain form
dpma-sim token --user simphone --config-pass 344486
dpma-sim --state s.json token --user simphone --config-pass 344486
dpma-sim --state s.json config            # reuses session, token, and port
cargo run -q -p dpma-tests --bin dpma-ami -- DPMAShowPhones
```

The simulator's test configuration provides the test phones `simphone`
(MAC `000fd3000001`, the simulator's default; pin 1234; line 1001) and
`simphone2` (MAC `000fd3000002`; pin 5678; line 1002); the scratch
configuration's global pin is 344486.  The rustdoc of
`dpma_tests::harness::fixtures::SIM_CONF` describes the configuration,
that of `dpma_tests::mkpki` the PKI and the handshake bundles, and that
of `dpma_tests::sim` the protocol details the simulator implements.

## CI

`.github/workflows/ci.yml` runs on every push and pull request.  A first
job reads the major versions from the pin file (`cargo xtask asterisk
majors`); then one job per major version, on `ubuntu-24.04`, with
`DPMA_SLOT=1` and `LOGDIR=test-logs`:

1. Rust 1.99 (the MSRV) with clippy through `rustup`, then `cargo xtask
   ci setup`: Asterisk's build dependencies, `pkg-config` and the
   OpenSSL headers, libclang for bindgen, and the suites' tools
   (`openssl`, `iproute2`, `util-linux`, `binutils`) through `apt-get`;
   and `kernel.apparmor_restrict_unprivileged_userns=0`, since Ubuntu
   23.10 and later restrict the unprivileged user namespaces that
   `apps-discovery` needs.
2. Restores `dev/asterisk-builds/<release>` (source tree and prefix) from
   the cache, keyed by the release, its checksum, the runner's OS and
   architecture, and the hash of `tools/src/` and `tools/asterisk-conf/`.
   On a miss it runs `cargo xtask asterisk build --install <major>` and
   saves the cache right away, so a failing test run does not lose the
   build.
3. `cargo xtask ci job <major>`: the Asterisk build (a no-op when
   installed), `cargo build` with `ASTERISK_SOURCE_DIR` set to the
   release's source tree, both clippy runs (`--all-targets`, and `-p
   res_dpma_rs --features devtest`) with warnings as errors, `cargo test
   --workspace --exclude res_dpma_rs`, the devtest build, a fresh
   instance of the release (an existing `dev/run/slot<n>` is deleted
   first), and `cargo xtask test all` (every suite, `ami-expiry`
   included).
4. Uploads the suites' logs (`$LOGDIR`) as an artifact.

The job runs the same way locally: `DPMA_SLOT=<n> cargo xtask ci job
<version>` (after `cargo xtask ci setup` on Ubuntu; building the xtask
itself needs Rust and a C linker).
