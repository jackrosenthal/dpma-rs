# Test suites

Every suite runs against a private Asterisk instance (`DPMA_SLOT`, see
`dev/tools/ast.sh`) with a devtest build of `res_dpma_rs` installed.  Most
of them install their own configuration into the instance, and several
cannot share it: `config-xml` and `methods-vm` replace
`res_digium_phone.conf`, `methods-calls` edits `pjsip.conf`, and the
simulator's test identify (`match=127.0.0.1`, which catches every SIP
request from 127.0.0.1, REGISTERs included) breaks the parking,
recording, and voicemail play checks and must not be there for
`pjsip-helpers`.  Where the simulator runs without it, the module's PJSIP
side (the original's endpoint identifier helper) identifies the simulator
by its `X-Digium-User-Agent` header.  So each
suite starts from a fresh copy of the scratch configuration:
`dev/tools/ast.sh reset-conf`.

| Suite | Setup | Run | Checks |
|---|---|---|---|
| `session` | `dev/sim/mkpki.py`, `dev/sim/install-conf.sh` | `dev/sim/scripts/session-all.sh` | Sessions, handshake, encryption, and framing with the phone simulator ([../sim/README.md](../sim/README.md)) |
| `config-xml` | `config-xml/setup.sh` | `config-xml/check.py` | The configuration, contacts, and user list documents are produced and well formed |
| `users-runtime` | `users-runtime/setup.sh` | `users-runtime/check.sh` | Tokens, lookups, presence, and `show status` |
| `methods-vm` | `methods-vm/setup.sh` | `methods-vm/run.py` | The voicemail methods |
| `methods-vm-phone` | `methods-vm/setup.sh`, `dev/sim/mkpki.py` | `methods-vm/run.py --via phone` | The voicemail methods called by the simulator (encrypted AsteriskRequests) |
| `methods-calls` | `methods-calls/setup.sh` | `methods-calls/run.py` | The queue, parking, recording, phonebook, and echo methods |
| `methods-calls-phone` | `methods-calls/setup.sh`, `dev/sim/mkpki.py` | `methods-calls/run.py --via phone` | The call methods called by the simulator (AsteriskRequests) |
| `methods-calls-http` | `methods-calls/setup.sh`, `dev/sim/mkpki.py` | `methods-calls/run.py --via http` | The call methods called by the simulator (HTTPRequests) |
| `pjsip-helpers` | (by `check.sh`) | `pjsip-helpers/check.sh`, then `stress.py 15` | The module's PJSIP side (the original's two helper modules): the endpoint identifier against the expected transcript (the original helper's), the dialog-info supplement, and line locking ([pjsip-helpers/README.md](pjsip-helpers/README.md)) |
| `request-handlers` | `dev/sim/mkpki.py`, `dev/sim/install-conf.sh`, `request-handlers/setup.sh` | `request-handlers/run.py`, then `request-handlers/users-flows.py` | Every request type in every authentication mode, FileRequest paths, AsteriskRequest and HTTPRequest, AMI-registered methods; then the phone users' runtime over real sessions (reconfigure, events, tokens, stale phones, restore after a restart) |
| `ami` | `dev/sim/mkpki.py`, `dev/sim/install-conf.sh`, `ami/setup.sh` | `ami/run.py` (`--via phone`) | DPMAMessageRegister, DPMAMessageResponse, and DPMAMessageSend byte for byte, requests forwarded to AMI, reconfigure from the CLI, AMI, and reloads |
| `apps-discovery` | `apps-discovery/setup.sh` | `apps-discovery/run.sh` (restarts the instance inside `netns.sh`'s network namespace) | DigiumControlPlayback, DigiumVoicemailPlayback, `show settings`, the mDNS responder, and unloading and loading the module |
| `raw-bytes` | `dev/sim/mkpki.py`, `dev/sim/install-conf.sh`, `raw-bytes/setup.sh` | `raw-bytes/run.py` | Latin-1 (not UTF-8) text in the configuration, from the simulator, and in AMI headers comes out byte for byte in the configuration document, the user list, file requests, events, CLI and AMI output, AstDB, and the log; the JSON (jansson) and XML (libxml2) paths fail on it as in the original |
| `ami-expiry` (not in the default list) | as `ami` | `ami/run.py --expiry` | The `ami` checks, then a forwarded request that nobody answers expires after 300 s (about six minutes in all) |

`apps-discovery` needs unprivileged user namespaces (`unshare -rn`).

`dev/tests/parity/run.py` (not part of `run-all.sh`) captures every CLI
command and AMI action that needs no connected phone, from our module and
from the original binaries in `res_digium_phone-24.0_3.6.13-x86_64/`
(local testing only), and compares them byte for byte (usage in the
script).

## Running them all

```
export DPMA_SLOT=<n> ASTERISK_INCLUDE_DIR=$PWD/dev/asterisk-24/include CARGO_INCREMENTAL=0
dev/tools/ast.sh init <n>          # once
cargo build && cargo build -p res_dpma_rs --features devtest
cargo test -p dpma-proto -p dpma-bytes -p dpma-sys
dev/tests/run-all.sh               # or: dev/tests/run-all.sh session methods-calls
```

(For another Asterisk version, see "Asterisk versions" below.)
`run-all.sh` runs the suites in the order of the table (`ami-expiry`
only when named, or with `run-all.sh all`), prints one line per suite
(`ok` or `FAIL`), and keeps each suite's
output in `$LOGDIR` (default: a new temporary directory).  For every
suite that uses the instance it stops Asterisk, resets the configuration,
runs the suite's setup, installs the build (`ast.sh install`, which also
removes any original modules from the instance), and starts Asterisk.  At the end it puts the
simulator setup back (reset, test PKI, `install-conf.sh`) and stops
Asterisk.  A full run takes about twelve minutes.

## Running one suite by hand

```
dev/tools/ast.sh stop && dev/tools/ast.sh reset-conf
dev/tests/methods-calls/setup.sh   # the suite's setup
dev/tools/ast.sh install && dev/tools/ast.sh start
python3 -I dev/tests/methods-calls/run.py
```

Back to the simulator setup afterwards:
`dev/tools/ast.sh reset-conf && python3 dev/sim/mkpki.py && dev/sim/install-conf.sh`.

## Asterisk versions

dpma-rs is built and tested against Asterisk 22, 23, and 24.  The exact
releases are pinned in `dev/tools/asterisk-versions`: one line per major
version with the release (a tarball in
`https://downloads.asterisk.org/pub/telephony/asterisk/releases/`) and the
tarball's SHA-256 checksum.  Versions are bumped by hand there; the
scripts and the CI workflow read the file.  `dev/asterisk-24` (built from
an unversioned source checkout) stays the default for `ast.sh`.

| Tool | Purpose |
|---|---|
| `dev/tools/asterisk-build.sh [-j N] [--install] <version>` | Downloads the pinned tarball into `dev/asterisk-builds/downloads/` (unless already there), checks its checksum, extracts and configures it in `dev/asterisk-builds/<release>/src` (with `dev/asterisk-24`'s configure options and BUILD_NATIVE off), and generates `buildopts.h`.  With `--install` it builds it (`make -jN`, N = the number of CPUs) and installs it into `dev/asterisk-builds/<release>/prefix`, with the samples and the scratch configuration of `dev/tools/asterisk-conf/` on top (as in `dev/asterisk-24`).  Steps already done are skipped.  `<version>` is a major version (`22`) or a release (`22.11.0`). |
| `dev/tools/asterisk-build.sh info <version>` | Prints `major=`, `version=`, `sha256=`, `src=`, and `prefix=`. |
| `dev/tools/ast.sh init <n> <version>` | Creates an instance of that version: it records the release in `dev/run/slot<n>/asterisk-version`, and every later `ast.sh` command on the instance (and so `run-all.sh`) uses that release's install.  `DPMA_AST_VERSION=<version>` does the same at `init`; on an existing instance it must agree with the recorded version.  Instances made without a version use `dev/asterisk-24`.  An instance cannot change versions: delete `dev/run/slot<n>` and run `init` again. |
| `DPMA_SLOT=<n> dev/tools/ci-job.sh <version>` | The CI job for one version (below), run locally. |
| `sudo dev/tools/ci-setup.sh` | Installs what the job needs on Ubuntu (Asterisk's build dependencies, libclang, Python with `cryptography`, and the suites' tools) and allows unprivileged user namespaces. |

The module build takes the headers from the configured source tree:

```
dev/tools/asterisk-build.sh --install 22
eval "$(dev/tools/asterisk-build.sh info 22)"
export DPMA_SLOT=<n> CARGO_INCREMENTAL=0 ASTERISK_INCLUDE_DIR=$src/include
export PJPROJECT_DIR=$src/third-party/pjproject/source
cargo build && cargo build -p res_digium_phone --features devtest
rm -rf dev/run/slot<n> && dev/tools/ast.sh init <n> 22
dev/tests/run-all.sh all
```

Build against the same version as the instance: `ast.sh install`
copies whatever `target/debug` holds.

### CI

`.github/workflows/ci.yml` runs on every push and pull request.  A first
job reads the major versions from the pin file (`asterisk-build.sh
majors`); then one job per major version, on `ubuntu-24.04`:

1. `sudo dev/tools/ci-setup.sh`, and Rust 1.99 (the MSRV) with clippy
   through `rustup`.
2. Restores `dev/asterisk-builds/<release>` (source tree and prefix) from
   the cache, keyed by the release, its checksum, the runner's OS and
   architecture, and the hash of `asterisk-build.sh` and
   `dev/tools/asterisk-conf/`.  On a miss it runs
   `asterisk-build.sh --install <major>` and saves the cache right away,
   so a failing test run does not lose the build.
3. `DPMA_SLOT=1 dev/tools/ci-job.sh <major>`: `cargo build`, both clippy
   runs (`--all-targets`, and `-p res_digium_phone --features devtest`)
   with warnings as errors, `cargo test` for the crates whose tests run
   outside Asterisk (all but the three module crates, whose test
   binaries cannot link without Asterisk), the devtest build, a fresh
   instance of the version, and `dev/tests/run-all.sh all` (every suite,
   `ami-expiry` included).
4. Uploads the suites' logs (`$LOGDIR`) as an artifact.

The job is a thin wrapper: `DPMA_SLOT=<n> dev/tools/ci-job.sh <version>`
does the same locally (it deletes and recreates `dev/run/slot<n>`).
