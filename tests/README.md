# Test suites

Every suite but `exports` runs against a private Asterisk instance
(`DPMA_SLOT`, see `dev/tools/ast.sh`) with a devtest build installed.  Most
of them install their own configuration into the instance, and several
cannot share it: `config-xml` and `methods-vm` replace
`res_digium_phone.conf`, `methods-calls` edits `pjsip.conf`, and the
simulator's test identify (`match=127.0.0.1`, which catches every SIP
request from 127.0.0.1) breaks the parking and recording checks of
`methods-calls` and must not be there for `pjsip-helpers`.  So each suite
starts from a fresh copy of the scratch configuration: `dev/tools/ast.sh
reset-conf`.

| Suite | Setup | Run | Checks |
|---|---|---|---|
| `exports` | none (no instance) | `dev/tests/exports/run.sh` | The exported C API against the original binary |
| `session` | `dev/sim/mkpki.py`, `dev/sim/install-conf.sh` | `dev/sim/scripts/session-all.sh` | Sessions, handshake, encryption, and framing with the phone simulator ([../sim/README.md](../sim/README.md)) |
| `config-xml` | `config-xml/setup.sh` | `config-xml/check.py` | The configuration, contacts, and user list documents are produced and well formed |
| `users-runtime` | `users-runtime/setup.sh` | `users-runtime/check.sh` | Tokens, lookups, presence, and `show status` |
| `methods-vm` | `methods-vm/setup.sh` | `methods-vm/run.py` | The voicemail methods |
| `methods-calls` | `methods-calls/setup.sh` | `methods-calls/run.py` | The queue, parking, recording, phonebook, and echo methods |
| `pjsip-helpers` | (by `compare.sh`) | `pjsip-helpers/compare.sh`, then `stress.py 15` | The endpoint identifier helper against the original, the dialog-info supplement, and line locking ([pjsip-helpers/README.md](pjsip-helpers/README.md)) |

`exports` and `pjsip-helpers` load the original binaries from
`res_digium_phone-24.0_3.6.13-x86_64/` (local testing only).

## Running them all

```
export DPMA_SLOT=<n> ASTERISK_INCLUDE_DIR=$PWD/dev/asterisk-24/include CARGO_INCREMENTAL=0
dev/tools/ast.sh init <n>          # once
cargo build && cargo build -p res_digium_phone --features devtest
cargo test -p dpma-proto
dev/tests/run-all.sh               # or: dev/tests/run-all.sh session methods-calls
```

`run-all.sh` runs the suites in the order of the table, prints one line
per suite, and keeps each suite's output in `$LOGDIR` (default: a new
temporary directory).  For every suite that uses the instance it stops
Asterisk, resets the configuration, runs the suite's setup, installs the
build (`ast.sh install`, which also installs the PJSIP helpers), and
starts Asterisk.  At the end it puts the simulator setup back (reset,
test PKI, `install-conf.sh`) and stops Asterisk.  A full run takes about
seven minutes.

## Running one suite by hand

```
dev/tools/ast.sh stop && dev/tools/ast.sh reset-conf
dev/tests/methods-calls/setup.sh   # the suite's setup
dev/tools/ast.sh install && dev/tools/ast.sh start
python3 -I dev/tests/methods-calls/run.py
```

Back to the simulator setup afterwards:
`dev/tools/ast.sh reset-conf && python3 dev/sim/mkpki.py && dev/sim/install-conf.sh`.
