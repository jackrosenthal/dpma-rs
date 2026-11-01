# DPMA phone simulator and test harness

Tools for testing res_digium_phone without Digium phones
(dev/notes/port-plan.md, sections 6.3 and 6.4):

| File | Purpose |
|---|---|
| `dpma_sim.py` | The phone simulator: SIP MESSAGE over UDP or TCP, handshake, encryption, chunking, every request type, events, scripts, self-test.  Python 3 with `cryptography` 42 or later (tested with 50). |
| `ami.py` | AMI client: send an action, print the response and events; also a Python class used by the simulator's scripts. |
| `mkpki.py` | Generates the test PKI and installs the trust material into an instance. |
| `install-conf.sh` | Installs the test configuration (`conf/`) into an instance. |
| `conf/` | Test-only pjsip, dialplan, and phone configuration snippets. |
| `scripts/` | Simulator scripts: `loopback.sim` (works without the module); for the session layer (package P7) `session.sim`, `session-chunks.sim`, `session-output.sim`, `session-prune.sim`, `session-reassembly.py`, `session-restart.sh` (restarts Asterisk), and `session-all.sh`, which runs them all over UDP and TCP. |
| `vectors.json` | Deterministic crypto and framing vectors for cross-checking `dpma-proto` (its `tests/sim_vectors.rs` checks them; `selftest` checks the simulator against dpma-proto's `tests/fixtures/proto_vectors.json`). |

Everything is written from the decompile (the phone side of
`phone_message.c`, `phone_crypto.c`, and `phone_request.c`), independently
of the Rust code.  Nothing comes from the original binary: all certificates
and keys are generated locally.

## Setting up an instance

```
export DPMA_SLOT=<n>                 # your private instance (dev/tools/ast.sh)
python3 dev/sim/mkpki.py             # test PKI; installs phone_ca.pem and appserver.pem
python3 dev/sim/mkpki.py --check     # verify every certificate with openssl
dev/sim/install-conf.sh              # pjsip, dialplan, and phone test configuration
dev/tools/ast.sh start               # (or restart; or reload res_pjsip and the dialplan)
python3 dev/sim/dpma_sim.py selftest # no server needed
```

`mkpki.py` writes keys and certificates to `dev/sim/pki/` (not committed;
rerun it in a new workspace) and copies `root-ca.pem` to
`<instance>/etc/asterisk/dpma/phone_ca.pem` and `appserver.pem` to
`<instance>/etc/asterisk/dpma/appserver.pem`, the defaults of
`phone_ca_file` and `appserver_certificate`.  Existing files are kept;
`--force` regenerates them.

The PKI:

| Entity | Issuer | Notes |
|---|---|---|
| `root-ca` | itself | The module's `phone_ca_file`. |
| `intermediate-ca` | root-ca | Serial number 4097 (logged by the module as "Intermediate cert serial number"). |
| `phone` | intermediate-ca | Chain form phone certificate. |
| `legacy` | root-ca | Legacy form phone certificate. |
| `phone-expired`, `legacy-expired` | intermediate-ca, root-ca | Valid 2001 to 2002. |
| `rogue-ca`, `rogue` | itself, rogue-ca | Not trusted by the module. |
| `weak` | root-ca | 512-bit RSA, SHA-1 signature (made with the `openssl` command). |
| `appserver-ca`, `appserver` | itself, appserver-ca | The module's `appserver_certificate`; the simulator checks the HandshakeResponse body against `appserver-ca`. |

Handshake bundles (`pki/bundles.json`; `--bundle NAME`):

| Bundle | Body | Module's expected answer |
|---|---|---|
| `legacy` | legacy | HandshakeResponse |
| `chain` | legacy, intermediate-ca, phone | HandshakeResponse with `Handshake-Version: 1` |
| `chain-expired`, `legacy-expired` | as above, expired | accepted (OpenSSL errors 9 and 10 are ignored) |
| `weak` | weak | accepted (512-bit keys and SHA-1 must work) |
| `rogue` | rogue | no reply; auth incident |
| `two`, `four` | 2 or 4 certificates | no reply ("Expected two certificates in the chain, found 1/3") |

The common password is always encrypted to the key of the last certificate
of the body; the bundle's key decrypts it.

### Test configuration (`install-conf.sh`)

Adds `#include` lines to the instance's `pjsip.conf`, `extensions.conf`,
and `res_digium_phone.conf` (`--remove` takes them out):

- `pjsip_dpma_sim.conf`: a TCP transport on the instance's SIP port; the
  endpoint `dpma-sim` with `message_context=dpma_pjsip_message_context`,
  identified by `match=127.0.0.1` (the test-only stand-in for the endpoint
  identifier helper, section 6.3); and `dpma-sim-loopback`, identified by
  `match=127.0.0.2`, whose messages go to a static test context.  With the
  endpoint identifier helper loaded, the simulator's MESSAGEs (which carry
  `X-Digium-User-Agent`) are identified by the helper instead, and the
  `dpma-sim` identify is not needed; remove the include when testing other
  PJSIP clients: it matches every request from 127.0.0.1, REGISTERs
  included.  The loopback path needs `--no-digium-ua-header` while the
  helper is loaded.
- `extensions_dpma_sim.conf`: `[dpma-sim-loopback]` logs every MESSAGE
  from 127.0.0.2 with its AppServer headers and answers Echo the way the
  module's `handle_request_echo` does (no module needed); `[dpma-sim-send]`
  sends an unencrypted `digium.config.update` event to a listening
  simulator: `ast.sh cli "channel originate Local/<port>@dpma-sim-send
  application Wait 1"`.
- `res_digium_phone_sim.conf`: the standard test phones.

| Phone | MAC (`--mac`) | Pin | Line |
|---|---|---|---|
| `simphone` | `000fd3000001` (the simulator's default) | 1234 | 1001 (PJSIP endpoint 1001, secret `secret1001`) |
| `simphone2` | `000fd3000002` | 5678 | 1002 (secret `secret1002`) |

The scratch configuration's `[general]` has `globalpin=344486`,
`config_auth=mac_globalpin`, and `userlist_auth=disabled`; change them in
your instance for the other authentication modes.

## Using the simulator

```
dpma_sim.py [global options] COMMAND [command options]
```

The simulator sends to `sip:proxy@<server>:<port>` (what real phones use as
`config_server_url`) from one socket, and answers every MESSAGE it receives
with 200 OK.  The server replies to the address the request came from
(`PJSIP_RECVADDR`), so replies arrive on the same socket; over TCP they come
back on the same connection.  In TCP mode the simulator also listens for
UDP on its port, as phones do: the original server sends its "Session
Timeout" reply (MAC or contact mismatch, `phone_msg_send_timeout`) to the
bare Response-URI, without `;transport=tcp`, so it arrives over UDP.
dpma-rs sends it over TCP (port plan section 8, item 11); the `transport`
condition tells the two apart.

Global options (before the command):

| Option | Default | Meaning |
|---|---|---|
| `--slot N` | `$DPMA_SLOT` | SIP port 15060+100N, AMI port 15038+100N |
| `--server`, `--sip-port` | 127.0.0.1, from the slot | Asterisk |
| `--local-host`, `--local-port` | 127.0.0.1, any | The simulator's socket.  `--local-host 127.0.0.2` selects the loopback test path. |
| `--transport udp\|tcp` | udp | |
| `--mac` | `000fd3000001` | `X-Digium-AppServer-MACAddress` (colons removed) |
| `--user-agent` | `Digium D65 2_9_17` | Sent as `User-Agent` and `X-Digium-User-Agent`; an empty one sends neither |
| `--no-digium-ua-header` | off | Do not send `X-Digium-User-Agent`.  The PJSIP helper (res_pjsip_endpoint_identifier_dpma) gives every request with that header its own endpoint, whose context is `pjsip_message_context`; use this option for the loopback path while the helper is loaded. |
| `--contact` | `sip:<mac>@<host>:<port>` | The Contact URI (the session is bound to it) |
| `--origination-network` | none | Sends `X-Origination-Network` |
| `--form legacy\|chain`, `--bundle` | chain | Handshake certificates |
| `--pki DIR` | `dev/sim/pki` | |
| `--no-appserver-check` | | Do not fail the handshake when the AppServer certificate does not verify against the test AppServer CA (for example, against a server using the original certificate) |
| `--no-auto-handshake` | | Commands that need a session handshake first unless this is given |
| `--state FILE` | | Keep the session (id, common password, token, local port) across invocations |
| `--chunk-size N` | 600 (UDP), 900 (TCP) | Maximum body bytes per MESSAGE (per request: `--chunk-size` after the command) |
| `--chunk-style split\|stream` | split | Encrypted chunking (see below) |
| `--chunk-delay MS` | 5 | Pause between chunks |
| `--plain` | | Send requests unencrypted even with a session |
| `--timeout S` | 5 | Reply timeout (per request: `--timeout` after the command) |
| `-v`, `-vv` | | SIP summary, full SIP messages |

Commands:

| Command | Sends |
|---|---|
| `handshake [--bundle B]` | `Handshake` with the bundle's certificates; recovers the common password with the bundle's key; checks the AppServer certificate |
| `ping` | `PingRequest` |
| `echo [BODY]` | `Echo` (never encrypted, no session) |
| `token [--user U] [--pin P] [--config-pass C]` | `TokenRequest` with `Username`, `Password`, and `ConfigPassword` (encrypted); keeps the returned `Config-Token` |
| `config [--token T]` | `ConfigRequest` with the `Config-Token` (default: the last token) |
| `verify [--token T]` | `VerifyRequest` |
| `userlist [--config-pass C]` | `UserlistRequest` |
| `file NAME` | `FileRequest`, body `file://NAME` (`default`, `null`, or a file) |
| `asterisk --auth USER:SECRET (--method M [--params P] [--format json\|xml] \| --json DOC \| --xml DOC \| --body TEXT) [--type HTTPRequest]` | `AsteriskRequest`: the line `X-Digium-AppServer-Digest-Auth=USER:SECRET`, then the request document |
| `raw TYPE [--body TEXT\|@FILE] [--encrypt auto\|yes\|no] [--session S] [--mac M] [--contact URI] [--username/--password/--config-password/--config-token V] [--id ID]` | Anything, for negative tests (`Preconfig`, unknown types, wrong session, MAC, or contact) |
| `listen [--seconds S] [--count N] [--event NAME]` | Nothing; prints incoming messages |
| `script FILE\|-` | Runs a script |
| `selftest [--vectors]` | Nothing; crypto, framing, PKI, and an in-process protocol round trip |

Request commands also take `--header 'Name: Value'`, `--timeout`,
`--chunk-size`, `--no-wait`, and `--pem-cuts` (plaintext chunks end right
before and right after every PEM BEGIN and END line, line break included,
so the server loses exactly those line breaks; for example, `handshake
--pem-cuts`).  Exit status: 0 when the expected response
type arrives without an error (`raw`: any reply), 1 otherwise, 2 on setup
errors.

Examples:

```
dpma_sim.py handshake                       # chain form
dpma_sim.py --form legacy -v ping           # handshake, then an encrypted ping
dpma_sim.py token --user simphone --config-pass 344486
dpma_sim.py --state /tmp/s.json token --user simphone --config-pass 344486
dpma_sim.py --state /tmp/s.json config      # reuses session, token, and port
dpma_sim.py asterisk --auth simphone:1234 --method test.dpma.api.echo --params '{"x": 1}'
dpma_sim.py --local-port 15599 listen       # events (e.g., reconfigure)
dpma_sim.py --local-host 127.0.0.2 --no-digium-ua-header echo hi  # loopback: no module needed
```

Output: `>>` describes what was sent (type, transaction id, chunks,
encryption, SIP status of each chunk), `<<` the reply: its `X-` headers,
decrypted fields, problems, and body.  The body shown is the payload: for
events and error replies the server's `Command: ` prefix is removed from
every chunk.

## Scripts

One command per line; `#` starts a comment line; words use shell quoting;
`${NAME}` expands variables.  Any command above works (with its options),
plus:

| Line | Meaning |
|---|---|
| `try COMMAND` | Run without failing on the outcome; check it with `expect` |
| `expect COND...` | Check the last reply (or the last `listen` message) |
| `wait-reply [--timeout S]` | Wait for the reply to the last `--no-wait` request |
| `set NAME=VALUE`, `capture NAME SOURCE [REGEX]` | Variables; SOURCE as in conditions (`body`, `payload`, `header:N`, `field:N`, `ami:KEY`, or a variable); REGEX keeps its first group |
| `sleep S`, `print TEXT` | |
| `forget` | Drop the session (as a phone reboot would) |
| `ami ACTION [Key=Value...]` | AMI action (list actions collect their events) |
| `ami-event NAME [Key=Value\|Key~Regex...] [--timeout S]` | Wait for an AMI event (events are collected from the first AMI command on) |
| `cli WORDS...` | CLI command through AMI `Command` |
| `expect-ami COND...` | Check the last AMI response or event: `Key=V`, `Key~RE`, `Key!=V`, `Key?`, `Key!`; repeated keys (`Output`, list events) are joined with newlines |

Conditions are `KEY=VALUE`, `KEY!=VALUE`, `KEY~REGEX`, `KEY?` (present), or
`KEY!` (absent):

| Key | Value |
|---|---|
| `reply` | `yes` or `none` |
| `type` | Response type (else request type, event name) |
| `event` | `X-Event-Name` |
| `error` | `X-Digium-AppServer-Error-ID`, or `none` |
| `body`, `payload` | Decrypted body; payload without the `Command: ` prefixes |
| `header:NAME` | A header of the first chunk; `X-Digium-AppServer-` may be omitted |
| `field:NAME` | A decrypted header (`Password`, `Config-Token`) |
| `chunks` | Number of chunks of the reply |
| `transport` | Transport(s) the reply's chunks arrived on: `udp`, `tcp`, or `tcp,udp` |
| `encrypted` | `yes` or `no` |
| `appserver` | `ok`, `fail`, or `none` (handshake) |
| `status` | SIP status of every chunk sent (`status=202`) |
| `session` | `set` or `none` (the simulator's state) |
| `problems` | Decoding problems, or `none` |

Variables: `session`, `token`, `mac`, `contact`, `transport` (the
simulator's, `udp` or `tcp`), `id` (last transaction id), `body`, `payload`, `error`, `type`, `ami.KEY` (last AMI message),
`env.NAME`, and anything set with `set` or `capture`.

A script stops at the first failing line (`--keep-going` runs to the end)
and exits 1.  Example, for an AMI-registered method (package P13):

```
ami DPMAMessageRegister Method=com.example.hello
asterisk --auth simphone:1234 --method com.example.hello --params '{"a": 1}' --no-wait
ami-event DPMAMessage Method=com.example.hello --timeout 10
capture rid ami:RequestID
ami DPMAMessageResponse RequestID=${rid} Format=json 'Response={"hello": 1}'
wait-reply
expect type=AsteriskResponse body~hello
```

## Python

```
import sys; sys.path.insert(0, "dev/sim")
from dpma_sim import Phone, Options
with Phone(Options(slot=5, form="legacy")) as phone:
    ex = phone.handshake()
    assert ex.ok, ex.describe()
    ex = phone.get_token(user="simphone", config_password="344486")
    ex = phone.config()
    print(ex.reply.body.decode())
    ev = phone.next_event(timeout=30, name="digium.config.update")
```

`Phone.request(type, body, encrypt=, session=, username=, password=,
config_password=, config_token=, headers=, wait=, timeout=, chunk_size=,
chunk_style=, txid=, mac=, contact=)` is the general form; it returns an
`Exchange` (`.ok`, `.sip_statuses`, `.reply`), and a reply is a `Reply`
(`.type`, `.error`, `.body`, `.payload`, `.fields`, `.header(name)`,
`.parts`).  `ami.AmiClient` is the AMI side (`action`, `command`,
`wait_event`).

Bodies are bytes.  Header values (and the user agent, origination
network, user name, and passwords) are text in which bytes that are not
UTF-8 are lone surrogates (Python's `surrogateescape`), both ways: send
`b"Jos\xe9".decode("utf-8", "surrogateescape")` to put the Latin-1 bytes
on the wire, and encode a received value the same way to get its bytes
back.  `ami.py` treats AMI text the same way.

## AMI helper

```
DPMA_SLOT=5 dev/sim/ami.py DPMAShowPhones
dev/sim/ami.py --slot 5 Command Command="digium_phones show sessions"
dev/sim/ami.py --slot 5 --wait-event DPMAMessage --events 60 DPMAMessageRegister Method=m
dev/sim/ami.py --slot 5 --listen 30
```

Logs in as test/test.  For list actions it waits for `EventList:
Complete`; otherwise it prints the events of the next `--events` seconds
(default 1).  Exit status 0 when the response is `Success`.

## Protocol details the simulator implements

Phone to server:

- Every chunk carries `RequestType`, `ID` (a counter starting at a random
  value, so a restarted simulator does not collide with an incomplete
  transaction the server keeps for 40 s under `"<ID>-<MAC>"`), `MACAddress`,
  `Session` (except Handshake, Echo, and Preconfig), `Message-Sequence`
  (0, 1, ...), and on the last `Message-Finished: 1`; `Content-Type:
  text/plain` always (res_pjsip_messaging refuses a MESSAGE without it,
  even with an empty body).
- After the handshake everything but Echo is encrypted: a new 8-byte salt
  per request (`Message-Salt`, 16 uppercase hex digits); key and IV from
  `EVP_BytesToKey(aes-128-cbc, SHA-1, salt, common password, 1)`;
  `Password`, `ConfigPassword`, and `Config-Token` each encrypted as their
  own CBC stream with that key and IV.
- Encrypted bodies (`--chunk-style split`, the default): the whole body is
  encrypted and base64 encoded, and the text is split into chunks.  The
  server concatenates the chunk bodies and decodes them once with
  `ast_base64decode`, which stops at the first `=`, so this is the form it
  can reassemble.  `--chunk-style stream` sends the way the server itself
  sends (one CBC stream, each chunk's ciphertext base64 encoded on its own);
  the server cannot reassemble that whenever a non-final chunk's ciphertext
  length is not a multiple of 3.
- Plaintext chunks never end in CR or LF (except the last, and with
  `--pem-cuts`): res_pjsip_messaging strips trailing CR/LF from every
  MESSAGE body, so a line break at a chunk boundary would be lost.  It also keeps at most 1023
  bytes of a body, so keep `--chunk-size` at or below 1022 bytes of wire body.

Server to phone:

- Chunks are grouped by transaction id, salt, and type (events carry no
  `X-Digium-AppServer-ID`), ordered by `Message-Sequence`, and complete when
  the chunk with `Message-Finished` is in and none is missing, or at once
  when a chunk has no sequence (a single-chunk HandshakeResponse).
- Encrypted replies: each chunk's body is base64 decoded on its own, the
  ciphertexts are concatenated and decrypted as one stream, and `Password`
  and `Config-Token` are decrypted with the same salt.
- HandshakeResponse: unencrypted; `X-Digium-AppServer-Password` is the
  40-byte common password, RSA PKCS#1 v1.5 encrypted to the phone key; the
  body is the AppServer certificate.
- Events and error replies have `Command: ` at the start of every chunk's
  plaintext (inside the encryption); `payload` removes them.

## Session layer acceptance (package P7)

With a devtest build installed and running in the instance (the scripts
use `dpmadev session ...` to change flags, backdate activity, and send
events):

```
DPMA_SLOT=<n> dev/sim/scripts/session-all.sh
```

| Script | Checks |
|---|---|
| `session.sim` | Handshake in both forms and the rejected bundles, handshakes whose chunks end at PEM BEGIN and END lines, encrypted Ping, Echo, a multi-chunk request, unknown session (-398 HandshakeResponse), MAC and contact mismatch (Session Timeout, over the simulator's transport), an unencrypted AsteriskRequest dropped, the CLI and AMI, a module reload, pruning the old session on a new handshake |
| `session-chunks.sim` | Multi-chunk requests (encrypted and plaintext) and replies (an encrypted 2000-byte event, `digium.assignment.update`, the HandshakeResponse); `EVENT_CHUNKS` is 5 over UDP, 3 over TCP |
| `session-output.sim` | `digium_phones show sessions` and `DPMAShowPhones` field by field, with each flag |
| `session-prune.sim` | Idle pruning: unauthenticated sessions after 119 s, authenticated but inactive ones after 59 s, never authenticated active ones |
| `session-reassembly.py` | Incoming chunks out of order, transactions keyed by ID and MAC, incomplete transactions dropped after 40 s (takes about 50 s) |
| `session-restart.sh` | AstDB persistence across two Asterisk restarts (restored authenticated and inactive, same common password, expiry at 59 s), an undecryptable entry dropped, `DPMAShowPhones` user details, and the `message_delay` pause |

## Self-test

`dpma_sim.py selftest` needs no server: known-answer key, IV, and
ciphertext (checked against OpenSSL's `EVP_BytesToKey` through ctypes and
`openssl enc`), stream encryption, header fields, `set_hex` and
`ast_base64decode` quirks, both directions of framing (the server side
emulated from `phone_msg_outgoing_send` and `incoming_check_finalize`), the
CR/LF rule, RSA common passwords with every bundle key, the AppServer
check, an in-process protocol round trip over UDP sockets (both handshake
forms, encrypted requests and replies in many chunks, tokens, events,
unknown session, rejected certificate), `vectors.json`, and dpma-proto's
`crates/dpma-proto/tests/fixtures/proto_vectors.json` (key and IV, header
fields, `set_hex`, `ast_base64decode`, chunking, both directions of
encrypted framing, the RSA common password, and error bodies).
`selftest --vectors` prints the vectors.
