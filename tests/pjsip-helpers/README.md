# Tests for the PJSIP side (the original's two helper modules)

res_dpma_rs does what the original distribution's two PJSIP helper
modules do, `res_pjsip_endpoint_identifier_dpma` and
`res_pjsip_dialog_info_digium_body_supplement` (`crates/res_dpma_rs/src/pjsip/`).
These tests check that side of the module.

| File | Purpose |
|---|---|
| `setup.sh` | Installs `conf/` into a private instance (`#include` lines; `--remove` undoes it) and enables HTTP for ARI on 127.0.0.1:15088+100*slot. |
| `conf/` | PJSIP endpoints 2001 to 2003, phones and lines 2001 to 2005, the test dialplan, memory wizards for ARI push configuration, and an ARI user. |
| `scenario.py` | `identifier` and `dialog-info` scenarios; prints a normalized transcript. |
| `check.sh` | Runs `identifier` and compares the transcript with `expected-identifier.txt`, then runs `dialog-info` and checks the supplemented NOTIFYs. |
| `expected-identifier.txt` | The expected `identifier` transcript (see below). |
| `stress.py` | Line locking stress test (observer threads versus readers and reloads). |
| `sipua.py` | Minimal SIP UA: REGISTER, MESSAGE, a UAS that rings or answers and prints INFOs, and a dialog SUBSCRIBE that prints NOTIFY bodies. |

## Running

```
export ASTERISK_SOURCE_DIR=$PWD/dev/asterisk-24-src CARGO_INCREMENTAL=0
cargo build && cargo build -p res_dpma_rs --features devtest
export DPMA_SLOT=19
dev/tests/pjsip-helpers/check.sh /some/dir       # about 2 minutes
dev/tools/ast.sh install && dev/tools/ast.sh start
dev/tests/pjsip-helpers/stress.py 15             # PASS / FAIL
dev/tools/ast.sh stop
```

`check.sh` stops Asterisk at the end; the instance keeps the test
configuration (`setup.sh --remove` takes it out).

## The expected transcript

Until package P19 merged the helpers into the module, this suite ran the
identifier scenario with the ORIGINAL `res_pjsip_endpoint_identifier_dpma.so`
(loaded against dpma-rs's res_digium_phone through its exported C API)
and with dpma-rs's own helper, and diffed the two transcripts: they were
identical up to the last step, where the original crashes Asterisk.
`expected-identifier.txt` is the transcript of the merged module
(2026-11-01, slot 19).  It is the original helper's transcript of that
time except for what the merge changes by design: one module
(`res_dpma_rs.so`) where there were three, so the `module show`, `module
unload`, and `module load` steps name one module and its use count is 0
(the original res_digium_phone's was 4: two dependent helpers and two
handler references); the `dpmadev pjsip ...` test commands (formerly
`dpmadev exports ...`) print `pjsip_auth (object)` and `phone` where they
printed the exported functions' names; and the last step, which the
original does not survive.  Logs, line settings, last URIs, INFO
requests, and MESSAGE routing are byte for byte the same.

The dialog-info transcript depends on timing (an intermediate NOTIFY may
or may not be sent), so `check.sh` only checks that the supplement adds
the restricted caller to the Digium subscriber's NOTIFY and never to the
other subscriber's.

## What the identifier scenario covers

- Load: the module's use count, the NOTICE about
  `ast_sip_session_get_dialog()`, "Reconfiguring triggered by identifier
  load", and the settings of lines 2001 to 2005 (`dpmadev pjsip line`):
  tech, context, callerid, secret, authname, pjsip_auth, mailbox (the
  first of the endpoint's `mailboxes`, else of the first AOR that has
  some), and the `[2002]` line section winning over PJSIP after a full
  pass.
- `module reload res_pjsip.so` with a changed password and caller ID: the
  endpoint observer's `loaded` callback reprocesses everything
  ("Reconfiguring triggered by endpoint").
- ARI push configuration of endpoint, auth, and AOR 2005: endpoint
  created, updated, and deleted (the line is cleared, context included),
  auth updated and deleted, AOR created (no observer: no change until the
  endpoint changes).
- REGISTER from Digium and Sangoma user agents (the phone named after the
  AOR gets `pjsip:<host:port>;transport=<transport>` as its last URI,
  `dpmadev pjsip lastinfo`) and from others (nothing);
  `dpma_pjsip_endpoint_is_dphone` (`dpmadev pjsip isdphone`).
- SIP INFO through `dpma_info_send` (`dpmadev pjsip info`) on a PJSIP
  channel (headers and JSON body, and no body) and on a Local channel
  (-1).
- MESSAGEs with and without `X-Digium-User-Agent` to the `proxy` and
  `probe` extensions, then with `pjsip_message_context=dpma-p11-test` after
  `module reload res_dpma_rs.so` (the config hook moves the DPMA endpoint
  to that context), and back.
- Two unload/load cycles of the module.
- Last: an AOR update while some line has no PJSIP endpoint.

## Findings

- The original's AOR observer (`pjsip_aor_changed`) reads the `aors` of
  each line's endpoint before checking that the endpoint exists, so any
  AOR update or deletion (ARI push configuration, realtime) crashes
  Asterisk in `ast_sorcery_objectset_create2` whenever a line has no PJSIP
  endpoint of its name (external lines, lines of other phones).  Ours
  skips such lines (deviation).
- The original sends INFO on a channel's PJSIP session without checking
  `ast_channel_tech_pvt()`; on a hung-up PJSIP channel it would crash.
  Ours returns -1.
- The original fails to load (AST_MODULE_LOAD_FAILURE, which aborts
  Asterisk startup) when there is no default outbound endpoint
  (`default_outbound_endpoint` in pjsip.conf `[global]`); ours does the
  same.
- `pjsip_contact_update` always adds `;transport=` (it tests the address,
  never NULL, instead of the transport), so a contact without a transport
  gives `pjsip:<host:port>;transport=`.  Kept.
- After an observer update, a line's tech, context, callerid, secret,
  authname, pjsip_auth, and mailbox come from PJSIP even when its
  res_digium_phone.conf section sets them (`process_pjsip_line_info`
  applies the section first, then clears and sets those seven); a full
  pass applies the section last.  Kept (both helpers do this).

## The dialog-info supplement

`scenario.py dialog-info` subscribes to `dialog` events for 2002 as 2001
with a Digium user agent and with another one, rings 2002 from
"Carol Caller" <3003> (early), then answers a call and rings a second one
with restricted caller ID (ringing while in use), printing every NOTIFY
body and the supplement's debug log.  Checked against the decompile
(`dev/analysis/decomp/helpers/res_pjsip_dialog_info_digium_body_supplement.c`):

- Other user agents ("Not a digium or sangoma phone") and states without a
  ringing channel ("No Channel") are left alone.
- Early: Asterisk's generator already adds `<remote>` and `<local>` with
  `<identity>` and `<target>`; the supplement finds them ("Using existing
  ... node", "Skipping due to existing ...") and changes nothing.
- Ringing while in use: the generator writes `<state>confirmed</state>`
  only; the supplement (which asks for the state string with
  `notify_early_inuse_ringing` set, so it says "early" in its logs) adds
  `<local><target uri=.../><identity display=...>uri</identity></local>`
  from the ringing channel's caller and `<remote>` from its connected
  line, with `sip:anonymous@anonymous.invalid` and display "anonymous" for
  a restricted number and name, and the local URI's domain otherwise.
- Asterisk bug #2186 ("extstate: Include causing device channel details
  in legacy callbacks"): the new extension state API of 22.11.0, 23.5.0,
  and 24.0.0-rc1 leaves the device that caused an update, here the
  ringing one, out of the extension state data, so the supplement finds
  no ringing channel ("No Channel") and adds nothing, and the
  generator's early NOTIFY has no `<remote>`.  Fixed in 22.12.0, 23.6.0,
  and 24.0.0-rc2.  On releases with the bug (by release number)
  `check.sh` expects exactly that.
- "No domain in local uri" cannot happen with Asterisk 24 (a
  subscription's local URI is the Request-URI with the resource as its
  user), and the "Created dialog node" branch cannot either (the generator
  always adds `<dialog>`).

## stress.py

Phase 1 races ARI updates of auth and endpoint 2005 (the PJSIP side's
observers rewrite line 2005 under the line object's ao2 lock) against
`dpmadev config 2003` reads of the line's account.  With the readers
taking the line lock, no read sees a half-updated line; without it (as
before P11), about a third of the reads did (empty password, authname
falling back to the line name, empty caller ID).  Phase 2 adds
res_dpma_rs and res_pjsip reloads and checks for deadlocks only.
