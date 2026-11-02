//! The users-runtime suite: the phone users' runtime without sessions
//! (package P8; was `tests/users-runtime/check.sh`).
//!
//! ```text
//! cargo xtask test users-runtime
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test users-runtime -- --ignored [--no-prepare] [PART...]
//! ```
//!
//! Prerequisites: the test instance and the devtest build of the module
//! (the checks use its `dpmadev` CLI commands).  The suite prepares the
//! instance (fresh configuration, the P8 test phones of
//! `tests/data/users-runtime/res_digium_phone_p8.conf` included from
//! `res_digium_phone.conf`, the debug build installed, Asterisk
//! restarted; `--no-prepare` skips this).  Before the first part it
//! deletes the test phones' AstDB entries and restarts Asterisk, so that
//! the runtime state starts out empty.  It takes about ten seconds.
//!
//! Each check runs a CLI command and looks for fixed strings in its
//! output:
//!
//! | Part | Checks |
//! |---|---|
//! | `presence` | Presence options from status applications (and the six defaults), `digium_phones show status`, the `send_dnd` options of the configuration document, and the `switchvox.users.presence` methods (`options.getList`, `update`, `getInfo`) with their errors |
//! | `tokens` | Configuration tokens (build and find, the previous token), last-seen information and AstDB (orphaned by MAC, MAC mismatch, stale location), `digium_phones show tokens`, events to phones without a session; then the lookups (by credentials, MAC, group pin, last MAC, user name, line, mailbox, applications), which rely on the tokens' last-seen information |
//! | `incidents` | Auth incidents keyed by the full IPv6 host (`DPMAShowIncidents`) |

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use dpma_tests::harness::{fixtures, setup, Ctx, Suite};

/// Whether the runtime state was reset (once per run, before the first
/// part).
static RESET: AtomicBool = AtomicBool::new(false);

/// Deletes the test phones' AstDB entries and restarts Asterisk, once.
fn reset(ctx: &mut Ctx) -> Result<()> {
    if RESET.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    for p in ["p8phone", "p8phone2", "p8nolines", "1001"] {
        ctx.cli(&format!("database del DigiumPhoneUsers {p}"));
    }
    ctx.drop_ami();
    ctx.inst.stop()?;
    ctx.inst.start()
}

/// Runs a CLI command and checks that its output contains every one of
/// `wanted` (as `grep -F` found each on some line).
fn expect(ctx: &mut Ctx, cmd: &str, wanted: &[&str]) {
    let out = ctx.cli(cmd);
    ctx.c.contains(cmd, &out, wanted);
}

fn presence(ctx: &mut Ctx) -> Result<()> {
    reset(ctx)?;
    ctx.cli("presencestate change CustomPresence:p8line available");
    ctx.cli("presencestate change CustomPresence:p8line3 available");

    expect(
        ctx,
        "digium_phones show status p8phone2",
        &[
            "(*) 1: available  ",
            "    2: unavailable  ",
            "    3: away  ",
            "    4: xa  ",
            "    5: chat  ",
            "    6: dnd  ",
        ],
    );
    expect(
        ctx,
        "digium_phones show status p8phone",
        &[
            "    1: dnd  ",
            "    2: dnd - In a meeting",
            "    3: dnd - ",
            "(*) 4: available  ",
        ],
    );
    // The name is matched case sensitively: nothing is printed.
    let out = ctx.cli("digium_phones show status P8phone");
    ctx.c.check(
        "digium_phones show status P8phone (empty)",
        out.iter().all(|&b| b == b'\n'),
        format!("printed: {out:?}"),
    );
    expect(
        ctx,
        "dpmadev config p8phone D65",
        &[r#"<send_dnd status="available" /><send_dnd status="xa" />"#],
    );
    expect(
        ctx,
        "dpmadev config p8phone2 D65",
        &[r#"<send_dnd status="dnd" /><send_dnd status="xa" />"#],
    );
    expect(
        ctx,
        "dpmadev method call p8phone switchvox.users.presence.options.getList {}",
        &[
            r#"{"response":{"method":"switchvox.users.presence.options.getList","result":{"presence_options":{"presence_option":[{"id":"1","presence":"dnd","sub_presence":"","owner":"system","active":"0"},{"id":"2","presence":"dnd","sub_presence":"In a meeting","owner":"system","active":"0"},{"id":"3","presence":"dnd","sub_presence":"","owner":"system","active":"0"},{"id":"4","presence":"available","sub_presence":"","owner":"system","active":"1"}]}}}}"#,
        ],
    );
    expect(
        ctx,
        r#"dpmadev method call p8phone switchvox.users.presence.update {\"presence_option_id\":\"2\",\"message\":\"back at 3\"}"#,
        &[r#"{"response":{"method":"switchvox.users.presence.update","result":{"success":{}}}}"#],
    );
    expect(
        ctx,
        "presencestate list",
        &[
            "'CustomPresence:p8line'",
            "State: 'dnd'",
            "Subtype: 'In a meeting'",
            "Message: 'back at 3'",
        ],
    );
    expect(
        ctx,
        "digium_phones show status p8phone",
        &["(*) 2: dnd - In a meeting"],
    );
    expect(
        ctx,
        "dpmadev method call p8phone switchvox.users.presence.getInfo {}",
        &[
            r#"{"response":{"method":"switchvox.users.presence.getInfo","result":{"presence":{"id":"2","presence":"dnd","sub_presence":"In a meeting","message":"back at 3"}}}}"#,
        ],
    );
    expect(
        ctx,
        r#"dpmadev method call p8phone switchvox.users.presence.update {\"presence_option_id\":2}"#,
        &[r#""code":10011,"message":"Parameters not found: j_option_id ""#],
    );
    expect(
        ctx,
        r#"dpmadev method call p8phone switchvox.users.presence.update {\"presence_option_id\":\"x\"}"#,
        &[r#""code":10011,"message":"Parameters not found: option_id_str ""#],
    );
    expect(
        ctx,
        r#"dpmadev method call p8phone switchvox.users.presence.update {\"presence_option_id\":\" 9z\"}"#,
        &[
            r#""code":42013,"message":"The account id does not match the owners presence option: phone_presence_update ""#,
        ],
    );
    ctx.cli("presencestate change CustomPresence:p8line away,,gone");
    expect(
        ctx,
        "dpmadev method call p8phone switchvox.users.presence.getInfo {}",
        &[r#""code":10002,"message":"Error parsing request: presence_option ""#],
    );
    ctx.cli("presencestate change CustomPresence:p8line available");
    Ok(())
}

fn tokens(ctx: &mut Ctx) -> Result<()> {
    reset(ctx)?;
    // Tokens and last-seen information.
    let t = "p8phone/000fd3000801/2087735778/1706321644";
    expect(
        ctx,
        "dpmadev token build p8phone 000fd3000801 sess1 pjsip:127.0.0.1:5061",
        &[&format!("token: {t}")],
    );
    expect(
        ctx,
        "dpmadev token info p8phone",
        &[
            "last_mac='000fd3000801' last_uri='pjsip:127.0.0.1:5061' last_session_id='sess1' token_state=1",
            "AstDB: last_mac=000fd3000801;last_uri=pjsip:127.0.0.1:5061;last_session_id=sess1",
        ],
    );
    expect(
        ctx,
        &format!("dpmadev token find {t} 000fd3000801 sess1 pjsip:127.0.0.1:5061"),
        &["phone: p8phone  previous_token: false"],
    );
    expect(
        ctx,
        "dpmadev token find p8phone/000fd3000801XYZ . . pjsip:127.0.0.1:5061",
        &["phone: p8phone "],
    );
    expect(
        ctx,
        "dpmadev token find p8phone-000fd3000801-1 . . pjsip:127.0.0.1:5061",
        &["phone: p8phone "],
    );
    expect(
        ctx,
        "dpmadev token find P8phone/000fd3000801/1/2 . . u",
        &["phone: (none)"],
    );
    expect(ctx, "dpmadev token find /x . . u", &["phone: (none)"]);
    expect(
        ctx,
        "dpmadev token build p8phone 000fd3000801 sess1 pjsip:127.0.0.1:5061 other",
        &["token: p8phone/000fd3000801/2087735778/182229153"],
    );
    // Same character sum as the token before the latest one, but no
    // match.
    expect(
        ctx,
        "dpmadev token find p8phone/000fd3000810/2087735778/1706321644 . . u",
        &["phone: (none)  previous_token: true"],
    );
    // Orphaned by MAC, then a MAC mismatch, then a stale location.
    expect(
        ctx,
        "dpmadev token build p8phone2 000fd3000801 sess2 pjsip:127.0.0.1:5062",
        &["token: p8phone2/000fd3000801/"],
    );
    expect(
        ctx,
        "dpmadev token info p8phone",
        &[
            "last_mac='' last_uri='' last_session_id=''",
            "AstDB: (none)",
        ],
    );
    expect(
        ctx,
        "dpmadev token lastinfo p8phone2 pjsip:127.0.0.1:5062 sess2 000fd3000802",
        &["last_mac='000fd3000802' last_uri='pjsip:127.0.0.1:5062'"],
    );
    expect(
        ctx,
        "dpmadev token lastinfo p8phone2 pjsip:127.0.0.1:5062;transport=udp - -",
        &["last_uri='pjsip:127.0.0.1:5062' last_session_id='sess2'"],
    );
    expect(
        ctx,
        "dpmadev token lastinfo p8phone2 pjsip:127.0.0.1:5062;transport=tcp - -",
        &["last_uri='pjsip:127.0.0.1:5062;transport=tcp' last_session_id='sess2'"],
    );
    expect(
        ctx,
        "dpmadev token build p8phone 000fd3000801 sess3 pjsip:127.0.0.1:5062;transport=tcp",
        &[&format!("token: {t}")],
    );
    expect(
        ctx,
        "dpmadev token info p8phone2",
        &[
            "last_mac='' last_uri='' last_session_id=''",
            "AstDB: (none)",
        ],
    );
    expect(
        ctx,
        "digium_phones show tokens",
        &["p8phone  MAC:000fd3000801  URI:pjsip:127.0.0.1:5062;transport=tcp SessionID:sess3"],
    );
    expect(
        ctx,
        "dpmadev token event p8phone2 digium.test <x/>",
        &[r#"Err("Phone has not contacted server")"#],
    );
    expect(
        ctx,
        "dpmadev token event nosuch digium.test <x/>",
        &[r#"Err("Memory allocation error")"#],
    );

    // Lookups.
    for (cmd, want) in [
        ("dpmadev token lookup auth P8PHONE 1111", "p8phone"),
        ("dpmadev token lookup auth p8phone 111", "(none)"),
        ("dpmadev token lookup auth p8nolines .", "p8nolines"),
        (
            "dpmadev token lookup authmac p8phone 1111 000FD3000801",
            "p8phone",
        ),
        ("dpmadev token lookup mac p8phone 000fd3000802", "(none)"),
        ("dpmadev token lookup grouppin p8phone gp8", "p8phone"),
        ("dpmadev token lookup lastmac 000FD3000801", "p8phone"),
        ("dpmadev token lookup username 8101 .", "p8phone"),
        ("dpmadev token lookup username p8line2 .", "(none)"),
        ("dpmadev token lookup username . 000fd3000802", "p8phone2"),
        ("dpmadev token lookup username p8nolines .", "p8nolines"),
        ("dpmadev token lookup line p8line s3cret", "p8line"),
        ("dpmadev token lookup line p8line S3cret", "(none)"),
        ("dpmadev token lookup lineuser P8LINE2", "p8phone"),
        ("dpmadev token lookup mailbox p8line", "8001@default"),
        ("dpmadev token lookup hasline p8phone p8line3", "false"),
        (
            "dpmadev token lookup apps p8phone Status",
            r#"["p8-avail", "p8-dnd"]"#,
        ),
    ] {
        expect(ctx, cmd, &[want]);
    }
    Ok(())
}

fn incidents(ctx: &mut Ctx) -> Result<()> {
    reset(ctx)?;
    expect(
        ctx,
        "dpmadev auth alert [2001:db8::1]:5060 000fd3000801 UA1 invalid credentials",
        &["recorded"],
    );
    expect(
        ctx,
        "dpmadev auth alert [2001:db8::2]:5060 000fd3000802 UA2 invalid credentials",
        &["recorded"],
    );
    let found = fixtures::incidents(ctx.ami()?);
    for ip in ["2001:db8::1", "2001:db8::2"] {
        ctx.c.check(
            format!("incident for {ip}"),
            found.contains_key(ip.as_bytes()),
            format!("incidents: {:?}", found.keys().collect::<Vec<_>>()),
        );
    }
    for ip in ["2001:db8::1", "2001:db8::2"] {
        ctx.ami()?.action("DPMARemoveIncident", [("IPAddress", ip)]);
    }
    Ok(())
}

fn main() -> ExitCode {
    Suite::new("users-runtime")
        .prepare(|inst| {
            fixtures::prepare(inst, |inst| {
                setup::install_snippet(
                    inst,
                    "res_digium_phone_p8.conf",
                    "res_digium_phone.conf",
                    include_bytes!("../../data/users-runtime/res_digium_phone_p8.conf"),
                )
            })
        })
        .part("presence", presence)
        .part("tokens", tokens)
        .part("incidents", incidents)
        .main()
}
