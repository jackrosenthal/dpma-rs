//! The dialog-info scenario (the dialog-info supplement) and its checks.
//!
//! Asterisk bug #2186 ("extstate: Include causing device channel details
//! in legacy callbacks"): the new extension state API of 22.11.0, 23.5.0,
//! and 24.0.0-rc1 leaves the ringing channel out of the extension state
//! data, so the supplement finds none ("Bail.  No Channel") and adds
//! nothing.  It is fixed in 22.12.0, 23.6.0, and 24.0.0-rc2.  On releases
//! with the bug (detected by the release number, from `asterisk -V`) the
//! checks expect exactly that; on the others, the supplement for the
//! Digium subscriber only.

use anyhow::Result;
use dpma_tests::harness::{fixtures, Ctx};

use crate::{restart, transcript_dir, Scenario, DIGIUM_UA};

/// What the supplement adds for the restricted caller.
const ANON: &str = "<remote><target uri=\"sip:anonymous@anonymous.invalid\" />";

/// Whether `release` has Asterisk bug #2186.
pub fn has_bug_2186(release: &str) -> bool {
    release.starts_with("22.11.") || release.starts_with("23.5.") || release == "24.0.0-rc1"
}

pub fn run(ctx: &mut Ctx) -> Result<()> {
    restart(ctx)?;
    let version = ctx.inst.release()?;
    let mut s = Scenario::new(&ctx.inst, ctx.verbose);
    let res = scenario(&mut s);
    let path = transcript_dir(&ctx.inst)?.join("dialog-info.txt");
    s.save(&path)?;
    ctx.c.note(format!(
        "transcript in {} (Asterisk {version})",
        path.display()
    ));
    let lines = s.lines();
    let notify: Vec<&String> = lines.iter().filter(|l| l.contains(": NOTIFY ")).collect();
    // On failure, the NOTIFYs and the supplement's log.
    let detail = |ok: bool| {
        if ok {
            return String::new();
        }
        lines
            .iter()
            .filter(|l| {
                l.contains(": NOTIFY ") || l.contains(": SUBSCRIBE ") || l.starts_with("  log: ")
            })
            .map(|l| l.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    };
    if has_bug_2186(&version) {
        ctx.c.note(format!(
            "Asterisk {version} has bug #2186 (fixed in 22.12.0, 23.6.0, and 24.0.0-rc2): \
             no ringing channel, so nothing is supplemented"
        ));
        let ok = !notify.iter().any(|l| l.contains("anonymous.invalid"));
        ctx.c.check(
            "dialog-info: no NOTIFY supplemented (bug #2186: no ringing channel)",
            ok,
            detail(ok),
        );
        let ok = lines
            .iter()
            .any(|l| l.starts_with("  log: ") && l.contains("Bail.  No Channel"));
        ctx.c.check(
            "dialog-info: \"Bail.  No Channel\" for the Digium subscriber (bug #2186)",
            ok,
            detail(ok),
        );
    } else {
        let ok = notify
            .iter()
            .any(|l| l.starts_with("  digium: ") && l.contains(ANON));
        ctx.c.check(
            "dialog-info: the Digium subscriber's NOTIFY supplemented",
            ok,
            detail(ok),
        );
        let ok = !notify
            .iter()
            .any(|l| l.starts_with("  other: ") && l.contains("anonymous.invalid"));
        ctx.c.check(
            "dialog-info: the other subscriber's NOTIFY not supplemented",
            ok,
            detail(ok),
        );
    }
    res
}

fn scenario(s: &mut Scenario) -> Result<()> {
    s.forget_contacts();
    s.step("dialog-info supplement");
    s.ast("core set debug 3 res_dpma_rs", true);
    let uas = s.uas("2002", "pw2002", "Acme Phone 1.0", 16.0, &[2])?;
    fixtures::sleep(1.0);
    let subs = [
        (
            "digium",
            s.subscribe("2001", "pw2001", DIGIUM_UA, "2002", 15.0),
        ),
        (
            "other",
            s.subscribe("2001", "pw2001", "Acme Phone 1.0", "2002", 15.0),
        ),
    ];
    fixtures::sleep(1.5);
    s.out("-- ringing (early), Carol Caller <3003>");
    s.ast(
        "channel originate Local/3002@test-phones application Wait 3",
        false,
    );
    fixtures::sleep(1.5);
    s.ast("hangup request all", true);
    fixtures::sleep(1.5);
    s.out("-- answered (in use), then a restricted call rings (ringing while in use)");
    s.ast(
        "channel originate Local/3002@test-phones application Wait 8",
        false,
    );
    fixtures::sleep(1.5);
    s.ast(
        "channel originate Local/3012@test-phones application Wait 3",
        false,
    );
    fixtures::sleep(2.0);
    s.ast("hangup request all", true);
    for (label, h) in subs {
        s.collect_subscriber(h, label);
    }
    s.collect_uas(uas.join(), "2002", "uas");
    s.log_show();
    s.ast("core set debug 0 res_dpma_rs", true);
    Ok(())
}
