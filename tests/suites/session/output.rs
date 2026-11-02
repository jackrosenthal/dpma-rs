//! `digium_phones show sessions` and `DPMAShowPhones` in the official
//! DPMA's formats (handle_cli_show_sessions FUN_00148e40,
//! action_dpma_show_phones FUN_001500d0).

use anyhow::Result;
use dpma_tests::harness::Ctx;
use dpma_tests::sim::Phone;
use regex::escape;

use crate::{ami_action, ami_cli};

pub fn run(ctx: &mut Ctx) -> Result<()> {
    let phone = Phone::start(ctx.sim_options())?;
    let ex = phone.handshake().send()?;
    ctx.c
        .exchange("handshake", &ex)
        .ok()
        .ty("HandshakeResponse");
    let session = phone.session().unwrap_or_default();
    let sid = escape(&session);
    let mac = escape(phone.mac());
    let contact = escape(&phone.contact_uri());

    let res = ami_cli(ctx, "digium_phones show sessions")?;
    ctx.c
        .ami("show sessions", res.response.as_ref())
        .matches("Output", r"(?m)^---- Digium Phone Module Active Sessions ---- ?$")
        .matches(
            "Output",
            &format!(
                r"(?m)^SessionID:{sid} *SecondsAlive:[0-9]+ +SecondsLastActivity:[0-9]+ +URI:pjsip:127\.0\.0\.1:[0-9]+;transport=(udp|tcp) +Auth:No  Inactive:No  Configured: No  MAC:{mac}$"
            ),
        )
        .matches("Output", r"(?m)^--- Total active sessions:[0-9]+ ---$");

    let m = ami_action(ctx, "DPMAShowPhones", &[("ActionID", "p7-output")])?;
    ctx.c
        .ami("DPMAShowPhones", Some(&m))
        .eq("Response", "Success")
        .matches("EventList", "start")
        .eq("Message", "DPMA phone list will follow")
        .matches("Event", "DPMAShowPhonesList")
        .matches("SessionID", &format!("(?m)^{sid}$"))
        .matches("Contact", &format!("(?m)^{contact}$"))
        .matches("URI", r"pjsip:127\.0\.0\.1:[0-9]+;transport=")
        .matches("Auth", "(?m)^0$")
        .matches("Inactive", "(?m)^0$")
        .matches("Configured", "(?m)^0$")
        .matches("MAC", &format!("(?m)^{mac}$"))
        .matches("UserAgent", "Digium D65")
        .matches("SecondsAlive", "[0-9]")
        .matches("SecondsLastActivity", "[0-9]")
        .matches("Event", "DPMAShowPhonesComplete")
        .matches("EventList", "Complete")
        .matches("ListItems", "[0-9]+");

    // Flags: authenticated, then inactive, then configured.
    ami_cli(
        ctx,
        &format!("dpmadev session mark {session} authenticated"),
    )?;
    let res = ami_cli(ctx, "digium_phones show sessions")?;
    ctx.c
        .ami("show sessions, authenticated", res.response.as_ref())
        .matches(
            "Output",
            &format!(r"(?m)^SessionID:{sid} .* Auth:Yes Inactive:No  Configured: No  MAC:{mac}$"),
        );
    ami_cli(ctx, &format!("dpmadev session mark {session} configured"))?;
    ami_cli(ctx, &format!("dpmadev session mark {session} inactive"))?;
    let res = ami_cli(ctx, "digium_phones show sessions")?;
    ctx.c
        .ami("show sessions, every flag", res.response.as_ref())
        .matches(
            "Output",
            &format!(r"(?m)^SessionID:{sid} .* Auth:Yes Inactive:Yes Configured: Yes MAC:{mac}$"),
        );
    let m = ami_action(ctx, "DPMAShowPhones", &[])?;
    ctx.c
        .ami("DPMAShowPhones, every flag", Some(&m))
        .matches("Auth", "(?m)^1$")
        .matches("Inactive", "(?m)^1$")
        .matches("Configured", "(?m)^1$");
    Ok(())
}
