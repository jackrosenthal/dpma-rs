//! The identifier scenario (`scenario.py identifier`, the endpoint
//! identifier side): lines filled from `pjsip.conf`, res_pjsip reloads,
//! ARI-driven endpoint, auth, and AOR observers, REGISTER handling, the
//! endpoint-is-dphone function, SIP INFO, MESSAGE identification and
//! `pjsip_message_context` changes (config hook), unload/load cycles,
//! and, last, an AOR update while a line has no endpoint (which crashes
//! the original).  Its transcript must be the expected one byte for byte.

use anyhow::Result;
use dpma_tests::diff;
use dpma_tests::harness::{fixtures, Ctx};

use crate::{restart, transcript_dir, Scenario, DIGIUM_UA, DPMA};

/// An ARI request: method, path, and fields.
type AriRequest<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

/// The expected transcript.
const EXPECTED: &str = include_str!("../../data/pjsip-helpers/expected-identifier.txt");

pub fn run(ctx: &mut Ctx) -> Result<()> {
    restart(ctx)?;
    let mut s = Scenario::new(&ctx.inst, ctx.verbose);
    let res = scenario(&mut s);
    let path = transcript_dir(&ctx.inst)?.join("identifier.txt");
    s.save(&path)?;
    ctx.c.note(format!("transcript in {}", path.display()));
    let got = s.text();
    let ok = got == EXPECTED;
    let n = s.lines().len();
    ctx.c
        .check_with("identifier transcript as expected", ok, || {
            if ok {
                format!("{n} lines")
            } else {
                format!(
                    "{n} lines; - expected, + now:\n{}",
                    diff::unified(
                        EXPECTED,
                        &got,
                        "expected-identifier.txt",
                        "identifier.txt",
                        3
                    )
                )
            }
        });
    res
}

fn scenario(s: &mut Scenario) -> Result<()> {
    s.log_from_start();
    s.forget_contacts();
    s.step("load");
    s.ast(&format!("module show like {DPMA}"), false);
    s.log_show();
    s.line_settings(&["2001", "2002", "2003", "2004", "2005"]);

    s.step("res_pjsip reload with changed endpoint and auth");
    let conf = "pjsip_p11.conf";
    s.edit(
        conf,
        "callerid=\"Phone One\" <2001>",
        "callerid=\"Phone One B\" <2001>",
    )?;
    s.edit(conf, "password=pw2001\n", "password=pw2001b\n")?;
    s.ast("module reload res_pjsip.so", false);
    fixtures::sleep(2.0);
    s.log_show();
    s.line_settings(&["2001"]);
    s.edit(
        conf,
        "callerid=\"Phone One B\" <2001>",
        "callerid=\"Phone One\" <2001>",
    )?;
    s.edit(conf, "password=pw2001b\n", "password=pw2001\n")?;
    s.ast("module reload res_pjsip.so", false);
    fixtures::sleep(2.0);
    s.log_show();
    s.line_settings(&["2001"]);

    s.step("observers through ARI push configuration");
    let updates: [AriRequest; 8] = [
        (
            "PUT",
            "endpoint/2005",
            &[
                ("context", "p11-phones"),
                ("allow", "!all,ulaw"),
                ("aors", "2005"),
                ("auth", "2005-auth"),
                ("callerid", "\"ARI Five\" <2005>"),
            ],
        ),
        (
            "PUT",
            "auth/2005-auth",
            &[
                ("auth_type", "userpass"),
                ("username", "ari5"),
                ("password", "pw2005"),
            ],
        ),
        (
            "PUT",
            "endpoint/2005",
            &[("callerid", "\"ARI Five B\" <2005>")],
        ),
        ("PUT", "auth/2005-auth", &[("password", "pw2005b")]),
        ("PUT", "aor/2005", &[("mailboxes", "2005@default")]),
        ("PUT", "endpoint/2005", &[("mailboxes", "")]),
        ("DELETE", "auth/2005-auth", &[]),
        ("DELETE", "endpoint/2005", &[]),
    ];
    for (method, path, fields) in updates {
        s.ari(method, path, fields);
        s.log_show();
        s.line_settings(&["2005"]);
    }

    s.step("REGISTER");
    s.ast("core set debug 2 res_dpma_rs", true);
    s.ast("dpmadev pjsip lastinfo clear", true);
    s.register("2001", "pw2001", DIGIUM_UA)?;
    s.register("2002", "pw2002", "Acme Phone 1.0")?;
    fixtures::sleep(1.0);
    s.log_show();
    s.ast("dpmadev pjsip lastinfo", false);
    for e in ["2001", "2002", "2003", "2004", "nonexistent"] {
        s.ast(&format!("dpmadev pjsip isdphone {e}"), false);
    }
    // Phone 2001 again (contact replaced); 2002 is not a phone but now has
    // a Sangoma contact as well.
    s.register("2001", "pw2001", "Sangoma P370 2.0")?;
    s.register("2002", "pw2002", "Sangoma P330 1.0")?;
    fixtures::sleep(1.0);
    s.log_show();
    s.ast("dpmadev pjsip lastinfo", false);
    s.ast("dpmadev pjsip isdphone 2002", false);
    s.ast("core set debug 0 res_dpma_rs", true);

    s.step("SIP INFO");
    let uas = s.uas("2001", "pw2001", DIGIUM_UA, 8.0, &[1])?;
    fixtures::sleep(1.5);
    s.ast("channel originate PJSIP/2001 application Wait 5", false);
    fixtures::sleep(1.0);
    let chan = s.channel("PJSIP/2001-");
    let shown = crate::norm(chan.as_deref().unwrap_or("None"));
    s.out(format!("  channel: {shown}"));
    if let Some(chan) = &chan {
        s.ast(
            &format!("dpmadev pjsip info {chan} {{\"location\":5}}"),
            false,
        );
        s.ast(&format!("dpmadev pjsip info {chan}"), false);
    }
    s.ast(
        "channel originate Local/2002@p11-phones application Wait 2",
        false,
    );
    fixtures::sleep(0.5);
    if let Some(local) = s.channel("Local/2002@p11-phones-") {
        s.ast(&format!("dpmadev pjsip info {local} {{}}"), false);
    }
    s.collect_uas(uas, "2001", "uas");
    s.ast("hangup request all", true);

    s.step("MESSAGE identification and pjsip_message_context");
    for exten in ["proxy", "probe"] {
        s.message(exten, Some(DIGIUM_UA))?;
        s.message(exten, None)?;
    }
    s.log_show();
    s.set_message_context(Some("dpma-p11-test"))?;
    s.ast(&format!("module reload {DPMA}"), false);
    fixtures::sleep(1.0);
    for exten in ["proxy", "probe"] {
        s.message(exten, Some(DIGIUM_UA))?;
    }
    s.log_show();
    s.set_message_context(None)?;
    s.ast(&format!("module reload {DPMA}"), false);
    fixtures::sleep(1.0);
    s.message("probe", Some(DIGIUM_UA))?;
    s.log_show();

    for i in 1..=2 {
        s.step(&format!("unload and load {i}"));
        s.ast(&format!("module unload {DPMA}"), false);
        s.ast(&format!("module show like {DPMA}"), false);
        s.ast(&format!("module load {DPMA}"), false);
        s.ast(&format!("module show like {DPMA}"), false);
        s.log_show();
        s.line_settings(&["2001", "2002"]);
    }

    s.step("AOR update while line 2004 has no endpoint");
    s.ari(
        "PUT",
        "endpoint/2005",
        &[
            ("context", "p11-phones"),
            ("allow", "!all,ulaw"),
            ("aors", "2005"),
        ],
    );
    s.ari("PUT", "aor/2005", &[("mailboxes", "2005@other")]);
    fixtures::sleep(1.0);
    let alive = s.alive();
    s.out(format!(
        "  asterisk running: {}",
        if alive { "yes" } else { "NO" }
    ));
    if s.alive() {
        s.log_show();
        s.line_settings(&["2005"]);
        s.ari("DELETE", "aor/2005", &[]);
        s.ari("DELETE", "endpoint/2005", &[]);
    }
    Ok(())
}
