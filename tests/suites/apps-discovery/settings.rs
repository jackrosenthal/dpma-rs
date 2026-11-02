//! `digium_phones show settings` for several `[general]` configurations,
//! compared with the official DPMA's format strings.

use anyhow::Result;
use dpma_tests::harness::Ctx;

use crate::{cli_raw, set_general, with_conf};

/// The fields of `digium_phones show settings`.
struct Settings<'a> {
    uuid: &'a str,
    pin: &'a str,
    discovery: &'a str,
    name: &'a str,
    addr: &'a str,
    port: &'a str,
    userlist: &'a str,
    config: &'a str,
    fw: &'a str,
    files: &'a str,
    context: &'a str,
    delay: &'a str,
}

impl<'a> Settings<'a> {
    /// The test configuration's settings; `files` is the default file
    /// directory.
    fn new(files: &'a str) -> Settings<'a> {
        Settings {
            uuid: "<Not Set>",
            pin: "<Set>",
            discovery: "Disabled",
            name: "Digium Phone Config Server",
            addr: "<Not Set>",
            port: "5060",
            userlist: "disabled",
            config: "mac globalpin",
            fw: "<Not Set>",
            files,
            context: "dpma_pjsip_message_context",
            delay: "5",
        }
    }

    fn text(&self) -> String {
        format!(
            "---- Digium Phone Module Global Settings ---- \n\
             Server UUID: {}\nGlobalPin: {}\nService Discovery: {}\nService Disc. Name: {}\n\
             Service Disc. Addr: {}\nService Disc. Port: {}\nUserlist Authentication: {}\n\
             Config Authentication: {}\nFirmware Package Directory: {}\nFile Directory: {}\n\
             PJSIP message context: {}\nMessage Delay: {} ms\n",
            self.uuid,
            self.pin,
            self.discovery,
            self.name,
            self.addr,
            self.port,
            self.userlist,
            self.config,
            self.fw,
            self.files,
            self.context,
            self.delay
        )
    }
}

/// The part: `discovery_ok` is whether service discovery may be enabled
/// (in a network namespace whose only interface is `lo`).
pub fn run(ctx: &mut Ctx, discovery_ok: bool) -> Result<()> {
    with_conf(ctx, |ctx, orig| checks(ctx, orig, discovery_ok))
}

fn checks(ctx: &mut Ctx, orig: &[u8], discovery_ok: bool) -> Result<()> {
    let file_dir = ctx.inst.var_lib().join("digium_phones");
    let file_dir = file_dir.to_string_lossy().into_owned();
    let base = Settings::new(&file_dir);
    let show = |ctx: &Ctx| cli_raw(ctx, "digium_phones show settings");

    set_general(
        ctx,
        orig,
        &[
            ("globalpin", b"344486"),
            ("userlist_auth", b"disabled"),
            ("config_auth", b"mac_globalpin"),
            ("service_discovery_enabled", b"no"),
        ],
    )?;
    let out = show(ctx);
    ctx.c
        .same("show settings: test configuration", out, base.text());
    let out = cli_raw(ctx, "digium_phones show settings now");
    ctx.c
        .same("show settings takes extra words", out, base.text());

    set_general(
        ctx,
        orig,
        &[
            ("server_uuid", b"1c0ffee0-p14"),
            ("userlist_auth", b"globalpin"),
            ("config_auth", b"mac"),
            ("mdns_address", b"10.1.2.3"),
            ("mdns_port", b"5070"),
            ("mdns_transport", b"tcp"),
            ("service_name", b"P14 Settings"),
            ("firmware_package_directory", b"/tmp/p14fw"),
            ("file_directory", b"/tmp/p14files"),
            ("pjsip_message_context", b"p14ctx"),
            ("message_delay", b"25"),
            (
                "service_discovery_enabled",
                if discovery_ok { &b"yes"[..] } else { b"no" },
            ),
        ],
    )?;
    let out = show(ctx);
    ctx.c.same(
        "show settings: everything set, config_auth=mac",
        out,
        Settings {
            uuid: "1c0ffee0-p14",
            pin: "<Not Set>",
            discovery: if discovery_ok { "Enabled" } else { "Disabled" },
            name: "P14 Settings",
            addr: "10.1.2.3",
            port: "5070",
            userlist: "globalpin",
            config: "mac ",
            fw: "/tmp/p14fw/",
            files: "/tmp/p14files",
            context: "p14ctx",
            delay: "25",
        }
        .text(),
    );

    set_general(
        ctx,
        orig,
        &[
            ("config_auth", b"pin"),
            ("registration_address", b"10.9.9.9"),
            ("registration_port", b"5099"),
            ("mdns_port", b"123456789012"),
            ("service_discovery_enabled", b"no"),
            ("message_delay", b"0"),
        ],
    )?;
    let out = show(ctx);
    ctx.c.same(
        "show settings: config_auth=pin, registration address, long port",
        out,
        Settings {
            pin: "<Not Set>",
            addr: "10.9.9.9",
            port: "123456789",
            config: "pin",
            delay: "0",
            ..Settings::new(&file_dir)
        }
        .text(),
    );

    set_general(
        ctx,
        orig,
        &[
            ("config_auth", b"mac_pin"),
            ("registration_port", b"5098"),
            ("service_name", b""),
            ("service_discovery_enabled", b"no"),
        ],
    )?;
    let out = show(ctx);
    ctx.c.same(
        "show settings: config_auth=mac_pin, registration port",
        out,
        Settings {
            pin: "<Not Set>",
            port: "5098",
            config: "mac pin",
            ..Settings::new(&file_dir)
        }
        .text(),
    );

    set_general(
        ctx,
        orig,
        &[
            ("config_auth", b"disabled"),
            ("service_discovery_enabled", b"no"),
            ("globalpin", b"1"),
        ],
    )?;
    let out = show(ctx);
    ctx.c.same(
        "show settings: config_auth=disabled",
        out,
        Settings {
            config: "disabled",
            ..Settings::new(&file_dir)
        }
        .text(),
    );

    set_general(
        ctx,
        orig,
        &[
            ("config_auth", b"globalpin"),
            ("service_discovery_enabled", b"no"),
        ],
    )?;
    let out = show(ctx);
    ctx.c.same(
        "show settings: config_auth=globalpin",
        out,
        Settings {
            pin: "<Not Set>",
            config: "globalpin",
            ..Settings::new(&file_dir)
        }
        .text(),
    );
    let out = cli_raw(ctx, "digium_phones show version");
    ctx.c
        .same("show version", out.as_str(), "dpma-rs version 0.1.0\n");
    Ok(())
}
