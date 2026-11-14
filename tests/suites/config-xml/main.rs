//! The config-xml suite: smoke checks of the documents the configuration
//! builds.
//!
//! ```text
//! cargo xtask test config-xml
//! ```
//!
//! runs it in the test container after building the devtest module, as
//!
//! ```text
//! cargo test -p dpma-tests --test config-xml -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! The suite prepares the instance with the setup of
//! [`dpma_tests::harness::setup::config_xml`] (`--no-prepare` skips this).
//! `-v` prints the documents.
//!
//! No expected documents are recorded (they were compared with the
//! decompile by hand); the suite checks that every document the setup
//! describes is produced and well formed.

use std::process::ExitCode;

use anyhow::{bail, Result};
use bstr::{BString, ByteSlice};
use dpma_tests::harness::{fixtures, setup, Ctx, Suite};
use dpma_tests::xml;

/// Values the official DPMA writes unescaped (attribute text as in the
/// document), by phone.
const UNESCAPED: [(&str, &[&str]); 2] = [
    (
        "fullphone",
        &[
            r#"display_name="Remote & <Other>""#,
            r#"value="ACME <Corp>""#,
        ],
    ),
    ("nolinephone", &[r#"display_name="Remote & <Other>""#]),
];

/// The output of a `dpmadev` command (printed with `-v`); fails when the
/// module has no `dpmadev` commands.
fn document(ctx: &Ctx, cmd: &str) -> Result<BString> {
    let out = ctx.cli(cmd);
    if out.contains_str("No such command") {
        bail!("dpmadev hooks not available (devtest build installed and Asterisk running?)");
    }
    if ctx.verbose {
        ctx.c.say(out.to_str_lossy());
    }
    Ok(out)
}

/// The first `n` bytes of `doc` as text.
fn head(doc: &[u8], n: usize) -> String {
    doc[..doc.len().min(n)].to_str_lossy().into_owned()
}

fn config(ctx: &mut Ctx) -> Result<()> {
    for phone in ["fullphone", "minphone", "altphone", "nolinephone"] {
        let mut doc = document(ctx, &format!("dpmadev config {phone} D65"))?;
        ctx.c.check(
            format!("{phone}: a configuration document"),
            doc.contains_str("<config>") && doc.contains_str("</config>"),
            head(&doc, 200),
        );
        let unescaped = UNESCAPED
            .iter()
            .find(|(p, _)| *p == phone)
            .map_or(&[][..], |(_, t)| *t);
        for text in unescaped {
            ctx.c.check(
                format!("{phone}: unescaped {text}"),
                doc.contains_str(text),
                "",
            );
            let (name, value) = text.split_once('=').expect("name=\"value\"");
            let value = xml::escape(&value.as_bytes()[1..value.len() - 1]);
            let mut escaped = format!("{name}=\"").into_bytes();
            escaped.extend_from_slice(&value);
            escaped.push(b'"');
            doc = doc.replace(text, &escaped).into();
        }
        let err = xml::well_formed(&doc);
        ctx.c.check(
            format!("{phone}: well formed"),
            err.is_ok(),
            err.err().unwrap_or_default(),
        );
        if phone == "altphone" {
            ctx.c.check(
                "altphone: display rules merged",
                doc.starts_with(b"<?xml version=\"1.0\"?>\n<config>"),
                head(&doc, 80),
            );
        }
    }
    dphone_options(ctx)?;
    let doc = document(ctx, "dpmadev config cfgphone D65")?;
    ctx.c.check(
        "cfgphone: the config_file",
        doc == "<config>\n<setting id=\"x\" value=\"1\" />\n</config>\n",
        format!("{doc:?}"),
    );
    Ok(())
}

/// Open DPhone's settings as `fullphone` sets them: the two settings, and
/// the two acceptable keys of the six configured (a duplicate, a private
/// key header, a line with options, and a short blob are left out).
const DPHONE_SETTINGS: &str = concat!(
    "<setting id=\"dphone_ssh_enabled\" value=\"0\" />\n",
    "<setting id=\"dphone_ignore_provisioned_firmware\" value=\"1\" />\n",
);
const DPHONE_KEYS: &str = concat!(
    "<dphone_ssh_authorized_keys>\n",
    "<key id=\"1\" value=\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa alice@laptop\" />\n",
    "<key id=\"2\" value=\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb bob &lt;desk&gt; &amp; co\" />\n",
    "</dphone_ssh_authorized_keys>\n",
    "</config>\n",
);

/// The Open DPhone options: present as configured for `fullphone`, and
/// absent from the document of a phone that does not set them.
fn dphone_options(ctx: &mut Ctx) -> Result<()> {
    let doc = document(ctx, "dpmadev config fullphone D65")?;
    ctx.c.check(
        "fullphone: Open DPhone settings",
        doc.contains_str(DPHONE_SETTINGS),
        "",
    );
    ctx.c.check(
        "fullphone: Open DPhone SSH keys",
        doc.contains_str(DPHONE_KEYS) && !doc.contains_str("PRIVATE KEY"),
        "",
    );
    // A firmware file found on the server has its checksum stated; one
    // named by URL, or not found, has the entry of the official DPMA.
    ctx.c.check(
        "fullphone: checksum of a profile's local file",
        doc.contains_str(
            "1_1_0_0_48178_D40_firmware.eff\" network_id=\"network1\" checksum=\"0a1b2c3d-1500000-ffffffff-39321600\" />\n",
        ),
        "",
    );
    ctx.c.check(
        "fullphone: no checksum for a URL",
        doc.contains_str(
            "url=\"http://fw.example.com/2_9_17_D65_firmware.eff\" network_id=\"network1\" />\n",
        ),
        "",
    );
    // altphone has no firmware options, so it is offered the packages;
    // its document is rewritten when the display rules are merged in, so
    // only the attribute is looked for.  One of the two packages with a
    // version is a file in the package directory, and altphone has two
    // networks.
    let doc = document(ctx, "dpmadev config altphone D65")?;
    ctx.c.check(
        "altphone: checksum of the package file that is here, and no other",
        doc.find_iter("checksum=\"0a1b2c3d-1500000-ffffffff-39321600\"")
            .count()
            == 2
            && doc.find_iter("checksum=").count() == 2
            && doc.find_iter("<firmware ").count() == 4,
        doc.lines()
            .filter(|l| l.contains_str("firmware"))
            .map(|l| l.to_str_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" | "),
    );
    for phone in ["minphone", "altphone", "nolinephone"] {
        let doc = document(ctx, &format!("dpmadev config {phone} D65"))?;
        ctx.c.check(
            format!("{phone}: no Open DPhone options"),
            !doc.contains_str("dphone_"),
            "",
        );
    }
    Ok(())
}

fn contacts(ctx: &mut Ctx) -> Result<()> {
    let doc = document(ctx, "dpmadev contacts")?;
    let err = xml::well_formed(&doc);
    let ok = doc.starts_with(b"<contacts ") && err.is_ok();
    ctx.c.check(
        "contacts: well formed",
        ok,
        err.err().unwrap_or_else(|| head(&doc, 200)),
    );
    Ok(())
}

fn userlist(ctx: &mut Ctx) -> Result<()> {
    for (args, count, line) in [
        ("", 0, "0 user(s), group pin filter on"),
        (" 344486", 5, "5 user(s), group pin filter off"),
    ] {
        let out = document(ctx, &format!("dpmadev userlist{args}"))?;
        let (first, body) = out.split_once_str("\n").unwrap_or((&out, b""));
        let users = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v["users"].as_array().map(Vec::len));
        ctx.c.check(
            format!("userlist{args}: {count} user(s)"),
            first == line.as_bytes() && users == Some(count),
            head(&out, 200),
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    Suite::new("config-xml")
        .prepare(|inst| fixtures::prepare(inst, setup::config_xml))
        .part("config", config)
        .part("contacts", contacts)
        .part("userlist", userlist)
        .main()
}
