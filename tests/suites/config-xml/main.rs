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
    let doc = document(ctx, "dpmadev config cfgphone D65")?;
    ctx.c.check(
        "cfgphone: the config_file",
        doc == "<config>\n<setting id=\"x\" value=\"1\" />\n</config>\n",
        format!("{doc:?}"),
    );
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
