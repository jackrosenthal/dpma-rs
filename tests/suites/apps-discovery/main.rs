//! The apps-discovery suite: the dialplan applications
//! DigiumControlPlayback and DigiumVoicemailPlayback, `digium_phones show
//! settings`, and the mDNS announcement.
//!
//! ```text
//! cargo xtask test apps-discovery
//! ```
//!
//! which runs, inside the test container, after building the devtest
//! module:
//!
//! ```text
//! cargo test -p dpma-tests --test apps-discovery -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! The test container's network namespace has no interface but `lo`, on
//! which `cargo xtask test` turns multicast on and routes 224.0.0.0/4, so
//! that the mDNS announcements never reach a real network.  Without such
//! a network namespace (an interface other than `lo`, or `lo` without
//! multicast), the mDNS checks are skipped and service discovery stays
//! off.

mod apps;
mod discovery;
mod settings;

use std::process::{Command, ExitCode};

use anyhow::Result;
use bstr::BString;
use dpma_tests::harness::{fixtures, ConfFile, Ctx, Instance, Suite};

const VM_PHONE_CONF: &str = include_str!("../../data/methods-vm/res_digium_phone.conf");
const VM_VOICEMAIL_CONF: &str = include_str!("../../data/methods-vm/voicemail.conf");
const VM_DIALPLAN: &str = include_str!("../../data/methods-vm/extensions_dpma_vm.conf");
const APPS_DIALPLAN: &str = include_str!("../../data/apps-discovery/extensions_dpma_apps.conf");

/// The test tone (in the sounds directory).
pub const TONE: &str = "dpma-apps-tone";

/// A WAV file: 8 kHz, 16-bit mono.
fn wav(samples: &[i16]) -> Vec<u8> {
    let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    for v in [
        16u32.to_le_bytes(),
        [1, 0, 1, 0],
        8000u32.to_le_bytes(),
        16000u32.to_le_bytes(),
        [2, 0, 16, 0],
    ] {
        out.extend_from_slice(&v);
    }
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend(data);
    out
}

/// The test setup.
fn setup(inst: &Instance) -> Result<()> {
    std::fs::write(inst.conf("res_digium_phone.conf"), VM_PHONE_CONF)?;
    std::fs::write(inst.conf("voicemail.conf"), VM_VOICEMAIL_CONF)?;
    let ext = ConfFile::new(&inst.conf("extensions.conf"));
    for (name, text) in [
        ("extensions_dpma_vm.conf", VM_DIALPLAN),
        ("extensions_dpma_apps.conf", APPS_DIALPLAN),
    ] {
        std::fs::write(inst.conf(name), text)?;
        ext.add_include(name)?;
    }
    let vm = inst.spool().join("voicemail");
    for b in ["default/1001", "default/1002", "default/1003", "other/2001"] {
        let d = vm.join(b);
        if d.exists() {
            std::fs::remove_dir_all(d)?;
        }
    }
    let sounds = inst.var_lib().join("sounds");
    std::fs::create_dir_all(&sounds)?;
    let samples: Vec<i16> = (0..3 * 8000)
        .map(|i| {
            (8000.0 * (2.0 * std::f64::consts::PI * 440.0 * f64::from(i) / 8000.0).sin()) as i16
        })
        .collect();
    std::fs::write(sounds.join(format!("{TONE}.wav")), wav(&samples))?;
    Ok(())
}

/// A CLI command through AMI's `Command` action: its output lines.
pub fn cli(ctx: &mut Ctx, command: &str) -> Vec<BString> {
    ctx.ami()
        .ok()
        .and_then(|a| a.command(command).ok())
        .unwrap_or_default()
}

/// A CLI command's exact output through the control socket.
pub fn cli_raw(ctx: &Ctx, command: &str) -> String {
    // (The remote console's own notice inside a namespace without
    // ethernet.)
    ctx.cli_text(command)
        .split_inclusive('\n')
        .filter(|l| !l.starts_with("No ethernet interface found for seeding global EID"))
        .collect()
}

/// Replaces `[general]` of `res_digium_phone.conf` (from `original`) with
/// `options` and reloads the module (through AMI).
pub fn set_general(ctx: &mut Ctx, original: &[u8], options: &[(&str, &[u8])]) -> Result<()> {
    let f = ConfFile::new(&ctx.inst.conf("res_digium_phone.conf"));
    f.write(original)?;
    let lines: Vec<Vec<u8>> = options
        .iter()
        .map(|(k, v)| [k.as_bytes(), b"=", v].concat())
        .collect();
    let refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
    f.replace_section("general", &refs)?;
    cli(ctx, "module reload res_dpma_rs.so");
    Ok(())
}

/// Runs `f` with the current `res_digium_phone.conf`, then puts it back
/// and reloads the module.
pub fn with_conf(ctx: &mut Ctx, f: impl FnOnce(&mut Ctx, &[u8]) -> Result<()>) -> Result<()> {
    let path = ctx.inst.conf("res_digium_phone.conf");
    let original = std::fs::read(&path)?;
    let r = f(ctx, &original);
    std::fs::write(&path, &original)?;
    cli(ctx, "module reload res_dpma_rs.so");
    r
}

/// Whether the network namespace's only interface is `lo`, with multicast
/// on (`ip -o link`).
fn isolated() -> bool {
    let Ok(out) = Command::new("ip").args(["-o", "link"]).output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    names == ["lo"] && text.contains("MULTICAST")
}

fn main() -> ExitCode {
    let discovery_ok = isolated();
    Suite::new("apps-discovery")
        .prepare(|inst| fixtures::prepare(inst, setup))
        .part("applications", apps::registered)
        .part("controlplayback", apps::controlplayback)
        .part("vm-playback", apps::vm_playback)
        .part("show-settings", move |ctx| settings::run(ctx, discovery_ok))
        .part("mdns", move |ctx| {
            if discovery_ok {
                discovery::run(ctx)
            } else {
                ctx.c.skip(
                    "mDNS checks",
                    "not in a network namespace whose only interface is lo, with multicast",
                );
                Ok(())
            }
        })
        .main()
}
