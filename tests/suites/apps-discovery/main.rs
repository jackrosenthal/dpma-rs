//! The apps-discovery suite: the dialplan applications
//! DigiumControlPlayback and DigiumVoicemailPlayback, `digium_phones show
//! settings`, and the mDNS announcement (package P14; the Rust form of
//! `tests/apps-discovery/run.sh`, `run.py`, `netns.sh`, and
//! `mdns_probe.py`).
//!
//! ```text
//! export DPMA_SLOT=<n> ASTERISK_SOURCE_DIR=$PWD/dev/asterisk-builds/24.0.0-rc4/src
//! cargo build -p res_dpma_rs --features devtest
//! cargo test -p dpma-tests --test apps-discovery -- --ignored [--no-prepare] [-v] [PART...]
//! ```
//!
//! Prerequisites: a private instance (`DPMA_SLOT`), a devtest build of the
//! module, unprivileged user namespaces (`unshare -rn`), and `ip` and `ss`
//! (iproute2).
//!
//! The suite runs itself again inside a private network namespace
//! ([`dpma_tests::netns`]) whose only interface is `lo`, so that the mDNS
//! announcements never reach a real network, and runs Asterisk there:
//! inside, it prepares the instance (fresh configuration, the voicemail
//! setup of the methods-vm suite, this suite's dialplan
//! `extensions_dpma_apps.conf`, a 3 second test tone
//! `<astvarlibdir>/sounds/dpma-apps-tone.wav`, the debug build installed,
//! Asterisk restarted; with `--no-prepare`, Asterisk is only restarted,
//! since it must run inside the namespace), runs the parts, and stops
//! Asterisk at the end.
//!
//! | Part | Checks |
//! |---|---|
//! | `applications` | Both applications are registered |
//! | `controlplayback` | Local channels into extensions that run DigiumControlPlayback and Asterisk's ControlPlayback with the same arguments and DTMF (sent from the other half): the result variables (`CPLAYBACKSTATUS`, `CPLAYBACKSTOPKEY`, `CPLAYBACKOFFSET`, read back from AstDB) agree, have the expected values, and the log has the usage and invalid-key messages and the debug lines of the keys |
//! | `vm-playback` | A message left in 1001@default, then DigiumVoicemailPlayback with good and bad arguments and DTMF: `VOICEMAIL_PLAYBACKSTATUS` and the usage message |
//! | `show-settings` | `digium_phones show settings` for several `[general]` configurations, compared with the original's format strings, and `digium_phones show version` |
//! | `mdns` | The service, port, TXT records, and address for several configurations (legacy unicast queries through [`dpma_tests::mdns`]); announcements and goodbyes at reload, disable, unload, load, Asterisk shutdown, and startup (this restarts Asterisk); names Avahi refuses; the responder socket |
//!
//! The parts that change `[general]` of `res_digium_phone.conf` put the
//! file back (and reload the module) at their end.

mod apps;
mod discovery;
mod settings;

use std::process::ExitCode;

use anyhow::Result;
use bstr::BString;
use dpma_tests::harness::{fixtures, ConfFile, Ctx, Instance, Suite};
use dpma_tests::netns;

const VM_PHONE_CONF: &str = include_str!("../../data/apps-discovery/res_digium_phone.conf");
const VM_VOICEMAIL_CONF: &str = include_str!("../../data/apps-discovery/voicemail.conf");
const VM_DIALPLAN: &str = include_str!("../../data/apps-discovery/extensions_dpma_vm.conf");
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

/// The test setup: the methods-vm suite's voicemail setup (phones whose
/// lines have mailboxes, `voicemail.conf`, the dialplan that leaves
/// messages, the test mailboxes' spool emptied), this suite's dialplan,
/// and the 3 second 440 Hz test tone.
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

/// A CLI command through AMI's `Command` action (as the old suite's
/// `cli`): its output lines.
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |a: &str| args.iter().any(|x| x == a);
    let run = has("--ignored") || has("--include-ignored");
    if run && !has("--list") && !netns::inside() {
        println!("suite apps-discovery: running inside a private network namespace (unshare -rn)");
        return netns::reexec().unwrap_or_else(|e| {
            println!("FAIL suite apps-discovery: {e:#}");
            ExitCode::FAILURE
        });
    }
    let inst = if netns::inside() {
        let setup = netns::setup_loopback().and_then(|()| Instance::from_env());
        match setup {
            Ok(i) => Some(i),
            Err(e) => {
                println!("FAIL suite apps-discovery: {e:#}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    // Asterisk must run inside the namespace: restart it there even
    // without the preparation.
    if let (Some(i), true) = (&inst, has("--no-prepare")) {
        if let Err(e) = i.start().and_then(|()| fixtures::check_devtest(i)) {
            println!("FAIL suite apps-discovery: {e:#}");
            return ExitCode::FAILURE;
        }
    }
    let discovery_ok = netns::isolated();
    let code = Suite::new("apps-discovery")
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
                    "not inside a private network namespace whose only interface is lo",
                );
                Ok(())
            }
        })
        .main();
    if let Some(i) = inst {
        let _ = i.stop();
    }
    code
}
