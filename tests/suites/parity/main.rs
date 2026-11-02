//! The parity suite: compares the CLI and AMI output of res_dpma_rs with
//! the original binary's (`res_digium_phone.so` 24.0_3.6.13), byte for
//! byte, for every command and action that needs no connected phone.
//! The Rust form of `tests/parity/run.py`.
//!
//! ```text
//! export DPMA_SLOT=<n> ASTERISK_SOURCE_DIR=$PWD/dev/asterisk-builds/24.0.0-rc4/src
//! cargo build -p res_dpma_rs
//! cargo test -p dpma-tests --test parity -- --ignored [--no-prepare] [-v] [--keep DIR] [--original DIR] [PART...]
//! cargo test -p dpma-tests --test parity -- --capture ours|original [--keep DIR]
//! cargo test -p dpma-tests --test parity -- [-v] --compare A B
//! ```
//!
//! Prerequisites: a private instance (`DPMA_SLOT`) of Asterisk 24
//! (24.0.0-rc4; the original binary is built for Asterisk 24, so the
//! suite refuses older releases) and the original binaries:
//! `res_digium_phone.so`, `res_pjsip_endpoint_identifier_dpma.so`, and
//! `res_pjsip_dialog_info_digium_body_supplement.so` in `--original DIR`
//! (default `res_digium_phone-24.0_3.6.13-x86_64/` in the repository,
//! which is not committed).  The original binaries go into the private
//! instance's module directory only, never into a shared install.
//!
//! The suite prepares the instance (Asterisk stopped, a fresh
//! configuration, and the test configuration below; then a check of the
//! Asterisk release with our module; `--no-prepare` skips this) and runs
//! these parts:
//!
//! | Part | What it does |
//! |---|---|
//! | `ours` | Installs res_dpma_rs (the debug build; installing it removes the original modules), starts Asterisk, captures, and stops Asterisk |
//! | `original` | Removes res_dpma_rs from the module directory, copies the three original modules into it, starts Asterisk, captures, and stops Asterisk; then installs res_dpma_rs again (and removes the original modules), whatever happened |
//! | `compare` | Compares the two captures: one check per item |
//!
//! The captures go to `--keep DIR` (default `<instance>/parity`), each in
//! its own directory (`ours`, `original`), one file per item, with the
//! list of items (`ITEMS`) and whether the module was licensed
//! (`LICENSED`).
//!
//! `--capture ours|original` captures the module currently running in
//! the instance into `<keep>/ours` or `<keep>/original` (no install,
//! start, or configuration change); `--compare A B` compares two capture
//! directories (ours, then the original's) without an instance.
//! Relative paths in options are relative to the repository root (Cargo
//! runs test targets in `tests/`).
//!
//! # The test configuration
//!
//! The config-xml suite's test configuration (phones, lines, external
//! lines, networks, applications, alerts, ringtones, firmware profiles,
//! multicast pages, and a firmware package file;
//! [`dpma_tests::harness::setup::config_xml`], from
//! `tests/data/config-xml/`) plus two translation tables.
//!
//! # The items
//!
//! - `core show help digium_phones` and every command's usage;
//! - every `digium_phones` command: each list, each object of the
//!   configuration by name, an unknown name, and wrong argument counts;
//!   `show status` for every phone; `reconfigure` for a phone without a
//!   session, an unknown phone, and all;
//! - `manager show command` for each AMI action, and each action's raw
//!   response and events (DPMAShowPhones, DPMAShowIncidents,
//!   DPMARemoveIncident, DigiumPhoneReconfigure(All), and the DPMAMessage*
//!   actions where no phone is involved).
//!
//! Each item is "same", "DIFF" (a failed check, shown with both outputs as
//! a unified diff), "deviation" (a documented difference, plan section 8:
//! show version, license status, and the fields of item 15), or "not in
//! the original".  `-v` also shows the differences of deviations and of
//! items that are not in the original.
//!
//! The original without a license (no licenses under
//! `<astvardir>/licenses`) loads disabled: it registers only `show
//! settings`, `show version`, and `license status`, and its `show
//! settings` crashes Asterisk because no configuration is loaded, so that
//! capture skips everything else ("not in the original").  That is
//! expected: the license check is never bypassed.  So a run compares 3
//! items as the same, 6 as documented deviations, and 115 as "not in the
//! original", and must report 0 differences.
//!
//! # Changes from the Python version
//!
//! - The captures go to `<instance>/parity` by default, not to a new
//!   temporary directory; a capture first removes the files of the
//!   previous capture in its directory.
//! - The prepare step fails early when the original binaries are missing
//!   or the instance is not of Asterisk 24.
//! - The AMI client frames messages by lines, where `run.py` split at
//!   `\r\n\r\n`: DigiumPhoneReconfigure's "Phone has not contacted the
//!   server" error, as the module sends it, ends its last line with a bare
//!   `\n`, so `run.py` glued it to the next action's response.
//!   Each item now has its own response.  Both sides are captured the same
//!   way, so this changes no comparison.
//! - One more check: that res_dpma_rs is installed again and the original
//!   modules are gone after the `original` part.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bstr::ByteSlice;
use dpma_tests::harness::{fixtures, setup, Checker, ConfFile, Instance, Suite};
use dpma_tests::{diff, sim};
use regex::bytes::Regex;

/// The original modules.  Ours replaces all three: only one side may be
/// in the module directory at a time.
const MODULES: [&str; 3] = [
    "res_digium_phone.so",
    "res_pjsip_endpoint_identifier_dpma.so",
    "res_pjsip_dialog_info_digium_body_supplement.so",
];
/// Our module.
const OURS: &str = "res_dpma_rs.so";

/// Two translation tables, appended to the config-xml test
/// configuration.
const TRANSLATIONS: &str = "
[p15-trans]
type=translation
INBOX=Neue
Old=Alte
Work=Arbeit

[p15-empty]
type=translation
";

/// Items that differ by design (plan section 8).
const DEVIATIONS: [(&str, &str); 6] = [
    ("cli: digium_phones show version", "section 8, item 5"),
    ("cli: digium_phones license status", "section 8, item 1"),
    ("help: digium_phones license status", "section 8, item 1"),
    // AuthName, Logout Extension, and Send486 (the test configuration's
    // external line with a server, its queue application, and its status
    // application with send486=yes).
    ("cli: digium_phones show line ext1234", "section 8, item 15"),
    (
        "cli: digium_phones show application queue-app",
        "section 8, item 15",
    ),
    (
        "cli: digium_phones show application status-app",
        "section 8, item 15",
    ),
];

/// The commands without an object name.
const COMMANDS: [&str; 13] = [
    "show phones",
    "show lines",
    "show networks",
    "show alerts",
    "show multicastpages",
    "show applications",
    "show firmwares",
    "show sessions",
    "show tokens",
    "show translations",
    "show settings",
    "show version",
    "license status",
];

/// The `show <object>` commands and the configuration section types of
/// their objects.
const PER_OBJECT: [(&str, &[&str]); 9] = [
    ("phone", &["phone"]),
    ("line", &["line", "external_line"]),
    ("network", &["network"]),
    ("alert", &["alert"]),
    ("multicastpage", &["multicastpage"]),
    ("application", &["application"]),
    ("firmware", &["firmware"]),
    ("translation", &["translation"]),
    ("status", &["phone"]),
];

/// The AMI actions.
const AMI_ACTIONS: [&str; 8] = [
    "DPMAShowPhones",
    "DPMAShowIncidents",
    "DPMARemoveIncident",
    "DigiumPhoneReconfigure",
    "DigiumPhoneReconfigureAll",
    "DPMAMessageRegister",
    "DPMAMessageResponse",
    "DPMAMessageSend",
];

/// The command-line options of the suite (the others go to the
/// [`Suite`]).
#[derive(Clone, Debug)]
struct Opts {
    keep: Option<PathBuf>,
    original: PathBuf,
    capture: Option<String>,
    compare: Option<(PathBuf, PathBuf)>,
    verbose: bool,
    rest: Vec<String>,
}

/// A path from the command line: relative to the repository root.
fn path(p: String) -> PathBuf {
    sim::repo_root().join(p)
}

fn parse_opts(args: impl IntoIterator<Item = String>) -> Result<Opts> {
    let mut o = Opts {
        keep: None,
        original: sim::repo_root().join("res_digium_phone-24.0_3.6.13-x86_64"),
        capture: None,
        compare: None,
        verbose: false,
        rest: Vec::new(),
    };
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = |what: &str| {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or_else(|| anyhow!("{what} needs a value"))
        };
        match name.as_str() {
            "--keep" => o.keep = Some(path(value("--keep")?)),
            "--original" => o.original = path(value("--original")?),
            "--capture" => {
                let v = value("--capture")?;
                if v != "ours" && v != "original" {
                    bail!("--capture ours|original, not {v:?}");
                }
                o.capture = Some(v);
            }
            "--compare" => {
                let a = value("--compare")?;
                let b = args
                    .next()
                    .ok_or_else(|| anyhow!("--compare needs two directories"))?;
                o.compare = Some((path(a), path(b)));
            }
            _ => {
                if a == "-v" || a == "--verbose" {
                    o.verbose = true;
                }
                o.rest.push(a);
            }
        }
    }
    Ok(o)
}

fn keep_dir(opts: &Opts, inst: &Instance) -> PathBuf {
    opts.keep.clone().unwrap_or_else(|| inst.dir.join("parity"))
}

/// Runs a CLI command; its exact output (empty when Asterisk does not
/// answer).
fn cli(inst: &Instance, cmd: &str) -> Vec<u8> {
    inst.cli_run(cmd).map(|o| o.to_vec()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Configuration and the original binaries
// ---------------------------------------------------------------------------

/// Installs the test configuration into a fresh copy of the scratch
/// configuration (Asterisk stopped).
fn install_config(inst: &Instance) -> Result<()> {
    inst.stop()?;
    inst.reset_conf()?;
    setup::config_xml(inst)?;
    let path = inst.conf("res_digium_phone.conf");
    let conf = ConfFile::new(&path);
    let mut data = conf.read()?;
    data.extend_from_slice(TRANSLATIONS.as_bytes());
    conf.write(data)
}

/// The release of the running Asterisk (`core show version`).
fn asterisk_version(inst: &Instance) -> String {
    inst.cli_text("core show version")
        .lines()
        .find_map(|l| Some(l.strip_prefix("Asterisk ")?.split_once(' ')?.0.to_string()))
        .unwrap_or_default()
}

/// Fails unless the original binaries are in `dir`.
fn check_original(dir: &Path) -> Result<()> {
    let missing: Vec<&str> = MODULES
        .iter()
        .copied()
        .filter(|m| !dir.join(m).is_file())
        .collect();
    if !missing.is_empty() {
        bail!(
            "the original binaries are not in {} (missing {}; see --original)",
            dir.display(),
            missing.join(", ")
        );
    }
    Ok(())
}

/// The prepare step: the test configuration, and checks that the
/// original binaries are there and that the instance runs Asterisk 24
/// (started with our module for that, and stopped again).
fn prepare(inst: &Instance, original: &Path) -> Result<()> {
    check_original(original)?;
    install_config(inst)?;
    inst.install("debug")?;
    inst.start()?;
    let version = asterisk_version(inst);
    inst.stop()?;
    let major = version
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok());
    if major.is_some_and(|m| m < 24) {
        bail!(
            "the original binary is built for Asterisk 24; this instance runs Asterisk {version} \
             (use an instance of 24.0.0-rc4)"
        );
    }
    println!("     Asterisk {version}");
    Ok(())
}

/// The instance's module directory, which must be inside the private
/// instance.
fn private_modules_dir(inst: &Instance) -> Result<PathBuf> {
    let dir = inst.modules_dir();
    let real = dir
        .canonicalize()
        .with_context(|| dir.display().to_string())?;
    let home = inst
        .dir
        .canonicalize()
        .with_context(|| inst.dir.display().to_string())?;
    if !real.starts_with(&home) {
        bail!(
            "the module directory {} is not inside the private instance {}: not installing the original binaries there",
            real.display(),
            home.display()
        );
    }
    Ok(dir)
}

/// Replaces our module with the original three in the private instance's
/// module directory (Asterisk stopped).
fn install_original(inst: &Instance, original: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    check_original(original)?;
    let dir = private_modules_dir(inst)?;
    match std::fs::remove_file(dir.join(OURS)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    for m in MODULES {
        let dest = dir.join(m);
        let tmp = dir.join(format!("{m}.new"));
        std::fs::copy(original.join(m), &tmp).with_context(|| tmp.display().to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&tmp, &dest).with_context(|| dest.display().to_string())?;
    }
    Ok(())
}

/// Installs our module again and makes sure the original modules are
/// gone (Asterisk stopped).
fn restore_ours(inst: &Instance) -> Result<()> {
    inst.stop()?;
    inst.install("debug")?;
    let dir = inst.modules_dir();
    for m in MODULES {
        match std::fs::remove_file(dir.join(m)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Items and captures
// ---------------------------------------------------------------------------

/// `{type: [names]}` of the instance's `res_digium_phone.conf`.
fn sections(inst: &Instance) -> BTreeMap<String, Vec<String>> {
    static HEADER: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^\[([^\]]+)\]").expect("valid"));
    static TYPE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^type\s*=").expect("valid"));
    let text = std::fs::read(inst.conf("res_digium_phone.conf")).unwrap_or_default();
    let text = text.to_str_lossy();
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or_default().trim();
        if let Some(c) = HEADER.captures(line) {
            name = Some(c[1].to_string());
        } else if let Some(n) = name.as_deref().filter(|n| *n != "general") {
            if TYPE.is_match(line) {
                let ty = line
                    .split_once('=')
                    .map(|(_, v)| v.trim())
                    .unwrap_or_default();
                out.entry(ty.to_string()).or_default().push(n.to_string());
            }
        }
    }
    out
}

/// The CLI items: (item, command).
fn cli_items(inst: &Instance) -> Vec<(String, String)> {
    let s = sections(inst);
    let names_of = |t: &str| s.get(t).cloned().unwrap_or_default();
    let mut items = vec![(
        "help: core show help digium_phones".to_string(),
        "core show help digium_phones".to_string(),
    )];
    let usage: BTreeSet<String> = COMMANDS
        .iter()
        .map(|c| c.to_string())
        .chain(PER_OBJECT.iter().map(|(k, _)| format!("show {k}")))
        .chain([
            "reconfigure phone".to_string(),
            "reconfigure all".to_string(),
        ])
        .collect();
    items.extend(usage.iter().map(|c| {
        (
            format!("help: digium_phones {c}"),
            format!("core show help digium_phones {c}"),
        )
    }));
    items.extend(COMMANDS.iter().map(|c| {
        (
            format!("cli: digium_phones {c}"),
            format!("digium_phones {c}"),
        )
    }));
    for (cmd, types) in PER_OBJECT {
        let mut names: Vec<String> = types.iter().flat_map(|t| names_of(t)).collect();
        if cmd == "network" {
            names.extend(names_of("phone")); // the networks named after phones
        }
        names.push("p15-nosuch".into());
        for n in names {
            items.push((
                format!("cli: digium_phones show {cmd} {n}"),
                format!("digium_phones show {cmd} {n}"),
            ));
        }
        items.push((
            format!("cli: digium_phones show {cmd} (no name)"),
            format!("digium_phones show {cmd}"),
        ));
    }
    for (item, cmd) in [
        (
            "cli: digium_phones show phones extra",
            "digium_phones show phones extra",
        ),
        (
            "cli: digium_phones show lines extra",
            "digium_phones show lines extra",
        ),
        (
            "cli: digium_phones show phone two names",
            "digium_phones show phone minphone extra",
        ),
        (
            "cli: digium_phones reconfigure phone minphone",
            "digium_phones reconfigure phone minphone",
        ),
        (
            "cli: digium_phones reconfigure phone p15-nosuch",
            "digium_phones reconfigure phone p15-nosuch",
        ),
        (
            "cli: digium_phones reconfigure phone (no name)",
            "digium_phones reconfigure phone",
        ),
        (
            "cli: digium_phones reconfigure all",
            "digium_phones reconfigure all",
        ),
    ] {
        items.push((item.into(), cmd.into()));
    }
    items
}

/// An AMI item: `manager show command` (a CLI command) or an action with
/// its fields.
enum AmiItem {
    Help(String, String),
    Action(
        &'static str,
        &'static str,
        Vec<(&'static str, &'static str)>,
    ),
}

/// An action item: the item, the action, and its fields.
type ActionItem = (
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
);

fn ami_items() -> Vec<AmiItem> {
    let mut items: Vec<AmiItem> = AMI_ACTIONS
        .iter()
        .map(|a| {
            AmiItem::Help(
                format!("ami-help: {a}"),
                format!("manager show command {a}"),
            )
        })
        .collect();
    let actions: [ActionItem; 13] = [
        ("ami: DPMAShowPhones", "DPMAShowPhones", vec![]),
        ("ami: DPMAShowIncidents", "DPMAShowIncidents", vec![]),
        (
            "ami: DPMARemoveIncident (none)",
            "DPMARemoveIncident",
            vec![],
        ),
        (
            "ami: DPMARemoveIncident unknown",
            "DPMARemoveIncident",
            vec![("IPAddress", "192.0.2.99")],
        ),
        (
            "ami: DigiumPhoneReconfigure minphone",
            "DigiumPhoneReconfigure",
            vec![("PhoneName", "minphone")],
        ),
        (
            "ami: DigiumPhoneReconfigure unknown",
            "DigiumPhoneReconfigure",
            vec![("PhoneName", "p15-nosuch")],
        ),
        (
            "ami: DigiumPhoneReconfigure (none)",
            "DigiumPhoneReconfigure",
            vec![],
        ),
        (
            "ami: DigiumPhoneReconfigureAll",
            "DigiumPhoneReconfigureAll",
            vec![],
        ),
        (
            "ami: DPMAMessageRegister (none)",
            "DPMAMessageRegister",
            vec![],
        ),
        (
            "ami: DPMAMessageRegister",
            "DPMAMessageRegister",
            vec![("Method", "com.p15.parity")],
        ),
        (
            "ami: DPMAMessageResponse unknown",
            "DPMAMessageResponse",
            vec![
                ("RequestID", "p15-nosuch"),
                ("Format", "json"),
                ("Response", "x"),
            ],
        ),
        (
            "ami: DPMAMessageSend no session",
            "DPMAMessageSend",
            vec![
                ("PhoneName", "minphone"),
                ("Method", "p15.event"),
                ("Message", "hello"),
            ],
        ),
        (
            "ami: DPMAMessageSend unknown",
            "DPMAMessageSend",
            vec![("PhoneName", "p15-nosuch"), ("Method", "x")],
        ),
    ];
    items.extend(
        actions
            .into_iter()
            .map(|(i, a, f)| AmiItem::Action(i, a, f)),
    );
    items
}

/// The file name of an item's capture.
fn fname(item: &str) -> String {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"[^A-Za-z0-9_.-]+").expect("valid"));
    RE.replace_all(item, "_").into_owned()
}

/// Removes an earlier capture's files from `dir` (those its `ITEMS`
/// names), so that items skipped now do not show old output.
fn clear_capture(dir: &Path) {
    if let Ok(items) = std::fs::read_to_string(dir.join("ITEMS")) {
        for item in items.lines().filter(|l| !l.is_empty()) {
            let _ = std::fs::remove_file(dir.join(fname(item)));
        }
    }
    let _ = std::fs::remove_file(dir.join("ITEMS"));
    let _ = std::fs::remove_file(dir.join("LICENSED"));
}

/// Captures every item from the module running in the instance into
/// `outdir`.
fn capture(inst: &Instance, outdir: &Path, which: &str, c: &Checker) -> Result<()> {
    std::fs::create_dir_all(outdir).with_context(|| outdir.display().to_string())?;
    clear_capture(outdir);
    let help = cli(inst, "core show help digium_phones");
    let licensed = help.contains_str("digium_phones show phones");
    if !licensed {
        c.note(format!(
            "{which}: only {} digium_phones commands registered (the original without a license)",
            help.find_iter("digium_phones ").count() / 2
        ));
    }
    let mut results: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    for (item, cmd) in cli_items(inst) {
        let skip = !licensed
            && (item.starts_with("cli: digium_phones show settings")
                || !(item.starts_with("help:")
                    || item.starts_with("cli: digium_phones show version")
                    || item.starts_with("cli: digium_phones license status")));
        let data = (!skip).then(|| cli(inst, &cmd));
        results.push((item, data));
    }
    let ami = inst.ami()?;
    for (seq, it) in ami_items().into_iter().enumerate() {
        match it {
            AmiItem::Help(item, cmd) => {
                let data = cli(inst, &cmd);
                results.push((item, Some(data)));
            }
            AmiItem::Action(item, action, fields) => {
                // The ActionID is part of the captured bytes, so both sides
                // number their actions the same way.
                let id = format!("parity-{}", seq + 1);
                let mut f = vec![("ActionID", id.as_str())];
                f.extend(fields);
                let res = ami.action_timeout(action, f, Duration::from_secs(3));
                let mut data = res.response.map(|r| r.raw().to_vec()).unwrap_or_default();
                for e in &res.events {
                    data.extend_from_slice(e.raw());
                }
                results.push((item.to_string(), Some(data)));
            }
        }
    }
    for (item, data) in &results {
        if let Some(d) = data {
            let path = outdir.join(fname(item));
            std::fs::write(&path, d).with_context(|| path.display().to_string())?;
        }
    }
    let items: String = results.iter().map(|(i, _)| format!("{i}\n")).collect();
    std::fs::write(outdir.join("ITEMS"), items)?;
    std::fs::write(
        outdir.join("LICENSED"),
        if licensed { "yes\n" } else { "no\n" },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Comparing
// ---------------------------------------------------------------------------

/// Not captured, or the command or action does not exist (`manager show
/// command` prints nothing for an unknown action).
fn unavailable(data: Option<&[u8]>, item: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:No such command '|No manager action |Response: Error\r\n(?:ActionID: [^\r]*\r\n)?Message: Invalid/unknown command)",
        )
        .expect("valid")
    });
    match data {
        None => true,
        Some(d) => (item.starts_with("ami-help:") && d.is_empty()) || RE.is_match(d),
    }
}

/// The first field of a `core show help` line (the command).
fn help_command(line: &[u8]) -> &[u8] {
    line.split_str(" -- ")
        .next()
        .unwrap_or_default()
        .trim_ascii()
}

/// Compares the captures in `a` (ours) and `b` (the original's), one
/// check per item; the number of differences.
fn compare(a: &Path, b: &Path, c: &mut Checker, verbose: bool) -> Result<usize> {
    let items = std::fs::read_to_string(a.join("ITEMS"))
        .with_context(|| a.join("ITEMS").display().to_string())?;
    let licensed = std::fs::read_to_string(b.join("LICENSED"))
        .with_context(|| b.join("LICENSED").display().to_string())?
        .trim()
        == "yes";
    let deviations: BTreeMap<&str, &str> = DEVIATIONS.into_iter().collect();
    let read = |d: &Path, item: &str| std::fs::read(d.join(fname(item))).ok();
    let (mut diffs, mut counts) = (0, BTreeMap::<&str, usize>::new());
    for item in items.lines().filter(|l| !l.is_empty()) {
        let (mut ours, mut orig) = (read(a, item), read(b, item));
        let mut subset = false;
        if item == "help: core show help digium_phones" && !licensed {
            if let (Some(o), Some(g)) = (&ours, &orig) {
                if !o.is_empty() && !g.is_empty() {
                    // Compare the commands the original registers without a
                    // license (license status aside, section 8, item 1).
                    let have: BTreeSet<&[u8]> = g.split_str("\n").map(help_command).collect();
                    let o2 = o
                        .split_str("\n")
                        .filter(|l| have.contains(help_command(l)))
                        .collect::<Vec<_>>()
                        .join(&b"\n"[..]);
                    let g2 = g
                        .split_str("\n")
                        .filter(|l| !l.starts_with(b"digium_phones license status"))
                        .collect::<Vec<_>>()
                        .join(&b"\n"[..]);
                    ours = Some(o2);
                    orig = Some(g2);
                    subset = true;
                }
            }
        }
        let (word, note) = if ours == orig {
            ("same", subset.then_some("registered subset"))
        } else if let Some(d) = deviations.get(item) {
            ("deviation", Some(*d))
        } else if unavailable(orig.as_deref(), item) {
            ("not in the original", None)
        } else {
            diffs += 1;
            ("DIFF", None)
        };
        *counts.entry(word).or_default() += 1;
        let status = match note {
            Some(n) => format!("{word} ({n})"),
            None => word.to_string(),
        };
        let shown = |d: &Option<Vec<u8>>| {
            d.as_deref()
                .unwrap_or_default()
                .to_str_lossy()
                .replace('\r', "\\r")
        };
        let show_diff = word == "DIFF" || (verbose && word != "same");
        let detail = if show_diff {
            diff::unified(&shown(&orig), &shown(&ours), "original", "ours", 2)
        } else {
            String::new()
        };
        c.check(format!("{item}: {status}"), word != "DIFF", detail);
    }
    let summary: Vec<String> = counts.iter().map(|(w, n)| format!("{n} {w}")).collect();
    c.note(format!("{diffs} difference(s) ({})", summary.join(", ")));
    Ok(diffs)
}

/// `--compare A B`.
fn compare_main(a: &Path, b: &Path, verbose: bool) -> ExitCode {
    let mut c = Checker::new().verbose(verbose);
    match compare(a, b, &mut c, verbose) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("parity: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// `--capture ours|original`.
fn capture_main(opts: &Opts, which: &str) -> ExitCode {
    let res = (|| -> Result<PathBuf> {
        let inst = Instance::from_env()?;
        let dir = keep_dir(opts, &inst).join(which);
        capture(&inst, &dir, which, &Checker::new())?;
        Ok(dir)
    })();
    match res {
        Ok(dir) => {
            println!("capture in {}", dir.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("parity: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let opts = match parse_opts(std::env::args().skip(1)) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("parity: {e:#}");
            return ExitCode::from(2);
        }
    };
    if let Some((a, b)) = &opts.compare {
        return compare_main(a, b, opts.verbose);
    }
    if let Some(which) = &opts.capture {
        return capture_main(&opts, which);
    }
    let (o1, o2, o3, o4) = (opts.clone(), opts.clone(), opts.clone(), opts.clone());
    Suite::new("parity")
        .prepare(move |inst| prepare(inst, &o1.original))
        .part("ours", move |ctx| {
            let dir = keep_dir(&o2, &ctx.inst).join("ours");
            ctx.inst.stop()?;
            ctx.inst.install("debug")?;
            ctx.inst.start()?;
            fixtures::sleep(1.0);
            let res = capture(&ctx.inst, &dir, "ours", &ctx.c);
            ctx.drop_ami();
            ctx.inst.stop()?;
            res?;
            ctx.c.note(format!("capture in {}", dir.display()));
            Ok(())
        })
        .part("original", move |ctx| {
            let dir = keep_dir(&o3, &ctx.inst).join("original");
            let res = (|| -> Result<()> {
                ctx.inst.stop()?;
                install_original(&ctx.inst, &o3.original)?;
                ctx.inst.start()?;
                fixtures::sleep(1.0);
                capture(&ctx.inst, &dir, "original", &ctx.c)
            })();
            ctx.drop_ami();
            let restored = restore_ours(&ctx.inst);
            ctx.c.check(
                "res_dpma_rs installed again, the original modules removed",
                restored.is_ok(),
                restored
                    .as_ref()
                    .err()
                    .map(|e| format!("{e:#}"))
                    .unwrap_or_default(),
            );
            res?;
            ctx.c.note(format!("capture in {}", dir.display()));
            Ok(())
        })
        .part("compare", move |ctx| {
            let keep = keep_dir(&o4, &ctx.inst);
            let verbose = ctx.verbose;
            compare(
                &keep.join("ours"),
                &keep.join("original"),
                &mut ctx.c,
                verbose,
            )?;
            Ok(())
        })
        .main_with_args(opts.rest)
}
