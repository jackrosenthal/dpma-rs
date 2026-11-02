//! The dialplan applications: Local channels into extensions running each
//! application (`extensions_dpma_apps.conf`), with DTMF sent from the
//! other half; the result variables (`CPLAYBACKSTATUS`,
//! `CPLAYBACKSTOPKEY`, `CPLAYBACKOFFSET`, `VOICEMAIL_PLAYBACKSTATUS`) are
//! read back from AstDB.  DigiumControlPlayback is compared with
//! Asterisk's own ControlPlayback on the same cases.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use anyhow::Result;
use bstr::ByteSlice;
use dpma_tests::harness::{fixtures, regex_search, Ctx};
use regex::Regex;

use crate::{cli, cli_raw, TONE};

/// The result variables of a test: status, stop key, offset, and
/// voicemail status (`None`: the test stored no result).
type Results = BTreeMap<String, Option<Vec<String>>>;

/// Originates `Local/<app>@dpma-apps` for test `tid`; the other half
/// sends `keys`, one per `gap` seconds.
fn originate(ctx: &mut Ctx, app: &str, tid: &str, args: &str, keys: &str, gap: &str) -> Result<()> {
    cli(ctx, &format!("database del dpma-apps {tid}"));
    let fields = [
        ("Channel", format!("Local/{app}@dpma-apps")),
        ("Context", "dpma-apps-keys".into()),
        ("Exten", "keys".into()),
        ("Priority", "1".into()),
        ("Async", "true".into()),
        ("Variable", format!("P14ID={tid}")),
        (
            "Variable",
            format!("P14ARGS={}", fixtures::ami_var_escape(args)),
        ),
        ("Variable", format!("P14KEYS={keys}")),
        ("Variable", format!("P14GAP={gap}")),
    ];
    let res = ctx.ami()?.action("Originate", fields);
    let ok = res
        .response
        .as_ref()
        .and_then(|r| r.get("Response"))
        .is_some_and(|v| v == "Success");
    if !ok {
        let detail = res
            .response
            .as_ref()
            .map(|r| r.text().to_str_lossy().into_owned())
            .unwrap_or_else(|| "no response".into());
        ctx.c.check(format!("originate {tid}"), false, detail);
    }
    Ok(())
}

/// The results of `tids` once every test stored its result (or after
/// `timeout`).
fn results(ctx: &mut Ctx, tids: &[String], timeout: Duration) -> Results {
    let mut out: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && out.len() < tids.len() {
        for t in tids {
            if out.contains_key(t) {
                continue;
            }
            let lines = cli(ctx, &format!("database get dpma-apps {t}"));
            if let Some(v) = lines
                .first()
                .and_then(|l| l.strip_prefix(b"Value: "))
                .map(|v| v.to_str_lossy().into_owned())
            {
                out.insert(t.clone(), Some(v.split('|').map(str::to_string).collect()));
            }
        }
        fixtures::sleep(0.05);
    }
    for t in tids {
        out.entry(t.clone()).or_insert(None);
    }
    out
}

/// Two offsets within `tol` ms of each other (or equal texts when they
/// are not numbers).
fn near(a: &str, b: &str, tol: i64) -> bool {
    match (a.parse::<i64>(), b.parse::<i64>()) {
        (Ok(x), Ok(y)) => (x - y).abs() <= tol,
        _ => a == b,
    }
}

/// A test case: id, arguments, DTMF keys, the gap between keys, and
/// whether it is comparable with ControlPlayback.
struct Case {
    id: &'static str,
    args: String,
    keys: &'static str,
    gap: &'static str,
    comparable: bool,
}

fn cases() -> Vec<Case> {
    let c = |id, args: &str, keys, gap, comparable| Case {
        id,
        args: args.to_string(),
        keys,
        gap,
        comparable,
    };
    vec![
        c("play", TONE, "", "1", true),
        c("stop", &format!("{TONE},,,,5"), "5", "0.7", true),
        c(
            "offset",
            &format!("{TONE},,,,5,,,o(1500)"),
            "5",
            "0.7",
            true,
        ),
        c("ff", &format!("{TONE},1000,,,5"), "#5", "0.5", true),
        c(
            "rew",
            &format!("{TONE},1000,,,5,,,o(2000)"),
            "*5",
            "0.5",
            true,
        ),
        c(
            "customkeys",
            &format!("{TONE},1000,1,2,5"),
            "15",
            "0.5",
            true,
        ),
        c("stopdefault", &format!("{TONE},,,,#"), "#", "0.7", true),
        c("stopinvalidff", &format!("{TONE},,x,,#"), "#", "0.7", true),
        c("restart", &format!("{TONE},,,,5,,0"), "05", "0.7", true),
        c("skipzero", &format!("{TONE},abc,,,5"), "#5", "0.3", true),
        c("missing", "dpma-apps-no-such-file", "", "1", true),
        c("noargs", "", "", "1", true),
        c("invalid", &format!("{TONE},,x,y,z,w,v"), "", "1", true),
        c(
            "callback",
            &format!("{TONE},1000,,,5,,,u"),
            "#*5",
            "0.4",
            false,
        ),
    ]
}

/// `got` with the fields `want` does not care about (`None`) masked.
fn masked(got: Option<&Vec<String>>, want: &[Option<&str>; 4]) -> Option<Vec<Option<String>>> {
    got.map(|d| {
        d.iter()
            .enumerate()
            .map(|(i, x)| want.get(i).copied().flatten().map(|_| x.clone()))
            .collect()
    })
}

fn wanted(want: &[Option<&str>; 4]) -> Option<Vec<Option<String>>> {
    Some(want.iter().map(|w| w.map(str::to_string)).collect())
}

/// Both applications are registered.
pub fn registered(ctx: &mut Ctx) -> Result<()> {
    for app in ["DigiumControlPlayback", "DigiumVoicemailPlayback"] {
        let out = cli_raw(ctx, &format!("core show application {app}"));
        ctx.c.same(
            format!("core show application {app}"),
            out.contains(&format!("-= Info about Application '{app}' =-")),
            true,
        );
    }
    Ok(())
}

/// DigiumControlPlayback, compared with ControlPlayback.
pub fn controlplayback(ctx: &mut Ctx) -> Result<()> {
    cli(ctx, "core set debug 1 res_dpma_rs");
    let log = ctx.log();
    let mark = log.mark();
    let cases = cases();
    for c in &cases {
        originate(ctx, "dcp", &format!("dcp-{}", c.id), &c.args, c.keys, c.gap)?;
        originate(ctx, "acp", &format!("acp-{}", c.id), &c.args, c.keys, c.gap)?;
    }
    let tids: Vec<String> = cases
        .iter()
        .map(|c| format!("dcp-{}", c.id))
        .chain(cases.iter().map(|c| format!("acp-{}", c.id)))
        .collect();
    let res = results(ctx, &tids, Duration::from_secs(20));
    let text = log.since(mark);
    cli(ctx, "core set debug 0 res_dpma_rs");
    let get = |tid: &str| res.get(tid).cloned().flatten();
    for case in &cases {
        let d = get(&format!("dcp-{}", case.id));
        let a = get(&format!("acp-{}", case.id));
        ctx.c.check(
            format!("DigiumControlPlayback {} ran", case.id),
            d.is_some(),
            "",
        );
        if let (true, Some(d), Some(a)) = (case.comparable, &d, &a) {
            let ok = d.get(..2) == a.get(..2)
                && near(
                    d.get(2).map_or("", String::as_str),
                    a.get(2).map_or("", String::as_str),
                    120,
                );
            ctx.c.check(
                format!("DigiumControlPlayback {} like ControlPlayback", case.id),
                ok,
                format!("Digium: {d:?}\nAsterisk: {a:?}"),
            );
        }
    }
    let want: [(&str, [Option<&str>; 4]); 8] = [
        ("play", [Some("SUCCESS"), Some(""), Some("-1"), Some("")]),
        ("stop", [Some("USERSTOPPED"), Some("5"), None, Some("")]),
        (
            "stopdefault",
            [Some("USERSTOPPED"), Some("#"), None, Some("")],
        ),
        (
            "stopinvalidff",
            [Some("USERSTOPPED"), Some("#"), None, Some("")],
        ),
        ("missing", [Some("ERROR"), Some(""), Some("-1"), Some("")]),
        ("noargs", [Some(""), Some(""), Some(""), Some("")]),
        ("invalid", [Some("SUCCESS"), Some(""), Some("-1"), Some("")]),
        ("callback", [Some("USERSTOPPED"), Some("5"), None, Some("")]),
    ];
    for (tid, w) in &want {
        let d = get(&format!("dcp-{tid}"));
        ctx.c.same(
            format!("DigiumControlPlayback {tid} variables"),
            masked(d.as_ref(), w),
            wanted(w),
        );
    }
    let d = get("dcp-offset");
    ctx.c.check(
        "DigiumControlPlayback o(1500) starts at 1.5 s",
        d.as_ref()
            .and_then(|d| d.get(2))
            .and_then(|v| v.parse::<i64>().ok())
            .is_some_and(|v| 1500 < v && v < 2700),
        format!("{d:?}"),
    );
    ctx.c.same(
        "usage logged without arguments",
        regex_search(
            r"DPMA\[\d+\](\[[^\]]*\])? apps.rs: DigiumControlPlayback requires an argument \(filename\)",
            &text,
        ),
        true,
    );
    // "invalid" has five invalid keys, "stopinvalidff" an invalid
    // forward key.
    for (what, count) in [
        ("Invalid fast forward key specified.", 2),
        ("Invalid rewind key specified.", 1),
        ("Invalid stop specified.", 1),
        ("Invalid pause key specified.", 1),
        ("Invalid restart key specified.", 1),
    ] {
        ctx.c.same(
            format!("logged: {what}"),
            text.find_iter(what).count(),
            count,
        );
    }
    ctx.c.same(
        "debug: default keys",
        text.contains_str("Forward key = #, Rewind key = *"),
        true,
    );
    ctx.c.same(
        "debug: '#' used as the stop key: the empty forward key stays",
        text.contains_str("Forward key = , Rewind key = *"),
        true,
    );
    ctx.c.same(
        "debug: '#' used as the stop key: the invalid forward key stays NULL",
        text.contains_str("Forward key = (null), Rewind key = *"),
        true,
    );
    ctx.c.same(
        "debug: custom keys",
        text.contains_str("Forward key = 1, Rewind key = 2"),
        true,
    );
    ctx.c.same(
        "no panics",
        text.contains_str("Internal error (panic)"),
        false,
    );
    Ok(())
}

/// Leaves a message in 1001@default (the methods-vm dialplan); returns
/// its id.
fn leave_message(ctx: &mut Ctx) -> Result<Option<String>> {
    let inbox = ctx.inst.spool().join("voicemail/default/1001/INBOX");
    let list = |d: &std::path::Path| -> BTreeSet<String> {
        std::fs::read_dir(d)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = list(&inbox);
    ctx.ami()?.action(
        "Originate",
        [
            ("Channel", "Local/1001@dpma-vm-leave"),
            ("Context", "dpma-vm-source"),
            ("Exten", "tone"),
            ("Priority", "1"),
            ("CallerID", "\"P14\" <5551234>"),
            ("Async", "true"),
        ],
    );
    let re = Regex::new(r"(?m)^msg_id=(.*)$").expect("valid");
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let now = list(&inbox);
        for f in now.difference(&before).filter(|f| f.ends_with(".txt")) {
            let text = String::from_utf8_lossy(&std::fs::read(inbox.join(f)).unwrap_or_default())
                .into_owned();
            if let (Some(m), true) = (re.captures(&text), text.contains("duration=")) {
                return Ok(Some(m[1].to_string()));
            }
        }
        fixtures::sleep(0.2);
    }
    Ok(None)
}

/// DigiumVoicemailPlayback.
pub fn vm_playback(ctx: &mut Ctx) -> Result<()> {
    let msg_id = leave_message(ctx)?;
    ctx.c.check("message left for 1001", msg_id.is_some(), "");
    let Some(msg_id) = msg_id else {
        return Ok(());
    };
    let log = ctx.log();
    let mark = log.mark();
    let cases = [
        ("vm-noargs", String::new(), ""),
        ("vm-nomsg", "1001@default,INBOX".to_string(), ""),
        ("vm-emptyfolder", format!("1001@default,,{msg_id}"), ""),
        ("vm-ok", format!("1001@default,INBOX,{msg_id}"), ""),
        ("vm-nocontext", format!("1001,INBOX,{msg_id}"), ""),
        ("vm-bad", "1001@default,INBOX,no-such-id".to_string(), ""),
        ("vm-keys", format!("1001@default,INBOX,{msg_id}"), "#*"),
        ("vm-pause", format!("1001@default,INBOX,{msg_id}"), "00"),
    ];
    for (tid, args, keys) in &cases {
        originate(ctx, "vmp", tid, args, keys, "0.4")?;
    }
    let tids: Vec<String> = cases.iter().map(|c| c.0.to_string()).collect();
    let res = results(ctx, &tids, Duration::from_secs(20));
    let text = log.since(mark);
    let want = [
        ("vm-noargs", ""),
        ("vm-nomsg", ""),
        ("vm-emptyfolder", ""),
        ("vm-ok", "SUCCESS"),
        ("vm-nocontext", "SUCCESS"),
        ("vm-bad", "FAILED"),
        ("vm-keys", "SUCCESS"),
        ("vm-pause", "SUCCESS"),
    ];
    for (tid, status) in want {
        ctx.c.same(
            format!("DigiumVoicemailPlayback {tid}"),
            res.get(tid).cloned().flatten(),
            Some(vec![
                String::new(),
                String::new(),
                String::new(),
                status.to_string(),
            ]),
        );
    }
    ctx.c.same(
        "usage logged three times",
        text.find_iter("DigiumVoicemailPlayback requires arguments (mailbox|folder|message)")
            .count(),
        3,
    );
    ctx.c.same(
        "no panics",
        text.contains_str("Internal error (panic)"),
        false,
    );
    Ok(())
}
