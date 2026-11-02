//! The line locking stress test for the module's PJSIP side.
//!
//! Phase 1: ARI updates of auth 2005-auth and endpoint 2005 make the PJSIP
//! side's sorcery observers rewrite line 2005 on their own threads (clear
//! the settings, then set them), while readers run `dpmadev config 2003`,
//! which reads the line's account from phone 2003's configuration
//! document, over and over.  The document must always show a complete
//! line.  Before readers took the line's ao2 lock, a read could land
//! between the clearing and the setting.
//!
//! Phase 2: the same plus res_dpma_rs and res_pjsip reloads (full
//! processing passes, also from a sorcery thread).  A pass has its own
//! intermediate states (as in the official DPMA), so only deadlocks are
//! checked: every CLI command and ARI request must answer in time.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use dpma_tests::ari::Ari;
use dpma_tests::harness::{fixtures, Cli, Ctx, Instance};
use regex::bytes::Regex;

use crate::{restart, ARI_USER, HTTP_PORT};

/// How long a CLI command or ARI request may take.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Line 2005's account in phone 2003's configuration document.
static ACCOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<account \n(?:[^<]*?)account_id="2005"(?P<rest>[^<]*?)/?>"#).expect("valid")
});

/// What a read saw: password, authname, and caller ID.
type Sample = (Option<String>, Option<String>, Option<String>);

#[derive(Default)]
struct Stats {
    reads: usize,
    bad: usize,
    updates: usize,
    reloads: usize,
    timeouts: usize,
    samples: Vec<Sample>,
}

struct Shared {
    inst: Instance,
    ari: Ari,
    stop: AtomicBool,
    stats: Mutex<Stats>,
}

impl Shared {
    /// A CLI command with the time limit; `None` (and a timeout
    /// counted) when it takes that long.  When Asterisk does not answer
    /// at all, the output is empty.
    fn cli(&self, cmd: &str) -> Option<Vec<u8>> {
        let t = Instant::now();
        let out = self
            .inst
            .cli()
            .and_then(|c| Cli::timeout(c, TIMEOUT).run(cmd))
            .map(|o| o.to_vec())
            .unwrap_or_default();
        if t.elapsed() >= TIMEOUT {
            self.stats.lock().unwrap().timeouts += 1;
            return None;
        }
        Some(out)
    }

    /// An ARI push configuration update; a failure (no answer in time, or
    /// an HTTP error status) is counted as a timeout.
    fn ari(&self, path: &str, fields: &[(&str, &str)]) {
        let (ty, id) = path.split_once('/').unwrap_or((path, ""));
        let ok = self
            .ari
            .put_dynamic_config("res_pjsip", ty, id, fields)
            .is_ok_and(|status| status < 400);
        if !ok {
            self.stats.lock().unwrap().timeouts += 1;
        }
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

fn updater(sh: &Shared, auth: bool) {
    let mut i = 0;
    while !sh.stopped() {
        i += 1;
        let ab = if i % 2 == 1 { "A" } else { "B" };
        if auth {
            sh.ari("auth/2005-auth", &[("password", &format!("pw{ab}"))]);
        } else {
            sh.ari(
                "endpoint/2005",
                &[("callerid", &format!("\"{ab}\" <2005>"))],
            );
        }
        sh.stats.lock().unwrap().updates += 1;
    }
}

fn attribute(rest: &[u8], name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"{name}="([^"]*)""#)).expect("valid");
    re.captures(rest)
        .map(|c| String::from_utf8_lossy(&c[1]).into_owned())
}

fn reader(sh: &Shared, check: bool) {
    while !sh.stopped() {
        let Some(text) = sh.cli("dpmadev config 2003") else {
            continue;
        };
        let rest = ACCOUNT
            .captures(&text)
            .map(|c| c["rest"].to_vec())
            .unwrap_or_default();
        let got: Sample = (
            attribute(&rest, "password"),
            attribute(&rest, "authname"),
            attribute(&rest, "caller_id"),
        );
        let ok = matches!(got.0.as_deref(), Some("pwA" | "pwB"))
            && got.1.as_deref() == Some("ari5")
            && matches!(
                got.2.as_deref(),
                Some("&quot;A&quot; &lt;2005&gt;" | "&quot;B&quot; &lt;2005&gt;")
            );
        let mut st = sh.stats.lock().unwrap();
        st.reads += 1;
        if check && !ok {
            st.bad += 1;
            if st.samples.len() < 5 {
                st.samples.push(got);
            }
        }
    }
}

fn reloader(sh: &Shared) {
    let mut i = 0;
    while !sh.stopped() {
        i += 1;
        sh.cli(if i % 2 == 1 {
            "module reload res_dpma_rs.so"
        } else {
            "module reload res_pjsip.so"
        });
        sh.stats.lock().unwrap().reloads += 1;
        fixtures::sleep(0.5);
    }
}

/// One phase: the updaters and readers (and the reloader) for `seconds`;
/// whether Asterisk still answers afterwards.
fn phase(sh: &Shared, seconds: f64, check: bool, reloads: bool) -> bool {
    sh.stop.store(false, Ordering::SeqCst);
    *sh.stats.lock().unwrap() = Stats::default();
    std::thread::scope(|scope| {
        scope.spawn(|| updater(sh, true));
        scope.spawn(|| updater(sh, false));
        for _ in 0..3 {
            scope.spawn(|| reader(sh, check));
        }
        if reloads {
            scope.spawn(|| reloader(sh));
        }
        fixtures::sleep(seconds);
        sh.stop.store(true, Ordering::SeqCst);
    });
    sh.cli("core show uptime").is_some_and(|o| {
        String::from_utf8_lossy(&o)
            .to_lowercase()
            .contains("uptime")
    })
}

pub fn run(ctx: &mut Ctx, seconds: f64) -> Result<()> {
    restart(ctx)?;
    let sh = Shared {
        inst: ctx.inst.clone(),
        ari: Ari::with_timeout("127.0.0.1", HTTP_PORT, ARI_USER.0, ARI_USER.1, TIMEOUT),
        stop: AtomicBool::new(false),
        stats: Mutex::new(Stats::default()),
    };
    sh.ari(
        "auth/2005-auth",
        &[
            ("auth_type", "userpass"),
            ("username", "ari5"),
            ("password", "pwA"),
        ],
    );
    sh.ari(
        "endpoint/2005",
        &[
            ("context", "test-phones"),
            ("allow", "!all,ulaw"),
            ("aors", "2005"),
            ("auth", "2005-auth"),
            ("callerid", "\"A\" <2005>"),
        ],
    );
    fixtures::sleep(1.0);

    let alive = phase(&sh, seconds, true, false);
    {
        let st = sh.stats.lock().unwrap();
        ctx.c.note(format!(
            "phase 1: {} reads, {} incomplete, {} updates, {} timeouts",
            st.reads, st.bad, st.updates, st.timeouts
        ));
        let samples: Vec<String> = st
            .samples
            .iter()
            .map(|(p, a, c)| format!("incomplete: password={p:?} authname={a:?} caller_id={c:?}"))
            .collect();
        ctx.c.check("phase 1: Asterisk responsive", alive, "");
        ctx.c.check(
            "phase 1: every read saw a complete line",
            st.bad == 0,
            format!(
                "{} of {} reads incomplete\n{}",
                st.bad,
                st.reads,
                samples.join("\n")
            ),
        );
        ctx.c.check(
            "phase 1: no CLI or ARI timeouts",
            st.timeouts == 0,
            format!("{} timeouts", st.timeouts),
        );
        ctx.c.check(
            "phase 1: reads done",
            st.reads > 0,
            format!("{} reads", st.reads),
        );
    }

    let alive = phase(&sh, seconds, false, true);
    {
        let st = sh.stats.lock().unwrap();
        ctx.c.note(format!(
            "phase 2: {} reads, {} updates, {} reloads, {} timeouts",
            st.reads, st.updates, st.reloads, st.timeouts
        ));
        ctx.c.check("phase 2: Asterisk responsive", alive, "");
        ctx.c.check(
            "phase 2: no CLI or ARI timeouts",
            st.timeouts == 0,
            format!("{} timeouts", st.timeouts),
        );
    }
    let _ = sh
        .ari
        .delete_dynamic_config("res_pjsip", "endpoint", "2005");
    Ok(())
}
