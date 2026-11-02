//! `dpma-ami`: sends an AMI action and prints the response and the events
//! that follow it (see `dpma_tests::ami`).
//!
//! ```text
//! dpma-ami [options] ACTION [Key=Value | "Key: Value"]...
//! dpma-ami [options] --listen SECONDS
//! ```
//!
//! Logs in to the AMI port of 127.0.0.1 as test/test.  For list actions it
//! waits for `EventList: Complete`; otherwise it prints the events of the
//! next `--events` seconds.  Exit status 0 when the response is
//! `Success`.

use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;
use dpma_tests::ami::{default_port, parse_fields, AmiClient};

#[derive(Parser)]
#[command(
    name = "dpma-ami",
    about = "Send an AMI action and print the response and events."
)]
struct Args {
    /// Action name.
    action: Option<String>,
    /// Key=Value or 'Key: Value'.
    fields: Vec<String>,
    /// AMI host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// AMI port (default: from --slot or $DPMA_SLOT).
    #[arg(long)]
    port: Option<u16>,
    /// Instance slot.
    #[arg(long)]
    slot: Option<u32>,
    /// AMI user.
    #[arg(long, default_value = "test")]
    user: String,
    /// AMI secret.
    #[arg(long, default_value = "test")]
    secret: String,
    /// Seconds to print events after a non-list response.
    #[arg(long, default_value_t = 1.0)]
    events: f64,
    /// After the response, wait (up to --events seconds) for this event, print it, and exit.
    #[arg(long, value_name = "NAME")]
    wait_event: Option<String>,
    /// Print all events for SECONDS (no action needed).
    #[arg(long, value_name = "SECONDS")]
    listen: Option<f64>,
}

fn out(text: &[u8]) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(text);
    let _ = o.flush();
}

fn main() -> ExitCode {
    let a = Args::parse();
    if a.action.is_none() && a.listen.is_none() {
        eprintln!("dpma-ami: an action or --listen is required");
        return ExitCode::from(2);
    }
    let slot = a
        .slot
        .or_else(|| std::env::var("DPMA_SLOT").ok().and_then(|s| s.parse().ok()));
    let port = a.port.unwrap_or_else(|| default_port(slot));
    let ami = match AmiClient::connect(
        &a.host,
        port,
        &a.user,
        &a.secret,
        true,
        Duration::from_secs(10),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("dpma-ami: {}:{port}: {e:#}", a.host);
            return ExitCode::from(2);
        }
    };
    ami.drain_events(); // FullyBooted, SuccessfulAuth, ... from the login
    let mut ok = true;
    if let Some(action) = &a.action {
        let fields = match parse_fields(&a.fields) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("dpma-ami: {e}");
                return ExitCode::from(2);
            }
        };
        let res = ami.action(action, fields);
        out(&res.text());
        ok = res.success();
        let wait = Duration::from_secs_f64(a.events.max(0.0));
        if let Some(name) = &a.wait_event {
            match ami.wait_event(Some(name), &[], wait) {
                Some(ev) => {
                    out(b"\n");
                    out(&ev.text());
                }
                None => {
                    eprintln!("dpma-ami: no {name} event within {} s", a.events);
                    ok = false;
                }
            }
        } else if res.events.is_empty() && a.events > 0.0 {
            std::thread::sleep(wait);
            for ev in ami.drain_events() {
                out(b"\n");
                out(&ev.text());
            }
        }
    }
    if let Some(secs) = a.listen {
        let deadline = Instant::now() + Duration::from_secs_f64(secs.max(0.0));
        while Instant::now() < deadline {
            if let Some(ev) = ami.wait_event(
                None,
                &[],
                deadline.saturating_duration_since(Instant::now()),
            ) {
                out(&ev.text());
                out(b"\n");
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
