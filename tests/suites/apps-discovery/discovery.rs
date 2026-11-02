//! The mDNS announcement: the service, port, TXT records, and address
//! for several configurations; announcements and goodbyes at reload,
//! disable, unload, load, Asterisk shutdown, and startup (this restarts
//! Asterisk).  Queries are legacy unicast ([`dpma_tests::mdns`]), on the
//! test container's loopback interface.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::Result;
use bstr::ByteSlice;
use dpma_tests::harness::{fixtures, Ctx};
use dpma_tests::mdns::{self, rtype, Heard, Listener, RecordData, ServiceInstance, SERVICE};
use regex::bytes::Regex;

use crate::{cli, cli_raw, set_general, with_conf};

const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;
const MODULE: &str = "res_dpma_rs.so";

type Found = BTreeMap<String, ServiceInstance>;

fn browse(wait: f64) -> Found {
    mdns::browse(SERVICE, LO, Duration::from_secs_f64(wait)).unwrap_or_default()
}

/// Browses until `pred` holds (or `timeout` seconds); returns the last
/// result.
fn wait_browse(pred: impl Fn(&Found) -> bool, timeout: f64) -> Found {
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    let mut found = Found::new();
    while Instant::now() < deadline {
        found = browse(0.5);
        if pred(&found) {
            return found;
        }
        fixtures::sleep(0.1);
    }
    found
}

/// Waits up to `timeout` seconds until the listener heard, since `mark`,
/// a PTR record of the service for every instance in `names` (goodbyes
/// when `goodbye`); whether it did.
fn heard(lst: &Listener, mark: usize, goodbye: bool, names: &[&str], timeout: f64) -> bool {
    dpma_tests::util::wait_until(
        Duration::from_secs_f64(timeout),
        Duration::from_millis(50),
        || {
            let got = ptrs(&lst.since(mark), goodbye);
            names.iter().all(|n| got.contains(*n))
        },
    )
}

/// Waits up to three seconds until Asterisk holds no mDNS socket; the
/// sockets it still holds.
fn mdns_sockets_closed() -> Vec<String> {
    dpma_tests::util::wait_until(Duration::from_secs(3), Duration::from_millis(50), || {
        asterisk_mdns_sockets().is_empty()
    });
    asterisk_mdns_sockets()
}

fn has(name: &str) -> impl Fn(&Found) -> bool + '_ {
    move |f| f.contains_key(name)
}

fn names(found: &Found) -> Vec<String> {
    found.keys().cloned().collect()
}

/// Instance labels in PTR records for the service (goodbyes, or not).
fn ptrs(records: &[Heard], ttl_zero: bool) -> BTreeSet<String> {
    records
        .iter()
        .map(|h| &h.record)
        .filter(|r| {
            r.rtype == rtype::PTR
                && r.name.trim_end_matches('.') == SERVICE
                && (r.ttl == 0) == ttl_zero
        })
        .filter_map(|r| match &r.data {
            RecordData::Ptr(t) => Some(mdns::instance_label(t, SERVICE)),
            _ => None,
        })
        .collect()
}

/// The UDP sockets on port 5353 that Asterisk holds (`ss -ulnp`).
fn asterisk_mdns_sockets() -> Vec<String> {
    let out = Command::new("ss")
        .arg("-ulnp")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    out.lines()
        .filter(|l| l.contains(":5353 ") && l.contains("asterisk"))
        .map(str::to_string)
        .collect()
}

/// The SRV target the module announces: the host name's first label and
/// `-dpma.local.`.
fn host_name() -> String {
    let h = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    format!(
        "{}-dpma.local.",
        h.trim().split('.').next().unwrap_or_default()
    )
}

fn port(found: &Found, name: &str) -> Option<u16> {
    found.get(name).and_then(|i| i.port)
}

fn txt(found: &Found, name: &str) -> Option<Vec<String>> {
    found.get(name).and_then(|i| i.txt.clone())
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The part.
pub fn run(ctx: &mut Ctx) -> Result<()> {
    with_conf(ctx, checks)
}

fn checks(ctx: &mut Ctx, orig: &[u8]) -> Result<()> {
    let lst = Listener::start(LO)?;
    let log = ctx.log();

    // Announce with every option set.
    let mark = lst.mark();
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("mdns_address", b"10.1.2.3"),
            ("mdns_port", b"5070"),
            ("mdns_transport", b"tcp"),
            ("service_name", b"P14 Test Server"),
        ],
    )?;
    let found = wait_browse(has("P14 Test Server"), 8.0);
    let c = &mut ctx.c;
    c.same(
        "mDNS: one instance",
        names(&found),
        strings(&["P14 Test Server"]),
    );
    c.same("mDNS: port", port(&found, "P14 Test Server"), Some(5070));
    c.same(
        "mDNS: TXT records",
        txt(&found, "P14 Test Server"),
        Some(strings(&[
            "serviceType=asterisk",
            "sipUrl=sip:proxy@10.1.2.3:5070;transport=tcp",
        ])),
    );
    c.same(
        "mDNS: SRV target",
        found.get("P14 Test Server").and_then(|i| i.target.clone()),
        Some(host_name()),
    );
    c.same(
        "mDNS: target addresses (A, AAAA)",
        found.get("P14 Test Server").map(|i| i.addresses.clone()),
        Some(strings(&["127.0.0.1", "::1"])),
    );
    c.same(
        "mDNS: announced (unsolicited)",
        heard(&lst, mark, false, &["P14 Test Server"], 3.0),
        true,
    );
    let types = mdns::query(
        "_services._dns-sd._udp.local",
        rtype::PTR,
        LO,
        Duration::from_secs_f64(0.7),
    )
    .unwrap_or_default();
    c.same(
        "mDNS: service type enumeration",
        types
            .iter()
            .filter_map(|r| match &r.data {
                RecordData::Ptr(t) if r.rtype == rtype::PTR => Some(t.clone()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![format!("{SERVICE}.")],
    );
    c.same(
        "mDNS: one responder socket set",
        !asterisk_mdns_sockets().is_empty(),
        true,
    );

    // Reload with another name and no address: goodbye, then the new
    // one.
    let mark = lst.mark();
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", b"P14 Renamed"),
        ],
    )?;
    let found = wait_browse(has("P14 Renamed"), 8.0);
    let c = &mut ctx.c;
    c.same(
        "mDNS reload: only the new instance",
        names(&found),
        strings(&["P14 Renamed"]),
    );
    c.same(
        "mDNS reload: default port",
        port(&found, "P14 Renamed"),
        Some(5060),
    );
    c.same(
        "mDNS reload: TXT without sipUrl",
        txt(&found, "P14 Renamed"),
        Some(strings(&["serviceType=asterisk"])),
    );
    c.same(
        "mDNS reload: goodbye for the old name",
        heard(&lst, mark, true, &["P14 Test Server"], 3.0),
        true,
    );
    c.same(
        "mDNS reload: new name announced",
        heard(&lst, mark, false, &["P14 Renamed"], 3.0),
        true,
    );

    // Same configuration again: withdrawn and announced again (as
    // Avahi's group reset).
    let mark = lst.mark();
    cli(ctx, "module reload res_dpma_rs.so");
    let c = &mut ctx.c;
    c.same(
        "mDNS unchanged reload: goodbye",
        heard(&lst, mark, true, &["P14 Renamed"], 3.0),
        true,
    );
    c.same(
        "mDNS unchanged reload: announced again",
        heard(&lst, mark, false, &["P14 Renamed"], 3.0),
        true,
    );

    // Port arithmetic, registration address fallback, and a long sipUrl.
    let long_addr = "h".repeat(300);
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", b"P14 Port"),
            ("registration_address", b"10.7.7.7"),
            ("mdns_port", b"70000"),
        ],
    )?;
    let found = wait_browse(has("P14 Port"), 8.0);
    ctx.c.same(
        "mDNS: port 70000 & 0xffff",
        port(&found, "P14 Port"),
        Some((70000 & 0xffff) as u16),
    );
    ctx.c.same(
        "mDNS: registration_address as mdns_address",
        txt(&found, "P14 Port"),
        Some(strings(&[
            "serviceType=asterisk",
            "sipUrl=sip:proxy@10.7.7.7:70000",
        ])),
    );
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", b"P14 Long"),
            ("mdns_address", long_addr.as_bytes()),
            ("mdns_transport", b"udp"),
        ],
    )?;
    let found = wait_browse(has("P14 Long"), 8.0);
    let want: String = format!("sipUrl=sip:proxy@{long_addr}:5060;transport=udp")
        .chars()
        .take(255)
        .collect();
    ctx.c.same(
        "mDNS: sipUrl cut to 255 bytes",
        txt(&found, "P14 Long").unwrap_or_default(),
        vec!["serviceType=asterisk".to_string(), want],
    );

    // Names Avahi refuses are not announced; 63 bytes is the limit.  (A
    // reload withdraws the old name first, then announces the new one
    // or nothing.)
    let n64 = "N".repeat(64);
    let n63 = "N".repeat(63);
    let mark = lst.mark();
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", n64.as_bytes()),
        ],
    )?;
    heard(&lst, mark, true, &["P14 Long"], 3.0);
    ctx.c.same(
        "mDNS: 64-byte name not announced",
        browse(0.7),
        Found::new(),
    );
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", n63.as_bytes()),
        ],
    )?;
    let found = wait_browse(has(&n63), 8.0);
    ctx.c.same(
        "mDNS: 63-byte name announced",
        names(&found),
        vec![n63.clone()],
    );
    // A name that is not valid UTF-8 (Latin-1 "Café") is not announced;
    // an error is logged instead (`mdns-sd` takes UTF-8 names only).
    let mark = log.mark();
    let lmark = lst.mark();
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", b"P14 Caf\xe9"),
        ],
    )?;
    heard(&lst, lmark, true, &[&n63], 3.0);
    ctx.c.same(
        "mDNS: non-UTF-8 name not announced",
        browse(0.7),
        Found::new(),
    );
    let re = Regex::new(r"(?-u)ERROR\[[^\n]*Service name 'P14 Caf\xE9' is not valid UTF-8")
        .expect("valid");
    let text = log.since(mark);
    ctx.c.check(
        "mDNS: non-UTF-8 name logged as an error",
        re.is_match(&text),
        "",
    );
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", b"P14 dotted.name"),
        ],
    )?;
    let found = wait_browse(has("P14 dotted.name"), 8.0);
    ctx.c.same(
        "mDNS: name with a dot",
        names(&found),
        strings(&["P14 dotted.name"]),
    );

    // Disabled: goodbye, no answers, no socket.
    let mark = lst.mark();
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"no"),
            ("service_name", b"P14 Off"),
        ],
    )?;
    let c = &mut ctx.c;
    c.same(
        "mDNS disabled: goodbye",
        heard(&lst, mark, true, &["P14 dotted.name"], 3.0),
        true,
    );
    c.same(
        "mDNS disabled: nothing announced",
        browse(0.7),
        Found::new(),
    );
    c.same(
        "mDNS disabled: no responder socket",
        mdns_sockets_closed(),
        Vec::<String>::new(),
    );

    // Unload and load the module.
    set_general(
        ctx,
        orig,
        &[
            ("service_discovery_enabled", b"yes"),
            ("service_name", b"P14 Lifecycle"),
        ],
    )?;
    wait_browse(has("P14 Lifecycle"), 8.0);
    let mark = lst.mark();
    // (AMI's Command refuses "module load" and "module unload".)
    let out = cli_raw(ctx, &format!("module unload {MODULE}"));
    ctx.c.same(
        format!("unload {MODULE}"),
        out,
        format!("Unloaded {MODULE}\n"),
    );
    let c = &mut ctx.c;
    c.same(
        "mDNS unload: goodbye",
        heard(&lst, mark, true, &["P14 Lifecycle"], 3.0),
        true,
    );
    c.same("mDNS unload: nothing announced", browse(0.7), Found::new());
    c.same(
        "mDNS unload: no responder socket",
        mdns_sockets_closed(),
        Vec::<String>::new(),
    );
    let mark = lst.mark();
    let out = cli_raw(ctx, &format!("module load {MODULE}"));
    ctx.c
        .same(format!("load {MODULE}"), out, format!("Loaded {MODULE}\n"));
    let found = wait_browse(has("P14 Lifecycle"), 8.0);
    ctx.c.same(
        "mDNS load: announced again",
        names(&found),
        strings(&["P14 Lifecycle"]),
    );
    ctx.c.same(
        "mDNS load: unsolicited announcement",
        heard(&lst, mark, false, &["P14 Lifecycle"], 3.0),
        true,
    );
    // Again: the responder was started from the AMI session's thread (the
    // reload above), which keeps the module's image mapped after an
    // unload; the loader's dlclose must still succeed every time
    // (dpma_ast::module::reopen_if_restarted).
    let pos = log.mark();
    let out = cli_raw(ctx, &format!("module unload {MODULE}"));
    ctx.c.same(
        format!("unload {MODULE} again"),
        out,
        format!("Unloaded {MODULE}\n"),
    );
    let out = cli_raw(ctx, &format!("module load {MODULE}"));
    ctx.c.same(
        format!("load {MODULE} again"),
        out,
        format!("Loaded {MODULE}\n"),
    );
    wait_browse(has("P14 Lifecycle"), 8.0);
    cli_raw(ctx, &format!("module unload {MODULE}"));
    cli_raw(ctx, &format!("module load {MODULE}"));
    fixtures::sleep(0.5);
    let text = log.since(pos);
    let failed: Vec<String> = text
        .lines()
        .filter(|l| l.contains_str("Failure in dlclose"))
        .map(|l| l.to_str_lossy().into_owned())
        .collect();
    ctx.c.same(
        "unload and load twice more: dlclose succeeds",
        failed,
        Vec::<String>::new(),
    );

    // Asterisk shutdown and startup (discovery enabled in the file).
    ctx.drop_ami();
    let mark = lst.mark();
    ctx.inst.stop()?;
    ctx.c.same(
        "mDNS shutdown: goodbye",
        heard(&lst, mark, true, &["P14 Lifecycle"], 3.0),
        true,
    );
    let mark = lst.mark();
    ctx.inst.start()?;
    ctx.ami()?;
    let found = wait_browse(has("P14 Lifecycle"), 15.0);
    ctx.c.same(
        "mDNS startup: announced",
        names(&found),
        strings(&["P14 Lifecycle"]),
    );
    ctx.c.same(
        "mDNS startup: unsolicited announcement",
        heard(&lst, mark, false, &["P14 Lifecycle"], 3.0),
        true,
    );
    Ok(())
}
