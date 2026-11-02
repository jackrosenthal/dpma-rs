//! Test hooks for the PJSIP side (feature "devtest").

use crate::users::objects::{self, LineObj, UserObj};
use dpma_ast::bformat;
use dpma_ast::channel::Channel;
use dpma_ast::cli::{CliArgs, CliCommand, CliResult};
use std::os::raw::c_void;

/// The reference count of `obj` (without changing it).
fn refs<T>(obj: &T) -> i32 {
    // SAFETY: the caller holds a reference on the ao2 object.
    unsafe { dpma_ast::ao2::ao2_ref(obj as *const T as *mut c_void, 0) }
}

fn cmd_line(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let Some(line) = objects::find_line(&dpma_ast::cstr(&a.argv[3])) else {
        a.out(bformat!("phone_line_find('{}') returned NULL\n", a.argv[3]));
        return CliResult::Success;
    };
    let l: &LineObj = &line;
    a.out(bformat!(
        "object {:p} name '{}' refs {} (with ours) linked {}\npjsip_auth (object): '{}'\n",
        l,
        l.name().to_bytes(),
        refs(l),
        l.is_linked(),
        l.pjsip_auth(),
    ));
    if let Some(phone) = crate::users::runtime::phone_for_line(l.key()) {
        a.out(bformat!("phone: '{}'\n", phone));
    }
    l.with_line(|line| {
        a.out(bformat!(
            "tech '{}'\nsecret '{}'\ncallerid '{}'\nmailbox '{}'\ncontext '{}'\nauthname '{}'\npjsip_auth '{}'\nline_label '{}'\ndelme {}\n",
            line.tech, line.secret, line.callerid, line.mailbox, line.context, line.authname, line.pjsip_auth, line.line_label, line.delme
        ))
    });
    CliResult::Success
}

fn cmd_objects(a: &CliArgs) -> CliResult {
    a.out(bformat!(
        "lines container {:p}\n",
        objects::lines_container()
    ));
    for l in objects::all_lines() {
        let l: &LineObj = &l;
        a.out(bformat!(
            "  line {:p} '{}' refs {} pjsip_auth '{}'\n",
            l,
            l.key(),
            refs(l) - 1,
            l.pjsip_auth()
        ));
    }
    a.out(bformat!(
        "users container {:p}\n",
        objects::users_container()
    ));
    // SAFETY: each object comes with a reference, dropped here.
    unsafe {
        for o in dpma_ast::ao2::collect(objects::users_container()) {
            let u = &*(o as *const UserObj);
            a.out(bformat!(
                "  user {:p} '{}' refs {}\n",
                o,
                u.key(),
                refs(u) - 1
            ));
            dpma_ast::ao2::cleanup(o);
        }
    }
    CliResult::Success
}

fn cmd_isdphone(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let r = super::endpoint_is_dphone(&a.argv[3]);
    a.out(bformat!(
        "dpma_pjsip_endpoint_is_dphone('{}') = {}\n",
        a.argv[3],
        r
    ));
    CliResult::Success
}

fn cmd_info(a: &CliArgs) -> CliResult {
    if a.argc() != 4 && a.argc() != 5 {
        return CliResult::ShowUsage;
    }
    let Some(chan) = Channel::get_by_name(&a.argv[3]) else {
        a.out(bformat!("No channel '{}'\n", a.argv[3]));
        return CliResult::Success;
    };
    let body = a.argv.get(4).map_or(&b""[..], Vec::as_slice);
    let ct = if body.is_empty() {
        ""
    } else {
        "application/json"
    };
    // SAFETY: we hold a reference on the channel.
    let r = unsafe {
        super::info_send(
            chan.as_ptr(),
            &[("X-Event-Name", "digium.test"), ("X-Extra", "1")],
            ct,
            body,
        )
    };
    a.out(bformat!("info_send = {}\n", r));
    CliResult::Success
}

static LAST_INFO: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

/// Record a last URI set through a phone object.
pub fn record_last_info(
    phone: &[u8],
    uri: &[u8],
    session: Option<&[u8]>,
    mac: Option<&[u8]>,
    linked: bool,
) {
    let mut v = LAST_INFO.lock().unwrap_or_else(|e| e.into_inner());
    let quoted = |x: Option<&[u8]>| x.map_or(b"NULL".to_vec(), |s| bformat!("'{}'", s));
    v.push(bformat!(
        "phone '{}' uri '{}' session {} mac {}{}",
        phone,
        uri,
        quoted(session),
        quoted(mac),
        if linked { "" } else { " (unlinked)" }
    ));
}

fn cmd_lastinfo(a: &CliArgs) -> CliResult {
    let mut v = LAST_INFO.lock().unwrap_or_else(|e| e.into_inner());
    match a.argc() {
        3 => {
            for (i, l) in v.iter().enumerate() {
                a.out(bformat!("{}: {}\n", i + 1, l));
            }
            a.out(bformat!("{} calls\n", v.len()));
        }
        4 if a.argv[3] == b"clear" => v.clear(),
        _ => return CliResult::ShowUsage,
    }
    CliResult::Success
}

pub fn devtest_commands() -> Vec<CliCommand> {
    vec![
        CliCommand {
            command: "dpmadev pjsip lastinfo",
            summary: "List the last URIs recorded for phones",
            usage: "Usage: dpmadev pjsip lastinfo [clear]\n",
            exec: cmd_lastinfo,
            complete: None,
        },
        CliCommand {
            command: "dpmadev pjsip info",
            summary: "Send a SIP INFO on a channel",
            usage: "Usage: dpmadev pjsip info <channel> [<body>]\n",
            exec: cmd_info,
            complete: None,
        },
        CliCommand {
            command: "dpmadev pjsip line",
            summary: "Show a line through its object",
            usage: "Usage: dpmadev pjsip line <name>\n",
            exec: cmd_line,
            complete: None,
        },
        CliCommand {
            command: "dpmadev pjsip objects",
            summary: "List the line and phone objects",
            usage: "Usage: dpmadev pjsip objects\n",
            exec: cmd_objects,
            complete: None,
        },
        CliCommand {
            command: "dpmadev pjsip isdphone",
            summary: "Ask whether an endpoint is a Digium phone",
            usage: "Usage: dpmadev pjsip isdphone <endpoint>\n",
            exec: cmd_isdphone,
            complete: None,
        },
    ]
}
