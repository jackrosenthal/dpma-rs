//! Dialplan applications DigiumControlPlayback (`controlplayback_exec`
//! FUN_001729a0) and DigiumVoicemailPlayback (`vm_play_exec`
//! FUN_001726e0, which plays through FUN_00172870), with `playback_cb`
//! (FUN_001728e0) telling the phone the new position after a fast forward
//! or rewind: SIP INFO `digium.voicemail.play.location.change` through
//! `dpma_info_send` (phone_apps.c; load FUN_00173090, unload
//! FUN_001730d0).
//!
//! DigiumControlPlayback is the original's variant of an older
//! app_controlplayback: `DigiumControlPlayback(filename[,skipms[,ff[,rew[,stop[,pause[,restart[,options]]]]]]])`
//! with options `o(ms)` (start offset) and `u` (send the location INFO on
//! fast forward and rewind).  It sets CPLAYBACKSTATUS (SUCCESS,
//! USERSTOPPED, or ERROR), CPLAYBACKSTOPKEY, and CPLAYBACKOFFSET.
//! DigiumVoicemailPlayback(mailbox[@context],folder,msg_id) answers,
//! plays the message with `#` and `*` as fast forward and rewind, and
//! sets VOICEMAIL_PLAYBACKSTATUS (SUCCESS or FAILED).
//!
//! Both are registered without a module (as the original does), so they
//! hold no module reference while they run.

use dpma_ast::app::{self, AppOptions, WAITSTREAM_CB_FASTFORWARD, WAITSTREAM_CB_REWIND};
use dpma_ast::types::AstChannel;
use dpma_ast::{channel, dial, dpma_debug, dpma_log, vm};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_long};

const APP_CONTROLPLAYBACK: &str = "DigiumControlPlayback";
const APP_VM_PLAYBACK: &str = "DigiumVoicemailPlayback";

/// The location event sent to the phone (`playback_cb`).
const LOCATION_EVENT: &str = "digium.voicemail.play.location.change";

/// DigiumControlPlayback option `o(ms)`: start offset.
const OPT_OFFSET: u32 = 1 << 1;
/// DigiumControlPlayback option `u`: send the location event.
const OPT_CALLBACK: u32 = 1 << 2;

/// The option table (DAT_0032a580).
static CPB_OPTS: AppOptions =
    AppOptions::new().option_arg(b'o', OPT_OFFSET as u64, 0).option(b'u', OPT_CALLBACK as u64);

/// Register both applications (FUN_00173090).  The original ORs the two
/// results, so both are attempted.
pub fn load() -> Result<(), ()> {
    let a = app::register(APP_CONTROLPLAYBACK, controlplayback_exec);
    let b = app::register(APP_VM_PLAYBACK, vm_play_exec);
    if (a | b) != 0 {
        Err(())
    } else {
        Ok(())
    }
}

/// Unregister both applications (FUN_001730d0).
pub fn unload() {
    app::unregister(APP_CONTROLPLAYBACK);
    app::unregister(APP_VM_PLAYBACK);
}

unsafe fn data_bytes<'a>(data: *const c_char) -> &'a [u8] {
    if data.is_null() {
        &[]
    } else {
        CStr::from_ptr(data).to_bytes()
    }
}

/// `strtol(s, NULL, 10)`.
fn strtol(s: &[u8]) -> c_long {
    let c = vm::c_bytes(s);
    unsafe { libc::strtol(c.as_ptr(), std::ptr::null_mut(), 10) }
}

/// `is_on_phonepad`: a digit, `#`, or `*`.
fn is_on_phonepad(key: u8) -> bool {
    key == b'#' || key == b'*' || key.is_ascii_digit()
}

fn non_empty(arg: &Option<Vec<u8>>) -> bool {
    arg.as_ref().is_some_and(|a| !a.is_empty())
}

/// How `%s` prints an argument (glibc prints NULL as "(null)").
fn show(arg: &Option<Vec<u8>>) -> String {
    match arg {
        Some(a) => String::from_utf8_lossy(a).into_owned(),
        None => "(null)".into(),
    }
}

/// `playback_cb` (FUN_001728e0), the `ast_waitstream_fr_cb` of both
/// applications: after a rewind or fast forward, tell the phone the new
/// position in seconds.
unsafe extern "C" fn playback_cb(chan: *mut AstChannel, ms: c_long, val: c_int) {
    dpma_ast::guard((), || {
        if val == WAITSTREAM_CB_REWIND || val == WAITSTREAM_CB_FASTFORWARD {
            let body = format!("{{'location':{}}}", ms / 1000);
            crate::exports::info_send(chan, &[("X-Event-Name", LOCATION_EVENT)], "application/json", &body);
        }
    })
}

unsafe extern "C" fn controlplayback_exec(chan: *mut AstChannel, data: *const c_char) -> c_int {
    dpma_ast::guard(-1, || controlplayback(chan, data_bytes(data)))
}

/// `controlplayback_exec` (FUN_001729a0).
unsafe fn controlplayback(chan: *mut AstChannel, data: &[u8]) -> c_int {
    if data.is_empty() {
        dpma_log!("DigiumControlPlayback requires an argument (filename)");
        return -1;
    }
    let (argc, args) = app::separate_args(data, b',', true, 8);
    if argc == 0 {
        dpma_log!("DigiumControlPlayback requires an argument (filename)");
        return -1;
    }
    let mut args = args.into_iter();
    let mut next = || args.next().flatten();
    let filename = next();
    let skip = next();
    let (mut fwd, mut rev, mut stop, mut pause, mut restart) = (next(), next(), next(), next(), next());
    let options = next();

    let skipms = match &skip {
        Some(s) if !s.is_empty() => match strtol(s) as c_int {
            0 => 3000,
            n => n,
        },
        _ => 3000,
    };

    // Invalid keys are dropped (and logged).  The original remembers only
    // the first character of the last valid key, in one stack byte that is
    // otherwise uninitialized (taken as none here); an empty or missing
    // fast forward key becomes `#` unless that character is `#`, and an
    // empty or missing rewind key becomes `*` unless it is `*`.
    let mut last: u8 = 0;
    for (arg, msg) in [
        (&mut fwd, "Invalid fast forward key specified."),
        (&mut rev, "Invalid rewind key specified."),
        (&mut stop, "Invalid stop specified."),
        (&mut pause, "Invalid pause key specified."),
        (&mut restart, "Invalid restart key specified."),
    ] {
        if let Some(&key) = arg.as_ref().and_then(|a| a.first()) {
            if is_on_phonepad(key) {
                last = key;
            } else {
                *arg = None;
                dpma_log!("{}", msg);
            }
        }
    }
    if !non_empty(&fwd) && last != b'#' {
        fwd = Some(b"#".to_vec());
    }
    if !non_empty(&rev) && last != b'*' {
        rev = Some(b"*".to_vec());
    }
    dpma_debug!(1, "Forward key = {}, Rewind key = {}", show(&fwd), show(&rev));

    let mut offsetms: c_long = 0;
    let mut flags = 0;
    if let Some(o) = options.as_ref().filter(|o| !o.is_empty()) {
        let (_, f, opt_args) = app::parse_options(&CPB_OPTS, o, 1);
        flags = f;
        if flags & OPT_OFFSET != 0 {
            offsetms = strtol(opt_args[0].as_deref().unwrap_or_default());
        }
    }
    let cb = if flags & OPT_CALLBACK != 0 { Some(playback_cb as app::WaitstreamFrCb) } else { None };
    let res = app::control_streamfile(
        chan,
        filename.as_deref().unwrap_or_default(),
        fwd.as_deref(),
        rev.as_deref(),
        stop.as_deref(),
        pause.as_deref(),
        restart.as_deref(),
        skipms,
        &mut offsetms,
        cb,
    );

    let mut ret = res;
    if res < 0 {
        ret = 0;
        dial::setvar(chan, "CPLAYBACKSTATUS", b"ERROR");
    } else {
        // strchr(stop, res): the key as a char; NUL matches the terminator.
        let key = res as u8;
        let stopped = res > 0 && stop.as_ref().is_some_and(|s| !s.is_empty() && (key == 0 || s.contains(&key)));
        if stopped {
            dial::setvar(chan, "CPLAYBACKSTATUS", b"USERSTOPPED");
            // snprintf(buf, 2, "%c", res)
            let stopkey: &[u8] = if key == 0 { b"" } else { std::slice::from_ref(&key) };
            dial::setvar(chan, "CPLAYBACKSTOPKEY", stopkey);
            ret = 0;
        } else {
            dial::setvar(chan, "CPLAYBACKSTATUS", b"SUCCESS");
        }
    }
    // snprintf(buf, 20, "%ld", offsetms)
    let mut offset = offsetms.to_string();
    offset.truncate(19);
    dial::setvar(chan, "CPLAYBACKOFFSET", offset.as_bytes());
    ret
}

/// FUN_00172870, the `ast_vm_msg_play_cb` of DigiumVoicemailPlayback:
/// play the message with `#` and `*` skipping a fifth of its duration
/// (at least whole seconds; 3 s for messages under 5 s), `0` as stop and
/// pause key, and the location event.
unsafe extern "C" fn vm_play_cb(chan: *mut AstChannel, playfile: *const c_char, duration: c_int) {
    dpma_ast::guard((), || {
        let skipms = if duration / 5 != 0 { (duration / 5) * 1000 } else { 3000 };
        let mut offsetms: c_long = 0;
        app::control_streamfile(
            chan,
            data_bytes(playfile),
            Some(b"#"),
            Some(b"*"),
            Some(b"0"),
            Some(b"0"),
            None,
            skipms,
            &mut offsetms,
            Some(playback_cb),
        );
    })
}

unsafe extern "C" fn vm_play_exec(chan: *mut AstChannel, data: *const c_char) -> c_int {
    dpma_ast::guard(-1, || vm_play(chan, data_bytes(data)))
}

/// `vm_play_exec` (FUN_001726e0).
unsafe fn vm_play(chan: *mut AstChannel, data: &[u8]) -> c_int {
    const USAGE: &str = "DigiumVoicemailPlayback requires arguments (mailbox|folder|message)";
    if data.is_empty() {
        dpma_log!("{}", USAGE);
        return -1;
    }
    let (_, args) = app::separate_args(data, b',', true, 3);
    let [mailbox, folder, msg_id]: [Option<Vec<u8>>; 3] = args.try_into().unwrap_or_default();
    let (Some(mailbox), Some(folder), Some(msg_id)) = (mailbox, folder, msg_id) else {
        dpma_log!("{}", USAGE);
        return -1;
    };
    if mailbox.is_empty() || folder.is_empty() || msg_id.is_empty() {
        dpma_log!("{}", USAGE);
        return -1;
    }
    if channel::state(chan) != channel::STATE_UP {
        channel::answer(chan);
    }
    let (mailbox, context) = match mailbox.iter().position(|&b| b == b'@') {
        Some(at) => (&mailbox[..at], Some(&mailbox[at + 1..])),
        None => (&mailbox[..], None),
    };
    let res = vm::msg_play(chan, mailbox, context, &folder, &msg_id, vm_play_cb);
    let status: &[u8] = if res == 0 { b"SUCCESS" } else { b"FAILED" };
    dial::setvar(chan, "VOICEMAIL_PLAYBACKSTATUS", status);
    0
}
