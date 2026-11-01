//! Dialplan applications DigiumControlPlayback (`controlplayback_exec`
//! FUN_001729a0) and DigiumVoicemailPlayback (FUN_001726e0, with
//! `playback_cb` FUN_001728e0 sending
//! `digium.voicemail.play.location.change` through `dpma_info_send`)
//! (phone_apps.c; load FUN_00173090, unload FUN_001730d0).
//!
//! Owner: P14 "apps-discovery" (wave 3).

/// Register both applications ("Failed to load phone apps" on error).
pub fn load() -> Result<(), ()> {
    Ok(())
}

pub fn unload() {}
