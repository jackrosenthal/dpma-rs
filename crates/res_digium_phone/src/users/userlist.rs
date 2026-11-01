//! The user list returned to UserlistRequest
//! (`phone_user_list_build_json` FUN_00161830).
//!
//! Owner: P4 "config-xml" (wave 1).

/// Build the JSON user list into `out`.  `with_pins` mirrors the
/// original's second argument (userlist auth by global pin is in force);
/// `mac` is the requesting phone's MAC; `config_password` the supplied
/// configuration password.  Returns the number of users listed, or Err
/// when nothing may be listed.
pub fn build_userlist_json(_out: &mut String, _with_pins: bool, _mac: &str, _config_password: &str) -> Result<usize, ()> {
    Err(())
}
