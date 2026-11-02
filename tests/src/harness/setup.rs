//! Test setups that suites install into the instance: configuration
//! snippets included from a main configuration file, and the
//! configuration document test setup (`tests/data/config-xml`), which the
//! config-xml and parity suites share.

use std::path::Path;

use anyhow::{Context, Result};

use super::conf::ConfFile;
use super::instance::Instance;

/// Writes the configuration snippet `name` (contents `text`) into the
/// instance's configuration directory and includes it from `main` (e.g.,
/// `res_digium_phone.conf`) unless `main` already has that `#include`
/// line.  Reload or restart Asterisk afterwards.
pub fn install_snippet(inst: &Instance, name: &str, main: &str, text: &[u8]) -> Result<()> {
    write_file(&inst.conf(name), text)?;
    ConfFile::new(&inst.conf(main)).add_include(name)
}

/// The configuration document test configuration: `@INSTANCE@` stands for
/// the instance directory.
pub const CONFIG_XML_CONF: &str = include_str!("../../data/config-xml/res_digium_phone.conf.in");

/// The files the configuration document test configuration refers to
/// (contacts, display rules, a `config_file`, a logo, and a firmware
/// package file), by their path under its `file_directory`
/// (`<instance>/var/lib/asterisk/digium_phones`).
pub const CONFIG_XML_FILES: [(&str, &[u8]); 5] = [
    (
        "cfgphone.xml",
        include_bytes!("../../data/config-xml/digium_phones/cfgphone.xml"),
    ),
    (
        "contacts-local.xml",
        include_bytes!("../../data/config-xml/digium_phones/contacts-local.xml"),
    ),
    (
        "d65_logo.png",
        include_bytes!("../../data/config-xml/digium_phones/d65_logo.png"),
    ),
    (
        "rules.xml",
        include_bytes!("../../data/config-xml/digium_phones/rules.xml"),
    ),
    (
        "firmware/digium_phones_firmware.conf",
        include_bytes!("../../data/config-xml/digium_phones/firmware/digium_phones_firmware.conf"),
    ),
];

/// Installs the configuration document test setup (package P4; was
/// `tests/config-xml/setup.sh`): replaces the instance's
/// `res_digium_phone.conf` with phones, lines, networks, applications,
/// ringtones, alerts, firmware, and multicast pages that use every
/// option the configuration document emits, and copies the files it
/// refers to into `<instance>/var/lib/asterisk/digium_phones`.
/// network2's alias is deliberately not valid XML; altphone gets merged
/// display rules; cfgphone has a `config_file`.
pub fn config_xml(inst: &Instance) -> Result<()> {
    let dir = inst.dir.to_string_lossy();
    write_file(
        &inst.conf("res_digium_phone.conf"),
        CONFIG_XML_CONF.replace("@INSTANCE@", &dir).as_bytes(),
    )?;
    let files = inst.var_lib().join("digium_phones");
    for (name, data) in CONFIG_XML_FILES {
        write_file(&files.join(name), data)?;
    }
    Ok(())
}

/// Writes `data` to `path` (creating its directory) through a temporary
/// file renamed into place.
fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).with_context(|| d.display().to_string())?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    std::fs::write(&tmp, data).with_context(|| path.display().to_string())?;
    std::fs::rename(&tmp, path).with_context(|| path.display().to_string())
}
