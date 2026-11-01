//! The firmware package description, digium_phones_firmware.conf, found in
//! the `firmware_package_directory` (the original module's
//! phone_firmware.c).  Each section is a phone model with the `version` and
//! `file` of the firmware to load on it.

use crate::util::NamedMap;
use dpma_ast::cli::CliArgs;
use dpma_ast::config::{self, LoadResult};
use dpma_ast::{bformat, dpma_log, dpma_bytes::ByteSlice};
use std::sync::RwLock;

pub const PACKAGE_CONFIG_FILE: &str = "digium_phones_firmware.conf";

#[derive(Debug, Clone)]
pub struct Package {
    pub model: Vec<u8>,
    pub version: Vec<u8>,
    pub file: Vec<u8>,
}

static PACKAGES: RwLock<Option<NamedMap<Package>>> = RwLock::new(None);

/// Read the package file.  None when no package directory is configured or
/// the file can't be read.
fn read_config() -> Option<Vec<Package>> {
    let general = crate::config::get();
    let file = &general.firmware_package_file;
    if file.is_empty() {
        return None;
    }
    let cats = match config::load(file, "res_digium_phone", 0) {
        LoadResult::Loaded(c) => c,
        _ => {
            dpma_log!("Could not load firmware package config file {}", file);
            return None;
        }
    };
    Some(
        cats.iter()
            .map(|cat| {
                let mut p = Package {
                    model: crate::util::truncate(&cat.name, 0x80),
                    version: Vec::new(),
                    file: Vec::new(),
                };
                for v in &cat.vars {
                    if v.name.eq_ignore_ascii_case(b"version") {
                        p.version = crate::util::truncate(&v.value, 0x100);
                    } else if v.name.eq_ignore_ascii_case(b"file") {
                        p.file = crate::util::truncate(&v.value, 0x1000);
                    }
                }
                p
            })
            .collect(),
    )
}

/// `firmwares_load`.
pub fn load() -> Result<(), ()> {
    *PACKAGES.write().unwrap() = Some(NamedMap::new(13));
    reload()
}

/// `firmwares_reload`.  A successful read replaces the packages (the
/// original never dropped packages removed from the file); a failed read
/// keeps the previous ones.
pub fn reload() -> Result<(), ()> {
    let Some(pkgs) = read_config() else { return Ok(()) };
    let mut g = PACKAGES.write().unwrap();
    let map = g.get_or_insert_with(|| NamedMap::new(13));
    let keep: Vec<Vec<u8>> = pkgs.iter().map(|p| p.model.to_ascii_lowercase()).collect();
    for p in pkgs {
        let model = p.model.clone();
        map.insert(&model, p);
    }
    map.retain(|p| keep.contains(&p.model.to_ascii_lowercase()));
    Ok(())
}

pub fn unload() {
    PACKAGES.write().unwrap().take();
}

/// The package for a phone model.
pub fn find(model: &[u8]) -> Option<Package> {
    PACKAGES.read().unwrap().as_ref()?.get(model).cloned()
}

/// All packages, in container order.
pub fn all() -> Vec<Package> {
    PACKAGES.read().unwrap().as_ref().map(|m| m.values().cloned().collect()).unwrap_or_default()
}

/// `firmwares_no_option_settings` (FUN_0017a9f0): the `<firmwares>`
/// element of a phone configuration document for a phone without
/// `firmware=` options, listing every package for network `network` with
/// URLs under `url_prefix` (the network's `file_url_prefix`).  Each piece
/// goes through `append`, one call per piece of the original.  Nothing is
/// emitted when the packages were never loaded.
pub fn no_option_settings(append: &mut dyn FnMut(&[u8]), url_prefix: &[u8], network: &[u8]) {
    let g = PACKAGES.read().unwrap();
    let Some(map) = g.as_ref() else { return };
    append(b"<firmwares>\n");
    for p in map.values() {
        if p.version.is_empty() || p.file.is_empty() {
            continue;
        }
        let prefix = if p.file.starts_with(b"/") || p.file.contains_str("//") { b"" } else { url_prefix };
        append(&bformat!(
            "<firmware model=\"{}\" version=\"{}\" url=\"{}{}\" network_id=\"{}\" />\n",
            p.model, p.version, prefix, p.file, network
        ));
    }
    append(b"</firmwares>\n");
}

/// `firmwares_cli_display`, shown at the top of `digium_phones show
/// firmwares`.
pub fn cli_display(a: &CliArgs) {
    let pkgs = all();
    if pkgs.is_empty() {
        return;
    }
    let dir = crate::config::get().firmware_package_directory.clone();
    a.out("--- Firmware Package Settings ---\n");
    for p in pkgs {
        a.out(bformat!("Phone Model: {}\n", p.model));
        a.out(bformat!("Firmware Version: {}\n", p.version));
        a.out(bformat!("Path: {}\n", dir));
        a.out(bformat!("Filename: {}\n\n", p.file));
    }
}
