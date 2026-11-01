//! The firmware package description, digium_phones_firmware.conf, found in
//! the `firmware_package_directory` (the original module's
//! phone_firmware.c).  Each section is a phone model with the `version` and
//! `file` of the firmware to load on it.

use crate::util::NamedMap;
use dpma_ast::cli::CliArgs;
use dpma_ast::config::{self, LoadResult};
use dpma_ast::dpma_log;
use std::sync::RwLock;

pub const PACKAGE_CONFIG_FILE: &str = "digium_phones_firmware.conf";

#[derive(Debug, Clone)]
pub struct Package {
    pub model: String,
    pub version: String,
    pub file: String,
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
                    version: String::new(),
                    file: String::new(),
                };
                for v in &cat.vars {
                    if v.name.eq_ignore_ascii_case("version") {
                        p.version = crate::util::truncate(&v.value, 0x100);
                    } else if v.name.eq_ignore_ascii_case("file") {
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
    let keep: Vec<String> = pkgs.iter().map(|p| p.model.to_ascii_lowercase()).collect();
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
pub fn find(model: &str) -> Option<Package> {
    PACKAGES.read().unwrap().as_ref()?.get(model).cloned()
}

/// All packages, in container order.
pub fn all() -> Vec<Package> {
    PACKAGES.read().unwrap().as_ref().map(|m| m.values().cloned().collect()).unwrap_or_default()
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
        a.out(&format!("Phone Model: {}\n", p.model));
        a.out(&format!("Firmware Version: {}\n", p.version));
        a.out(&format!("Path: {}\n", dir));
        a.out(&format!("Filename: {}\n\n", p.file));
    }
}
