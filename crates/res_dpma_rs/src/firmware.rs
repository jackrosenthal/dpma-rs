//! The firmware package description, digium_phones_firmware.conf, found in
//! the `firmware_package_directory` (the official DPMA's
//! phone_firmware.c).  Each section is a phone model with the `version` and
//! `file` of the firmware to load on it.

use crate::util::NamedMap;
use dpma_ast::cli::CliArgs;
use dpma_ast::config::{self, LoadResult};
use dpma_ast::{bformat, dpma_bytes::ByteSlice, dpma_log};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;

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
    let cats = match config::load(file, crate::MODULE_NAME, 0) {
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
/// official DPMA never dropped packages removed from the file); a failed
/// read keeps the previous ones.
pub fn reload() -> Result<(), ()> {
    let Some(pkgs) = read_config() else {
        return Ok(());
    };
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
    PACKAGES
        .read()
        .unwrap()
        .as_ref()
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default()
}

/// Checksums of firmware files already read, by path, with the
/// modification time and size they were read at.
type ChecksumCache = HashMap<PathBuf, (Option<SystemTime>, u64, Option<String>)>;
static CHECKSUMS: Mutex<Option<ChecksumCache>> = Mutex::new(None);

/// The `checksum` attribute for a `<firmware>` entry whose file is `file`
/// in the local directory `dir`, with its leading space, or nothing.
///
/// The attribute states the CRCs and sizes of the image's kernel and root
/// file system (see [`dpma_proto::firmware`]), so that a phone which
/// compares firmware by checksum sees that it already runs the image
/// without fetching it.  The official DPMA has no such attribute, and the
/// stock firmware does not read it.
///
/// It is only given when the file can be found here: `file` must be a
/// plain relative name (not a URL or an absolute path) of a readable
/// firmware image in `dir`.  Otherwise the entry is as the official DPMA
/// writes it.  The header is read once for each change of the file.
pub fn checksum_attr(dir: &[u8], file: &[u8]) -> Vec<u8> {
    if dir.is_empty() || file.is_empty() || file.starts_with(b"/") || file.contains_str("//") {
        return Vec::new();
    }
    let path = crate::util::path(&crate::util::truncate(
        &bformat!("{}/{}", dir, file),
        0x1000,
    ))
    .to_path_buf();
    let Ok(meta) = std::fs::metadata(&path) else {
        return Vec::new();
    };
    if !meta.is_file() {
        return Vec::new();
    }
    let stamp = (meta.modified().ok(), meta.len());
    let mut g = CHECKSUMS.lock().unwrap();
    let cache = g.get_or_insert_with(HashMap::new);
    let sum = match cache.get(&path) {
        Some((mtime, len, sum)) if (*mtime, *len) == stamp => sum.clone(),
        _ => {
            let sum = std::fs::File::open(&path)
                .ok()
                .and_then(dpma_proto::firmware::ImageChecksum::read)
                .map(|c| c.to_string());
            if sum.is_none() {
                log::debug!(
                    "{} is not a readable firmware image; no checksum is given for it",
                    path.display()
                );
            }
            cache.insert(path, (stamp.0, stamp.1, sum.clone()));
            sum
        }
    };
    match sum {
        Some(sum) => bformat!(" checksum=\"{}\"", sum),
        None => Vec::new(),
    }
}

/// `firmwares_no_option_settings` (FUN_0017a9f0): the `<firmwares>`
/// element of a phone configuration document for a phone without
/// `firmware=` options, listing every package for network `network` with
/// URLs under `url_prefix` (the network's `file_url_prefix`), and the
/// checksum of each package file found in the package directory (see
/// [`checksum_attr`]).  Each piece
/// goes through `append`, one call per piece, as in the official DPMA.
/// Nothing is emitted when the packages were never loaded.
pub fn no_option_settings(append: &mut dyn FnMut(&[u8]), url_prefix: &[u8], network: &[u8]) {
    let package_dir = crate::config::get().firmware_package_directory.clone();
    let g = PACKAGES.read().unwrap();
    let Some(map) = g.as_ref() else { return };
    append(b"<firmwares>\n");
    for p in map.values() {
        if p.version.is_empty() || p.file.is_empty() {
            continue;
        }
        let prefix = if p.file.starts_with(b"/") || p.file.contains_str("//") {
            b""
        } else {
            url_prefix
        };
        append(&bformat!(
            "<firmware model=\"{}\" version=\"{}\" url=\"{}{}\" network_id=\"{}\"{} />\n",
            p.model,
            p.version,
            prefix,
            p.file,
            network,
            checksum_attr(&package_dir, &p.file)
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
