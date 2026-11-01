//! Voicemail folder translation tables (`type=translation` sections),
//! the original module's phone_translation.c.

use crate::util::NamedMap;
use dpma_ast::cli::{complete_from, CliArgs, CliCommand, CliResult, CompleteArgs};
use dpma_ast::config::{self, LoadResult};
use dpma_ast::{bformat, dpma_log};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct Table {
    pub name: Vec<u8>,
    /// (folder, translated name) in file order.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

static TABLES: RwLock<Option<Arc<NamedMap<Arc<Table>>>>> = RwLock::new(None);

fn load_tables(filename: &str) -> Option<NamedMap<Arc<Table>>> {
    let cats = match config::load(filename, "res_digium_phone", 0) {
        LoadResult::Loaded(c) => c,
        _ => return None,
    };
    let mut tables = NamedMap::new(31);
    for cat in cats.iter().filter(|c| !c.name.eq_ignore_ascii_case(b"general")) {
        match cat.get("type") {
            None => dpma_log!("No type set for translation table {}", cat.name),
            Some(t) if t.eq_ignore_ascii_case(b"translation") => {
                let entries = cat
                    .vars
                    .iter()
                    .filter(|v| !v.name.eq_ignore_ascii_case(b"type"))
                    .map(|v| (v.name.clone(), v.value.clone()))
                    .collect();
                tables.insert(&cat.name, Arc::new(Table { name: cat.name.clone(), entries }));
            }
            Some(_) => {}
        }
    }
    Some(tables)
}

/// Load the translation tables.  Fails when the file cannot be read.
pub fn load(filename: &str) -> Result<(), ()> {
    let t = load_tables(filename).ok_or(())?;
    *TABLES.write().unwrap() = Some(Arc::new(t));
    Ok(())
}

/// Reload; the previous tables stay in place when the file cannot be read.
pub fn reload(filename: &str) -> Result<(), ()> {
    let t = load_tables(filename).ok_or(())?;
    *TABLES.write().unwrap() = Some(Arc::new(t));
    Ok(())
}

pub fn unload() {
    TABLES.write().unwrap().take();
}

/// Look up a table by name (case insensitive).
pub fn get(name: &[u8]) -> Option<Arc<Table>> {
    TABLES.read().unwrap().as_ref()?.get(name).cloned()
}

pub fn exists(name: &[u8]) -> bool {
    get(name).is_some()
}

fn names() -> Vec<Vec<u8>> {
    TABLES
        .read()
        .unwrap()
        .as_ref()
        .map(|t| t.values().map(|x| x.name.clone()).collect())
        .unwrap_or_default()
}

fn show_translations(a: &CliArgs) -> CliResult {
    if a.argc() != 3 {
        return CliResult::ShowUsage;
    }
    a.out("--- Translation tables ---\n");
    for n in names() {
        a.out(bformat!("    {}\n", n));
    }
    CliResult::Success
}

fn show_translation(a: &CliArgs) -> CliResult {
    if a.argc() != 4 {
        return CliResult::ShowUsage;
    }
    let name = crate::util::truncate(&a.argv[3], 0x80);
    match get(&name) {
        None => a.out(bformat!("Table {} not found.\n", a.argv[3])),
        Some(t) => {
            a.out(bformat!("--- {} ---\n", t.name));
            for (k, v) in &t.entries {
                a.out(bformat!("    {} ==> {}\n", k, v));
            }
            a.out("\n");
        }
    }
    CliResult::Success
}

fn complete_translation(a: &CompleteArgs) -> Option<Vec<u8>> {
    complete_from(a, names())
}

pub fn commands() -> Vec<CliCommand> {
    vec![
        CliCommand {
            command: "digium_phones show translations",
            summary: "digium_phones show translations",
            usage: "Usage: digium_phones show translations\n       Display the loaded translation tables\n",
            exec: show_translations,
            complete: None,
        },
        CliCommand {
            command: "digium_phones show translation",
            summary: "digium_phones show translation",
            usage: "Usage: digium_phones show translation <table>\n       Display the specified translation table\n",
            exec: show_translation,
            complete: Some(complete_translation),
        },
    ]
}
