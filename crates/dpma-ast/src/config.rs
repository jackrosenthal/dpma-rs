//! Reading Asterisk configuration files.

use crate::ffi;
use crate::types::AstConfig;
use crate::util::{cstr, from_ptr};

/// One `name = value` line of a configuration category.
#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub value: String,
    pub lineno: i32,
}

/// One `[category]` with its variables in file order.
#[derive(Debug, Clone)]
pub struct Category {
    pub name: String,
    pub vars: Vec<Variable>,
}

impl Category {
    /// First value for `name` (case insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
            .map(|v| v.value.as_str())
    }
}

/// Outcome of loading a configuration file.
#[derive(Debug)]
pub enum LoadResult {
    Missing,
    Unchanged,
    Invalid,
    Loaded(Vec<Category>),
}

pub const CONFIG_FLAG_NOCACHE: u32 = 1 << 2;

/// Load `filename` and copy its contents into Rust structures.
pub fn load(filename: &str, who_asked: &str, flags: u32) -> LoadResult {
    let f = cstr(filename);
    let w = cstr(who_asked);
    unsafe {
        let cfg = ffi::dpma_glue_config_load(f.as_ptr(), w.as_ptr(), flags);
        match ffi::dpma_glue_config_status(cfg) {
            0 => LoadResult::Missing,
            1 => LoadResult::Unchanged,
            2 => LoadResult::Invalid,
            _ => {
                let cats = copy_config(cfg);
                ffi::ast_config_destroy(cfg);
                LoadResult::Loaded(cats)
            }
        }
    }
}

/// Copy all categories and variables out of an `ast_config`.
///
/// # Safety
/// `cfg` must be a valid, loaded configuration.
pub unsafe fn copy_config(cfg: *mut AstConfig) -> Vec<Category> {
    let mut cats = Vec::new();
    let mut prev: *mut std::os::raw::c_char = std::ptr::null_mut();
    loop {
        let cat = ffi::ast_category_browse(cfg, prev);
        if cat.is_null() {
            break;
        }
        let name = from_ptr(cat).unwrap_or_default();
        let mut vars = Vec::new();
        let mut v = ffi::ast_variable_browse(cfg, cat);
        while !v.is_null() {
            vars.push(Variable {
                name: from_ptr(ffi::dpma_glue_variable_name(v)).unwrap_or_default(),
                value: from_ptr(ffi::dpma_glue_variable_value(v)).unwrap_or_default(),
                lineno: ffi::dpma_glue_variable_lineno(v),
            });
            v = ffi::dpma_glue_variable_next(v);
        }
        cats.push(Category { name, vars });
        prev = cat;
    }
    cats
}
