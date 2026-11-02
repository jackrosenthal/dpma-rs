//! Reading Asterisk configuration files.

use crate::sys;
use crate::types::{AstConfig, AstVariable};
use crate::util::{cstr, from_ptr};

/// One `name = value` line of a configuration category.
#[derive(Debug, Clone)]
pub struct Variable {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub lineno: i32,
}

/// A list of `ast_variable`s (`ast_variable_new` for each pair, in order),
/// freed with `ast_variables_destroy` on drop.
pub struct VariableList(*mut AstVariable);

impl VariableList {
    /// The list of `pairs`, with `filename` as each variable's file.  None
    /// when an allocation fails.
    pub fn new(pairs: &[(&[u8], &[u8])], filename: &str) -> Option<VariableList> {
        let file = cstr(filename);
        let mut head: *mut AstVariable = std::ptr::null_mut();
        // Built back to front.
        for (name, value) in pairs.iter().rev() {
            let (n, v) = (cstr(name), cstr(value));
            let (src, line, func) = crate::here!("VariableList::new");
            // SAFETY: `_ast_variable_new` copies the strings.
            let var = unsafe { sys::_ast_variable_new(n.as_ptr(), v.as_ptr(), file.as_ptr(), src, func, line) };
            if var.is_null() {
                drop(VariableList(head));
                return None;
            }
            // SAFETY: a fresh variable, not in any list yet.
            unsafe { (*var).next = head };
            head = var;
        }
        Some(VariableList(head))
    }

    /// The head of the list (NULL when empty).
    pub fn as_ptr(&self) -> *mut AstVariable {
        self.0
    }
}

impl Drop for VariableList {
    fn drop(&mut self) {
        // SAFETY: the list this wrapper owns (NULL is allowed).
        unsafe { sys::ast_variables_destroy(self.0) };
    }
}

/// The variables of a list, as (name, value) pairs.
///
/// # Safety
/// `v` must be NULL or a valid `ast_variable` list.
pub unsafe fn variables(mut v: *const AstVariable) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    while !v.is_null() {
        out.push((from_ptr((*v).name).unwrap_or_default(), from_ptr((*v).value).unwrap_or_default()));
        v = (*v).next;
    }
    out
}

/// One `[category]` with its variables in file order.
#[derive(Debug, Clone)]
pub struct Category {
    pub name: Vec<u8>,
    pub vars: Vec<Variable>,
}

impl Category {
    /// First value for `name` (case insensitive).
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.vars
            .iter()
            .find(|v| dpma_bytes::eq_ic(&v.name, name.as_bytes()))
            .map(|v| v.value.as_slice())
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

pub const CONFIG_FLAG_NOCACHE: u32 = sys::CONFIG_FLAG_NOCACHE;

/// `CONFIG_STATUS_FILEUNCHANGED` (`(void *) -1`).
const CONFIG_STATUS_FILEUNCHANGED: *mut AstConfig = usize::MAX as *mut AstConfig;
/// `CONFIG_STATUS_FILEINVALID` (`(void *) -2`).
const CONFIG_STATUS_FILEINVALID: *mut AstConfig = (usize::MAX - 1) as *mut AstConfig;

/// Whether `cfg`, as `ast_config_load2` returns it, is a loaded
/// configuration rather than a status.
pub(crate) fn is_loaded(cfg: *mut AstConfig) -> bool {
    !cfg.is_null() && cfg != CONFIG_STATUS_FILEUNCHANGED && cfg != CONFIG_STATUS_FILEINVALID
}

/// Load `filename` (`ast_config_load2`, as module `who_asked`) and copy
/// its contents into Rust structures.
pub fn load(filename: impl AsRef<[u8]>, who_asked: &str, flags: u32) -> LoadResult {
    let f = cstr(filename);
    let w = cstr(who_asked);
    // SAFETY: valid C strings; a loaded configuration is copied and
    // destroyed here, the status values are not pointers.
    unsafe {
        let cfg = sys::ast_config_load2(f.as_ptr(), w.as_ptr(), sys::ast_flags { flags });
        if cfg.is_null() {
            LoadResult::Missing
        } else if cfg == CONFIG_STATUS_FILEUNCHANGED {
            LoadResult::Unchanged
        } else if cfg == CONFIG_STATUS_FILEINVALID {
            LoadResult::Invalid
        } else {
            let cats = copy_config(cfg);
            sys::ast_config_destroy(cfg);
            LoadResult::Loaded(cats)
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
        let cat = sys::ast_category_browse(cfg, prev);
        if cat.is_null() {
            break;
        }
        let name = from_ptr(cat).unwrap_or_default();
        let mut vars = Vec::new();
        let mut v = sys::ast_variable_browse(cfg, cat);
        while !v.is_null() {
            vars.push(Variable {
                name: from_ptr((*v).name).unwrap_or_default(),
                value: from_ptr((*v).value).unwrap_or_default(),
                lineno: (*v).lineno,
            });
            v = (*v).next;
        }
        cats.push(Category { name, vars });
        prev = cat;
    }
    cats
}
