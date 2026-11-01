//! phone_utils.c exports (`phone_utils_*`, `dpma_asprintf`,
//! 0x1731a0..0x173a80).  `phone_utils_parse_uri` and
//! `phone_utils_verify_user_agent` are imported by the PJSIP helper (H).
//!
//! ```c
//! char *phone_utils_xml_escape(const char *in, char *out, int outlen);
//! xmlNodePtr phone_utils_xml_find(xmlDocPtr doc, const xmlChar *xpath);
//! xmlNodePtr phone_utils_xml_add(xmlNodePtr parent, xmlNodePtr node);
//! xmlNodePtr phone_utils_xml_add_doc(xmlNodePtr parent, xmlDocPtr doc, const char *xpath);
//! void phone_utils_xml_add_file(xmlNodePtr parent, const char *file, const char *xpath);
//! struct ast_str *phone_utils_filename_to_fullpath(const char *name, const char *dir);
//! struct ast_str *phone_utils_shell_quoted(const char *in);
//! void  phone_utils_parse_uri(char *uri, char **addr, char **transport);
//! int   phone_utils_str_to_uint(const char *s, unsigned int *out);
//! int   phone_utils_verify_user_agent(const char *ua);
//! int   phone_utils_get_model(const char *ua, char *model);
//! int   dpma_asprintf(char **ret, const char *fmt, ...);
//! ```
//!
//! The XML functions use libxml2 directly (resolved from the Asterisk
//! process, which links it), as the original does.  The `struct ast_str`
//! results are freed by the caller with `ast_free`.

use dpma_ast::{ast_log, dpma_log, log::LOG_ERROR};
use std::ffi::{CStr, VaList};
use std::os::raw::{c_char, c_int, c_uint, c_ulong, c_void};

/// `char *phone_utils_xml_escape(const char *in, char *out, int outlen)`:
/// escape `"`, `&`, `'`, `<`, and `>` into `out` (at most `outlen` bytes
/// with the terminator) and return `out`.  An entity that does not fit is
/// replaced by the raw character; copying stops when `out` is full.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_xml_escape(input: *const c_char, out: *mut c_char, outlen: c_int) -> *mut c_char {
    let start = out;
    let mut out = out;
    let mut room = outlen - 1;
    let mut p = input;
    while *p != 0 {
        let c = *p;
        let entity: Option<&[u8]> = match c as u8 {
            b'"' => Some(b"&quot;"),
            b'&' => Some(b"&amp;"),
            b'\'' => Some(b"&apos;"),
            b'<' => Some(b"&lt;"),
            b'>' => Some(b"&gt;"),
            _ => None,
        };
        match entity {
            Some(e) if (e.len() as c_int) < room => {
                for (i, b) in e.iter().enumerate() {
                    *out.add(i) = *b as c_char;
                }
                *out.add(e.len()) = 0;
                out = out.add(e.len());
                room -= e.len() as c_int;
            }
            _ => {
                if room < 1 {
                    break;
                }
                *out = c;
                out = out.add(1);
                room -= 1;
            }
        }
        p = p.add(1);
    }
    *out = 0;
    start
}

// ---- libxml2 ----

#[repr(C)]
struct XmlNodeSet {
    node_nr: c_int,
    node_max: c_int,
    node_tab: *mut *mut c_void,
}

#[repr(C)]
struct XmlXPathObject {
    kind: c_int,
    nodesetval: *mut XmlNodeSet,
}

extern "C" {
    fn xmlXPathNewContext(doc: *mut c_void) -> *mut c_void;
    fn xmlXPathEvalExpression(expr: *const c_char, ctx: *mut c_void) -> *mut XmlXPathObject;
    fn xmlXPathFreeObject(obj: *mut XmlXPathObject);
    fn xmlXPathFreeContext(ctx: *mut c_void);
    fn xmlCopyNode(node: *mut c_void, extended: c_int) -> *mut c_void;
    fn xmlAddChild(parent: *mut c_void, cur: *mut c_void) -> *mut c_void;
    fn xmlDocGetRootElement(doc: *mut c_void) -> *mut c_void;
    fn xmlReadFile(filename: *const c_char, encoding: *const c_char, options: c_int) -> *mut c_void;
    fn xmlFreeDoc(doc: *mut c_void);
}

/// `xmlNodePtr phone_utils_xml_find(xmlDocPtr doc, const xmlChar *xpath)`:
/// the first node matching `xpath`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_xml_find(doc: *mut c_void, xpath: *const c_char) -> *mut c_void {
    let ctx = xmlXPathNewContext(doc);
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    let obj = xmlXPathEvalExpression(xpath, ctx);
    if obj.is_null() {
        xmlXPathFreeContext(ctx);
        return std::ptr::null_mut();
    }
    let set = (*obj).nodesetval;
    let node = if !set.is_null() && (*set).node_nr != 0 { *(*set).node_tab } else { std::ptr::null_mut() };
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
    node
}

/// `xmlNodePtr phone_utils_xml_add(xmlNodePtr parent, xmlNodePtr node)`:
/// append a deep copy of `node` to `parent`.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_xml_add(parent: *mut c_void, node: *mut c_void) -> *mut c_void {
    xmlAddChild(parent, xmlCopyNode(node, 1))
}

/// `xmlNodePtr phone_utils_xml_add_doc(xmlNodePtr parent, xmlDocPtr doc,
/// const char *xpath)`: append a copy of the node of `doc` selected by
/// `xpath` (its root element when NULL); NULL without a parent or doc.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_xml_add_doc(parent: *mut c_void, doc: *mut c_void, xpath: *const c_char) -> *mut c_void {
    if doc.is_null() || parent.is_null() {
        return std::ptr::null_mut();
    }
    let node = if xpath.is_null() { xmlDocGetRootElement(doc) } else { phone_utils_xml_find(doc, xpath) };
    phone_utils_xml_add(parent, node)
}

/// `void phone_utils_xml_add_file(xmlNodePtr parent, const char *file,
/// const char *xpath)`: `phone_utils_xml_add_doc` with the document read
/// from `file`.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_xml_add_file(parent: *mut c_void, file: *const c_char, xpath: *const c_char) {
    let name = || CStr::from_ptr(file).to_string_lossy().into_owned();
    let doc = xmlReadFile(file, std::ptr::null(), 0);
    if doc.is_null() {
        dpma_log!("Unable to read XML file {}", name());
        return;
    }
    if phone_utils_xml_add_doc(parent, doc, xpath).is_null() {
        dpma_log!("Unable to add file {} to parent", name());
    }
    xmlFreeDoc(doc);
}

// ---- struct ast_str results ----

extern "C" {
    fn dpma_glue_exports_str_new(init: usize, value: *const c_char) -> *mut c_void;
    fn dpma_glue_exports_vasprintf(ret: *mut *mut c_char, fmt: *const c_char, ap: VaList) -> c_int;
}

/// `struct ast_str *phone_utils_filename_to_fullpath(const char *name,
/// const char *dir)`: `name` if absolute, else "<dir>/<name>".  Without a
/// name the (empty) string is returned after a log.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_filename_to_fullpath(name: *const c_char, dir: *const c_char) -> *mut c_void {
    let buf = dpma_glue_exports_str_new(0x80, std::ptr::null());
    if buf.is_null() {
        return buf;
    }
    if name.is_null() || *name == 0 {
        dpma_log!("No file name was provided for a file save option.");
        return buf;
    }
    let name = CStr::from_ptr(name).to_string_lossy();
    let path = if name.starts_with('/') {
        name.into_owned()
    } else {
        let dir = if dir.is_null() { "(null)".into() } else { CStr::from_ptr(dir).to_string_lossy() };
        format!("{}/{}", dir, name)
    };
    // ast_str_set on the buffer just made: free it and set a new one.
    dpma_ast::ffi::dpma_glue_free(buf);
    let v = dpma_ast::cstr(&path);
    dpma_glue_exports_str_new(0x80, v.as_ptr())
}

/// `struct ast_str *phone_utils_shell_quoted(const char *in)`: `in` in
/// single quotes, each `'` written as `'\''`; `''` for an empty string.
/// (The original crashes on NULL; here NULL is treated as "".)
#[no_mangle]
pub unsafe extern "C" fn phone_utils_shell_quoted(input: *const c_char) -> *mut c_void {
    let bytes: &[u8] = if input.is_null() { b"" } else { CStr::from_ptr(input).to_bytes() };
    let mut q = Vec::with_capacity(bytes.len() * 4 + 3);
    q.push(b'\'');
    for &b in bytes {
        if b == b'\'' {
            q.extend_from_slice(b"'\\''");
        } else {
            q.push(b);
        }
    }
    q.push(b'\'');
    let v = std::ffi::CString::new(q).unwrap_or_default();
    dpma_glue_exports_str_new(0x10, v.as_ptr())
}

/// `void phone_utils_parse_uri(char *uri, char **addr, char **transport)`
/// (H): split "scheme:user@host;params" in place.  `*addr` points at the
/// host part (after any '@'), `*transport` (when requested) at the value
/// of a `transport=` parameter or "".  Without a ':' `*addr` is "".
/// Every ';' is replaced by a NUL.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_parse_uri(uri: *mut c_char, addr: *mut *mut c_char, transport: *mut *mut c_char) {
    static EMPTY: [c_char; 1] = [0];
    let empty = EMPTY.as_ptr() as *mut c_char;
    if !transport.is_null() {
        *transport = empty;
    }
    let colon = if uri.is_null() { std::ptr::null_mut() } else { libc::strchr(uri, b':' as c_int) };
    if colon.is_null() {
        *addr = empty;
        return;
    }
    *addr = colon.add(1);
    *colon = 0;
    let mut s = *addr;
    let at = libc::strchr(s, b'@' as c_int);
    if !at.is_null() {
        s = at.add(1);
        *addr = s;
    }
    loop {
        let semi = libc::strchr(s, b';' as c_int);
        if semi.is_null() {
            break;
        }
        *semi = 0;
        s = semi.add(1);
        if !transport.is_null() && libc::strncmp(s, c"transport=".as_ptr(), 10) == 0 {
            *transport = semi.add(11);
        }
    }
}

/// `int phone_utils_str_to_uint(const char *s, unsigned int *out)`: 0 when
/// all of `s` is an unsigned number (strtoul, base 0), else -1.  A leading
/// '-' is rejected; `*out` is written whenever strtoul ran.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_str_to_uint(s: *const c_char, out: *mut c_uint) -> c_int {
    if *s == b'-' as c_char {
        return -1;
    }
    *libc::__errno_location() = 0;
    let mut end: *mut c_char = std::ptr::null_mut();
    let v: c_ulong = libc::strtoul(s, &mut end, 0);
    *out = v as c_uint;
    if std::ptr::eq(end, s) || *end != 0 {
        -1
    } else {
        0
    }
}

/// `int dpma_asprintf(char **ret, const char *fmt, ...)`: `ast_vasprintf`,
/// 0 on success, -1 (with a log) on failure.
#[no_mangle]
pub unsafe extern "C" fn dpma_asprintf(ret: *mut *mut c_char, fmt: *const c_char, args: ...) -> c_int {
    if dpma_glue_exports_vasprintf(ret, fmt, args) < 0 {
        let f = if fmt.is_null() { String::from("(null)") } else { CStr::from_ptr(fmt).to_string_lossy().into_owned() };
        ast_log!(LOG_ERROR, "Unable to encode format '{}'", f);
        return -1;
    }
    0
}

const SANGOMA: &[u8] = b"sangoma p\0";
const DIGIUM: &[u8] = b"digium\0";

/// `int phone_utils_verify_user_agent(const char *ua)` (H): 1 when the user
/// agent contains "sangoma p" or "digium" (case insensitive).
#[no_mangle]
pub unsafe extern "C" fn phone_utils_verify_user_agent(ua: *const c_char) -> c_int {
    if ua.is_null() || *ua == 0 {
        return 0;
    }
    let found = |n: &[u8]| !libc::strcasestr(ua, n.as_ptr() as *const c_char).is_null();
    c_int::from(found(SANGOMA) || found(DIGIUM))
}

/// `int phone_utils_get_model(const char *ua, char *model)`: for a user
/// agent whose first word is a prefix of "sangoma p" or "digium" (case
/// insensitive), copy the second word into `model` and return 0; else -1.
#[no_mangle]
pub unsafe extern "C" fn phone_utils_get_model(ua: *const c_char, model: *mut c_char) -> c_int {
    if ua.is_null() || *ua == 0 {
        return -1;
    }
    let space = libc::strchr(ua, b' ' as c_int);
    if space.is_null() {
        return -1;
    }
    let n = space.offset_from(ua) as usize;
    if libc::strncasecmp(ua, SANGOMA.as_ptr() as *const c_char, n) != 0
        && libc::strncasecmp(ua, DIGIUM.as_ptr() as *const c_char, n) != 0
    {
        return -1;
    }
    let word = space.add(1);
    let mut end = libc::strchr(word, b' ' as c_int);
    if end.is_null() {
        end = word.add(libc::strlen(word));
    }
    // ast_copy_string(model, word, end - word + 1)
    let mut size = end.offset_from(word) as usize + 1;
    let mut d = model;
    let mut s = word;
    while *s != 0 && size != 0 {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
        size -= 1;
    }
    if size == 0 {
        d = d.sub(1);
    }
    *d = 0;
    0
}
