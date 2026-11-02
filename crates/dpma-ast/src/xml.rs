//! XML documents through libxml2, the library behind Asterisk's `ast_xml_*`
//! API.
//!
//! The original module calls libxml2 directly (it does not link libxml2
//! itself; the symbols resolve against the copy Asterisk loads), so this
//! wrapper does the same: Asterisk's `ast_xml_open` adds XInclude and XSLT
//! processing and parser options the original never used, which would
//! change the documents sent to phones.
//!
//! libxml2 is not one of the libraries `dpma-sys` binds (its headers are
//! not needed to build dpma-rs), so the few functions and the leading
//! fields of the structures used are declared here.  Some are public for
//! `astxml.rs`, which serializes Asterisk's XML nodes with them.

use crate::util::cstr;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
struct XmlNodeSet {
    node_nr: c_int,
    node_max: c_int,
    node_tab: *mut *mut c_void,
}

/// The leading fields of libxml2's `xmlXPathObject`.
#[repr(C)]
struct XmlXPathObject {
    kind: c_int,
    nodesetval: *mut XmlNodeSet,
}

extern "C" {
    pub fn xmlParseMemory(buffer: *const c_char, size: c_int) -> *mut c_void;
    fn xmlReadFile(url: *const c_char, encoding: *const c_char, options: c_int) -> *mut c_void;
    fn xmlFreeDoc(doc: *mut c_void);
    fn xmlDocGetRootElement(doc: *const c_void) -> *mut c_void;
    fn xmlCopyNode(node: *mut c_void, extended: c_int) -> *mut c_void;
    fn xmlAddChild(parent: *mut c_void, cur: *mut c_void) -> *mut c_void;
    fn xmlFreeNode(node: *mut c_void);
    fn xmlXPathNewContext(doc: *mut c_void) -> *mut c_void;
    fn xmlXPathFreeContext(ctx: *mut c_void);
    fn xmlXPathEvalExpression(expr: *const c_char, ctx: *mut c_void) -> *mut XmlXPathObject;
    fn xmlXPathFreeObject(obj: *mut XmlXPathObject);
    fn xmlDocDumpFormatMemory(doc: *mut c_void, mem: *mut *mut c_char, size: *mut c_int, format: c_int);
    pub fn xmlBufferCreate() -> *mut c_void;
    pub fn xmlBufferFree(buf: *mut c_void);
    pub fn xmlBufferContent(buf: *const c_void) -> *const c_char;
    pub fn xmlNodeDump(buf: *mut c_void, doc: *mut c_void, cur: *mut c_void, level: c_int, format: c_int) -> c_int;
}

/// Asterisk's wrapper around libxml2's `xmlFree`.
use crate::sys::ast_xml_free_text;

/// An owned libxml2 document (`xmlDocPtr`), freed on drop.
pub struct Doc(*mut c_void);

unsafe impl Send for Doc {}

/// A node inside a document (`xmlNodePtr`), valid while the document lives.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    ptr: *mut c_void,
    _doc: PhantomData<&'a Doc>,
}

impl<'a> Node<'a> {
    fn new(ptr: *mut c_void) -> Option<Node<'a>> {
        if ptr.is_null() {
            None
        } else {
            Some(Node { ptr, _doc: PhantomData })
        }
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr
    }
}

impl Doc {
    /// `xmlParseMemory`.
    pub fn parse_memory(buf: &[u8]) -> Option<Doc> {
        let len = c_int::try_from(buf.len()).ok()?;
        let p = unsafe { xmlParseMemory(buf.as_ptr() as *const c_char, len) };
        (!p.is_null()).then_some(Doc(p))
    }

    /// `xmlReadFile(path, NULL, 0)`.
    pub fn read_file(path: impl AsRef<[u8]>) -> Option<Doc> {
        let c = cstr(path);
        let p = unsafe { xmlReadFile(c.as_ptr(), std::ptr::null(), 0) };
        (!p.is_null()).then_some(Doc(p))
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }

    /// `xmlDocGetRootElement`.
    pub fn root(&self) -> Option<Node<'_>> {
        Node::new(unsafe { xmlDocGetRootElement(self.0) })
    }

    /// The first node matching an XPath expression (`phone_utils_xml_find`).
    pub fn xpath_first(&self, expr: impl AsRef<[u8]>) -> Option<Node<'_>> {
        // SAFETY: the context and result are freed here; the node belongs
        // to the document.
        unsafe { xpath_first_raw(self.0, expr).and_then(Node::new) }
    }

    /// `xmlDocDumpFormatMemory(doc, ..., 1)`.
    pub fn dump_format(&self) -> Vec<u8> {
        let mut mem: *mut c_char = std::ptr::null_mut();
        let mut size: c_int = 0;
        unsafe {
            xmlDocDumpFormatMemory(self.0, &mut mem, &mut size, 1);
            if mem.is_null() {
                return Vec::new();
            }
            let v = std::slice::from_raw_parts(mem as *const u8, size.max(0) as usize).to_vec();
            ast_xml_free_text(mem);
            v
        }
    }
}

impl Drop for Doc {
    fn drop(&mut self) {
        unsafe { xmlFreeDoc(self.0) };
    }
}

/// The first node matching `expr` in the raw document `doc`, as
/// `phone_utils_xml_find` computes it.
///
/// # Safety
/// `doc` must be a valid `xmlDocPtr`.
unsafe fn xpath_first_raw(doc: *mut c_void, expr: impl AsRef<[u8]>) -> Option<*mut c_void> {
    let expr = cstr(expr);
    let ctx = xmlXPathNewContext(doc);
    if ctx.is_null() {
        return None;
    }
    let obj = xmlXPathEvalExpression(expr.as_ptr(), ctx);
    let mut found = None;
    if !obj.is_null() {
        let set = (*obj).nodesetval;
        if !set.is_null() && (*set).node_nr != 0 {
            found = Some(*(*set).node_tab);
        }
        xmlXPathFreeObject(obj);
    }
    xmlXPathFreeContext(ctx);
    found
}

/// Append a recursive copy of `node` to `parent` (`phone_utils_xml_add`:
/// `xmlAddChild(parent, xmlCopyNode(node, 1))`).  Returns the added node.
///
/// # Safety
/// Both must be NULL or valid nodes.
unsafe fn add_copy_raw(parent: *mut c_void, node: *mut c_void) -> *mut c_void {
    let copy = xmlCopyNode(node, 1);
    let added = xmlAddChild(parent, copy);
    if added.is_null() && !copy.is_null() {
        xmlFreeNode(copy);
    }
    added
}

/// Safe form of `add_copy_raw`.
pub fn add_copy<'a>(parent: Node<'a>, node: Option<Node<'_>>) -> Option<Node<'a>> {
    let n = node.map_or(std::ptr::null_mut(), |n| n.ptr);
    Node::new(unsafe { add_copy_raw(parent.ptr, n) })
}
