//! Asterisk's own XML API (`ast_xml_*`, main/xml.c).
//!
//! Most of the original module calls libxml2 directly (see `xml.rs`), but
//! the call methods of phone_method_internal_api.c (the phonebook entry
//! method and the XML recording methods) use `ast_xml_open`,
//! `ast_xml_find_element`, `ast_xml_doc_dump_file`, and friends, which
//! differ from plain libxml2 (parser options, XInclude processing, attribute
//! matching).  This wraps those functions so the behavior is the same.
//! The phone request handlers (phone_request.c) use it too, for the XML
//! requests' attributes and node markup.

use crate::sys;
use crate::util::{cstr, from_ptr};
use crate::xml::{xmlBufferContent, xmlBufferCreate, xmlBufferFree, xmlNodeDump, xmlParseMemory};
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int};

type AstXmlDoc = sys::ast_xml_doc;
type AstXmlNode = sys::ast_xml_node;

/// An owned `struct ast_xml_doc`, closed with `ast_xml_close` on drop.
pub struct Doc(*mut AstXmlDoc);

unsafe impl Send for Doc {}

/// A node of a [`Doc`] (`struct ast_xml_node`).
#[derive(Clone, Copy)]
pub struct Node<'a> {
    ptr: *mut AstXmlNode,
    _doc: PhantomData<&'a Doc>,
}

fn node<'a>(ptr: *mut AstXmlNode) -> Option<Node<'a>> {
    (!ptr.is_null()).then_some(Node { ptr, _doc: PhantomData })
}

fn opt_cstr(s: Option<&[u8]>) -> Option<std::ffi::CString> {
    s.map(cstr)
}

impl Doc {
    /// `ast_xml_open(filename)`.
    pub fn open(filename: impl AsRef<[u8]>) -> Option<Doc> {
        let c = cstr(filename);
        let p = unsafe { sys::ast_xml_open(c.as_ptr() as *mut c_char) };
        (!p.is_null()).then_some(Doc(p))
    }

    /// `ast_xml_read_memory(buffer, size)`: libxml2's `xmlParseMemory`,
    /// which is what `ast_xml_read_memory` amounts to when parsing succeeds
    /// (its XInclude processing only runs, on NULL, when parsing fails).
    pub fn read_memory(buf: impl AsRef<[u8]>) -> Option<Doc> {
        let buf = buf.as_ref();
        let len = c_int::try_from(buf.len()).ok()?;
        let p = unsafe { xmlParseMemory(buf.as_ptr() as *const c_char, len) }.cast::<AstXmlDoc>();
        (!p.is_null()).then_some(Doc(p))
    }

    /// `ast_xml_get_root`.
    pub fn root(&self) -> Option<Node<'_>> {
        node(unsafe { sys::ast_xml_get_root(self.0) })
    }

    /// `fopen(path, "w")` and `ast_xml_doc_dump_file` (libxml2's
    /// `xmlDocDump`).  False when the file cannot be opened.
    pub fn dump_file(&self, path: impl AsRef<[u8]>) -> bool {
        let p = cstr(path);
        unsafe {
            let f = libc::fopen(p.as_ptr(), c"w".as_ptr());
            if f.is_null() {
                return false;
            }
            sys::ast_xml_doc_dump_file(f.cast(), self.0);
            libc::fclose(f);
        }
        true
    }

    /// The markup of `node` (one of this document's nodes) as libxml2's
    /// `xmlNodeDump` writes it, unformatted; None when libxml2 fails.
    pub fn node_markup(&self, node: &Node<'_>) -> Option<Vec<u8>> {
        unsafe {
            let buf = xmlBufferCreate();
            if buf.is_null() {
                return None;
            }
            let res = if xmlNodeDump(buf, self.0.cast(), node.ptr.cast(), 0, 0) < 0 {
                None
            } else {
                from_ptr(xmlBufferContent(buf))
            };
            xmlBufferFree(buf);
            res
        }
    }
}

impl Drop for Doc {
    fn drop(&mut self) {
        unsafe { sys::ast_xml_close(self.0) };
    }
}

impl<'a> Node<'a> {
    /// `ast_xml_node_get_name` ("" when libxml2 has none).
    pub fn name(&self) -> Vec<u8> {
        unsafe { from_ptr(sys::ast_xml_node_get_name(self.ptr)).unwrap_or_default() }
    }

    /// `ast_xml_node_get_children`: the first child (text nodes included).
    pub fn children(&self) -> Option<Node<'a>> {
        node(unsafe { sys::ast_xml_node_get_children(self.ptr) })
    }

    /// `ast_xml_node_get_next`: the next sibling.
    pub fn next(&self) -> Option<Node<'a>> {
        node(unsafe { sys::ast_xml_node_get_next(self.ptr) })
    }

    /// `ast_xml_find_element(self, name, attrname, attrvalue)`: this node or
    /// one of its following siblings named `name` (and, when `attr` is
    /// given, with that attribute value).
    pub fn find_element(&self, name: &str, attr: Option<(&str, &[u8])>) -> Option<Node<'a>> {
        let n = cstr(name);
        let an = opt_cstr(attr.map(|a| a.0.as_bytes()));
        let av = opt_cstr(attr.map(|a| a.1));
        let ptr = |c: &Option<std::ffi::CString>| c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        node(unsafe { sys::ast_xml_find_element(self.ptr, n.as_ptr(), ptr(&an), ptr(&av)) })
    }

    /// `ast_xml_new_child(self, name)`: append a new element.
    pub fn new_child(&self, name: impl AsRef<[u8]>) -> Option<Node<'a>> {
        let n = cstr(name);
        node(unsafe { sys::ast_xml_new_child(self.ptr, n.as_ptr()) })
    }

    /// `ast_xml_set_attribute`.
    pub fn set_attribute(&self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> bool {
        let n = cstr(name);
        let v = cstr(value);
        unsafe { sys::ast_xml_set_attribute(self.ptr, n.as_ptr(), v.as_ptr()) == 0 }
    }

    /// `ast_xml_get_attribute(self, name)`; None when the element has no
    /// such attribute.
    pub fn attribute(&self, name: &str) -> Option<Vec<u8>> {
        let n = cstr(name);
        unsafe {
            let a = sys::ast_xml_get_attribute(self.ptr, n.as_ptr());
            if a.is_null() {
                return None;
            }
            let s = from_ptr(a);
            sys::ast_xml_free_attr(a);
            s
        }
    }

    /// `ast_xml_get_text` (libxml2's `xmlNodeGetContent`); None when it
    /// returns NULL.
    pub fn text(&self) -> Option<Vec<u8>> {
        unsafe {
            let t = sys::ast_xml_get_text(self.ptr);
            if t.is_null() {
                return None;
            }
            let s = from_ptr(t);
            sys::ast_xml_free_text(t);
            s
        }
    }
}
