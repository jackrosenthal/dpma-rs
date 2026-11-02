//! XML document helpers (phone_utils.c: `phone_utils_xml_escape` 0x1731a0,
//! `phone_utils_xml_find` 0x173360, `phone_utils_xml_add` 0x1733e0,
//! `phone_utils_xml_add_doc` 0x173400, `phone_utils_xml_add_file`
//! 0x173450, and `phone_utils_filename_to_fullpath` 0x173520).

use dpma_ast::dpma_log;
use dpma_ast::xml::{self, Doc, Node};

/// `phone_utils_xml_escape(in, buf, size)`: escape `&`, `<`, `>`, `"`,
/// and `'` into a buffer of `size` bytes.
///
/// The official DPMA fills the buffer byte by byte: an entity is written
/// only when it is shorter than the space left (not counting the
/// terminating NUL); otherwise the character itself is copied, and copying
/// stops when the buffer is full.  So at most `size - 1` bytes come out,
/// and a value near the limit can end with a raw special character or half
/// of a multi-byte character.  (The configuration document always uses a
/// 256 byte buffer.)
pub fn escape(input: &[u8], size: usize) -> Vec<u8> {
    dpma_proto::xml::escape_bounded(input, size)
}

/// `phone_utils_xml_find`: the first node of `doc` matching `xpath`.
pub fn xml_find<'a>(doc: &'a Doc, xpath: &str) -> Option<Node<'a>> {
    doc.xpath_first(xpath)
}

/// `phone_utils_xml_add`: append a deep copy of `node` to `parent`.
pub fn xml_add<'a>(parent: Node<'a>, node: Option<Node<'_>>) -> Option<Node<'a>> {
    xml::add_copy(parent, node)
}

/// `phone_utils_xml_add_doc`: append a copy of `doc`'s root element (or of
/// the first node matching `xpath`) to `parent`.
pub fn xml_add_doc<'a>(parent: Node<'a>, doc: &Doc, xpath: Option<&str>) -> Option<Node<'a>> {
    match xpath {
        Some(x) => xml_add(parent, xml_find(doc, x)),
        None => xml_add(parent, doc.root()),
    }
}

/// `phone_utils_xml_add_file`: read the XML file `path` and append its
/// root element (or the first node matching `xpath`) to `parent`.
pub fn xml_add_file(parent: Node<'_>, path: &[u8], xpath: Option<&str>) {
    let Some(doc) = Doc::read_file(path) else {
        dpma_log!("Unable to read XML file {}", path);
        return;
    };
    if xml_add_doc(parent, &doc, xpath).is_none() {
        dpma_log!("Unable to add file {} to parent", path);
    }
}

