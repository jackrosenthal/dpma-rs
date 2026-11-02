//! XML well-formedness, checked with roxmltree, a strict XML 1.0 parser
//! independent of the module's (xmltree).
//!
//! ```
//! use dpma_tests::xml;
//! assert!(xml::well_formed(b"<?xml version=\"1.0\"?>\n<config><a x=\"1\"/></config>\n").is_ok());
//! assert!(xml::well_formed(b"<config><a x=\"A & B\"/></config>").is_err());
//! assert_eq!(xml::escape(b"A & <B>"), b"A &amp; &lt;B&gt;");
//! ```

use roxmltree::{Document, ParsingOptions};

/// Checks that `doc` is a well-formed UTF-8 XML document; returns the
/// parser's error otherwise.  A document type declaration is allowed.
pub fn well_formed(doc: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(doc).map_err(|e| format!("not UTF-8: {e}"))?;
    let opt = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(text, opt)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Escapes `&`, `<`, and `>`:
/// enough for character data and for attribute values in double quotes
/// that contain no double quote.
pub fn escape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for &b in text {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b => out.push(b),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents() {
        for ok in [
            &b"<config></config>"[..],
            b"<?xml version=\"1.0\"?>\n<config>\n<setting id=\"x\" value=\"1\" />\n</config>\n",
            b"<contacts group_name=\"null\" editable=\"0\" />\n",
            b"<!DOCTYPE c [<!ENTITY e \"x\">]><c>&e;</c>",
            "<c a=\"\u{e9}\">\u{e9}</c>".as_bytes(),
        ] {
            assert_eq!(well_formed(ok), Ok(()), "{:?}", String::from_utf8_lossy(ok));
        }
        for bad in [
            &b""[..],
            b"text",
            b"<config>",
            b"<a></b>",
            b"<a/><b/>",
            b"<a x=\"<\"/>",
            b"<a>&</a>",
            b"<a x=\"1\" x=\"2\"/>",
            b" <?xml version=\"1.0\"?><a/>",
            b"<a>\xe9</a>",
        ] {
            assert!(
                well_formed(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
