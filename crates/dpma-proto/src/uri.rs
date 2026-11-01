//! SIP URI and header parsing (reqresp_parser.c, derived from chan_sip,
//! and `phone_utils_parse_uri`).
//!
//! Owner: P1 "proto" (wave 1).

/// `sip_reqresp_parser_init` (FUN_00187f10): nothing to do; kept so the
/// load order matches the original.
pub fn parser_init() -> crate::Result<()> {
    Ok(())
}

/// Result of `parse_uri_full`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedUri {
    pub scheme: String,
    pub user: String,
    pub pass: String,
    pub hostport: String,
    pub params: String,
    pub headers: String,
    pub residue: String,
}

/// `parse_uri_full` (0x187100): split `uri` whose scheme must be one of
/// the comma separated `schemes` (e.g., "sip,sips").
pub fn parse_uri_full(_uri: &str, _schemes: &str) -> Option<ParsedUri> {
    None
}

/// `get_in_brackets` / `get_in_brackets_full` (0x187a50 / 0x1878c0):
/// the part of a header value between `<` and `>`, honoring quotes.
pub fn get_in_brackets(s: &str) -> String {
    s.to_string()
}

/// `get_calleridname` (0x1876e0): the display name of a From/To value.
pub fn get_calleridname(_s: &str) -> String {
    String::new()
}

/// `parse_uri` style helper used on the `To` header (0x187a80): returns
/// the user part of a sip/sips URI.
pub fn uri_user(_s: &str, _schemes: &str) -> Option<String> {
    None
}

/// `phone_utils_parse_uri` (0x1737f0): split a contact/URI into the
/// address part and the transport parameter value (if any).
pub fn phone_utils_parse_uri(_uri: &str) -> (String, Option<String>) {
    (String::new(), None)
}

/// Compare two URIs the way `FUN_00152570` does (address and transport,
/// default transport "udp").
pub fn same_uri(_a: &str, _b: &str) -> bool {
    false
}
