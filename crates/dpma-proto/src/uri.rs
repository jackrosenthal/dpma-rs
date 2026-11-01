//! SIP URI and header parsing: the original's copy of chan_sip's
//! reqresp_parser.c (`parse_uri_full`, `parse_uri`, `get_calleridname`,
//! `get_in_brackets_full`, `get_in_brackets`, `parse_name_andor_addr`,
//! `sip_uri_cmp` with its parameter, header, and domain helpers), the
//! Asterisk helpers they use (`ast_uri_decode`,
//! `ast_sockaddr_split_hostport`, `ast_sockaddr_parse`,
//! `ast_sockaddr_cmp`), `phone_utils_parse_uri`, and the URI comparison of
//! phone_users.c.
//!
//! The C functions cut their input apart in place (writing NULs, and
//! putting `=` and `;` back for parameters they do not know) and return
//! pointers into it; they are ported on a byte buffer so that every result is exactly
//! the C string the original's pointer would show.  Unlike chan_sip's
//! versions, this copy logs its warnings at the `DPMA` level.

use crate::cbuf::{c_bytes, contains_ignore_case, eq_ignore_case, CBuf, EMPTY};
use crate::LogLevel;
use dpma_bytes::bformat;

const FILE: &str = "reqresp_parser.c";

fn log(line: u32, func: &str, msg: &[u8]) {
    crate::log(LogLevel::Dpma, FILE, line, func, msg);
}

/// `sip_reqresp_parser_init` (FUN_00187f10): nothing to do; kept so the
/// load order matches the original.
pub fn parser_init() -> crate::Result<()> {
    Ok(())
}

/// `struct uriparams`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UriParams {
    pub transport: Vec<u8>,
    pub user: Vec<u8>,
    pub method: Vec<u8>,
    pub ttl: Vec<u8>,
    pub maddr: Vec<u8>,
    pub lr: bool,
}

/// Which optional outputs the caller asks `parse_uri_full` for.  In C a
/// NULL `pass`, `hostport`, or `params` pointer changes how the rest is
/// split, so these are part of the input; the other outputs never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOpts {
    /// Split `user:password`.
    pub pass: bool,
    /// Split `userinfo@hostport` (otherwise everything is `user`).
    pub hostport: bool,
    /// Parse the known parameters (this also moves `residue` past them).
    pub params: bool,
}

impl ParseOpts {
    pub const ALL: ParseOpts = ParseOpts { pass: true, hostport: true, params: true };
}

impl Default for ParseOpts {
    fn default() -> Self {
        ParseOpts::ALL
    }
}

/// Result of `parse_uri_full`.  Outputs that were not asked for (see
/// [`ParseOpts`]) are empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedUri {
    /// The return value was -1 (empty URI, or none of the schemes
    /// matched; in the latter case the other fields are still filled).
    pub error: bool,
    pub user: Vec<u8>,
    pub pass: Vec<u8>,
    pub hostport: Vec<u8>,
    pub params: UriParams,
    pub headers: Vec<u8>,
    pub residue: Vec<u8>,
}

impl ParsedUri {
    /// The C return value (0 or -1).
    pub fn result(&self) -> i32 {
        if self.error {
            -1
        } else {
            0
        }
    }
}

#[derive(Default)]
struct Pos {
    error: bool,
    user: usize,
    pass: usize,
    hostport: usize,
    headers: usize,
    residue: usize,
    transport: usize,
    puser: usize,
    method: usize,
    ttl: usize,
    maddr: usize,
    lr: bool,
}

impl Pos {
    fn empty() -> Pos {
        Pos {
            error: false,
            user: EMPTY,
            pass: EMPTY,
            hostport: EMPTY,
            headers: EMPTY,
            residue: EMPTY,
            transport: EMPTY,
            puser: EMPTY,
            method: EMPTY,
            ttl: EMPTY,
            maddr: EMPTY,
            lr: false,
        }
    }

    fn read(&self, b: &CBuf, opts: ParseOpts) -> ParsedUri {
        ParsedUri {
            error: self.error,
            user: b.get(self.user),
            pass: if opts.pass { b.get(self.pass) } else { Vec::new() },
            hostport: if opts.hostport { b.get(self.hostport) } else { Vec::new() },
            params: if opts.params {
                UriParams {
                    transport: b.get(self.transport),
                    user: b.get(self.puser),
                    method: b.get(self.method),
                    ttl: b.get(self.ttl),
                    maddr: b.get(self.maddr),
                    lr: self.lr,
                }
            } else {
                UriParams::default()
            },
            headers: b.get(self.headers),
            residue: b.get(self.residue),
        }
    }
}

/// `strncasecmp(s, prefix, strlen(prefix)) == 0`.
fn starts_with_ignore_case(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && eq_ignore_case(&s[..prefix.len()], prefix)
}

/// `parse_uri_full` (FUN_00187100) on the buffer, from `start`.
fn parse_uri_full_buf(b: &mut CBuf, start: usize, scheme: Option<&str>, opts: ParseOpts) -> Pos {
    let mut r = Pos::empty();
    if b.strlen(start) == 0 {
        r.error = true;
        return r;
    }
    let mut uri = start;
    if let Some(scheme) = scheme {
        let mut matched = false;
        for cur in scheme.as_bytes().split(|&c| c == b',') {
            if cur.is_empty() {
                break;
            }
            if starts_with_ignore_case(b.bytes(uri), cur) {
                uri += cur.len();
                matched = true;
                break;
            }
        }
        if !matched {
            log(
                0x60,
                "parse_uri_full",
                &bformat!("No supported scheme found in '{}' using the scheme[s] {}\n", b.get(uri), scheme),
            );
            r.error = true;
        }
    }

    let userinfo;
    if opts.hostport {
        if let Some(c) = b.strchr(uri, b'@') {
            b.set(c, 0);
            r.hostport = c + 1;
            userinfo = uri;
            // userinfo can contain ? and ; so step past it.
            uri = c + 1;
        } else {
            r.hostport = uri;
            userinfo = EMPTY;
        }
    } else {
        userinfo = uri;
    }
    if opts.pass {
        if let Some(c) = b.strchr(userinfo, b':') {
            b.set(c, 0);
            r.pass = c + 1;
        }
    }
    r.user = userinfo;

    let mut parameters = uri;
    // Strip [?headers] from the end, even if nobody wants them.
    if let Some(c) = b.strrchr(uri, b'?') {
        b.set(c, 0);
        let h = c + 1;
        r.headers = h;
        uri = match b.strrchr(h, b';') {
            Some(c) => {
                b.set(c, 0);
                c + 1
            }
            None => b.end(h),
        };
    }

    let endparams = b.end(parameters);
    parameters = match b.strchr(parameters, b';') {
        Some(c) => {
            b.set(c, 0);
            c + 1
        }
        None => endparams,
    };

    if opts.params {
        let mut rem = parameters;
        let mut lr = false;
        loop {
            // while ((value = strchr(parameters, '=')) ||
            //        (lr = !strncmp(parameters, "lr", 2)))
            let value = match b.strchr(parameters, b'=') {
                Some(v) => {
                    if lr {
                        parameters
                    } else {
                        b.set(v, 0);
                        v + 1
                    }
                }
                None => {
                    lr = b.starts_with(parameters, b"lr");
                    if !lr {
                        break;
                    }
                    parameters
                }
            };
            let label = parameters;
            let c = b.strchr(value, b';');
            parameters = match c {
                Some(c) => {
                    b.set(c, 0);
                    c + 1
                }
                None => endparams,
            };
            if b.eq(label, b"transport") {
                r.transport = value;
                rem = parameters;
            } else if b.eq(label, b"user") {
                r.puser = value;
                rem = parameters;
            } else if b.eq(label, b"method") {
                r.method = value;
                rem = parameters;
            } else if b.eq(label, b"ttl") {
                r.ttl = value;
                rem = parameters;
            } else if b.eq(label, b"maddr") {
                r.maddr = value;
                rem = parameters;
            } else if (b.eq(label, b"lr")
                && !b.eq(value, b"no")
                && !b.eq(value, b"off")
                && !b.eq(value, b"0")
                && !b.eq(value, b""))
                || (lr && !b.eq(value, b"lr"))
            {
                r.lr = true;
                rem = parameters;
            } else {
                // Put the parameter back together.  (Not reached in "lr"
                // mode, where `value` is `parameters`.)
                b.set(value - 1, b'=');
                if let Some(c) = c {
                    b.set(c, b';');
                }
            }
        }
        if rem > uri {
            uri = rem;
        }
    }
    r.residue = uri;
    r
}

/// `parse_uri_full` (FUN_00187100): split `uri` whose scheme must be one
/// of the comma separated `scheme` list (e.g., "sip:,sips:"; the scheme
/// text, including any colon, is stripped).  With `None` no scheme is
/// expected.
pub fn parse_uri_full(uri: impl AsRef<[u8]>, scheme: Option<&str>, opts: ParseOpts) -> ParsedUri {
    let mut b = CBuf::new(uri.as_ref());
    let p = parse_uri_full_buf(&mut b, 0, scheme, opts);
    p.read(&b, opts)
}

/// `parse_uri` (FUN_001876a0): `parse_uri_full` with parameters parsed;
/// callers use `params.transport`.
pub fn parse_uri(uri: impl AsRef<[u8]>, scheme: Option<&str>, pass: bool, hostport: bool) -> ParsedUri {
    parse_uri_full(uri, scheme, ParseOpts { pass, hostport, params: true })
}

/// `get_calleridname` on the buffer: returns the display name (at most
/// `outputsize - 1` bytes) and the position where parsing continues.
fn get_calleridname_buf(b: &CBuf, input: usize, outputsize: usize) -> (Vec<u8>, usize) {
    if outputsize == 0 {
        return (Vec::new(), input);
    }
    let mut room = outputsize - 1;
    let mut out = Vec::new();
    let mut i = input;
    // ast_skip_blanks
    while (1..=32).contains(&b.at(i)) {
        i += 1;
    }
    if b.at(i) == b'<' {
        return (out, i);
    }
    if b.at(i) == b'"' {
        i += 1;
        loop {
            let mut c = b.at(i);
            if c == 0 || c == b'"' {
                break;
            }
            if c == b'\\' {
                i += 1;
                c = b.at(i);
                if c == 0 {
                    break;
                }
                if c > 0x7f || c == b'\n' || c == b'\r' {
                    i += 1;
                    continue;
                }
            } else if (c != b'\t' && c < 0x20) || c == 0x7f {
                i += 1;
                continue;
            }
            if room > 0 {
                out.push(c);
                room -= 1;
            }
            i += 1;
        }
        if b.at(i) != b'"' {
            log(0x146, "get_calleridname", b"No ending quote for display-name was found\n");
            return (Vec::new(), input);
        }
        (out, i + 1)
    } else {
        loop {
            let c = b.at(i);
            if c == 0 {
                break;
            }
            let token = c.is_ascii_alphanumeric() || b"-.!%*_+`'~\t ".contains(&c);
            if token {
                if room > 0 {
                    out.push(c);
                    room -= 1;
                }
            } else if c == b'<' {
                break;
            } else if c == b':' {
                // An addr-spec rather than a display-name.
                return (Vec::new(), input);
            }
            i += 1;
        }
        if b.at(i) != b'<' {
            return (Vec::new(), input);
        }
        while matches!(out.last(), Some(b'\t') | Some(b' ')) {
            out.pop();
        }
        (out, i)
    }
}

/// `get_calleridname` (FUN_001876e0) with an output buffer of
/// `outputsize` bytes: returns the display name of a From/To/Contact value
/// (quoted-string or token form) and the rest of the input after it (the
/// whole input when there is no display name).
pub fn get_calleridname(input: impl AsRef<[u8]>, outputsize: usize) -> (Vec<u8>, Vec<u8>) {
    let b = CBuf::new(input.as_ref());
    let (name, rest) = get_calleridname_buf(&b, 0, outputsize);
    (name, b.get(rest))
}

/// `find_closing_quote(start, NULL)`.
fn find_closing_quote(b: &CBuf, start: usize) -> usize {
    let mut last = 0u8;
    let mut s = start;
    while b.at(s) != 0 {
        if b.at(s) == b'"' && last != b'\\' {
            break;
        }
        last = b.at(s);
        s += 1;
    }
    s
}

/// `get_in_brackets_full` on the buffer: (result, out, residue).
fn get_in_brackets_full_buf(b: &mut CBuf, tmp: usize) -> (i32, usize, usize) {
    if b.strlen(tmp) == 0 {
        return (1, EMPTY, EMPTY);
    }
    let mut parse = tmp;
    let first_bracket = loop {
        let Some(fb) = b.strchr(parse, b'<') else { break None };
        let fb = fb + 1;
        match b.strchr(parse, b'"') {
            Some(q) if q < fb => {
                // The bracket is within quotes, so skip the quoted part.
                let s = find_closing_quote(b, q + 1);
                if b.at(s) == 0 {
                    log(0x195, "get_in_brackets_full", &bformat!("No closing quote found in '{}'\n", b.get(tmp)));
                    return (-1, EMPTY, EMPTY);
                }
                parse = s + 1;
            }
            _ => break Some(fb),
        }
    };
    let p = first_bracket.unwrap_or(tmp);
    if let Some(sb) = b.strchr(p, b'>') {
        b.set(sb, 0);
        return (0, p, sb + 1);
    }
    if first_bracket.is_some() {
        log(0x1b0, "get_in_brackets_full", &bformat!("No closing bracket found in '{}'\n", b.get(tmp)));
        return (-1, EMPTY, EMPTY);
    }
    (1, tmp, EMPTY)
}

/// Result of [`get_in_brackets_full`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InBrackets {
    /// 0: found `<...>`; 1: no brackets (`out` is the whole input, or
    /// empty for empty input); -1: unbalanced quote or bracket (logged).
    pub result: i32,
    pub out: Vec<u8>,
    /// What follows the closing `>`.
    pub residue: Vec<u8>,
}

/// `get_in_brackets_full` (FUN_001878c0): the part of a header value
/// between `<` and `>`, skipping brackets inside quotes.
pub fn get_in_brackets_full(s: impl AsRef<[u8]>) -> InBrackets {
    let mut b = CBuf::new(s.as_ref());
    let (result, out, residue) = get_in_brackets_full_buf(&mut b, 0);
    InBrackets { result, out: b.get(out), residue: b.get(residue) }
}

/// `get_in_brackets` (FUN_00187a50): the bracketed part, or the input
/// unchanged when there is none or it is malformed.
pub fn get_in_brackets(s: impl AsRef<[u8]>) -> Vec<u8> {
    let s = s.as_ref();
    let r = get_in_brackets_full(s);
    if r.result == 0 {
        r.out
    } else {
        // C returns the input pointer, which may have been cut at '>' only
        // on success, so it is the original text.
        c_bytes(s).to_vec()
    }
}

/// Result of [`parse_name_andor_addr`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameAddr {
    /// The display name (empty when not asked for or absent).
    pub name: Vec<u8>,
    /// The URI parts; `uri.error` is the return value.
    pub uri: ParsedUri,
}

/// `parse_name_andor_addr` (FUN_00187a80): an optional display name, then
/// a URI in brackets (whose trailing parameters are returned in
/// `residue`, past the first `;`) or bare (parsed by `parse_uri_full`).
pub fn parse_name_andor_addr(value: impl AsRef<[u8]>, scheme: Option<&str>, want_name: bool, opts: ParseOpts) -> NameAddr {
    let mut b = CBuf::new(value.as_ref());
    let mut uri = 0;
    let mut name = Vec::new();
    if want_name {
        let (n, u) = get_calleridname_buf(&b, 0, 1024);
        name = n;
        uri = u;
    }
    let (ret, out, mut residue) = get_in_brackets_full_buf(&mut b, uri);
    let uri = out;
    let bracketed = ret == 0;
    if bracketed && b.at(residue) != 0 {
        // Step over the first semicolon, as parse_uri's residue does.
        residue += 1;
    }
    let mut name_pos = EMPTY;
    if want_name && !name.is_empty() {
        // There is always room at the start for the display name, because
        // a '"' or '<' has been removed.
        b.strcpy(0, &name);
        name_pos = 0;
    }
    let mut p = parse_uri_full_buf(&mut b, uri, scheme, opts);
    if bracketed {
        p.residue = residue;
    }
    NameAddr { name: if want_name { b.get(name_pos) } else { Vec::new() }, uri: p.read(&b, opts) }
}

/// The `To` header handling of `incoming_check_finalize`:
/// `parse_name_andor_addr(to, "sip,sips", ...)` for the host and port,
/// then `ast_sockaddr_split_hostport`.  `None` when the parse fails (the
/// transaction then keeps empty values).
pub fn to_host_port(to: impl AsRef<[u8]>) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let r = parse_name_andor_addr(to, Some("sip,sips"), false, ParseOpts { pass: false, hostport: true, params: false });
    if r.uri.error {
        return None;
    }
    Some(split_hostport(&r.uri.hostport))
}

/// `ast_sockaddr_split_hostport(str, &host, &port, 0)`: `[v6]:port`,
/// `host:port`, or `host`; a host with more than one colon (bare IPv6) has
/// no port.
pub fn split_hostport(s: impl AsRef<[u8]>) -> (Vec<u8>, Option<Vec<u8>>) {
    let (h, p) = split_hostport_bytes(c_bytes(s.as_ref()));
    (h.to_vec(), p.map(<[u8]>::to_vec))
}

fn split_hostport_bytes(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    if s.first() == Some(&b'[') {
        let rest = &s[1..];
        match rest.iter().position(|&c| c == b']') {
            Some(e) => {
                let after = &rest[e + 1..];
                let port = (after.first() == Some(&b':')).then(|| &after[1..]);
                (&rest[..e], port)
            }
            // No closing bracket: the host runs to the end (and there is
            // no port, since the scan stopped at the NUL).
            None => (rest, None),
        }
    } else {
        let colons: Vec<usize> = s.iter().enumerate().filter(|(_, &c)| c == b':').map(|(i, _)| i).collect();
        if colons.len() == 1 {
            (&s[..colons[0]], Some(&s[colons[0] + 1..]))
        } else {
            (s, None)
        }
    }
}

/// `ast_uri_decode(s, ast_uri_sip_user)`: `%XX` sequences decoded with
/// `sscanf("%2x")` semantics (so one hex digit, a sign, or leading
/// whitespace also "decode", and three characters are always consumed);
/// no `+` to space.  The result is a C string: a decoded NUL ends it.
pub fn uri_decode(s: &[u8]) -> Vec<u8> {
    let s = c_bytes(s);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            if let Some(v) = scan_2x(&s[i + 1..]) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    c_bytes(&out).to_vec()
}

/// `sscanf(s, "%2x", &tmp) == 1`, returning `(char)tmp`.
fn scan_2x(s: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (b'\t'..=b'\r').contains(&s[i])) {
        i += 1;
    }
    let mut width = 2;
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
        width -= 1;
    }
    let mut v: u32 = 0;
    let mut digits = 0;
    while width > 0 && i < s.len() {
        let Some(d) = (s[i] as char).to_digit(16) else { break };
        v = v * 16 + d;
        digits += 1;
        width -= 1;
        i += 1;
    }
    if digits == 0 {
        return None;
    }
    Some((if neg { v.wrapping_neg() } else { v }) as u8)
}

/// A parsed numeric socket address (`struct ast_sockaddr` contents that
/// matter to `ast_sockaddr_cmp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SockAddr {
    V4([u8; 4], u16),
    V6([u8; 16], u16, u32),
}

/// `strtoul(s, &end, base)` (base 0 picks 8, 10, or 16 from the prefix):
/// (value, bytes consumed, overflowed).  Consumes 0 bytes when there are
/// no digits.
fn strtoul(s: &[u8], base: u32) -> (u64, usize, bool) {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (b'\t'..=b'\r').contains(&s[i])) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut base = base;
    if (base == 0 || base == 16) && s.get(i) == Some(&b'0') && matches!(s.get(i + 1), Some(b'x') | Some(b'X')) && s.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit()) {
        i += 2;
        base = 16;
    } else if base == 0 {
        base = if s.get(i) == Some(&b'0') { 8 } else { 10 };
    }
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while let Some(d) = s.get(i).and_then(|&c| (c as char).to_digit(base)) {
        match v.checked_mul(u64::from(base)).and_then(|x| x.checked_add(u64::from(d))) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return (0, 0, false);
    }
    if overflow {
        return (u64::MAX, i, true);
    }
    (if neg { v.wrapping_neg() } else { v }, i, false)
}

/// glibc `inet_aton` as used by `getaddrinfo(AI_NUMERICHOST)`
/// (`__inet_aton_exact`): one to four parts in C notation.
fn inet_aton(s: &[u8]) -> Option<[u8; 4]> {
    let mut parts: Vec<u64> = Vec::new();
    let mut i = 0;
    let val = loop {
        if !s.get(i).is_some_and(|c| c.is_ascii_digit()) {
            return None;
        }
        let (v, n, overflow) = strtoul(&s[i..], 0);
        if overflow || v > 0xffff_ffff {
            return None;
        }
        i += n;
        if s.get(i) == Some(&b'.') {
            if parts.len() > 2 || v > 0xff {
                return None;
            }
            parts.push(v);
            i += 1;
        } else {
            break v;
        }
    };
    if i != s.len() {
        return None;
    }
    let max = [0xffff_ffffu64, 0xff_ffff, 0xffff, 0xff][parts.len()];
    if val > max {
        return None;
    }
    let mut addr = val as u32;
    for (k, p) in parts.iter().enumerate() {
        addr |= (*p as u32) << (24 - 8 * k);
    }
    Some(addr.to_be_bytes())
}

/// `ast_sockaddr_parse(addr, str, 0)`: a numeric host (IPv4 in any
/// `inet_aton` form, or IPv6 with an optional numeric scope) and an
/// optional numeric port.  Host names fail.  (glibc also accepts IPv6
/// scopes given as interface names; those fail here.)
fn sockaddr_parse(s: &[u8]) -> Option<SockAddr> {
    let (host, port) = split_hostport_bytes(s);
    let port = match port {
        None => 0,
        Some(p) => {
            let (v, n, _) = strtoul(p, 10);
            if n != p.len() {
                return None;
            }
            v as u16
        }
    };
    if let Some(a) = inet_aton(host) {
        return Some(SockAddr::V4(a, port));
    }
    let (addr, scope) = match host.iter().position(|&c| c == b'%') {
        Some(i) => (&host[..i], Some(&host[i + 1..])),
        None => (host, None),
    };
    let a: std::net::Ipv6Addr = std::str::from_utf8(addr).ok()?.parse().ok()?;
    let scope = match scope {
        None => 0,
        Some(sc) => {
            let (v, n, overflow) = strtoul(sc, 10);
            if n == 0 || n != sc.len() || overflow || v > u64::from(u32::MAX) {
                return None;
            }
            v as u32
        }
    };
    Some(SockAddr::V6(a.octets(), port, scope))
}

/// `ast_sockaddr_cmp(a, b) == 0`, including its IPv4-mapped handling.
fn sockaddr_eq(a: SockAddr, b: SockAddr) -> bool {
    fn mapped(a: SockAddr) -> SockAddr {
        match a {
            SockAddr::V6(o, port, _) if o[..10].iter().all(|&x| x == 0) && o[10] == 0xff && o[11] == 0xff => {
                SockAddr::V4([o[12], o[13], o[14], o[15]], port)
            }
            other => other,
        }
    }
    match (a, b) {
        (SockAddr::V4(..), SockAddr::V6(..)) | (SockAddr::V6(..), SockAddr::V4(..)) => mapped(a) == mapped(b),
        _ => a == b,
    }
}

/// `sip_uri_domain_cmp` (FUN_00186f40): true when the hosts differ.
fn domain_differs(host1: &[u8], host2: &[u8]) -> bool {
    match (sockaddr_parse(host1), sockaddr_parse(host2)) {
        (Some(a), Some(b)) => !sockaddr_eq(a, b),
        (None, None) => !eq_ignore_case(host1, host2),
        _ => true,
    }
}

/// `sip_uri_headers_cmp` (FUN_00186fc0): true when the headers differ.
fn headers_differ(h1: Option<&[u8]>, h2: Option<&[u8]>) -> bool {
    let h1 = h1.filter(|h| !h.is_empty());
    let h2 = h2.filter(|h| !h.is_empty());
    match (h1, h2) {
        (None, None) => false,
        (Some(a), Some(b)) => {
            if a.len() != b.len() {
                return true;
            }
            a.split(|&c| c == b'&').any(|h| !contains_ignore_case(b, h))
        }
        _ => true,
    }
}

/// `sip_uri_params_cmp` (FUN_00186b60): true when the parameters differ.
/// Parameters present on both sides must have equal values; `maddr`,
/// `ttl`, `user`, and `method` must be on both sides.
fn params_differ(p1: Option<&[u8]>, p2: Option<&[u8]>) -> bool {
    const MUST: [&[u8]; 4] = [b"maddr", b"ttl", b"user", b"method"];
    let p1 = p1.filter(|p| !p.is_empty());
    let p2 = p2.filter(|p| !p.is_empty());
    if p1.is_none() && p2.is_none() {
        return false;
    }
    let mut matched_must = [false; 4];
    for pos1 in p1.map(|p| p.split(|&c| c == b';').collect::<Vec<_>>()).unwrap_or_default() {
        let (name1, value1) = match pos1.iter().position(|&c| c == b'=') {
            Some(i) => (&pos1[..i], &pos1[i + 1..]),
            None => (pos1, &b""[..]),
        };
        let mut matched = false;
        for pos2 in p2.map(|p| p.split(|&c| c == b';').collect::<Vec<_>>()).unwrap_or_default() {
            let (name2, value2) = match pos2.iter().position(|&c| c == b'=') {
                Some(i) => (&pos2[..i], &pos2[i + 1..]),
                None => (pos2, &b""[..]),
            };
            if eq_ignore_case(name1, name2) {
                if !eq_ignore_case(value1, value2) {
                    return true;
                }
                matched = true;
                break;
            }
        }
        if let Some(k) = MUST.iter().position(|m| eq_ignore_case(name1, m)) {
            if !matched {
                return true;
            }
            matched_must[k] = true;
        }
    }
    for pos2 in p2.map(|p| p.split(|&c| c == b';').collect::<Vec<_>>()).unwrap_or_default() {
        let name2 = pos2.split(|&c| c == b'=').next().unwrap_or(b"");
        if let Some(k) = MUST.iter().position(|m| eq_ignore_case(name2, m)) {
            if !matched_must[k] {
                return true;
            }
        }
    }
    false
}

/// Split at the first `c`: (before, after), as `strsep`/`strchr` + NUL.
fn cut(s: &[u8], c: u8) -> (&[u8], Option<&[u8]>) {
    match s.iter().position(|&x| x == c) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// `sip_uri_cmp` (FUN_00187bd0): 0 when two sip/sips URIs are equivalent
/// per RFC 3261 19.1.4 (as chan_sip implements it), 1 otherwise.  Used by
/// `validate_session` on the Contact.
pub fn sip_uri_cmp(input1: impl AsRef<[u8]>, input2: impl AsRef<[u8]>) -> i32 {
    let d1 = uri_decode(input1.as_ref());
    let d2 = uri_decode(input2.as_ref());
    let (scheme1, uri1) = cut(&d1, b':');
    let (scheme2, uri2) = cut(&d2, b':');
    if scheme1 != scheme2 {
        return 1;
    }
    if scheme1 != b"sip" && scheme1 != b"sips" {
        return 1;
    }
    let (Some(uri1), Some(uri2)) = (uri1, uri2) else { return 1 };
    if uri1.is_empty() || uri2.is_empty() {
        return 1;
    }
    let (user1, host1) = cut(uri1, b'@');
    let (user2, host2) = cut(uri2, b'@');
    // User and password are the only case-sensitive comparison.
    match (host1, host2) {
        (Some(_), None) | (None, Some(_)) => return 1,
        (Some(_), Some(_)) if user1 != user2 => return 1,
        _ => {}
    }
    let host1 = host1.unwrap_or(uri1);
    let host2 = host2.unwrap_or(uri2);
    let (host1, params1) = cut(host1, b';');
    let (host2, params2) = cut(host2, b';');
    // Headers come after the parameters, but may come without them:
    // strchr(S_OR(params, host), '?').
    let (host1, params1, headers1) = split_headers(host1, params1);
    let (host2, params2, headers2) = split_headers(host2, params2);
    if domain_differs(host1, host2) {
        return 1;
    }
    if headers_differ(headers1, headers2) {
        return 1;
    }
    i32::from(params_differ(params1, params2))
}

/// The `?headers` split of `sip_uri_cmp`: searched in the parameters when
/// there are any, else in the host.
fn split_headers<'a>(host: &'a [u8], params: Option<&'a [u8]>) -> (&'a [u8], Option<&'a [u8]>, Option<&'a [u8]>) {
    match params {
        Some(p) if !p.is_empty() => {
            let (p, h) = cut(p, b'?');
            (host, Some(p), h)
        }
        _ => {
            let (host, h) = cut(host, b'?');
            (host, params, h)
        }
    }
}

/// `phone_utils_parse_uri` (0x1737f0) on a NUL-terminated buffer, in
/// place, as the exported C function works: returns the offsets of the
/// address and (when `want_transport`) of the transport value; `None`
/// stands for a pointer to a static `""`.
///
/// The address is what follows the first `:` and, if present, the first
/// `@` after it; every `;` after that is cut.  With `want_transport`, the
/// value of the last `;transport=` parameter is returned.
pub fn phone_utils_parse_uri_in_place(buf: &mut [u8], want_transport: bool) -> (Option<usize>, Option<usize>) {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = &mut buf[..len];
    let Some(colon) = s.iter().position(|&c| c == b':') else { return (None, None) };
    s[colon] = 0;
    let mut addr = colon + 1;
    if let Some(at) = s[addr..].iter().position(|&c| c == 0 || c == b'@').filter(|&i| s[addr + i] == b'@') {
        addr += at + 1;
    }
    let mut transport = None;
    let mut p = addr;
    while let Some(semi) = s[p..].iter().position(|&c| c == 0 || c == b';').filter(|&i| s[p + i] == b';') {
        let semi = p + semi;
        s[semi] = 0;
        p = semi + 1;
        if want_transport && s[p..].starts_with(b"transport=") {
            transport = Some(p + 10);
        }
    }
    (Some(addr), transport)
}

/// `phone_utils_parse_uri` (0x1737f0): the address part of a contact or
/// URI and the `transport` parameter value, if any (the C function
/// returns `""` for none).
pub fn phone_utils_parse_uri(uri: impl AsRef<[u8]>) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut b = c_bytes(uri.as_ref()).to_vec();
    b.push(0);
    let (addr, transport) = phone_utils_parse_uri_in_place(&mut b, true);
    let get = |p: Option<usize>| p.map(|i| c_bytes(&b[i..]).to_vec());
    (get(addr).unwrap_or_default(), get(transport))
}

/// Compare two URIs the way FUN_00152570 (phone_users.c) does: equal
/// addresses (case insensitive) and transports, where a missing transport
/// is "udp".
pub fn same_uri(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> bool {
    let (addr1, t1) = phone_utils_parse_uri(a);
    let (addr2, t2) = phone_utils_parse_uri(b);
    let t1 = t1.filter(|t| !t.is_empty()).unwrap_or_else(|| b"udp".to_vec());
    let t2 = t2.filter(|t| !t.is_empty()).unwrap_or_else(|| b"udp".to_vec());
    eq_ignore_case(&addr1, &addr2) && eq_ignore_case(&t1, &t2)
}

#[cfg(test)]
mod tests;
