//! SIP messages as bytes, shared by the phone simulator
//! ([`crate::sim`]) and the test user agents ([`crate::sipua`]).

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{bail, Result};
use bstr::{BString, ByteSlice};

/// A SIP transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Transport {
    /// UDP (the default).
    #[default]
    Udp,
    /// TCP.
    Tcp,
}

impl Transport {
    /// `"udp"` or `"tcp"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Transport {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Ok(Transport::Udp),
            "tcp" => Ok(Transport::Tcp),
            _ => bail!("unknown transport {s:?}"),
        }
    }
}

/// The compact forms of header names (RFC 3261, section 7.3.3).
pub fn expand_compact(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "i" => "Call-ID",
        "m" => "Contact",
        "e" => "Content-Encoding",
        "l" => "Content-Length",
        "c" => "Content-Type",
        "f" => "From",
        "s" => "Subject",
        "k" => "Supported",
        "t" => "To",
        "v" => "Via",
        "o" => "Event",
        "u" => "Allow-Events",
        "r" => "Refer-To",
        "b" => "Referred-By",
        "x" => "Session-Expires",
        _ => return None,
    })
}

/// One SIP request or response.
#[derive(Clone, Debug)]
pub struct Message {
    /// The request line or status line, without the line break.
    pub first_line: BString,
    /// The headers in order (compact names expanded).
    pub headers: Vec<(String, BString)>,
    /// The body (cut to `Content-Length` when parsed).
    pub body: BString,
    /// Where an incoming message came from.
    pub source: Option<SocketAddr>,
    /// The transport an incoming message arrived on.
    pub transport: Option<Transport>,
    /// When the message was received or built.
    pub received: Instant,
    /// The bytes a parsed message was parsed from (empty for a built
    /// one): header lines exactly as they arrived, padding included.
    pub raw: BString,
}

impl Message {
    /// A message from its parts.
    pub fn new(
        first_line: impl Into<BString>,
        headers: Vec<(String, BString)>,
        body: impl Into<BString>,
    ) -> Self {
        Message {
            first_line: first_line.into(),
            headers,
            body: body.into(),
            source: None,
            transport: None,
            received: Instant::now(),
            raw: BString::default(),
        }
    }

    /// Whether this is a request (not a response).
    pub fn is_request(&self) -> bool {
        !self.first_line.starts_with(b"SIP/2.0 ")
    }

    /// The status code of a response.
    pub fn status(&self) -> Option<u16> {
        if self.is_request() {
            return None;
        }
        self.first_line
            .split_str(" ")
            .filter(|s| !s.is_empty())
            .nth(1)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.parse().ok())
    }

    /// The reason phrase of a response.
    pub fn reason(&self) -> BString {
        self.first_line
            .splitn_str(3, " ")
            .nth(2)
            .map(BString::from)
            .unwrap_or_default()
    }

    /// The method of a request.
    pub fn method(&self) -> Option<String> {
        self.is_request().then(|| {
            self.first_line
                .splitn_str(2, " ")
                .next()
                .unwrap_or_default()
                .to_str_lossy()
                .into_owned()
        })
    }

    /// The request URI of a request.
    pub fn uri(&self) -> Option<BString> {
        self.is_request().then(|| {
            self.first_line
                .splitn_str(3, " ")
                .nth(1)
                .map(BString::from)
                .unwrap_or_default()
        })
    }

    /// The first header named `name` (case insensitive).
    pub fn get(&self, name: &str) -> Option<&BString> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Every header named `name` (case insensitive), in order.
    pub fn get_all(&self, name: &str) -> Vec<&BString> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
            .collect()
    }

    /// The first header named `name`, as text (lossy).
    pub fn get_str(&self, name: &str) -> Option<String> {
        self.get(name).map(|v| v.to_str_lossy().into_owned())
    }

    /// The wire form: first line, headers, blank line, body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(&self.first_line);
        out.extend_from_slice(b"\r\n");
        for (k, v) in &self.headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// The wire form as text (lossy), for logs.
    pub fn text(&self) -> String {
        self.encode().to_str_lossy().into_owned()
    }
}

/// Parses one SIP message.  Header continuation lines are joined, lines
/// without a colon are skipped, and the body is cut to `Content-Length`.
pub fn parse(data: &[u8], source: Option<SocketAddr>) -> Result<Message> {
    let (head, body) = match data.find(b"\r\n\r\n") {
        Some(i) => (&data[..i], &data[i + 4..]),
        None => match data.find(b"\n\n") {
            Some(i) => (&data[..i], &data[i + 2..]),
            None => (data, &b""[..]),
        },
    };
    let head = head.replace(b"\r\n", b"\n");
    let mut lines: Vec<&[u8]> = head.split_str("\n").collect();
    while lines.first().is_some_and(|l| l.is_empty()) {
        lines.remove(0);
    }
    let Some(first) = lines.first() else {
        bail!("empty SIP message");
    };
    let mut headers: Vec<(String, BString)> = Vec::new();
    for line in &lines[1..] {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some((_, v)) = headers.last_mut() {
                v.push(b' ');
                v.extend_from_slice(line.trim_ascii());
                continue;
            }
        }
        let Some(colon) = line.find_byte(b':') else {
            continue;
        };
        let k = line[..colon].trim_ascii().to_str_lossy().into_owned();
        let v = BString::from(line[colon + 1..].trim_ascii());
        let k = if k.len() == 1 {
            expand_compact(&k).map(str::to_string).unwrap_or(k)
        } else {
            k
        };
        headers.push((k, v));
    }
    let mut msg = Message::new(first.trim_ascii(), headers, body);
    msg.source = source;
    msg.raw = data.into();
    if let Some(cl) = msg
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        let n = cl.min(msg.body.len());
        msg.body.truncate(n);
    }
    Ok(msg)
}

/// The `branch` parameter of a Via header value.
pub fn via_branch(via: &[u8]) -> Option<String> {
    let i = via.find(b"branch=")? + 7;
    let rest = &via[i..];
    let end = rest
        .iter()
        .position(|&c| c == b';' || c == b',' || c.is_ascii_whitespace())
        .unwrap_or(rest.len());
    (end > 0).then(|| rest[..end].to_str_lossy().into_owned())
}

/// Converts a list of `(name, value)` pairs given as text into message
/// headers.
pub fn headers<'a>(items: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Vec<(String, BString)> {
    items
        .into_iter()
        .map(|(k, v)| (k.to_string(), BString::from(v)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compact_and_continuation() {
        let m = parse(b"MESSAGE sip:a@b SIP/2.0\r\nv: SIP/2.0/UDP x;branch=z9hG4bKabc\r\nX-A: one\r\n two\r\nl: 3\r\n\r\nbodyextra", None).unwrap();
        assert!(m.is_request());
        assert_eq!(m.method().as_deref(), Some("MESSAGE"));
        assert_eq!(m.get("Via").unwrap(), "SIP/2.0/UDP x;branch=z9hG4bKabc");
        assert_eq!(m.get("x-a").unwrap(), "one two");
        assert_eq!(m.body, "bod");
        assert_eq!(
            via_branch(m.get("via").unwrap()).as_deref(),
            Some("z9hG4bKabc")
        );
        let r = parse(b"SIP/2.0 202 Accepted\r\n\r\n", None).unwrap();
        assert_eq!(r.status(), Some(202));
        assert_eq!(r.reason(), "Accepted");
    }
}
