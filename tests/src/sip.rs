//! The SIP messages that the simulator and the test user agents report,
//! as plain data (the SIP itself is `rsipstack`'s).

use std::fmt;
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

/// The runtime that the SIP stack ([`rsipstack`]) runs on.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a tokio runtime")
    })
}

fn headers_of(headers: &rsipstack::sip::Headers) -> Vec<(String, BString)> {
    headers
        .iter()
        .map(|h| (h.name().to_string(), BString::from(h.value())))
        .collect()
}

/// A request that `rsipstack` received, as a [`Message`].  Its transport is
/// the one in the top Via header.
pub fn from_request(r: &rsipstack::sip::Request) -> Message {
    let mut m = Message::new(
        format!("{} {} SIP/2.0", r.method, r.uri),
        headers_of(&r.headers),
        r.body.clone(),
    );
    m.transport = m.get("Via").and_then(|via| {
        let via = via.to_str_lossy().to_ascii_uppercase();
        if via.starts_with("SIP/2.0/TCP") {
            Some(Transport::Tcp)
        } else if via.starts_with("SIP/2.0/UDP") {
            Some(Transport::Udp)
        } else {
            None
        }
    });
    m
}

/// A response that `rsipstack` received, as a [`Message`].
pub fn from_response(r: &rsipstack::sip::Response, transport: Transport) -> Message {
    let mut m = Message::new(
        format!(
            "SIP/2.0 {} {}",
            r.status_code.code(),
            r.status_code
                .to_string()
                .split_once(' ')
                .map_or("", |x| x.1)
        ),
        headers_of(&r.headers),
        r.body.clone(),
    );
    m.transport = Some(transport);
    m
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
    /// The transport an incoming message arrived on.
    pub transport: Option<Transport>,
    /// When the message was received or built.
    pub received: Instant,
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
            transport: None,
            received: Instant::now(),
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
}
