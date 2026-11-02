//! Chunking in both directions (`phone_msg_outgoing_send`,
//! `incoming_add_msg`, `incoming_check_finalize`).
//!
//! Phone to server ([`frame_request_body`]): plaintext is split so that no
//! chunk but the last ends in CR or LF (res_pjsip_messaging strips them);
//! encrypted bodies are encrypted whole, base64 encoded, and the text
//! split, because the server joins the chunk bodies and decodes them once.
//!
//! Server to phone ([`server_frame`]): an emulation of the module's
//! framing, for the self-test and the vectors: chunks of at most a fixed
//! number of plaintext bytes (prefix included), one CBC stream with each
//! chunk's ciphertext base64 encoded on its own.

use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::{bail, Result};
use regex::bytes::Regex;

use super::crypto::{b64encode, salt_hex, StreamEncryptor};
use super::proto::{H_FINISHED, H_SALT, H_SEQUENCE};

/// The server's per-chunk plaintext limit over UDP, plaintext messages.
pub const SERVER_UDP_PLAIN_LIMIT: usize = 0x267;
/// The server's per-chunk plaintext limit over UDP, encrypted messages.
pub const SERVER_UDP_ENCRYPTED_LIMIT: usize = 0x1a4;
/// The server's per-chunk plaintext limit when the response URI has
/// `transport=tcp`.
pub const SERVER_TCP_LIMIT: usize = 0x384;

/// How an encrypted request body is cut into chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChunkStyle {
    /// The whole body is encrypted and base64 encoded, and the text split
    /// into chunks: the form the server can reassemble.
    #[default]
    Split,
    /// The way the server itself sends: one CBC stream, each chunk's
    /// ciphertext base64 encoded on its own.  The server cannot reassemble
    /// it whenever a non-final chunk's ciphertext length is not a multiple
    /// of 3.
    Stream,
}

impl FromStr for ChunkStyle {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "split" => Ok(ChunkStyle::Split),
            "stream" => Ok(ChunkStyle::Stream),
            _ => bail!("unknown chunk style {s:?}"),
        }
    }
}

impl fmt::Display for ChunkStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChunkStyle::Split => "split",
            ChunkStyle::Stream => "stream",
        })
    }
}

/// Splits `data` into pieces of at most `size` bytes (one empty piece for
/// empty data).
pub fn split_bytes(data: &[u8], size: usize) -> Result<Vec<Vec<u8>>> {
    if size < 1 {
        bail!("chunk size must be positive");
    }
    if data.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    Ok(data.chunks(size).map(<[u8]>::to_vec).collect())
}

/// Splits plaintext into pieces of at most `size` bytes such that no piece
/// but the last ends in CR or LF: res_pjsip_messaging's `print_body`
/// strips trailing CR/LF from every MESSAGE body, so a line break at the
/// end of a chunk would be lost in the server's reassembly.
pub fn split_plain(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let mut end = (pos + size).min(data.len());
        if end < data.len() {
            let mut cut = end;
            while cut > pos && matches!(data[cut - 1], b'\r' | b'\n') {
                cut -= 1;
            }
            if cut > pos {
                end = cut;
            }
        }
        out.push(data[pos..end].to_vec());
        pos = end;
    }
    if out.is_empty() {
        out.push(Vec::new());
    }
    out
}

fn pem_marker_line() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"-----(?:BEGIN|END) [^\r\n-]*-----(?:\r?\n)?").unwrap())
}

/// Cuts `data` before and after every PEM BEGIN and END line (its line
/// break included).  Chunks cut there end right after a BEGIN or END line
/// or right before one, so res_pjsip_messaging's CR/LF stripping removes
/// exactly the line breaks at the PEM boundaries (dpma-rs restores them).
pub fn pem_segments(data: &[u8]) -> Vec<&[u8]> {
    let mut cuts = vec![0, data.len()];
    for m in pem_marker_line().find_iter(data) {
        cuts.push(m.start());
        cuts.push(m.end());
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts.windows(2).map(|w| &data[w[0]..w[1]]).collect()
}

/// What res_pjsip_messaging makes of a MESSAGE body: at most 1023 bytes
/// (`MAX_BODY_SIZE`), trailing CR/LF removed.
pub fn asterisk_print_body(body: &[u8]) -> Vec<u8> {
    let mut b = &body[..body.len().min(1023)];
    while let [rest @ .., b'\r' | b'\n'] = b {
        b = rest;
    }
    b.to_vec()
}

/// Wire bodies for a phone-to-server request.
///
/// Plaintext (`enc` is `None`): the body split into pieces of at most
/// `size` bytes, never ending a piece (but the last) in CR or LF (see
/// [`split_plain`]).  With `pem_cuts`, pieces also end right before and
/// right after every PEM BEGIN and END line, line break included (see
/// [`pem_segments`]), so the server loses those line breaks.
///
/// Encrypted (`enc` is the common password and the salt): see
/// [`ChunkStyle`].
pub fn frame_request_body(
    body: &[u8],
    size: usize,
    enc: Option<(&[u8], &[u8])>,
    style: ChunkStyle,
    pem_cuts: bool,
) -> Result<Vec<Vec<u8>>> {
    if size < 1 {
        bail!("chunk size must be positive");
    }
    let Some((password, salt)) = enc else {
        if pem_cuts {
            let out: Vec<Vec<u8>> = pem_segments(body)
                .into_iter()
                .flat_map(|seg| split_plain(seg, size))
                .collect();
            return Ok(if out.is_empty() {
                vec![Vec::new()]
            } else {
                out
            });
        }
        return Ok(split_plain(body, size));
    };
    if body.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    match style {
        ChunkStyle::Split => {
            let text = b64encode(&super::crypto::encrypt(password, salt, body));
            split_bytes(text.as_bytes(), size)
        }
        ChunkStyle::Stream => {
            let pieces = split_bytes(body, size)?;
            let n = pieces.len();
            let mut stream = Some(StreamEncryptor::new(password, salt));
            Ok(pieces
                .iter()
                .enumerate()
                .map(|(i, piece)| {
                    let mut data = stream.as_mut().map(|e| e.update(piece)).unwrap_or_default();
                    if i == n - 1 {
                        data.extend(
                            stream
                                .take()
                                .map(StreamEncryptor::finish)
                                .unwrap_or_default(),
                        );
                    }
                    b64encode(&data).into_bytes()
                })
                .collect())
        }
    }
}

/// One chunk of the server's framing: its framing headers (salt,
/// sequence, finished, in that order) and its wire body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerFrame {
    /// `Message-Salt`, `Message-Sequence`, and `Message-Finished`, as
    /// present.
    pub headers: Vec<(&'static str, String)>,
    /// The wire body: plaintext, or the chunk's ciphertext in base64.
    pub body: Vec<u8>,
}

impl ServerFrame {
    /// A framing header's value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An emulation of the server's `phone_msg_outgoing_send` framing:
/// chunks of at most `limit` plaintext bytes including `prefix`, one CBC
/// stream with each chunk's output base64 encoded on its own (`enc` is the
/// common password and salt), `Message-Sequence` on every chunk except the
/// only chunk of a HandshakeResponse, and `Message-Finished` on the last.
/// An empty body is sent as `empty body`.
pub fn server_frame(
    body: &[u8],
    limit: usize,
    enc: Option<(&[u8], &[u8])>,
    prefix: &[u8],
    handshake_response: bool,
) -> Vec<ServerFrame> {
    let body: &[u8] = if body.is_empty() { b"empty body" } else { body };
    let mut stream = enc.map(|(pw, salt)| StreamEncryptor::new(pw, salt));
    let mut out = Vec::new();
    let mut pos = 0;
    let mut seq = 0;
    loop {
        let take = (body.len() - pos).min(limit - prefix.len());
        let mut plain = prefix.to_vec();
        plain.extend_from_slice(&body[pos..pos + take]);
        pos += take;
        let last = pos >= body.len();
        let wire = match stream.as_mut() {
            Some(e) => {
                let mut data = e.update(&plain);
                if last {
                    data.extend(stream.take().unwrap().finish());
                }
                b64encode(&data).into_bytes()
            }
            None => plain,
        };
        let mut headers = Vec::new();
        if let Some((_, salt)) = enc {
            headers.push((H_SALT, salt_hex(salt)));
        }
        if !(last && seq == 0 && handshake_response) {
            headers.push((H_SEQUENCE, seq.to_string()));
            if last {
                headers.push((H_FINISHED, "1".to_string()));
            }
        }
        out.push(ServerFrame {
            headers,
            body: wire,
        });
        seq += 1;
        if last {
            return out;
        }
    }
}
