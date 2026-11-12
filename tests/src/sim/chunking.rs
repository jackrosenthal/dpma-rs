//! The ways the simulator deliberately sends a request differently from
//! [`dpma_proto::message::Request::encode`], to see how the module copes:
//! with the chunking of the server, and with the cuts that real phones make
//! in a Handshake body.

use std::str::FromStr;

use anyhow::{bail, Result};
use dpma_proto::framing::{self, Chunk};
use dpma_proto::headers as h;
use dpma_proto::message::{Message, Request};
use regex::bytes::Regex;

/// How an encrypted request body is cut into chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChunkStyle {
    /// The whole body is encrypted and base64 encoded, and the text split
    /// into chunks: the form the server can reassemble (what
    /// `Request::encode` sends).
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

impl std::fmt::Display for ChunkStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChunkStyle::Split => "split",
            ChunkStyle::Stream => "stream",
        })
    }
}

/// `messages` (as `Request::encode` made them) with their bodies replaced
/// by `bodies`, and the sequence headers to match.
fn with_bodies(messages: &[Message], bodies: Vec<Vec<u8>>) -> Vec<Message> {
    let mut base = messages[0].clone();
    base.headers.retain(|(k, _)| {
        !k.eq_ignore_ascii_case(h::MESSAGE_SEQUENCE) && !k.eq_ignore_ascii_case(h::MESSAGE_FINISHED)
    });
    let n = bodies.len();
    bodies
        .into_iter()
        .enumerate()
        .map(|(i, body)| {
            let mut m = base.clone();
            m.set(h::MESSAGE_SEQUENCE, i.to_string());
            if i + 1 == n {
                m.set(h::MESSAGE_FINISHED, "1");
            }
            m.body = body;
            m
        })
        .collect()
}

/// Cuts `data` before and after every PEM BEGIN and END line (its line
/// break included), so that the pieces end right after a BEGIN or END line
/// or right before one.
fn pem_segments(data: &[u8]) -> Vec<&[u8]> {
    let marker = Regex::new(r"-----(?:BEGIN|END) [^\r\n-]*-----(?:\r?\n)?").unwrap();
    let mut cuts = vec![0, data.len()];
    for m in marker.find_iter(data) {
        cuts.push(m.start());
        cuts.push(m.end());
    }
    cuts.sort_unstable();
    cuts.dedup();
    cuts.windows(2).map(|w| &data[w[0]..w[1]]).collect()
}

/// The MESSAGEs of `request`, sent with the deviations asked for.
/// `password` is the common password when the request is encrypted.
pub fn encode(
    request: &Request,
    password: Option<&[u8]>,
    size: usize,
    style: ChunkStyle,
    pem_cuts: bool,
) -> Result<Vec<Message>> {
    let messages = request.encode(password, size)?;
    match (password, style, pem_cuts) {
        (Some(password), ChunkStyle::Stream, _) if !request.body.is_empty() => {
            let salt = messages[0]
                .header(h::MESSAGE_SALT)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            let salt = dpma_proto::crypto::salt_from_hex(salt)?;
            let chunks: Vec<Chunk> = request
                .body
                .chunks(size.max(1))
                .map(|piece| Chunk {
                    sequence: None,
                    finished: false,
                    plain: piece.to_vec(),
                })
                .collect();
            let bodies = framing::encrypt_chunks(&chunks, password, &salt)?
                .into_iter()
                .map(String::into_bytes)
                .collect();
            Ok(with_bodies(&messages, bodies))
        }
        (None, _, true) => {
            let mut bodies = Vec::new();
            for segment in pem_segments(&request.body) {
                let piece = Request {
                    body: segment.to_vec(),
                    ..Default::default()
                };
                bodies.extend(piece.encode(None, size)?.into_iter().map(|m| m.body));
            }
            Ok(with_bodies(&messages, bodies))
        }
        _ => Ok(messages),
    }
}
