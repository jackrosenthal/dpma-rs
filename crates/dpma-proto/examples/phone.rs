//! A phone: handshakes with a DPMA server, then pings it.
//!
//! ```text
//! cargo run --example phone -- SERVER_ADDR CERTIFICATES.pem PRIVATE_KEY.pem [MAC]
//! ```
//!
//! `CERTIFICATES.pem` is the PEM text that the phone sends in its Handshake
//! (the certificates of its chain, the phone's own last), and `PRIVATE_KEY.pem`
//! is the RSA private key (PKCS#1) of that last certificate.  The protocol is
//! `dpma-proto`'s; SIP is `rsipstack`'s (see `common/mod.rs`).

mod common;

use std::net::SocketAddr;

use common::{uri, Error, Sip};
use dpma_proto::message::{Collector, Request, Sender};
use dpma_proto::{crypto, types};
use rsa::pkcs1::DecodeRsaPrivateKey;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let (Some(server), Some(certificates), Some(key)) = (args.next(), args.next(), args.next())
    else {
        return Err("usage: phone SERVER_ADDR CERTIFICATES.pem PRIVATE_KEY.pem [MAC]".into());
    };
    let mac = args.next().unwrap_or_else(|| "0004f2aabbcc".into());
    let server: SocketAddr = server.parse()?;
    let certificates = std::fs::read(certificates)?;
    let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(&std::fs::read_to_string(key)?)?;

    let mut sip = Sip::start("127.0.0.1:0".parse()?).await?;
    let (server, me) = (uri("dpma", server), uri(&mac, sip.addr()));

    // Handshake: the certificates go in, and the common password comes back
    // encrypted to the key of the last of them.
    let handshake = Request {
        request_type: types::HANDSHAKE.into(),
        mac: mac.clone().into_bytes(),
        body: certificates,
        ..Default::default()
    };
    for message in handshake.encode(None, 600)? {
        sip.send(&server, &me, &me, &message).await?;
    }
    let response = receive(&mut sip, None).await?;
    if response.error != 0 {
        return Err(format!("the handshake failed: error {}", response.error).into());
    }
    let password = crypto::decrypt_common_password(&private_key, &response.password)?;
    let session = response.session_id;
    println!(
        "handshake: session {}, {} bytes of AppServer certificate",
        String::from_utf8_lossy(&session),
        response.body.len()
    );

    // Every request from now on is encrypted with the common password.
    let ping = Request {
        request_type: types::PING_REQUEST.into(),
        mac: mac.into_bytes(),
        session_id: session,
        ..Default::default()
    };
    for message in ping.encode(Some(&password), 600)? {
        sip.send(&server, &me, &me, &message).await?;
    }
    let pong = receive(&mut sip, Some(&password)).await?;
    println!(
        "{}: error {}",
        String::from_utf8_lossy(&pong.response_type),
        pong.error
    );
    Ok(())
}

/// The next whole message from the server, decoded.
async fn receive(
    sip: &mut Sip,
    password: Option<&[u8]>,
) -> Result<dpma_proto::message::Incoming, Error> {
    let mut parts = Collector::new();
    while let Some(received) = sip.receive().await {
        parts.add(received.message, ());
        if parts.is_complete() {
            return Ok(parts.decode(Sender::Server, password)?);
        }
    }
    Err("the server went away".into())
}
