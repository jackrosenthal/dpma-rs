//! A DPMA server: handshakes with phones and answers their pings.
//!
//! ```text
//! cargo run --example server -- [LISTEN_ADDR] [CA_CERTIFICATES.pem]
//! ```
//!
//! Phones are verified against the CA certificates built into the official
//! DPMA unless `CA_CERTIFICATES.pem` names others.  The protocol is
//! `dpma-proto`'s; SIP is `rsipstack`'s (see `common/mod.rs`).

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;

use common::{uri, Error, Sip};
use dpma_proto::message::{Outgoing, SendContext, Sender, Transactions};
use dpma_proto::{cert, crypto, headers, types};
use rsipstack::sip::Uri;

/// What a server remembers of a phone after its handshake.
struct Session {
    password: Vec<u8>,
    /// The phone sent the certificate-chain form of its Handshake.
    chain_certificate: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let listen: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:5060".into())
        .parse()?;
    let store = match args.next() {
        Some(path) => cert::CaStore::from_pem(&std::fs::read(path)?)?,
        None => cert::CaStore::builtin(),
    };

    let mut sip = Sip::start(listen).await?;
    let me = uri("dpma", sip.addr());
    println!("listening on {}", sip.addr());

    let mut sessions: HashMap<Vec<u8>, Session> = HashMap::new();
    let mut next_session = 1000;
    // MESSAGEs are grouped by transaction; each carries the session it is
    // for and where to send the reply.
    let mut transactions: Transactions<(Vec<u8>, Uri)> = Transactions::new(Sender::Phone);
    let mut clock = 0;

    while let Some(received) = sip.receive().await {
        clock += 1;
        let session_id = received
            .message
            .header(headers::SESSION)
            .unwrap_or_default()
            .to_vec();
        let Some(((session_id, contact), parts)) =
            transactions.add(received.message, (), clock, (session_id, received.contact))
        else {
            continue;
        };
        let password = sessions.get(&session_id).map(|s| s.password.as_slice());
        let request = match parts.decode(Sender::Phone, password) {
            Ok(request) => request,
            Err(e) => {
                println!("dropped a request: {e}");
                continue;
            }
        };
        let request_type = String::from_utf8_lossy(&request.request_type).into_owned();
        println!("{request_type} from {contact}");

        let mut reply = Outgoing::new();
        reply.id = request.id.clone();
        reply.response_uri = contact.to_string().into_bytes();
        let send = if request_type.eq_ignore_ascii_case(types::HANDSHAKE) {
            // A phone's certificates arrive without the line breaks that
            // Asterisk strips from the ends of MESSAGEs.
            let certificates = cert::restore_pem_newlines(&request.body);
            let contact_text = contact.to_string();
            let info = cert::ClientInfo {
                contact: contact_text.as_bytes(),
                mac: Some(&request.mac),
                user_agent: b"",
            };
            let client = match cert::verify_client_chain(&store, certificates, &info) {
                Ok(client) => client,
                Err(e) => {
                    println!("refused the handshake: {e}");
                    continue;
                }
            };
            let Some(phone_key) = &client.public_key else {
                continue;
            };
            // The HandshakeResponse (the one message that is not encrypted)
            // carries the new common password, encrypted to the phone's key,
            // and the AppServer certificate.
            let password = crypto::new_common_password()?;
            reply.response_type = types::response_type_for(types::HANDSHAKE)
                .unwrap_or_default()
                .into();
            reply.password = crypto::encrypt_common_password(phone_key, &password)?.into_bytes();
            reply.append(cert::DEFAULT_APPSERVER_CERTIFICATE);
            let session_id = next_session.to_string().into_bytes();
            next_session += 1;
            let session = Session {
                password,
                chain_certificate: client.intermediate_serial != 0,
            };
            let ctx = context(&session, &session_id);
            let messages = reply.encode(&ctx)?;
            sessions.insert(session_id, session);
            messages
        } else if let (Some(session), Some(response_type)) = (
            sessions.get(&session_id),
            types::response_type_for(&request.request_type),
        ) {
            // Any other request is answered with an empty reply of its type.
            reply.response_type = response_type.into();
            reply.encode(&context(session, &session_id))?
        } else {
            println!("no session {}", String::from_utf8_lossy(&session_id));
            continue;
        };
        for message in &send {
            sip.send(&contact, &me, &me, message).await?;
        }
    }
    Ok(())
}

fn context<'a>(session: &'a Session, session_id: &'a [u8]) -> SendContext<'a> {
    SendContext {
        password: &session.password,
        session_id,
        origination_network: b"",
        chain_certificate: session.chain_certificate,
    }
}
