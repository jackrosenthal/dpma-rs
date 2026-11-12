//! The SIP side of the examples: an `rsipstack` endpoint that sends and
//! receives the protocol's MESSAGEs as `dpma_proto::message::Message`s.
//! Everything about the protocol itself is in `dpma-proto`.

// Each example uses some of this.
#![allow(dead_code)]

use std::net::SocketAddr;

use dpma_proto::message::Message;
use rsipstack::sip::headers::untyped::ToTypedHeader;
use rsipstack::sip::prelude::HeadersExt;
use rsipstack::sip::{Header, Method, StatusCode, Uri};
use rsipstack::transaction::endpoint::EndpointInnerRef;
use rsipstack::transaction::key::{TransactionKey, TransactionRole};
use rsipstack::transaction::transaction::Transaction;
use rsipstack::transaction::{make_tag, TransactionReceiver};
use rsipstack::transport::udp::UdpConnection;
use rsipstack::EndpointBuilder;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A SIP endpoint on one UDP port.
pub struct Sip {
    inner: EndpointInnerRef,
    incoming: TransactionReceiver,
    addr: SocketAddr,
}

/// A MESSAGE that arrived.
pub struct Received {
    pub message: Message,
    /// The `Contact` of the sender: where to send replies.
    pub contact: Uri,
}

impl Sip {
    /// Listen on `bind`.
    pub async fn start(bind: SocketAddr) -> Result<Sip, Error> {
        let endpoint = EndpointBuilder::new()
            .with_user_agent("dpma-proto example")
            .build();
        let connection = UdpConnection::create_connection(bind, None, None).await?;
        let addr = connection.get_addr().addr.to_owned();
        endpoint
            .inner
            .transport_layer
            .add_transport(connection.into());
        let incoming = endpoint.incoming_transactions()?;
        let inner = endpoint.inner.clone();
        tokio::spawn(async move {
            let _ = inner.serve().await;
        });
        Ok(Sip {
            inner: endpoint.inner.clone(),
            incoming,
            addr: addr.try_into()?,
        })
    }

    /// The address this endpoint listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The next MESSAGE, which is answered `200 OK`.
    pub async fn receive(&mut self) -> Option<Received> {
        loop {
            let mut tx = self.incoming.recv().await?;
            if tx.original.method != Method::Message {
                let _ = tx.reply(StatusCode::MethodNotAllowed).await;
                continue;
            }
            let message = Message {
                headers: tx
                    .original
                    .headers
                    .iter()
                    .map(|h| (h.name().to_string(), h.value().as_bytes().to_vec()))
                    .collect(),
                body: tx.original.body.clone(),
            };
            let contact = tx
                .original
                .contact_header()
                .ok()
                .and_then(|c| c.typed().ok())
                .map(|c| c.uri);
            let _ = tx.reply(StatusCode::OK).await;
            let Some(contact) = contact else { continue };
            return Some(Received { message, contact });
        }
    }

    /// Send `message` as a SIP MESSAGE to `to`, as `from` (a SIP URI),
    /// with `contact` as the address that replies go to.  Returns when the
    /// MESSAGE has been answered.
    pub async fn send(
        &self,
        to: &Uri,
        from: &Uri,
        contact: &Uri,
        message: &Message,
    ) -> Result<(), Error> {
        let via = self.inner.get_via(None, None)?;
        let mut request = self.inner.make_request(
            Method::Message,
            to.clone(),
            via,
            rsipstack::sip::typed::From {
                display_name: None,
                uri: from.clone(),
                params: vec![],
            }
            .with_tag(make_tag()),
            rsipstack::sip::typed::To {
                display_name: None,
                uri: to.clone(),
                params: vec![],
            },
            1,
            None,
        );
        request.headers.push(Header::Contact(
            rsipstack::sip::typed::Contact {
                display_name: None,
                uri: contact.clone(),
                params: vec![],
            }
            .into(),
        ));
        request
            .headers
            .push(Header::ContentType("text/plain".to_string().into()));
        for (name, value) in &message.headers {
            request.headers.push(Header::Other(
                name.clone(),
                String::from_utf8_lossy(value).into_owned(),
            ));
        }
        request.body = message.body.clone();

        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request, self.inner.clone(), None);
        tx.send().await?;
        while let Some(reply) = tx.receive().await {
            if let rsipstack::sip::SipMessage::Response(r) = reply {
                if r.status_code.code() >= 200 {
                    return match r.status_code.code() {
                        200..=299 => Ok(()),
                        code => Err(format!("the MESSAGE was refused: {code}").into()),
                    };
                }
            }
        }
        Err("the MESSAGE was not answered".into())
    }
}

/// The SIP URI of `addr`.
pub fn uri(user: &str, addr: SocketAddr) -> Uri {
    Uri::try_from(format!("sip:{user}@{addr}").as_str()).expect("a SIP URI")
}
