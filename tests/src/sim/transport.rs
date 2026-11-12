//! The simulator's SIP layer, on `rsipstack`: sends out-of-dialog requests
//! and waits for their final response, and answers every incoming request
//! with 200 OK, handing MESSAGEs to a callback.
//!
//! Over TCP it keeps one connection to the server, from the local port
//! asked for, and also listens for UDP on the same port, as phones do: the
//! official DPMA answers a session that fails validation ("Session
//! Timeout") at the bare Response-URI, without `;transport=tcp`, so over
//! UDP; dpma-rs answers over TCP.
//!
//! `rsipstack` keeps header values as text, so a SIP header value that is
//! not UTF-8 does not survive the trip (request bodies do).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bstr::BString;
use rsipstack::sip::{Header, Method, StatusCode};
use rsipstack::transaction::endpoint::EndpointInnerRef;
use rsipstack::transaction::key::{TransactionKey, TransactionRole};
use rsipstack::transaction::make_tag;
use rsipstack::transaction::transaction::Transaction;
use rsipstack::transport::tcp::TcpConnection;
use rsipstack::transport::udp::UdpConnection;
use rsipstack::transport::{SipAddr, SipConnection};
use rsipstack::EndpointBuilder;
use socket2::{Domain, Protocol, Socket, Type};
use tokio_util::sync::CancellationToken;

use super::Logger;
use crate::sip::{self, runtime, Message, Transport};

/// Called with every incoming MESSAGE (after it was answered).
pub type MessageHandler = Box<dyn Fn(Message) + Send + Sync>;

/// The simulator's SIP endpoint (see the module documentation).
pub struct SipEndpoint {
    inner: EndpointInnerRef,
    server: SocketAddr,
    transport: Transport,
    local: SocketAddr,
    log: Logger,
    cseq: AtomicU32,
    cancel: CancellationToken,
}

fn bind_stream(local: SocketAddr) -> Result<Socket> {
    let s = Socket::new(
        Domain::for_address(local),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    s.set_reuse_address(true)?;
    s.bind(&local.into())
        .with_context(|| format!("binding {local}"))?;
    Ok(s)
}

impl SipEndpoint {
    /// Binds `local` (port 0: any) and, over TCP, connects to `server`;
    /// then starts receiving.  `timeout` bounds the TCP connect.
    pub fn start(
        server: SocketAddr,
        local: SocketAddr,
        transport: Transport,
        timeout: Duration,
        log: Logger,
        on_message: MessageHandler,
    ) -> Result<Self> {
        let cancel = CancellationToken::new();
        let endpoint = EndpointBuilder::new()
            .with_cancel_token(cancel.clone())
            .with_user_agent("dpma-sim")
            .build();
        let layer = &endpoint.inner.transport_layer;
        let local_addr = runtime().block_on(async {
            match transport {
                Transport::Udp => {
                    let c =
                        UdpConnection::create_connection(local, None, Some(cancel.child_token()))
                            .await
                            .map_err(|e| anyhow!("binding {local}: {e}"))?;
                    let addr = c.get_addr().addr.to_owned();
                    layer.add_transport(c.into());
                    Ok::<_, anyhow::Error>(SocketAddr::try_from(addr)?)
                }
                Transport::Tcp => {
                    let s = bind_stream(local)?;
                    s.connect_timeout(&server.into(), timeout)
                        .map_err(|e| anyhow!("TCP connect to {server} failed: {e}"))?;
                    let std: std::net::TcpStream = s.into();
                    std.set_nonblocking(true)?;
                    let stream = tokio::net::TcpStream::from_std(std)?;
                    let local_addr = stream.local_addr()?;
                    let sip_addr = SipAddr {
                        r#type: Some(rsipstack::sip::Transport::Tcp),
                        addr: local_addr.into(),
                    };
                    let c =
                        TcpConnection::from_stream(stream, sip_addr, Some(cancel.child_token()))
                            .map_err(|e| anyhow!("{e}"))?;
                    layer.add_connection(SipConnection::Tcp(c));
                    match UdpConnection::create_connection(
                        local_addr,
                        None,
                        Some(cancel.child_token()),
                    )
                    .await
                    {
                        Ok(u) => layer.add_transport(u.into()),
                        Err(e) => log.log(
                            1,
                            &format!("--- no UDP listener next to the TCP connection: {e}"),
                        ),
                    }
                    Ok(local_addr)
                }
            }
        })?;
        let mut incoming = endpoint
            .incoming_transactions()
            .map_err(|e| anyhow!("{e}"))?;
        let serving = endpoint.inner.clone();
        runtime().spawn(async move {
            let _ = serving.serve().await;
        });
        let handler: Arc<MessageHandler> = Arc::new(on_message);
        let hlog = log.clone();
        runtime().spawn(async move {
            while let Some(mut tx) = incoming.recv().await {
                let is_message = tx.original.method == Method::Message;
                let msg = sip::from_request(&tx.original);
                let _ = tx.reply(StatusCode::OK).await;
                if is_message {
                    hlog.log(2, &format!("<<< SIP\n{}", tx.original));
                    handler(msg);
                }
            }
        });
        Ok(SipEndpoint {
            inner: endpoint.inner.clone(),
            server,
            transport,
            local: local_addr,
            log,
            cseq: AtomicU32::new(rand::random::<u32>() % 10000 + 1),
            cancel,
        })
    }

    /// The local address (the port the server answers to).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The transport.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Sends a request and returns its final response (`None` on
    /// timeout).
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        method: &str,
        ruri: &str,
        headers: &[(String, BString)],
        body: &[u8],
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        timeout: Duration,
    ) -> Option<Message> {
        runtime()
            .block_on(async {
                tokio::time::timeout(
                    timeout,
                    self.request_async(method, ruri, headers, body, from_uri, to_uri),
                )
                .await
            })
            .ok()?
    }

    async fn request_async(
        &self,
        method: &str,
        ruri: &str,
        headers: &[(String, BString)],
        body: &[u8],
        from_uri: Option<&str>,
        to_uri: Option<&str>,
    ) -> Option<Message> {
        let host = self.local.ip().to_string();
        let uri = |s: &str| rsipstack::sip::Uri::try_from(s).ok();
        let ruri_parsed = uri(ruri)?;
        let from = rsipstack::sip::typed::From {
            display_name: None,
            uri: uri(&from_uri
                .map(str::to_string)
                .unwrap_or_else(|| format!("sip:sim@{host}")))?,
            params: vec![],
        }
        .with_tag(make_tag());
        let to = rsipstack::sip::typed::To {
            display_name: None,
            uri: uri(to_uri.unwrap_or(ruri))?,
            params: vec![],
        };
        let via = self
            .inner
            .get_via(
                Some(SipAddr {
                    r#type: Some(match self.transport {
                        Transport::Udp => rsipstack::sip::Transport::Udp,
                        Transport::Tcp => rsipstack::sip::Transport::Tcp,
                    }),
                    addr: self.local.into(),
                }),
                None,
            )
            .ok()?;
        let cseq = self.cseq.fetch_add(1, Ordering::SeqCst) + 1;
        let mut request = self.inner.make_request(
            Method::try_from(method).ok()?,
            ruri_parsed,
            via,
            from,
            to,
            cseq,
            None,
        );
        // The caller's headers replace the endpoint's own User-Agent.
        request
            .headers
            .retain(|h| !matches!(h, Header::UserAgent(_)));
        for (name, value) in headers {
            request.headers.push(Header::Other(
                name.clone(),
                String::from_utf8_lossy(value).into_owned(),
            ));
        }
        request.body = body.to_vec();
        self.log
            .log(2, &format!(">>> SIP to {}\n{}", self.server, request));
        self.log.log(
            1,
            &format!(">>> {method} {ruri} ({} body bytes)", body.len()),
        );
        let key = TransactionKey::from_request(&request, TransactionRole::Client).ok()?;
        let mut tx = Transaction::new_client(key, request, self.inner.clone(), None);
        tx.destination = Some(SipAddr {
            r#type: Some(match self.transport {
                Transport::Udp => rsipstack::sip::Transport::Udp,
                Transport::Tcp => rsipstack::sip::Transport::Tcp,
            }),
            addr: self.server.into(),
        });
        tx.send().await.ok()?;
        while let Some(reply) = tx.receive().await {
            if let rsipstack::sip::SipMessage::Response(r) = reply {
                if r.status_code.code() >= 200 {
                    self.log.log(2, &format!("<<< SIP\n{r}"));
                    return Some(sip::from_response(&r, self.transport));
                }
            }
        }
        None
    }

    /// Stops receiving and closes the sockets.
    pub fn close(&mut self) {
        self.cancel.cancel();
    }
}

impl Drop for SipEndpoint {
    fn drop(&mut self) {
        self.close();
    }
}
