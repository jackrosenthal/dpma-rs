//! `dpma-sim`: the phone simulator from the command line (see the
//! `dpma_tests::sim` documentation).
//!
//! ```text
//! dpma-sim [global options] COMMAND [command options]
//! ```
//!
//! Requests that need a session handshake first, unless
//! `--no-auto-handshake` is given; `--state FILE` keeps the session (id,
//! common password, token, and local port) across invocations.  Examples:
//!
//! ```text
//! dpma-sim handshake                        # chain form
//! dpma-sim --form legacy -v ping            # handshake, then an encrypted ping
//! dpma-sim token --user simphone --config-pass 344486
//! dpma-sim --state s.json token --user simphone --config-pass 344486
//! dpma-sim --state s.json config            # reuses session, token, and port
//! dpma-sim asterisk --auth simphone:1234 --method test.dpma.api.echo --params '{"x": 1}'
//! dpma-sim --local-port 15599 listen        # events (e.g., reconfigure)
//! dpma-sim --local-host 127.0.0.2 --no-digium-ua-header echo hi   # loopback: no module needed
//! dpma-sim selftest                         # no server needed
//! ```
//!
//! Output: `>>` describes what was sent (type, transaction id, chunks,
//! encryption, and the SIP status of each chunk), `<<` the reply: its
//! `X-` headers, decrypted fields, problems, and body.  The body shown is
//! the payload: for events and error replies the server's `Command: `
//! prefix is removed from every chunk.
//!
//! Exit status: 0 when the expected response type arrives without an
//! error (`raw`: any reply), 1 otherwise, 2 on setup errors.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use bstr::BString;
use clap::{Args, Parser, Subcommand, ValueEnum};
use dpma_tests::harness::Checker;
use dpma_tests::sim::proto::{method_request_json, method_request_xml, needs_session};
use dpma_tests::sim::{
    self, selftest, ChunkStyle, Exchange, Form, Options, Phone, RequestBuilder, Transport,
};

#[derive(Parser)]
#[command(name = "dpma-sim", about = "Simulate a Digium phone against dpma-rs.")]
struct Cli {
    /// Instance slot: SIP port 15060+100*slot (default: $DPMA_SLOT).
    #[arg(long)]
    slot: Option<u32>,
    /// Asterisk address.
    #[arg(long, default_value = "127.0.0.1")]
    server: String,
    /// Asterisk SIP port (overrides --slot).
    #[arg(long)]
    sip_port: Option<u16>,
    /// The simulator's address (127.0.0.2: the loopback test path).
    #[arg(long, default_value = "127.0.0.1")]
    local_host: String,
    /// The simulator's port (default: any; reused from --state).
    #[arg(long, default_value_t = 0)]
    local_port: u16,
    /// SIP transport.
    #[arg(long, value_enum, default_value_t = TransportArg::Udp)]
    transport: TransportArg,
    /// X-Digium-AppServer-MACAddress (colons removed).
    #[arg(long, default_value = sim::DEFAULT_MAC)]
    mac: String,
    /// User-Agent and X-Digium-User-Agent; '' sends neither.
    #[arg(long, default_value = sim::DEFAULT_UA)]
    user_agent: OsString,
    /// Do not send X-Digium-User-Agent (by which the module identifies phones).
    #[arg(long)]
    no_digium_ua_header: bool,
    /// Contact URI (default: sip:MAC@HOST:PORT of the local socket).
    #[arg(long)]
    contact: Option<String>,
    /// Send X-Origination-Network.
    #[arg(long)]
    origination_network: Option<OsString>,
    /// Handshake certificate form.
    #[arg(long, value_enum, default_value_t = FormArg::Chain)]
    form: FormArg,
    /// Handshake bundle of the test PKI (overrides --form).
    #[arg(long)]
    bundle: Option<String>,
    /// Test PKI directory.
    #[arg(long)]
    pki: Option<PathBuf>,
    /// Do not fail when the AppServer certificate does not verify.
    #[arg(long)]
    no_appserver_check: bool,
    /// Do not handshake before a request that needs a session.
    #[arg(long)]
    no_auto_handshake: bool,
    /// Load and save the session in this JSON file.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Maximum body bytes per MESSAGE (default 600 UDP, 900 TCP).
    #[arg(long)]
    chunk_size: Option<usize>,
    /// Encrypted chunking.
    #[arg(long, value_enum, default_value_t = StyleArg::Split)]
    chunk_style: StyleArg,
    /// Milliseconds between chunks.
    #[arg(long, default_value_t = 5.0)]
    chunk_delay: f64,
    /// Send requests unencrypted even with a session.
    #[arg(long)]
    plain: bool,
    /// Reply timeout in seconds.
    #[arg(long, default_value_t = 5.0)]
    timeout: f64,
    /// -v: SIP summary, -vv: full SIP messages.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum TransportArg {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, ValueEnum)]
enum FormArg {
    Legacy,
    Chain,
}

#[derive(Clone, Copy, ValueEnum)]
enum StyleArg {
    Split,
    Stream,
}

#[derive(Clone, Copy, ValueEnum)]
enum EncryptArg {
    Auto,
    Yes,
    No,
}

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Json,
    Xml,
}

#[derive(Clone, Copy, ValueEnum)]
#[allow(clippy::enum_variant_names)]
enum RequestTypeArg {
    #[value(name = "AsteriskRequest")]
    AsteriskRequest,
    #[value(name = "HTTPRequest")]
    HttpRequest,
}

#[derive(Args, Clone)]
struct ReqOpts {
    /// Send without waiting for the reply.
    #[arg(long)]
    no_wait: bool,
    /// Reply timeout in seconds (default: the global --timeout).
    #[arg(long = "timeout")]
    cmd_timeout: Option<f64>,
    /// Extra header for every chunk, 'Name: Value' (repeatable).
    #[arg(long)]
    header: Vec<OsString>,
    /// Maximum body bytes per MESSAGE for this request.
    #[arg(long = "chunk-size")]
    cmd_chunk_size: Option<usize>,
    /// End plaintext chunks right before and after every PEM BEGIN and END line.
    #[arg(long)]
    pem_cuts: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Handshake (legacy or chain certificate form).
    Handshake {
        /// Bundle (default from --form).
        #[arg(long = "bundle")]
        cmd_bundle: Option<String>,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// PingRequest.
    Ping {
        #[command(flatten)]
        o: ReqOpts,
    },
    /// Echo (unencrypted, no session).
    Echo {
        #[arg(default_value = "hello from dpma_sim")]
        body: OsString,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// ConfigRequest with the configuration token.
    Config {
        /// Token (default: from the last TokenRequest).
        #[arg(long)]
        token: Option<OsString>,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// TokenRequest.
    Token {
        /// X-Digium-AppServer-Username (phone name).
        #[arg(long)]
        user: Option<OsString>,
        /// X-Digium-AppServer-Password (phone pin).
        #[arg(long)]
        pin: Option<OsString>,
        /// X-Digium-AppServer-ConfigPassword (global or group pin).
        #[arg(long)]
        config_pass: Option<OsString>,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// UserlistRequest.
    Userlist {
        /// X-Digium-AppServer-ConfigPassword.
        #[arg(long)]
        config_pass: Option<OsString>,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// FileRequest for file://NAME.
    File {
        /// default, null, or a file in file_directory.
        name: OsString,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// VerifyRequest with the configuration token.
    Verify {
        /// Token (default: from the last TokenRequest).
        #[arg(long)]
        token: Option<OsString>,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// AsteriskRequest or HTTPRequest (method call).
    Asterisk {
        /// Credentials USER:SECRET for X-Digium-AppServer-Digest-Auth.
        #[arg(long)]
        auth: Option<OsString>,
        /// Request type.
        #[arg(long = "type", value_enum, default_value_t = RequestTypeArg::AsteriskRequest)]
        rtype: RequestTypeArg,
        /// Method name (with --params and --format).
        #[arg(long, group = "doc")]
        method: Option<String>,
        /// A complete XML request document.
        #[arg(long, group = "doc")]
        xml: Option<OsString>,
        /// A complete JSON request document.
        #[arg(long, group = "doc")]
        json: Option<OsString>,
        /// The complete body (credentials included), sent as is.
        #[arg(long, group = "doc")]
        body: Option<OsString>,
        /// JSON value (json) or XML fragment (xml).
        #[arg(long)]
        params: Option<String>,
        /// Document format for --method.
        #[arg(long, value_enum, default_value_t = FormatArg::Json)]
        format: FormatArg,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// Any request type, for negative tests.
    Raw {
        /// X-Digium-AppServer-RequestType.
        #[arg(value_name = "TYPE")]
        rtype: String,
        /// Body text, or @FILE.
        #[arg(long, default_value = "")]
        body: OsString,
        /// Encrypt the request.
        #[arg(long, value_enum, default_value_t = EncryptArg::Auto)]
        encrypt: EncryptArg,
        /// Session id to send (default: the current one; '' for none).
        #[arg(long)]
        session: Option<String>,
        /// X-Digium-AppServer-Username.
        #[arg(long)]
        username: Option<OsString>,
        /// X-Digium-AppServer-Password.
        #[arg(long)]
        password: Option<OsString>,
        /// X-Digium-AppServer-ConfigPassword.
        #[arg(long)]
        config_password: Option<OsString>,
        /// X-Digium-AppServer-Config-Token.
        #[arg(long)]
        config_token: Option<OsString>,
        /// Transaction id.
        #[arg(long)]
        id: Option<String>,
        /// MAC header for this request.
        #[arg(long = "mac", value_name = "MAC")]
        raw_mac: Option<String>,
        /// Contact URI for this request.
        #[arg(long = "contact", value_name = "URI")]
        raw_contact: Option<String>,
        #[command(flatten)]
        o: ReqOpts,
    },
    /// Print incoming messages (events).
    Listen {
        /// Stop after SECONDS (default: never).
        #[arg(long)]
        seconds: Option<f64>,
        /// Stop after COUNT messages.
        #[arg(long)]
        count: Option<usize>,
        /// Only this X-Event-Name (others are skipped).
        #[arg(long)]
        event: Option<OsString>,
    },
    /// Crypto, framing, and protocol self-test (no server needed).
    Selftest {
        /// Also print the cross-check vectors (JSON).
        #[arg(long)]
        vectors: bool,
    },
    /// Print the cross-check vectors (tests/data/vectors.json), or write them.
    Vectors {
        /// Write them to this file instead.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn b(s: &OsString) -> &[u8] {
    s.as_bytes()
}

fn options(a: &Cli) -> Result<Options> {
    let slot = a
        .slot
        .or_else(|| std::env::var("DPMA_SLOT").ok().and_then(|s| s.parse().ok()));
    let mut o = match slot {
        Some(s) => Options::for_slot(s),
        None => Options::default(),
    };
    if let Some(p) = a.sip_port {
        o.sip_port = p;
    }
    o.server = a.server.clone();
    o.local_host = a.local_host.clone();
    o.local_port = a.local_port;
    o.transport = match a.transport {
        TransportArg::Udp => Transport::Udp,
        TransportArg::Tcp => Transport::Tcp,
    };
    o = o.mac(&a.mac);
    o.user_agent = b(&a.user_agent).into();
    o.digium_ua_header = !a.no_digium_ua_header;
    o.contact = a.contact.clone();
    o.origination_network = a.origination_network.as_ref().map(|v| b(v).into());
    o.form = match a.form {
        FormArg::Legacy => Form::Legacy,
        FormArg::Chain => Form::Chain,
    };
    o.bundle = a.bundle.clone();
    if let Some(p) = &a.pki {
        o.pki = p.clone();
    }
    o.appserver_check = !a.no_appserver_check;
    o.chunk_size = a.chunk_size;
    o.chunk_style = match a.chunk_style {
        StyleArg::Split => ChunkStyle::Split,
        StyleArg::Stream => ChunkStyle::Stream,
    };
    o.chunk_delay = Duration::from_secs_f64(a.chunk_delay.max(0.0) / 1000.0);
    o.timeout = Duration::from_secs_f64(a.timeout.max(0.0));
    o.plain = a.plain;
    o.verbose = i32::from(a.verbose);
    o.auto_handshake = !a.no_auto_handshake;
    o.state = a.state.clone();
    if let (Some(state), 0) = (&a.state, a.local_port) {
        if let Some(p) = Phone::state_local_port(state) {
            o.local_port = p;
        }
    }
    Ok(o)
}

fn apply<'p>(mut r: RequestBuilder<'p>, o: &ReqOpts) -> Result<RequestBuilder<'p>> {
    if o.no_wait {
        r = r.no_wait();
    }
    if let Some(t) = o.cmd_timeout {
        r = r.timeout_secs(t);
    }
    if let Some(n) = o.cmd_chunk_size.filter(|&n| n > 0) {
        r = r.chunk_size(n);
    }
    if o.pem_cuts {
        r = r.pem_cuts();
    }
    for h in &o.header {
        let h = b(h);
        let Some(i) = h.iter().position(|&c| c == b':') else {
            bail!("bad --header {:?} (use 'Name: Value')", BString::from(h));
        };
        r = r.header(
            String::from_utf8_lossy(h[..i].trim_ascii()).as_ref(),
            h[i + 1..].trim_ascii(),
        );
    }
    Ok(r)
}

fn print(text: &[u8]) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Runs a request command; returns the exchange, the request options, and
/// whether success means any reply (`raw`).
fn request(phone: &Phone, cmd: &Cmd) -> Result<(Exchange, bool, bool)> {
    let needs_handshake = match cmd {
        Cmd::Handshake { .. } | Cmd::Echo { .. } => false,
        Cmd::Raw { rtype, session, .. } => needs_session(rtype) && session.is_none(),
        _ => true,
    };
    if needs_handshake {
        phone.ensure_session()?;
    }
    let (ex, o, raw) = match cmd {
        Cmd::Handshake { cmd_bundle, o } => {
            let mut r = phone.handshake();
            if let Some(bn) = cmd_bundle {
                r = r.bundle(bn);
            }
            (apply(r, o)?.send()?, o, false)
        }
        Cmd::Ping { o } => (apply(phone.ping(), o)?.send()?, o, false),
        Cmd::Echo { body, o } => (apply(phone.echo(b(body)), o)?.send()?, o, false),
        Cmd::Config { token, o } => {
            let mut r = phone.config();
            if let Some(t) = token {
                r = r.config_token(b(t));
            }
            (apply(r, o)?.send()?, o, false)
        }
        Cmd::Verify { token, o } => {
            let mut r = phone.verify();
            if let Some(t) = token {
                r = r.config_token(b(t));
            }
            (apply(r, o)?.send()?, o, false)
        }
        Cmd::Token {
            user,
            pin,
            config_pass,
            o,
        } => {
            let mut r = phone.get_token();
            if let Some(v) = user {
                r = r.user(b(v));
            }
            if let Some(v) = pin {
                r = r.pin(b(v));
            }
            if let Some(v) = config_pass {
                r = r.config_password(b(v));
            }
            (apply(r, o)?.send()?, o, false)
        }
        Cmd::Userlist { config_pass, o } => {
            let mut r = phone.userlist();
            if let Some(v) = config_pass {
                r = r.config_password(b(v));
            }
            (apply(r, o)?.send()?, o, false)
        }
        Cmd::File { name, o } => (apply(phone.file(b(name)), o)?.send()?, o, false),
        Cmd::Asterisk {
            auth,
            rtype,
            method,
            xml,
            json,
            body,
            params,
            format,
            o,
        } => {
            let type_name = match rtype {
                RequestTypeArg::AsteriskRequest => "AsteriskRequest",
                RequestTypeArg::HttpRequest => "HTTPRequest",
            };
            if let Some(body) = body {
                (
                    apply(phone.request(type_name).body(b(body)), o)?.send()?,
                    o,
                    false,
                )
            } else {
                let doc: Vec<u8> = if let Some(m) = method {
                    match format {
                        FormatArg::Json => {
                            let p = params
                                .as_deref()
                                .map(serde_json::from_str::<serde_json::Value>)
                                .transpose()?;
                            method_request_json(m, p.as_ref()).into_bytes()
                        }
                        FormatArg::Xml => {
                            method_request_xml(m, params.as_deref().unwrap_or("")).into_bytes()
                        }
                    }
                } else if let Some(d) = xml.as_ref().or(json.as_ref()) {
                    b(d).to_vec()
                } else {
                    bail!("one of --method, --xml, --json, or --body is required");
                };
                let mut r = match rtype {
                    RequestTypeArg::AsteriskRequest => phone.asterisk(doc),
                    RequestTypeArg::HttpRequest => phone.http(doc),
                };
                if let Some(a) = auth {
                    r = r.auth(b(a));
                }
                (apply(r, o)?.send()?, o, false)
            }
        }
        Cmd::Raw {
            rtype,
            body,
            encrypt,
            session,
            username,
            password,
            config_password,
            config_token,
            id,
            raw_mac,
            raw_contact,
            o,
        } => {
            let body: Vec<u8> = match b(body).strip_prefix(b"@") {
                Some(path) => std::fs::read(std::ffi::OsStr::from_bytes(path))?,
                None => b(body).to_vec(),
            };
            let mut r = phone.request(rtype).body(body);
            r = match encrypt {
                EncryptArg::Auto => r,
                EncryptArg::Yes => r.encrypt(true),
                EncryptArg::No => r.encrypt(false),
            };
            if let Some(s) = session {
                r = r.session(s.clone());
            }
            if let Some(v) = username {
                r = r.username(b(v));
            }
            if let Some(v) = password {
                r = r.password(b(v));
            }
            if let Some(v) = config_password {
                r = r.config_password(b(v));
            }
            if let Some(v) = config_token {
                r = r.config_token(b(v));
            }
            if let Some(i) = id {
                r = r.txid(i.clone());
            }
            if let Some(m) = raw_mac {
                r = r.mac(m.clone());
            }
            if let Some(c) = raw_contact {
                r = r.contact(c.clone());
            }
            (apply(r, o)?.send()?, o, true)
        }
        _ => return Err(anyhow!("not a request command")),
    };
    Ok((ex, raw, o.no_wait))
}

fn run_listen(
    phone: &Phone,
    seconds: Option<f64>,
    count: Option<usize>,
    event: Option<&OsString>,
) -> usize {
    let deadline = seconds.map(|s| Instant::now() + Duration::from_secs_f64(s.max(0.0)));
    let mut got = 0;
    let name = event.map(|e| b(e).to_vec());
    while count.is_none_or(|c| got < c) {
        let left = match deadline {
            Some(d) if Instant::now() >= d => break,
            Some(d) => d - Instant::now(),
            None => Duration::from_secs(3600),
        };
        if let Some(r) = phone.next_event_bytes(left, name.as_deref()) {
            got += 1;
            print(&r.describe(phone.opts().verbose));
        }
    }
    got
}

fn main() -> ExitCode {
    let a = Cli::parse();
    match &a.command {
        Cmd::Selftest { vectors } => {
            let mut c = Checker::new();
            let pki = a.pki.clone().unwrap_or_else(sim::default_pki_dir);
            selftest::run(&mut c, &pki);
            if *vectors {
                print!("{}", selftest::vectors_text());
            }
            println!("{} failure(s)", c.failures().len());
            return if c.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Cmd::Vectors { out } => {
            let text = selftest::vectors_text();
            return match out {
                Some(p) => match std::fs::write(p, text) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("dpma-sim: {}: {e}", p.display());
                        ExitCode::from(2)
                    }
                },
                None => {
                    print!("{text}");
                    ExitCode::SUCCESS
                }
            };
        }
        _ => {}
    }
    let opts = match options(&a) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("dpma-sim: {e:#}");
            return ExitCode::from(2);
        }
    };
    let verbose = opts.verbose;
    let mut phone = match Phone::start(opts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dpma-sim: {e:#}");
            return ExitCode::from(2);
        }
    };
    let code = match &a.command {
        Cmd::Listen {
            seconds,
            count,
            event,
        } => {
            let got = run_listen(&phone, *seconds, *count, event.as_ref());
            if count.is_none_or(|c| got >= c) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        cmd => match request(&phone, cmd) {
            Ok((ex, raw, no_wait)) => {
                print(&ex.describe(verbose));
                let ok = if no_wait {
                    ex.sip_ok()
                } else if raw {
                    ex.raw_ok()
                } else {
                    ex.ok()
                };
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(e) => {
                eprintln!("dpma-sim: {e:#}");
                ExitCode::FAILURE
            }
        },
    };
    phone.close();
    code
}
