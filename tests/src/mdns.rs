//! A small mDNS client (the Rust form of
//! `tests/apps-discovery/mdns_probe.py`).
//!
//! [`browse`] sends one-shot (legacy unicast) queries to
//! 224.0.0.251:5353: PTR for the service type, then SRV and TXT for every
//! instance found, then A and AAAA for every SRV target.  [`Listener`]
//! joins the mDNS group and collects every response it sees
//! (announcements and goodbyes).  Queries and the group membership use
//! the interface of a given address (normally 127.0.0.1), so nothing
//! leaves the loopback interface.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};

/// The mDNS group.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The mDNS port.
pub const PORT: u16 = 5353;
/// The service the module announces.
pub const SERVICE: &str = "_digiumproxy._udp.local";

/// Record types.
pub mod rtype {
    /// IPv4 address.
    pub const A: u16 = 1;
    /// Pointer.
    pub const PTR: u16 = 12;
    /// Text strings.
    pub const TXT: u16 = 16;
    /// IPv6 address.
    pub const AAAA: u16 = 28;
    /// Service location.
    pub const SRV: u16 = 33;
    /// Any type (queries).
    pub const ANY: u16 = 255;
}

/// The name of a record type (`"A"`, `"PTR"`, ...), or its number.
pub fn type_name(t: u16) -> String {
    match t {
        rtype::A => "A".into(),
        rtype::PTR => "PTR".into(),
        rtype::TXT => "TXT".into(),
        rtype::AAAA => "AAAA".into(),
        rtype::SRV => "SRV".into(),
        rtype::ANY => "ANY".into(),
        n => n.to_string(),
    }
}

/// The data of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    /// PTR: the target name.
    Ptr(String),
    /// SRV.
    Srv {
        /// Priority.
        priority: u16,
        /// Weight.
        weight: u16,
        /// Port.
        port: u16,
        /// Target host name.
        target: String,
    },
    /// TXT: the strings (lossy UTF-8).
    Txt(Vec<String>),
    /// A.
    A(Ipv4Addr),
    /// AAAA.
    Aaaa(Ipv6Addr),
    /// Anything else: the raw data.
    Other(Vec<u8>),
}

/// One resource record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// `answer`, `authority`, or `additional`.
    pub section: &'static str,
    /// The owner name, dotted with a final dot (`\.` is a dot inside a
    /// label).
    pub name: String,
    /// The record type.
    pub rtype: u16,
    /// The cache-flush bit of the class.
    pub cache_flush: bool,
    /// The TTL (0: a goodbye).
    pub ttl: u32,
    /// The data.
    pub data: RecordData,
}

/// A parsed DNS message.
#[derive(Clone, Debug)]
pub struct DnsMessage {
    /// The id.
    pub id: u16,
    /// The flags (0x8000: response).
    pub flags: u16,
    /// The questions: name and type.
    pub questions: Vec<(String, u16)>,
    /// Every record of every section.
    pub records: Vec<Record>,
}

/// The labels of a dotted name (`\.` is a dot inside a label).
pub fn split_name(name: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut cur = String::new();
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek().is_some() => cur.push(chars.next().unwrap_or_default()),
            '.' => labels.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        labels.push(cur);
    }
    labels
}

/// A name in wire form.
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in split_name(name) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A one-question query (class IN).
pub fn build_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [id, 0, 1, 0, 0, 0] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend(encode_name(name));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn u16_at(d: &[u8], off: usize) -> Result<u16> {
    match d.get(off..off + 2) {
        Some(b) => Ok(u16::from_be_bytes([b[0], b[1]])),
        None => bail!("truncated DNS message"),
    }
}

/// A name at `off` (following compression pointers) and the offset after
/// it.
pub fn read_name(data: &[u8], mut off: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let Some(&n) = data.get(off) else {
            bail!("truncated DNS name")
        };
        if n & 0xc0 == 0xc0 {
            if end.is_none() {
                end = Some(off + 2);
            }
            off = (usize::from(n & 0x3f) << 8) | usize::from(*data.get(off + 1).unwrap_or(&0));
            continue;
        }
        if n == 0 {
            off += 1;
            break;
        }
        let label = data
            .get(off + 1..off + 1 + usize::from(n))
            .unwrap_or_default();
        labels.push(String::from_utf8_lossy(label).replace('.', "\\."));
        off += 1 + usize::from(n);
    }
    Ok((labels.join(".") + ".", end.unwrap_or(off)))
}

/// Parses a DNS message.
pub fn parse(data: &[u8]) -> Result<DnsMessage> {
    let h: Vec<u16> = (0..6).map(|i| u16_at(data, i * 2)).collect::<Result<_>>()?;
    let mut off = 12;
    let mut questions = Vec::new();
    for _ in 0..h[2] {
        let (name, o) = read_name(data, off)?;
        questions.push((name, u16_at(data, o)?));
        off = o + 4;
    }
    let mut records = Vec::new();
    for (section, count) in [("answer", h[3]), ("authority", h[4]), ("additional", h[5])] {
        for _ in 0..count {
            let (name, o) = read_name(data, off)?;
            let rt = u16_at(data, o)?;
            let class = u16_at(data, o + 2)?;
            let ttl = (u32::from(u16_at(data, o + 4)?) << 16) | u32::from(u16_at(data, o + 6)?);
            let len = usize::from(u16_at(data, o + 8)?);
            let start = o + 10;
            let rd = data.get(start..start + len).unwrap_or_default();
            let rdata = match rt {
                rtype::PTR => RecordData::Ptr(read_name(data, start)?.0),
                rtype::SRV => RecordData::Srv {
                    priority: u16_at(rd, 0)?,
                    weight: u16_at(rd, 2)?,
                    port: u16_at(rd, 4)?,
                    target: read_name(data, start + 6)?.0,
                },
                rtype::TXT => {
                    let mut strings = Vec::new();
                    let mut i = 0;
                    while i < rd.len() {
                        let n = usize::from(rd[i]);
                        strings.push(
                            String::from_utf8_lossy(rd.get(i + 1..i + 1 + n).unwrap_or_default())
                                .into_owned(),
                        );
                        i += 1 + n;
                    }
                    RecordData::Txt(strings)
                }
                rtype::A if rd.len() == 4 => {
                    RecordData::A(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]))
                }
                rtype::AAAA if rd.len() == 16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(rd);
                    RecordData::Aaaa(Ipv6Addr::from(b))
                }
                _ => RecordData::Other(rd.to_vec()),
            };
            records.push(Record {
                section,
                name,
                rtype: rt,
                cache_flush: class & 0x8000 != 0,
                ttl,
                data: rdata,
            });
            off = start + len;
        }
    }
    Ok(DnsMessage {
        id: h[0],
        flags: h[1],
        questions,
        records,
    })
}

/// Sends a legacy unicast query from the interface of `iface` and
/// returns the records of every reply that arrives within `wait`.
pub fn query(name: &str, qtype: u16, iface: Ipv4Addr, wait: Duration) -> Result<Vec<Record>> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_multicast_if_v4(&iface)?;
    s.set_multicast_ttl_v4(255)?;
    s.bind(&SocketAddr::V4(SocketAddrV4::new(iface, 0)).into())?;
    let s: UdpSocket = s.into();
    let id: u16 = rand::thread_rng().gen();
    s.send_to(
        &build_query(name, qtype, id),
        SocketAddrV4::new(GROUP, PORT),
    )?;
    let deadline = Instant::now() + wait;
    let mut records = Vec::new();
    let mut buf = vec![0u8; 9000];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        s.set_read_timeout(Some(left))?;
        let Ok((n, _)) = s.recv_from(&mut buf) else {
            break;
        };
        if let Ok(m) = parse(&buf[..n]) {
            if m.flags & 0x8000 != 0 && m.id == id {
                records.extend(m.records);
            }
        }
    }
    Ok(records)
}

/// An instance found by [`browse`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceInstance {
    /// The SRV port.
    pub port: Option<u16>,
    /// The SRV target host.
    pub target: Option<String>,
    /// The TXT strings.
    pub txt: Option<Vec<String>>,
    /// The target's A and AAAA addresses.
    pub addresses: Vec<String>,
}

/// The instance label of a full service instance name (dots unescaped).
pub fn instance_label(fullname: &str, service_type: &str) -> String {
    let suffix = format!(".{}.", service_type.trim_end_matches('.'));
    match fullname.strip_suffix(&suffix) {
        Some(l) => l.replace("\\.", "."),
        None => fullname.to_string(),
    }
}

/// `f(a)` and `f(b)`, run at the same time (two queries wait for their
/// replies together).
fn both<T: Send>(f: impl Fn(u16) -> T + Sync, a: u16, b: u16) -> [T; 2] {
    std::thread::scope(|s| {
        let first = s.spawn(|| f(a));
        let second = f(b);
        [first.join().expect("query thread"), second]
    })
}

/// Every live (TTL > 0) instance of `service_type`, by instance label
/// (its PTR query, then its SRV and TXT queries together, then the
/// target's A and AAAA queries together, each waiting `wait`).
pub fn browse(
    service_type: &str,
    iface: Ipv4Addr,
    wait: Duration,
) -> Result<BTreeMap<String, ServiceInstance>> {
    let mut found = BTreeMap::new();
    let st = service_type.trim_end_matches('.');
    for p in query(service_type, rtype::PTR, iface, wait)? {
        let RecordData::Ptr(full) = &p.data else {
            continue;
        };
        if p.ttl == 0 || p.name.trim_end_matches('.') != st {
            continue;
        }
        let mut inst = ServiceInstance::default();
        let mut rs = Vec::new();
        for r in both(|t| query(full, t, iface, wait), rtype::SRV, rtype::TXT) {
            rs.extend(r?);
        }
        for r in rs {
            if &r.name != full {
                continue;
            }
            match r.data {
                RecordData::Srv { port, target, .. } => {
                    inst.port = Some(port);
                    inst.target = Some(target);
                }
                RecordData::Txt(t) => inst.txt = Some(t),
                _ => {}
            }
        }
        if let Some(target) = inst.target.clone() {
            for (t, rs) in [rtype::A, rtype::AAAA].into_iter().zip(both(
                |t| query(&target, t, iface, wait),
                rtype::A,
                rtype::AAAA,
            )) {
                for r in rs? {
                    if r.rtype != t || !r.name.eq_ignore_ascii_case(&target) || r.ttl == 0 {
                        continue;
                    }
                    let a = match r.data {
                        RecordData::A(a) => a.to_string(),
                        RecordData::Aaaa(a) => a.to_string(),
                        _ => continue,
                    };
                    if !inst.addresses.contains(&a) {
                        inst.addresses.push(a);
                    }
                }
            }
        }
        found.insert(instance_label(full, service_type), inst);
    }
    Ok(found)
}

/// A record seen by a [`Listener`], with when and from where.
#[derive(Clone, Debug)]
pub struct Heard {
    /// The record.
    pub record: Record,
    /// When it arrived.
    pub time: Instant,
    /// The sender's address.
    pub source: SocketAddr,
}

/// Collects the records of every mDNS response multicast on an
/// interface (port 5353, shared with the responders).
pub struct Listener {
    records: Arc<Mutex<Vec<Heard>>>,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Listener {
    /// Joins the group on the interface of `iface` and starts collecting.
    pub fn start(iface: Ipv4Addr) -> Result<Listener> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).into())?;
        s.join_multicast_v4(&GROUP, &iface)?;
        s.set_read_timeout(Some(Duration::from_millis(200)))?;
        let sock: UdpSocket = s.into();
        let records = Arc::new(Mutex::new(Vec::new()));
        let running = Arc::new(AtomicBool::new(true));
        let (r, run) = (records.clone(), running.clone());
        let thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 9000];
            while run.load(Ordering::SeqCst) {
                let Ok((n, addr)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let Ok(m) = parse(&buf[..n]) else { continue };
                if m.flags & 0x8000 == 0 {
                    continue;
                }
                let now = Instant::now();
                let mut r = r.lock().unwrap();
                r.extend(m.records.into_iter().map(|record| Heard {
                    record,
                    time: now,
                    source: addr,
                }));
            }
        });
        Ok(Listener {
            records,
            running,
            thread: Some(thread),
        })
    }

    /// A mark: the number of records so far.
    pub fn mark(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// The records since `mark`.
    pub fn since(&self, mark: usize) -> Vec<Heard> {
        self.records
            .lock()
            .unwrap()
            .get(mark..)
            .map(<[Heard]>::to_vec)
            .unwrap_or_default()
    }

    /// Stops collecting.
    pub fn close(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_response_round_trip() {
        let q = build_query("My\\.Server._digiumproxy._udp.local", rtype::SRV, 0x1234);
        let m = parse(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert_eq!(
            m.questions,
            vec![(
                "My\\.Server._digiumproxy._udp.local.".to_string(),
                rtype::SRV
            )]
        );

        // A response: PTR (compressed target), SRV, TXT, and A.
        let mut r = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        let svc = encode_name("_digiumproxy._udp.local");
        let svc_off = r.len();
        r.extend(&svc);
        r.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x11, 0x94]);
        let inst = {
            let mut v = vec![4];
            v.extend_from_slice(b"Srv.");
            v.extend_from_slice(&[0xc0, svc_off as u8]);
            v
        };
        r.extend_from_slice(&(inst.len() as u16).to_be_bytes());
        let inst_off = r.len();
        r.extend(&inst);
        r.extend_from_slice(&[0xc0, inst_off as u8, 0, 33, 0x80, 1, 0, 0, 0, 120]);
        let host = encode_name("h-dpma.local");
        r.extend_from_slice(&((6 + host.len()) as u16).to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0, 0x13, 0xc4]);
        let host_off = r.len();
        r.extend(&host);
        r.extend_from_slice(&[
            0xc0,
            inst_off as u8,
            0,
            16,
            0x80,
            1,
            0,
            0,
            0,
            120,
            0,
            4,
            3,
            b'a',
            b'=',
            b'b',
        ]);
        r.extend_from_slice(&[
            0xc0,
            host_off as u8,
            0,
            1,
            0x80,
            1,
            0,
            0,
            0,
            0,
            0,
            4,
            127,
            0,
            0,
            1,
        ]);
        let m = parse(&r).unwrap();
        assert_eq!(m.records.len(), 4);
        assert_eq!(
            m.records[0].data,
            RecordData::Ptr("Srv\\.._digiumproxy._udp.local.".into())
        );
        assert_eq!(
            instance_label("Srv\\.._digiumproxy._udp.local.", SERVICE),
            "Srv."
        );
        assert_eq!(
            m.records[1].data,
            RecordData::Srv {
                priority: 0,
                weight: 0,
                port: 5060,
                target: "h-dpma.local.".into()
            }
        );
        assert!(m.records[1].cache_flush);
        assert_eq!(m.records[2].data, RecordData::Txt(vec!["a=b".into()]));
        assert_eq!(m.records[3].data, RecordData::A(Ipv4Addr::LOCALHOST));
        assert_eq!(m.records[3].ttl, 0);
    }
}
