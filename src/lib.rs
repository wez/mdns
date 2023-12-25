pub mod dns_parser;
pub mod mac_addr;
pub mod net_utils;

pub use dns_parser::QueryType;
use dns_parser::{Builder, Packet, QueryClass, RData, ResourceRecord};
use smol::channel::{bounded, Receiver};
use smol::net::UdpSocket;
use smol::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use thiserror::*;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;

/// Errors that may occur during resolution/discovery
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ChanRecv(#[from] smol::channel::RecvError),
    #[error(transparent)]
    ChanSend(#[from] smol::channel::SendError<Response>),
    #[error("failed to build DNS packet")]
    DnsPacketBuildError,
    #[error("Timed out")]
    Timeout,
    #[error("The QueryParameters were invalid")]
    InvalidQueryParams,
    #[error("Unable to determine local interface")]
    LocalInterfaceUnknown,
}

pub type Result<T> = std::result::Result<T, Error>;

fn sockaddr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    let addr = std::net::SocketAddrV4::new(ip, port);
    addr.into()
}

async fn create_socket() -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_reuse_port(true);

    let addr = sockaddr(Ipv4Addr::UNSPECIFIED, MULTICAST_PORT);
    socket.bind(&addr.into())?;

    let socket = UdpSocket::from(smol::Async::new(socket.into())?);
    socket.set_multicast_loop_v4(false)?;
    socket.join_multicast_v4(MULTICAST_ADDR, Ipv4Addr::UNSPECIFIED)?;
    Ok(socket)
}

/// An mDNS query response
#[derive(Debug)]
pub struct Response {
    pub answers: Vec<Record>,
    pub nameservers: Vec<Record>,
    pub additional: Vec<Record>,
}

/// The resolved information about a host (or rather, a service)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// A friendly name for this instance.
    pub name: String,
    /// The mDNS `A` (or `AAAA`) resolvable hostname for this host.
    /// May be different from `name`.
    pub host_name: Option<String>,
    /// The set of addresses
    pub ip_address: Vec<IpAddr>,
    /// The set of addresses with port numbers.
    /// May be empty if no SRV record was resolved
    pub socket_address: Vec<SocketAddr>,
    /// The instant at which this information is no longer valid
    pub expires: Instant,
}

impl Host {
    /// Returns true if the information is still valid (within the
    /// TTL specified by the mDNS response).
    pub fn valid(&self) -> bool {
        Instant::now() < self.expires
    }
}

impl Response {
    fn new(packet: &Packet) -> Self {
        Self {
            answers: packet.answers.iter().map(Record::new).collect(),
            nameservers: packet.nameservers.iter().map(Record::new).collect(),
            additional: packet.additional.iter().map(Record::new).collect(),
        }
    }

    fn all_records(&self) -> impl Iterator<Item = &Record> {
        self.answers
            .iter()
            .chain(self.additional.iter())
            .chain(self.nameservers.iter())
    }

    /// Compose the response as an array of Host structs
    pub fn hosts(&self) -> Vec<Host> {
        let mut result = vec![];

        for ans in &self.answers {
            match &ans.kind {
                RecordKind::A(addr) => {
                    result.push(Host {
                        name: ans.name.clone(),
                        host_name: Some(ans.name.clone()),
                        ip_address: vec![(*addr).into()],
                        socket_address: vec![],
                        expires: Instant::now() + Duration::from_secs(ans.ttl.into()),
                    });
                }
                RecordKind::AAAA(addr) => {
                    result.push(Host {
                        name: ans.name.clone(),
                        host_name: Some(ans.name.clone()),
                        ip_address: vec![(*addr).into()],
                        socket_address: vec![],
                        expires: Instant::now() + Duration::from_secs(ans.ttl.into()),
                    });
                }
                RecordKind::PTR(name) => {
                    let name = name.clone();
                    let mut found_port = None;
                    let mut host_name = None;
                    let mut ip_address = vec![];
                    let mut socket_address = vec![];

                    for r in self.all_records() {
                        if r.name != name {
                            continue;
                        }

                        match &r.kind {
                            RecordKind::SRV { port, target, .. } => {
                                found_port.replace(*port);
                                host_name.replace(target.clone());
                            }
                            _ => {}
                        }
                    }

                    if let Some(host_name) = host_name.as_ref() {
                        for r in self.all_records() {
                            if &r.name != host_name {
                                continue;
                            }

                            match &r.kind {
                                RecordKind::A(addr) => {
                                    ip_address.push(addr.clone().into());
                                }
                                RecordKind::AAAA(addr) => {
                                    ip_address.push(addr.clone().into());
                                }
                                _ => {}
                            }
                        }
                    }

                    if let Some(port) = found_port {
                        for addr in &ip_address {
                            socket_address.push(SocketAddr::new(*addr, port));
                        }
                    }

                    result.push(Host {
                        name,
                        host_name,
                        ip_address,
                        socket_address,
                        expires: Instant::now() + Duration::from_secs(ans.ttl.into()),
                    });
                }
                _ => {}
            }
        }
        result
    }
}

/// mDNS Records compose into a [Response](struct.Record.html)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub class: dns_parser::Class,
    pub ttl: u32,
    pub kind: RecordKind,
}

impl Record {
    fn new(rr: &ResourceRecord) -> Self {
        Self {
            name: rr.name.to_string(),
            class: rr.cls,
            ttl: rr.ttl,
            kind: RecordKind::new(&rr.data),
        }
    }
}

/// mDNS record data of various kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordKind {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    PTR(String),
    NS(String),
    MX {
        preference: u16,
        exchange: String,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    SOA {
        primary_ns: String,
        mailbox: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum_ttl: u32,
    },
    TXT(Vec<String>),
    Unimplemented {
        kind: dns_parser::Type,
        data: Vec<u8>,
    },
}

impl RecordKind {
    fn new(data: &RData) -> Self {
        match data {
            RData::A(dns_parser::rdata::a::Record(addr)) => Self::A(*addr),
            RData::AAAA(dns_parser::rdata::aaaa::Record(addr)) => Self::AAAA(*addr),
            RData::CNAME(name) => Self::CNAME(name.to_string()),
            RData::NS(name) => Self::NS(name.to_string()),
            RData::PTR(name) => Self::PTR(name.to_string()),
            RData::MX(dns_parser::rdata::mx::Record {
                preference,
                exchange,
            }) => Self::MX {
                preference: *preference,
                exchange: exchange.to_string(),
            },
            RData::SRV(dns_parser::rdata::srv::Record {
                priority,
                weight,
                port,
                target,
            }) => Self::SRV {
                priority: *priority,
                weight: *weight,
                port: *port,
                target: target.to_string(),
            },
            RData::TXT(txt) => Self::TXT(
                txt.iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect(),
            ),
            RData::SOA(dns_parser::rdata::soa::Record {
                primary_ns,
                mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum_ttl,
            }) => Self::SOA {
                primary_ns: primary_ns.to_string(),
                mailbox: mailbox.to_string(),
                serial: *serial,
                refresh: *refresh,
                retry: *retry,
                expire: *expire,
                minimum_ttl: *minimum_ttl,
            },
            RData::Unknown(kind, data) => Self::Unimplemented {
                kind: *kind,
                data: data.to_vec(),
            },
        }
    }
}

/// Resolve a single host using an mDNS request.
/// Returns a `Response` if found within the specified timeout,
/// otherwise yields an Error.
pub async fn resolve_one<S: AsRef<str>>(
    service_name: S,
    params: QueryParameters,
) -> Result<Response> {
    let responses = resolve(service_name, params).await?;
    let response = responses.recv().await?;
    Ok(response)
}

/// Controls how to perform the query.
/// You will typically use one of the associated constants
/// [DISCOVERY](#associatedconstant.DISCOVERY),
/// [SERVICE_LOOKUP](#associatedconstant.SERVICE_LOOKUP),
/// [HOST_LOOKUP](#associatedconstant.HOST_LOOKUP)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryParameters {
    pub query_type: QueryType,
    /// If specified, the query will be re-issued after this duration
    pub base_repeat_interval: Option<Duration>,
    /// The maximum interval between retries
    pub max_repeat_interval: Option<Duration>,
    /// If true, repeat interval will be doubled on each iteration
    /// until it reaches the max_repeat_interval.
    /// If false, it will increment by base_repeat_interval on each
    /// iteration until it reaches the max_repeat_interval.
    pub exponential_backoff: bool,
    /// If set, specifies the upper bound on total time spent
    /// processing the request.
    /// Otherwise, the request will keep going forever, subject to
    /// the repeat interval.
    pub timeout_after: Option<Duration>,
}

impl QueryParameters {
    /// Parameters suitable for performing long-running discovery.
    /// Repeatedly performs a PTR lookup with exponential backoff
    /// ranging from 2 seconds up to 5 minutes.
    pub const DISCOVERY: QueryParameters = QueryParameters {
        query_type: QueryType::PTR,
        base_repeat_interval: Some(Duration::from_secs(2)),
        exponential_backoff: true,
        max_repeat_interval: Some(Duration::from_secs(300)),
        timeout_after: None,
    };

    /// Parameters suitable for performing short-lived discovery.
    /// Repeatedly performs a PTR lookup with exponential backoff
    /// ranging from 2 seconds up to 5 minutes.
    pub const SERVICE_LOOKUP: QueryParameters = QueryParameters {
        query_type: QueryType::PTR,
        base_repeat_interval: Some(Duration::from_secs(2)),
        exponential_backoff: true,
        max_repeat_interval: None,
        timeout_after: Some(Duration::from_secs(60)),
    };

    /// Parameters suitable for resolving a single host.
    /// Performs an A lookup with exponential backoff ranging from
    /// 1 second.  The overall lookup will timeout after 1 minutes.
    pub const HOST_LOOKUP: QueryParameters = QueryParameters {
        query_type: QueryType::A,
        base_repeat_interval: Some(Duration::from_secs(1)),
        exponential_backoff: true,
        max_repeat_interval: None,
        timeout_after: Some(Duration::from_secs(60)),
    };

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_after.replace(timeout);
        self
    }
}

fn make_query(service_name: &str, query_type: QueryType) -> Result<Vec<u8>> {
    let mut builder = Builder::new_query(rand::random(), false);
    let prefer_unicast = false;
    builder.add_question(&service_name, prefer_unicast, query_type, QueryClass::IN);
    Ok(builder.build().map_err(|_| Error::DnsPacketBuildError)?)
}

/// The source UDP port in all Multicast DNS responses MUST
/// be 5353 (the well-known port assigned to mDNS).
/// Multicast DNS implementations MUST silently ignore any
/// Multicast DNS responses they receive where the source
/// UDP port is not 5353.
///
/// Also applies the Source Address Check from section 11 of
/// <https://tools.ietf.org/html/rfc6762>
fn valid_source_address(addr: SocketAddr) -> bool {
    if addr.port() != MULTICAST_PORT {
        false
    } else {
        /// Computes the masked address bits.
        fn masked(addr: &[u8], mask: &[u8]) -> Vec<u8> {
            assert_eq!(addr.len(), mask.len());
            addr.iter().zip(mask.iter()).map(|(a, m)| a & m).collect()
        }

        let ifaces = match crate::net_utils::get_if_addrs() {
            Ok(i) => i,
            Err(err) => {
                log::error!("error while listing local interfaces: {}", err);
                return false;
            }
        };

        for iface in ifaces {
            let matches_iface = match (&iface.addr, addr.ip()) {
                (crate::net_utils::IfAddr::V4(a), IpAddr::V4(source)) => {
                    masked(&a.ip.octets(), &a.netmask.octets())
                        == masked(&source.octets(), &a.netmask.octets())
                }

                (crate::net_utils::IfAddr::V6(a), IpAddr::V6(source)) => {
                    masked(&a.ip.octets(), &a.netmask.octets())
                        == masked(&source.octets(), &a.netmask.octets())
                }
                _ => false,
            };

            if matches_iface {
                return true;
            }
        }

        false
    }
}

/// Resolve records matching the requested service name.
/// Returns a Receiver that will yield successive responses.
/// Once `timeout` passes, the Sender side of the receiver
/// will disconnect and the channel will yield a RecvError.
pub async fn resolve<S: AsRef<str>>(
    service_name: S,
    params: QueryParameters,
) -> Result<Receiver<Response>> {
    if params.base_repeat_interval.is_none() && params.timeout_after.is_none() {
        return Err(Error::InvalidQueryParams);
    }

    let service_name = service_name.as_ref().to_string();
    let deadline = params.timeout_after.map(|d| Instant::now() + d);

    let data = make_query(&service_name, params.query_type)?;

    let socket = create_socket().await?;
    let addr = sockaddr(MULTICAST_ADDR, MULTICAST_PORT);

    socket.send_to(&data, addr).await?;

    let (tx, rx) = bounded(8);

    smol::spawn(async move {
        let mut retry_interval = params.base_repeat_interval;
        let mut last_send = Instant::now();

        loop {
            let now = Instant::now();

            if let Some(deadline) = deadline {
                if now >= deadline {
                    log::trace!("resolve loop completing because {now:?} >= {deadline:?}");
                    break;
                }
            }

            let recv_deadline = match retry_interval {
                Some(retry) => match deadline {
                    Some(overall) => (last_send + retry).min(overall),
                    None => last_send + retry,
                },
                None => match deadline {
                    Some(overall) => overall,
                    None => {
                        // Shouldn't be possible and we should
                        // have caught this in the params validation
                        // at entry to the function.
                        log::error!("resolve loop aborting because params are invalid");
                        return Err(Error::InvalidQueryParams);
                    }
                },
            };

            let mut buf = [0u8; 4096];

            let recv = async {
                let (len, addr) = socket.recv_from(&mut buf).await?;
                Result::Ok(Some((len, addr)))
            };

            let timer = async {
                let timer = smol::Timer::at(recv_deadline);
                timer.await;
                Result::Ok(None)
            };

            if let Some((len, addr)) = recv.or(timer).await? {
                match Packet::parse(&buf[..len]) {
                    Ok(dns) => {
                        let response = Response::new(&dns);
                        if !valid_source_address(addr) {
                            log::warn!(
                                "ignoring response {response:?} from {addr:?} which is not local",
                            );
                        } else {
                            let matched = response
                                .answers
                                .iter()
                                .any(|answer| answer.name == service_name);
                            if matched {
                                tx.send(response).await?;
                            }
                        }
                    }
                    Err(e) => {
                        log::trace!("failed to parse packet: {e:?} received from {addr:?}");
                    }
                }
            } else {
                log::trace!("resolve loop read timeout; send another query");
                // retry_interval exceeded, so send another query
                let data = make_query(&service_name, params.query_type)?;
                socket.send_to(&data, addr).await?;
                last_send = Instant::now();

                // And compute next interval
                match retry_interval.take() {
                    None => {
                        // No retries; we're done!
                        break;
                    }
                    Some(retry) => {
                        let base = params.base_repeat_interval.unwrap();

                        let retry = if params.exponential_backoff {
                            retry + retry
                        } else {
                            retry + base
                        };

                        let retry = params
                            .max_repeat_interval
                            .map(|max| retry.min(max))
                            .unwrap_or(retry);

                        retry_interval.replace(retry);
                    }
                }
                log::trace!("updated retry_interval is now {retry_interval:?}");
            }
        }

        log::trace!("resolve loop completing OK");
        Result::Ok(())
    })
    .detach();

    Ok(rx)
}
