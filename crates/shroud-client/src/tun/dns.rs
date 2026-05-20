use anyhow::{Context, Result, bail};
use shroud_core::config::TunInboundConfig;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, warn};

const DNS_PORT: u16 = 53;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const FAKE_POOL_START: u32 = u32::from_be_bytes([198, 18, 0, 1]);
const FAKE_POOL_END: u32 = u32::from_be_bytes([198, 19, 255, 254]);
const FAKE_TTL_SECONDS: u32 = 30;

#[derive(Clone, Debug)]
pub struct FakeDns {
    inner: Arc<Mutex<FakeDnsState>>,
}

impl FakeDns {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeDnsState::new())),
        }
    }

    pub async fn resolve_or_allocate(&self, domain: &str) -> Result<Ipv4Addr> {
        let domain = normalize_domain(domain)?;
        let mut inner = self.inner.lock().await;
        inner.resolve_or_allocate(domain)
    }

    pub async fn lookup_domain(&self, ip: Ipv4Addr) -> Option<String> {
        let inner = self.inner.lock().await;
        inner.ip_to_domain.get(&ip).cloned()
    }
}

impl Default for FakeDns {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct FakeDnsState {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, String>,
    next: u32,
}

impl FakeDnsState {
    fn new() -> Self {
        Self {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            next: FAKE_POOL_START,
        }
    }

    fn resolve_or_allocate(&mut self, domain: String) -> Result<Ipv4Addr> {
        if let Some(ip) = self.domain_to_ip.get(&domain) {
            return Ok(*ip);
        }

        let ip = self.allocate_ip()?;
        self.domain_to_ip.insert(domain.clone(), ip);
        self.ip_to_domain.insert(ip, domain);
        Ok(ip)
    }

    fn allocate_ip(&mut self) -> Result<Ipv4Addr> {
        if self.next > FAKE_POOL_END {
            bail!("fake DNS IPv4 pool is exhausted");
        }

        let ip = Ipv4Addr::from(self.next);
        self.next += 1;
        Ok(ip)
    }
}

pub fn listen_addr(tun: &TunInboundConfig) -> SocketAddr {
    SocketAddr::new(tun.dns.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)), DNS_PORT)
}

pub async fn serve(bind: SocketAddr, fake_dns: FakeDns) -> Result<()> {
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("failed to bind fake DNS listener at {bind}"))?;
    let mut buf = vec![0u8; 4096];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let query = &buf[..len];

        let response = match handle_query(query, &fake_dns).await {
            Ok(response) => response,
            Err(err) => {
                debug!(%peer, error = %err, "failed to handle fake DNS query");
                continue;
            }
        };

        if let Err(err) = socket.send_to(&response, peer).await {
            warn!(%peer, error = %err, "failed to send fake DNS response");
        }
    }
}

async fn handle_query(query: &[u8], fake_dns: &FakeDns) -> Result<Vec<u8>> {
    let parsed = parse_query(query)?;
    if parsed.qclass != CLASS_IN {
        return Ok(build_empty_response(query, &parsed, ResponseCode::NoError));
    }

    if parsed.qtype != TYPE_A {
        return Ok(build_empty_response(query, &parsed, ResponseCode::NoError));
    }

    let fake_ip = fake_dns.resolve_or_allocate(&parsed.domain).await?;
    Ok(build_a_response(query, &parsed, fake_ip))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuery {
    id: u16,
    flags: u16,
    question_end: usize,
    domain: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Clone, Copy)]
enum ResponseCode {
    NoError,
}

fn parse_query(packet: &[u8]) -> Result<DnsQuery> {
    if packet.len() < 12 {
        bail!("DNS packet is too short");
    }

    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    if (flags & 0x8000) != 0 {
        bail!("DNS packet is not a query");
    }

    let question_count = read_u16(packet, 4)?;
    if question_count != 1 {
        bail!("only single-question DNS queries are supported");
    }

    let (domain, cursor) = parse_qname(packet, 12)?;
    let qtype = read_u16(packet, cursor)?;
    let qclass = read_u16(packet, cursor + 2)?;
    let question_end = cursor + 4;

    if packet.len() < question_end {
        bail!("DNS question is truncated");
    }

    Ok(DnsQuery {
        id,
        flags,
        question_end,
        domain,
        qtype,
        qclass,
    })
}

fn parse_qname(packet: &[u8], mut cursor: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();

    loop {
        let Some(len) = packet.get(cursor).copied() else {
            bail!("DNS qname is truncated");
        };
        cursor += 1;

        if len == 0 {
            break;
        }
        if (len & 0xC0) != 0 {
            bail!("compressed DNS qname is not supported in questions");
        }

        let label_len = len as usize;
        let end = cursor + label_len;
        if end > packet.len() {
            bail!("DNS qname label is truncated");
        }

        let label = std::str::from_utf8(&packet[cursor..end])
            .context("DNS qname label is not valid UTF-8")?;
        labels.push(label.to_ascii_lowercase());
        cursor = end;
    }

    if labels.is_empty() {
        bail!("DNS qname cannot be root");
    }

    Ok((labels.join("."), cursor))
}

fn build_a_response(query: &[u8], parsed: &DnsQuery, fake_ip: Ipv4Addr) -> Vec<u8> {
    let mut response = build_response_header(parsed, 1, ResponseCode::NoError);
    response.extend_from_slice(&query[12..parsed.question_end]);
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&TYPE_A.to_be_bytes());
    response.extend_from_slice(&CLASS_IN.to_be_bytes());
    response.extend_from_slice(&FAKE_TTL_SECONDS.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&fake_ip.octets());
    response
}

fn build_empty_response(query: &[u8], parsed: &DnsQuery, code: ResponseCode) -> Vec<u8> {
    let mut response = build_response_header(parsed, 0, code);
    response.extend_from_slice(&query[12..parsed.question_end]);
    response
}

fn build_response_header(parsed: &DnsQuery, answer_count: u16, code: ResponseCode) -> Vec<u8> {
    let mut response = Vec::with_capacity(64);
    response.extend_from_slice(&parsed.id.to_be_bytes());
    response.extend_from_slice(&response_flags(parsed.flags, code).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

fn response_flags(query_flags: u16, code: ResponseCode) -> u16 {
    let opcode = query_flags & 0x7800;
    let recursion_desired = query_flags & 0x0100;
    let rcode = match code {
        ResponseCode::NoError => 0,
    };

    0x8000 | opcode | recursion_desired | 0x0080 | rcode
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16> {
    if packet.len() < offset + 2 {
        bail!("DNS packet is truncated");
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn normalize_domain(domain: &str) -> Result<String> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        bail!("domain cannot be empty");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x1234u16.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in domain.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    #[tokio::test]
    async fn fake_dns_allocates_stable_ip_and_reverse_mapping() {
        let dns = FakeDns::new();

        let first = dns.resolve_or_allocate("Example.COM.").await.expect("ip");
        let second = dns.resolve_or_allocate("example.com").await.expect("ip");

        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(first, second);
        assert_eq!(
            dns.lookup_domain(first).await.expect("domain"),
            "example.com"
        );
    }

    #[test]
    fn parses_single_question_a_query() {
        let packet = query("Example.COM", TYPE_A);
        let parsed = parse_query(&packet).expect("parse");

        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        assert_eq!(parsed.qclass, CLASS_IN);
        assert_eq!(parsed.question_end, packet.len());
    }

    #[tokio::test]
    async fn builds_a_response_with_fake_ip_answer() {
        let dns = FakeDns::new();
        let packet = query("example.com", TYPE_A);
        let response = handle_query(&packet, &dns).await.expect("response");

        assert_eq!(&response[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert!(response.ends_with(&[198, 18, 0, 1]));
    }

    #[tokio::test]
    async fn unsupported_qtype_returns_no_answers() {
        let dns = FakeDns::new();
        let packet = query("example.com", 28);
        let response = handle_query(&packet, &dns).await.expect("response");

        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert!(
            dns.lookup_domain(Ipv4Addr::new(198, 18, 0, 1))
                .await
                .is_none()
        );
    }

    #[test]
    fn default_listener_uses_configured_dns_ip_or_localhost() {
        let mut tun = TunInboundConfig::default();
        assert_eq!(
            listen_addr(&tun).to_string(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_PORT).to_string()
        );

        tun.dns = Some(IpAddr::V4(Ipv4Addr::new(10, 10, 0, 53)));
        assert_eq!(listen_addr(&tun).to_string(), "10.10.0.53:53");
    }
}
