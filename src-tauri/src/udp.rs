use crate::router::{self, Lan};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

pub const LIFETIME: u32 = 3600;
pub const NAT_RISK: &str = "NAT-PMP has no read-only mapping inspection, description or ownership nonce. Even the initial request may replace a pre-existing mapping for this client's same internal IP/port/protocol. Renewal and deletion cannot prove that another application has not since reused that tuple. Explicit NAT-PMP checkbox consent is required; a lease journal is not current ownership proof.";

#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub lifetime: u32,
    pub epoch: u32,
    pub external_port: u16,
    pub external_ip: Option<Ipv4Addr>,
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(b[i..i + 4].try_into().unwrap())
}

pub fn protocol(proto: &str) -> Result<u8, String> {
    match proto {
        "TCP" => Ok(6),
        "UDP" => Ok(17),
        _ => Err("Invalid mapping protocol".into()),
    }
}

pub fn pcp_request(
    local: Ipv4Addr,
    nonce: Option<[u8; 12]>,
    proto: u8,
    internal: u16,
    external: u16,
    ip: Option<Ipv4Addr>,
    lifetime: u32,
) -> Vec<u8> {
    let mut b = vec![
        0;
        if nonce.is_some() {
            if lifetime == 0 {
                60
            } else {
                64
            }
        } else {
            24
        }
    ];
    b[0] = 2;
    b[1] = u8::from(nonce.is_some());
    b[4..8].copy_from_slice(&lifetime.to_be_bytes());
    b[18..20].copy_from_slice(&[255, 255]);
    b[20..24].copy_from_slice(&local.octets());
    if let Some(nonce) = nonce {
        b[24..36].copy_from_slice(&nonce);
        b[36] = proto;
        b[40..42].copy_from_slice(&internal.to_be_bytes());
        b[42..44].copy_from_slice(&external.to_be_bytes());
               b[54..56].copy_from_slice(&[255, 255]);
        if let Some(ip) = ip {
            b[56..60].copy_from_slice(&ip.octets());
        }
        if lifetime != 0 {
            b[60] = 2; 
        }
           }
    b
}

fn pcp_options(b: &[u8]) -> Result<bool, String> {
    let mut i = 60;
    let mut prefer = false;
    while i < b.len() {
        if b.len() - i < 4 {
            return Err("Truncated PCP option".into());
        }
        let len = usize::from(u16_at(b, i + 2));
        let end = i + 4 + ((len + 3) & !3);
        if end > b.len() {
            return Err("Invalid PCP option length".into());
        }
        if b[i] == 2 {
            if len != 0 || prefer {
                return Err("Invalid PCP PREFER_FAILURE option".into());
            }
            prefer = true;
        }
               i = end;
    }
    Ok(prefer)
}

pub fn pcp_decode(b: &[u8], request: &[u8]) -> Result<Reply, String> {
    if request.len() < 24
        || request[0] != 2
        || !matches!(request[1], 0 | 1)
        || (request[1] == 1 && request.len() < 60)
    {
        return Err("Invalid PCP request identity context".into());
    }
    if b.len() < 24
        || b.len() > 1100
        || !b.len().is_multiple_of(4)
        || b[0] != 2
        || b[1] != (128 | request[1])
    {
        return Err("Invalid PCP version/opcode/header/length".into());
    }
    if request[1] == 1 {
        if b.len() < 60
            || b[24..36] != request[24..36]
            || b[36] != request[36]
            || b[40..42] != request[40..42]
        {
            return Err("PCP nonce/protocol/internal port identity mismatch".into());
        }
        let prefer = pcp_options(b)?;
        if b[3] == 0 && u32_at(request, 4) > 0 && !prefer {
            return Err("PCP success omitted mandatory PREFER_FAILURE acknowledgement".into());
        }
    } else if b.len() != 24 {
        return Err("Invalid PCP ANNOUNCE length".into());
    }
    if b[3] != 0 {
        if request[1] == 1 && (b[42..60] != request[42..60]) {
            return Err("PCP error response external tuple identity mismatch".into());
        }
        return Err(format!("PCP error {} ({})", b[3], pcp_error(b[3])));
    }
    let lifetime = u32_at(b, 4);
    let epoch = u32_at(b, 8);
    if request[1] == 0 {
        if lifetime != 0 {
            return Err("Invalid PCP ANNOUNCE lifetime".into());
        }
        return Ok(Reply {
            lifetime,
            epoch,
            external_port: 0,
            external_ip: None,
        });
    }
    let external_port = u16_at(b, 42);
    if external_port == 0 {
        return Err("Invalid zero PCP external port".into());
    }
       if b[44..56] != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255] {
        return Err("PCP returned a non-IPv4-mapped external address".into());
    }
    let ip = Ipv4Addr::new(b[56], b[57], b[58], b[59]);
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || ip.is_broadcast() {
        return Err("Invalid PCP external IPv4".into());
    }
    Ok(Reply {
        lifetime,
        epoch,
        external_port,
        external_ip: Some(ip),
    })
}

fn pcp_error(code: u8) -> &'static str {
    match code {
        1 => "UNSUPP_VERSION",
        2 => "NOT_AUTHORIZED",
        3 => "MALFORMED_REQUEST",
        4 => "UNSUPP_OPCODE",
        5 => "UNSUPP_OPTION",
        6 => "MALFORMED_OPTION",
        7 => "NETWORK_FAILURE",
        8 => "NO_RESOURCES",
        9 => "UNSUPP_PROTOCOL",
        10 => "USER_EX_QUOTA",
        11 => "CANNOT_PROVIDE_EXTERNAL",
        12 => "ADDRESS_MISMATCH",
        13 => "EXCESSIVE_REMOTE_PEERS",
        _ => "unknown failure",
    }
}

pub fn nat_request(proto: u8, internal: u16, external: u16, lifetime: u32) -> Vec<u8> {
    let mut b = vec![0; 12];
    b[1] = if proto == 6 { 2 } else { 1 };
    b[4..6].copy_from_slice(&internal.to_be_bytes());
       b[6..8].copy_from_slice(&if lifetime == 0 { 0 } else { external }.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

pub fn nat_decode(b: &[u8], request: &[u8]) -> Result<Reply, String> {
    if request.len() < 2
        || request[0] != 0
        || !matches!(request[1], 0..=2)
        || (request[1] != 0 && request.len() != 12)
    {
        return Err("Invalid NAT-PMP request identity context".into());
    }
    let address = request[1] == 0;
    if b.len() != if address { 12 } else { 16 } || b[0] != 0 || b[1] != (128 | request[1]) {
        return Err("Invalid NAT-PMP version/opcode/length".into());
    }
    let code = u16_at(b, 2);
    if !address && b[8..10] != request[4..6] {
        return Err("NAT-PMP internal port identity mismatch".into());
    }
    if code != 0 {
        return Err(format!("NAT-PMP error {code}"));
    }
    let epoch = u32_at(b, 4);
    if address {
        let ip = Ipv4Addr::new(b[8], b[9], b[10], b[11]);
        if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || ip.is_broadcast() {
            return Err("Invalid NAT-PMP external IPv4".into());
        }
        return Ok(Reply {
            lifetime: 0,
            epoch,
            external_port: 0,
            external_ip: Some(ip),
        });
    }
    let external_port = u16_at(b, 10);
       if u32_at(request, 8) != 0 && external_port == 0 {
        return Err("Invalid zero NAT-PMP external port".into());
    }
    Ok(Reply {
        lifetime: u32_at(b, 12),
        epoch,
        external_port,
        external_ip: None,
    })
}

pub trait Transport {
    fn exchange(&mut self, request: &[u8], pcp: bool) -> Result<Reply, String>;
}

pub struct PhysicalTransport {
    socket: UdpSocket,
    lan: Lan,
    lease_deadline: Option<u64>,
}

impl PhysicalTransport {
    pub fn new(lan: &Lan) -> Result<Self, String> {
        router::network_allowed()?;
        router::verify_route(lan)?;
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| e.to_string())?;
        socket
            .bind(&SocketAddrV4::new(lan.local, 0).into())
            .map_err(|e| e.to_string())?;
        socket
            .connect(&SocketAddrV4::new(lan.gateway, 5351).into())
            .map_err(|e| e.to_string())?;
        let socket: UdpSocket = socket.into();
        if socket.local_addr().map_err(|e| e.to_string())?.ip() != lan.local {
            return Err("UDP source is not selected physical LAN".into());
        }
        Ok(Self {
            socket,
            lan: lan.clone(),
            lease_deadline: None,
        })
    }

    pub fn before_expiry(mut self, end: u64) -> Self {
        self.lease_deadline = Some(end);
        self
    }

    fn check_deadline(&self) -> Result<(), String> {
        if self.lease_deadline.is_some_and(|end| end <= crate::now()) {
            Err("Known lease deadline reached; not recreated or deleted.".into())
        } else {
            Ok(())
        }
    }
}

impl Transport for PhysicalTransport {
    fn exchange(&mut self, request: &[u8], pcp: bool) -> Result<Reply, String> {
        router::network_allowed()?;
        router::verify_route(&self.lan)?;
        let mut last = "No response (unconfirmed, not unsupported)".to_string();
        let mut buffer = [0; 1101];
        for seconds in [1, 2, 4] {
            router::verify_route(&self.lan)?;
            self.check_deadline()?;
            self.socket
                .send(request)
                .map_err(|e| format!("UDP send failed; outcome unconfirmed: {e}"))?;
            let deadline = Instant::now() + Duration::from_secs(seconds);
            for _ in 0..64 {
                let mut remaining = deadline.saturating_duration_since(Instant::now());
                if let Some(end) = self.lease_deadline {
                    remaining =
                        remaining.min(Duration::from_secs(end.saturating_sub(crate::now())));
                }
                if remaining.is_zero() {
                    break;
                }
                self.socket
                    .set_read_timeout(Some(remaining))
                    .map_err(|e| e.to_string())?;
                match self.socket.recv_from(&mut buffer) {
                    Ok((len, source))
                        if source == SocketAddrV4::new(self.lan.gateway, 5351).into() =>
                    {
                        let result = if pcp {
                            pcp_decode(&buffer[..len], request)
                        } else {
                            nat_decode(&buffer[..len], request)
                        };
                        match result {
                            Ok(reply) => return Ok(reply),
                            Err(e)
                                if e.starts_with("PCP error") || e.starts_with("NAT-PMP error") =>
                            {
                                return Err(e)
                            }
                            Err(e) => last = e,
                        }
                    }
                    Ok(_) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        break
                    }
                    Err(e) => return Err(format!("UDP response unconfirmed: {e}")),
                }
            }
        }
        Err(format!(
            "Bounded UDP retries exhausted: {last}; outcome unconfirmed"
        ))
    }
}

pub fn epoch_valid(previous: u32, current: u32, elapsed: u64) -> bool {
    if current < previous {
        return false;
    }
    let delta = u64::from(current - previous);
    elapsed.saturating_add(2) >= delta - delta / 16
        && delta.saturating_add(2) >= elapsed - elapsed / 16
}

pub fn validate_grant(
    reply: &Reply,
    requested: u16,
    ip: Option<Ipv4Addr>,
    deleting: bool,
) -> Result<(), String> {
    if deleting {
        if reply.lifetime != 0 {
            return Err("Deletion response has nonzero lifetime; removal unconfirmed".into());
        }
    } else if reply.lifetime == 0 || reply.lifetime > LIFETIME {
        return Err(format!(
            "Granted lease {} is not within 1..=3600; retained for safe explicit cleanup",
            reply.lifetime
        ));
    }
    if reply.external_port != requested
        && !(deleting && reply.external_ip.is_none() && reply.external_port == 0)
    {
        return Err("Router remapped external port; exact port required, returned tuple retained for cleanup".into());
    }
    if ip.is_some() && reply.external_ip.is_some() && ip != reply.external_ip {
        return Err("External address changed; exact tuple retained for cleanup".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "udp_tests.rs"]
mod tests;
