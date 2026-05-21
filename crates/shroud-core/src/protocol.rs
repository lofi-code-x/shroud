use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 16;
pub const MAX_FRAME_PAYLOAD_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    AuthChallenge = 0x01,
    AuthResponse = 0x02,
    TcpConnect = 0x10,
    TcpData = 0x11,
    TcpClose = 0x12,
    Ping = 0x20,
    Pong = 0x21,
    ErrorFrame = 0x7F,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let frame_type = match value {
            0x01 => Self::AuthChallenge,
            0x02 => Self::AuthResponse,
            0x10 => Self::TcpConnect,
            0x11 => Self::TcpData,
            0x12 => Self::TcpClose,
            0x20 => Self::Ping,
            0x21 => Self::Pong,
            0x7F => Self::ErrorFrame,
            _ => return Err(ProtocolError::UnknownFrameType(value)),
        };
        Ok(frame_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub stream_id: u64,
    pub flags: u16,
    pub payload: Bytes,
}

impl Frame {
    pub fn encode(&self) -> Bytes {
        assert!(
            self.payload.len() <= MAX_FRAME_PAYLOAD_LEN,
            "frame payload exceeds maximum size"
        );
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        out.put_u8(PROTOCOL_VERSION);
        out.put_u8(self.frame_type as u8);
        out.put_u64(self.stream_id);
        out.put_u16(self.flags);
        out.put_u32(self.payload.len() as u32);
        out.extend_from_slice(&self.payload);
        out.freeze()
    }

    pub fn decode(mut src: Bytes) -> Result<Self, ProtocolError> {
        if src.len() < HEADER_LEN {
            return Err(ProtocolError::FrameTooShort(src.len()));
        }

        let version = src.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch {
                got: version,
                expected: PROTOCOL_VERSION,
            });
        }

        let frame_type = FrameType::try_from(src.get_u8())?;
        let stream_id = src.get_u64();
        let flags = src.get_u16();
        let length = src.get_u32() as usize;

        if length > MAX_FRAME_PAYLOAD_LEN {
            return Err(ProtocolError::FramePayloadTooLarge {
                max: MAX_FRAME_PAYLOAD_LEN,
                got: length,
            });
        }

        if src.len() != length {
            return Err(ProtocolError::PayloadLengthMismatch {
                expected: length,
                got: src.len(),
            });
        }

        Ok(Self {
            frame_type,
            stream_id,
            flags,
            payload: src,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ipv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::Ipv6),
            _ => Err(ProtocolError::UnknownAddressType(value)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("unknown frame type: {0:#04x}")]
    UnknownFrameType(u8),
    #[error("unknown address type: {0:#04x}")]
    UnknownAddressType(u8),
    #[error("frame too short: {0} bytes")]
    FrameTooShort(usize),
    #[error("protocol version mismatch: got={got}, expected={expected}")]
    VersionMismatch { got: u8, expected: u8 },
    #[error("payload length mismatch: expected={expected}, got={got}")]
    PayloadLengthMismatch { expected: usize, got: usize },
    #[error("frame payload too large: max={max}, got={got}")]
    FramePayloadTooLarge { max: usize, got: usize },
    #[error("invalid connect payload: {0}")]
    InvalidConnectPayload(&'static str),
    #[error("domain is too long for protocol: {0} bytes")]
    DomainTooLong(usize),
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthChallenge => write!(f, "AUTH_CHALLENGE"),
            Self::AuthResponse => write!(f, "AUTH_RESPONSE"),
            Self::TcpConnect => write!(f, "TCP_CONNECT"),
            Self::TcpData => write!(f, "TCP_DATA"),
            Self::TcpClose => write!(f, "TCP_CLOSE"),
            Self::Ping => write!(f, "PING"),
            Self::Pong => write!(f, "PONG"),
            Self::ErrorFrame => write!(f, "ERROR"),
        }
    }
}

pub fn encode_tcp_connect_payload(host: &str, port: u16) -> Result<Bytes, ProtocolError> {
    let mut payload = BytesMut::new();

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(addr) => {
                payload.put_u8(AddressType::Ipv4 as u8);
                payload.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                payload.put_u8(AddressType::Ipv6 as u8);
                payload.extend_from_slice(&addr.octets());
            }
        }
    } else {
        let host_bytes = host.as_bytes();
        if host_bytes.len() > u8::MAX as usize {
            return Err(ProtocolError::DomainTooLong(host_bytes.len()));
        }

        payload.put_u8(AddressType::Domain as u8);
        payload.put_u8(host_bytes.len() as u8);
        payload.extend_from_slice(host_bytes);
    }

    payload.put_u16(port);
    Ok(payload.freeze())
}

pub fn decode_tcp_connect_payload(payload: &[u8]) -> Result<(String, u16), ProtocolError> {
    if payload.len() < 3 {
        return Err(ProtocolError::InvalidConnectPayload("payload too short"));
    }

    let addr_type = AddressType::try_from(payload[0])?;
    let mut cursor = 1usize;

    let host = match addr_type {
        AddressType::Ipv4 => {
            if payload.len() < cursor + 4 + 2 {
                return Err(ProtocolError::InvalidConnectPayload(
                    "ipv4 payload shorter than expected",
                ));
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&payload[cursor..cursor + 4]);
            cursor += 4;
            IpAddr::V4(Ipv4Addr::from(raw)).to_string()
        }
        AddressType::Ipv6 => {
            if payload.len() < cursor + 16 + 2 {
                return Err(ProtocolError::InvalidConnectPayload(
                    "ipv6 payload shorter than expected",
                ));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&payload[cursor..cursor + 16]);
            cursor += 16;
            IpAddr::V6(Ipv6Addr::from(raw)).to_string()
        }
        AddressType::Domain => {
            let domain_len = *payload
                .get(cursor)
                .ok_or(ProtocolError::InvalidConnectPayload(
                    "missing domain length",
                ))? as usize;
            cursor += 1;
            if payload.len() < cursor + domain_len + 2 {
                return Err(ProtocolError::InvalidConnectPayload(
                    "domain payload shorter than expected",
                ));
            }
            let domain_raw = &payload[cursor..cursor + domain_len];
            cursor += domain_len;
            std::str::from_utf8(domain_raw)
                .map_err(|_| ProtocolError::InvalidConnectPayload("domain is not valid utf-8"))?
                .to_string()
        }
    };

    if payload.len() != cursor + 2 {
        return Err(ProtocolError::InvalidConnectPayload(
            "payload has unexpected trailing bytes",
        ));
    }

    let port = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn roundtrip_frame() {
        let frame = Frame {
            frame_type: FrameType::Ping,
            stream_id: 42,
            flags: 1,
            payload: Bytes::from_static(b"hello"),
        };

        let encoded = frame.encode();
        let decoded = Frame::decode(encoded).expect("decode");

        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.payload, Bytes::from_static(b"hello"));
    }

    #[test]
    fn decode_rejects_oversized_payload_length() {
        let mut encoded = BytesMut::with_capacity(HEADER_LEN);
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(FrameType::TcpData as u8);
        encoded.put_u64(1);
        encoded.put_u16(0);
        encoded.put_u32((MAX_FRAME_PAYLOAD_LEN + 1) as u32);

        let err = Frame::decode(encoded.freeze()).expect_err("oversized frame must fail");
        assert!(matches!(err, ProtocolError::FramePayloadTooLarge { .. }));
    }

    #[test]
    fn roundtrip_connect_payload_domain() {
        let payload = encode_tcp_connect_payload("example.com", 443).expect("encode");
        let (host, port) = decode_tcp_connect_payload(payload.as_ref()).expect("decode");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn roundtrip_connect_payload_ipv4() {
        let payload = encode_tcp_connect_payload("127.0.0.1", 8080).expect("encode");
        let (host, port) = decode_tcp_connect_payload(payload.as_ref()).expect("decode");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
    }
}
