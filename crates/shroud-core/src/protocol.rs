use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    UdpDatagram = 0x30,
    UdpAssociateRequest = 0x31,
    UdpAssociateResponse = 0x32,
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
            0x30 => Self::UdpDatagram,
            0x31 => Self::UdpAssociateRequest,
            0x32 => Self::UdpAssociateResponse,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameCommand {
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

pub async fn write_frame<W>(
    writer: &mut W,
    frame_type: FrameType,
    stream_id: u64,
    flags: u16,
    payload: Bytes,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::FramePayloadTooLarge {
            max: MAX_FRAME_PAYLOAD_LEN,
            got: payload.len(),
        });
    }

    let frame = Frame {
        frame_type,
        stream_id,
        flags,
        payload,
    };
    writer.write_all(frame.encode().as_ref()).await?;
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame, ProtocolError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let payload_len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::FramePayloadTooLarge {
            max: MAX_FRAME_PAYLOAD_LEN,
            got: payload_len,
        });
    }

    let mut raw = Vec::with_capacity(HEADER_LEN + payload_len);
    raw.extend_from_slice(&header);

    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }

    Frame::decode(Bytes::from(raw))
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
    #[error("invalid udp datagram payload: {0}")]
    InvalidUdpDatagramPayload(&'static str),
    #[error("invalid udp associate response payload: {0}")]
    InvalidUdpAssociateResponsePayload(&'static str),
    #[error("domain is too long for protocol: {0} bytes")]
    DomainTooLong(usize),
    #[error("udp datagram payload is too large: max={max}, got={got}")]
    UdpDatagramPayloadTooLarge { max: usize, got: usize },
    #[error("frame IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthChallenge => write!(f, "AUTH_CHALLENGE"),
            Self::AuthResponse => write!(f, "AUTH_RESPONSE"),
            Self::TcpConnect => write!(f, "TCP_CONNECT"),
            Self::TcpData => write!(f, "TCP_DATA"),
            Self::TcpClose => write!(f, "TCP_CLOSE"),
            Self::UdpDatagram => write!(f, "UDP_DATAGRAM"),
            Self::UdpAssociateRequest => write!(f, "UDP_ASSOCIATE_REQUEST"),
            Self::UdpAssociateResponse => write!(f, "UDP_ASSOCIATE_RESPONSE"),
            Self::Ping => write!(f, "PING"),
            Self::Pong => write!(f, "PONG"),
            Self::ErrorFrame => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub target_host: String,
    pub target_port: u16,
    pub payload: Bytes,
    pub association_id: Option<u64>,
}

const UDP_DATAGRAM_ASSOCIATION_ID_FLAG: u8 = 0x01;

pub fn encode_tcp_connect_payload(host: &str, port: u16) -> Result<Bytes, ProtocolError> {
    let mut payload = BytesMut::new();

    encode_target_addr(host, &mut payload)?;
    payload.put_u16(port);
    Ok(payload.freeze())
}

pub fn decode_tcp_connect_payload(payload: &[u8]) -> Result<(String, u16), ProtocolError> {
    if payload.len() < 3 {
        return Err(ProtocolError::InvalidConnectPayload("payload too short"));
    }

    let (host, cursor) = decode_target_addr(payload, 0, ProtocolError::InvalidConnectPayload)?;

    if payload.len() != cursor + 2 {
        return Err(ProtocolError::InvalidConnectPayload(
            "payload has unexpected trailing bytes",
        ));
    }

    let port = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    Ok((host, port))
}

pub fn encode_udp_associate_response_payload(
    bind_host: &str,
    bind_port: u16,
) -> Result<Bytes, ProtocolError> {
    let mut payload = BytesMut::new();

    encode_target_addr(bind_host, &mut payload)?;
    payload.put_u16(bind_port);
    Ok(payload.freeze())
}

pub fn decode_udp_associate_response_payload(
    payload: &[u8],
) -> Result<(String, u16), ProtocolError> {
    if payload.len() < 3 {
        return Err(ProtocolError::InvalidUdpAssociateResponsePayload(
            "payload too short",
        ));
    }

    let (host, cursor) = decode_target_addr(
        payload,
        0,
        ProtocolError::InvalidUdpAssociateResponsePayload,
    )?;

    if payload.len() != cursor + 2 {
        return Err(ProtocolError::InvalidUdpAssociateResponsePayload(
            "payload has unexpected trailing bytes",
        ));
    }

    let port = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    Ok((host, port))
}

pub fn encode_udp_datagram(datagram: &UdpDatagram) -> Result<Bytes, ProtocolError> {
    let mut payload = BytesMut::new();
    let flags = if datagram.association_id.is_some() {
        UDP_DATAGRAM_ASSOCIATION_ID_FLAG
    } else {
        0
    };
    payload.put_u8(flags);

    if let Some(association_id) = datagram.association_id {
        payload.put_u64(association_id);
    }

    encode_target_addr(&datagram.target_host, &mut payload)?;
    payload.put_u16(datagram.target_port);
    payload.extend_from_slice(&datagram.payload);

    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::UdpDatagramPayloadTooLarge {
            max: MAX_FRAME_PAYLOAD_LEN,
            got: payload.len(),
        });
    }

    Ok(payload.freeze())
}

pub fn decode_udp_datagram(payload: &[u8]) -> Result<UdpDatagram, ProtocolError> {
    let flags = *payload
        .first()
        .ok_or(ProtocolError::InvalidUdpDatagramPayload(
            "payload too short",
        ))?;
    if flags & !UDP_DATAGRAM_ASSOCIATION_ID_FLAG != 0 {
        return Err(ProtocolError::InvalidUdpDatagramPayload(
            "unknown udp datagram flags",
        ));
    }

    let mut cursor = 1usize;
    let association_id = if flags & UDP_DATAGRAM_ASSOCIATION_ID_FLAG != 0 {
        if payload.len() < cursor + 8 {
            return Err(ProtocolError::InvalidUdpDatagramPayload(
                "missing association id",
            ));
        }
        let id = u64::from_be_bytes(
            payload[cursor..cursor + 8]
                .try_into()
                .expect("slice length checked"),
        );
        cursor += 8;
        Some(id)
    } else {
        None
    };

    let (target_host, cursor) =
        decode_target_addr(payload, cursor, ProtocolError::InvalidUdpDatagramPayload)?;
    if payload.len() < cursor + 2 {
        return Err(ProtocolError::InvalidUdpDatagramPayload(
            "missing target port",
        ));
    }
    let target_port = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
    let cursor = cursor + 2;

    Ok(UdpDatagram {
        target_host,
        target_port,
        payload: Bytes::copy_from_slice(&payload[cursor..]),
        association_id,
    })
}

fn encode_target_addr(host: &str, payload: &mut BytesMut) -> Result<(), ProtocolError> {
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

    Ok(())
}

fn decode_target_addr(
    payload: &[u8],
    start: usize,
    invalid: fn(&'static str) -> ProtocolError,
) -> Result<(String, usize), ProtocolError> {
    let addr_type = *payload.get(start).ok_or(invalid("missing address type"))?;
    let addr_type = AddressType::try_from(addr_type)?;
    let mut cursor = start + 1;

    let host = match addr_type {
        AddressType::Ipv4 => {
            if payload.len() < cursor + 4 {
                return Err(invalid("ipv4 payload shorter than expected"));
            }
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&payload[cursor..cursor + 4]);
            cursor += 4;
            IpAddr::V4(Ipv4Addr::from(raw)).to_string()
        }
        AddressType::Ipv6 => {
            if payload.len() < cursor + 16 {
                return Err(invalid("ipv6 payload shorter than expected"));
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&payload[cursor..cursor + 16]);
            cursor += 16;
            IpAddr::V6(Ipv6Addr::from(raw)).to_string()
        }
        AddressType::Domain => {
            let domain_len = *payload
                .get(cursor)
                .ok_or(invalid("missing domain length"))? as usize;
            cursor += 1;
            if payload.len() < cursor + domain_len {
                return Err(invalid("domain payload shorter than expected"));
            }
            let domain_raw = &payload[cursor..cursor + domain_len];
            cursor += domain_len;
            std::str::from_utf8(domain_raw)
                .map_err(|_| invalid("domain is not valid utf-8"))?
                .to_string()
        }
    };

    Ok((host, cursor))
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

    #[tokio::test]
    async fn read_write_frame_preserves_non_default_stream_id() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);

        write_frame(
            &mut writer,
            FrameType::TcpData,
            7,
            0x0002,
            Bytes::from_static(b"payload"),
        )
        .await
        .expect("write frame");

        let decoded = read_frame(&mut reader).await.expect("read frame");

        assert_eq!(decoded.frame_type, FrameType::TcpData);
        assert_eq!(decoded.stream_id, 7);
        assert_eq!(decoded.flags, 0x0002);
        assert_eq!(decoded.payload, Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let (mut writer, _reader) = tokio::io::duplex(1024);
        let payload = Bytes::from(vec![0u8; MAX_FRAME_PAYLOAD_LEN + 1]);

        let err = write_frame(&mut writer, FrameType::TcpData, 1, 0, payload)
            .await
            .expect_err("oversized frame must fail");

        assert!(matches!(err, ProtocolError::FramePayloadTooLarge { .. }));
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
    fn decode_rejects_short_header() {
        let err = Frame::decode(Bytes::from_static(b"\x01\x11"))
            .expect_err("short frame header must fail");
        assert!(matches!(err, ProtocolError::FrameTooShort(2)));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let mut encoded = BytesMut::with_capacity(HEADER_LEN + 2);
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(FrameType::TcpData as u8);
        encoded.put_u64(1);
        encoded.put_u16(0);
        encoded.put_u32(3);
        encoded.extend_from_slice(b"ab");

        let err = Frame::decode(encoded.freeze()).expect_err("truncated payload must fail");
        assert!(matches!(
            err,
            ProtocolError::PayloadLengthMismatch {
                expected: 3,
                got: 2
            }
        ));
    }

    #[test]
    fn decode_rejects_payload_length_with_trailing_bytes() {
        let mut encoded = BytesMut::with_capacity(HEADER_LEN + 3);
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(FrameType::TcpData as u8);
        encoded.put_u64(1);
        encoded.put_u16(0);
        encoded.put_u32(2);
        encoded.extend_from_slice(b"abc");

        let err = Frame::decode(encoded.freeze()).expect_err("trailing payload bytes must fail");
        assert!(matches!(
            err,
            ProtocolError::PayloadLengthMismatch {
                expected: 2,
                got: 3
            }
        ));
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

    #[test]
    fn roundtrip_udp_associate_response_payload_ipv4() {
        let payload = encode_udp_associate_response_payload("127.0.0.1", 49152).expect("encode");
        let (host, port) = decode_udp_associate_response_payload(payload.as_ref()).expect("decode");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 49152);
    }

    #[test]
    fn roundtrip_udp_datagram_domain_without_association() {
        let datagram = UdpDatagram {
            target_host: "example.com".to_string(),
            target_port: 53,
            payload: Bytes::from_static(b"dns"),
            association_id: None,
        };

        let encoded = encode_udp_datagram(&datagram).expect("encode");
        let decoded = decode_udp_datagram(encoded.as_ref()).expect("decode");

        assert_eq!(decoded, datagram);
    }

    #[test]
    fn roundtrip_udp_datagram_ipv4_with_association() {
        let datagram = UdpDatagram {
            target_host: "192.0.2.10".to_string(),
            target_port: 443,
            payload: Bytes::from_static(b"payload"),
            association_id: Some(42),
        };

        let encoded = encode_udp_datagram(&datagram).expect("encode");
        let decoded = decode_udp_datagram(encoded.as_ref()).expect("decode");

        assert_eq!(decoded, datagram);
    }

    #[test]
    fn roundtrip_udp_datagram_ipv6() {
        let datagram = UdpDatagram {
            target_host: "2001:db8::1".to_string(),
            target_port: 5353,
            payload: Bytes::from_static(b"payload"),
            association_id: None,
        };

        let encoded = encode_udp_datagram(&datagram).expect("encode");
        let decoded = decode_udp_datagram(encoded.as_ref()).expect("decode");

        assert_eq!(decoded, datagram);
    }

    #[test]
    fn decode_udp_datagram_rejects_unknown_flags() {
        let payload = Bytes::from_static(b"\x02");
        let err = decode_udp_datagram(payload.as_ref()).expect_err("unknown flags must fail");
        assert!(matches!(
            err,
            ProtocolError::InvalidUdpDatagramPayload("unknown udp datagram flags")
        ));
    }

    #[test]
    fn decode_udp_datagram_rejects_truncated_association_id() {
        let payload = Bytes::from_static(b"\x01\x00\x00");
        let err = decode_udp_datagram(payload.as_ref()).expect_err("truncated id must fail");
        assert!(matches!(
            err,
            ProtocolError::InvalidUdpDatagramPayload("missing association id")
        ));
    }
}
