use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 16;

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
}
