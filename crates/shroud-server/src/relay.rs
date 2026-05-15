use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::protocol::{Frame, FrameType, HEADER_LEN, decode_tcp_connect_payload};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const CONNECT_OK_FLAG: u16 = 0x0001;

pub async fn relay_tunnel(mut tunnel_stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let connect_request = read_frame(&mut tunnel_stream).await?;
    if connect_request.frame_type != FrameType::TcpConnect {
        write_frame(
            &mut tunnel_stream,
            FrameType::ErrorFrame,
            connect_request.stream_id,
            0,
            Bytes::from_static(b"expected TCP_CONNECT as first frame"),
        )
        .await?;
        bail!(
            "first frame from peer {} is not TCP_CONNECT: {}",
            peer,
            connect_request.frame_type
        );
    }

    let stream_id = connect_request.stream_id;
    let (target_host, target_port) =
        decode_tcp_connect_payload(connect_request.payload.as_ref())
            .map_err(|err| anyhow!("invalid TCP_CONNECT payload: {err}"))?;

    let mut target_stream = match TcpStream::connect((target_host.as_str(), target_port)).await {
        Ok(stream) => stream,
        Err(err) => {
            let message = format!("failed to connect target {target_host}:{target_port}: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };

    write_frame(
        &mut tunnel_stream,
        FrameType::TcpConnect,
        stream_id,
        CONNECT_OK_FLAG,
        Bytes::new(),
    )
    .await?;

    let (mut tunnel_read, mut tunnel_write) = tunnel_stream.split();
    let (mut target_read, mut target_write) = target_stream.split();

    let tunnel_to_target = async {
        let mut transferred = 0u64;

        loop {
            let frame = read_frame(&mut tunnel_read).await?;
            if frame.stream_id != stream_id {
                bail!(
                    "unexpected stream id from peer {}; expected={}, got={}",
                    peer,
                    stream_id,
                    frame.stream_id
                );
            }

            match frame.frame_type {
                FrameType::TcpData => {
                    transferred += frame.payload.len() as u64;
                    target_write.write_all(frame.payload.as_ref()).await?;
                }
                FrameType::TcpClose => {
                    target_write.shutdown().await?;
                    break;
                }
                FrameType::ErrorFrame => {
                    let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                    bail!("peer sent ERROR frame: {message}");
                }
                other => bail!("unexpected frame type from peer during relay: {other}"),
            }
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let target_to_tunnel = async {
        let mut transferred = 0u64;
        let mut buf = [0u8; 16 * 1024];

        loop {
            let n = target_read.read(&mut buf).await?;
            if n == 0 {
                write_frame(
                    &mut tunnel_write,
                    FrameType::TcpClose,
                    stream_id,
                    0,
                    Bytes::new(),
                )
                .await?;
                tunnel_write.shutdown().await?;
                break;
            }

            transferred += n as u64;
            write_frame(
                &mut tunnel_write,
                FrameType::TcpData,
                stream_id,
                0,
                Bytes::copy_from_slice(&buf[..n]),
            )
            .await?;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let (upstream_to_target_bytes, target_to_upstream_bytes) =
        tokio::try_join!(tunnel_to_target, target_to_tunnel)?;

    debug!(
        %peer,
        stream_id,
        target_host,
        target_port,
        upstream_to_target_bytes,
        target_to_upstream_bytes,
        "tunnel relay finished"
    );

    Ok(())
}

async fn write_frame<W>(
    writer: &mut W,
    frame_type: FrameType,
    stream_id: u64,
    flags: u16,
    payload: Bytes,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = Frame {
        frame_type,
        stream_id,
        flags,
        payload,
    };
    writer.write_all(frame.encode().as_ref()).await?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let payload_len = u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let mut raw = Vec::with_capacity(HEADER_LEN + payload_len);
    raw.extend_from_slice(&header);

    if payload_len > 0 {
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;
        raw.extend_from_slice(&payload);
    }

    Frame::decode(Bytes::from(raw)).map_err(|err| anyhow!("failed to decode frame: {err}"))
}
