use crate::tunnel::{TunnelClient, TunnelStream};
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{
    FrameCommand, FrameType, encode_tcp_connect_payload, read_frame, write_frame,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

const WRITER_CHANNEL_CAPACITY: usize = 128;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD: Duration = Duration::from_millis(1);

type StreamTx = mpsc::Sender<Bytes>;

#[derive(Clone)]
pub struct TunnelManager {
    inner: Arc<TunnelManagerInner>,
}

struct TunnelManagerInner {
    writer_tx: mpsc::Sender<FrameCommand>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    next_stream_id: AtomicU64,
}

pub struct TunnelStreamHandle {
    stream_id: u64,
    target_host: String,
    target_port: u16,
    opened_at: Instant,
    writer_tx: mpsc::Sender<FrameCommand>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    inbound_rx: mpsc::Receiver<Bytes>,
    closed: Arc<AtomicBool>,
}

pub struct TunnelStreamReadHalf {
    inbound_rx: mpsc::Receiver<Bytes>,
}

#[derive(Clone)]
pub struct TunnelStreamWriteHalf {
    stream_id: u64,
    writer_tx: mpsc::Sender<FrameCommand>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    closed: Arc<AtomicBool>,
}

impl TunnelManager {
    pub async fn connect(outbound: OutboundConfig, auth: ClientAuthConfig) -> Result<Self> {
        let tunnel = TunnelClient::new(outbound, auth);
        let stream = tunnel.open_persistent_tunnel_transport().await?;
        let (read_half, write_half) = split(stream);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_CHANNEL_CAPACITY);
        let streams = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(tunnel_writer_loop(
            write_half,
            writer_rx,
            Arc::clone(&streams),
        ));
        tokio::spawn(tunnel_reader_loop(read_half, Arc::clone(&streams)));

        info!("persistent physical tunnel opened");

        Ok(Self {
            inner: Arc::new(TunnelManagerInner {
                writer_tx,
                streams,
                next_stream_id: AtomicU64::new(1),
            }),
        })
    }

    pub async fn open_tcp_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStreamHandle> {
        let stream_id = self.inner.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let payload = encode_tcp_connect_payload(target_host, target_port)
            .map_err(|err| anyhow!("failed to encode TCP_CONNECT payload: {err}"))?;
        let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

        {
            let mut streams = self.inner.streams.lock().await;
            streams.insert(stream_id, inbound_tx);
            debug!(
                stream_id,
                target_host,
                target_port,
                active_streams = streams.len(),
                "logical TCP stream opened"
            );
        }

        if let Err(err) = send_writer_command(
            &self.inner.writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpConnect,
                stream_id,
                flags: 0,
                payload,
            },
            "TCP_CONNECT",
        )
        .await
        {
            let mut streams = self.inner.streams.lock().await;
            streams.remove(&stream_id);
            return Err(err).context("failed to queue TCP_CONNECT for persistent tunnel");
        }

        Ok(TunnelStreamHandle {
            stream_id,
            target_host: target_host.to_owned(),
            target_port,
            opened_at: Instant::now(),
            writer_tx: self.inner.writer_tx.clone(),
            streams: Arc::clone(&self.inner.streams),
            inbound_rx,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl TunnelStreamHandle {
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    pub fn opened_at(&self) -> Instant {
        self.opened_at
    }

    pub fn into_split(self) -> (TunnelStreamReadHalf, TunnelStreamWriteHalf) {
        (
            TunnelStreamReadHalf {
                inbound_rx: self.inbound_rx,
            },
            TunnelStreamWriteHalf {
                stream_id: self.stream_id,
                writer_tx: self.writer_tx,
                streams: self.streams,
                closed: self.closed,
            },
        )
    }

    pub async fn send_data(&self, bytes: Bytes) -> Result<()> {
        send_writer_command(
            &self.writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: self.stream_id,
                flags: 0,
                payload: bytes,
            },
            "TCP_DATA",
        )
        .await
    }

    pub async fn recv_data(&mut self) -> Option<Bytes> {
        self.inbound_rx.recv().await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(self.stream_id, &self.writer_tx, &self.streams, &self.closed).await
    }
}

impl TunnelStreamReadHalf {
    pub async fn recv_data(&mut self) -> Option<Bytes> {
        self.inbound_rx.recv().await
    }
}

impl TunnelStreamWriteHalf {
    pub async fn send_data(&self, bytes: Bytes) -> Result<()> {
        send_writer_command(
            &self.writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: self.stream_id,
                flags: 0,
                payload: bytes,
            },
            "TCP_DATA",
        )
        .await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(self.stream_id, &self.writer_tx, &self.streams, &self.closed).await
    }

    pub async fn cleanup_local(&self) -> usize {
        self.closed.store(true, Ordering::Release);
        let mut streams = self.streams.lock().await;
        streams.remove(&self.stream_id);
        streams.len()
    }
}

async fn close_stream(
    stream_id: u64,
    writer_tx: &mpsc::Sender<FrameCommand>,
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
    closed: &AtomicBool,
) -> Result<()> {
    if closed.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    if let Err(err) = send_writer_command(
        writer_tx,
        FrameCommand {
            frame_type: FrameType::TcpClose,
            stream_id,
            flags: 0,
            payload: Bytes::new(),
        },
        "TCP_CLOSE",
    )
    .await
    {
        streams.lock().await.remove(&stream_id);
        return Err(err).context("failed to queue TCP_CLOSE for persistent tunnel");
    }

    Ok(())
}

async fn tunnel_writer_loop(
    mut write_half: WriteHalf<TunnelStream>,
    mut rx: mpsc::Receiver<FrameCommand>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
) {
    while let Some(cmd) = rx.recv().await {
        if let Err(err) = write_frame(
            &mut write_half,
            cmd.frame_type,
            cmd.stream_id,
            cmd.flags,
            cmd.payload,
        )
        .await
        {
            let active_streams = clear_streams(&streams).await;
            warn!(
                error = %err,
                active_streams,
                "persistent physical tunnel closed after writer failure"
            );
            break;
        }
    }

    debug!("persistent tunnel writer finished");
}

async fn tunnel_reader_loop(
    mut read_half: ReadHalf<TunnelStream>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
) {
    loop {
        let frame = match read_frame(&mut read_half).await {
            Ok(frame) => frame,
            Err(err) => {
                let active_streams = clear_streams(&streams).await;
                warn!(
                    error = %err,
                    active_streams,
                    "persistent physical tunnel closed after reader failure"
                );
                break;
            }
        };

        match frame.frame_type {
            FrameType::TcpData => {
                let tx = {
                    let streams = streams.lock().await;
                    streams.get(&frame.stream_id).cloned()
                };

                if let Some(tx) = tx {
                    if tx.send(frame.payload).await.is_err() {
                        let mut streams = streams.lock().await;
                        streams.remove(&frame.stream_id);
                        debug!(
                            stream_id = frame.stream_id,
                            active_streams = streams.len(),
                            "logical TCP stream removed after inbound receiver closed"
                        );
                    }
                } else {
                    debug!(
                        stream_id = frame.stream_id,
                        "dropping TCP_DATA for unknown stream"
                    );
                }
            }
            FrameType::TcpClose => {
                let mut streams = streams.lock().await;
                streams.remove(&frame.stream_id);
                debug!(
                    stream_id = frame.stream_id,
                    active_streams = streams.len(),
                    "logical TCP stream closed by peer"
                );
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                let mut streams = streams.lock().await;
                streams.remove(&frame.stream_id);
                debug!(
                    stream_id = frame.stream_id,
                    active_streams = streams.len(),
                    error = %message,
                    "logical TCP stream failed by peer"
                );
            }
            FrameType::Pong => {
                debug!("persistent tunnel PONG received");
            }
            FrameType::TcpConnect => {
                debug!(
                    stream_id = frame.stream_id,
                    flags = frame.flags,
                    "persistent tunnel TCP_CONNECT response received"
                );
            }
            other => {
                debug!(
                    stream_id = frame.stream_id,
                    frame_type = %other,
                    "ignoring unsupported frame on persistent tunnel"
                );
            }
        }
    }
}

async fn send_writer_command(
    writer_tx: &mpsc::Sender<FrameCommand>,
    cmd: FrameCommand,
    operation: &'static str,
) -> Result<()> {
    let frame_type = cmd.frame_type;
    let stream_id = cmd.stream_id;
    let payload_len = cmd.payload.len();
    let started = Instant::now();

    writer_tx
        .send(cmd)
        .await
        .with_context(|| format!("failed to queue {operation} for persistent tunnel"))?;

    let wait = started.elapsed();
    if wait >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
        debug!(
            stream_id,
            frame_type = %frame_type,
            payload_len,
            writer_channel_send_wait_ms = elapsed_millis(wait),
            "persistent tunnel writer channel send waited"
        );
    }

    Ok(())
}

async fn clear_streams(streams: &Arc<Mutex<HashMap<u64, StreamTx>>>) -> usize {
    let mut streams = streams.lock().await;
    let active_streams = streams.len();
    streams.clear();
    active_streams
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{read_frame, write_frame};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::time::timeout;

    #[test]
    fn stream_ids_are_client_odd_ids() {
        let next_stream_id = AtomicU64::new(1);

        assert_eq!(next_stream_id.fetch_add(2, Ordering::Relaxed), 1);
        assert_eq!(next_stream_id.fetch_add(2, Ordering::Relaxed), 3);
        assert_eq!(next_stream_id.fetch_add(2, Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn writer_loop_serializes_frame_commands() {
        let (stream, mut peer) = duplex(1024);
        let (_read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (tx, rx) = mpsc::channel(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let writer = tokio::spawn(tunnel_writer_loop(write_half, rx, streams));

        tx.send(FrameCommand {
            frame_type: FrameType::TcpData,
            stream_id: 3,
            flags: 0,
            payload: Bytes::from_static(b"hello"),
        })
        .await
        .expect("send frame command");
        drop(tx);

        let frame = timeout(Duration::from_secs(1), read_frame(&mut peer))
            .await
            .expect("read frame timeout")
            .expect("read frame");
        writer.await.expect("writer task");

        assert_eq!(frame.frame_type, FrameType::TcpData);
        assert_eq!(frame.stream_id, 3);
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));
    }

    #[tokio::test]
    async fn reader_loop_dispatches_tcp_data_to_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let reader = tokio::spawn(tunnel_reader_loop(read_half, Arc::clone(&streams)));

        write_frame(
            &mut peer,
            FrameType::TcpData,
            5,
            0,
            Bytes::from_static(b"payload"),
        )
        .await
        .expect("write frame");
        drop(peer);

        let payload = timeout(Duration::from_secs(1), stream_rx.recv())
            .await
            .expect("receive payload timeout")
            .expect("receive payload");
        reader.await.expect("reader task");

        assert_eq!(payload, Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn reader_loop_removes_stream_on_tcp_close() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(7, stream_tx);
        let reader = tokio::spawn(tunnel_reader_loop(read_half, Arc::clone(&streams)));

        write_frame(&mut peer, FrameType::TcpClose, 7, 0, Bytes::new())
            .await
            .expect("write frame");
        drop(peer);
        reader.await.expect("reader task");

        assert!(!streams.lock().await.contains_key(&7));
    }

    #[tokio::test]
    async fn reader_loop_removes_stream_on_error() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(9, stream_tx);
        let reader = tokio::spawn(tunnel_reader_loop(read_half, Arc::clone(&streams)));

        write_frame(
            &mut peer,
            FrameType::ErrorFrame,
            9,
            0,
            Bytes::from_static(b"target connect failed"),
        )
        .await
        .expect("write frame");
        drop(peer);
        reader.await.expect("reader task");

        assert!(!streams.lock().await.contains_key(&9));
    }

    #[tokio::test]
    async fn reader_loop_ignores_unknown_tcp_data_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let reader = tokio::spawn(tunnel_reader_loop(read_half, Arc::clone(&streams)));

        write_frame(
            &mut peer,
            FrameType::TcpData,
            11,
            0,
            Bytes::from_static(b"orphaned payload"),
        )
        .await
        .expect("write frame");
        drop(peer);
        reader.await.expect("reader task");

        assert!(streams.lock().await.is_empty());
    }

    #[tokio::test]
    async fn close_stream_sends_tcp_close_without_dropping_inbound_dispatch() {
        let (writer_tx, mut writer_rx) = mpsc::channel(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(15, stream_tx);
        let closed = AtomicBool::new(false);

        close_stream(15, &writer_tx, &streams, &closed)
            .await
            .expect("close stream");

        let frame = writer_rx.recv().await.expect("TCP_CLOSE frame");
        assert_eq!(frame.frame_type, FrameType::TcpClose);
        assert_eq!(frame.stream_id, 15);
        assert!(streams.lock().await.contains_key(&15));

        streams
            .lock()
            .await
            .get(&15)
            .expect("stream tx")
            .send(Bytes::from_static(b"late response"))
            .await
            .expect("late response send");
        assert_eq!(
            stream_rx.recv().await,
            Some(Bytes::from_static(b"late response"))
        );
    }

    #[tokio::test]
    async fn writer_loop_clears_streams_on_physical_write_failure() {
        let (stream, peer) = duplex(1024);
        drop(peer);
        let (_read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (tx, rx) = mpsc::channel(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(17, stream_tx);
        let writer = tokio::spawn(tunnel_writer_loop(write_half, rx, Arc::clone(&streams)));

        tx.send(FrameCommand {
            frame_type: FrameType::TcpData,
            stream_id: 17,
            flags: 0,
            payload: Bytes::from_static(b"payload"),
        })
        .await
        .expect("send frame command");
        drop(tx);
        writer.await.expect("writer task");

        assert!(streams.lock().await.is_empty());
    }
}
