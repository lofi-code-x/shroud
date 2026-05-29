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
struct WriterChannels {
    control_tx: mpsc::Sender<FrameCommand>,
    data_tx: mpsc::Sender<FrameCommand>,
}

#[derive(Clone)]
pub struct TunnelPool {
    tunnels: Arc<Vec<Arc<TunnelManager>>>,
    max_streams_per_tunnel: usize,
}

#[derive(Clone)]
pub struct TunnelManager {
    inner: Arc<TunnelManagerInner>,
}

struct TunnelManagerInner {
    tunnel_id: usize,
    writer_tx: WriterChannels,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    next_stream_id: AtomicU64,
}

pub struct TunnelStreamHandle {
    tunnel_id: usize,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    opened_at: Instant,
    writer_tx: WriterChannels,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    inbound_rx: mpsc::Receiver<Bytes>,
    closed: Arc<AtomicBool>,
}

pub struct TunnelStreamReadHalf {
    inbound_rx: mpsc::Receiver<Bytes>,
}

#[derive(Clone)]
pub struct TunnelStreamWriteHalf {
    tunnel_id: usize,
    stream_id: u64,
    target_host: String,
    writer_tx: WriterChannels,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    closed: Arc<AtomicBool>,
}

impl TunnelPool {
    pub async fn connect(outbound: OutboundConfig, auth: ClientAuthConfig) -> Result<Self> {
        let tunnel_count = outbound.multiplex_tunnels.max(1);
        let mut tunnels = Vec::with_capacity(tunnel_count);

        for tunnel_id in 0..tunnel_count {
            let tunnel = TunnelManager::connect_with_id(tunnel_id, outbound.clone(), auth.clone())
                .await
                .with_context(|| {
                    format!("failed to connect persistent tunnel manager {tunnel_id}")
                })?;
            tunnels.push(Arc::new(tunnel));
        }

        info!(
            multiplex_tunnels = tunnel_count,
            max_streams_per_tunnel = outbound.max_streams_per_tunnel,
            "persistent tunnel pool opened"
        );

        Ok(Self {
            tunnels: Arc::new(tunnels),
            max_streams_per_tunnel: outbound.max_streams_per_tunnel.max(1),
        })
    }

    pub async fn open_tcp_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStreamHandle> {
        let tunnel = self
            .select_tunnel()
            .await
            .context("persistent tunnel pool is empty")?;
        tunnel.open_tcp_stream(target_host, target_port).await
    }

    async fn select_tunnel(&self) -> Option<Arc<TunnelManager>> {
        let mut least_under_limit: Option<(Arc<TunnelManager>, usize)> = None;
        let mut least_loaded: Option<(Arc<TunnelManager>, usize)> = None;

        for tunnel in self.tunnels.iter() {
            let active_streams = tunnel.active_streams().await;
            if active_streams < self.max_streams_per_tunnel
                && least_under_limit
                    .as_ref()
                    .map_or(true, |(_, best)| active_streams < *best)
            {
                least_under_limit = Some((Arc::clone(tunnel), active_streams));
            }

            if least_loaded
                .as_ref()
                .map_or(true, |(_, best)| active_streams < *best)
            {
                least_loaded = Some((Arc::clone(tunnel), active_streams));
            }
        }

        least_under_limit.or(least_loaded).map(|(tunnel, _)| tunnel)
    }
}

impl TunnelManager {
    pub async fn connect(outbound: OutboundConfig, auth: ClientAuthConfig) -> Result<Self> {
        Self::connect_with_id(0, outbound, auth).await
    }

    pub async fn connect_with_id(
        tunnel_id: usize,
        outbound: OutboundConfig,
        auth: ClientAuthConfig,
    ) -> Result<Self> {
        let tunnel = TunnelClient::new(outbound, auth);
        let stream = tunnel.open_persistent_tunnel_transport().await?;
        let (read_half, write_half) = split(stream);
        let (writer_tx, control_rx, data_rx) = writer_channels(WRITER_CHANNEL_CAPACITY);
        let streams = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(tunnel_writer_loop(
            tunnel_id,
            write_half,
            control_rx,
            data_rx,
            Arc::clone(&streams),
        ));
        tokio::spawn(tunnel_reader_loop(
            tunnel_id,
            read_half,
            Arc::clone(&streams),
        ));

        info!(tunnel_id, "persistent physical tunnel opened");

        Ok(Self {
            inner: Arc::new(TunnelManagerInner {
                tunnel_id,
                writer_tx,
                streams,
                next_stream_id: AtomicU64::new(1),
            }),
        })
    }

    pub fn tunnel_id(&self) -> usize {
        self.inner.tunnel_id
    }

    pub async fn active_streams(&self) -> usize {
        self.inner.streams.lock().await.len()
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
                tunnel_id = self.inner.tunnel_id,
                stream_id,
                target_host,
                target_port,
                active_streams_on_tunnel = streams.len(),
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
            self.inner.tunnel_id,
        )
        .await
        {
            let mut streams = self.inner.streams.lock().await;
            streams.remove(&stream_id);
            return Err(err).context("failed to queue TCP_CONNECT for persistent tunnel");
        }

        Ok(TunnelStreamHandle {
            tunnel_id: self.inner.tunnel_id,
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
    pub fn tunnel_id(&self) -> usize {
        self.tunnel_id
    }

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
                tunnel_id: self.tunnel_id,
                stream_id: self.stream_id,
                target_host: self.target_host,
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
            self.tunnel_id,
        )
        .await
    }

    pub async fn recv_data(&mut self) -> Option<Bytes> {
        self.inbound_rx.recv().await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(
            self.tunnel_id,
            self.stream_id,
            &self.writer_tx,
            &self.streams,
            &self.closed,
        )
        .await
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
            self.tunnel_id,
        )
        .await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(
            self.tunnel_id,
            self.stream_id,
            &self.writer_tx,
            &self.streams,
            &self.closed,
        )
        .await
    }

    pub async fn cleanup_local(&self) -> usize {
        self.closed.store(true, Ordering::Release);
        let mut streams = self.streams.lock().await;
        streams.remove(&self.stream_id);
        streams.len()
    }

    pub fn tunnel_id(&self) -> usize {
        self.tunnel_id
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }
}

async fn close_stream(
    tunnel_id: usize,
    stream_id: u64,
    writer_tx: &WriterChannels,
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
        tunnel_id,
    )
    .await
    {
        streams.lock().await.remove(&stream_id);
        return Err(err).context("failed to queue TCP_CLOSE for persistent tunnel");
    }

    Ok(())
}

async fn tunnel_writer_loop(
    tunnel_id: usize,
    mut write_half: WriteHalf<TunnelStream>,
    mut control_rx: mpsc::Receiver<FrameCommand>,
    mut data_rx: mpsc::Receiver<FrameCommand>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
) {
    while let Some(cmd) = recv_writer_command(&mut control_rx, &mut data_rx).await {
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
                tunnel_id,
                error = %err,
                active_streams_on_tunnel = active_streams,
                "persistent physical tunnel closed after writer failure"
            );
            break;
        }
    }

    debug!(tunnel_id, "persistent tunnel writer finished");
}

async fn tunnel_reader_loop(
    tunnel_id: usize,
    mut read_half: ReadHalf<TunnelStream>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
) {
    loop {
        let frame = match read_frame(&mut read_half).await {
            Ok(frame) => frame,
            Err(err) => {
                let active_streams = clear_streams(&streams).await;
                warn!(
                    tunnel_id,
                    error = %err,
                    active_streams_on_tunnel = active_streams,
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
                            tunnel_id,
                            stream_id = frame.stream_id,
                            active_streams_on_tunnel = streams.len(),
                            "logical TCP stream removed after inbound receiver closed"
                        );
                    }
                } else {
                    debug!(
                        tunnel_id,
                        stream_id = frame.stream_id,
                        "dropping TCP_DATA for unknown stream"
                    );
                }
            }
            FrameType::TcpClose => {
                let mut streams = streams.lock().await;
                streams.remove(&frame.stream_id);
                debug!(
                    tunnel_id,
                    stream_id = frame.stream_id,
                    active_streams_on_tunnel = streams.len(),
                    "logical TCP stream closed by peer"
                );
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                let mut streams = streams.lock().await;
                streams.remove(&frame.stream_id);
                debug!(
                    tunnel_id,
                    stream_id = frame.stream_id,
                    active_streams_on_tunnel = streams.len(),
                    error = %message,
                    "logical TCP stream failed by peer"
                );
            }
            FrameType::Pong => {
                debug!(tunnel_id, "persistent tunnel PONG received");
            }
            FrameType::TcpConnect => {
                debug!(
                    tunnel_id,
                    stream_id = frame.stream_id,
                    flags = frame.flags,
                    "persistent tunnel TCP_CONNECT response received"
                );
            }
            other => {
                debug!(
                    tunnel_id,
                    stream_id = frame.stream_id,
                    frame_type = %other,
                    "ignoring unsupported frame on persistent tunnel"
                );
            }
        }
    }
}

async fn send_writer_command(
    writer_tx: &WriterChannels,
    cmd: FrameCommand,
    operation: &'static str,
    tunnel_id: usize,
) -> Result<()> {
    let frame_type = cmd.frame_type;
    let stream_id = cmd.stream_id;
    let payload_len = cmd.payload.len();
    let started = Instant::now();

    writer_tx
        .sender_for(frame_type)
        .send(cmd)
        .await
        .with_context(|| format!("failed to queue {operation} for persistent tunnel"))?;

    let wait = started.elapsed();
    if wait >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
        debug!(
            tunnel_id,
            stream_id,
            frame_type = %frame_type,
            payload_len,
            writer_channel_send_wait_ms = elapsed_millis(wait),
            "persistent tunnel writer channel send waited"
        );
    }

    Ok(())
}

fn writer_channels(
    capacity: usize,
) -> (
    WriterChannels,
    mpsc::Receiver<FrameCommand>,
    mpsc::Receiver<FrameCommand>,
) {
    let (control_tx, control_rx) = mpsc::channel(capacity);
    let (data_tx, data_rx) = mpsc::channel(capacity);
    (
        WriterChannels {
            control_tx,
            data_tx,
        },
        control_rx,
        data_rx,
    )
}

impl WriterChannels {
    fn sender_for(&self, frame_type: FrameType) -> &mpsc::Sender<FrameCommand> {
        if is_control_frame(frame_type) {
            &self.control_tx
        } else {
            &self.data_tx
        }
    }
}

fn is_control_frame(frame_type: FrameType) -> bool {
    !matches!(frame_type, FrameType::TcpData)
}

async fn recv_writer_command(
    control_rx: &mut mpsc::Receiver<FrameCommand>,
    data_rx: &mut mpsc::Receiver<FrameCommand>,
) -> Option<FrameCommand> {
    let mut control_open = true;
    let mut data_open = true;

    loop {
        if !control_open && !data_open {
            return None;
        }

        tokio::select! {
            biased;

            cmd = control_rx.recv(), if control_open => {
                if let Some(cmd) = cmd {
                    return Some(cmd);
                }
                control_open = false;
            }
            cmd = data_rx.recv(), if data_open => {
                if let Some(cmd) = cmd {
                    return Some(cmd);
                }
                data_open = false;
            }
        }
    }
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
        let (tx, control_rx, data_rx) = writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let writer = tokio::spawn(tunnel_writer_loop(
            0, write_half, control_rx, data_rx, streams,
        ));

        tx.data_tx
            .send(FrameCommand {
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
    async fn writer_command_receive_prioritizes_control_over_data() {
        let (tx, mut control_rx, mut data_rx) = writer_channels(2);

        tx.data_tx
            .send(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 3,
                flags: 0,
                payload: Bytes::from_static(b"data"),
            })
            .await
            .expect("send data frame command");
        tx.control_tx
            .send(FrameCommand {
                frame_type: FrameType::TcpClose,
                stream_id: 3,
                flags: 0,
                payload: Bytes::new(),
            })
            .await
            .expect("send control frame command");

        let frame = recv_writer_command(&mut control_rx, &mut data_rx)
            .await
            .expect("writer command");
        assert_eq!(frame.frame_type, FrameType::TcpClose);
    }

    #[tokio::test]
    async fn reader_loop_dispatches_tcp_data_to_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let reader = tokio::spawn(tunnel_reader_loop(0, read_half, Arc::clone(&streams)));

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
        let reader = tokio::spawn(tunnel_reader_loop(0, read_half, Arc::clone(&streams)));

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
        let reader = tokio::spawn(tunnel_reader_loop(0, read_half, Arc::clone(&streams)));

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
        let reader = tokio::spawn(tunnel_reader_loop(0, read_half, Arc::clone(&streams)));

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
        let (writer_tx, mut control_rx, _data_rx) = writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(15, stream_tx);
        let closed = AtomicBool::new(false);

        close_stream(0, 15, &writer_tx, &streams, &closed)
            .await
            .expect("close stream");

        let frame = control_rx.recv().await.expect("TCP_CLOSE frame");
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
        let (tx, control_rx, data_rx) = writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(17, stream_tx);
        let writer = tokio::spawn(tunnel_writer_loop(
            0,
            write_half,
            control_rx,
            data_rx,
            Arc::clone(&streams),
        ));

        tx.data_tx
            .send(FrameCommand {
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
