use crate::tunnel::{TunnelClient, TunnelStream};
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::config::{ClientAuthConfig, OutboundConfig};
use shroud_core::protocol::{
    FrameCommand, FrameType, encode_tcp_connect_payload, read_frame, write_frame,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{ReadHalf, WriteHalf, split};
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{debug, info, warn};

const WRITER_CHANNEL_CAPACITY: usize = 128;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD: Duration = Duration::from_millis(1);
const TCP_CONNECT_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const DATA_FRAMES_BEFORE_CONTROL_CHECK: usize = 8;
const CONNECT_OK_FLAG: u16 = 0x0001;

type StreamTx = mpsc::Sender<StreamEvent>;

#[derive(Debug, PartialEq, Eq)]
enum StreamEvent {
    Connected,
    Data(Bytes),
    RemoteClosed,
    Error(String),
}

#[derive(Clone)]
struct WriterChannels {
    control_tx: mpsc::Sender<FrameCommand>,
    data_tx: mpsc::Sender<FrameCommand>,
    recent_writer_wait_ms: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelState {
    Connecting,
    Connected,
    Disconnected,
}

impl TunnelState {
    fn as_u8(self) -> u8 {
        match self {
            Self::Connecting => 0,
            Self::Connected => 1,
            Self::Disconnected => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Connected,
            2 => Self::Disconnected,
            _ => Self::Connecting,
        }
    }
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
    tunnel: TunnelClient,
    writer_tx: Mutex<Option<WriterChannels>>,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    next_stream_id: AtomicU64,
    state: AtomicU8,
    generation: AtomicU64,
    reconnecting: AtomicBool,
    recent_writer_wait_ms: Arc<AtomicU64>,
    last_pong_at_ms: AtomicU64,
    keepalive_interval: Duration,
    keepalive_timeout: Duration,
    reconnect_enabled: bool,
}

pub struct TunnelStreamHandle {
    tunnel_id: usize,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    opened_at: Instant,
    writer_tx: WriterChannels,
    streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    inbound_rx: mpsc::Receiver<StreamEvent>,
    closed: Arc<AtomicBool>,
}

pub struct TunnelStreamReadHalf {
    inbound_rx: mpsc::Receiver<StreamEvent>,
}

#[derive(Clone)]
pub struct TunnelStreamWriteHalf {
    tunnel_id: usize,
    stream_id: u64,
    target_host: String,
    target_port: u16,
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
            .context("persistent tunnel pool has no connected tunnels")?;
        tunnel.open_tcp_stream(target_host, target_port).await
    }

    async fn select_tunnel(&self) -> Option<Arc<TunnelManager>> {
        let mut least_under_limit: Option<TunnelSelection> = None;
        let mut least_loaded: Option<TunnelSelection> = None;

        for tunnel in self.tunnels.iter() {
            if tunnel.state() != TunnelState::Connected {
                continue;
            }

            let active_streams = tunnel.active_streams().await;
            let recent_writer_wait_ms = tunnel.recent_writer_wait_ms();
            let score = tunnel_pressure_score(active_streams, recent_writer_wait_ms);
            let selection = TunnelSelection {
                tunnel: Arc::clone(tunnel),
                active_streams,
                recent_writer_wait_ms,
                score,
            };

            if active_streams < self.max_streams_per_tunnel
                && least_under_limit
                    .as_ref()
                    .map_or(true, |best| selection.score < best.score)
            {
                least_under_limit = Some(selection.clone());
            }

            if least_loaded
                .as_ref()
                .map_or(true, |best| selection.score < best.score)
            {
                least_loaded = Some(selection);
            }
        }

        let selected = least_under_limit.or(least_loaded)?;
        debug!(
            selected_tunnel_id = selected.tunnel.tunnel_id(),
            active_streams = selected.active_streams,
            recent_writer_wait_ms = selected.recent_writer_wait_ms,
            score = selected.score,
            "selected persistent tunnel for new stream"
        );
        Some(selected.tunnel)
    }
}

#[derive(Clone)]
struct TunnelSelection {
    tunnel: Arc<TunnelManager>,
    active_streams: usize,
    recent_writer_wait_ms: u64,
    score: u64,
}

fn tunnel_pressure_score(active_streams: usize, recent_writer_wait_ms: u64) -> u64 {
    (active_streams as u64)
        .saturating_mul(100)
        .saturating_add(recent_writer_wait_ms)
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
        let keepalive_interval = Duration::from_secs(outbound.keepalive_interval_secs);
        let keepalive_timeout = Duration::from_secs(outbound.keepalive_timeout_secs);
        let tunnel = TunnelClient::new(outbound, auth);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = Arc::new(TunnelManagerInner {
            tunnel_id,
            tunnel,
            writer_tx: Mutex::new(None),
            streams,
            next_stream_id: AtomicU64::new(1),
            state: AtomicU8::new(TunnelState::Connecting.as_u8()),
            generation: AtomicU64::new(0),
            reconnecting: AtomicBool::new(false),
            recent_writer_wait_ms: Arc::new(AtomicU64::new(0)),
            last_pong_at_ms: AtomicU64::new(now_millis()),
            keepalive_interval,
            keepalive_timeout,
            reconnect_enabled: true,
        });

        establish_physical_tunnel(Arc::clone(&inner))
            .await
            .with_context(|| format!("failed to open persistent physical tunnel {tunnel_id}"))?;
        tokio::spawn(keepalive_loop(Arc::clone(&inner)));

        info!(tunnel_id, "persistent physical tunnel opened");

        Ok(Self { inner })
    }

    pub fn tunnel_id(&self) -> usize {
        self.inner.tunnel_id
    }

    pub async fn active_streams(&self) -> usize {
        self.inner.streams.lock().await.len()
    }

    fn state(&self) -> TunnelState {
        TunnelState::from_u8(self.inner.state.load(Ordering::Acquire))
    }

    fn recent_writer_wait_ms(&self) -> u64 {
        self.inner.recent_writer_wait_ms.load(Ordering::Relaxed)
    }

    pub async fn open_tcp_stream(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<TunnelStreamHandle> {
        let stream_id = self.inner.next_stream_id.fetch_add(2, Ordering::Relaxed);
        let payload = encode_tcp_connect_payload(target_host, target_port)
            .map_err(|err| anyhow!("failed to encode TCP_CONNECT payload: {err}"))?;
        if self.state() != TunnelState::Connected {
            bail!(
                "persistent tunnel {} is not connected",
                self.inner.tunnel_id
            );
        }

        let writer_tx = self.inner.current_writer_tx().await.with_context(|| {
            format!(
                "persistent tunnel {} is not connected",
                self.inner.tunnel_id
            )
        })?;
        let (inbound_tx, mut inbound_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

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
            &writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpConnect,
                stream_id,
                flags: 0,
                payload,
            },
            "TCP_CONNECT",
            self.inner.tunnel_id,
            Some(target_host),
            Some(target_port),
        )
        .await
        {
            let mut streams = self.inner.streams.lock().await;
            streams.remove(&stream_id);
            return Err(err).context("failed to queue TCP_CONNECT for persistent tunnel");
        }

        wait_for_connect_response(
            self.inner.tunnel_id,
            stream_id,
            target_host,
            target_port,
            &mut inbound_rx,
            &self.inner.streams,
        )
        .await?;

        Ok(TunnelStreamHandle {
            tunnel_id: self.inner.tunnel_id,
            stream_id,
            target_host: target_host.to_owned(),
            target_port,
            opened_at: Instant::now(),
            writer_tx,
            streams: Arc::clone(&self.inner.streams),
            inbound_rx,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl TunnelManagerInner {
    async fn current_writer_tx(&self) -> Option<WriterChannels> {
        self.writer_tx.lock().await.clone()
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn set_state(&self, state: TunnelState) {
        self.state.store(state.as_u8(), Ordering::Release);
    }
}

async fn establish_physical_tunnel(inner: Arc<TunnelManagerInner>) -> Result<()> {
    inner.set_state(TunnelState::Connecting);
    let stream = inner.tunnel.open_persistent_tunnel_transport().await?;
    let (read_half, write_half) = split(stream);
    let generation = inner.generation.fetch_add(1, Ordering::AcqRel) + 1;
    let (writer_tx, control_rx, data_rx) = writer_channels(
        WRITER_CHANNEL_CAPACITY,
        Arc::clone(&inner.recent_writer_wait_ms),
    );

    {
        let mut current = inner.writer_tx.lock().await;
        *current = Some(writer_tx);
    }

    inner.last_pong_at_ms.store(now_millis(), Ordering::Release);
    inner.set_state(TunnelState::Connected);

    tokio::spawn(tunnel_writer_loop(
        Arc::clone(&inner),
        generation,
        write_half,
        control_rx,
        data_rx,
    ));
    tokio::spawn(tunnel_reader_loop(
        Arc::clone(&inner),
        generation,
        read_half,
    ));

    info!(
        tunnel_id = inner.tunnel_id,
        generation, "persistent physical tunnel connected"
    );
    Ok(())
}

async fn mark_tunnel_broken(
    inner: Arc<TunnelManagerInner>,
    generation: u64,
    close_reason: &'static str,
    schedule_reconnect: bool,
) {
    if inner.generation() != generation {
        return;
    }

    let previous = TunnelState::from_u8(
        inner
            .state
            .swap(TunnelState::Disconnected.as_u8(), Ordering::AcqRel),
    );
    if previous == TunnelState::Disconnected {
        return;
    }

    {
        let mut writer_tx = inner.writer_tx.lock().await;
        *writer_tx = None;
    }

    let active_streams = clear_streams(&inner.streams).await;
    warn!(
        tunnel_id = inner.tunnel_id,
        generation,
        active_streams_on_tunnel = active_streams,
        close_reason,
        "persistent physical tunnel marked disconnected"
    );

    if schedule_reconnect && !inner.reconnecting.swap(true, Ordering::AcqRel) {
        spawn_reconnect_loop(inner);
    }
}

fn spawn_reconnect_loop(inner: Arc<TunnelManagerInner>) {
    tokio::spawn(async move {
        loop {
            sleep(TUNNEL_RECONNECT_DELAY).await;
            match establish_physical_tunnel(Arc::clone(&inner)).await {
                Ok(()) => {
                    inner.reconnecting.store(false, Ordering::Release);
                    info!(
                        tunnel_id = inner.tunnel_id,
                        "persistent physical tunnel reconnected"
                    );
                    return;
                }
                Err(err) => {
                    inner.set_state(TunnelState::Disconnected);
                    warn!(
                        tunnel_id = inner.tunnel_id,
                        error = %err,
                        "persistent physical tunnel reconnect failed"
                    );
                }
            }
        }
    });
}

async fn keepalive_loop(inner: Arc<TunnelManagerInner>) {
    loop {
        sleep(inner.keepalive_interval).await;
        if TunnelState::from_u8(inner.state.load(Ordering::Acquire)) != TunnelState::Connected {
            continue;
        }

        let Some(writer_tx) = inner.current_writer_tx().await else {
            continue;
        };
        let ping_sent_at_ms = now_millis();
        if send_writer_command(
            &writer_tx,
            FrameCommand {
                frame_type: FrameType::Ping,
                stream_id: 0,
                flags: 0,
                payload: Bytes::new(),
            },
            "PING",
            inner.tunnel_id,
            None,
            None,
        )
        .await
        .is_err()
        {
            mark_tunnel_broken(
                Arc::clone(&inner),
                inner.generation(),
                "keepalive_send_failed",
                true,
            )
            .await;
            continue;
        }

        sleep(inner.keepalive_timeout).await;
        if TunnelState::from_u8(inner.state.load(Ordering::Acquire)) == TunnelState::Connected
            && inner.last_pong_at_ms.load(Ordering::Acquire) < ping_sent_at_ms
        {
            warn!(
                tunnel_id = inner.tunnel_id,
                keepalive_timeout_ms = elapsed_millis(inner.keepalive_timeout),
                "persistent tunnel keepalive timed out"
            );
            mark_tunnel_broken(
                Arc::clone(&inner),
                inner.generation(),
                "keepalive_timeout",
                true,
            )
            .await;
        }
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
                target_port: self.target_port,
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
            Some(&self.target_host),
            Some(self.target_port),
        )
        .await
    }

    pub async fn recv_data(&mut self) -> Option<Bytes> {
        recv_stream_data(&mut self.inbound_rx).await
    }

    pub async fn close(&self) -> Result<()> {
        close_stream(
            self.tunnel_id,
            self.stream_id,
            &self.writer_tx,
            &self.streams,
            &self.closed,
            Some(&self.target_host),
            Some(self.target_port),
        )
        .await
    }
}

impl TunnelStreamReadHalf {
    pub async fn recv_data(&mut self) -> Option<Bytes> {
        recv_stream_data(&mut self.inbound_rx).await
    }
}

async fn wait_for_connect_response(
    tunnel_id: usize,
    stream_id: u64,
    target_host: &str,
    target_port: u16,
    inbound_rx: &mut mpsc::Receiver<StreamEvent>,
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
) -> Result<()> {
    let event = tokio::time::timeout(TCP_CONNECT_REPLY_TIMEOUT, inbound_rx.recv())
        .await
        .with_context(|| {
            format!("timed out waiting for TCP_CONNECT reply for {target_host}:{target_port}")
        })?;

    match event {
        Some(StreamEvent::Connected) => {
            debug!(
                tunnel_id,
                stream_id, target_host, target_port, "logical TCP stream connected"
            );
            Ok(())
        }
        Some(StreamEvent::Error(message)) => {
            streams.lock().await.remove(&stream_id);
            bail!("server refused TCP_CONNECT: {message}");
        }
        Some(StreamEvent::RemoteClosed) => {
            streams.lock().await.remove(&stream_id);
            bail!("server closed stream before TCP_CONNECT completed");
        }
        Some(StreamEvent::Data(_)) => {
            streams.lock().await.remove(&stream_id);
            bail!("received TCP_DATA before TCP_CONNECT completed");
        }
        None => {
            streams.lock().await.remove(&stream_id);
            bail!("persistent tunnel closed before TCP_CONNECT completed");
        }
    }
}

async fn recv_stream_data(inbound_rx: &mut mpsc::Receiver<StreamEvent>) -> Option<Bytes> {
    while let Some(event) = inbound_rx.recv().await {
        match event {
            StreamEvent::Data(bytes) => return Some(bytes),
            StreamEvent::Connected => {}
            StreamEvent::RemoteClosed => return None,
            StreamEvent::Error(message) => {
                debug!(error = %message, "logical TCP stream failed by peer");
                return None;
            }
        }
    }

    None
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
            Some(&self.target_host),
            Some(self.target_port),
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
            Some(&self.target_host),
            Some(self.target_port),
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

    pub fn target_port(&self) -> u16 {
        self.target_port
    }
}

async fn close_stream(
    tunnel_id: usize,
    stream_id: u64,
    writer_tx: &WriterChannels,
    streams: &Arc<Mutex<HashMap<u64, StreamTx>>>,
    closed: &AtomicBool,
    target_host: Option<&str>,
    target_port: Option<u16>,
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
        target_host,
        target_port,
    )
    .await
    {
        streams.lock().await.remove(&stream_id);
        return Err(err).context("failed to queue TCP_CLOSE for persistent tunnel");
    }

    debug!(
        tunnel_id,
        stream_id,
        target_host = %target_host.unwrap_or("<unknown>"),
        target_port = target_port.unwrap_or_default(),
        close_reason = "client_closed",
        "logical TCP stream close queued"
    );

    Ok(())
}

async fn tunnel_writer_loop(
    inner: Arc<TunnelManagerInner>,
    generation: u64,
    mut write_half: WriteHalf<TunnelStream>,
    mut control_rx: mpsc::Receiver<FrameCommand>,
    mut data_rx: mpsc::Receiver<FrameCommand>,
) {
    let mut data_frames_since_control_check = 0usize;
    while let Some(cmd) = recv_writer_command(
        &mut control_rx,
        &mut data_rx,
        &mut data_frames_since_control_check,
    )
    .await
    {
        if let Err(err) = write_frame(
            &mut write_half,
            cmd.frame_type,
            cmd.stream_id,
            cmd.flags,
            cmd.payload,
        )
        .await
        {
            warn!(
                tunnel_id = inner.tunnel_id,
                generation,
                error = %err,
                "persistent physical tunnel closed after writer failure"
            );
            let reconnect_enabled = inner.reconnect_enabled;
            mark_tunnel_broken(
                Arc::clone(&inner),
                generation,
                "writer_failed",
                reconnect_enabled,
            )
            .await;
            break;
        }
    }

    debug!(
        tunnel_id = inner.tunnel_id,
        generation, "persistent tunnel writer finished"
    );
}

async fn tunnel_reader_loop(
    inner: Arc<TunnelManagerInner>,
    generation: u64,
    mut read_half: ReadHalf<TunnelStream>,
) {
    loop {
        let frame = match read_frame(&mut read_half).await {
            Ok(frame) => frame,
            Err(err) => {
                warn!(
                    tunnel_id = inner.tunnel_id,
                    generation,
                    error = %err,
                    "persistent physical tunnel closed after reader failure"
                );
                let reconnect_enabled = inner.reconnect_enabled;
                mark_tunnel_broken(
                    Arc::clone(&inner),
                    generation,
                    "reader_failed",
                    reconnect_enabled,
                )
                .await;
                break;
            }
        };

        match frame.frame_type {
            FrameType::TcpData => {
                let tx = {
                    let streams = inner.streams.lock().await;
                    streams.get(&frame.stream_id).cloned()
                };

                if let Some(tx) = tx {
                    if tx.send(StreamEvent::Data(frame.payload)).await.is_err() {
                        let mut streams = inner.streams.lock().await;
                        streams.remove(&frame.stream_id);
                        debug!(
                            tunnel_id = inner.tunnel_id,
                            stream_id = frame.stream_id,
                            active_streams_on_tunnel = streams.len(),
                            "logical TCP stream removed after inbound receiver closed"
                        );
                    }
                } else {
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        "dropping TCP_DATA for unknown stream"
                    );
                }
            }
            FrameType::TcpClose => {
                let tx = {
                    let mut streams = inner.streams.lock().await;
                    let tx = streams.remove(&frame.stream_id);
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        active_streams_on_tunnel = streams.len(),
                        close_reason = "remote_closed",
                        "logical TCP stream closed by peer"
                    );
                    tx
                };

                if let Some(tx) = tx {
                    let _ = tx.send(StreamEvent::RemoteClosed).await;
                }
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                let tx = {
                    let mut streams = inner.streams.lock().await;
                    let tx = streams.remove(&frame.stream_id);
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        active_streams_on_tunnel = streams.len(),
                        error = %message,
                        close_reason = "protocol_error",
                        "logical TCP stream failed by peer"
                    );
                    tx
                };

                if let Some(tx) = tx {
                    let _ = tx.send(StreamEvent::Error(message)).await;
                }
            }
            FrameType::TcpConnect => {
                let is_connected = (frame.flags & CONNECT_OK_FLAG) != 0;
                let tx = if is_connected {
                    let streams = inner.streams.lock().await;
                    streams.get(&frame.stream_id).cloned()
                } else {
                    let mut streams = inner.streams.lock().await;
                    streams.remove(&frame.stream_id)
                };

                let event = if is_connected {
                    StreamEvent::Connected
                } else {
                    StreamEvent::Error(format!(
                        "server returned TCP_CONNECT without success flag; flags={}",
                        frame.flags
                    ))
                };

                if let Some(tx) = tx {
                    if tx.send(event).await.is_err() {
                        let mut streams = inner.streams.lock().await;
                        streams.remove(&frame.stream_id);
                        debug!(
                            tunnel_id = inner.tunnel_id,
                            stream_id = frame.stream_id,
                            active_streams_on_tunnel = streams.len(),
                            "logical TCP stream removed after connect receiver closed"
                        );
                    }
                } else {
                    debug!(
                        tunnel_id = inner.tunnel_id,
                        stream_id = frame.stream_id,
                        flags = frame.flags,
                        "dropping TCP_CONNECT response for unknown stream"
                    );
                }
                debug!(
                    tunnel_id = inner.tunnel_id,
                    stream_id = frame.stream_id,
                    flags = frame.flags,
                    "persistent tunnel TCP_CONNECT response received"
                );
            }
            FrameType::Pong => {
                inner.last_pong_at_ms.store(now_millis(), Ordering::Release);
                debug!(
                    tunnel_id = inner.tunnel_id,
                    generation, "persistent tunnel PONG received"
                );
            }
            other => {
                debug!(
                    tunnel_id = inner.tunnel_id,
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
    target_host: Option<&str>,
    target_port: Option<u16>,
) -> Result<()> {
    let frame_type = cmd.frame_type;
    let stream_id = cmd.stream_id;
    let payload_len = cmd.payload.len();
    let sender = writer_tx.sender_for(frame_type);
    let queue = writer_queue_metrics(sender);
    let started = Instant::now();

    sender
        .send(cmd)
        .await
        .with_context(|| format!("failed to queue {operation} for persistent tunnel"))?;

    let wait = started.elapsed();
    record_recent_writer_wait(&writer_tx.recent_writer_wait_ms, elapsed_millis(wait));
    if wait >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
        debug!(
            tunnel_id,
            stream_id,
            target_host = %target_host.unwrap_or("<unknown>"),
            target_port = target_port.unwrap_or_default(),
            frame_type = %frame_type,
            payload_len,
            writer_queue_capacity = queue.capacity,
            writer_queue_available = queue.available,
            writer_queue_depth = queue.depth,
            writer_channel_send_wait_ms = elapsed_millis(wait),
            "persistent tunnel writer channel send waited"
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct WriterQueueMetrics {
    capacity: usize,
    available: usize,
    depth: usize,
}

fn writer_queue_metrics(sender: &mpsc::Sender<FrameCommand>) -> WriterQueueMetrics {
    let capacity = sender.max_capacity();
    let available = sender.capacity();
    WriterQueueMetrics {
        capacity,
        available,
        depth: capacity.saturating_sub(available),
    }
}

fn writer_channels(
    capacity: usize,
    recent_writer_wait_ms: Arc<AtomicU64>,
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
            recent_writer_wait_ms,
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
    data_frames_since_control_check: &mut usize,
) -> Option<FrameCommand> {
    let mut control_open = true;
    let mut data_open = true;

    loop {
        if !control_open && !data_open {
            return None;
        }

        if control_open {
            match control_rx.try_recv() {
                Ok(cmd) => {
                    *data_frames_since_control_check = 0;
                    return Some(cmd);
                }
                Err(mpsc::error::TryRecvError::Disconnected) => control_open = false,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if *data_frames_since_control_check >= DATA_FRAMES_BEFORE_CONTROL_CHECK {
            *data_frames_since_control_check = 0;
            tokio::task::yield_now().await;
            if control_open {
                match control_rx.try_recv() {
                    Ok(cmd) => return Some(cmd),
                    Err(mpsc::error::TryRecvError::Disconnected) => control_open = false,
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }
            }
        }

        tokio::select! {
            biased;

            cmd = control_rx.recv(), if control_open => {
                if let Some(cmd) = cmd {
                    *data_frames_since_control_check = 0;
                    return Some(cmd);
                }
                control_open = false;
            }
            cmd = data_rx.recv(), if data_open => {
                if let Some(cmd) = cmd {
                    *data_frames_since_control_check =
                        (*data_frames_since_control_check).saturating_add(1);
                    return Some(cmd);
                }
                data_open = false;
            }
        }
    }
}

fn record_recent_writer_wait(recent_writer_wait_ms: &AtomicU64, wait_ms: u64) {
    let mut current = recent_writer_wait_ms.load(Ordering::Relaxed);
    loop {
        let next = current
            .saturating_mul(7)
            .saturating_add(wait_ms)
            .saturating_div(8);
        match recent_writer_wait_ms.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
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

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{read_frame, write_frame};
    use std::time::Duration;
    use tokio::io::duplex;
    use tokio::time::timeout;

    fn test_writer_channels(
        capacity: usize,
    ) -> (
        WriterChannels,
        mpsc::Receiver<FrameCommand>,
        mpsc::Receiver<FrameCommand>,
    ) {
        writer_channels(capacity, Arc::new(AtomicU64::new(0)))
    }

    fn test_inner(
        tunnel_id: usize,
        writer_tx: Option<WriterChannels>,
        streams: Arc<Mutex<HashMap<u64, StreamTx>>>,
    ) -> Arc<TunnelManagerInner> {
        Arc::new(TunnelManagerInner {
            tunnel_id,
            tunnel: TunnelClient::new(OutboundConfig::default(), ClientAuthConfig::default()),
            writer_tx: Mutex::new(writer_tx),
            streams,
            next_stream_id: AtomicU64::new(1),
            state: AtomicU8::new(TunnelState::Connected.as_u8()),
            generation: AtomicU64::new(1),
            reconnecting: AtomicBool::new(false),
            recent_writer_wait_ms: Arc::new(AtomicU64::new(0)),
            last_pong_at_ms: AtomicU64::new(now_millis()),
            keepalive_interval: Duration::from_secs(20),
            keepalive_timeout: Duration::from_secs(10),
            reconnect_enabled: false,
        })
    }

    async fn test_manager_with_load(
        tunnel_id: usize,
        state: TunnelState,
        active_streams: usize,
        recent_writer_wait_ms: u64,
    ) -> Arc<TunnelManager> {
        let streams = Arc::new(Mutex::new(HashMap::new()));
        for stream_id in 0..active_streams as u64 {
            let (tx, _rx) = mpsc::channel(1);
            streams.lock().await.insert(stream_id * 2 + 1, tx);
        }
        let inner = test_inner(tunnel_id, None, streams);
        inner.state.store(state.as_u8(), Ordering::Release);
        inner
            .recent_writer_wait_ms
            .store(recent_writer_wait_ms, Ordering::Release);
        Arc::new(TunnelManager { inner })
    }

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
        let (tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, None, Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            inner, 1, write_half, control_rx, data_rx,
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
        let (tx, mut control_rx, mut data_rx) = test_writer_channels(2);

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

        let mut data_frames_since_control_check = 0;
        let frame = recv_writer_command(
            &mut control_rx,
            &mut data_rx,
            &mut data_frames_since_control_check,
        )
        .await
        .expect("writer command");
        assert_eq!(frame.frame_type, FrameType::TcpClose);
    }

    #[tokio::test]
    async fn tunnel_pool_selects_by_pressure_score() {
        let high_pressure = test_manager_with_load(0, TunnelState::Connected, 1, 1_000).await;
        let lower_score = test_manager_with_load(1, TunnelState::Connected, 3, 0).await;
        let pool = TunnelPool {
            tunnels: Arc::new(vec![Arc::clone(&high_pressure), Arc::clone(&lower_score)]),
            max_streams_per_tunnel: 16,
        };

        let selected = pool.select_tunnel().await.expect("selected tunnel");

        assert_eq!(selected.tunnel_id(), 1);
    }

    #[tokio::test]
    async fn tunnel_pool_excludes_disconnected_tunnels() {
        let disconnected = test_manager_with_load(0, TunnelState::Disconnected, 0, 0).await;
        let connected = test_manager_with_load(1, TunnelState::Connected, 8, 0).await;
        let pool = TunnelPool {
            tunnels: Arc::new(vec![Arc::clone(&disconnected), Arc::clone(&connected)]),
            max_streams_per_tunnel: 16,
        };

        let selected = pool.select_tunnel().await.expect("selected tunnel");

        assert_eq!(selected.tunnel_id(), 1);
    }

    #[tokio::test]
    async fn marking_tunnel_broken_clears_streams_and_disconnects() {
        let (writer_tx, _control_rx, _data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(19, stream_tx);
        let inner = test_inner(0, Some(writer_tx), Arc::clone(&streams));

        mark_tunnel_broken(Arc::clone(&inner), 1, "test_failure", false).await;

        assert_eq!(
            TunnelState::from_u8(inner.state.load(Ordering::Acquire)),
            TunnelState::Disconnected
        );
        assert!(inner.writer_tx.lock().await.is_none());
        assert!(streams.lock().await.is_empty());
    }

    #[tokio::test]
    async fn reader_loop_dispatches_tcp_data_to_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

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

        assert_eq!(payload, StreamEvent::Data(Bytes::from_static(b"payload")));
    }

    #[tokio::test]
    async fn reader_loop_dispatches_tcp_connect_success_to_stream() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

        write_frame(
            &mut peer,
            FrameType::TcpConnect,
            5,
            CONNECT_OK_FLAG,
            Bytes::new(),
        )
        .await
        .expect("write frame");

        let event = timeout(Duration::from_secs(1), stream_rx.recv())
            .await
            .expect("receive connect event timeout")
            .expect("receive connect event");

        assert_eq!(event, StreamEvent::Connected);
        assert!(streams.lock().await.contains_key(&5));

        drop(peer);
        reader.await.expect("reader task");
    }

    #[tokio::test]
    async fn open_tcp_stream_waits_for_tcp_connect_success() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (writer_tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, Some(writer_tx.clone()), Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            Arc::clone(&inner),
            1,
            write_half,
            control_rx,
            data_rx,
        ));
        let reader = tokio::spawn(tunnel_reader_loop(Arc::clone(&inner), 1, read_half));
        let manager = TunnelManager { inner };
        drop(writer_tx);
        let mut open =
            tokio::spawn(async move { manager.open_tcp_stream("example.com", 443).await });

        let connect = timeout(Duration::from_secs(1), read_frame(&mut peer))
            .await
            .expect("read TCP_CONNECT timeout")
            .expect("read TCP_CONNECT");
        assert_eq!(connect.frame_type, FrameType::TcpConnect);
        assert_eq!(connect.stream_id, 1);

        assert!(
            timeout(Duration::from_millis(50), &mut open).await.is_err(),
            "open_tcp_stream returned before TCP_CONNECT response"
        );

        write_frame(
            &mut peer,
            FrameType::TcpConnect,
            connect.stream_id,
            CONNECT_OK_FLAG,
            Bytes::new(),
        )
        .await
        .expect("write TCP_CONNECT OK");

        let handle = timeout(Duration::from_secs(1), open)
            .await
            .expect("open stream timeout")
            .expect("open task")
            .expect("open stream");
        assert_eq!(handle.stream_id(), connect.stream_id);

        drop(handle);
        drop(peer);
        writer.await.expect("writer task");
        reader.await.expect("reader task");
    }

    #[tokio::test]
    async fn open_tcp_stream_fails_on_error_frame() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (writer_tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let inner = test_inner(0, Some(writer_tx.clone()), Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            Arc::clone(&inner),
            1,
            write_half,
            control_rx,
            data_rx,
        ));
        let reader = tokio::spawn(tunnel_reader_loop(Arc::clone(&inner), 1, read_half));
        let manager = TunnelManager { inner };
        drop(writer_tx);
        let open = tokio::spawn(async move { manager.open_tcp_stream("example.com", 443).await });

        let connect = timeout(Duration::from_secs(1), read_frame(&mut peer))
            .await
            .expect("read TCP_CONNECT timeout")
            .expect("read TCP_CONNECT");
        write_frame(
            &mut peer,
            FrameType::ErrorFrame,
            connect.stream_id,
            0,
            Bytes::from_static(b"target unavailable"),
        )
        .await
        .expect("write ERROR frame");

        let result = timeout(Duration::from_secs(1), open)
            .await
            .expect("open stream timeout")
            .expect("open task");
        let err = match result {
            Ok(_) => panic!("open stream must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("server refused TCP_CONNECT")
                && err.to_string().contains("target unavailable"),
            "unexpected error: {err:#}"
        );
        assert!(streams.lock().await.is_empty());

        drop(peer);
        writer.await.expect("writer task");
        reader.await.expect("reader task");
    }

    #[tokio::test]
    async fn wait_for_connect_response_requires_tcp_connect_success() {
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let stream_tx = streams.lock().await.get(&5).expect("stream tx").clone();
        stream_tx
            .send(StreamEvent::Connected)
            .await
            .expect("send connected event");

        wait_for_connect_response(0, 5, "example.com", 443, &mut stream_rx, &streams)
            .await
            .expect("connect response");

        assert!(streams.lock().await.contains_key(&5));
    }

    #[tokio::test]
    async fn wait_for_connect_response_turns_error_into_open_failure() {
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(5, stream_tx);
        let stream_tx = streams.lock().await.get(&5).expect("stream tx").clone();
        stream_tx
            .send(StreamEvent::Error("target unavailable".to_string()))
            .await
            .expect("send error event");

        let err = wait_for_connect_response(0, 5, "example.com", 443, &mut stream_rx, &streams)
            .await
            .expect_err("connect response must fail");

        assert!(
            err.to_string().contains("server refused TCP_CONNECT")
                && err.to_string().contains("target unavailable"),
            "unexpected error: {err:#}"
        );
        assert!(!streams.lock().await.contains_key(&5));
    }

    #[tokio::test]
    async fn reader_loop_removes_stream_on_tcp_close() {
        let (stream, mut peer) = duplex(1024);
        let (read_half, _write_half) = split(Box::new(stream) as TunnelStream);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(7, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

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
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

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
        let inner = test_inner(0, None, Arc::clone(&streams));
        let reader = tokio::spawn(tunnel_reader_loop(inner, 1, read_half));

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
        let (writer_tx, mut control_rx, _data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(15, stream_tx);
        let closed = AtomicBool::new(false);

        close_stream(
            0,
            15,
            &writer_tx,
            &streams,
            &closed,
            Some("example.com"),
            Some(443),
        )
        .await
        .expect("close stream");

        let frame = control_rx.recv().await.expect("TCP_CLOSE frame");
        assert_eq!(frame.frame_type, FrameType::TcpClose);
        assert_eq!(frame.stream_id, 15);
        assert!(streams.lock().await.contains_key(&15));

        let stream_tx = streams.lock().await.get(&15).expect("stream tx").clone();
        stream_tx
            .send(StreamEvent::Data(Bytes::from_static(b"late response")))
            .await
            .expect("late response send");
        assert_eq!(
            stream_rx.recv().await,
            Some(StreamEvent::Data(Bytes::from_static(b"late response")))
        );
    }

    #[tokio::test]
    async fn writer_loop_clears_streams_on_physical_write_failure() {
        let (stream, peer) = duplex(1024);
        drop(peer);
        let (_read_half, write_half) = split(Box::new(stream) as TunnelStream);
        let (tx, control_rx, data_rx) = test_writer_channels(1);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let (stream_tx, _stream_rx) = mpsc::channel(1);
        streams.lock().await.insert(17, stream_tx);
        let inner = test_inner(0, None, Arc::clone(&streams));
        let writer = tokio::spawn(tunnel_writer_loop(
            inner, 1, write_half, control_rx, data_rx,
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
