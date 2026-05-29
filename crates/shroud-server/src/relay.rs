use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use shroud_core::protocol::{
    Frame, FrameCommand, FrameType, MAX_FRAME_PAYLOAD_LEN, ProtocolError, UdpDatagram,
    decode_tcp_connect_payload, decode_udp_datagram, encode_udp_associate_response_payload,
    encode_udp_datagram, read_frame, write_frame,
};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tracing::{debug, info, warn};

const CONNECT_OK_FLAG: u16 = 0x0001;
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const WRITER_CHANNEL_CAPACITY: usize = 128;
const STREAM_CHANNEL_CAPACITY: usize = 128;
const WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD: Duration = Duration::from_millis(1);

type TargetStreamTx = mpsc::Sender<Bytes>;

#[derive(Clone)]
struct WriterChannels {
    control_tx: mpsc::Sender<FrameCommand>,
    data_tx: mpsc::Sender<FrameCommand>,
}

struct ServerTunnelState {
    streams: Mutex<HashMap<u64, TargetStreamTx>>,
    writer_tx: WriterChannels,
    tunnel_closed: AtomicBool,
}

pub async fn relay_multiplexed_tunnel<S>(tunnel_stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let opened_at = Instant::now();
    let (read_half, write_half) = tokio::io::split(tunnel_stream);
    let (writer_tx, control_rx, data_rx) = writer_channels(WRITER_CHANNEL_CAPACITY);
    let state = Arc::new(ServerTunnelState {
        streams: Mutex::new(HashMap::new()),
        writer_tx,
        tunnel_closed: AtomicBool::new(false),
    });

    info!(%peer, "multiplexed physical tunnel opened");

    let writer_task = tokio::spawn(server_tunnel_writer_loop(write_half, control_rx, data_rx));
    let result = server_tunnel_reader_loop(read_half, Arc::clone(&state), peer).await;

    state.tunnel_closed.store(true, Ordering::Release);
    let active_streams = clear_multiplexed_streams(&state).await;
    writer_task.abort();
    let _ = writer_task.await;

    match &result {
        Ok(()) => info!(
            %peer,
            duration_ms = elapsed_millis(opened_at.elapsed()),
            active_streams,
            "multiplexed physical tunnel closed"
        ),
        Err(err) => warn!(
            %peer,
            duration_ms = elapsed_millis(opened_at.elapsed()),
            active_streams,
            error = %err,
            "multiplexed physical tunnel closed with error"
        ),
    }

    result
}

async fn server_tunnel_reader_loop<R>(
    mut read_half: tokio::io::ReadHalf<R>,
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = match timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut read_half)).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(ProtocolError::Io(err))) if err.kind() == ErrorKind::UnexpectedEof => {
                debug!(%peer, "multiplexed tunnel peer closed connection");
                return Ok(());
            }
            Ok(Err(err)) => return Err(anyhow!("failed to read multiplexed tunnel frame: {err}")),
            Err(_) => bail!("multiplexed tunnel idle timeout while reading from peer {peer}"),
        };

        match frame.frame_type {
            FrameType::TcpConnect => {
                let (target_host, target_port) = decode_tcp_connect_payload(frame.payload.as_ref())
                    .map_err(|err| anyhow!("invalid TCP_CONNECT payload: {err}"))?;
                handle_multiplexed_tcp_connect(
                    Arc::clone(&state),
                    peer,
                    frame.stream_id,
                    target_host,
                    target_port,
                )
                .await?;
            }
            FrameType::TcpData => {
                dispatch_tcp_data_to_target(Arc::clone(&state), peer, frame).await?;
            }
            FrameType::TcpClose => {
                let active_streams = remove_multiplexed_stream(&state, frame.stream_id).await;
                debug!(
                    %peer,
                    stream_id = frame.stream_id,
                    active_streams,
                    "multiplexed TCP stream closed by peer"
                );
            }
            FrameType::ErrorFrame => {
                let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                let active_streams = remove_multiplexed_stream(&state, frame.stream_id).await;
                debug!(
                    %peer,
                    stream_id = frame.stream_id,
                    active_streams,
                    error = %message,
                    "multiplexed TCP stream failed by peer"
                );
            }
            FrameType::Ping => {
                send_writer_command(
                    &state.writer_tx,
                    FrameCommand {
                        frame_type: FrameType::Pong,
                        stream_id: frame.stream_id,
                        flags: 0,
                        payload: frame.payload,
                    },
                    "PONG",
                )
                .await
                .context("failed to queue PONG for multiplexed tunnel")?;
            }
            other => {
                debug!(
                    %peer,
                    stream_id = frame.stream_id,
                    frame_type = %other,
                    "ignoring unsupported frame on multiplexed tunnel"
                );
            }
        }
    }
}

async fn server_tunnel_writer_loop<W>(
    mut write_half: tokio::io::WriteHalf<W>,
    mut control_rx: mpsc::Receiver<FrameCommand>,
    mut data_rx: mpsc::Receiver<FrameCommand>,
) where
    W: AsyncWrite + Unpin,
{
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
            warn!(error = %err, "multiplexed tunnel writer stopped");
            break;
        }
    }

    debug!("multiplexed tunnel writer finished");
}

async fn handle_multiplexed_tcp_connect(
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
    stream_id: u64,
    target_host: String,
    target_port: u16,
) -> Result<()> {
    let (to_target_tx, to_target_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

    {
        let mut streams = state.streams.lock().await;
        if streams.contains_key(&stream_id) {
            drop(streams);
            send_writer_command(
                &state.writer_tx,
                FrameCommand {
                    frame_type: FrameType::ErrorFrame,
                    stream_id,
                    flags: 0,
                    payload: Bytes::from_static(b"duplicate stream id"),
                },
                "duplicate stream id ERROR",
            )
            .await
            .context("failed to queue duplicate stream id error")?;
            return Ok(());
        }

        streams.insert(stream_id, to_target_tx);
        debug!(
            %peer,
            stream_id,
            target_host,
            target_port,
            active_streams = streams.len(),
            "multiplexed TCP stream opened"
        );
    }

    tokio::spawn(connect_and_relay_target(
        state,
        peer,
        stream_id,
        target_host,
        target_port,
        to_target_rx,
    ));

    Ok(())
}

async fn dispatch_tcp_data_to_target(
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
    frame: Frame,
) -> Result<()> {
    let tx = {
        let streams = state.streams.lock().await;
        streams.get(&frame.stream_id).cloned()
    };

    let Some(tx) = tx else {
        debug!(
            %peer,
            stream_id = frame.stream_id,
            "dropping TCP_DATA for unknown multiplexed stream"
        );
        return Ok(());
    };

    if tx.send(frame.payload).await.is_err() {
        let active_streams = remove_multiplexed_stream(&state, frame.stream_id).await;
        debug!(
            %peer,
            stream_id = frame.stream_id,
            active_streams,
            "multiplexed TCP stream removed after target input closed"
        );
    }

    Ok(())
}

async fn connect_and_relay_target(
    state: Arc<ServerTunnelState>,
    peer: SocketAddr,
    stream_id: u64,
    target_host: String,
    target_port: u16,
    to_target_rx: mpsc::Receiver<Bytes>,
) {
    let opened_at = Instant::now();
    let tunnel_to_target_bytes = Arc::new(AtomicU64::new(0));
    let target_to_tunnel_bytes = Arc::new(AtomicU64::new(0));
    let target_connect_started = Instant::now();
    let target_stream = match timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    {
        Err(_) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("timed out connecting target {target_host}:{target_port}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "multiplexed target TCP connect timed out"
            );
            fail_multiplexed_stream(&state, stream_id, message).await;
            log_multiplexed_stream_closed(
                peer,
                stream_id,
                &target_host,
                target_port,
                opened_at,
                tunnel_to_target_bytes.load(Ordering::Relaxed),
                target_to_tunnel_bytes.load(Ordering::Relaxed),
                active_multiplexed_streams(&state).await,
            );
            return;
        }
        Ok(Ok(stream)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            if let Err(err) = stream.set_nodelay(true) {
                let message = format!(
                    "failed to enable TCP_NODELAY for target connection {target_host}:{target_port}: {err}"
                );
                fail_multiplexed_stream(&state, stream_id, message).await;
                log_multiplexed_stream_closed(
                    peer,
                    stream_id,
                    &target_host,
                    target_port,
                    opened_at,
                    tunnel_to_target_bytes.load(Ordering::Relaxed),
                    target_to_tunnel_bytes.load(Ordering::Relaxed),
                    active_multiplexed_streams(&state).await,
                );
                return;
            }

            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "multiplexed target TCP connect finished"
            );

            stream
        }
        Ok(Err(err)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("failed to connect target {target_host}:{target_port}: {err}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                error = %err,
                "multiplexed target TCP connect failed"
            );
            fail_multiplexed_stream(&state, stream_id, message).await;
            log_multiplexed_stream_closed(
                peer,
                stream_id,
                &target_host,
                target_port,
                opened_at,
                tunnel_to_target_bytes.load(Ordering::Relaxed),
                target_to_tunnel_bytes.load(Ordering::Relaxed),
                active_multiplexed_streams(&state).await,
            );
            return;
        }
    };

    if !is_multiplexed_stream_active(&state, stream_id).await {
        debug!(
            %peer,
            stream_id,
            target_host,
            target_port,
            "multiplexed stream closed before target connect response"
        );
        log_multiplexed_stream_closed(
            peer,
            stream_id,
            &target_host,
            target_port,
            opened_at,
            tunnel_to_target_bytes.load(Ordering::Relaxed),
            target_to_tunnel_bytes.load(Ordering::Relaxed),
            active_multiplexed_streams(&state).await,
        );
        return;
    }

    if send_writer_command(
        &state.writer_tx,
        FrameCommand {
            frame_type: FrameType::TcpConnect,
            stream_id,
            flags: CONNECT_OK_FLAG,
            payload: Bytes::new(),
        },
        "TCP_CONNECT response",
    )
    .await
    .is_err()
    {
        remove_multiplexed_stream(&state, stream_id).await;
        log_multiplexed_stream_closed(
            peer,
            stream_id,
            &target_host,
            target_port,
            opened_at,
            tunnel_to_target_bytes.load(Ordering::Relaxed),
            target_to_tunnel_bytes.load(Ordering::Relaxed),
            active_multiplexed_streams(&state).await,
        );
        return;
    }

    let (target_read, target_write) = target_stream.into_split();
    let writer_tx = state.writer_tx.clone();
    let mut reader_task = tokio::spawn(target_reader_loop(
        stream_id,
        target_read,
        writer_tx,
        Arc::clone(&target_to_tunnel_bytes),
    ));
    let mut writer_task = tokio::spawn(target_writer_loop(
        stream_id,
        target_write,
        to_target_rx,
        Arc::clone(&tunnel_to_target_bytes),
    ));

    tokio::select! {
        result = &mut reader_task => {
            match result {
                Ok(Ok(bytes)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    target_to_tunnel_bytes = bytes,
                    "multiplexed target reader finished"
                ),
                Ok(Err(err)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    "multiplexed target reader failed"
                ),
                Err(err) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    "multiplexed target reader task failed"
                ),
            }
            remove_multiplexed_stream(&state, stream_id).await;
            let _ = send_writer_command(&state.writer_tx, FrameCommand {
                frame_type: FrameType::TcpClose,
                stream_id,
                flags: 0,
                payload: Bytes::new(),
            }, "TCP_CLOSE").await;
            writer_task.abort();
            let _ = writer_task.await;
        }
        result = &mut writer_task => {
            let writer_finished_cleanly = matches!(result, Ok(Ok(_)));
            match result {
                Ok(Ok(bytes)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    tunnel_to_target_bytes = bytes,
                    "multiplexed target writer finished"
                ),
                Ok(Err(err)) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    "multiplexed target writer failed"
                ),
                Err(err) => debug!(
                    %peer,
                    stream_id,
                    target_host,
                    target_port,
                    error = %err,
                    "multiplexed target writer task failed"
                ),
            }

            if writer_finished_cleanly && !state.tunnel_closed.load(Ordering::Acquire) {
                match reader_task.await {
                    Ok(Ok(bytes)) => debug!(
                        %peer,
                        stream_id,
                        target_host,
                        target_port,
                        target_to_tunnel_bytes = bytes,
                        "multiplexed target reader finished after input close"
                    ),
                    Ok(Err(err)) => debug!(
                        %peer,
                        stream_id,
                        target_host,
                        target_port,
                        error = %err,
                        "multiplexed target reader failed after input close"
                    ),
                    Err(err) => debug!(
                        %peer,
                        stream_id,
                        target_host,
                        target_port,
                        error = %err,
                        "multiplexed target reader task failed after input close"
                    ),
                }
                remove_multiplexed_stream(&state, stream_id).await;
                let _ = send_writer_command(&state.writer_tx, FrameCommand {
                    frame_type: FrameType::TcpClose,
                    stream_id,
                    flags: 0,
                    payload: Bytes::new(),
                }, "TCP_CLOSE").await;
            } else {
                remove_multiplexed_stream(&state, stream_id).await;
                reader_task.abort();
                let _ = reader_task.await;
            }
        }
    }

    log_multiplexed_stream_closed(
        peer,
        stream_id,
        &target_host,
        target_port,
        opened_at,
        tunnel_to_target_bytes.load(Ordering::Relaxed),
        target_to_tunnel_bytes.load(Ordering::Relaxed),
        active_multiplexed_streams(&state).await,
    );
}

async fn target_reader_loop(
    stream_id: u64,
    mut target_read: impl AsyncRead + Unpin,
    writer_tx: WriterChannels,
    transferred_counter: Arc<AtomicU64>,
) -> Result<u64> {
    let mut transferred = 0u64;
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = timeout(RELAY_IDLE_TIMEOUT, target_read.read(&mut buf))
            .await
            .map_err(|_| anyhow!("relay idle timeout while reading from target"))??;
        if n == 0 {
            break;
        }

        transferred += n as u64;
        transferred_counter.store(transferred, Ordering::Relaxed);
        send_writer_command(
            &writer_tx,
            FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id,
                flags: 0,
                payload: Bytes::copy_from_slice(&buf[..n]),
            },
            "TCP_DATA",
        )
        .await
        .context("failed to queue TCP_DATA from target")?;
    }

    Ok(transferred)
}

async fn target_writer_loop(
    _stream_id: u64,
    mut target_write: impl AsyncWrite + Unpin,
    mut rx: mpsc::Receiver<Bytes>,
    transferred_counter: Arc<AtomicU64>,
) -> Result<u64> {
    let mut transferred = 0u64;

    while let Some(bytes) = rx.recv().await {
        transferred += bytes.len() as u64;
        transferred_counter.store(transferred, Ordering::Relaxed);
        timeout(RELAY_IDLE_TIMEOUT, target_write.write_all(bytes.as_ref()))
            .await
            .map_err(|_| anyhow!("relay timeout while writing to target"))??;
    }

    timeout(RELAY_IDLE_TIMEOUT, target_write.shutdown())
        .await
        .map_err(|_| anyhow!("relay timeout while shutting down target writer"))??;
    Ok(transferred)
}

async fn fail_multiplexed_stream(state: &Arc<ServerTunnelState>, stream_id: u64, message: String) {
    remove_multiplexed_stream(state, stream_id).await;
    let _ = send_writer_command(
        &state.writer_tx,
        FrameCommand {
            frame_type: FrameType::ErrorFrame,
            stream_id,
            flags: 0,
            payload: Bytes::from(message),
        },
        "ERROR",
    )
    .await;
}

async fn remove_multiplexed_stream(state: &Arc<ServerTunnelState>, stream_id: u64) -> usize {
    let mut streams = state.streams.lock().await;
    streams.remove(&stream_id);
    streams.len()
}

async fn is_multiplexed_stream_active(state: &Arc<ServerTunnelState>, stream_id: u64) -> bool {
    state.streams.lock().await.contains_key(&stream_id)
}

async fn active_multiplexed_streams(state: &Arc<ServerTunnelState>) -> usize {
    state.streams.lock().await.len()
}

async fn clear_multiplexed_streams(state: &Arc<ServerTunnelState>) -> usize {
    let mut streams = state.streams.lock().await;
    let active_streams = streams.len();
    streams.clear();
    active_streams
}

async fn send_writer_command(
    writer_tx: &WriterChannels,
    cmd: FrameCommand,
    operation: &'static str,
) -> Result<()> {
    let frame_type = cmd.frame_type;
    let stream_id = cmd.stream_id;
    let payload_len = cmd.payload.len();
    let started = Instant::now();

    writer_tx
        .sender_for(frame_type)
        .send(cmd)
        .await
        .with_context(|| format!("failed to queue {operation} for multiplexed tunnel"))?;

    let wait = started.elapsed();
    if wait >= WRITER_CHANNEL_SEND_WAIT_LOG_THRESHOLD {
        debug!(
            stream_id,
            frame_type = %frame_type,
            payload_len,
            writer_channel_send_wait_ms = elapsed_millis(wait),
            "multiplexed tunnel writer channel send waited"
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

fn log_multiplexed_stream_closed(
    peer: SocketAddr,
    stream_id: u64,
    target_host: &str,
    target_port: u16,
    opened_at: Instant,
    bytes_up: u64,
    bytes_down: u64,
    active_streams: usize,
) {
    let duration = opened_at.elapsed();
    debug!(
        %peer,
        stream_id,
        target_host,
        target_port,
        duration_ms = elapsed_millis(duration),
        bytes_up,
        bytes_down,
        mbps = mbps(bytes_up + bytes_down, duration),
        active_streams,
        "multiplexed TCP stream closed"
    );
}

pub async fn relay_tunnel<S>(mut tunnel_stream: S, peer: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first_frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_stream))
        .await
        .map_err(|_| anyhow!("timed out waiting for first tunnel frame"))??;

    match first_frame.frame_type {
        FrameType::TcpConnect => relay_tcp_tunnel(tunnel_stream, peer, first_frame).await,
        FrameType::UdpAssociateRequest => {
            relay_udp_association(tunnel_stream, peer, first_frame).await
        }
        other => {
            write_frame(
                &mut tunnel_stream,
                FrameType::ErrorFrame,
                first_frame.stream_id,
                0,
                Bytes::from_static(b"expected TCP_CONNECT or UDP_ASSOCIATE_REQUEST as first frame"),
            )
            .await?;
            bail!("first frame from peer {peer} is not a tunnel open request: {other}");
        }
    }
}

async fn relay_tcp_tunnel<S>(
    mut tunnel_stream: S,
    peer: SocketAddr,
    connect_request: Frame,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = connect_request.stream_id;
    let (target_host, target_port) =
        decode_tcp_connect_payload(connect_request.payload.as_ref())
            .map_err(|err| anyhow!("invalid TCP_CONNECT payload: {err}"))?;

    let target_connect_started = Instant::now();
    let mut target_stream = match timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    {
        Err(_) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("timed out connecting target {target_host}:{target_port}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "target TCP connect timed out"
            );
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
        Ok(Ok(stream)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            stream.set_nodelay(true).with_context(|| {
                format!(
                    "failed to enable TCP_NODELAY for target connection {target_host}:{target_port}"
                )
            })?;

            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                "target TCP connect finished"
            );

            stream
        }
        Ok(Err(err)) => {
            let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());
            let message = format!("failed to connect target {target_host}:{target_port}: {err}");
            debug!(
                %peer,
                stream_id,
                target_host,
                target_port,
                target_tcp_connect_ms,
                error = %err,
                "target TCP connect failed"
            );
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
    let target_tcp_connect_ms = elapsed_millis(target_connect_started.elapsed());

    write_frame(
        &mut tunnel_stream,
        FrameType::TcpConnect,
        stream_id,
        CONNECT_OK_FLAG,
        Bytes::new(),
    )
    .await?;

    let relay_started = Instant::now();
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);
    let (mut target_read, mut target_write) = target_stream.split();

    let tunnel_to_target = async {
        let mut transferred = 0u64;

        loop {
            let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_read))
                .await
                .map_err(|_| anyhow!("relay idle timeout while reading from tunnel peer"))??;
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
                    timeout(
                        RELAY_IDLE_TIMEOUT,
                        target_write.write_all(frame.payload.as_ref()),
                    )
                    .await
                    .map_err(|_| anyhow!("relay timeout while writing to target"))??;
                }
                FrameType::TcpClose => {
                    timeout(RELAY_IDLE_TIMEOUT, target_write.shutdown())
                        .await
                        .map_err(|_| {
                            anyhow!("relay timeout while shutting down target writer")
                        })??;
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
        let mut buf = [0u8; 64 * 1024];

        loop {
            let n = timeout(RELAY_IDLE_TIMEOUT, target_read.read(&mut buf))
                .await
                .map_err(|_| anyhow!("relay idle timeout while reading from target"))??;
            if n == 0 {
                timeout(
                    RELAY_IDLE_TIMEOUT,
                    write_frame(
                        &mut tunnel_write,
                        FrameType::TcpClose,
                        stream_id,
                        0,
                        Bytes::new(),
                    ),
                )
                .await
                .map_err(|_| anyhow!("relay timeout while writing TCP_CLOSE to tunnel"))??;
                timeout(RELAY_IDLE_TIMEOUT, tunnel_write.shutdown())
                    .await
                    .map_err(|_| anyhow!("relay timeout while shutting down tunnel writer"))??;
                break;
            }

            transferred += n as u64;
            timeout(
                RELAY_IDLE_TIMEOUT,
                write_frame(
                    &mut tunnel_write,
                    FrameType::TcpData,
                    stream_id,
                    0,
                    Bytes::copy_from_slice(&buf[..n]),
                ),
            )
            .await
            .map_err(|_| anyhow!("relay timeout while writing TCP_DATA to tunnel"))??;
        }

        Ok::<u64, anyhow::Error>(transferred)
    };

    let (upstream_to_target_bytes, target_to_upstream_bytes) =
        tokio::try_join!(tunnel_to_target, target_to_tunnel)?;
    let relay_elapsed = relay_started.elapsed();
    let total_bytes = upstream_to_target_bytes + target_to_upstream_bytes;
    let mbps = mbps(total_bytes, relay_elapsed);

    debug!(
        %peer,
        stream_id,
        target_host,
        target_port,
        target_tcp_connect_ms,
        upstream_to_target_bytes,
        target_to_upstream_bytes,
        total_bytes,
        duration_ms = elapsed_millis(relay_elapsed),
        mbps,
        "tunnel relay finished"
    );

    Ok(())
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn mbps(total_bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds > 0.0 {
        (total_bytes as f64 * 8.0) / seconds / 1_000_000.0
    } else {
        0.0
    }
}

async fn relay_udp_association<S>(
    mut tunnel_stream: S,
    peer: SocketAddr,
    associate_request: Frame,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream_id = associate_request.stream_id;
    let udp_socket = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await {
        Ok(socket) => socket,
        Err(err) => {
            let message = format!("failed to bind remote UDP socket: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::UdpAssociateResponse,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };

    let bind_addr = match udp_socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            let message = format!("failed to inspect remote UDP bind address: {err}");
            write_frame(
                &mut tunnel_stream,
                FrameType::UdpAssociateResponse,
                stream_id,
                0,
                Bytes::from(message.clone()),
            )
            .await?;
            bail!("{message}");
        }
    };
    let response_payload =
        encode_udp_associate_response_payload(&bind_addr.ip().to_string(), bind_addr.port())
            .map_err(|err| anyhow!("failed to encode UDP associate response: {err}"))?;
    write_frame(
        &mut tunnel_stream,
        FrameType::UdpAssociateResponse,
        stream_id,
        CONNECT_OK_FLAG,
        response_payload,
    )
    .await?;

    let counters = Arc::new(UdpRelayCounters::default());
    let udp_socket = Arc::new(udp_socket);
    let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel_stream);

    let tunnel_to_udp_socket = Arc::clone(&udp_socket);
    let tunnel_to_udp_counters = Arc::clone(&counters);
    let tunnel_to_udp = async move {
        loop {
            let frame = timeout(RELAY_IDLE_TIMEOUT, read_frame(&mut tunnel_read))
                .await
                .map_err(|_| anyhow!("udp relay idle timeout while reading from tunnel peer"))??;
            if frame.stream_id != stream_id {
                bail!(
                    "unexpected stream id from peer {}; expected={}, got={}",
                    peer,
                    stream_id,
                    frame.stream_id
                );
            }

            match frame.frame_type {
                FrameType::UdpDatagram => {
                    let datagram = decode_udp_datagram(frame.payload.as_ref())
                        .map_err(|err| anyhow!("invalid UDP_DATAGRAM payload: {err}"))?;
                    let sent = timeout(
                        RELAY_IDLE_TIMEOUT,
                        tunnel_to_udp_socket.send_to(
                            datagram.payload.as_ref(),
                            (datagram.target_host.as_str(), datagram.target_port),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow!("udp relay timeout while sending datagram"))??;
                    tunnel_to_udp_counters.record_tunnel_to_udp(sent as u64);
                }
                FrameType::ErrorFrame => {
                    let message = String::from_utf8_lossy(frame.payload.as_ref()).into_owned();
                    bail!("peer sent ERROR frame: {message}");
                }
                other => bail!("unexpected frame type from peer during udp relay: {other}"),
            }
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let udp_to_tunnel_socket = Arc::clone(&udp_socket);
    let udp_to_tunnel_counters = Arc::clone(&counters);
    let udp_to_tunnel = async move {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        loop {
            let (n, source) = timeout(RELAY_IDLE_TIMEOUT, udp_to_tunnel_socket.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow!("udp relay idle timeout while reading from udp socket"))??;
            let payload = encode_udp_datagram(&UdpDatagram {
                target_host: source.ip().to_string(),
                target_port: source.port(),
                payload: Bytes::copy_from_slice(&buf[..n]),
                association_id: None,
            })
            .map_err(|err| anyhow!("failed to encode UDP_DATAGRAM payload: {err}"))?;
            timeout(
                RELAY_IDLE_TIMEOUT,
                write_frame(
                    &mut tunnel_write,
                    FrameType::UdpDatagram,
                    stream_id,
                    0,
                    payload,
                ),
            )
            .await
            .map_err(|_| anyhow!("udp relay timeout while writing UDP_DATAGRAM to tunnel"))??;
            udp_to_tunnel_counters.record_udp_to_tunnel(n as u64);
        }

        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let result = tokio::try_join!(tunnel_to_udp, udp_to_tunnel);
    let snapshot = counters.snapshot();
    match &result {
        Ok(_) => debug!(
            %peer,
            stream_id,
            bind_addr = %bind_addr,
            tunnel_to_udp_datagrams = snapshot.tunnel_to_udp_datagrams,
            tunnel_to_udp_bytes = snapshot.tunnel_to_udp_bytes,
            udp_to_tunnel_datagrams = snapshot.udp_to_tunnel_datagrams,
            udp_to_tunnel_bytes = snapshot.udp_to_tunnel_bytes,
            "udp tunnel relay finished"
        ),
        Err(err) => debug!(
            %peer,
            stream_id,
            bind_addr = %bind_addr,
            tunnel_to_udp_datagrams = snapshot.tunnel_to_udp_datagrams,
            tunnel_to_udp_bytes = snapshot.tunnel_to_udp_bytes,
            udp_to_tunnel_datagrams = snapshot.udp_to_tunnel_datagrams,
            udp_to_tunnel_bytes = snapshot.udp_to_tunnel_bytes,
            error = %err,
            "udp tunnel relay stopped"
        ),
    }

    result.map(|_| ())
}

#[derive(Default)]
struct UdpRelayCounters {
    tunnel_to_udp_datagrams: AtomicU64,
    tunnel_to_udp_bytes: AtomicU64,
    udp_to_tunnel_datagrams: AtomicU64,
    udp_to_tunnel_bytes: AtomicU64,
}

impl UdpRelayCounters {
    fn record_tunnel_to_udp(&self, bytes: u64) {
        self.tunnel_to_udp_datagrams.fetch_add(1, Ordering::Relaxed);
        self.tunnel_to_udp_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_udp_to_tunnel(&self, bytes: u64) {
        self.udp_to_tunnel_datagrams.fetch_add(1, Ordering::Relaxed);
        self.udp_to_tunnel_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn snapshot(&self) -> UdpRelayCounterSnapshot {
        UdpRelayCounterSnapshot {
            tunnel_to_udp_datagrams: self.tunnel_to_udp_datagrams.load(Ordering::Relaxed),
            tunnel_to_udp_bytes: self.tunnel_to_udp_bytes.load(Ordering::Relaxed),
            udp_to_tunnel_datagrams: self.udp_to_tunnel_datagrams.load(Ordering::Relaxed),
            udp_to_tunnel_bytes: self.udp_to_tunnel_bytes.load(Ordering::Relaxed),
        }
    }
}

struct UdpRelayCounterSnapshot {
    tunnel_to_udp_datagrams: u64,
    tunnel_to_udp_bytes: u64,
    udp_to_tunnel_datagrams: u64,
    udp_to_tunnel_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroud_core::protocol::{
        UdpDatagram, decode_udp_associate_response_payload, encode_tcp_connect_payload,
        encode_udp_datagram,
    };
    use std::collections::{HashMap, HashSet};
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn multiplexed_dispatch_sends_tcp_data_to_registered_stream() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            streams: Mutex::new(HashMap::new()),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        state.streams.lock().await.insert(9, stream_tx);
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;

        dispatch_tcp_data_to_target(
            Arc::clone(&state),
            peer,
            Frame {
                frame_type: FrameType::TcpData,
                stream_id: 9,
                flags: 0,
                payload: Bytes::from_static(b"payload"),
            },
        )
        .await?;

        let payload = timeout(Duration::from_secs(1), stream_rx.recv())
            .await?
            .expect("stream payload");
        assert_eq!(payload, Bytes::from_static(b"payload"));
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_remove_stream_drops_target_input_sender() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            streams: Mutex::new(HashMap::new()),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (stream_tx, mut stream_rx) = mpsc::channel(1);
        state.streams.lock().await.insert(21, stream_tx);

        remove_multiplexed_stream(&state, 21).await;

        assert!(stream_rx.recv().await.is_none());
        assert!(!is_multiplexed_stream_active(&state, 21).await);
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_physical_tunnel_cleanup_drops_all_stream_inputs() -> Result<()> {
        let (writer_tx, _control_rx, _data_rx) = writer_channels(1);
        let state = Arc::new(ServerTunnelState {
            streams: Mutex::new(HashMap::new()),
            writer_tx,
            tunnel_closed: AtomicBool::new(false),
        });
        let (first_tx, mut first_rx) = mpsc::channel(1);
        let (second_tx, mut second_rx) = mpsc::channel(1);
        state.streams.lock().await.insert(23, first_tx);
        state.streams.lock().await.insert(25, second_tx);

        state.streams.lock().await.clear();

        assert!(first_rx.recv().await.is_none());
        assert!(second_rx.recv().await.is_none());
        assert!(state.streams.lock().await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn target_writer_finishes_when_stream_input_is_dropped() -> Result<()> {
        let (target_side, mut peer_side) = duplex(1024);
        let (_target_read, target_write) = tokio::io::split(target_side);
        let (tx, rx) = mpsc::channel(1);
        drop(tx);

        let transferred =
            target_writer_loop(27, target_write, rx, Arc::new(AtomicU64::new(0))).await?;

        assert_eq!(transferred, 0);
        let mut buf = [0u8; 1];
        let n = timeout(Duration::from_secs(1), peer_side.read(&mut buf)).await??;
        assert_eq!(n, 0);
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_writer_loop_serializes_frame_commands() -> Result<()> {
        let (stream, mut peer) = duplex(1024);
        let (_read_half, write_half) = tokio::io::split(stream);
        let (tx, control_rx, data_rx) = writer_channels(1);
        let writer = tokio::spawn(server_tunnel_writer_loop(write_half, control_rx, data_rx));

        tx.data_tx
            .send(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 13,
                flags: 0,
                payload: Bytes::from_static(b"hello"),
            })
            .await?;
        drop(tx);

        let frame = timeout(Duration::from_secs(1), read_frame(&mut peer)).await??;
        writer.await?;

        assert_eq!(frame.frame_type, FrameType::TcpData);
        assert_eq!(frame.stream_id, 13);
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));
        Ok(())
    }

    #[tokio::test]
    async fn multiplexed_writer_receive_prioritizes_control_over_data() -> Result<()> {
        let (tx, mut control_rx, mut data_rx) = writer_channels(2);

        tx.data_tx
            .send(FrameCommand {
                frame_type: FrameType::TcpData,
                stream_id: 13,
                flags: 0,
                payload: Bytes::from_static(b"data"),
            })
            .await?;
        tx.control_tx
            .send(FrameCommand {
                frame_type: FrameType::TcpClose,
                stream_id: 13,
                flags: 0,
                payload: Bytes::new(),
            })
            .await?;

        let frame = recv_writer_command(&mut control_rx, &mut data_rx)
            .await
            .expect("writer command");
        assert_eq!(frame.frame_type, FrameType::TcpClose);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires loopback TCP sockets"]
    async fn multiplexed_tunnel_relays_tcp_data_for_multiple_streams() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = listener.local_addr()?;
        let echo_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await?;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = socket.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        socket.write_all(&buf[..n]).await?;
                    }
                    Ok::<(), std::io::Error>(())
                });
            }
            Ok::<(), std::io::Error>(())
        });

        let (mut client_side, server_side) = duplex(128 * 1024);
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;
        let relay_task = tokio::spawn(relay_multiplexed_tunnel(server_side, peer));

        for (stream_id, payload) in [(1, b"one".as_slice()), (3, b"three".as_slice())] {
            write_frame(
                &mut client_side,
                FrameType::TcpConnect,
                stream_id,
                0,
                encode_tcp_connect_payload(&target_addr.ip().to_string(), target_addr.port())?,
            )
            .await?;
            write_frame(
                &mut client_side,
                FrameType::TcpData,
                stream_id,
                0,
                Bytes::copy_from_slice(payload),
            )
            .await?;
        }

        let mut connected = HashSet::new();
        let mut echoed = HashMap::new();
        while connected.len() < 2 || echoed.len() < 2 {
            let frame = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
            match frame.frame_type {
                FrameType::TcpConnect => {
                    assert_ne!(frame.flags & CONNECT_OK_FLAG, 0);
                    connected.insert(frame.stream_id);
                }
                FrameType::TcpData => {
                    echoed.insert(frame.stream_id, frame.payload);
                }
                other => bail!("unexpected frame from multiplexed tunnel: {other}"),
            }
        }

        assert!(connected.contains(&1));
        assert!(connected.contains(&3));
        assert_eq!(echoed.get(&1), Some(&Bytes::from_static(b"one")));
        assert_eq!(echoed.get(&3), Some(&Bytes::from_static(b"three")));

        write_frame(&mut client_side, FrameType::TcpClose, 1, 0, Bytes::new()).await?;
        write_frame(&mut client_side, FrameType::TcpClose, 3, 0, Bytes::new()).await?;
        drop(client_side);

        echo_task.await??;
        timeout(Duration::from_secs(2), relay_task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn udp_associate_relays_datagrams_both_directions() -> Result<()> {
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_addr = echo_socket.local_addr()?;
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, peer) = echo_socket.recv_from(&mut buf).await?;
            echo_socket.send_to(&buf[..n], peer).await?;
            Ok::<(), std::io::Error>(())
        });

        let (mut client_side, server_side) = duplex(128 * 1024);
        let peer = "127.0.0.1:12345".parse::<SocketAddr>()?;
        let relay_task = tokio::spawn(relay_tunnel(server_side, peer));

        write_frame(
            &mut client_side,
            FrameType::UdpAssociateRequest,
            77,
            0,
            Bytes::new(),
        )
        .await?;

        let response = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
        assert_eq!(response.frame_type, FrameType::UdpAssociateResponse);
        assert_eq!(response.stream_id, 77);
        assert_ne!(response.flags & CONNECT_OK_FLAG, 0);
        let (_bind_host, bind_port) =
            decode_udp_associate_response_payload(response.payload.as_ref())?;
        assert_ne!(bind_port, 0);

        let datagram_payload = encode_udp_datagram(&UdpDatagram {
            target_host: echo_addr.ip().to_string(),
            target_port: echo_addr.port(),
            payload: Bytes::from_static(b"ping"),
            association_id: None,
        })?;
        write_frame(
            &mut client_side,
            FrameType::UdpDatagram,
            77,
            0,
            datagram_payload,
        )
        .await?;

        let reply = timeout(Duration::from_secs(2), read_frame(&mut client_side)).await??;
        assert_eq!(reply.frame_type, FrameType::UdpDatagram);
        assert_eq!(reply.stream_id, 77);
        let reply = decode_udp_datagram(reply.payload.as_ref())?;
        assert_eq!(reply.target_host, echo_addr.ip().to_string());
        assert_eq!(reply.target_port, echo_addr.port());
        assert_eq!(reply.payload, Bytes::from_static(b"ping"));

        echo_task.await??;
        relay_task.abort();
        let _ = relay_task.await;
        Ok(())
    }
}
