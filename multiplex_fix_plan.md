# План исправления multiplex performance и стабильности видео

## 0. Текущая проблема

После реализации multiplex прокси стал работать через один persistent physical tunnel, внутри которого передаются many logical TCP streams по `stream_id`.

Текущая схема:

```text
browser
  -> SOCKS client
  -> one persistent TCP/TLS tunnel
  -> shroud server
  -> target/CDN
```

Проблема проявляется на видео в высоком качестве:

- видео плохо буферизуется;
- high-quality сегменты грузятся медленно;
- в логах есть большое количество active streams;
- writer queue на сервере забивается;
- маленькие frames ждут за большими video/data frames;
- иногда приходят `TCP_DATA` для уже неизвестного `stream_id`.

Главный вывод:

```text
один physical TCP tunnel не вывозит 30+ logical streams,
особенно когда среди них есть heavy downstream video streams.
```

---

## 1. Улучшить диагностику

Цель: точно видеть, какой physical tunnel, какой stream и какой host создают нагрузку.

### 1.1. Добавить `tunnel_id`

Сейчас в логах есть:

```text
stream_id=113
target_host="..."
active_streams=36
```

Нужно добавить:

```text
tunnel_id=0
```

Желаемый лог:

```text
multiplexed tunnel writer channel send waited
tunnel_id=0
stream_id=113
target_host="river-6-604.rtbcdn.ru"
frame_type=TCP_DATA
payload_len=65536
writer_channel_send_wait_ms=984
active_streams=36
```

### 1.2. Логировать `target_host` в writer wait логах

Сейчас видно, что `stream_id=93` или `stream_id=113` ждут writer queue, но не всегда видно, какой это host.

Нужно хранить metadata:

```rust
struct StreamMeta {
    stream_id: u64,
    target_host: String,
    target_port: u16,
    created_at: Instant,
    bytes_up: u64,
    bytes_down: u64,
}
```

И использовать её в логах writer wait.

### 1.3. Добавить writer queue depth

Если используется bounded channel, нужно логировать:

```text
writer_queue_capacity
writer_queue_available
writer_queue_depth
```

Цель:

```text
понять, канал иногда забивается или постоянно находится почти full.
```

### 1.4. Добавить close reason

Сейчас есть:

```text
multiplexed TCP stream closed
multiplexed TCP stream closed by peer
target reader finished
target writer finished
```

Лучше привести к явным причинам:

```text
close_reason=client_closed
close_reason=target_closed
close_reason=writer_channel_closed
close_reason=tunnel_broken
close_reason=protocol_error
close_reason=idle_timeout
```

---

## 2. Починить lifecycle multiplex stream

Цель: убрать ситуацию, когда сервер уже удалил stream, но потом получает для него `TCP_DATA`.

Текущая проблема:

```text
dropping TCP_DATA for unknown multiplexed stream stream_id=...
```

Это означает:

```text
stream удалён из active map,
но данные для него всё ещё приходят.
```

### 2.1. Не удалять stream сразу при `TCP_CLOSE`

Плохая модель:

```text
TCP_CLOSE -> remove stream_id
```

Нужна модель half-close:

```text
Open
  -> ClientWriteClosed
  -> TargetWriteClosed
  -> FullyClosed
```

### 2.2. Ввести состояние stream'а

Пример:

```rust
enum StreamState {
    Open,
    ClientWriteClosed,
    TargetWriteClosed,
    Closing,
    Closed,
}
```

И хранить не просто `HashMap<u64, Sender>`, а полноценный entry:

```rust
struct MultiplexStream {
    tx_to_target: mpsc::Sender<Bytes>,
    state: StreamState,
    meta: StreamMeta,
}
```

### 2.3. Обработка `TCP_CLOSE` от клиента

Когда сервер получает `TCP_CLOSE` от клиента:

```text
не удалять stream сразу;
закрыть направление client -> target;
позволить target -> client ещё дочитать данные;
удалить stream только после завершения обеих сторон.
```

То есть:

```text
client sent TCP_CLOSE
  -> mark ClientWriteClosed
  -> close tx_to_target
  -> wait target reader finish
  -> send TCP_CLOSE back if needed
  -> remove stream
```

### 2.4. Добавить grace period как временный MVP

Если полноценный half-close сложно сделать сразу, можно временно:

```text
TCP_CLOSE -> mark Closing
wait 2-5 seconds
then remove stream
```

Это хуже, чем полноценная модель, но лучше, чем мгновенное удаление.

### 2.5. Изменить лог unknown stream

Сейчас:

```text
dropping TCP_DATA for unknown multiplexed stream
```

После lifecycle fix нужно различать:

```text
unknown stream_id действительно неизвестен
stream_id уже closing
stream_id уже fully closed
late TCP_DATA after close
```

Пример:

```text
late TCP_DATA for closing stream ignored
```

Это поможет отделить нормальные late frames от реальных protocol bugs.

---

## 3. Добавить TunnelPool вместо одного TunnelManager

Цель: убрать bottleneck одного TCP/TLS physical tunnel.

Текущая схема:

```text
1 physical tunnel
  -> 30-36 logical streams
```

Новая схема:

```text
4 physical tunnels
  -> примерно 8-10 logical streams на каждый
```

### 3.1. Новый конфиг

Клиент:

```yaml
outbound:
  multiplex: true
  multiplex_tunnels: 4
  max_streams_per_tunnel: 16
```

Сервер:

```yaml
multiplex:
  enabled: true
```

На сервере можно не знать заранее количество туннелей. Каждый incoming persistent tunnel будет отдельной multiplex session.

### 3.2. Ввести `TunnelPool`

Вместо:

```rust
SessionCore::new_multiplexed(router, tunnel, tunnel_manager, dns)
```

сделать:

```rust
SessionCore::new_multiplexed(router, tunnel_pool, dns)
```

Пример структуры:

```rust
pub struct TunnelPool {
    tunnels: Vec<Arc<TunnelManager>>,
    next: AtomicUsize,
}
```

### 3.3. Открывать несколько persistent tunnels при старте

При запуске клиента:

```rust
let mut tunnels = Vec::new();

for tunnel_id in 0..cfg.outbound.multiplex_tunnels {
    let manager = TunnelManager::connect_with_id(
        tunnel_id,
        outbound.clone(),
        cfg.auth.clone(),
    ).await?;

    tunnels.push(Arc::new(manager));
}

let tunnel_pool = TunnelPool::new(tunnels);
```

### 3.4. Выбор tunnel для нового stream

MVP-вариант:

```text
round-robin
```

Пример:

```rust
let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.tunnels.len();
```

Лучший вариант:

```text
least_active_streams
```

Пример:

```rust
self.tunnels
    .iter()
    .min_by_key(|t| t.active_streams())
```

Ещё лучше в будущем:

```text
least_active_streams + writer_send_wait_score
```

### 3.5. Логировать распределение

При открытии stream:

```text
opening multiplex stream
tunnel_id=2
stream_id=57
target_host="river-6-604.rtbcdn.ru"
active_streams_on_tunnel=8
total_active_streams=31
```

---

## 4. Ограничить количество streams на один tunnel

Цель: не дать одному tunnel снова накопить 30+ streams.

### 4.1. Добавить лимит

```yaml
outbound:
  max_streams_per_tunnel: 16
```

### 4.2. Поведение при превышении лимита

Вариант A, простой:

```text
если все tunnels забиты -> всё равно выбрать least loaded
```

Вариант B, лучше:

```text
если все tunnels забиты -> открыть дополнительный tunnel
```

Вариант C, строгий:

```text
если все tunnels забиты -> вернуть ошибку
```

Для прокси лучше вариант A или B.

### 4.3. Рекомендуемые значения для теста

```yaml
multiplex_tunnels: 4
max_streams_per_tunnel: 12
```

или:

```yaml
multiplex_tunnels: 4
max_streams_per_tunnel: 16
```

---

## 5. Уменьшить head-of-line blocking внутри одного tunnel

Цель: чтобы большие video frames меньше задерживали маленькие служебные frames.

### 5.1. Проверить размер payload frame

Сейчас в логах видны frames:

```text
payload_len=65536
```

Это 64 KiB.

Для throughput это нормально, но для fairness может быть тяжело.

Нужно протестировать:

```text
16 KiB
32 KiB
64 KiB
```

Рекомендуемый первый тест:

```rust
const COPY_BUF_SIZE: usize = 32 * 1024;
```

### 5.2. Не делать слишком маленький frame

Не стоит сразу ставить 4 KiB или 8 KiB, потому что будет слишком много overhead:

```text
больше frames
больше headers
больше wakeups
больше syscalls
```

Оптимальный диапазон для тестов:

```text
32-64 KiB
```

### 5.3. Приоритет control frames

Control frames должны проходить быстрее, чем большие `TCP_DATA`.

К control frames относятся:

```text
TCP_CONNECT
TCP_CLOSE
PING
PONG
ERROR
```

Проблема из лога:

```text
TCP_CONNECT тоже ждал writer_channel_send_wait_ms=573
```

Это плохо: открытие новых stream'ов не должно стоять за большими data frames.

Решение:

```text
разделить writer queue на две очереди:
- control queue
- data queue
```

Writer loop должен сначала проверять control queue:

```text
1. drain control frames
2. send limited number of data frames
3. снова проверить control frames
```

Пример логики:

```rust
tokio::select! {
    Some(cmd) = control_rx.recv() => {
        write_frame(cmd.frame).await?;
    }

    Some(cmd) = data_rx.recv() => {
        write_frame(cmd.frame).await?;
    }
}
```

Но лучше добавить fairness:

```text
после N data frames снова обязательно проверить control queue
```

---

## 6. Добавить backpressure-aware scheduling

Цель: не позволять одному heavy stream полностью забивать tunnel writer.

### 6.1. Считать writer wait score

Для каждого tunnel хранить:

```rust
struct TunnelStats {
    active_streams: AtomicUsize,
    recent_writer_wait_ms: AtomicU64,
    bytes_out: AtomicU64,
}
```

Если tunnel регулярно показывает:

```text
writer_channel_send_wait_ms > 500
```

то новые streams лучше отправлять в другой tunnel.

### 6.2. Выбор tunnel с учётом writer pressure

Пример логики:

```text
score = active_streams * 100 + recent_writer_wait_ms
выбрать tunnel с минимальным score
```

MVP:

```text
least_active_streams
```

Улучшение:

```text
least_pressure_score
```

### 6.3. Логировать pressure

Пример:

```text
selected tunnel for new stream
selected_tunnel_id=2
score=900
active_streams=7
recent_writer_wait_ms=200
```

---

## 7. Добавить keepalive и reconnect

Цель: persistent tunnel должен сам восстанавливаться.

### 7.1. Keepalive Ping/Pong

В протоколе уже есть:

```text
PING
PONG
```

Нужно добавить loop на клиенте:

```text
каждые 20-30 секунд отправлять PING
если PONG нет N секунд -> tunnel считается broken
```

Пример конфига:

```yaml
outbound:
  keepalive_interval_secs: 20
  keepalive_timeout_secs: 10
```

### 7.2. Reconnect tunnel

Если physical tunnel умер:

```text
- пометить tunnel как Disconnected;
- закрыть все active streams этого tunnel;
- открыть новый physical tunnel;
- новые streams направлять только в Connected tunnels.
```

Состояния:

```rust
enum TunnelState {
    Connecting,
    Connected,
    Disconnected,
}
```

### 7.3. Поведение TunnelPool при падении одного tunnel

Если один tunnel упал:

```text
- не валить весь клиент;
- убрать tunnel из выбора;
- начать reconnect;
- остальные tunnels продолжают работать.
```

---

## 8. Исправить SOCKS success semantics для multiplex

Цель: клиент не должен отвечать SOCKS success до того, как сервер реально подключился к target.

Сейчас вероятная проблема:

```text
client получает SOCKS CONNECT
client отправляет TCP_CONNECT frame
client сразу отвечает браузеру success
server ещё не успел подключиться к target
```

Правильная модель:

```text
client -> server: TCP_CONNECT
server -> target: TcpStream::connect
server -> client: TCP_CONNECT OK или ERROR
client -> browser: SOCKS success или SOCKS error
```

### 8.1. Добавить per-stream event channel

Сейчас stream в основном получает data bytes.

Нужно сделать события:

```rust
enum StreamEvent {
    Connected,
    Data(Bytes),
    RemoteClosed,
    Error(String),
}
```

### 8.2. `open_tcp_stream()` должен ждать connect result

Пример:

```rust
pub async fn open_tcp_stream(
    &self,
    target_host: &str,
    target_port: u16,
) -> Result<TunnelStreamHandle> {
    let stream_id = self.allocate_stream_id();

    let (event_tx, event_rx) = mpsc::channel(...);

    self.streams.insert(stream_id, StreamEntry {
        event_tx,
        state: Opening,
    });

    self.send_tcp_connect(stream_id, target_host, target_port).await?;

    wait_for_connected_or_error(event_rx).await?;

    Ok(TunnelStreamHandle { ... })
}
```

### 8.3. Reader loop должен обрабатывать connect response

Когда приходит:

```text
TCP_CONNECT OK
```

reader loop отправляет:

```rust
StreamEvent::Connected
```

Когда приходит:

```text
ERROR
```

reader loop отправляет:

```rust
StreamEvent::Error(...)
```

---

## 9. Протестировать производительность

Цель: сравнить поведение до/после.

### 9.1. Базовые тесты

Тестировать режимы:

```text
multiplex_tunnels=1
multiplex_tunnels=2
multiplex_tunnels=4
multiplex_tunnels=6
```

Для каждого режима смотреть:

```text
writer_channel_send_wait_ms
active_streams per tunnel
bytes_down для video CDN streams
duration_ms для video CDN streams
mbps
количество dropped/late TCP_DATA
```

### 9.2. Целевые значения

Хороший результат:

```text
writer_channel_send_wait_ms обычно < 50-100 ms
редкие пики допустимы до 200-300 ms
нет постоянных ожиданий 800-1800 ms
```

Плохой результат:

```text
writer_channel_send_wait_ms регулярно > 500 ms
active_streams > 25 на один tunnel
control frames ждут сотни ms
```

### 9.3. Проверить конкретно video CDN streams

Нужно отдельно смотреть stream'ы вида:

```text
river-*.rtbcdn.ru
*.rtbcdn.ru
cdn.vigo.tech
```

Для них важны:

```text
bytes_down
duration_ms
mbps
writer_wait_ms
```

Пример желаемого close лога:

```text
multiplexed TCP stream closed
tunnel_id=2
stream_id=929
target_host="river-6-604.rtbcdn.ru"
duration_ms=12000
bytes_up=5000
bytes_down=52428800
mbps=34.9
max_writer_wait_ms=80
avg_writer_wait_ms=12
```

---

## 10. Добавить тесты

### 10.1. Тест: несколько streams через один tunnel

Проверить:

```text
stream_id=1 получает только свои данные
stream_id=3 получает только свои данные
stream_id=5 получает только свои данные
```

### 10.2. Тест: late TCP_DATA после TCP_CLOSE

Сценарий:

```text
client sends TCP_CLOSE
client sends late TCP_DATA
server should not panic
server should log late frame
server should not corrupt another stream
```

### 10.3. Тест: stream half-close

Сценарий:

```text
client closes write side
target still sends response
server must forward response to client
only then stream can be removed
```

### 10.4. Тест: TunnelPool распределяет streams

Сценарий:

```text
4 tunnels
16 streams
ожидание: streams распределены примерно равномерно
```

### 10.5. Тест: один tunnel падает

Сценарий:

```text
4 tunnels
tunnel 2 disconnected
new streams should go to tunnel 0/1/3
reconnect should restore tunnel 2
```

---

## Приоритет выполнения

### P0 — обязательно

1. Добавить `tunnel_id`, `target_host`, writer wait metrics.
2. Починить stream lifecycle / half-close.
3. Реализовать TunnelPool из нескольких persistent tunnels.
4. Ограничить active streams per tunnel.

### P1 — очень желательно

5. Добавить control/data queues.
6. Добавить keepalive Ping/Pong.
7. Добавить reconnect physical tunnel.
8. Исправить SOCKS success: ждать `TCP_CONNECT OK`.

### P2 — оптимизация

9. Подобрать frame size: 32 KiB vs 64 KiB.
10. Добавить pressure-based tunnel selection.
11. Добавить per-host/per-stream throughput summary.
12. Подумать о future QUIC/WebTransport transport после стабилизации TCP MVP.

---

## Рекомендуемый порядок коммитов

### Commit 1: observability

```text
Add tunnel_id and stream metadata to multiplex logs
Add writer queue wait metrics with target_host
Add close_reason to stream close logs
```

### Commit 2: stream lifecycle

```text
Implement multiplex stream state machine
Support half-close semantics
Avoid immediate stream removal on TCP_CLOSE
Handle late TCP_DATA explicitly
```

### Commit 3: tunnel pool MVP

```text
Add outbound.multiplex_tunnels config
Create multiple persistent TunnelManager instances
Distribute new streams by round-robin or least_active_streams
Log tunnel_id for every stream
```

### Commit 4: stream limits

```text
Add max_streams_per_tunnel
Avoid overloading a single physical tunnel
Prefer least-loaded tunnel for new streams
```

### Commit 5: writer fairness

```text
Split control and data writer queues
Prioritize TCP_CONNECT, TCP_CLOSE, PING, PONG, ERROR
Prevent control frames from waiting behind large TCP_DATA frames
```

### Commit 6: keepalive and reconnect

```text
Add periodic PING/PONG keepalive
Detect dead physical tunnels
Reconnect broken tunnels inside TunnelPool
```

### Commit 7: connect acknowledgement

```text
Wait for multiplex TCP_CONNECT response before SOCKS success
Propagate server connect errors to SOCKS client
```

### Commit 8: performance tuning

```text
Benchmark frame sizes
Compare multiplex_tunnels=1/2/4/6
Tune COPY_BUF_SIZE and max_streams_per_tunnel
```

---

## Ожидаемый результат

До исправлений:

```text
1 tunnel
30-36 active streams
writer wait 800-1800 ms
video buffers badly
```

После исправлений:

```text
4 tunnels
8-12 active streams per tunnel
writer wait mostly < 100 ms
video segments load more smoothly
```

Главный критерий успеха:

```text
writer_channel_send_wait_ms перестаёт регулярно уходить в сотни/тысячи ms.
```
