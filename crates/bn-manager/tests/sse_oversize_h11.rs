/// H-11: SSE caps integration tests.
///
/// Verifies:
/// 1. Per-event size cap: a frame past 64 KiB closes the connection and counts
///    as a failure (reconnect / failover). It is not skipped in place.
/// 2. Content-Type check: wrong CT causes connection drop.
/// 3. Bounded mpsc dispatch: full channel drops events; loop continues.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rvc_bn_manager::sse::{subscribe_events, SseConfig, SseEvent};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;

// ── helper: raw TCP SSE server ────────────────────────────────────────────────

/// Spawn a minimal HTTP/1.1 SSE server that writes `sse_body` once per connection,
/// using `content_type` as the `Content-Type` response header.
async fn start_sse_server_with_ct(
    sse_body: String,
    content_type: &'static str,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = sse_body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n"
                );
                let _ = stream.write_all(headers.as_bytes()).await;
                let chunk = format!("{:x}\r\n{}\r\n", body.len(), body);
                let _ = stream.write_all(chunk.as_bytes()).await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = stream.write_all(b"0\r\n\r\n").await;
            });
        }
    });

    (port, handle)
}

/// Spawn a standard `text/event-stream` server.
async fn start_sse_server(sse_body: String) -> (u16, tokio::task::JoinHandle<()>) {
    start_sse_server_with_ct(sse_body, "text/event-stream").await
}

// ── helpers to build SSE event payloads ──────────────────────────────────────

fn head_event_json(slot: u64) -> String {
    format!(
        "{{\"slot\":\"{slot}\",\"block\":\"0xa\",\"state\":\"0xb\",\
         \"epoch_transition\":false,\"previous_duty_dependent_root\":\"0xc\",\
         \"current_duty_dependent_root\":\"0xd\",\"execution_optimistic\":false}}"
    )
}

fn sse_event_line(event_type: &str, data: &str) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}

/// Send `body` and hold the socket open so a client that skips the frame in
/// place never observes end-of-stream.
async fn start_holding_sse_server(body: String) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\n\r\n";
                let _ = stream.write_all(headers.as_bytes()).await;
                let chunk = format!("{:x}\r\n{}\r\n", body.len(), body);
                let _ = stream.write_all(chunk.as_bytes()).await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    (port, handle)
}

// ── H-11 test 1: oversize frame closes the connection and fails over ─────────

#[tokio::test]
async fn test_oversize_event_fails_over() {
    // 128 KiB event data (exceeds the 64 KiB default cap). The socket stays
    // open afterwards: skipping the frame in place would never fail over.
    let huge_data = "x".repeat(128 * 1024);
    let huge_event = sse_event_line("head", &huge_data);
    let (primary_port, primary_handle) = start_holding_sse_server(huge_event).await;

    let normal_event = sse_event_line("head", &head_event_json(2));
    let (secondary_port, secondary_handle) = start_sse_server(normal_event).await;

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let received_clone = received.clone();

    let (tx_shutdown, rx_shutdown) = watch::channel(false);
    let configs = vec![
        SseConfig::new(format!("http://127.0.0.1:{primary_port}")),
        SseConfig::new(format!("http://127.0.0.1:{secondary_port}")),
    ];

    let handle = tokio::spawn(async move {
        subscribe_events(
            configs,
            move |_event: SseEvent| {
                received_clone.fetch_add(1, Ordering::Relaxed);
            },
            rx_shutdown,
        )
        .await;
    });

    // Three failures on the primary (500 ms apart) then the secondary.
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if received.load(Ordering::Relaxed) >= 1 {
            break;
        }
    }

    tx_shutdown.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
    primary_handle.abort();
    secondary_handle.abort();

    let got = received.load(Ordering::Relaxed);
    assert!(
        got >= 1,
        "oversize frame must count as a failure and fail over to the secondary, got {got}"
    );
}

// ── H-11 test 2: wrong Content-Type drops connection ─────────────────────────

#[tokio::test]
async fn test_wrong_content_type_disconnects() {
    let normal_event = sse_event_line("head", &head_event_json(99));
    let sse_body = normal_event;

    // Server returns application/json — should be rejected
    let (port, server_handle) = start_sse_server_with_ct(sse_body, "application/json").await;

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let received_clone = received.clone();

    let (tx_shutdown, rx_shutdown) = watch::channel(false);
    let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

    let handle = tokio::spawn(async move {
        subscribe_events(
            vec![config],
            move |_event: SseEvent| {
                received_clone.fetch_add(1, Ordering::Relaxed);
            },
            rx_shutdown,
        )
        .await;
    });

    // Give the subscriber time to attempt a connection and (correctly) refuse it
    tokio::time::sleep(Duration::from_millis(500)).await;

    // No events should have been dispatched — the connection should be dropped.
    tx_shutdown.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    server_handle.abort();

    let got = received.load(Ordering::Relaxed);
    assert_eq!(
        got, 0,
        "wrong Content-Type should have caused 0 events to be dispatched, got {got}"
    );
}

/// Unblocks the parked SSE callback when the test returns or unwinds.
struct ReleaseParked(Arc<(Mutex<bool>, Condvar)>);

impl Drop for ReleaseParked {
    fn drop(&mut self) {
        let (lock, cv) = &*self.0;
        if let Ok(mut ready) = lock.lock() {
            *ready = true;
            cv.notify_all();
        }
    }
}

// ── H-11 test 3: saturated channel drops events; loop continues ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_callback_full_drops_event() {
    let events: String = (0u64..200).map(|i| sse_event_line("head", &head_event_json(i))).collect();

    let (port, server_handle) = start_sse_server(events).await;
    let drop_rx = rvc_bn_manager::sse::testing_subscribe_sse_drops();

    let received: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let received_clone = received.clone();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let release_cb = Arc::clone(&release);
    // Dropped on panic as well as on the success path, so a failed wait does
    // not leave the callback parked through runtime teardown.
    let release_on_unwind = ReleaseParked(Arc::clone(&release));
    let held_first = AtomicBool::new(true);

    let (tx_shutdown, rx_shutdown) = watch::channel(false);
    let config = SseConfig::new(format!("http://127.0.0.1:{port}"));

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let handle = tokio::spawn(async move {
        subscribe_events(
            vec![config],
            move |_event: SseEvent| {
                received_clone.fetch_add(1, Ordering::Relaxed);
                if held_first.swap(false, Ordering::Relaxed) {
                    let _ = entered_tx.send(());
                    let (lock, cv) = &*release_cb;
                    let mut ready = lock.lock().expect("callback release");
                    let limit = std::time::Instant::now() + Duration::from_secs(30);
                    while !*ready {
                        let remaining = limit.saturating_duration_since(std::time::Instant::now());
                        if remaining.is_zero() {
                            panic!("callback was not released within 30s");
                        }
                        let (next, timed) =
                            cv.wait_timeout(ready, remaining).expect("callback release");
                        ready = next;
                        if timed.timed_out() && !*ready {
                            panic!("callback was not released within 30s");
                        }
                    }
                }
            },
            rx_shutdown,
        )
        .await;
    });

    tokio::time::timeout(
        Duration::from_secs(6),
        tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(5))),
    )
    .await
    .expect("callback entry wait hung")
    .expect("callback entry wait")
    .expect("callback did not run");
    tokio::time::timeout(
        Duration::from_secs(6),
        tokio::task::spawn_blocking(move || drop_rx.recv_timeout(Duration::from_secs(5))),
    )
    .await
    .expect("sse drop wait hung")
    .expect("sse drop wait")
    .expect("callback channel did not drop an event");

    drop(release_on_unwind);
    tx_shutdown.send(true).unwrap();
    let subscribe_result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(subscribe_result.is_ok(), "subscribe_events must not block when channel is full");
    server_handle.abort();

    let got = received.load(Ordering::Relaxed);
    assert!(
        (1..200).contains(&got),
        "a full callback channel must deliver some events and drop the rest, got {got}"
    );
}
