//! T9 (TRC-2h): a completed sign span is exported only when an endpoint is set,
//! and the exported resource `service.name` is `rvc-signer` unless
//! `--tracing-service-name` overrides it.
//!
//! The collector is an in-test OTLP/HTTP endpoint. The signer binary is the
//! production subscriber (`init_logging` → `telemetry::init_tracing` →
//! `BatchSpanProcessor`). Shutdown awaits `shutdown_tracing`, which flushes
//! ended spans. An unclosed span is never exported.

// RF1-12: SIGTERM via libc::kill in the common harness.
#![allow(unsafe_code)]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use common::{spawn_serve_clearing, wait_for_port, ServeFixture};

const OTEL_ENV_CLEARED: &[&str] = &[
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_TRACES_SAMPLER_ARG",
    "OTEL_SERVICE_NAME",
    "OTEL_RESOURCE_ATTRIBUTES",
];

/// One ended (or not) span taken from an OTLP `ExportTraceServiceRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportedSpan {
    name: String,
    end_time_unix_nano: u64,
    service_name: Option<String>,
}

/// Loopback OTLP/HTTP collector. Records raw protobuf bodies from `POST /v1/traces`.
struct OtlpCollector {
    port: u16,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl OtlpCollector {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind otlp collector");
        listener.set_nonblocking(true).expect("nonblocking accept");
        let port = listener.local_addr().expect("collector addr").port();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let bodies_thr = Arc::clone(&bodies);
        let shutdown_thr = Arc::clone(&shutdown);
        let thread = std::thread::spawn(move || {
            while !shutdown_thr.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
                        sock.set_write_timeout(Some(Duration::from_secs(2))).ok();
                        for body in read_otlp_bodies(&mut sock) {
                            bodies_thr.lock().expect("bodies").push(body);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Self { port, bodies, shutdown, thread: Some(thread) }
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().expect("bodies").clone()
    }
}

impl Drop for OtlpCollector {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_otlp_bodies(sock: &mut TcpStream) -> Vec<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut bodies = Vec::new();
    loop {
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
        while let Some((body, consumed)) = split_one_http_request(&buf) {
            bodies.push(body);
            buf.drain(..consumed);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    }
    bodies
}

/// Returns `(protobuf body, bytes consumed)` when one full HTTP/1.1 request is buffered.
fn split_one_http_request(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut content_length = None;
    for line in header.split("\r\n").skip(1) {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    let len = content_length?;
    let body_start = header_end + 4;
    let body_end = body_start.checked_add(len)?;
    if buf.len() < body_end {
        return None;
    }
    Some((buf[body_start..body_end].to_vec(), body_end))
}

fn decode_exports(bodies: &[Vec<u8>]) -> Vec<ExportedSpan> {
    let mut spans = Vec::new();
    for body in bodies {
        let mut reader = ProtoReader::new(body);
        while let Some((field, wire)) = reader.tag() {
            if field == 1 && wire == 2 {
                if let Some(resource_spans) = reader.len_bytes() {
                    spans.extend(decode_resource_spans(resource_spans));
                }
            } else if reader.skip(wire).is_none() {
                break;
            }
        }
    }
    spans
}

fn decode_resource_spans(bytes: &[u8]) -> Vec<ExportedSpan> {
    let mut service_name = None;
    let mut spans = Vec::new();
    let mut reader = ProtoReader::new(bytes);
    while let Some((field, wire)) = reader.tag() {
        match (field, wire) {
            (1, 2) => {
                if let Some(resource) = reader.len_bytes() {
                    service_name = decode_service_name(resource).or(service_name);
                }
            }
            (2, 2) => {
                if let Some(scope) = reader.len_bytes() {
                    spans.extend(decode_scope_spans(scope));
                }
            }
            _ => {
                if reader.skip(wire).is_none() {
                    break;
                }
            }
        }
    }
    for span in &mut spans {
        span.service_name = service_name.clone();
    }
    spans
}

fn decode_service_name(resource: &[u8]) -> Option<String> {
    let mut reader = ProtoReader::new(resource);
    while let Some((field, wire)) = reader.tag() {
        if field == 1 && wire == 2 {
            if let Some(kv) = reader.len_bytes() {
                if let Some(name) = decode_key_value_service_name(kv) {
                    return Some(name);
                }
            }
        } else if reader.skip(wire).is_none() {
            break;
        }
    }
    None
}

fn decode_key_value_service_name(kv: &[u8]) -> Option<String> {
    let mut key = None;
    let mut value = None;
    let mut reader = ProtoReader::new(kv);
    while let Some((field, wire)) = reader.tag() {
        match (field, wire) {
            (1, 2) => key = reader.len_bytes().and_then(|b| String::from_utf8(b.to_vec()).ok()),
            (2, 2) => value = reader.len_bytes().and_then(decode_any_string),
            _ => {
                if reader.skip(wire).is_none() {
                    break;
                }
            }
        }
    }
    match key.as_deref() {
        Some("service.name") => value,
        _ => None,
    }
}

fn decode_any_string(any: &[u8]) -> Option<String> {
    let mut reader = ProtoReader::new(any);
    while let Some((field, wire)) = reader.tag() {
        if field == 1 && wire == 2 {
            return reader.len_bytes().and_then(|b| String::from_utf8(b.to_vec()).ok());
        }
        if reader.skip(wire).is_none() {
            break;
        }
    }
    None
}

fn decode_scope_spans(scope: &[u8]) -> Vec<ExportedSpan> {
    let mut spans = Vec::new();
    let mut reader = ProtoReader::new(scope);
    while let Some((field, wire)) = reader.tag() {
        if field == 2 && wire == 2 {
            if let Some(span) = reader.len_bytes() {
                if let Some(decoded) = decode_span(span) {
                    spans.push(decoded);
                }
            }
        } else if reader.skip(wire).is_none() {
            break;
        }
    }
    spans
}

fn decode_span(bytes: &[u8]) -> Option<ExportedSpan> {
    let mut name = None;
    let mut end_time_unix_nano = 0;
    let mut reader = ProtoReader::new(bytes);
    while let Some((field, wire)) = reader.tag() {
        match (field, wire) {
            (5, 2) => {
                name = reader.len_bytes().and_then(|b| String::from_utf8(b.to_vec()).ok());
            }
            (8, 1) => end_time_unix_nano = reader.fixed64()?,
            _ => {
                if reader.skip(wire).is_none() {
                    break;
                }
            }
        }
    }
    Some(ExportedSpan { name: name?, end_time_unix_nano, service_name: None })
}

struct ProtoReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn tag(&mut self) -> Option<(u32, u8)> {
        if self.pos >= self.data.len() {
            return None;
        }
        let tag = self.varint()?;
        Some(((tag >> 3) as u32, (tag & 7) as u8))
    }

    fn varint(&mut self) -> Option<u64> {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            if self.pos >= self.data.len() || shift > 63 {
                return None;
            }
            let byte = self.data[self.pos];
            self.pos += 1;
            out |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(out);
            }
            shift += 7;
        }
    }

    fn len_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.varint()? as usize;
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    fn fixed64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        if end > self.data.len() {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Some(u64::from_le_bytes(buf))
    }

    fn skip(&mut self, wire: u8) -> Option<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.fixed64()?;
            }
            2 => {
                self.len_bytes()?;
            }
            5 => {
                let end = self.pos.checked_add(4)?;
                if end > self.data.len() {
                    return None;
                }
                self.pos = end;
            }
            _ => return None,
        }
        Some(())
    }
}

fn randao_body() -> String {
    r#"{ "type": "RANDAO_REVEAL", "fork_info": { "fork": { "previous_version": "0x03000000", "current_version": "0x04000000", "epoch": "100" }, "genesis_validators_root": "0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" }, "randao_reveal": { "epoch": "42" } }"#.to_string()
}

struct SignExport {
    stderr: String,
    spans: Vec<ExportedSpan>,
    http_status: u16,
}

/// Start the signer against `collector` (or with no endpoint), drive one RANDAO
/// sign, and shut the process down so `BatchSpanProcessor` flushes.
async fn drive_sign(tracing_args: &[&str], collector: Option<&OtlpCollector>) -> SignExport {
    let fx = ServeFixture::new();
    let keystore = crypto::test_utils::create_test_keystore(&fx.keystore_dir, &fx.password, None);
    let pubkey = format!("0x{}", hex::encode(keystore.pubkey()));
    let pki = rvc_test_support::TestPki::with_server_sans(["localhost", "127.0.0.1"]);
    let pem_dir = fx.dir.path().join("pki");
    std::fs::create_dir(&pem_dir).expect("pki dir");
    let pems = pki.write_server_pem(&pem_dir);
    let data_dir = fx.dir.path().join("data");
    std::fs::create_dir(&data_dir).expect("data dir");

    let grpc_port = common::free_port();
    let http_port = common::free_port();
    let metrics_port = common::free_port();
    let listen = format!("127.0.0.1:{grpc_port}");
    let http_listen = format!("127.0.0.1:{http_port}");
    let metrics = format!("127.0.0.1:{metrics_port}");

    let mut args = vec![
        "--insecure".to_string(),
        "--init-slashing-db".to_string(),
        "--keystore-dir".to_string(),
        fx.keystore_dir.to_string_lossy().into_owned(),
        "--password-file".to_string(),
        fx.password_file.to_string_lossy().into_owned(),
        "--listen-address".to_string(),
        listen,
        "--metrics-address".to_string(),
        metrics,
        "--data-dir".to_string(),
        data_dir.to_string_lossy().into_owned(),
        "--http-enabled".to_string(),
        "--http-listen-address".to_string(),
        http_listen,
        "--http-tls-mode".to_string(),
        "server-tls-only".to_string(),
        "--http-tls-cert".to_string(),
        pems.cert.to_string_lossy().into_owned(),
        "--http-tls-key".to_string(),
        pems.key.to_string_lossy().into_owned(),
        "--http-tls-ca-cert".to_string(),
        pems.ca_cert.to_string_lossy().into_owned(),
    ];
    args.extend(tracing_args.iter().map(|s| (*s).to_string()));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let child = spawn_serve_clearing(
        &arg_refs,
        &[("RVC_SIGNER_ALLOW_INSECURE", "true"), ("RUST_LOG", "info")],
        OTEL_ENV_CLEARED,
    );

    if !wait_for_port("127.0.0.1", http_port, Duration::from_secs(20)) {
        let outcome = child.kill_and_collect();
        panic!("signer HTTP API did not listen on {http_port}\n{}", outcome.diagnostic());
    }

    let ca = reqwest::Certificate::from_pem(&pki.ca_cert_pem).expect("ca pem");
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("https client");
    let response = client
        .post(format!("https://127.0.0.1:{http_port}/api/v1/eth2/sign/{pubkey}"))
        .header("content-type", "application/json")
        .body(randao_body())
        .send()
        .await
        .expect("sign request");
    let http_status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(http_status, 200, "drive a sign must succeed, body: {body}");

    // The handler span closes when the response is produced. SIGTERM then runs
    // `shutdown_tracing_guard`, which flushes BatchSpanProcessor.
    let outcome = child.terminate_and_wait(Duration::from_secs(15));
    assert!(
        outcome.status.success() && !outcome.timed_out,
        "SIGTERM should flush tracing and exit 0; {}",
        outcome.diagnostic()
    );

    let bodies = collector.map(|c| c.bodies()).unwrap_or_default();
    SignExport { stderr: outcome.stderr_lossy(), spans: decode_exports(&bodies), http_status }
}

fn completed_sign_spans(spans: &[ExportedSpan]) -> Vec<&ExportedSpan> {
    spans.iter().filter(|span| span.name == "sign" && span.end_time_unix_nano != 0).collect()
}

/// T9 positive: endpoint configured → the completed `sign` span is exported
/// with resource `service.name` = `rvc-signer`.
#[tokio::test]
async fn test_t9_sign_span_exported_with_default_service_name() {
    let collector = OtlpCollector::start();
    let endpoint = format!("http://127.0.0.1:{}", collector.port);
    let export = drive_sign(
        &["--tracing-endpoint", &endpoint, "--tracing-sample-rate", "1.0"],
        Some(&collector),
    )
    .await;

    assert!(
        export.stderr.contains("OpenTelemetry tracing enabled"),
        "an endpoint must install the OTel layer; stderr:\n{}",
        export.stderr
    );
    let sign_spans = completed_sign_spans(&export.spans);
    assert!(
        !sign_spans.is_empty(),
        "completed sign span must reach the exporter; spans={:?}\nstderr:\n{}",
        export.spans,
        export.stderr
    );
    for span in &sign_spans {
        assert_eq!(
            span.service_name.as_deref(),
            Some("rvc-signer"),
            "exported sign span resource service.name; spans={:?}",
            export.spans
        );
    }
}

/// `--tracing-service-name` overrides the signer default on the exported resource.
#[tokio::test]
async fn test_t9_tracing_service_name_overrides_exported_resource() {
    let collector = OtlpCollector::start();
    let endpoint = format!("http://127.0.0.1:{}", collector.port);
    let export = drive_sign(
        &[
            "--tracing-endpoint",
            &endpoint,
            "--tracing-sample-rate",
            "1.0",
            "--tracing-service-name",
            "x",
        ],
        Some(&collector),
    )
    .await;

    let sign_spans = completed_sign_spans(&export.spans);
    assert!(
        !sign_spans.is_empty(),
        "override still exports the completed sign span; spans={:?}\nstderr:\n{}",
        export.spans,
        export.stderr
    );
    for span in &sign_spans {
        assert_eq!(span.service_name.as_deref(), Some("x"), "spans={:?}", export.spans);
    }
}

/// T9 negative: no endpoint → no OTel layer and the in-test exporter stays empty
/// even after a completed sign.
#[tokio::test]
async fn test_t9_no_endpoint_installs_no_otel_layer_and_exports_nothing() {
    let collector = OtlpCollector::start();
    let export = drive_sign(&[], Some(&collector)).await;

    assert_eq!(export.http_status, 200);
    assert!(
        !export.stderr.contains("OpenTelemetry tracing enabled")
            && !export.stderr.contains("OpenTelemetry tracing config"),
        "no endpoint must not install an OTel layer; stderr:\n{}",
        export.stderr
    );
    assert!(
        export.spans.is_empty() && collector.bodies().is_empty(),
        "no endpoint must export nothing; spans={:?} bodies={}",
        export.spans,
        collector.bodies().len()
    );
}

#[test]
fn test_otlp_decoder_reads_completed_sign_span_service_name() {
    fn varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        }
        out
    }
    fn tagged_bytes(field: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = varint((u64::from(field) << 3) | 2);
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }
    fn tagged_fixed64(field: u32, value: u64) -> Vec<u8> {
        let mut out = varint((u64::from(field) << 3) | 1);
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    let mut kv = tagged_bytes(1, b"service.name");
    kv.extend(tagged_bytes(2, &tagged_bytes(1, b"rvc-signer")));
    let resource = tagged_bytes(1, &kv);
    let mut span = tagged_bytes(5, b"sign");
    span.extend(tagged_fixed64(8, 42));
    let scope = tagged_bytes(2, &span);
    let mut resource_spans = tagged_bytes(1, &resource);
    resource_spans.extend(tagged_bytes(2, &scope));
    let export = tagged_bytes(1, &resource_spans);

    let spans = decode_exports(&[export]);
    assert_eq!(
        spans,
        vec![ExportedSpan {
            name: "sign".to_string(),
            end_time_unix_nano: 42,
            service_name: Some("rvc-signer".to_string()),
        }]
    );
}
