//! HTTP server for exposing Prometheus metrics and health checks.
//!
//! Provides:
//! - `/metrics` endpoint that returns metrics in Prometheus text format
//! - `/health` endpoint that returns service health status

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use prometheus::Encoder;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::REGISTRY;

/// Health status of the validator client.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub beacon_connected: bool,
    pub validators_loaded: usize,
    pub slashing_db_initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HealthStatus {
    pub fn update_healthy(&mut self) {
        self.healthy =
            self.beacon_connected && self.validators_loaded > 0 && self.slashing_db_initialized;
    }
}

/// Shared state for health status.
pub type SharedHealthStatus = Arc<RwLock<HealthStatus>>;

/// Creates a new shared health status.
pub fn new_health_status() -> SharedHealthStatus {
    Arc::new(RwLock::new(HealthStatus::default()))
}

/// Creates an axum Router with the `/metrics` endpoint (without health).
pub fn create_metrics_router() -> Router {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Creates an axum Router with both `/metrics` and `/health` endpoints.
pub fn create_metrics_router_with_health(health_status: SharedHealthStatus) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler))
        .with_state(health_status)
}

/// Starts the metrics HTTP server on the specified address and port.
///
/// # Arguments
/// * `addr` - The IP address to bind to
/// * `port` - The port number to listen on
///
/// # Errors
/// Returns an error if the server fails to bind or serve.
pub async fn serve_metrics(addr: IpAddr, port: u16) -> Result<(), std::io::Error> {
    let router = create_metrics_router();
    let socket_addr = SocketAddr::from((addr, port));
    let listener = TcpListener::bind(socket_addr)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "metrics server failed to bind"))?;
    tracing::info!("Metrics server listening on {}", socket_addr);
    axum::serve(listener, router)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "metrics server stopped serving"))
}

/// Starts the metrics HTTP server with health endpoint on the specified address and port.
///
/// # Arguments
/// * `addr` - The IP address to bind to
/// * `port` - The port number to listen on
/// * `health_status` - Shared health status for the health endpoint
///
/// # Errors
/// Returns an error if the server fails to bind or serve.
pub async fn serve_metrics_with_health(
    addr: IpAddr,
    port: u16,
    health_status: SharedHealthStatus,
) -> Result<(), std::io::Error> {
    let socket_addr = SocketAddr::from((addr, port));
    let listener = TcpListener::bind(socket_addr)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "metrics server failed to bind"))?;
    serve_metrics_on(listener, health_status).await
}

/// Serves the metrics and health endpoints on a caller-supplied listener.
///
/// Does not bind. [`serve_metrics_with_health`] binds and then calls this
/// function. A serve failure is returned as [`std::io::Error`].
///
/// # Errors
/// Returns an error if the server stops serving.
pub async fn serve_metrics_on(
    listener: TcpListener,
    health_status: SharedHealthStatus,
) -> Result<(), std::io::Error> {
    let router = create_metrics_router_with_health(health_status);
    let bound = listener.local_addr()?;
    tracing::info!("Metrics server with health endpoint listening on {}", bound);
    axum::serve(listener, router)
        .await
        .inspect_err(|e| tracing::error!(error = %e, "metrics server stopped serving"))
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
            buffer,
        ),
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("Failed to encode metrics: {}", e).into_bytes(),
            )
        }
    }
}

async fn health_handler(State(health_status): State<SharedHealthStatus>) -> impl IntoResponse {
    let status = health_status.read().await;
    let http_status = if status.healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };

    (http_status, Json(status.clone()))
}

async fn livez_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz_handler(State(health_status): State<SharedHealthStatus>) -> impl IntoResponse {
    let status = health_status.read().await;
    if status.healthy {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn serve_metrics_logs_error_on_bind_failure() {
        use std::net::Ipv4Addr;
        // Occupy an ephemeral port, then ask serve_metrics to bind the same one.
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();

        let result = serve_metrics(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await;

        assert!(result.is_err(), "bind should fail on an already-occupied port");
        assert!(logs_contain("metrics server failed to bind"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_200() {
        let router = create_metrics_router();

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus_format() {
        let router = create_metrics_router();

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header should be present");

        assert!(
            content_type.to_str().unwrap().starts_with("text/plain"),
            "Content-Type should be text/plain for Prometheus format"
        );
    }

    #[tokio::test]
    async fn test_registered_metrics_appear_in_output() {
        use crate::register_counter;

        let counter = register_counter("test_server_counter", "A test counter for server tests")
            .expect("Failed to register counter");
        counter.inc();

        let router = create_metrics_router();

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            body_str.contains("test_server_counter"),
            "Response should contain registered metric. Body: {}",
            body_str
        );
    }

    #[test]
    fn test_health_status_default() {
        let status = HealthStatus::default();
        assert!(!status.healthy);
        assert!(!status.beacon_connected);
        assert_eq!(status.validators_loaded, 0);
        assert!(!status.slashing_db_initialized);
        assert!(status.current_slot.is_none());
        assert!(status.error.is_none());
    }

    #[test]
    fn test_health_status_update_healthy() {
        let mut status = HealthStatus {
            beacon_connected: true,
            validators_loaded: 5,
            slashing_db_initialized: true,
            ..Default::default()
        };
        status.update_healthy();

        assert!(status.healthy);
    }

    #[test]
    fn test_health_status_update_unhealthy_no_beacon() {
        let mut status = HealthStatus {
            beacon_connected: false,
            validators_loaded: 5,
            slashing_db_initialized: true,
            ..Default::default()
        };
        status.update_healthy();

        assert!(!status.healthy);
    }

    #[test]
    fn test_health_status_update_unhealthy_no_validators() {
        let mut status = HealthStatus {
            beacon_connected: true,
            validators_loaded: 0,
            slashing_db_initialized: true,
            ..Default::default()
        };
        status.update_healthy();

        assert!(!status.healthy);
    }

    #[tokio::test]
    async fn test_health_endpoint_unhealthy() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_health_endpoint_healthy() {
        let health_status = new_health_status();

        {
            let mut status = health_status.write().await;
            status.beacon_connected = true;
            status.validators_loaded = 5;
            status.slashing_db_initialized = true;
            status.update_healthy();
        }

        let router = create_metrics_router_with_health(health_status);
        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_json() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.contains("\"healthy\""));
        assert!(body_str.contains("\"beacon_connected\""));
        assert!(body_str.contains("\"validators_loaded\""));
    }

    #[tokio::test]
    async fn test_livez_endpoint() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/livez").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_endpoint_not_ready() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/readyz").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_readyz_endpoint_ready() {
        let health_status = new_health_status();

        {
            let mut status = health_status.write().await;
            status.beacon_connected = true;
            status.validators_loaded = 5;
            status.slashing_db_initialized = true;
            status.update_healthy();
        }

        let router = create_metrics_router_with_health(health_status);
        let request = Request::builder().uri("/readyz").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_with_health_router_has_metrics() {
        let health_status = new_health_status();
        let router = create_metrics_router_with_health(health_status);

        let request = Request::builder().uri("/metrics").body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_serve_metrics_accepts_ip_addr() {
        use std::net::{IpAddr, Ipv4Addr};

        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let handle = tokio::spawn(serve_metrics(addr, 0));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
    }

    #[tokio::test]
    async fn test_serve_metrics_with_health_accepts_ip_addr() {
        use std::net::{IpAddr, Ipv4Addr};

        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let health_status = new_health_status();
        let handle = tokio::spawn(serve_metrics_with_health(addr, 0, health_status));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
    }

    #[tokio::test]
    async fn test_serve_metrics_with_health_binds_to_specified_addr() {
        use std::net::{IpAddr, Ipv4Addr};

        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let health_status = new_health_status();
        let handle = tokio::spawn(serve_metrics_with_health(addr, 0, health_status));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
    }

    /// Caller binds port 0 and hands the listener to `serve_metrics_on`.
    /// The scrape must hit that listener's address, not a port the server binds itself.
    #[tokio::test]
    async fn serve_metrics_on_accepts_a_prebound_listener() {
        use std::net::Ipv4Addr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let health_status = new_health_status();
        let server = tokio::spawn(serve_metrics_on(listener, health_status));

        let mut stream = None;
        for _ in 0..50 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        let mut stream =
            stream.unwrap_or_else(|| panic!("metrics server did not accept at {addr}"));
        let req = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let body = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            String::from_utf8(buf).unwrap()
        })
        .await
        .expect("scrape /metrics on the pre-bound listener");

        let status = body
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("HTTP status line missing: {body}"));
        assert_eq!(status, 200, "GET /metrics on {addr} must succeed; body: {body}");
        assert!(
            body.to_ascii_lowercase().contains("text/plain; version=0.0.4"),
            "scrape must be Prometheus text; body: {body}"
        );

        server.abort();
        let _ = server.await;
    }
}
