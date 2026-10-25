//! HTTP probe for the container health check.
//!
//! `rvc health` and `rvc-signer health` call [`probe`]. The images then need no
//! `curl`. A probe passes only on a 2xx status. It does not follow a redirect
//! and it does not use a proxy.

use std::fmt;
use std::time::Duration;

/// Time limit for one probe. It is shorter than the 5 s `HEALTHCHECK --timeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Why a probe did not pass.
#[derive(Debug)]
pub enum ProbeError {
    /// No complete response arrived within the time limit.
    Timeout(Duration),
    /// The request failed before a status arrived (for example, connection refused).
    Request(reqwest::Error),
    /// The server answered with a status that is not 2xx.
    Status(reqwest::StatusCode),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(limit) => write!(f, "health probe got no response within {limit:?}"),
            Self::Request(err) => {
                write!(f, "health probe request failed: {err}")?;
                let mut source = std::error::Error::source(err);
                while let Some(cause) = source {
                    write!(f, ": {cause}")?;
                    source = cause.source();
                }
                Ok(())
            }
            Self::Status(status) => write!(f, "health probe got HTTP status {status}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Sends one `GET` to `url` and passes only on a 2xx status.
///
/// # Errors
/// Returns [`ProbeError`] on a non-2xx status, a failed request, or no
/// response within `timeout`.
///
/// # Examples
/// ```no_run
/// # async fn demo() -> Result<(), rvc_telemetry::health_probe::ProbeError> {
/// use rvc_telemetry::health_probe::{probe, DEFAULT_TIMEOUT};
///
/// let url = reqwest::Url::parse("http://127.0.0.1:8080/livez").expect("static URL");
/// probe(&url, DEFAULT_TIMEOUT).await?;
/// # Ok(())
/// # }
/// ```
pub async fn probe(url: &reqwest::Url, timeout: Duration) -> Result<(), ProbeError> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(ProbeError::Request)?;
    let response = client.get(url.clone()).send().await.map_err(|err| {
        if err.is_timeout() {
            ProbeError::Timeout(timeout)
        } else {
            ProbeError::Request(err)
        }
    })?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ProbeError::Status(status))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::time::{Duration, Instant};

    use super::*;

    fn serve_once(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response);
            }
        });
        addr
    }

    fn silent_server(hold: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(hold);
                drop(stream);
            }
        });
        addr
    }

    fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local_addr")
    }

    fn url(addr: SocketAddr, path: &str) -> reqwest::Url {
        reqwest::Url::parse(&format!("http://{addr}{path}")).expect("url")
    }

    const SHORT: Duration = Duration::from_millis(300);

    #[tokio::test]
    async fn test_probe_accepts_2xx() {
        let ok = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        probe(&url(ok, "/livez"), SHORT).await.expect("200 is healthy");

        let empty = serve_once(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        probe(&url(empty, "/livez"), SHORT).await.expect("204 is healthy");
    }

    #[tokio::test]
    async fn test_probe_rejects_404_and_5xx() {
        for (raw, code) in [
            (&b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], 404),
            (
                &b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
                503,
            ),
        ] {
            let addr = serve_once(raw);
            let err = probe(&url(addr, "/healthz"), SHORT).await.expect_err("non-2xx");
            assert!(
                matches!(err, ProbeError::Status(status) if status.as_u16() == code),
                "{err:?}"
            );
            assert!(err.to_string().contains(&code.to_string()), "{err}");
        }
    }

    #[tokio::test]
    async fn test_probe_does_not_follow_a_redirect() {
        let addr = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: /livez\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let err = probe(&url(addr, "/old"), SHORT).await.expect_err("3xx is not healthy");
        assert!(matches!(err, ProbeError::Status(status) if status.as_u16() == 302), "{err:?}");
    }

    #[tokio::test]
    async fn test_probe_fails_when_the_connection_is_refused() {
        let err = probe(&url(closed_port(), "/livez"), SHORT).await.expect_err("refused");
        assert!(matches!(err, ProbeError::Request(_)), "{err:?}");
    }

    /// The bound is wide so that a loaded host does not fail the test. The
    /// server holds the connection longer than the bound, so a probe that
    /// ignores its limit still fails.
    #[tokio::test]
    async fn test_probe_times_out_on_a_silent_server() {
        let bound = SHORT + Duration::from_secs(5);
        let addr = silent_server(bound + Duration::from_secs(5));
        let started = Instant::now();
        let err = probe(&url(addr, "/livez"), SHORT).await.expect_err("silent server");
        assert!(matches!(err, ProbeError::Timeout(t) if t == SHORT), "{err:?}");
        assert!(started.elapsed() < bound, "probe hung: {:?}", started.elapsed());
    }

    #[test]
    fn test_default_timeout_fits_inside_the_docker_healthcheck_timeout() {
        assert!(DEFAULT_TIMEOUT <= Duration::from_secs(4), "{DEFAULT_TIMEOUT:?}");
        assert!(DEFAULT_TIMEOUT > Duration::ZERO);
    }
}
