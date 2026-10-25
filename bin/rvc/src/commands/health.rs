//! `rvc health`: one HTTP probe for the container `HEALTHCHECK`.

use url::Url;

/// Liveness route of the metrics server on its default bind (`127.0.0.1:8080`).
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080/livez";

/// Probes `url` one time. Returns an error unless the status is 2xx.
pub async fn execute(url: &Url) -> anyhow::Result<()> {
    telemetry::health_probe::probe(url, telemetry::health_probe::DEFAULT_TIMEOUT).await?;
    Ok(())
}
