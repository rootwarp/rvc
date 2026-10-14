use std::fmt;

use anyhow::{bail, Result};

/// Exporter backend for telemetry data.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum ExporterKind {
    /// OpenTelemetry Protocol (OTLP) over HTTP.
    #[default]
    Otlp,
    /// Google Cloud Trace exporter (requires `gcp-trace` feature).
    #[cfg(feature = "gcp-trace")]
    Gcp,
}

impl fmt::Debug for ExporterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Otlp => write!(f, "Otlp"),
            #[cfg(feature = "gcp-trace")]
            Self::Gcp => write!(f, "Gcp"),
        }
    }
}

/// Configuration for the telemetry subsystem.
#[derive(Clone)]
pub struct TelemetryConfig {
    /// OTLP collector endpoint URL.
    pub endpoint: String,
    /// Which exporter backend to use.
    pub exporter: ExporterKind,
    /// Trace sampling rate (0.0 to 1.0).
    pub sample_rate: f64,
    /// Ethereum network name (e.g. "mainnet", "hoodi").
    pub network: String,
    /// Binary version for `service.version` resource attribute.
    /// When `None`, falls back to the telemetry crate's own version.
    pub service_version: Option<String>,
    /// OpenTelemetry `service.name` for resource and tracer (ADR-007 / TRC-1c).
    /// When `None`, [`crate::init::init_tracing`] falls back to `"rvc"`.
    pub service_name: Option<String>,
    /// Maximum number of spans queued for export (OTel SDK default: 2048).
    pub max_queue_size: Option<usize>,
    /// Maximum number of spans per export batch (OTel SDK default: 512).
    pub max_export_batch_size: Option<usize>,
}

impl fmt::Debug for TelemetryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryConfig")
            .field("endpoint", &redact_endpoint(&self.endpoint))
            .field("exporter", &self.exporter)
            .field("sample_rate", &self.sample_rate)
            .field("network", &self.network)
            .finish()
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4318".to_string(),
            exporter: ExporterKind::default(),
            sample_rate: 1.0,
            network: "mainnet".to_string(),
            service_version: None,
            service_name: None,
            max_queue_size: None,
            max_export_batch_size: None,
        }
    }
}

impl TelemetryConfig {
    /// Validate the configuration, returning an error for invalid values.
    pub fn validate(&self) -> Result<()> {
        if !self.sample_rate.is_finite() || !(0.0..=1.0).contains(&self.sample_rate) {
            bail!("sample_rate must be a finite value in 0.0..=1.0, got {}", self.sample_rate);
        }
        if self.requires_endpoint()
            && !self.endpoint.starts_with("http://")
            && !self.endpoint.starts_with("https://")
        {
            bail!("endpoint must start with http:// or https://, got {:?}", self.endpoint);
        }
        Ok(())
    }

    fn requires_endpoint(&self) -> bool {
        match self.exporter {
            ExporterKind::Otlp => true,
            #[cfg(feature = "gcp-trace")]
            ExporterKind::Gcp => false,
        }
    }
}

/// Redact credentials from an endpoint URL for safe logging.
///
/// Replaces `user:pass@` in `scheme://user:pass@host` with `***@`.
fn redact_endpoint(endpoint: &str) -> String {
    let Some(scheme_end) = endpoint.find("://") else {
        return endpoint.to_string();
    };
    let after_scheme = &endpoint[scheme_end + 3..];
    if let Some(at_pos) = after_scheme.find('@') {
        format!("{}://***@{}", &endpoint[..scheme_end], &after_scheme[at_pos + 1..])
    } else {
        endpoint.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.endpoint, "http://localhost:4318");
        assert_eq!(config.exporter, ExporterKind::Otlp);
        assert_eq!(config.sample_rate, 1.0);
        assert_eq!(config.network, "mainnet");
    }

    #[test]
    fn test_exporter_kind_default_is_otlp() {
        let kind = ExporterKind::default();
        assert_eq!(kind, ExporterKind::Otlp);
    }

    #[test]
    fn test_telemetry_config_custom_values() {
        let config = TelemetryConfig {
            endpoint: "http://collector:4318".to_string(),
            exporter: ExporterKind::Otlp,
            sample_rate: 0.5,
            network: "hoodi".to_string(),
            ..Default::default()
        };
        assert_eq!(config.endpoint, "http://collector:4318");
        assert_eq!(config.sample_rate, 0.5);
        assert_eq!(config.network, "hoodi");
    }

    #[test]
    fn test_telemetry_config_clone() {
        let config = TelemetryConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.endpoint, config.endpoint);
        assert_eq!(cloned.sample_rate, config.sample_rate);
        assert_eq!(cloned.network, config.network);
    }

    #[test]
    fn test_exporter_kind_debug() {
        let kind = ExporterKind::Otlp;
        let debug = format!("{kind:?}");
        assert_eq!(debug, "Otlp");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = TelemetryConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_sample_rate_zero() {
        let config = TelemetryConfig { sample_rate: 0.0, ..Default::default() };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_sample_rate_one() {
        let config = TelemetryConfig { sample_rate: 1.0, ..Default::default() };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_sample_rate_nan() {
        let config = TelemetryConfig { sample_rate: f64::NAN, ..Default::default() };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("sample_rate"));
    }

    #[test]
    fn test_validate_sample_rate_negative() {
        let config = TelemetryConfig { sample_rate: -0.1, ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_sample_rate_too_high() {
        let config = TelemetryConfig { sample_rate: 1.1, ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_sample_rate_infinity() {
        let config = TelemetryConfig { sample_rate: f64::INFINITY, ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_endpoint_no_scheme() {
        let config =
            TelemetryConfig { endpoint: "localhost:4318".to_string(), ..Default::default() };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("http://"));
    }

    #[test]
    fn test_validate_invalid_endpoint_ftp() {
        let config =
            TelemetryConfig { endpoint: "ftp://collector:21".to_string(), ..Default::default() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_https_endpoint() {
        let config = TelemetryConfig {
            endpoint: "https://collector.example.com:4318".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_debug_redacts_credentials() {
        let config = TelemetryConfig {
            endpoint: "http://user:secret@collector:4318".to_string(),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("user:"));
        assert!(debug.contains("***@collector:4318"));
    }

    #[test]
    fn test_debug_no_credentials_unchanged() {
        let config = TelemetryConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("http://localhost:4318"));
    }

    #[test]
    fn test_redact_endpoint_with_credentials() {
        assert_eq!(redact_endpoint("http://user:pass@host:4318/path"), "http://***@host:4318/path");
    }

    #[test]
    fn test_redact_endpoint_without_credentials() {
        assert_eq!(redact_endpoint("http://localhost:4318"), "http://localhost:4318");
    }

    #[test]
    fn test_redact_endpoint_no_scheme() {
        assert_eq!(redact_endpoint("localhost:4318"), "localhost:4318");
    }

    #[test]
    fn test_service_version_default_is_none() {
        let config = TelemetryConfig::default();
        assert!(config.service_version.is_none());
    }

    #[test]
    fn test_service_version_custom() {
        let config =
            TelemetryConfig { service_version: Some("1.2.3".to_string()), ..Default::default() };
        assert_eq!(config.service_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn test_service_name_default_is_none() {
        let config = TelemetryConfig::default();
        assert!(config.service_name.is_none());
    }

    #[test]
    fn test_service_name_custom() {
        let config =
            TelemetryConfig { service_name: Some("rvc-signer".to_string()), ..Default::default() };
        assert_eq!(config.service_name.as_deref(), Some("rvc-signer"));
    }

    #[test]
    fn test_max_queue_size_default_is_none() {
        let config = TelemetryConfig::default();
        assert!(config.max_queue_size.is_none());
    }

    #[test]
    fn test_max_export_batch_size_default_is_none() {
        let config = TelemetryConfig::default();
        assert!(config.max_export_batch_size.is_none());
    }

    #[test]
    fn test_batch_config_custom_values() {
        let config = TelemetryConfig {
            max_queue_size: Some(4096),
            max_export_batch_size: Some(1024),
            ..Default::default()
        };
        assert_eq!(config.max_queue_size, Some(4096));
        assert_eq!(config.max_export_batch_size, Some(1024));
    }

    #[cfg(feature = "gcp-trace")]
    #[test]
    fn test_validate_gcp_skips_endpoint_check() {
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "GCP exporter should not require a valid HTTP endpoint");
    }

    #[cfg(feature = "gcp-trace")]
    #[test]
    fn test_exporter_kind_gcp_debug() {
        let kind = ExporterKind::Gcp;
        assert_eq!(format!("{kind:?}"), "Gcp");
    }
}
