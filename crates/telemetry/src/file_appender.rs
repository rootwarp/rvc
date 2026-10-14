use anyhow::Result;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::Registry;

/// Configuration for the file logging layer.
#[derive(Debug, Clone)]
pub struct FileAppenderConfig {
    pub directory: String,
    pub filename: String,
    pub max_size_mb: u64,
    pub max_files: usize,
    pub compress: bool,
    pub level: String,
}

/// Creates a file logging layer with size-based rotation via `logroller`.
///
/// Returns a boxed `Layer` for composing into the subscriber stack, and a
/// `WorkerGuard` that must be held for the application lifetime.
pub fn create_file_layer(
    config: &FileAppenderConfig,
) -> Result<(Box<dyn Layer<Registry> + Send + Sync>, WorkerGuard)> {
    let mut builder = logroller::LogRollerBuilder::new(&config.directory, &config.filename)
        .rotation(logroller::Rotation::SizeBased(logroller::RotationSize::MB(config.max_size_mb)))
        .max_keep_files(config.max_files as u64);

    if config.compress {
        builder = builder.compression(logroller::Compression::Gzip);
    }

    let roller = builder.build().map_err(|e| anyhow::anyhow!("Failed to build log roller: {e}"))?;

    let (non_blocking, guard) = tracing_appender::non_blocking(roller);
    let layer = build_layer(non_blocking, &config.level);

    Ok((layer, guard))
}

fn build_layer(writer: NonBlocking, level: &str) -> Box<dyn Layer<Registry> + Send + Sync> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::new(level);
    // File keeps its own pretty rendering (independent of console LogFormat).
    // TraceIdFormat must still wrap here — missing the appender silently drops keys.
    let layer = fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .map_event_format(crate::format::TraceIdFormat)
        .with_filter(filter);

    Box::new(layer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_create_file_layer_basic() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "test.log".to_string(),
            max_size_mb: 1,
            max_files: 3,
            compress: false,
            level: "info".to_string(),
        };

        let result = create_file_layer(&config);
        assert!(result.is_ok());
        let (_layer, _guard) = result.unwrap();
    }

    #[test]
    fn test_create_file_layer_with_compression() {
        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "test-compress.log".to_string(),
            max_size_mb: 1,
            max_files: 2,
            compress: true,
            level: "debug".to_string(),
        };

        let result = create_file_layer(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_file_layer_writes_log_lines() {
        use tracing_subscriber::prelude::*;

        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "write-test.log".to_string(),
            max_size_mb: 1,
            max_files: 3,
            compress: false,
            level: "info".to_string(),
        };

        let (layer, guard) = create_file_layer(&config).unwrap();

        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("test log line for file appender");
        });

        // Drop guard to flush
        drop(guard);

        // Give non-blocking writer time to flush
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Verify the file was created in the directory
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert!(!entries.is_empty(), "Log file should be created");
    }

    /// File appender keeps its own pretty rendering and must still carry
    /// `trace_id` / `span_id` when TraceIdLayer has cached ids (TRC-2c).
    ///
    /// Goes through production [`create_file_layer`] so removing the
    /// `TraceIdFormat` wrap in `build_layer` turns this test RED.
    #[test]
    fn file_appender_emits_trace_id_keys_inside_sampled_span() {
        use crate::config::TelemetryConfig;
        use crate::init::init_tracing;
        use crate::propagation::inject_trace_context;
        use crate::trace_id::{TraceIdLayer, SPAN_ID_KEY, TRACE_ID_KEY};
        use tracing_subscriber::prelude::*;

        let dir = tempfile::tempdir().unwrap();
        let config = FileAppenderConfig {
            directory: dir.path().to_string_lossy().to_string(),
            filename: "trace-id-test.log".to_string(),
            max_size_mb: 1,
            max_files: 3,
            compress: false,
            level: "info".to_string(),
        };

        let (file_layer, file_guard) = create_file_layer(&config).expect("create_file_layer");
        let tc = TelemetryConfig { sample_rate: 1.0, ..TelemetryConfig::default() };
        let (otel, otel_guard) = init_tracing(&tc).expect("init_tracing");

        // Layered (not Vec): on_register_dispatch reaches TraceIdLayer; on_event
        // order is otel → TraceIdLayer → file so the cache is ready for Format.
        let layered = otel.and_then(TraceIdLayer::new()).and_then(file_layer);
        let subscriber = tracing_subscriber::registry().with(layered);
        let _default = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("file_appender_sampled");
        let _enter = span.enter();
        tracing::info!("file appender correlated event");

        let mut headers = reqwest::header::HeaderMap::new();
        inject_trace_context(&mut headers);
        let tp = headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .expect("inject_trace_context must yield traceparent");
        let injected = tp.split('-').nth(1).expect("trace-id field");

        drop(file_guard);
        std::thread::sleep(std::time::Duration::from_millis(150));

        let path = dir.path().join("trace-id-test.log");
        let contents = fs::read_to_string(&path).unwrap_or_else(|_| {
            // logroller may suffix the name; take any file in the directory.
            let entry = fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .next()
                .expect("log file created");
            fs::read_to_string(entry.path()).expect("read log file")
        });
        let line = contents
            .lines()
            .find(|l| l.contains("file appender correlated event"))
            .expect("correlated event line in file");
        assert!(
            line.contains(TRACE_ID_KEY) && line.contains(SPAN_ID_KEY),
            "file appender must carry both keys; got: {line:?}"
        );
        assert!(
            line.contains(injected),
            "file appender trace_id must match inject_trace_context; got: {line:?}, injected={tp}"
        );

        otel_guard.provider.shutdown().ok();
    }

    #[test]
    fn test_file_appender_config_defaults() {
        let config = FileAppenderConfig {
            directory: "/tmp".to_string(),
            filename: "rvc.log".to_string(),
            max_size_mb: 200,
            max_files: 5,
            compress: false,
            level: "info".to_string(),
        };

        assert_eq!(config.max_size_mb, 200);
        assert_eq!(config.max_files, 5);
        assert!(!config.compress);
    }
}
