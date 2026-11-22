//! Google Cloud Trace export through the OTLP endpoint of the Telemetry API.
//!
//! The exporter sends OTLP/HTTP protobuf to [`GCP_TRACES_ENDPOINT`]. It gets
//! the auth headers from Application Default Credentials (ADC) for each
//! request, and it adds the `gcp.project_id` resource attribute.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Result};
use google_cloud_auth::credentials::{Builder, CacheableResource, Credentials};
use opentelemetry::KeyValue;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

/// OTLP/HTTP traces endpoint of the Google Cloud Telemetry API.
pub const GCP_TRACES_ENDPOINT: &str = "https://telemetry.googleapis.com/v1/traces";

/// Environment variables that give the project ID, in priority order.
const PROJECT_ENV_VARS: [&str; 3] = ["GCP_PROJECT", "PROJECT_ID", "GCP_PROJECT_ID"];
const METADATA_TIMEOUT: Duration = Duration::from_secs(3);
/// The deadline for the ADC token request and the trace request together.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Sends each OTLP request on the Tokio runtime with the ADC auth headers.
///
/// The batch span processor exports on its own thread with no Tokio reactor.
/// Thus the client runs the token fetch and the request on `runtime`. At the
/// [`EXPORT_TIMEOUT`] deadline, the task drops the two requests. If the caller
/// drops the export first, [`AbortOnDrop`] stops the task.
#[derive(Debug)]
struct GcpHttpClient {
    http: reqwest::Client,
    credentials: Credentials,
    runtime: Handle,
}

/// Aborts the task when the caller drops the future that awaits it.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[async_trait::async_trait]
impl HttpClient for GcpHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (http, credentials) = (self.http.clone(), self.credentials.clone());
        let send = async move {
            let mut request = request;
            match credentials.headers(Default::default()).await? {
                CacheableResource::New { data, .. } => request.headers_mut().extend(data),
                CacheableResource::NotModified => return Err("ADC gave no auth headers".into()),
            }
            let response = http.execute(request.try_into()?).await?;
            let status = response.status();
            Ok(Response::builder().status(status).body(response.bytes().await?)?)
        };
        let task = self.runtime.spawn(async { tokio::time::timeout(EXPORT_TIMEOUT, send).await });
        let mut task = AbortOnDrop(task);
        match (&mut task.0).await? {
            Ok(response) => response,
            Err(_) => Err("the ADC token and trace requests did not end in 10 s".into()),
        }
    }
}

/// Builds the Cloud Trace span exporter and adds `gcp.project_id` to `resource`.
///
/// Must run on a multi-thread Tokio runtime.
pub(crate) fn exporter(resource: Resource) -> Result<(SpanExporter, Resource)> {
    let runtime = Handle::try_current().map_err(|e| anyhow!("GCP exporter needs Tokio: {e}"))?;
    let env = adc_env();
    let project_id = tokio::task::block_in_place(|| runtime.block_on(detect_project_id(&env)))
        .ok_or_else(|| {
            anyhow!(
                "GCP project ID detection failed: set GCP_PROJECT, PROJECT_ID or GCP_PROJECT_ID"
            )
        })?;
    let (endpoint, credentials) = destination()?;
    build_exporter(&endpoint, credentials, runtime, project_id, resource)
}

/// Returns the production endpoint and the ADC credentials.
fn destination() -> Result<(String, Credentials)> {
    #[cfg(test)]
    if let Some(local) = tests::DESTINATION.lock().unwrap_or_else(|e| e.into_inner()).take() {
        return Ok(local);
    }
    // google-cloud-auth uses reqwest with no TLS provider. Use ring, as the workspace does.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let credentials =
        Builder::default().build().map_err(|e| anyhow!("GCP credentials failed: {e}"))?;
    Ok((GCP_TRACES_ENDPOINT.to_owned(), credentials))
}

fn build_exporter(
    endpoint: &str,
    credentials: Credentials,
    runtime: Handle,
    project_id: String,
    resource: Resource,
) -> Result<(SpanExporter, Resource)> {
    let http = reqwest::Client::builder()
        .timeout(opentelemetry_otlp::OTEL_EXPORTER_OTLP_TIMEOUT_DEFAULT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_http_client(GcpHttpClient { http, credentials, runtime })
        .build()?;
    let resource = Resource::builder_empty()
        .with_attributes(resource.iter().map(|(k, v)| KeyValue::new(k.clone(), v.clone())))
        .with_attribute(KeyValue::new("gcp.project_id", project_id))
        .build();
    Ok((exporter, resource))
}

/// Reads the environment variables that gcloud-sdk read for the project ID.
/// Each name is a literal, thus the env allow-list gate can classify it.
fn adc_env() -> HashMap<&'static str, String> {
    [
        ("GCP_PROJECT", std::env::var("GCP_PROJECT")),
        ("PROJECT_ID", std::env::var("PROJECT_ID")),
        ("GCP_PROJECT_ID", std::env::var("GCP_PROJECT_ID")),
        ("GOOGLE_APPLICATION_CREDENTIALS", std::env::var("GOOGLE_APPLICATION_CREDENTIALS")),
        ("HOME", std::env::var("HOME")),
        ("GCE_METADATA_HOST", std::env::var("GCE_METADATA_HOST")),
    ]
    .into_iter()
    .filter_map(|(name, value)| Some((name, value.ok()?)))
    .collect()
}

/// Finds the project ID in the order of the removed gcloud-sdk exporter:
///
/// 1. The first of [`PROJECT_ENV_VARS`] that is set.
/// 2. `quota_project_id` in the ADC file: `GOOGLE_APPLICATION_CREDENTIALS`,
///    else `$HOME/.config/gcloud/application_default_credentials.json`.
/// 3. The metadata server (`GCE_METADATA_HOST`, else `metadata.google.internal`).
async fn detect_project_id(env: &HashMap<&str, String>) -> Option<String> {
    if let Some(id) = PROJECT_ENV_VARS.iter().find_map(|name| env.get(name)) {
        return Some(id.clone());
    }
    let adc = env.get("GOOGLE_APPLICATION_CREDENTIALS").cloned().or_else(|| {
        let home = env.get("HOME")?;
        Some(format!("{home}/.config/gcloud/application_default_credentials.json"))
    });
    if let Some(id) = adc.and_then(|path| quota_project_id(Path::new(&path))) {
        return Some(id);
    }
    metadata_project_id(metadata_host(env)).await
}

fn metadata_host<'a>(env: &'a HashMap<&str, String>) -> &'a str {
    env.get("GCE_METADATA_HOST").map_or("metadata.google.internal", String::as_str)
}

fn quota_project_id(path: &Path) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    json.get("quota_project_id")?.as_str().map(str::to_owned)
}

async fn metadata_project_id(host: &str) -> Option<String> {
    let response = reqwest::Client::new()
        .get(format!("http://{host}/computeMetadata/v1/project/project-id"))
        .header("Metadata-Flavor", "Google")
        .timeout(METADATA_TIMEOUT)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    let id = response.text().await.ok()?.trim().to_owned();
    (!id.is_empty()).then_some(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use google_cloud_auth::credentials::{CredentialsProvider, EntityTag};
    use google_cloud_auth::errors::CredentialsError;
    use opentelemetry::trace::{Tracer, TracerProvider};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// When set, the `gcp` exporter uses this endpoint and these credentials one time.
    pub(crate) static DESTINATION: Mutex<Option<(String, Credentials)>> = Mutex::new(None);

    /// The fake ADC source has three modes:
    ///
    /// - `Tokens` gives `Bearer token-N` for call N and a quota header.
    /// - `NoHeaders` gives `NotModified`.
    /// - `Stall` does not answer. Each waiting call holds one more reference to the `Arc`.
    #[derive(Debug)]
    enum FakeCredentials {
        Tokens(AtomicUsize),
        NoHeaders,
        Stall(Arc<()>),
    }

    impl FakeCredentials {
        fn tokens() -> Credentials {
            Credentials::from(Self::Tokens(AtomicUsize::new(0)))
        }
    }

    impl CredentialsProvider for FakeCredentials {
        async fn headers(
            &self,
            _: http::Extensions,
        ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
            let call = match self {
                Self::Tokens(calls) => calls.fetch_add(1, Ordering::SeqCst) + 1,
                Self::NoHeaders => return Ok(CacheableResource::NotModified),
                Self::Stall(waiting) => {
                    let _call = Arc::clone(waiting);
                    std::future::pending().await
                }
            };
            let mut data = HeaderMap::new();
            data.insert(AUTHORIZATION, format!("Bearer token-{call}").parse().unwrap());
            data.insert("x-goog-user-project", HeaderValue::from_static("quota-p"));
            Ok(CacheableResource::New { entity_tag: EntityTag::new(), data })
        }

        async fn universe_domain(&self) -> Option<String> {
            None
        }
    }

    fn contains(body: &[u8], text: &str) -> bool {
        body.windows(text.len()).any(|w| w == text.as_bytes())
    }

    async fn metadata_server(body: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/computeMetadata/v1/project/project-id"))
            .and(header("Metadata-Flavor", "Google"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        server
    }

    fn adc_file(dir: &Path, name: &str, quota_project: &str) -> String {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!(r#"{{"quota_project_id":"{quota_project}"}}"#)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn production_destinations_use_tls_and_the_google_hosts() {
        assert_eq!(GCP_TRACES_ENDPOINT, "https://telemetry.googleapis.com/v1/traces");
        assert_eq!(metadata_host(&HashMap::new()), "metadata.google.internal");
    }

    #[tokio::test]
    async fn detect_project_id_uses_env_then_adc_file_then_metadata_server() {
        let home = tempfile::tempdir().unwrap();
        adc_file(home.path(), ".config/gcloud/application_default_credentials.json", "home-p");
        let named = adc_file(home.path(), "named.json", "named-p");
        let server = metadata_server(" metadata-p\n").await;
        let mut vars = HashMap::from([
            ("GCP_PROJECT", "gcp-project".to_string()),
            ("PROJECT_ID", "project-id".to_string()),
            ("GCP_PROJECT_ID", "gcp-project-id".to_string()),
            ("GOOGLE_APPLICATION_CREDENTIALS", named),
            ("HOME", home.path().to_string_lossy().into_owned()),
            ("GCE_METADATA_HOST", server.address().to_string()),
        ]);
        for (remove, project) in [
            ("GCP_PROJECT", "gcp-project"),
            ("PROJECT_ID", "project-id"),
            ("GCP_PROJECT_ID", "gcp-project-id"),
            ("GOOGLE_APPLICATION_CREDENTIALS", "named-p"),
            ("HOME", "home-p"),
        ] {
            let found = detect_project_id(&vars).await;
            assert_eq!(
                found.as_deref(),
                Some(project),
                "{remove} must take priority over later sources."
            );
            vars.remove(remove);
        }
        let found = detect_project_id(&vars).await;
        assert_eq!(
            found.as_deref(),
            Some("metadata-p"),
            "The reader must remove whitespace around the metadata ID."
        );
    }

    #[tokio::test]
    async fn metadata_project_id_is_none_for_an_empty_body_or_an_error() {
        let blank = metadata_server(" \n").await;
        assert_eq!(metadata_project_id(&blank.address().to_string()).await, None);
        let missing = MockServer::start().await;
        assert_eq!(metadata_project_id(&missing.address().to_string()).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn metadata_project_id_stops_at_the_deadline() {
        let server = MockServer::start().await;
        let late = ResponseTemplate::new(200).set_body_string("late-p");
        Mock::given(method("GET"))
            .respond_with(late.set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let start = tokio::time::Instant::now();
        let found = metadata_project_id(&server.address().to_string()).await;
        assert_eq!(found, None, "A late metadata answer must give no project ID.");
        assert_eq!(start.elapsed(), Duration::from_secs(3), "The metadata deadline must be 3 s.");
    }

    #[test]
    fn quota_project_id_is_none_without_the_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("adc.json");
        std::fs::write(&path, r#"{"type":"authorized_user"}"#).unwrap();
        assert_eq!(quota_project_id(&path), None);
        assert_eq!(quota_project_id(&dir.path().join("absent.json")), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gcp_exporter_sends_the_project_id_and_does_not_follow_a_redirect() {
        let server = MockServer::start().await;
        let redirect = ResponseTemplate::new(307).insert_header("location", "/moved");
        Mock::given(path("/v1/traces")).respond_with(redirect).mount(&server).await;
        Mock::given(path("/moved")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let endpoint = format!("{}/v1/traces", server.uri());
        let credentials = FakeCredentials::tokens();
        let resource = Resource::builder_empty().with_service_name("rvc-test").build();
        let (exporter, resource) =
            build_exporter(&endpoint, credentials, Handle::current(), "test-p".into(), resource)
                .expect("The exporter must initialize.");

        let flushed = tokio::task::spawn_blocking(move || {
            let provider = SdkTracerProvider::builder()
                .with_resource(resource)
                .with_simple_exporter(exporter)
                .build();
            provider.tracer("test").in_span("gcp-export", |_| {});
            provider.shutdown()
        });
        flushed.await.unwrap().expect("The shutdown must succeed.");

        let requests = server.received_requests().await.unwrap();
        let paths: Vec<&str> = requests.iter().map(|r| r.url.path()).collect();
        assert_eq!(paths, ["/v1/traces"], "The exporter must not follow a redirect.");
        for text in ["gcp.project_id", "test-p", "rvc-test", "gcp-export"] {
            assert!(contains(&requests[0].body, text), "The request body must contain {text:?}.");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gcp_client_fails_when_the_credentials_give_no_headers() {
        let server = MockServer::start().await;
        let client = GcpHttpClient {
            http: reqwest::Client::new(),
            credentials: Credentials::from(FakeCredentials::NoHeaders),
            runtime: Handle::current(),
        };
        let request = Request::post(server.uri()).body(Bytes::new()).unwrap();
        assert!(client.send_bytes(request).await.is_err(), "No headers must give an error.");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Gives a client with `Stall` credentials. The count of `waiting` is 2 when no
    /// credential request waits, and 3 when one request waits.
    fn stalled_client(waiting: &Arc<()>) -> GcpHttpClient {
        GcpHttpClient {
            http: reqwest::Client::new(),
            credentials: Credentials::from(FakeCredentials::Stall(Arc::clone(waiting))),
            runtime: Handle::current(),
        }
    }

    fn trace_request() -> Request<Bytes> {
        Request::post("http://127.0.0.1:9/v1/traces").body(Bytes::new()).unwrap()
    }

    /// The test has no outer timeout. It examines the request at two points of
    /// paused time. Thus, without the deadline, an assertion fails.
    #[tokio::test(start_paused = true)]
    async fn gcp_client_stops_a_stalled_credential_request_at_the_deadline() {
        let waiting = Arc::new(());
        let client = Arc::new(stalled_client(&waiting));
        let caller = Arc::clone(&client);
        let start = tokio::time::Instant::now();
        let sent = tokio::spawn(async move {
            let failed = caller.send_bytes(trace_request()).await.is_err();
            (failed, start.elapsed())
        });
        tokio::time::sleep_until(start + Duration::from_millis(9_999)).await;
        let count = Arc::strong_count(&waiting);
        assert_eq!(count, 3, "The credential request must continue at 9.999 s.");
        tokio::time::sleep_until(start + Duration::from_millis(10_001)).await;
        let count = Arc::strong_count(&waiting);
        assert_eq!(count, 2, "The deadline must stop the credential request.");
        assert!(sent.is_finished(), "The client must return at the deadline.");
        let (failed, elapsed) = sent.await.unwrap();
        assert!(failed, "A stall must give an error.");
        assert_eq!(elapsed, Duration::from_secs(10), "The export deadline must be 10 s.");
    }

    /// The caller drops the export at 1 s. The deadline is at 10 s.
    #[tokio::test(start_paused = true)]
    async fn gcp_client_stops_the_credential_request_when_the_caller_cancels() {
        let waiting = Arc::new(());
        let client = stalled_client(&waiting);
        let mut sent = client.send_bytes(trace_request());
        let early = tokio::time::timeout(Duration::from_secs(1), &mut sent).await;
        assert!(early.is_err(), "The stalled export must not return in 1 s.");
        let count = Arc::strong_count(&waiting);
        assert_eq!(count, 3, "The credential request must continue at 1 s.");
        drop(sent);
        tokio::time::sleep(Duration::from_millis(1)).await;
        let count = Arc::strong_count(&waiting);
        assert_eq!(count, 2, "When the caller drops the export, the request must stop.");
    }

    /// The test runs the child test below in a new process with a set environment.
    /// Thus this process does not change its own environment.
    #[test]
    fn init_tracing_selects_the_gcp_exporter_with_the_env_project() {
        let child = "gcp::tests::gcp_child_exports_two_batches_with_new_adc_headers";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([child, "--exact", "--ignored", "--nocapture"])
            .env("GCP_PROJECT", "env-project")
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/adc.json")
            .output()
            .expect("The test binary must start.");
        let text = String::from_utf8_lossy(&[output.stdout, output.stderr].concat()).into_owned();
        assert!(output.status.success(), "The child test must pass:\n{text}");
        assert!(text.contains("1 passed"), "The child test must run:\n{text}");
        assert!(!text.contains("token-"), "The output must not contain a credential:\n{text}");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "init_tracing_selects_the_gcp_exporter_with_the_env_project runs this test"]
    async fn gcp_child_exports_two_batches_with_new_adc_headers() {
        use crate::config::{ExporterKind, TelemetryConfig};
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let local = (format!("{}/v1/traces", server.uri()), FakeCredentials::tokens());
        *DESTINATION.lock().unwrap() = Some(local);
        let config = TelemetryConfig { exporter: ExporterKind::Gcp, ..Default::default() };
        let (_layer, guard) = crate::init::init_tracing(&config).expect("The exporter must start.");
        let provider = guard.provider.clone();
        let exported = tokio::task::spawn_blocking(move || {
            for name in ["batch-1", "batch-2"] {
                provider.tracer("test").in_span(name, |_| {});
                provider.force_flush()?;
            }
            provider.shutdown()
        });
        exported.await.unwrap().expect("The two exports must succeed.");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2, "The exporter must send one request for each flush.");
        for (request, n) in requests.iter().zip(1..) {
            let header = |name: &str| request.headers.get(name).and_then(|v| v.to_str().ok());
            assert_eq!(request.method, "POST", "Request {n} must be a POST.");
            assert_eq!(request.url.path(), "/v1/traces", "Request {n} must use the trace path.");
            let token = format!("Bearer token-{n}");
            for (name, value) in [
                ("content-type", "application/x-protobuf"),
                ("authorization", token.as_str()),
                ("x-goog-user-project", "quota-p"),
            ] {
                assert!(header(name) == Some(value), "Request {n} must have {name}: {value}.");
            }
            for text in ["gcp.project_id", "env-project", &format!("batch-{n}")] {
                assert!(contains(&request.body, text), "Request {n} must contain {text:?}.");
            }
        }
    }
}
