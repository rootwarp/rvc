//! Google Cloud Trace export through the OTLP endpoint of the Telemetry API.
//!
//! RED stub: the exporter does not exist yet. The tests below define it.
#![allow(dead_code, unused_imports, unused_variables)]

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use google_cloud_auth::credentials::{CacheableResource, Credentials};
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::Resource;
use tokio::runtime::Handle;

/// OTLP/HTTP traces endpoint of the Google Cloud Telemetry API.
pub const GCP_TRACES_ENDPOINT: &str = "https://telemetry.googleapis.com/v1/traces";

#[derive(Debug)]
struct GcpHttpClient {
    http: reqwest::Client,
    credentials: Credentials,
    runtime: Handle,
}

#[async_trait::async_trait]
impl HttpClient for GcpHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        Ok(Response::new(Bytes::new()))
    }
}

fn build_exporter(
    endpoint: &str,
    credentials: Credentials,
    runtime: Handle,
    project_id: String,
    resource: Resource,
) -> Result<(SpanExporter, Resource)> {
    Err(anyhow!("RED stub"))
}

fn adc_env() -> HashMap<&'static str, String> {
    HashMap::new()
}

async fn detect_project_id(env: &HashMap<&str, String>) -> Option<String> {
    None
}

fn quota_project_id(path: &Path) -> Option<String> {
    None
}

async fn metadata_project_id(host: &str) -> Option<String> {
    None
}

#[cfg(test)]
// The selection test sets GCP_PROJECT. nextest runs each test in its own process.
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use google_cloud_auth::credentials::{CredentialsProvider, EntityTag};
    use google_cloud_auth::errors::CredentialsError;
    use opentelemetry::trace::{Tracer, TracerProvider};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Gives `Bearer test-token`, or `NotModified` when `token` is false.
    #[derive(Debug)]
    struct FakeCredentials {
        token: bool,
    }

    impl CredentialsProvider for FakeCredentials {
        async fn headers(
            &self,
            _: http::Extensions,
        ) -> Result<CacheableResource<HeaderMap>, CredentialsError> {
            if !self.token {
                return Ok(CacheableResource::NotModified);
            }
            let mut data = HeaderMap::new();
            data.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test-token"));
            Ok(CacheableResource::New { entity_tag: EntityTag::new(), data })
        }

        async fn universe_domain(&self) -> Option<String> {
            None
        }
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
            assert_eq!(found.as_deref(), Some(project), "{remove} must win over later sources.");
            vars.remove(remove);
        }
        let found = detect_project_id(&vars).await;
        assert_eq!(found.as_deref(), Some("metadata-p"), "The metadata ID must be trimmed.");
    }

    #[tokio::test]
    async fn metadata_project_id_is_none_for_an_empty_body_or_an_error() {
        let blank = metadata_server(" \n").await;
        assert_eq!(metadata_project_id(&blank.address().to_string()).await, None);
        let missing = MockServer::start().await;
        assert_eq!(metadata_project_id(&missing.address().to_string()).await, None);
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
    async fn gcp_exporter_sends_spans_with_auth_headers_and_the_project_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/traces"))
            .and(header("authorization", "Bearer test-token"))
            .and(header("content-type", "application/x-protobuf"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let endpoint = format!("{}/v1/traces", server.uri());
        let credentials = Credentials::from(FakeCredentials { token: true });
        let resource = Resource::builder_empty().with_service_name("rvc-test").build();
        let (exporter, resource) =
            build_exporter(&endpoint, credentials, Handle::current(), "test-p".into(), resource)
                .expect("build_exporter");

        let flushed = tokio::task::spawn_blocking(move || {
            let provider = SdkTracerProvider::builder()
                .with_resource(resource)
                .with_simple_exporter(exporter)
                .build();
            provider.tracer("test").in_span("gcp-export", |_| {});
            provider.shutdown()
        });
        flushed.await.unwrap().expect("The export must succeed.");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "The exporter must send one request.");
        let body = &requests[0].body;
        for text in [&b"gcp.project_id"[..], b"test-p", b"rvc-test", b"gcp-export"] {
            assert!(body.windows(text.len()).any(|w| w == text), "Body must hold {text:?}.");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gcp_client_fails_when_the_credentials_give_no_headers() {
        let server = MockServer::start().await;
        let client = GcpHttpClient {
            http: reqwest::Client::new(),
            credentials: Credentials::from(FakeCredentials { token: false }),
            runtime: Handle::current(),
        };
        let request = Request::post(server.uri()).body(Bytes::new()).unwrap();
        assert!(client.send_bytes(request).await.is_err(), "No headers must give an error.");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn init_tracing_selects_the_gcp_exporter_with_the_env_project() {
        use crate::config::{ExporterKind, TelemetryConfig};
        unsafe { std::env::set_var("GCP_PROJECT", "env-project") };
        unsafe { std::env::remove_var("GOOGLE_APPLICATION_CREDENTIALS") };
        let config = TelemetryConfig {
            endpoint: String::new(),
            exporter: ExporterKind::Gcp,
            ..Default::default()
        };
        let result = crate::init::init_tracing(&config);
        let env = adc_env();
        unsafe { std::env::remove_var("GCP_PROJECT") };
        assert_eq!(env.get("GCP_PROJECT").map(String::as_str), Some("env-project"));
        let (_layer, guard) = result.expect("Gcp with GCP_PROJECT must initialize.");
        guard.provider.shutdown().ok();
    }
}
