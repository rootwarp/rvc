use tonic::{Request, Response, Status};

use crate::proto::duty_tracker::duty_tracker_server::DutyTracker;
use crate::proto::duty_tracker::{HealthzRequest, HealthzResponse};

#[derive(Debug, Default)]
pub struct DutyTrackerService;

impl DutyTrackerService {
    pub fn new() -> Self {
        Self
    }
}

#[tonic::async_trait]
impl DutyTracker for DutyTrackerService {
    async fn healthz(
        &self,
        _request: Request<HealthzRequest>,
    ) -> Result<Response<HealthzResponse>, Status> {
        tracing::debug!("healthz request received");
        let response = HealthzResponse { status: true };
        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_healthz_returns_healthy_status() {
        let service = DutyTrackerService::new();
        let request = Request::new(HealthzRequest {});

        let response = service.healthz(request).await.unwrap();

        assert!(response.get_ref().status);
    }
}
