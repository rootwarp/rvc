use std::time::Duration;

use beacon::BeaconError;

/// Outcome of a single BN attempt during a broadcast operation.
#[derive(Debug)]
pub struct BnOutcome<T = ()> {
    pub endpoint: String,
    pub result: Result<T, BeaconError>,
    /// Wall-clock duration of this BN attempt (used in partial-failure logs).
    pub latency: Duration,
}

/// Outcome of broadcasting an operation to multiple beacon nodes.
#[derive(Debug)]
pub struct BroadcastResult<T = ()> {
    pub outcomes: Vec<BnOutcome<T>>,
}

impl<T> BroadcastResult<T> {
    pub fn any_success(&self) -> bool {
        self.outcomes.iter().any(|o| o.result.is_ok())
    }

    pub fn all_success(&self) -> bool {
        !self.outcomes.is_empty() && self.outcomes.iter().all(|o| o.result.is_ok())
    }

    pub fn into_result(self) -> Result<T, BeaconError> {
        self.into_result_attributed().map(|(_endpoint, value)| value)
    }

    /// First `Ok` outcome, paired with that beacon node's endpoint.
    ///
    /// Walks outcomes in broadcast order. A partial failure is `Ok`, so a
    /// later node's success does not replace it and failures are not merged.
    /// An empty outcome list is [`BeaconError::NoEligibleBn`].
    pub fn into_result_attributed(self) -> Result<(String, T), BeaconError> {
        let mut last_err = None;
        for outcome in self.outcomes {
            match outcome.result {
                Ok(val) => return Ok((outcome.endpoint, val)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(BeaconError::NoEligibleBn {
            operation: "broadcast".to_string(),
            role: "none".to_string(),
        }))
    }

    pub fn failures(&self) -> Vec<(&str, &BeaconError)> {
        self.outcomes
            .iter()
            .filter_map(|o| o.result.as_ref().err().map(|e| (o.endpoint.as_str(), e)))
            .collect()
    }

    pub fn counts(&self) -> (usize, usize) {
        let ok = self.outcomes.iter().filter(|o| o.result.is_ok()).count();
        (ok, self.outcomes.len() - ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_outcome(endpoint: &str) -> BnOutcome {
        BnOutcome {
            endpoint: endpoint.to_string(),
            result: Ok(()),
            latency: Duration::from_millis(50),
        }
    }

    fn err_outcome(endpoint: &str) -> BnOutcome {
        BnOutcome {
            endpoint: endpoint.to_string(),
            result: Err(BeaconError::ApiError { status: 400, message: "bad request".to_string() }),
            latency: Duration::from_millis(30),
        }
    }

    #[test]
    fn test_all_success() {
        let br =
            BroadcastResult { outcomes: vec![ok_outcome("http://bn1"), ok_outcome("http://bn2")] };
        assert!(br.any_success());
        assert!(br.all_success());
        assert_eq!(br.counts(), (2, 0));
        assert!(br.failures().is_empty());
    }

    #[test]
    fn test_partial_failure() {
        let br =
            BroadcastResult { outcomes: vec![err_outcome("http://bn1"), ok_outcome("http://bn2")] };
        assert!(br.any_success());
        assert!(!br.all_success());
        assert_eq!(br.counts(), (1, 1));
        let failures = br.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "http://bn1");
    }

    #[test]
    fn test_all_fail() {
        let br = BroadcastResult {
            outcomes: vec![err_outcome("http://bn1"), err_outcome("http://bn2")],
        };
        assert!(!br.any_success());
        assert!(!br.all_success());
        assert_eq!(br.counts(), (0, 2));
    }

    #[test]
    fn test_into_result_returns_first_success() {
        let br =
            BroadcastResult { outcomes: vec![err_outcome("http://bn1"), ok_outcome("http://bn2")] };
        assert!(br.into_result().is_ok());
    }

    #[test]
    fn test_into_result_returns_last_error_when_all_fail() {
        let br = BroadcastResult {
            outcomes: vec![err_outcome("http://bn1"), err_outcome("http://bn2")],
        };
        assert!(br.into_result().is_err());
    }

    #[test]
    fn test_into_result_empty_is_typed_error() {
        let br: BroadcastResult<()> = BroadcastResult { outcomes: vec![] };
        assert!(!br.any_success());
        assert!(!br.all_success());
        match br.into_result() {
            Err(BeaconError::NoEligibleBn { operation, role }) => {
                assert_eq!(operation, "broadcast");
                assert_eq!(role, "none");
            }
            other => panic!("expected NoEligibleBn, got {other:?}"),
        }
    }

    #[test]
    fn test_into_result_with_typed_value() {
        let br = BroadcastResult {
            outcomes: vec![
                BnOutcome {
                    endpoint: "http://bn1".to_string(),
                    result: Err(BeaconError::ApiError {
                        status: 500,
                        message: "error".to_string(),
                    }),
                    latency: Duration::from_millis(10),
                },
                BnOutcome {
                    endpoint: "http://bn2".to_string(),
                    result: Ok(42u64),
                    latency: Duration::from_millis(20),
                },
            ],
        };
        assert_eq!(br.into_result().unwrap(), 42u64);
    }

    #[test]
    fn test_into_result_attributed_returns_first_ok_endpoint() {
        let br =
            BroadcastResult { outcomes: vec![err_outcome("http://bn1"), ok_outcome("http://bn2")] };
        let (endpoint, ()) = br.into_result_attributed().unwrap();
        assert_eq!(endpoint, "http://bn2");
    }

    #[test]
    fn test_into_result_attributed_keeps_first_ok_without_merging() {
        use beacon::{IndexedAttestationError, SubmitAttestationResult};

        let br = BroadcastResult {
            outcomes: vec![
                BnOutcome {
                    endpoint: "http://bn1".to_string(),
                    result: Ok(SubmitAttestationResult::PartialFailure {
                        failures: vec![IndexedAttestationError {
                            index: 2,
                            message: "invalid signature".to_string(),
                        }],
                    }),
                    latency: Duration::from_millis(10),
                },
                BnOutcome {
                    endpoint: "http://bn2".to_string(),
                    result: Ok(SubmitAttestationResult::Success),
                    latency: Duration::from_millis(20),
                },
            ],
        };
        let (endpoint, result) = br.into_result_attributed().unwrap();
        assert_eq!(endpoint, "http://bn1");
        match result {
            SubmitAttestationResult::PartialFailure { failures } => {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].index, 2);
            }
            other => panic!("expected the first Ok partial failure, got {other:?}"),
        }
    }

    #[test]
    fn test_into_result_attributed_empty_is_typed_error() {
        let br: BroadcastResult<()> = BroadcastResult { outcomes: vec![] };
        match br.into_result_attributed() {
            Err(BeaconError::NoEligibleBn { operation, role }) => {
                assert_eq!(operation, "broadcast");
                assert_eq!(role, "none");
            }
            other => panic!("expected NoEligibleBn, got {other:?}"),
        }
    }
}
