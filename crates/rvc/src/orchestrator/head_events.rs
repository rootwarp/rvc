//! Latest-wins head-event bridge (ARCH-3l / C7).
//!
//! ADR-013 said the trigger "adds no channel" and would consume the existing
//! `mpsc(64)` inside `subscribe_events`. That callback is sync (`Fn(SseEvent)`),
//! so a bridge is required (VD-33). `watch` is bounded (one slot); `send_replace`
//! never blocks; losing an intermediate value is the C7 policy.

use std::sync::Arc;
use std::time::Duration;

use bn_manager::{HeadEvent, SseEvent};
use eth_types::Slot;
use metrics::definitions::RVC_SSE_EVENTS_DROPPED_TOTAL;

use crate::metrics::{attestation_trigger_source, RVC_ATTESTATION_TRIGGER_TOTAL};
use tokio::sync::watch;

/// Why [`HeadEventGate::wait_for_head_or`] returned: 1/3-slot timer or head event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerReason {
    Timer,
    HeadEvent,
}

/// Producer half of the SSE → orchestrator bridge. `publish` is the sync callback.
pub struct HeadEventBridge {
    tx: watch::Sender<Option<HeadEvent>>,
}

impl HeadEventBridge {
    /// Publish a head event. Non-head events are ignored. Never blocks, never
    /// panics if every receiver has been dropped (C7 / C9).
    pub fn publish(&self, event: SseEvent) {
        let SseEvent::Head(head) = event else {
            return;
        };
        let previous = self.tx.send_replace(Some(head));
        // Latest-wins: a superseded head is a C7 drop, not a failure.
        if previous.is_some() {
            record_expected_sse_drop();
        }
    }

    /// Convert into the `Fn(SseEvent)` `BnManager::start_sse` expects.
    pub fn into_callback(self) -> impl Fn(SseEvent) + Send + Sync + 'static {
        move |event| self.publish(event)
    }
}

/// Consumer half. ARCH-3i/3m call [`Self::wait_for_head_or`].
#[derive(Clone)]
pub struct HeadEventGate {
    rx: watch::Receiver<Option<HeadEvent>>,
    entered: Arc<parking_lot::Mutex<Option<Slot>>>,
}

impl HeadEventGate {
    /// Build a connected bridge/gate pair.
    pub fn pair() -> (HeadEventBridge, Self) {
        let (tx, rx) = watch::channel(None);
        (HeadEventBridge { tx }, Self { rx, entered: Arc::new(parking_lot::Mutex::new(None)) })
    }

    /// 1/3-slot timer or a matching head event, whichever first.
    ///
    /// The timer arm alone is sufficient: an empty or dropped bridge waits out
    /// `timer`. Events for another slot, or for a slot already entered, are
    /// ignored so they cannot pull phase 2 forward twice or for the wrong slot.
    ///
    /// `wait_for` evaluates the **current** watch value even when the parent
    /// receiver has already marked it seen. SSE head for slot N usually lands
    /// at t≈0, before this wait is armed; `changed()`-only would miss that.
    pub async fn wait_for_head_or(&self, slot: Slot, timer: Duration) -> TriggerReason {
        self.wait_for_head_or_deadline(slot, tokio::time::Instant::now() + timer).await
    }

    /// [`Self::wait_for_head_or`] against an absolute tokio deadline.
    pub(crate) async fn wait_for_head_or_deadline(
        &self,
        slot: Slot,
        deadline: tokio::time::Instant,
    ) -> TriggerReason {
        let mut rx = self.rx.clone();
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);

        let reason = tokio::select! {
            _ = &mut sleep => TriggerReason::Timer,
            // Map `watch::Ref` away before any further await (`Ref` is !Send).
            result = async {
                rx.wait_for(|ev| event_matches(ev, slot) && !self.already_entered(slot))
                    .await
                    .map(drop)
            } => {
                if result.is_err() {
                    // SSE sender gone: C7 — wait out the timer, never error.
                    sleep.await;
                    TriggerReason::Timer
                } else {
                    TriggerReason::HeadEvent
                }
            }
        };

        self.mark_entered(slot);
        record_trigger(reason);
        reason
    }

    /// Latest published head, if any.
    pub fn latest(&self) -> Option<HeadEvent> {
        self.rx.borrow().clone()
    }

    fn already_entered(&self, slot: Slot) -> bool {
        *self.entered.lock() == Some(slot)
    }

    fn mark_entered(&self, slot: Slot) {
        *self.entered.lock() = Some(slot);
    }
}

fn event_matches(ev: &Option<HeadEvent>, slot: Slot) -> bool {
    ev.as_ref().and_then(|head| head.slot.parse().ok()) == Some(slot)
}

fn record_trigger(reason: TriggerReason) {
    let source = match reason {
        TriggerReason::Timer => attestation_trigger_source::TIMER,
        TriggerReason::HeadEvent => attestation_trigger_source::HEAD_EVENT,
    };
    RVC_ATTESTATION_TRIGGER_TOTAL.with_label_values(&[source]).inc();
}

/// Increment `rvc_sse_events_dropped_total{expected="true"}`. Never an error path.
pub fn record_expected_sse_drop() {
    RVC_SSE_EVENTS_DROPPED_TOTAL.inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::OnceLock;
    use std::time::Instant;

    use metrics::definitions::RVC_MONITORING_PUSH_FAILURES_TOTAL;

    use crate::metrics::{
        attestation_status, attestation_trigger_source, RVC_ATTESTATIONS_TOTAL,
        RVC_ATTESTATION_TRIGGER_TOTAL,
    };
    use tokio::sync::{Mutex, MutexGuard};
    use tracing_test::traced_test;

    const ATT_TIMER: Duration = Duration::from_secs(4);

    /// Process-wide trigger vec; serialize every wait / delta assertion.
    async fn trigger_metric_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().await
    }

    fn trigger_count(source: &str) -> u64 {
        RVC_ATTESTATION_TRIGGER_TOTAL.with_label_values(&[source]).get()
    }

    async fn poll_pending<F>(fut: &mut std::pin::Pin<&mut F>)
    where
        F: Future,
    {
        tokio::select! {
            biased;
            _ = fut.as_mut() => panic!("wait must stay pending before the winning arm"),
            _ = tokio::task::yield_now() => {}
        }
    }

    async fn try_complete<F>(fut: &mut std::pin::Pin<&mut F>) -> Option<F::Output>
    where
        F: Future,
    {
        tokio::select! {
            biased;
            out = fut.as_mut() => Some(out),
            _ = tokio::task::yield_now() => None,
        }
    }

    fn sample_head(slot: &str) -> HeadEvent {
        HeadEvent {
            slot: slot.to_string(),
            block: "0xab".to_string(),
            state: "0xcd".to_string(),
            epoch_transition: false,
            previous_duty_dependent_root: "0x00".to_string(),
            current_duty_dependent_root: "0x01".to_string(),
            execution_optimistic: false,
        }
    }

    #[test]
    fn test_head_event_bridge_publishes_the_latest_event() {
        let (bridge, gate) = HeadEventGate::pair();
        let first = sample_head("10");
        let second = sample_head("11");

        let start = Instant::now();
        bridge.publish(SseEvent::Head(first));
        bridge.publish(SseEvent::Head(second.clone()));
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "watch send_replace must not block the SSE callback"
        );

        let latest = gate.latest().expect("watch must hold an event");
        assert_eq!(latest.slot, second.slot);
        assert_eq!(latest.block, second.block);
    }

    #[tokio::test]
    async fn test_wait_for_head_or_is_timer_only() {
        let _guard = trigger_metric_lock().await;
        let (bridge, gate) = HeadEventGate::pair();
        bridge.publish(SseEvent::Head(sample_head("99")));

        let reason = tokio::time::timeout(
            Duration::from_millis(200),
            gate.wait_for_head_or(1, Duration::from_millis(10)),
        )
        .await
        .expect("timer-only wait must resolve");
        assert_eq!(reason, TriggerReason::Timer, "a head event for another slot must not win");
    }

    #[test]
    #[traced_test]
    fn test_bridge_send_never_blocks_the_sse_callback() {
        let (bridge, gate) = HeadEventGate::pair();
        drop(gate);

        let start = Instant::now();
        bridge.publish(SseEvent::Head(sample_head("1")));
        bridge.publish(SseEvent::Head(sample_head("2")));
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "no-receiver send_replace must return promptly"
        );
        assert!(!logs_contain("ERROR"), "C7: no-receiver must not error-log");
    }

    #[test]
    #[traced_test]
    fn test_sse_drop_counter_is_labelled_expected() {
        let before = RVC_SSE_EVENTS_DROPPED_TOTAL.get();
        let (bridge, gate) = HeadEventGate::pair();

        bridge.publish(SseEvent::Head(sample_head("1")));
        assert_eq!(
            RVC_SSE_EVENTS_DROPPED_TOTAL.get(),
            before,
            "first published head is not a drop"
        );
        bridge.publish(SseEvent::Head(sample_head("2")));

        assert!(
            RVC_SSE_EVENTS_DROPPED_TOTAL.get() > before,
            "latest-wins overwrite with a live gate is an expected-path drop"
        );
        assert_eq!(gate.latest().expect("live gate").slot, "2");
        assert!(!logs_contain("ERROR"), "C7: drop must not error-log");

        let gathered = metrics::REGISTRY.gather();
        let mf = gathered
            .iter()
            .find(|m| m.name() == "rvc_sse_events_dropped_total")
            .expect("rvc_sse_events_dropped_total must be registered");
        for metric in mf.get_metric() {
            let has_expected =
                metric.get_label().iter().any(|l| l.name() == "expected" && l.value() == "true");
            assert!(has_expected, "drop counter must be labelled expected=\"true\"");
            assert!(
                !metric.get_label().iter().any(|l| l.name() == "expected" && l.value() != "true"),
                "drop counter must not carry a non-expected label"
            );
        }
        assert!(
            !gathered.iter().any(|m| {
                let n = m.name();
                n.contains("sse") && (n.contains("fail") || n.contains("error"))
            }),
            "C7: no SSE failure/error metric on drop"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_early_head_event_triggers_the_attestation_sooner() {
        let _guard = trigger_metric_lock().await;
        let (bridge, gate) = HeadEventGate::pair();
        let before_head = trigger_count(attestation_trigger_source::HEAD_EVENT);
        let before_timer = trigger_count(attestation_trigger_source::TIMER);

        let wait = gate.wait_for_head_or(10, ATT_TIMER);
        tokio::pin!(wait);
        poll_pending(&mut wait).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        bridge.publish(SseEvent::Head(sample_head("10")));

        let reason = try_complete(&mut wait)
            .await
            .expect("matching head event at t=1s must beat the 4s timer");
        assert_eq!(reason, TriggerReason::HeadEvent);
        assert_eq!(trigger_count(attestation_trigger_source::HEAD_EVENT), before_head + 1);
        assert_eq!(trigger_count(attestation_trigger_source::TIMER), before_timer);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_dropping_every_head_event_still_attests_on_the_timer() {
        let _guard = trigger_metric_lock().await;
        let (bridge, gate) = HeadEventGate::pair();
        drop(bridge);
        let before_timer = trigger_count(attestation_trigger_source::TIMER);
        let before_head = trigger_count(attestation_trigger_source::HEAD_EVENT);

        const N: Slot = 3;
        for slot in 1..=N {
            let wait = gate.wait_for_head_or(slot, ATT_TIMER);
            tokio::pin!(wait);
            poll_pending(&mut wait).await;
            tokio::time::advance(ATT_TIMER).await;
            let reason = wait.await;
            assert_eq!(
                reason,
                TriggerReason::Timer,
                "slot {slot}: dropped events must not skip or fail the timer"
            );
        }

        assert_eq!(trigger_count(attestation_trigger_source::TIMER), before_timer + N);
        assert_eq!(trigger_count(attestation_trigger_source::HEAD_EVENT), before_head);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_early_head_event_does_not_produce_a_duplicate_attestation() {
        let _guard = trigger_metric_lock().await;
        let (bridge, gate) = HeadEventGate::pair();
        let before_head = trigger_count(attestation_trigger_source::HEAD_EVENT);
        let before_timer = trigger_count(attestation_trigger_source::TIMER);

        let wait = gate.wait_for_head_or(10, ATT_TIMER);
        tokio::pin!(wait);
        poll_pending(&mut wait).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        bridge.publish(SseEvent::Head(sample_head("10")));

        let reason = try_complete(&mut wait)
            .await
            .expect("matching head at t=1s must win without waiting out the timer");
        assert_eq!(reason, TriggerReason::HeadEvent);
        let after_first_head = trigger_count(attestation_trigger_source::HEAD_EVENT);
        let after_first_timer = trigger_count(attestation_trigger_source::TIMER);
        assert_eq!(after_first_head, before_head + 1);
        assert_eq!(after_first_timer, before_timer);

        let wait_again = gate.wait_for_head_or(10, ATT_TIMER);
        tokio::pin!(wait_again);
        poll_pending(&mut wait_again).await;
        bridge.publish(SseEvent::Head(sample_head("10")));
        assert!(
            try_complete(&mut wait_again).await.is_none(),
            "a further event for an already-entered slot must not re-trigger"
        );
        tokio::time::advance(ATT_TIMER).await;
        assert_eq!(wait_again.await, TriggerReason::Timer);
        assert_eq!(
            trigger_count(attestation_trigger_source::HEAD_EVENT),
            after_first_head,
            "duplicate suppression must not count a second head_event"
        );
        assert_eq!(trigger_count(attestation_trigger_source::TIMER), after_first_timer + 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_head_event_for_another_slot_is_ignored() {
        let _guard = trigger_metric_lock().await;
        let (bridge, gate) = HeadEventGate::pair();
        let before_head = trigger_count(attestation_trigger_source::HEAD_EVENT);

        let wait = gate.wait_for_head_or(10, ATT_TIMER);
        tokio::pin!(wait);
        poll_pending(&mut wait).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        bridge.publish(SseEvent::Head(sample_head("9")));
        assert!(
            try_complete(&mut wait).await.is_none(),
            "a head event for another slot must not enter phase 2"
        );

        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(wait.await, TriggerReason::Timer);
        assert_eq!(trigger_count(attestation_trigger_source::HEAD_EVENT), before_head);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_pre_published_head_event_triggers_without_waiting() {
        let _guard = trigger_metric_lock().await;
        let (bridge, mut gate) = HeadEventGate::pair();
        let before_head = trigger_count(attestation_trigger_source::HEAD_EVENT);
        let before_timer = trigger_count(attestation_trigger_source::TIMER);

        bridge.publish(SseEvent::Head(sample_head("10")));
        // SSE at t≈0 marks the stored receiver seen; wait must still consume latest.
        let _ = gate.rx.borrow_and_update();

        let reason = gate.wait_for_head_or(10, ATT_TIMER).await;
        assert_eq!(reason, TriggerReason::HeadEvent);
        assert_eq!(trigger_count(attestation_trigger_source::HEAD_EVENT), before_head + 1);
        assert_eq!(trigger_count(attestation_trigger_source::TIMER), before_timer);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_stale_head_then_matching_head_event_triggers() {
        let _guard = trigger_metric_lock().await;
        let (bridge, mut gate) = HeadEventGate::pair();
        let before_head = trigger_count(attestation_trigger_source::HEAD_EVENT);
        let before_timer = trigger_count(attestation_trigger_source::TIMER);

        bridge.publish(SseEvent::Head(sample_head("9")));
        let _ = gate.rx.borrow_and_update();

        let wait = gate.wait_for_head_or(10, ATT_TIMER);
        tokio::pin!(wait);
        assert!(
            try_complete(&mut wait).await.is_none(),
            "a leftover head for another slot must not enter phase 2"
        );

        bridge.publish(SseEvent::Head(sample_head("10")));
        let reason =
            try_complete(&mut wait).await.expect("a later matching head must beat the timer");
        assert_eq!(reason, TriggerReason::HeadEvent);
        assert_eq!(trigger_count(attestation_trigger_source::HEAD_EVENT), before_head + 1);
        assert_eq!(trigger_count(attestation_trigger_source::TIMER), before_timer);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    #[traced_test]
    async fn test_no_error_log_or_failure_metric_on_drop_or_failover() {
        let _guard = trigger_metric_lock().await;
        let failed_before =
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get();
        let push_fail_before = RVC_MONITORING_PUSH_FAILURES_TOTAL.get();

        let (bridge, gate) = HeadEventGate::pair();
        {
            let wait = gate.wait_for_head_or(7, ATT_TIMER);
            tokio::pin!(wait);
            poll_pending(&mut wait).await;
        }

        bridge.publish(SseEvent::Head(sample_head("7")));
        bridge.publish(SseEvent::Head(sample_head("8")));
        drop(bridge);

        let wait_after = gate.wait_for_head_or(9, ATT_TIMER);
        tokio::pin!(wait_after);
        poll_pending(&mut wait_after).await;
        tokio::time::advance(ATT_TIMER).await;
        assert_eq!(wait_after.await, TriggerReason::Timer);

        assert!(!logs_contain("ERROR"), "C7: drop/failover must not error-log");
        assert_eq!(
            RVC_ATTESTATIONS_TOTAL.with_label_values(&[attestation_status::FAILED]).get(),
            failed_before,
            "C7: drop/failover must not increment attestation failures"
        );
        assert_eq!(
            RVC_MONITORING_PUSH_FAILURES_TOTAL.get(),
            push_fail_before,
            "C7: drop/failover must not increment a failure metric"
        );

        let gathered = metrics::REGISTRY.gather();
        assert!(
            !gathered.iter().any(|m| {
                let n = m.name();
                n.contains("sse") && (n.contains("fail") || n.contains("error"))
            }),
            "C7: no SSE failure/error metric on drop or failover"
        );
        let drop_mf = gathered
            .iter()
            .find(|m| m.name() == "rvc_sse_events_dropped_total")
            .expect("3l drop counter stays registered");
        for metric in drop_mf.get_metric() {
            assert!(
                metric.get_label().iter().any(|l| l.name() == "expected" && l.value() == "true"),
                "drop counter from 3l stays labelled expected"
            );
        }
    }
}
