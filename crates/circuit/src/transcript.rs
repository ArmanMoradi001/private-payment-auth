//! Deterministic evaluation transcripts.
//!
//! A [`TranscriptHook`] records *structural* events — which nodes were
//! used as inputs, which were computed, opened, and output. Events
//! carry node ids only; secret field values never appear, so the
//! transcript is safe to feed into future MPCitH/Fiat–Shamir
//! processing. The evaluator emits events in node order, which is a
//! topological order by construction.

use crate::types::NodeId;

/// One structural event in an MPC evaluation of a circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptEvent {
    /// A leaf node was instantiated (shared) as an input.
    Input(NodeId),
    /// A gate node was evaluated.
    Operation(NodeId),
    /// The value behind a node was explicitly revealed.
    Open(NodeId),
    /// A node was designated a circuit output.
    Output(NodeId),
}

/// Optional recorder of [`TranscriptEvent`]s during evaluation.
///
/// Pass `None` wherever a hook is accepted to run with zero overhead;
/// pass `Some(hook)` to build the deterministic event log that the
/// proof layer will later consume.
#[derive(Debug, Default, Clone)]
pub struct TranscriptHook {
    events: Vec<TranscriptEvent>,
    enabled: bool,
}

impl TranscriptHook {
    /// Creates an enabled hook collecting all events.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            enabled: true,
        }
    }

    /// Creates a disabled hook: recording becomes a no-op and no
    /// memory is retained. Useful for API uniformity when the caller
    /// does not want a transcript but must name a hook value.
    pub fn disabled() -> Self {
        Self {
            events: Vec::new(),
            enabled: false,
        }
    }

    /// Records one event (no-op while disabled).
    pub fn record(&mut self, event: TranscriptEvent) {
        if self.enabled {
            self.events.push(event);
        }
    }

    /// Returns the recorded events in emission order.
    pub fn events(&self) -> &[TranscriptEvent] {
        &self.events
    }

    /// `true` when recording is active.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of recorded events so far.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// `true` when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_recorded_in_order() {
        let mut hook = TranscriptHook::new();
        hook.record(TranscriptEvent::Input(NodeId::new(0)));
        hook.record(TranscriptEvent::Input(NodeId::new(1)));
        hook.record(TranscriptEvent::Operation(NodeId::new(2)));
        hook.record(TranscriptEvent::Output(NodeId::new(2)));
        hook.record(TranscriptEvent::Open(NodeId::new(2)));

        assert_eq!(hook.len(), 5);
        assert_eq!(
            hook.events(),
            &[
                TranscriptEvent::Input(NodeId::new(0)),
                TranscriptEvent::Input(NodeId::new(1)),
                TranscriptEvent::Operation(NodeId::new(2)),
                TranscriptEvent::Output(NodeId::new(2)),
                TranscriptEvent::Open(NodeId::new(2)),
            ]
        );
    }

    #[test]
    fn disabled_hook_records_nothing() {
        let mut hook = TranscriptHook::disabled();
        assert!(!hook.is_enabled());
        hook.record(TranscriptEvent::Open(NodeId::new(0)));
        assert!(hook.is_empty());
        assert_eq!(hook.len(), 0);
    }
}
