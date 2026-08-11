use net_lattice_core::{Error, Result};

use crate::event_provider::{EventProvider, EventReceiver};

bitflags::bitflags! {
    /// Optional, explicitly opt-in capabilities implemented through a
    /// non-native or lesser-quality mechanism (for example, polling instead
    /// of a native push subscription).
    ///
    /// Distinct from [`crate::Capability`]: every `Capability` flag
    /// describes a first-class native mechanism uniformly across backends;
    /// an `Addition` describes a documented workaround a caller must
    /// explicitly request, never advertised or activated by default. A
    /// backend that lacks a native mechanism for something simply does not
    /// set the corresponding `Capability` bit — `Addition` never expands
    /// what `Capability` means, it is an orthogonal opt-in surface for
    /// callers who have read the quality-tier caveat and still want the
    /// workaround.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Addition: u64 {
        /// Windows-only: synthesizes neighbor-table change events via
        /// periodic polling of `NeighborProvider::neighbors` instead of a
        /// native push subscription (Windows has no native
        /// `Capability::NEIGHBOR_MONITORING` mechanism). See this type's
        /// module doc for the general opt-in contract, and the quality/
        /// guarantee tier below — explicitly weaker than native
        /// `Capability::NEIGHBOR_MONITORING`, per ADR-0014 Decision 5:
        ///
        /// - **Latency**: bounded by the poll interval (2 seconds by
        ///   default on the Windows backend), not sub-second/push-based — a
        ///   change can take up to one interval to surface, unlike native
        ///   monitoring's push-on-change.
        /// - **Ordering**: no ordering guarantee relative to the
        ///   native-sourced portion of the same merged stream (consistent
        ///   with [`crate::EventReceiver`]'s existing "no cross-domain
        ///   ordering" contract — this extends the same disclaimer to cover
        ///   addition-vs-native interleaving too).
        /// - **Coalescing**: two neighbor changes within one poll interval
        ///   that cancel out (added then removed before the next poll) are
        ///   invisible — a real behavior difference from native monitoring.
        /// - **Resource cost**: one background polling thread per active
        ///   `watch_addition` call requesting this addition, torn down when
        ///   the returned [`crate::EventReceiver`] is dropped — bounded and
        ///   caller-controlled, never started unless requested.
        const NEIGHBOR_MONITORING_POLLING = 1 << 0;
    }
}

/// Reports which [`Addition`]s a backend can provide if a caller explicitly
/// opts in via an addition-aware watch entry point.
///
/// Every backend implements this at zero cost when it has nothing to offer:
/// the default [`Self::additions`] returns [`Addition::empty()`], so
/// implementing this trait requires no code change for a backend with no
/// additions (mirrors `RouteMutator::supports_route_metric`'s
/// default-provided-method precedent).
///
/// `AdditionProvider: EventProvider` because an addition's whole purpose is
/// to synthesize the same `Event`/`EventFilter` shape a native watch would —
/// reusing [`EventProvider::Event`] keeps addition-sourced events
/// indistinguishable in shape from native ones once merged into the same
/// stream, just with a documented weaker guarantee tier for the
/// addition-sourced ones.
pub trait AdditionProvider: EventProvider {
    /// Returns the [`Addition`]s this backend can provide. The default
    /// reports none.
    fn additions(&self) -> Addition {
        Addition::empty()
    }

    /// Starts the requested addition's workaround mechanism and returns an
    /// event receiver delivering its synthesized events.
    ///
    /// Returns [`Error::Unsupported`] by default; a backend overriding
    /// [`Self::additions`] to report a flag must also override this method
    /// to handle it.
    fn watch_addition(&self, addition: Addition) -> Result<EventReceiver<Self::Event>> {
        let _ = addition;
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::{Addition, AdditionProvider};
    use crate::event_provider::{EventProvider, EventReceiver};
    use net_lattice_core::Result;

    struct NoAdditionsBackend;

    impl EventProvider for NoAdditionsBackend {
        type Event = u32;
        type EventFilter = ();

        fn watch(&self) -> Result<EventReceiver<Self::Event>> {
            Ok(EventReceiver::bounded().1)
        }

        fn watch_filtered(&self, _filter: Self::EventFilter) -> Result<EventReceiver<Self::Event>> {
            Ok(EventReceiver::bounded().1)
        }
    }

    impl AdditionProvider for NoAdditionsBackend {}

    #[test]
    fn default_additions_reports_none() {
        let backend = NoAdditionsBackend;
        assert_eq!(backend.additions(), Addition::empty());
    }

    #[test]
    fn default_watch_addition_is_unsupported() {
        let backend = NoAdditionsBackend;
        let result = backend.watch_addition(Addition::NEIGHBOR_MONITORING_POLLING);
        match result {
            Ok(_) => panic!("default watch_addition must not succeed"),
            Err(error) => assert!(error.is_unsupported()),
        }
    }
}
