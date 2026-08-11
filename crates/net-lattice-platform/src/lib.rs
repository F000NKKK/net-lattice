//! The contract between the model and platform backends.
//!
//! `net-lattice-platform` depends only on `net-lattice-core` — never on
//! `net-lattice-model`. Its provider traits describe the *shape* of a
//! contract, not the *content* of the model, via associated types. See
//! ARCHITECTURE.md for the full rationale, including how model
//! convergence is enforced one layer up, in `lattice`.
//!
//! Provides read/inspection providers for routes, interfaces, DNS,
//! neighbors, and interface addresses; mutator traits for each of those
//! domains (`InterfaceMutator`, `NeighborMutator`, and their siblings) gated
//! by their respective `Capability` flags; `EventProvider` for native
//! change-notification delivery; `SnapshotProvider`, the whole-system state
//! assembly contract; and `AdditionProvider`, a disjoint, explicitly opt-in
//! tier of non-native capabilities (see [`Addition`]) that never dilutes
//! `Capability`'s uniform, native-only meaning.

mod addition;
mod address_mutator;
mod address_provider;
mod capability;
mod dns_mutator;
mod dns_provider;
mod event_provider;
mod interface_mutator;
mod interface_provider;
mod neighbor_mutator;
mod neighbor_provider;
mod route_provider;
mod snapshot_provider;
#[cfg(feature = "async")]
mod tokio_event_provider;

pub use addition::{Addition, AdditionProvider};
pub use address_mutator::AddressMutator;
pub use address_provider::AddressProvider;
pub use capability::{Capability, CapabilityProvider};
pub use dns_mutator::DnsMutator;
pub use dns_provider::DnsProvider;
pub use event_provider::{EventProvider, EventReceiver, EventSender};
pub use interface_mutator::InterfaceMutator;
pub use interface_provider::InterfaceProvider;
pub use neighbor_mutator::NeighborMutator;
pub use neighbor_provider::NeighborProvider;
pub use route_provider::{RouteMutator, RouteProvider, RouteReplaceOrder};
pub use snapshot_provider::SnapshotProvider;
#[cfg(feature = "async")]
pub use tokio_event_provider::{TokioEventReceiver, TokioEventSender};

/// Backend contract for native Tokio-based event delivery.
///
/// Implementations can expose operating-system notification mechanisms
/// directly through a Tokio-aware receiver without routing events through a
/// synchronous [`EventReceiver`] and a blocking adapter thread.
///
/// This trait is intended for backend implementations. Applications normally
/// subscribe through `Lattice::watch_async`.
///
/// Available with the `async` feature.
#[cfg(feature = "async")]
pub trait TokioEventProvider {
    /// The event type produced by the native watcher.
    type Event;
    /// The filter type accepted when creating a native watcher.
    type EventFilter;

    /// Creates a native Tokio-based watcher using `filter`.
    ///
    /// This method is intended for backend integration. Applications normally
    /// use `Lattice::watch_async`. The returned receiver owns the native
    /// subscription; dropping it releases associated backend resources and
    /// cancels event delivery.
    fn watch_tokio(
        &self,
        filter: Self::EventFilter,
    ) -> net_lattice_core::Result<TokioEventReceiver<Self::Event>>;
}
