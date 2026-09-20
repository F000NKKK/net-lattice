//! Cross-platform inspection, mutation, and monitoring of operating-system
//! networking through a strongly typed Rust API.
//!
//! Start with [`Lattice::connect`] to inspect interfaces, addresses, routes,
//! DNS configuration, and neighbor tables; perform supported mutations; or
//! subscribe to network change events.
//!
//! # Quick start
//!
//! ```no_run
//! use net_lattice::{Lattice, Result};
//!
//! fn main() -> Result<()> {
//!     let lattice = Lattice::connect()?;
//!     for interface in lattice.interfaces()? {
//!         println!("{interface:?}");
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Inspection
//!
//! [`Lattice::interfaces`], [`Lattice::routes`], [`Lattice::addresses`],
//! [`Lattice::neighbors`], and [`Lattice::dns_config`] read the connected
//! backend's current observed state; these calls are generally unprivileged.
//! [`Lattice::current_state`] reads all five domains in one call and returns
//! them together as a single [`CurrentState`] snapshot. The observed/desired-
//! state domain objects they return, plus their read/inspection provider
//! traits — [`Interface`], [`Route`], [`NeighborEntry`],
//! [`InterfaceAddress`], [`DnsConfig`], and [`CurrentState`] among them —
//! resolve only through the [`model`] module, not at the crate root.
//!
//! # Direct mutations
//!
//! Imperative single-operation calls such as [`Lattice::add_route`],
//! [`Lattice::set_interface_config`], and [`Lattice::add_static_neighbor`]
//! apply immediately against the connected backend and require the matching
//! runtime [`Capability`] (checked with [`Lattice::supports`]) before
//! submission. Mutation intent types (for example [`StaticNeighbor`] and
//! [`InterfaceConfig`]) are distinct from the observed state they produce; a
//! successful mutation returns a fresh read-after-write observation. These
//! types and the mutator traits a backend implements resolve through the
//! [`mutation`] module.
//!
//! ```no_run
//! use net_lattice::{Capability, Ipv4Address, Lattice, Result};
//! use net_lattice::model::{IpAddress, MacAddress};
//! use net_lattice::mutation::StaticNeighbor;
//!
//! fn main() -> Result<()> {
//!     let lattice = Lattice::connect()?;
//!     if lattice.supports(Capability::NEIGHBOR_MUTATION) {
//!         // Select an interface at runtime rather than hardcoding an index:
//!         // a hardcoded value risks clobbering an arbitrary or critical
//!         // real interface if this snippet is copy-pasted verbatim.
//!         if let Some(interface) = lattice.interfaces()?.into_iter().next() {
//!             let neighbor = StaticNeighbor::new(
//!                 interface.id,
//!                 IpAddress::from(Ipv4Address::new(192, 0, 2, 250)),
//!                 MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xfa]),
//!             );
//!             let observed = lattice.add_static_neighbor(neighbor)?;
//!             println!("{observed:?}");
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Transaction plans
//!
//! [`MutationPlan`] batches operations as data, independent of any backend.
//! Build a plan, check it against the connected backend with
//! [`Lattice::validate_plan`], execute it with [`Lattice::execute_plan`] and
//! an [`ExecutionOptions`] value, then inspect the returned
//! [`MutationPlanReport`], which preserves plan indices and distinguishes
//! validation, snapshot, execution, cancellation, and compensation
//! boundaries. This machinery, plus the mutator traits above, resolves
//! through the [`mutation`] module.
//!
//! ```no_run
//! use net_lattice::{Ipv4Address, Ipv4Network, Ipv4PrefixLength, Lattice, Result};
//! use net_lattice::model::Network;
//! use net_lattice::mutation::{ExecutionOptions, Mutation, MutationPlan, RouteConfig};
//!
//! fn main() -> Result<()> {
//!     let lattice = Lattice::connect()?;
//!     let destination = Network::from(Ipv4Network::new(
//!         Ipv4Address::new(198, 51, 100, 0),
//!         Ipv4PrefixLength::new(24).expect("24 is a valid IPv4 prefix length"),
//!     ));
//!     // Select an interface at runtime rather than hardcoding an index: a
//!     // hardcoded value risks clobbering an arbitrary or critical real
//!     // interface if this snippet is copy-pasted verbatim.
//!     let Some(interface) = lattice.interfaces()?.into_iter().next() else {
//!         return Ok(());
//!     };
//!     let route = RouteConfig::new(destination).with_interface_index(interface.index);
//!
//!     // Build: illustrative only. If the add succeeds and the remove then
//!     // fails, the route can remain installed — execution stops after the
//!     // first error (see below) and this plan has no automatic
//!     // compensation. Use an explicit snapshot/compensator (see
//!     // `ExecutionOptions`) when restoration on failure is required, and
//!     // never run this against a route/interface that was not deliberately
//!     // selected.
//!     let plan = MutationPlan::from_operations([
//!         Mutation::AddRoute(route),
//!         Mutation::RemoveRoute(route),
//!     ]);
//!
//!     // Validate: side-effect-free capability/precondition check.
//!     lattice.validate_plan(&plan)?;
//!
//!     // Execute: ordered submission, stopping after the first error.
//!     let mut options = ExecutionOptions::default();
//!     let report = lattice.execute_plan(&plan, &mut options);
//!
//!     // Report: one outcome per operation, in plan order.
//!     println!("{report:?}");
//!     Ok(())
//! }
//! ```
//!
//! # Monitoring
//!
//! [`Lattice::watch`] subscribes to every domain and requires aggregate
//! [`Capability::MONITORING`]; [`Lattice::watch_filtered`] (and, with the
//! `async` feature, `Lattice::watch_async`) subscribes to only the selected
//! [`EventFilter`] domains, each gated by its own monitoring capability.
//! Mutation support does not imply native change notifications:
//! a backend can advertise a mutation capability without advertising the
//! matching monitoring capability, and vice versa. Change events, filters,
//! and monitoring provider traits resolve through the [`monitoring`] module.
//!
//! # Implementing a backend
//!
//! [`LatticeBackend`] is the bound a backend must satisfy to be usable with
//! [`Lattice`]; the [`backend`] module collects every provider, mutator, and
//! event trait it requires in one place for third-party backend authors,
//! alongside the extension types ([`backend::EventSender`] and friends) not
//! reachable anywhere else.
//!
//! # Facade design
//!
//! Re-exports the types consumers need from `net-lattice-model` and
//! `net-lattice-ip`, selects a default backend based on `cfg(target_os =
//! "...")`, and enforces model convergence: `net-lattice-platform`'s generic
//! provider traits are constrained here to Net Lattice's own model types,
//! without `net-lattice-platform` ever depending on `net-lattice-model`. See
//! ARCHITECTURE.md for the full rationale.
//!
//! Only a small, cross-cutting set of items resolves at the bare crate root:
//! [`Error`], [`Id`], [`PlatformErrorCode`], [`Result`], the `Ipv4*`/`Ipv6*`
//! address/network/prefix-length primitives, [`Capability`],
//! [`CapabilityProvider`], and the crate-local [`Lattice`]/[`LatticeBackend`]
//! definitions — none of these duplicate a domain-module path, so there is
//! nothing to consolidate by moving them. Every other item (interfaces,
//! routes, neighbors, addresses, DNS configuration, mutation intents and
//! plans, and change events, along with their provider/mutator traits)
//! resolves only through the domain-scoped [`model`], [`mutation`], and
//! [`monitoring`] modules (and, for backend authors, [`backend`]) — it is
//! not also re-exported at the crate root. `net-lattice` has not reached
//! 1.0, so pre-1.0 releases may still refine public module organization
//! when the resulting API is clearer and the change is documented in the
//! changelog; keeping items reachable from two or three separate rendered
//! docs.rs pages would only ship redundant duplication for no benefit.

#![warn(missing_docs)]

// Async event adapters, enabled by the `async` feature. Not re-exported at
// the crate root (Category A, see the module docs above); reachable via
// `monitoring::EventStream`.
#[cfg(feature = "async")]
use net_lattice_async::EventStream;
mod executor;
// `Cancellation`/`Compensation`/`Snapshot` are not referenced by bare name
// anywhere else in this file; they are exposed solely via
// `mutation::{Cancellation, Compensation, Snapshot}`, imported there
// directly from `crate::executor`.
use executor::ExecutionOptions;
pub use net_lattice_core::{Error, Id, PlatformErrorCode, Result};
pub use net_lattice_ip::{
    Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
};
// `DesiredState`/`Diff`/`RouteChange` are referenced only by `#[cfg(test)]
// mod tests` below (via `use super::*;`), so a non-test `cargo check`
// reports them unused even though `cargo test` uses them.
use net_lattice_model::apply::{ApplyPlan, ApplyPlanReport};
#[allow(unused_imports)]
use net_lattice_model::desired_state::DesiredState;
#[allow(unused_imports)]
use net_lattice_model::diff::{Diff, RouteChange};
use net_lattice_model::dns::{DnsConfig, NewDnsConfig};
use net_lattice_model::event::{Event, EventDomain, EventFilter};
// `ChangeKind` is referenced only by `#[cfg(test)] mod tests` below (via
// `use super::*;`), so a non-test `cargo check` reports it unused even
// though `cargo test` uses it.
#[allow(unused_imports)]
use net_lattice_model::event::ChangeKind;
#[allow(unused_imports)]
use net_lattice_model::firewall::{Direction, PortRange, Protocol, Verdict};
use net_lattice_model::firewall::{FirewallPolicy, FirewallRule};
#[allow(unused_imports)]
use net_lattice_model::ifaddr::InterfaceAddressId;
use net_lattice_model::ifaddr::{InterfaceAddress, NewInterfaceAddress};
#[allow(unused_imports)]
use net_lattice_model::interface::{AdminState, DesiredAdminState, InterfaceId, InterfaceKind};
use net_lattice_model::interface::{Interface, InterfaceConfig};
#[allow(unused_imports)]
use net_lattice_model::mac::MacAddress;
use net_lattice_model::mutation::{
    Mutation, MutationExecutionPhase, MutationOperationReport, MutationOutcome, MutationPlan,
    MutationPlanReport, MutationSnapshot, MutationStopReason, RollbackStatus,
};
use net_lattice_model::neighbor::{NeighborEntry, StaticNeighbor};
#[allow(unused_imports)]
use net_lattice_model::neighbor::{NeighborId, NeighborState};
#[allow(unused_imports)]
use net_lattice_model::route::RouteId;
use net_lattice_model::route::{Route, RouteConfig};
use net_lattice_model::snapshot::CurrentState;
#[allow(unused_imports)]
use net_lattice_model::{IpAddress, Network};
#[allow(unused_imports)]
use net_lattice_platform::DnsProvider;
#[allow(unused_imports)]
use net_lattice_platform::FirewallProvider;
#[cfg(feature = "async")]
use net_lattice_platform::TokioEventProvider;
use net_lattice_platform::{
    Addition, AdditionProvider, AddressMutator, AddressProvider, DnsMutator, EventProvider,
    EventReceiver, EventSender, FirewallMutator, InterfaceMutator, InterfaceProvider,
    NeighborMutator, NeighborProvider, RouteMutator, RouteProvider, SnapshotProvider,
};
pub use net_lattice_platform::{Capability, CapabilityProvider};

/// Observed networking state, shared domain value types, and read/inspection
/// provider traits.
///
/// This is the only public path to these items: they are not re-exported at
/// the crate root. Platform traits re-exported here may additionally appear
/// under [`backend`] for backend authors.
pub mod model {
    #[doc(inline)]
    pub use net_lattice_model::dns::DnsConfig;
    #[doc(inline)]
    pub use net_lattice_model::firewall::{Direction, FirewallRule, PortRange, Protocol, Verdict};
    #[doc(inline)]
    pub use net_lattice_model::ifaddr::{InterfaceAddress, InterfaceAddressId};
    #[doc(inline)]
    pub use net_lattice_model::interface::{
        AdminState, Interface, InterfaceId, InterfaceKind, OperationalState,
    };
    #[doc(inline)]
    pub use net_lattice_model::mac::MacAddress;
    #[doc(inline)]
    pub use net_lattice_model::neighbor::{NeighborEntry, NeighborId, NeighborState};
    #[doc(inline)]
    pub use net_lattice_model::route::{Route, RouteId};
    #[doc(inline)]
    pub use net_lattice_model::snapshot::CurrentState;
    #[doc(inline)]
    pub use net_lattice_model::{IpAddress, Network};
    #[doc(inline)]
    pub use net_lattice_platform::{
        AddressProvider, DnsProvider, FirewallProvider, InterfaceProvider, NeighborProvider,
        RouteProvider, SnapshotProvider,
    };
}

/// Mutation intent types, plan/execution/report machinery, mutator traits,
/// and the declarative `DesiredState`/`Diff` pair built from those intent
/// types.
///
/// This is the only public path to these items: they are not re-exported at
/// the crate root. Platform traits re-exported here may additionally appear
/// under [`backend`] for backend authors.
pub mod mutation {
    #[doc(inline)]
    pub use crate::executor::{Cancellation, Compensation, ExecutionOptions, Snapshot};
    #[doc(inline)]
    pub use net_lattice_model::apply::{
        ApplyPlan, ApplyPlanReport, ApplyStep, ApplyStepOutcome, NonConvergentReason,
    };
    #[doc(inline)]
    pub use net_lattice_model::desired_state::DesiredState;
    #[doc(inline)]
    pub use net_lattice_model::diff::{
        AddressChange, Change, Diff, DnsChange, InterfaceDiff, NeighborChange, RouteChange,
    };
    #[doc(inline)]
    pub use net_lattice_model::dns::NewDnsConfig;
    #[doc(inline)]
    pub use net_lattice_model::firewall::FirewallPolicy;
    #[doc(inline)]
    pub use net_lattice_model::ifaddr::NewInterfaceAddress;
    #[doc(inline)]
    pub use net_lattice_model::interface::{DesiredAdminState, InterfaceConfig};
    #[doc(inline)]
    pub use net_lattice_model::mutation::{
        Mutation, MutationConfirmation, MutationExecutionPhase, MutationIdempotency, MutationKind,
        MutationOperationReport, MutationOutcome, MutationPlan, MutationPlanReport,
        MutationPrecondition, MutationPreflight, MutationPrivilege, MutationReversibility,
        MutationSemantics, MutationSnapshot, MutationStopReason, RollbackStatus,
    };
    #[doc(inline)]
    pub use net_lattice_model::neighbor::StaticNeighbor;
    #[doc(inline)]
    pub use net_lattice_model::route::RouteConfig;
    #[doc(inline)]
    pub use net_lattice_platform::{
        AddressMutator, DnsMutator, FirewallMutator, InterfaceMutator, NeighborMutator,
        RouteMutator, RouteReplaceOrder,
    };
}

/// Change events, event filters, and monitoring provider traits.
///
/// This is the only public path to these items: they are not re-exported at
/// the crate root. Platform traits re-exported here may additionally appear
/// under [`backend`] for backend authors.
pub mod monitoring {
    #[cfg(feature = "async")]
    #[doc(inline)]
    pub use net_lattice_async::EventStream;
    #[doc(inline)]
    pub use net_lattice_model::event::{ChangeKind, Event, EventDomain, EventFilter};
    #[cfg(feature = "async")]
    #[doc(inline)]
    pub use net_lattice_platform::TokioEventProvider;
    #[doc(inline)]
    pub use net_lattice_platform::{Addition, AdditionProvider, EventProvider, EventReceiver};
}

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Contracts for implementing a third-party Net Lattice backend.
///
/// These traits are a supported extension API. A backend must preserve the
/// documented read, mutation, event-delivery, and cancellation semantics of
/// each trait it implements. [`LatticeBackend`] (a crate-local item, not a
/// re-export) and [`CapabilityProvider`] (a cross-cutting root-only item,
/// not a domain re-export) both resolve at the bare crate root; every other
/// item re-exported in this module — [`CurrentState`] and the remaining 15
/// provider/mutator/event traits — resolves only through
/// [`model`]/[`mutation`]/[`monitoring`] and here, not at the crate root.
/// Application code that only consumes [`Lattice`] should
/// keep importing from the crate root or the [`model`], [`mutation`], and
/// [`monitoring`] modules, while this module exists specifically so
/// third-party backend implementers can see, in one place, every provider,
/// mutator, and event trait [`LatticeBackend`] requires.
pub mod backend {
    pub use crate::LatticeBackend;
    pub use net_lattice_model::snapshot::CurrentState;
    pub use net_lattice_platform::{
        Addition, AdditionProvider, AddressMutator, AddressProvider, CapabilityProvider,
        DnsMutator, DnsProvider, EventProvider, EventReceiver, EventSender, FirewallMutator,
        FirewallProvider, InterfaceMutator, InterfaceProvider, NeighborMutator, NeighborProvider,
        RouteMutator, RouteProvider, RouteReplaceOrder, SnapshotProvider,
    };
    #[cfg(feature = "async")]
    pub use net_lattice_platform::{TokioEventProvider, TokioEventReceiver, TokioEventSender};
}

/// Bound satisfied by any backend usable with [`Lattice`].
///
/// This is where model convergence is enforced: a backend whose
/// `RouteProvider::Route` (or `InterfaceProvider::Interface`,
/// `DnsProvider::DnsConfig`, `NeighborProvider::NeighborEntry`,
/// `AddressProvider::InterfaceAddress`, `AddressMutator`'s input/output,
/// `EventProvider::Event`) is not
/// literally `net_lattice_model`'s corresponding type fails to satisfy this
/// trait and cannot be used with [`Lattice`] — a compile error at the point
/// the backend is wired in, not a runtime surprise. See ARCHITECTURE.md's
/// `net-lattice` section. `CapabilityProvider` has no associated type to
/// converge — it reports plain runtime facts about the connected system,
/// not domain objects — so it's required as-is.
///
/// This bound deliberately does **not** include
/// [`SnapshotProvider`]: Rust's
/// orphan rules forbid a blanket `impl<B> SnapshotProvider for B` in this
/// crate (`SnapshotProvider` is a foreign trait defined in
/// `net-lattice-platform`, and a bare generic `B` is not a local type — see
/// [`Lattice`]'s own `SnapshotProvider` implementation below for the actual,
/// compiling shape of this contract). Requiring `SnapshotProvider` here
/// would force every third-party backend to implement it by hand, which is
/// exactly what this design avoids.
pub trait LatticeBackend:
    RouteProvider<Route = Route>
    + RouteMutator<RouteConfig = RouteConfig>
    + InterfaceProvider<Interface = Interface>
    + InterfaceMutator<Interface = Interface, InterfaceConfig = InterfaceConfig>
    + DnsMutator<NewDnsConfig = NewDnsConfig, DnsConfig = DnsConfig>
    + NeighborProvider<NeighborEntry = NeighborEntry>
    + NeighborMutator<StaticNeighbor = StaticNeighbor, NeighborEntry = NeighborEntry>
    + AddressProvider<InterfaceAddress = InterfaceAddress>
    + AddressMutator<NewInterfaceAddress = NewInterfaceAddress, InterfaceAddress = InterfaceAddress>
    + FirewallMutator<FirewallPolicy = FirewallPolicy, FirewallRule = FirewallRule>
    + EventProvider<Event = Event, EventFilter = EventFilter>
    + AdditionProvider
    + CapabilityProvider
{
}

impl<B> LatticeBackend for B where
    B: RouteProvider<Route = Route>
        + RouteMutator<RouteConfig = RouteConfig>
        + InterfaceProvider<Interface = Interface>
        + InterfaceMutator<Interface = Interface, InterfaceConfig = InterfaceConfig>
        + DnsMutator<NewDnsConfig = NewDnsConfig, DnsConfig = DnsConfig>
        + NeighborProvider<NeighborEntry = NeighborEntry>
        + NeighborMutator<StaticNeighbor = StaticNeighbor, NeighborEntry = NeighborEntry>
        + AddressProvider<InterfaceAddress = InterfaceAddress>
        + AddressMutator<
            NewInterfaceAddress = NewInterfaceAddress,
            InterfaceAddress = InterfaceAddress,
        > + FirewallMutator<FirewallPolicy = FirewallPolicy, FirewallRule = FirewallRule>
        + EventProvider<Event = Event, EventFilter = EventFilter>
        + AdditionProvider
        + CapabilityProvider
{
}

/// The top-level entry point: a connected backend for the current system.
pub struct Lattice<B: LatticeBackend> {
    backend: B,
}

/// Backend-owned subscription guard attached to a
/// [`Lattice::watch_with_additions`] receiver. Owns both the shutdown signal
/// and every fan-in thread's [`std::thread::JoinHandle`] (one for the native
/// watcher, one per activated [`Addition`]); dropping it stops every fan-in
/// thread and joins it before returning, so a dropped receiver has fully
/// torn down before `drop` returns.
struct AdditionMergeGuard {
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for AdditionMergeGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Forwarding-fan-in poll interval: how often a fan-in thread re-checks the
/// shutdown flag between events. Bounds how long
/// [`AdditionMergeGuard::drop`] can block joining a thread that is currently
/// idle-waiting on its source receiver.
const FAN_IN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// Spawns a thread that forwards every event from `source` into `sender`
/// until `source` disconnects, `sender`'s last other clone is dropped, or
/// `stop` is set. Used by [`Lattice::watch_with_additions`] to fan native and
/// addition-sourced events into one merged [`EventReceiver`]. When `filter`
/// is `Some`, an event that does not match it is silently dropped instead of
/// forwarded — used so addition-sourced events (which their native source
/// applies no object-id narrowing to) still obey the caller's full requested
/// [`EventFilter`].
fn spawn_event_fan_in(
    source: EventReceiver<Event>,
    sender: EventSender<Event>,
    stop: Arc<AtomicBool>,
    filter: Option<EventFilter>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match source.recv_timeout(FAN_IN_POLL_INTERVAL) {
                Ok(Some(event)) => {
                    if let Some(filter) = &filter
                        && !filter.matches(event)
                    {
                        continue;
                    }
                    if !sender.send(event, Event::resync_all()) {
                        break;
                    }
                }
                Ok(None) => continue,
                Err(Error::Disconnected) => break,
                Err(error) => {
                    let _ = sender.send_error(error);
                    break;
                }
            }
        }
    })
}

/// Running conflict-detection state threaded across one plan's preflight,
/// shared by [`Lattice::validate_plan`] (over a whole [`MutationPlan`]) and
/// `validate_apply_plan` (over an
/// [`net_lattice_model::apply::ApplyPlan`]'s `Single` steps).
///
/// Kept as an explicit struct instead of loop-local `Vec`s so both preflight
/// entry points can call [`Lattice::validate_one_mutation`] with one running
/// accumulator across the whole plan.
#[derive(Default)]
struct PlanAccumulators {
    planned_routes: Vec<RouteConfig>,
    removed_routes: Vec<RouteConfig>,
    planned_addresses: Vec<(u32, Network)>,
    removed_addresses: Vec<(u32, Network)>,
    planned_neighbors: Vec<(u32, IpAddress)>,
    removed_neighbors: Vec<(u32, IpAddress)>,
}

/// Assembles a [`CurrentState`] snapshot of the connected backend.
///
/// `net-lattice-platform`'s [`net_lattice_platform::SnapshotProvider`] is
/// generic over an associated `State` type because that crate does not
/// depend on `net-lattice-model` and cannot name `CurrentState` directly. A
/// blanket `impl<B> SnapshotProvider for B` over every raw backend type does
/// not compile: `SnapshotProvider` is a foreign trait here (defined in
/// `net-lattice-platform`) and a bare generic `B` is not a local type, so
/// Rust's orphan rules reject it (`E0210`, verified against this exact
/// impl). [`Lattice<B>`] is the local type this crate does own, so the
/// implementation is realized here instead: any [`Lattice<B>`] over a
/// [`LatticeBackend`] gets [`SnapshotProvider`]
/// for free, without any backend crate writing a single extra line — the
/// zero-backend-code guarantee is preserved, just at the facade type rather
/// than the raw backend type.
impl<B: LatticeBackend> SnapshotProvider for Lattice<B> {
    type State = CurrentState;

    /// Assembles a whole-system [`CurrentState`] snapshot. See
    /// [`Lattice::current_state`] for the primary, doc-complete entry point;
    /// this trait implementation exists so [`Lattice<B>`] can be used
    /// generically wherever a [`SnapshotProvider`]
    /// is expected.
    fn snapshot(&self) -> Result<CurrentState> {
        let routes = self.backend.routes()?;
        let interfaces = self.backend.interfaces()?;
        let neighbors = self.backend.neighbors()?;
        let addresses = self.backend.addresses()?;
        let dns = self.backend.dns_config()?;
        let firewall_rules = self.backend.firewall_rules()?;
        Ok(CurrentState::new(
            routes,
            interfaces,
            neighbors,
            addresses,
            dns,
            firewall_rules,
        ))
    }
}

#[cfg(test)]
static FORCE_CONNECT_FAILURE: AtomicBool = AtomicBool::new(false);

impl<B: LatticeBackend> Lattice<B> {
    /// Reads the observed routing table. Requires no capability; see
    /// [`Capability`] for mutation-side gating.
    pub fn routes(&self) -> Result<Vec<Route>> {
        self.backend.routes()
    }

    /// Adds a route. Requires [`Capability::ROUTE_MUTATION`]; use
    /// [`Self::execute_plan`] with [`Mutation::AddRoute`] for
    /// capability/precondition checks and compensation support.
    pub fn add_route(&self, route: RouteConfig) -> Result<()> {
        self.backend.add_route(route)
    }

    /// Removes a route. Requires [`Capability::ROUTE_MUTATION`]; use
    /// [`Self::execute_plan`] with [`Mutation::RemoveRoute`] for
    /// capability/precondition checks and compensation support.
    pub fn remove_route(&self, route: RouteConfig) -> Result<()> {
        self.backend.remove_route(route)
    }

    /// Reads the observed network interfaces. Requires no capability; see
    /// [`Capability`] for mutation-side gating.
    pub fn interfaces(&self) -> Result<Vec<Interface>> {
        self.backend.interfaces()
    }

    /// Applies a partial desired configuration to one interface.
    ///
    /// Requested administrative state and MTU are checked against the
    /// connected backend's runtime capabilities and the target interface is
    /// confirmed to exist before native submission. Success returns a fresh
    /// observed interface from the backend's read-after-write operation.
    /// Capabilities are feature gates rather than privilege guarantees, and a
    /// combined native update can still partially apply on error; use a
    /// [`MutationPlan`] with explicit [`ExecutionOptions`] compensation when
    /// an attempted restoration is required.
    pub fn set_interface_config(&self, config: InterfaceConfig) -> Result<Interface> {
        self.validate_interface_config(&config)?;
        self.backend.set_interface_config(config)
    }

    /// Reads the observed resolver configuration. Requires no capability;
    /// see [`Capability`] for mutation-side gating.
    pub fn dns_config(&self) -> Result<DnsConfig> {
        self.backend.dns_config()
    }

    /// Replaces resolver configuration and returns the resulting observed
    /// resolver view.
    pub fn set_dns_config(&self, config: NewDnsConfig) -> Result<DnsConfig> {
        self.backend.set_dns_config(config)
    }

    /// Reads the observed neighbor (ARP/NDP) table. Requires no capability;
    /// see [`Capability`] for mutation-side gating.
    pub fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        self.backend.neighbors()
    }

    /// Adds a static ARP/NDP entry and returns the resulting observed entry
    /// read back from the OS (`ReadAfterWrite`, per ADR-0001). Requires
    /// [`Capability::NEIGHBOR_MUTATION`]; use [`Self::execute_plan`] with
    /// [`Mutation::AddStaticNeighbor`] for capability/precondition checks and
    /// compensation support.
    pub fn add_static_neighbor(&self, neighbor: StaticNeighbor) -> Result<NeighborEntry> {
        self.backend.add_static_neighbor(neighbor)
    }

    /// Removes a static ARP/NDP entry. Requires
    /// [`Capability::NEIGHBOR_MUTATION`]; the backend refuses to remove a
    /// present but non-`Permanent` (dynamically learned) entry with
    /// [`Error::InvalidState`]. Prefer [`Self::execute_plan`] with
    /// [`Mutation::RemoveStaticNeighbor`] for capability/precondition checks
    /// and compensation support.
    pub fn remove_static_neighbor(&self, neighbor: StaticNeighbor) -> Result<()> {
        self.backend.remove_static_neighbor(neighbor)
    }

    /// Reads the observed interface addresses. Requires no capability; see
    /// [`Capability`] for mutation-side gating.
    pub fn addresses(&self) -> Result<Vec<InterfaceAddress>> {
        self.backend.addresses()
    }

    /// Assigns an address to an interface and returns the canonical record
    /// observed from the operating system after creation.
    pub fn add_address(&self, address: NewInterfaceAddress) -> Result<InterfaceAddress> {
        self.backend.add_address(address)
    }

    /// Removes the observed interface address.
    pub fn remove_address(&self, address: InterfaceAddress) -> Result<()> {
        self.backend.remove_address(address)
    }

    /// Reads the managed native-firewall policy's rules directly from the
    /// backend (a live kernel/engine dump on every shipped backend, not a
    /// cache). Requires no capability; see [`Capability::FIREWALL_MUTATION`]
    /// for mutation-side gating. Does not include
    /// [`FirewallPolicy::default_verdict`] — that fact isn't part of this
    /// provider's return type on any backend.
    pub fn firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        self.backend.firewall_rules()
    }

    /// Atomically replaces the managed native-firewall policy with `policy`.
    /// Requires [`Capability::FIREWALL_MUTATION`]. See
    /// [`FirewallMutator::set_firewall_policy`] for the exact atomicity and
    /// scope guarantees every backend gives this call.
    pub fn set_firewall_policy(&self, policy: FirewallPolicy) -> Result<()> {
        self.backend.set_firewall_policy(policy)
    }

    /// Clears the managed native-firewall policy back to an empty,
    /// default-allow policy. Requires [`Capability::FIREWALL_MUTATION`].
    pub fn clear_firewall_policy(&self) -> Result<()> {
        self.backend.clear_firewall_policy()
    }

    /// Assembles a whole-system snapshot of every domain this crate models:
    /// routes, interfaces, neighbors, interface addresses, and DNS
    /// configuration.
    ///
    /// The five constituent reads are performed sequentially with no lock or
    /// transaction spanning them, the same as every other multi-read path on
    /// this type — do not assume two fields of the returned [`CurrentState`]
    /// were observed at the same instant. If any one read fails, this
    /// returns that error and no [`CurrentState`] at all; there is no
    /// partial-result variant. A caller that wants best-effort partial data
    /// should call [`Self::routes`], [`Self::interfaces`],
    /// [`Self::neighbors`], [`Self::addresses`], and [`Self::dns_config`]
    /// directly instead.
    pub fn current_state(&self) -> Result<CurrentState> {
        SnapshotProvider::snapshot(self)
    }

    /// Computes the gap between the connected backend's observed state and
    /// `desired`, compiles it into an [`ApplyPlan`], and executes that plan
    /// through this backend in one call.
    ///
    /// This is the facade-level convenience chaining the three pure/read
    /// steps a caller would otherwise write out by hand:
    /// [`Self::current_state`] → [`Diff::compute`] → [`ApplyPlan::compile`]
    /// → [`Self::execute_apply_plan`]. Only [`Self::current_state`]'s
    /// underlying read can fail before compilation; `Diff::compute` and
    /// `ApplyPlan::compile` are both infallible pure computations over
    /// already-in-memory values (see ADR-0012), so the `Err` case of this
    /// method's `Result` is exactly the `Err` case of the initial state
    /// read. Once a plan exists, execution itself always produces a report
    /// rather than an error — including a plan rejected before any native
    /// call (see ADR-0013) — so the `Ok` case always carries a complete
    /// [`ApplyPlanReport`], never a partially-applied `Err`.
    ///
    /// Prefer calling [`Self::current_state`], [`Diff::compute`], and
    /// [`ApplyPlan::compile`] directly instead of this method when the
    /// caller wants to inspect or preflight the compiled [`ApplyPlan`]
    /// (for example via [`Self::validate_apply_plan`]) before deciding
    /// whether to execute it at all — this convenience always executes.
    pub fn apply(
        &self,
        desired: &DesiredState,
        options: &mut ExecutionOptions<'_>,
    ) -> Result<ApplyPlanReport> {
        let current = self.current_state()?;
        let diff = Diff::compute(&current, desired);
        let plan = ApplyPlan::compile(&diff);
        Ok(self.execute_apply_plan(&plan, options))
    }

    /// Computes the gap between the connected backend's observed state and
    /// `desired`, without compiling or executing anything.
    ///
    /// This is the facade-level convenience chaining the two steps
    /// [`Self::apply`]'s own doc comment names a caller "would otherwise
    /// write out by hand": [`Self::current_state`] → [`Diff::compute`].
    /// Callers who only want to inspect what would change (a dry-run /
    /// diff-preview) can use this instead of [`Self::apply`], which always
    /// executes; the `Err` case of this method's `Result` is exactly the
    /// `Err` case of the underlying state read, since `Diff::compute` is an
    /// infallible pure computation over already-in-memory values (see
    /// ADR-0012).
    pub fn diff(&self, desired: &DesiredState) -> Result<Diff> {
        let current = self.current_state()?;
        Ok(Diff::compute(&current, desired))
    }

    /// Performs the runtime portion of mutation preflight.
    ///
    /// This check is side-effect free. It validates capabilities exposed by
    /// the connected backend before an executor submits any operation; native
    /// privilege and current-state checks can still fail at execution time.
    pub fn validate_plan(&self, plan: &MutationPlan) -> Result<()> {
        let mut accumulators = PlanAccumulators::default();
        for operation in plan.operations() {
            self.validate_one_mutation(operation, &mut accumulators)?;
        }
        Ok(())
    }

    /// Runtime preflight for one operation, threading the running
    /// conflict-detection state for a whole plan through `accumulators`.
    ///
    /// Extracted so [`Self::validate_plan`] (over a [`MutationPlan`]) and
    /// `validate_apply_plan` (over an [`net_lattice_model::apply::ApplyPlan`]'s
    /// `Single` steps, interleaved with `ReplaceRoute` steps) both preflight
    /// each [`Mutation`] through the same logic with one running accumulator
    /// across the whole plan, rather than duplicating this match.
    fn validate_one_mutation(
        &self,
        operation: &Mutation,
        accumulators: &mut PlanAccumulators,
    ) -> Result<()> {
        if executor::requires_dns_capability(operation) && !self.supports(Capability::DNS_MUTATION)
        {
            return Err(Error::Unsupported);
        }
        if executor::requires_neighbor_capability(operation)
            && !self.supports(Capability::NEIGHBOR_MUTATION)
        {
            return Err(Error::Unsupported);
        }
        if executor::requires_route_capability(operation)
            && !self.supports(Capability::ROUTE_MUTATION)
        {
            return Err(Error::Unsupported);
        }
        if executor::requires_firewall_capability(operation)
            && !self.supports(Capability::FIREWALL_MUTATION)
        {
            return Err(Error::Unsupported);
        }

        match operation {
            Mutation::AddRoute(route) => {
                let exists_in_system = self
                    .routes()?
                    .iter()
                    .any(|candidate| Self::same_route(candidate, route))
                    && !accumulators
                        .removed_routes
                        .iter()
                        .any(|candidate| candidate == route);
                let exists = exists_in_system
                    || accumulators
                        .planned_routes
                        .iter()
                        .any(|candidate| candidate == route);
                if exists {
                    return Err(Error::AlreadyExists);
                }
                accumulators.planned_routes.push(*route);
                accumulators
                    .removed_routes
                    .retain(|candidate| candidate != route);
            }
            Mutation::RemoveRoute(route) => {
                let exists_in_system = self
                    .routes()?
                    .iter()
                    .any(|candidate| Self::same_route(candidate, route))
                    && !accumulators
                        .removed_routes
                        .iter()
                        .any(|candidate| candidate == route);
                let exists = exists_in_system
                    || accumulators
                        .planned_routes
                        .iter()
                        .any(|candidate| candidate == route);
                if !exists {
                    return Err(Error::NotFound);
                }
                accumulators
                    .planned_routes
                    .retain(|candidate| candidate != route);
                accumulators.removed_routes.push(*route);
            }
            Mutation::AddAddress(address) => {
                let interface_index = address.interface_id.value() as u32;
                if !self.interfaces()?.iter().any(|interface| {
                    interface.id == address.interface_id || interface.index == interface_index
                }) {
                    return Err(Error::NotFound);
                }
                let key = (interface_index, address.address);
                let exists_in_system = self.addresses()?.iter().any(|candidate| {
                    candidate.interface_index == interface_index
                        && candidate.address == address.address
                }) && !accumulators
                    .removed_addresses
                    .iter()
                    .any(|candidate| candidate == &key);
                if exists_in_system
                    || accumulators
                        .planned_addresses
                        .iter()
                        .any(|candidate| candidate == &key)
                {
                    return Err(Error::AlreadyExists);
                }
                accumulators.planned_addresses.push(key);
                accumulators
                    .removed_addresses
                    .retain(|candidate| candidate != &key);
            }
            Mutation::RemoveAddress(address) => {
                let key = (address.interface_index, address.address);
                let exists_in_system = self.addresses()?.iter().any(|candidate| {
                    candidate.id == address.id
                        || (candidate.interface_index == address.interface_index
                            && candidate.address == address.address)
                }) && !accumulators
                    .removed_addresses
                    .iter()
                    .any(|candidate| candidate == &key);
                if !exists_in_system
                    && !accumulators
                        .planned_addresses
                        .iter()
                        .any(|candidate| candidate == &key)
                {
                    return Err(Error::NotFound);
                }
                accumulators
                    .planned_addresses
                    .retain(|candidate| candidate != &key);
                accumulators.removed_addresses.push(key);
            }
            Mutation::AddStaticNeighbor(neighbor) => {
                let interface_index = neighbor.interface_id.value() as u32;
                if !self.interfaces()?.iter().any(|interface| {
                    interface.id == neighbor.interface_id || interface.index == interface_index
                }) {
                    return Err(Error::NotFound);
                }
                let key = (interface_index, neighbor.address);
                let exists_in_system = self.neighbors()?.iter().any(|candidate| {
                    candidate.interface_index == interface_index
                        && candidate.address == neighbor.address
                }) && !accumulators
                    .removed_neighbors
                    .iter()
                    .any(|candidate| candidate == &key);
                if exists_in_system
                    || accumulators
                        .planned_neighbors
                        .iter()
                        .any(|candidate| candidate == &key)
                {
                    return Err(Error::AlreadyExists);
                }
                accumulators.planned_neighbors.push(key);
                accumulators
                    .removed_neighbors
                    .retain(|candidate| candidate != &key);
            }
            Mutation::RemoveStaticNeighbor(neighbor) => {
                let interface_index = neighbor.interface_id.value() as u32;
                let key = (interface_index, neighbor.address);
                let exists_in_system = self.neighbors()?.iter().any(|candidate| {
                    candidate.interface_index == interface_index
                        && candidate.address == neighbor.address
                }) && !accumulators
                    .removed_neighbors
                    .iter()
                    .any(|candidate| candidate == &key);
                if !exists_in_system
                    && !accumulators
                        .planned_neighbors
                        .iter()
                        .any(|candidate| candidate == &key)
                {
                    return Err(Error::NotFound);
                }
                accumulators
                    .planned_neighbors
                    .retain(|candidate| candidate != &key);
                accumulators.removed_neighbors.push(key);
            }
            Mutation::SetDnsConfig(_) => {}
            Mutation::SetFirewallPolicy(_) => {}
            Mutation::SetInterfaceConfig(config) => self.validate_interface_config(config)?,
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }

    fn same_route(left: &Route, right: &RouteConfig) -> bool {
        left.destination == right.destination
            && left.gateway == right.gateway
            && left.metric == right.metric
            && left.interface_index == right.interface_index
    }

    fn validate_interface_config(&self, config: &InterfaceConfig) -> Result<()> {
        if config.admin_state().is_some() && !self.supports(Capability::INTERFACE_ADMIN_STATE) {
            return Err(Error::Unsupported);
        }
        if config.mtu().is_some() && !self.supports(Capability::INTERFACE_MTU) {
            return Err(Error::Unsupported);
        }
        if self
            .interfaces()?
            .iter()
            .all(|interface| interface.id != config.interface_id())
        {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Captures the currently observed state relevant to one mutation.
    ///
    /// This performs only provider reads and is safe to call before an
    /// operation. The returned value is a point-in-time observation; callers
    /// must still handle concurrent changes before compensation.
    pub fn snapshot_for_mutation(&self, operation: &Mutation) -> Result<MutationSnapshot> {
        match operation {
            Mutation::AddRoute(route) | Mutation::RemoveRoute(route) => {
                let observed = self.routes()?.into_iter().find(|candidate| {
                    candidate.destination == route.destination
                        && candidate.gateway == route.gateway
                        && candidate.metric == route.metric
                        && candidate.interface_index == route.interface_index
                });
                Ok(MutationSnapshot::Route(observed))
            }
            Mutation::AddAddress(address) => {
                let interface_index = address.interface_id.value() as u32;
                let observed = self.addresses()?.into_iter().find(|candidate| {
                    candidate.interface_index == interface_index
                        && candidate.address == address.address
                });
                Ok(MutationSnapshot::InterfaceAddress(observed))
            }
            Mutation::RemoveAddress(address) => {
                Ok(MutationSnapshot::InterfaceAddress(Some(address.clone())))
            }
            Mutation::AddStaticNeighbor(neighbor) => {
                let interface_index = neighbor.interface_id.value() as u32;
                let observed = self.neighbors()?.into_iter().find(|candidate| {
                    candidate.interface_index == interface_index
                        && candidate.address == neighbor.address
                });
                Ok(MutationSnapshot::Neighbor(observed))
            }
            Mutation::RemoveStaticNeighbor(neighbor) => {
                let interface_index = neighbor.interface_id.value() as u32;
                let observed = self.neighbors()?.into_iter().find(|candidate| {
                    candidate.interface_index == interface_index
                        && candidate.address == neighbor.address
                });
                Ok(MutationSnapshot::Neighbor(observed))
            }
            Mutation::SetDnsConfig(_) => Ok(MutationSnapshot::Dns(self.dns_config()?)),
            Mutation::SetFirewallPolicy(_) => {
                Ok(MutationSnapshot::Firewall(self.backend.firewall_rules()?))
            }
            Mutation::SetInterfaceConfig(config) => Ok(MutationSnapshot::Interface(
                self.interfaces()?
                    .into_iter()
                    .find(|interface| interface.id == config.interface_id()),
            )),
            _ => Err(Error::Unsupported),
        }
    }

    /// Executes an ordered mutation plan through this backend.
    ///
    /// The plan remains data-only; this method is the Stage 0.15 execution
    /// boundary. Operations are submitted in order and execution stops after
    /// the first error. The returned report always contains one outcome per
    /// plan operation. Failed operations carry their documented
    /// partial-application risk, and later operations are `NotAttempted`.
    /// Compensation is not inferred: until a caller supplies a prior-state
    /// snapshot, the report records [`RollbackStatus::NotAttempted`].
    pub fn execute_plan(
        &self,
        plan: &MutationPlan,
        options: &mut ExecutionOptions<'_>,
    ) -> MutationPlanReport {
        if let Err(error) = self.validate_plan(plan) {
            return executor::unsupported_plan_report(plan, error);
        }

        let mut outcomes = Vec::with_capacity(plan.len());
        let mut operation_reports = vec![MutationOperationReport::not_attempted(); plan.len()];
        let mut applied = Vec::new();
        let mut stopped = false;

        for (index, operation) in plan.operations().iter().enumerate() {
            if stopped {
                outcomes.push(MutationOutcome::NotAttempted);
                continue;
            }

            let (outcome, report, prior) = self.execute_one_mutation(index, operation, options);
            operation_reports[index] = report;

            if matches!(outcome, MutationOutcome::Applied) {
                applied.push((index, prior));
            } else {
                stopped = true;
            }

            outcomes.push(outcome);
        }

        let rollback = if !stopped {
            RollbackStatus::NotNeeded
        } else if applied.is_empty() {
            RollbackStatus::NotAttempted
        } else {
            let Some(compensate) = options.compensation.as_mut() else {
                return MutationPlanReport::with_operation_reports(
                    outcomes,
                    RollbackStatus::NotAttempted,
                    operation_reports,
                );
            };

            let mut status = RollbackStatus::Completed;

            for (index, prior) in applied.into_iter().rev() {
                let started = Instant::now();

                let operation = plan
                    .operation(index)
                    .expect("applied operation index must exist in the plan");

                let result = compensate(index, operation, prior.as_ref());

                operation_reports[index].phase = MutationExecutionPhase::Compensation;
                operation_reports[index].duration += started.elapsed();

                if let Err(error) = result {
                    operation_reports[index].stop_reason =
                        Some(MutationStopReason::CompensationFailed);

                    status = RollbackStatus::Failed {
                        operation_index: index,
                        error,
                    };

                    break;
                }
            }

            status
        };

        MutationPlanReport::with_operation_reports(outcomes, rollback, operation_reports)
    }

    /// Executes one [`Mutation`] at plan-local `index`: cancellation
    /// boundary, then (if a snapshot hook is installed) prior-state
    /// capture, then native dispatch.
    ///
    /// Extracted so [`Self::execute_plan`] and `execute_apply_plan` (for
    /// [`net_lattice_model::apply::ApplyStep::Single`] steps) run the exact
    /// same per-operation body rather than two independent copies of it.
    /// The returned `bool`-equivalent stop signal is implicit: the caller
    /// stops the plan whenever the returned [`MutationOutcome`] is not
    /// [`MutationOutcome::Applied`] — every non-`Applied` outcome this
    /// method can return (`NotAttempted` for cancellation, `Failed` for a
    /// snapshot or native execution error) already corresponds to a plan
    /// stop in [`Self::execute_plan`]'s original, unmodified contract.
    fn execute_one_mutation(
        &self,
        index: usize,
        operation: &Mutation,
        options: &mut ExecutionOptions<'_>,
    ) -> (
        MutationOutcome,
        MutationOperationReport,
        Option<MutationSnapshot>,
    ) {
        if options
            .cancellation
            .as_mut()
            .is_some_and(|callback| callback(index, operation))
        {
            return (
                MutationOutcome::NotAttempted,
                MutationOperationReport {
                    phase: MutationExecutionPhase::Cancellation,
                    duration: std::time::Duration::ZERO,
                    stop_reason: Some(MutationStopReason::Cancelled),
                },
                None,
            );
        }

        let mut report = MutationOperationReport::not_attempted();

        let prior = match options.snapshot.as_mut() {
            Some(snapshot) => {
                let started = Instant::now();

                match snapshot(index, operation) {
                    Ok(prior) => {
                        report.phase = MutationExecutionPhase::Snapshot;
                        report.duration = started.elapsed();
                        Some(prior)
                    }
                    Err(error) => {
                        report = MutationOperationReport {
                            phase: MutationExecutionPhase::Snapshot,
                            duration: started.elapsed(),
                            stop_reason: Some(MutationStopReason::SnapshotFailed),
                        };
                        return (
                            MutationOutcome::Failed {
                                error,
                                may_have_applied: false,
                            },
                            report,
                            None,
                        );
                    }
                }
            }
            None => None,
        };

        let started = Instant::now();

        let result = match operation {
            Mutation::AddRoute(route) => self.add_route(*route),

            Mutation::RemoveRoute(route) => self.remove_route(*route),

            Mutation::AddAddress(address) => self.add_address(address.clone()).map(|_| ()),

            Mutation::RemoveAddress(address) => self.remove_address(address.clone()),

            Mutation::AddStaticNeighbor(neighbor) => {
                self.add_static_neighbor(*neighbor).map(|_| ())
            }

            Mutation::RemoveStaticNeighbor(neighbor) => self.remove_static_neighbor(*neighbor),

            Mutation::SetDnsConfig(config) => self.set_dns_config(config.clone()).map(|_| ()),

            Mutation::SetInterfaceConfig(config) => {
                self.set_interface_config(config.clone()).map(|_| ())
            }

            Mutation::SetFirewallPolicy(policy) => self.set_firewall_policy(policy.clone()),

            _ => Err(Error::Unsupported),
        };

        match result {
            Ok(()) => {
                report.phase = MutationExecutionPhase::Execution;
                report.duration += started.elapsed();
                (MutationOutcome::Applied, report, prior)
            }

            Err(error) => {
                report = MutationOperationReport {
                    phase: MutationExecutionPhase::Execution,
                    duration: report.duration + started.elapsed(),
                    stop_reason: Some(MutationStopReason::ExecutionFailed),
                };
                (
                    MutationOutcome::Failed {
                        error,
                        may_have_applied: operation.semantics().may_partially_apply,
                    },
                    report,
                    prior,
                )
            }
        }
    }

    /// The full set of runtime-dependent [`Capability`] flags the connected
    /// backend currently has available.
    pub fn capabilities(&self) -> Capability {
        self.backend.capabilities()
    }

    /// Whether the connected backend currently has `capability` available.
    /// Shorthand for `self.capabilities().contains(capability)`.
    pub fn supports(&self, capability: Capability) -> bool {
        self.backend.capabilities().contains(capability)
    }

    /// Subscribes to change notifications. See [`EventReceiver`] for how to
    /// consume the returned events. Prefer `recv`/`try_recv`/`recv_timeout`
    /// when errors must be handled explicitly; `Iterator` terminates on any
    /// receiver error. This is an all-domain request and therefore requires
    /// aggregate [`Capability::MONITORING`].
    ///
    /// ```no_run
    /// use net_lattice::{Lattice, Result};
    ///
    /// fn main() -> Result<()> {
    ///     let lattice = Lattice::connect()?;
    ///     let events = lattice.watch()?;
    ///     loop {
    ///         println!("{:?}", events.recv()?);
    ///     }
    /// }
    /// ```
    pub fn watch(&self) -> Result<EventReceiver<Event>> {
        self.ensure_monitoring_for(&EventFilter::ALL)?;
        self.backend.watch()
    }

    /// Subscribes to async change notifications selected by `filter`.
    ///
    /// This is the Stage 0.11 async watcher API. It has the same filter
    /// semantics as [`Self::watch_filtered`]. Each selected domain must have
    /// its corresponding monitoring capability; an empty filter is valid and
    /// requests no delivery.
    ///
    /// ```no_run
    /// use futures::StreamExt;
    /// use net_lattice::{Lattice, Result};
    /// use net_lattice::monitoring::EventFilter;
    ///
    /// async fn monitor() -> Result<()> {
    ///     let lattice = Lattice::connect()?;
    ///     let mut events = lattice.watch_async(EventFilter::ALL)?;
    ///     while let Some(event) = events.next().await {
    ///         println!("{:?}", event?);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "async")]
    pub fn watch_async(&self, filter: EventFilter) -> Result<EventStream<Event>>
    where
        B: TokioEventProvider<Event = Event, EventFilter = EventFilter>,
    {
        self.ensure_monitoring_for(&filter)?;
        Ok(net_lattice_async::from_tokio_receiver(
            self.backend.watch_tokio(filter)?,
        ))
    }

    /// Subscribes to change notifications selected by `filter`.
    ///
    /// Every selected domain must be advertised by the connected backend:
    /// routes require [`Capability::ROUTE_MONITORING`], interfaces require
    /// [`Capability::INTERFACE_MONITORING`], neighbors require
    /// [`Capability::NEIGHBOR_MONITORING`], and interface addresses require
    /// [`Capability::ADDRESS_MONITORING`]. A request that includes an
    /// unsupported domain returns [`Error::Unsupported`] before native
    /// registration. An empty filter requests no domain and is valid without
    /// a monitoring capability.
    pub fn watch_filtered(&self, filter: EventFilter) -> Result<EventReceiver<Event>> {
        self.ensure_monitoring_for(&filter)?;
        self.backend.watch_filtered(filter)
    }

    /// Like [`Self::watch_filtered`], but also activates the requested
    /// [`Addition`]s and fans their synthesized events into the same
    /// receiver as the native, filter-selected events. See ADR-0014
    /// (`Addition`/`AdditionProvider`'s own rustdoc) for the addition-tier
    /// quality/guarantee caveats: addition-sourced events are ordinary
    /// [`Event`] values once merged, but carry a documented weaker guarantee
    /// tier (bounded-by-poll-interval latency, no ordering guarantee
    /// relative to native events, no coalescing across a poll interval).
    ///
    /// An `additions` bit not currently reported by
    /// [`AdditionProvider::additions`] on the connected backend is silently
    /// not activated — its bit is simply absent from the merged stream —
    /// rather than an error, matching [`Capability`]'s own "query, don't
    /// assume" caller contract. `filter` selection follows the same
    /// per-domain capability rules as [`Self::watch_filtered`].
    ///
    /// Dropping the returned [`EventReceiver`] tears down both the native
    /// subscription and every addition fan-in thread this call started.
    pub fn watch_with_additions(
        &self,
        filter: EventFilter,
        additions: Addition,
    ) -> Result<EventReceiver<Event>> {
        let reported = self.backend.additions() & additions;
        let mut covered_domains = Vec::new();
        let mut native_filter = filter.clone();
        for &(bit, domain) in ADDITION_DOMAINS {
            if reported.contains(bit) && filter.selects_domain(domain) {
                covered_domains.push(domain);
                native_filter = native_filter.without_domain(domain);
            }
        }
        self.ensure_monitoring_for_with_additions(&filter, &covered_domains)?;

        let native = self.backend.watch_filtered(native_filter)?;
        if reported.is_empty() {
            return Ok(native);
        }

        let (sender, receiver) = EventReceiver::bounded();
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        handles.push(spawn_event_fan_in(
            native,
            sender.clone(),
            Arc::clone(&stop),
            None,
        ));
        for bit in reported.iter() {
            if let Ok(addition_receiver) = self.backend.watch_addition(bit) {
                handles.push(spawn_event_fan_in(
                    addition_receiver,
                    sender.clone(),
                    Arc::clone(&stop),
                    Some(filter.clone()),
                ));
            }
        }
        drop(sender);

        Ok(receiver.with_subscription(AdditionMergeGuard { stop, handles }))
    }

    fn ensure_monitoring_for(&self, filter: &EventFilter) -> Result<()> {
        let capabilities = self.capabilities();
        let supported = [
            (EventDomain::Route, Capability::ROUTE_MONITORING),
            (EventDomain::Interface, Capability::INTERFACE_MONITORING),
            (EventDomain::Neighbor, Capability::NEIGHBOR_MONITORING),
            (EventDomain::Address, Capability::ADDRESS_MONITORING),
        ];
        if supported.into_iter().all(|(domain, capability)| {
            !filter.selects_domain(domain) || capabilities.contains(capability)
        }) {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }

    /// Like [`Self::ensure_monitoring_for`], but a domain in
    /// `covered_domains` also satisfies the gate even without its native
    /// [`Capability`] — used only by [`Self::watch_with_additions`], whose
    /// caller has additionally opted into an [`Addition`] covering that
    /// domain.
    fn ensure_monitoring_for_with_additions(
        &self,
        filter: &EventFilter,
        covered_domains: &[EventDomain],
    ) -> Result<()> {
        let capabilities = self.capabilities();
        let supported = [
            (EventDomain::Route, Capability::ROUTE_MONITORING),
            (EventDomain::Interface, Capability::INTERFACE_MONITORING),
            (EventDomain::Neighbor, Capability::NEIGHBOR_MONITORING),
            (EventDomain::Address, Capability::ADDRESS_MONITORING),
        ];
        if supported.into_iter().all(|(domain, capability)| {
            !filter.selects_domain(domain)
                || capabilities.contains(capability)
                || covered_domains.contains(&domain)
        }) {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
}

/// Which [`EventDomain`] each [`Addition`] bit covers, consulted by
/// [`Lattice::watch_with_additions`]'s domain gate and by its native-filter
/// stripping. Extend this table — not a new abstraction — when a future
/// [`Addition`] bit is added.
const ADDITION_DOMAINS: &[(Addition, EventDomain)] =
    &[(Addition::NEIGHBOR_MONITORING_POLLING, EventDomain::Neighbor)];

#[cfg(target_os = "linux")]
impl Lattice<net_lattice_backend_linux::LinuxBackend> {
    /// Connects using the default backend for the current platform.
    pub fn connect() -> Result<Self> {
        #[cfg(test)]
        if FORCE_CONNECT_FAILURE.swap(false, Ordering::SeqCst) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            backend: net_lattice_backend_linux::LinuxBackend::new()?,
        })
    }
}

#[cfg(target_os = "windows")]
impl Lattice<net_lattice_backend_windows::WindowsBackend> {
    /// Connects using the default backend for the current platform.
    pub fn connect() -> Result<Self> {
        #[cfg(test)]
        if FORCE_CONNECT_FAILURE.swap(false, Ordering::SeqCst) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            backend: net_lattice_backend_windows::WindowsBackend::new()?,
        })
    }
}

#[cfg(target_os = "macos")]
impl Lattice<net_lattice_backend_darwin::DarwinBackend> {
    /// Connects using the default backend for the current platform.
    pub fn connect() -> Result<Self> {
        #[cfg(test)]
        if FORCE_CONNECT_FAILURE.swap(false, Ordering::SeqCst) {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            backend: net_lattice_backend_darwin::DarwinBackend::new()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes ignored native facade tests across all platforms. Their
    /// real native networking operations (Netlink on Linux, IP Helper on
    /// Windows, `PF_ROUTE`/SCDynamicStore on macOS) mutate and observe
    /// shared OS-level state — routes, addresses, and change-notification
    /// subscriptions — that is not safe to touch concurrently from more
    /// than one test in this process. On Linux, concurrent route dumps in a
    /// shared CI network namespace can reject concurrent submissions with
    /// `EBUSY`; on Windows and macOS, concurrent native mutation and
    /// notification-subscription tests race on the same interface and can
    /// produce inconsistent or spurious failures. Every ignored/privileged
    /// test in this module takes this guard as its first statement.
    fn native_facade_privileged_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct TestBackend {
        capabilities: Capability,
        fail_events: bool,
        fail_mutations: bool,
        fail_dns_read: bool,
        /// [`Addition`]s this backend reports via [`AdditionProvider::additions`].
        /// Defaults to [`Addition::empty()`] for every existing test, matching
        /// a backend with no addition-tier workaround.
        additions: Addition,
        /// One-shot addition event source consumed by
        /// [`AdditionProvider::watch_addition`]. `None` (the default) makes
        /// `watch_addition` fail even for a bit `additions` reports, mirroring
        /// a misconfigured backend; tests that exercise a real addition set
        /// this explicitly.
        addition_receiver: std::sync::Mutex<Option<EventReceiver<Event>>>,
        /// Counts how many times the [`EventProvider::watch_filtered`]
        /// subscription guard this backend attaches to every watcher has been
        /// dropped, so a test can observe native-subscription teardown.
        native_drops: Arc<std::sync::atomic::AtomicUsize>,
        /// Records the [`EventFilter`] most recently passed to
        /// [`EventProvider::watch_filtered`], so a test can confirm
        /// [`Lattice::watch_with_additions`] strips an addition-covered
        /// domain before forwarding the filter to the native call.
        captured_watch_filter: std::sync::Mutex<Option<EventFilter>>,
    }

    /// Dropped alongside a [`TestBackend`] watcher's native subscription;
    /// increments the backend's `native_drops` counter so a test can confirm
    /// [`Lattice::watch_with_additions`] tears down the native subscription,
    /// not only its addition fan-in threads.
    struct NativeDropGuard(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for NativeDropGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn network() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ))
    }

    /// Observed record matching [`route`]'s intent, seeded into
    /// `TestBackend::routes`. Kept as a separate helper because
    /// `RouteProvider::Route` (observed) and `RouteMutator::RouteConfig`
    /// (intent) are now distinct types (ADR-0008, 0.19).
    fn observed_route() -> Route {
        Route::new(RouteId::new(1), network()).with_interface_index(1)
    }

    fn route() -> RouteConfig {
        RouteConfig::new(network()).with_interface_index(1)
    }

    fn planned_route() -> RouteConfig {
        route().with_metric(7)
    }

    fn ipv6_route() -> RouteConfig {
        let destination = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        RouteConfig::new(destination)
            .with_gateway(IpAddress::from(Ipv6Address::new([
                0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1,
            ])))
            .with_metric(42)
            .with_interface_index(7)
    }

    /// Converts an observed [`Route`] (e.g. read back from
    /// [`Lattice::routes`]) into the [`RouteConfig`] intent
    /// `Mutation::RemoveRoute` now requires, carrying over every field but
    /// the backend-synthesized [`RouteId`] (never accepted back as input).
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn to_route_config(observed: &Route) -> RouteConfig {
        let mut config = RouteConfig::new(observed.destination);
        if let Some(gateway) = observed.gateway {
            config = config.with_gateway(gateway);
        }
        if let Some(metric) = observed.metric {
            config = config.with_metric(metric);
        }
        if let Some(interface_index) = observed.interface_index {
            config = config.with_interface_index(interface_index);
        }
        config
    }

    fn ipv6_address() -> NewInterfaceAddress {
        NewInterfaceAddress::new(
            InterfaceId::new(1),
            Network::from(Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 7]),
                Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
            )),
        )
    }

    fn ipv6_neighbor() -> NeighborEntry {
        NeighborEntry::new(
            NeighborId::new(16),
            1,
            IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1])),
        )
        .with_mac(MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x16]))
        .with_state(NeighborState::Reachable)
    }

    /// The IPv6 counterpart of `existing_static_neighbor`, matching
    /// `ipv6_neighbor`'s `(interface_id, address)`.
    fn existing_ipv6_static_neighbor() -> StaticNeighbor {
        StaticNeighbor::new(
            InterfaceId::new(1),
            IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1])),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x16]),
        )
    }

    /// A static-neighbor intent whose `(interface_id, address)` does not
    /// match any entry `TestBackend::neighbors` reports, so `Add` succeeds
    /// preconditions and `Remove` fails them.
    fn static_neighbor() -> StaticNeighbor {
        StaticNeighbor::new(
            InterfaceId::new(1),
            IpAddress::from(Ipv4Address::new(192, 0, 2, 9)),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
        )
    }

    /// A static-neighbor intent whose `(interface_id, address)` matches the
    /// IPv4 entry `TestBackend::neighbors` already reports, so `Add` fails
    /// preconditions and `Remove` succeeds them.
    fn existing_static_neighbor() -> StaticNeighbor {
        StaticNeighbor::new(
            InterfaceId::new(1),
            IpAddress::from(Ipv4Address::new(192, 0, 2, 1)),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        )
    }

    impl RouteProvider for TestBackend {
        type Route = Route;

        fn routes(&self) -> Result<Vec<Self::Route>> {
            Ok(vec![observed_route()])
        }
    }

    impl RouteMutator for TestBackend {
        type RouteConfig = RouteConfig;

        fn add_route(&self, _route: Self::RouteConfig) -> Result<()> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(())
            }
        }

        fn remove_route(&self, _route: Self::RouteConfig) -> Result<()> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(())
            }
        }
    }

    impl InterfaceProvider for TestBackend {
        type Interface = Interface;

        fn interfaces(&self) -> Result<Vec<Self::Interface>> {
            Ok(vec![Interface::new(
                InterfaceId::new(1),
                1,
                "test0",
                InterfaceKind::Ethernet,
            )])
        }
    }

    impl InterfaceMutator for TestBackend {
        type InterfaceConfig = InterfaceConfig;

        fn set_interface_config(&self, config: Self::InterfaceConfig) -> Result<Self::Interface> {
            if self.fail_mutations {
                return Err(Error::InvalidState);
            }

            let mut interface = self
                .interfaces()?
                .into_iter()
                .find(|interface| interface.id == config.interface_id())
                .ok_or(Error::NotFound)?;
            if let Some(admin_state) = config.admin_state() {
                interface.admin_state = match admin_state {
                    DesiredAdminState::Up => AdminState::Up,
                    DesiredAdminState::Down => AdminState::Down,
                    _ => return Err(Error::Unsupported),
                };
            }
            if let Some(mtu) = config.mtu() {
                interface.mtu = Some(mtu);
            }
            Ok(interface)
        }
    }

    impl DnsProvider for TestBackend {
        type DnsConfig = DnsConfig;

        fn dns_config(&self) -> Result<Self::DnsConfig> {
            if self.fail_dns_read {
                Err(Error::Unsupported)
            } else {
                Ok(DnsConfig::new())
            }
        }
    }

    impl FirewallProvider for TestBackend {
        type FirewallRule = FirewallRule;

        fn firewall_rules(&self) -> Result<Vec<Self::FirewallRule>> {
            Ok(Vec::new())
        }
    }

    impl FirewallMutator for TestBackend {
        type FirewallPolicy = FirewallPolicy;

        fn set_firewall_policy(&self, _policy: Self::FirewallPolicy) -> Result<()> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(())
            }
        }

        fn clear_firewall_policy(&self) -> Result<()> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(())
            }
        }
    }

    impl DnsMutator for TestBackend {
        type NewDnsConfig = NewDnsConfig;

        fn set_dns_config(&self, _config: Self::NewDnsConfig) -> Result<Self::DnsConfig> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(DnsConfig::new())
            }
        }
    }

    impl NeighborProvider for TestBackend {
        type NeighborEntry = NeighborEntry;

        fn neighbors(&self) -> Result<Vec<Self::NeighborEntry>> {
            Ok(vec![
                NeighborEntry::new(
                    NeighborId::new(1),
                    1,
                    IpAddress::from(Ipv4Address::new(192, 0, 2, 1)),
                ),
                ipv6_neighbor(),
            ])
        }
    }

    impl NeighborMutator for TestBackend {
        type StaticNeighbor = StaticNeighbor;
        type NeighborEntry = NeighborEntry;

        fn add_static_neighbor(
            &self,
            neighbor: Self::StaticNeighbor,
        ) -> Result<Self::NeighborEntry> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(NeighborEntry::new(
                    NeighborId::new(1),
                    neighbor.interface_id.value() as u32,
                    neighbor.address,
                )
                .with_mac(neighbor.mac)
                .with_state(NeighborState::Permanent))
            }
        }

        fn remove_static_neighbor(&self, _neighbor: Self::StaticNeighbor) -> Result<()> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(())
            }
        }
    }

    impl AddressProvider for TestBackend {
        type InterfaceAddress = InterfaceAddress;

        fn addresses(&self) -> Result<Vec<Self::InterfaceAddress>> {
            Ok(vec![InterfaceAddress::new(
                InterfaceAddressId::new(1),
                1,
                network(),
            )])
        }
    }

    impl AddressMutator for TestBackend {
        type NewInterfaceAddress = NewInterfaceAddress;
        type InterfaceAddress = InterfaceAddress;

        fn add_address(
            &self,
            address: Self::NewInterfaceAddress,
        ) -> Result<Self::InterfaceAddress> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(InterfaceAddress::new(
                    InterfaceAddressId::new(1),
                    address.interface_id.value() as u32,
                    address.address,
                ))
            }
        }

        fn remove_address(&self, _address: Self::InterfaceAddress) -> Result<()> {
            if self.fail_mutations {
                Err(Error::InvalidState)
            } else {
                Ok(())
            }
        }
    }

    impl CapabilityProvider for TestBackend {
        fn capabilities(&self) -> Capability {
            self.capabilities
        }
    }

    impl EventProvider for TestBackend {
        type Event = Event;
        type EventFilter = EventFilter;

        fn watch(&self) -> Result<EventReceiver<Self::Event>> {
            self.watch_filtered(EventFilter::ALL)
        }

        fn watch_filtered(&self, filter: Self::EventFilter) -> Result<EventReceiver<Self::Event>> {
            *self
                .captured_watch_filter
                .lock()
                .expect("captured_watch_filter mutex poisoned") = Some(filter.clone());
            if self.fail_events {
                return Err(Error::InvalidState);
            }
            let (sender, receiver) = EventReceiver::bounded();
            let event = Event::Route {
                id: RouteId::new(1),
                kind: ChangeKind::Added,
            };
            let guard = NativeDropGuard(Arc::clone(&self.native_drops));
            if filter.matches(event) {
                assert!(sender.send(event, Event::resync_all()));
                Ok(receiver.with_subscription((sender, guard)))
            } else {
                // Keep an empty filtered watcher connected, matching a real
                // subscription that remains active while it waits for a
                // matching event.
                Ok(receiver.with_subscription((sender, guard)))
            }
        }
    }

    impl AdditionProvider for TestBackend {
        fn additions(&self) -> Addition {
            self.additions
        }

        fn watch_addition(&self, addition: Addition) -> Result<EventReceiver<Event>> {
            if !self.additions.contains(addition) {
                return Err(Error::Unsupported);
            }
            self.addition_receiver
                .lock()
                .expect("addition receiver mutex poisoned")
                .take()
                .ok_or(Error::Unsupported)
        }
    }

    #[cfg(feature = "async")]
    impl TokioEventProvider for TestBackend {
        type Event = Event;
        type EventFilter = EventFilter;

        fn watch_tokio(
            &self,
            filter: Self::EventFilter,
        ) -> Result<net_lattice_platform::TokioEventReceiver<Self::Event>> {
            if self.fail_events {
                return Err(Error::InvalidState);
            }
            let (sender, receiver) = net_lattice_platform::TokioEventReceiver::bounded();
            let event = Event::Route {
                id: RouteId::new(1),
                kind: ChangeKind::Added,
            };
            if filter.matches(event) {
                assert!(sender.send(event, Event::resync_all));
                Ok(receiver)
            } else {
                Ok(receiver.with_subscription(sender))
            }
        }
    }

    fn lattice(capabilities: Capability) -> Lattice<TestBackend> {
        Lattice {
            backend: TestBackend {
                capabilities,
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        }
    }

    #[test]
    fn facade_forwards_all_read_and_mutation_operations() {
        let lattice = lattice(
            Capability::MONITORING
                | Capability::DNS_MUTATION
                | Capability::INTERFACE_ADMIN_STATE
                | Capability::INTERFACE_MTU,
        );
        let route = route();
        let address = NewInterfaceAddress::new(InterfaceId::new(1), network());

        assert_eq!(lattice.routes().expect("routes").len(), 1);
        lattice.add_route(route).expect("add route");
        lattice.remove_route(route).expect("remove route");
        assert_eq!(lattice.interfaces().expect("interfaces").len(), 1);
        assert_eq!(lattice.dns_config().expect("dns").nameservers.len(), 0);
        let neighbors = lattice.neighbors().expect("neighbors");
        assert_eq!(neighbors.len(), 2);
        assert!(neighbors.contains(&ipv6_neighbor()));
        let ipv6_neighbor = ipv6_neighbor();
        let neighbor_filter = EventFilter::none().neighbor(ipv6_neighbor.id);
        assert!(neighbor_filter.matches(Event::Neighbor {
            id: ipv6_neighbor.id,
            kind: ChangeKind::Changed,
        }));
        assert!(!neighbor_filter.matches(Event::Neighbor {
            id: NeighborId::new(17),
            kind: ChangeKind::Changed,
        }));
        assert_eq!(lattice.addresses().expect("addresses").len(), 1);
        let observed = lattice.add_address(address).expect("add address");
        lattice.remove_address(observed).expect("remove address");
        assert_eq!(
            lattice
                .set_dns_config(NewDnsConfig::new())
                .expect("set DNS")
                .search_domains
                .len(),
            0
        );
        let configured = lattice
            .set_interface_config(
                InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), Some(1500))
                    .expect("valid config"),
            )
            .expect("configure interface");
        assert_eq!(configured.admin_state, AdminState::Up);
        assert_eq!(configured.mtu, Some(1500));
        assert!(lattice.firewall_rules().expect("firewall rules").is_empty());
        lattice
            .set_firewall_policy(FirewallPolicy::new(Verdict::Deny))
            .expect("set firewall policy");
        lattice
            .clear_firewall_policy()
            .expect("clear firewall policy");
    }

    #[test]
    fn current_state_assembles_all_six_domains() {
        let lattice = lattice(Capability::empty());

        let state = lattice.current_state().expect("current state");

        assert_eq!(state.routes, lattice.routes().expect("routes"));
        assert_eq!(state.interfaces, lattice.interfaces().expect("interfaces"));
        assert_eq!(state.neighbors, lattice.neighbors().expect("neighbors"));
        assert_eq!(state.addresses, lattice.addresses().expect("addresses"));
        assert_eq!(state.dns, lattice.dns_config().expect("dns"));
        assert_eq!(
            state.firewall_rules,
            lattice.firewall_rules().expect("firewall rules")
        );
    }

    #[test]
    fn current_state_fails_fast_and_returns_no_partial_state_on_dns_read_failure() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::empty(),
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: true,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        let result = lattice.current_state();

        assert!(matches!(result, Err(Error::Unsupported)));
    }

    /// Facade-level coverage for `net_lattice::mutation::{DesiredState,
    /// Diff}`, re-exported from `net-lattice-model` (see `NL-58`) — proves
    /// the re-export actually resolves and behaves correctly when driven
    /// through `Lattice::current_state()`, not just that the underlying
    /// `net-lattice-model` crate's own unit tests pass. `Diff::compute` is
    /// pure (no I/O, no native calls, see ADR NL-A-12/ADR-0010), so no
    /// privileged/`#[ignore]` test is needed for it specifically — it needs
    /// nothing beyond the two already-in-memory state values, which
    /// `TestBackend` supplies deterministically here.
    #[test]
    fn facade_diff_reports_no_changes_when_desired_matches_observed() {
        let lattice = lattice(Capability::empty());
        let current = lattice.current_state().expect("current state");
        let desired = DesiredState::empty().with_routes(vec![route()]);

        let diff = Diff::compute(&current, &desired);

        assert!(diff.routes.is_empty());
        assert!(diff.interfaces.is_empty());
        assert!(diff.neighbors.is_empty());
        assert!(diff.addresses.is_empty());
        assert!(diff.dns.is_none());
    }

    #[test]
    fn facade_diff_reports_added_and_removed_routes_when_desired_differs() {
        let lattice = lattice(Capability::empty());
        let current = lattice.current_state().expect("current state");
        let desired = DesiredState::empty().with_routes(vec![planned_route()]);

        let diff = Diff::compute(&current, &desired);

        assert_eq!(diff.routes.len(), 2);
        assert!(diff.routes.iter().any(
            |change| matches!(change, RouteChange::Added(added) if *added == planned_route())
        ));
        assert!(diff.routes.iter().any(
            |change| matches!(change, RouteChange::Removed(removed) if *removed == observed_route())
        ));
    }

    #[test]
    fn facade_diff_reports_no_changes_for_unmanaged_domains() {
        let lattice = lattice(Capability::empty());
        let current = lattice.current_state().expect("current state");
        let desired = DesiredState::empty();

        let diff = Diff::compute(&current, &desired);

        assert!(diff.routes.is_empty());
        assert!(diff.interfaces.is_empty());
        assert!(diff.neighbors.is_empty());
        assert!(diff.addresses.is_empty());
        assert!(diff.dns.is_none());
    }

    /// A route destination distinct from [`network`] (`observed_route`'s
    /// destination), so a [`DesiredState`] can request adding it without
    /// pairing against the already-observed route as a
    /// [`net_lattice_model::apply::ApplyStep::ReplaceRoute`] candidate.
    fn extra_network() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(203, 0, 113, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ))
    }

    fn extra_route() -> RouteConfig {
        RouteConfig::new(extra_network()).with_interface_index(1)
    }

    /// Facade-level coverage for [`Lattice::apply`] — proves the
    /// `current_state` → `Diff::compute` → `ApplyPlan::compile` →
    /// `execute_apply_plan` chain it wraps actually resolves and executes
    /// end to end, not just that each step passes in isolation (already
    /// covered by the `facade_diff_*` tests above and `executor::apply`'s
    /// own unit tests).
    #[test]
    fn facade_apply_reports_no_changes_when_desired_matches_observed() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        let desired = DesiredState::empty().with_routes(vec![route()]);

        let report = lattice
            .apply(&desired, &mut ExecutionOptions::default())
            .expect("apply");

        assert_eq!(report.len(), 0);
        assert!(report.is_success());
        assert!(matches!(report.rollback(), RollbackStatus::NotNeeded));
    }

    #[test]
    fn facade_apply_executes_an_added_route() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        // Keep the already-observed route unchanged and additionally
        // request a route at a distinct destination, so `Diff::compute`
        // produces exactly one unpaired `Added` route and `ApplyPlan::compile`
        // lowers it to a single `ApplyStep::Single(Mutation::AddRoute(_))`
        // rather than an `ApplyStep::ReplaceRoute` (see ADR-0012 Decision 4).
        let desired = DesiredState::empty().with_routes(vec![route(), extra_route()]);

        let report = lattice
            .apply(&desired, &mut ExecutionOptions::default())
            .expect("apply");

        assert_eq!(report.len(), 1);
        assert!(report.is_success(), "{report:?}");
        assert_eq!(report.applied_count(), 1);
    }

    #[test]
    fn facade_apply_rejects_a_plan_the_backend_lacks_capability_for() {
        let lattice = lattice(Capability::empty());
        let desired = DesiredState::empty().with_routes(vec![route(), extra_route()]);

        let report = lattice
            .apply(&desired, &mut ExecutionOptions::default())
            .expect("apply");

        assert!(!report.is_success());
        assert_eq!(report.rejected_count(), 1);
    }

    #[test]
    fn facade_apply_propagates_a_current_state_read_failure() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::ROUTE_MUTATION,
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: true,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };
        let desired = DesiredState::empty().with_routes(vec![extra_route()]);

        let result = lattice.apply(&desired, &mut ExecutionOptions::default());

        assert!(matches!(result, Err(Error::Unsupported)));
    }

    /// Facade-level coverage for [`Lattice::diff`] — proves the
    /// `current_state` → `Diff::compute` chain it wraps actually resolves
    /// and matches what a caller would get by writing the two steps out by
    /// hand (already covered by the `facade_diff_*` tests above).
    #[test]
    fn facade_lattice_diff_matches_the_hand_written_current_state_then_compute_chain() {
        let lattice = lattice(Capability::empty());
        let desired = DesiredState::empty().with_routes(vec![route(), extra_route()]);

        let diff = lattice.diff(&desired).expect("diff");

        let current = lattice.current_state().expect("current state");
        let expected = Diff::compute(&current, &desired);
        assert_eq!(diff, expected);
        assert_eq!(diff.routes.len(), 1);
    }

    #[test]
    fn facade_validates_and_executes_interface_configuration() {
        let lattice = lattice(Capability::INTERFACE_ADMIN_STATE | Capability::INTERFACE_MTU);
        let admin_only =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Down), None)
                .expect("valid admin config");
        let mtu_only =
            InterfaceConfig::new(InterfaceId::new(1), None, Some(9000)).expect("valid MTU config");
        let combined =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), Some(1500))
                .expect("valid combined config");

        assert_eq!(
            lattice
                .set_interface_config(admin_only)
                .expect("admin-only config")
                .admin_state,
            AdminState::Down
        );
        assert_eq!(
            lattice
                .set_interface_config(mtu_only)
                .expect("MTU-only config")
                .mtu,
            Some(9000)
        );
        let plan = MutationPlan::from_operations([Mutation::SetInterfaceConfig(combined)]);
        lattice.validate_plan(&plan).expect("valid plan");
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);
        assert!(report.is_success());
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
    }

    #[test]
    fn facade_rejects_interface_config_missing_capability_or_target() {
        let admin = InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), None)
            .expect("valid admin config");
        let mtu =
            InterfaceConfig::new(InterfaceId::new(1), None, Some(1500)).expect("valid MTU config");
        assert!(matches!(
            lattice(Capability::empty()).set_interface_config(admin),
            Err(Error::Unsupported)
        ));
        assert!(matches!(
            lattice(Capability::INTERFACE_ADMIN_STATE).set_interface_config(mtu),
            Err(Error::Unsupported)
        ));

        let missing =
            InterfaceConfig::new(InterfaceId::new(99), None, Some(1500)).expect("valid config");
        assert!(matches!(
            lattice(Capability::INTERFACE_MTU).set_interface_config(missing),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn facade_reports_partial_interface_configuration_failure() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::INTERFACE_ADMIN_STATE | Capability::INTERFACE_MTU,
                fail_events: false,
                fail_mutations: true,
                fail_dns_read: false,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };
        let config =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), Some(1500))
                .expect("valid combined config");
        let plan = MutationPlan::from_operations([Mutation::SetInterfaceConfig(config)]);
        let mut captured = false;
        let mut snapshot = |_, operation: &Mutation| {
            captured = matches!(operation, Mutation::SetInterfaceConfig(_));
            lattice.snapshot_for_mutation(operation)
        };
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(captured);
        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                may_have_applied: true,
                ..
            })
        ));
        assert!(matches!(
            report
                .operation_report(0)
                .expect("operation report")
                .stop_reason,
            Some(MutationStopReason::ExecutionFailed)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }

    #[test]
    fn facade_executes_ordered_plan_and_preserves_report_indices() {
        let lattice = lattice(Capability::DNS_MUTATION | Capability::ROUTE_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(planned_route()),
            Mutation::SetDnsConfig(NewDnsConfig::new()),
        ]);

        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(report.len(), plan.len());
        assert!(report.is_success());
        assert_eq!(report.applied_count(), 2);
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(report.outcome(1), Some(MutationOutcome::Applied)));
        assert!(matches!(report.rollback(), RollbackStatus::NotNeeded));
        assert_eq!(report.operation_reports().len(), plan.len());
        assert!(matches!(
            report.operation_reports()[0].phase,
            MutationExecutionPhase::Execution
        ));
    }

    #[test]
    fn facade_cancellation_stops_at_an_operation_boundary() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(planned_route()),
            Mutation::RemoveRoute(planned_route()),
        ]);

        let mut cancelled = |index, _: &Mutation| index == 1;
        let mut options = ExecutionOptions::default().cancellation(&mut cancelled);
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.not_attempted_count(), 1);
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(
            report.operation_reports()[1].stop_reason,
            Some(MutationStopReason::Cancelled)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }

    #[test]
    /// Contract test: a failing resolver write is reported as potentially
    /// partially applied without touching the host resolver configuration.
    fn facade_reports_partial_application_boundary_on_failed_dns_operation() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::DNS_MUTATION,
                fail_events: false,
                fail_mutations: true,
                fail_dns_read: false,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };
        let plan = MutationPlan::from_operations([Mutation::SetDnsConfig(NewDnsConfig::new())]);

        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                may_have_applied: true,
                ..
            })
        ));
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
        assert!(matches!(
            report.operation_reports()[0].stop_reason,
            Some(MutationStopReason::ExecutionFailed)
        ));
    }

    #[test]
    fn facade_executes_a_firewall_policy_plan() {
        let lattice = lattice(Capability::FIREWALL_MUTATION);
        let policy = FirewallPolicy::new(Verdict::Deny);
        let plan = MutationPlan::from_operations([Mutation::SetFirewallPolicy(policy)]);

        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(report.is_success());
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
    }

    #[test]
    fn facade_rejects_firewall_policy_plan_without_firewall_mutation_capability() {
        let lattice = lattice(Capability::empty());
        let policy = FirewallPolicy::new(Verdict::Allow);

        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([
                Mutation::SetFirewallPolicy(policy)
            ])),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn facade_executes_mixed_family_dns_plan_without_host_writes() {
        let lattice = lattice(Capability::DNS_MUTATION);
        let config = NewDnsConfig::with(
            vec![
                IpAddress::from(Ipv4Address::new(1, 1, 1, 1)),
                IpAddress::from(Ipv6Address::new([
                    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
                ])),
            ],
            vec!["example.test".to_string()],
        );
        let plan = MutationPlan::from_operations([
            Mutation::SetDnsConfig(config.clone()),
            Mutation::SetDnsConfig(config),
        ]);

        lattice
            .validate_plan(&plan)
            .expect("DNS capability and plan");
        assert!(matches!(
            lattice.snapshot_for_mutation(plan.operation(0).unwrap()),
            Ok(MutationSnapshot::Dns(_))
        ));

        let mut cancellation = |index, _: &Mutation| index == 1;
        let mut options = ExecutionOptions::default().cancellation(&mut cancellation);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.not_attempted_count(), 1);
    }

    #[test]
    fn facade_rejects_unsupported_capability_before_submitting_a_plan() {
        let lattice = lattice(Capability::empty());
        let plan = MutationPlan::from_operations([
            Mutation::SetDnsConfig(NewDnsConfig::new()),
            Mutation::AddRoute(planned_route()),
        ]);

        assert!(matches!(
            lattice.validate_plan(&plan),
            Err(Error::Unsupported)
        ));
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);
        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                error: Error::Unsupported,
                may_have_applied: false,
            })
        ));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(
            report.operation_reports()[0].stop_reason,
            Some(MutationStopReason::ValidationFailed)
        ));
    }

    #[test]
    fn facade_validates_route_and_address_preconditions() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([
                Mutation::AddRoute(route())
            ])),
            Err(Error::AlreadyExists)
        ));
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([Mutation::RemoveRoute(
                planned_route()
            )])),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([Mutation::AddAddress(
                NewInterfaceAddress::new(InterfaceId::new(99), network())
            )])),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([Mutation::RemoveAddress(
                InterfaceAddress::new(InterfaceAddressId::new(99), 99, network())
            )])),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn facade_captures_native_snapshots_for_each_mutation_domain() {
        let lattice = lattice(Capability::DNS_MUTATION);
        let route = route();
        let address = NewInterfaceAddress::new(InterfaceId::new(1), network());
        let observed_address = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network());

        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::AddRoute(route)),
            Ok(MutationSnapshot::Route(Some(_)))
        ));
        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::AddAddress(address)),
            Ok(MutationSnapshot::InterfaceAddress(Some(_)))
        ));
        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::RemoveAddress(observed_address)),
            Ok(MutationSnapshot::InterfaceAddress(Some(_)))
        ));
        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::SetDnsConfig(NewDnsConfig::new())),
            Ok(MutationSnapshot::Dns(_))
        ));
        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::SetFirewallPolicy(FirewallPolicy::new(
                Verdict::Allow
            ))),
            Ok(MutationSnapshot::Firewall(_))
        ));
        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::SetInterfaceConfig(
                InterfaceConfig::new(InterfaceId::new(1), None, Some(1500)).expect("valid config")
            )),
            Ok(MutationSnapshot::Interface(Some(_)))
        ));
        assert!(matches!(
            lattice.snapshot_for_mutation(&Mutation::AddStaticNeighbor(static_neighbor())),
            Ok(MutationSnapshot::Neighbor(None))
        ));
        assert!(matches!(
            lattice
                .snapshot_for_mutation(&Mutation::RemoveStaticNeighbor(existing_static_neighbor())),
            Ok(MutationSnapshot::Neighbor(Some(_)))
        ));
    }

    #[test]
    fn facade_rejects_static_neighbor_plan_without_neighbor_mutation_capability() {
        let lattice = lattice(Capability::empty());
        let plan = MutationPlan::from_operations([Mutation::AddStaticNeighbor(static_neighbor())]);

        assert!(matches!(
            lattice.validate_plan(&plan),
            Err(Error::Unsupported)
        ));
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);
        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                error: Error::Unsupported,
                may_have_applied: false,
            })
        ));
        assert!(matches!(
            report.operation_reports()[0].stop_reason,
            Some(MutationStopReason::ValidationFailed)
        ));
    }

    #[test]
    fn facade_validates_static_neighbor_preconditions() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION);

        // Missing interface.
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([
                Mutation::AddStaticNeighbor(StaticNeighbor::new(
                    InterfaceId::new(99),
                    IpAddress::from(Ipv4Address::new(192, 0, 2, 9)),
                    MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x09]),
                ))
            ])),
            Err(Error::NotFound)
        ));

        // Duplicate target (IPv4 and IPv6): the target already exists.
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([
                Mutation::AddStaticNeighbor(existing_static_neighbor())
            ])),
            Err(Error::AlreadyExists)
        ));
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([
                Mutation::AddStaticNeighbor(existing_ipv6_static_neighbor())
            ])),
            Err(Error::AlreadyExists)
        ));

        // Absent target: nothing to remove.
        assert!(matches!(
            lattice.validate_plan(&MutationPlan::from_operations([
                Mutation::RemoveStaticNeighbor(static_neighbor())
            ])),
            Err(Error::NotFound)
        ));

        // Valid plans.
        lattice
            .validate_plan(&MutationPlan::from_operations([
                Mutation::AddStaticNeighbor(static_neighbor()),
            ]))
            .expect("new static neighbor is addable");
        lattice
            .validate_plan(&MutationPlan::from_operations([
                Mutation::RemoveStaticNeighbor(existing_static_neighbor()),
            ]))
            .expect("existing static neighbor is removable");
        lattice
            .validate_plan(&MutationPlan::from_operations([
                Mutation::RemoveStaticNeighbor(existing_ipv6_static_neighbor()),
            ]))
            .expect("existing ipv6 static neighbor is removable");
    }

    #[test]
    fn facade_executes_static_neighbor_plan_and_preserves_report_indices() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION | Capability::ROUTE_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(static_neighbor()),
            Mutation::AddRoute(planned_route()),
        ]);

        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(report.len(), plan.len());
        assert!(report.is_success());
        assert_eq!(report.applied_count(), 2);
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(report.outcome(1), Some(MutationOutcome::Applied)));
        assert!(matches!(report.rollback(), RollbackStatus::NotNeeded));
    }

    #[test]
    fn facade_cancellation_stops_static_neighbor_plan_at_an_operation_boundary() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(static_neighbor()),
            Mutation::RemoveStaticNeighbor(existing_static_neighbor()),
        ]);

        let mut cancelled = |index, _: &Mutation| index == 1;
        let mut options = ExecutionOptions::default().cancellation(&mut cancelled);
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(report.applied_count(), 1);
        assert_eq!(report.not_attempted_count(), 1);
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(
            report.operation_reports()[1].stop_reason,
            Some(MutationStopReason::Cancelled)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }

    #[test]
    /// Contract test: `AddStaticNeighbor`/`RemoveStaticNeighbor` are
    /// `may_partially_apply = false` per ADR-0001, so a native failure is
    /// reported without the partial-application caveat `SetDnsConfig`/
    /// `SetInterfaceConfig` carry.
    fn facade_reports_no_partial_application_on_failed_static_neighbor_operation() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::NEIGHBOR_MUTATION,
                fail_events: false,
                fail_mutations: true,
                fail_dns_read: false,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };
        let add_plan =
            MutationPlan::from_operations([Mutation::AddStaticNeighbor(static_neighbor())]);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&add_plan, &mut options);
        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                may_have_applied: false,
                ..
            })
        ));
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));

        let remove_plan = MutationPlan::from_operations([Mutation::RemoveStaticNeighbor(
            existing_static_neighbor(),
        )]);
        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&remove_plan, &mut options);
        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                may_have_applied: false,
                ..
            })
        ));
    }

    #[test]
    fn facade_executes_and_compensates_a_static_neighbor_plan() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION);
        let neighbor = static_neighbor();
        let observed = NeighborEntry::new(
            NeighborId::new(1),
            neighbor.interface_id.value() as u32,
            neighbor.address,
        )
        .with_mac(neighbor.mac)
        .with_state(NeighborState::Permanent);
        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(neighbor),
            Mutation::RemoveStaticNeighbor(StaticNeighbor::new(
                neighbor.interface_id,
                observed.address,
                neighbor.mac,
            )),
        ]);
        lattice
            .validate_plan(&plan)
            .expect("static neighbor plan is valid before execution");

        let mut snapshots = Vec::new();
        let mut compensated = Vec::new();
        let mut cancellation = |index, _: &Mutation| index == 1;
        let mut snapshot = |index, operation: &Mutation| {
            snapshots.push((index, operation.clone()));
            lattice.snapshot_for_mutation(operation)
        };
        let mut compensate = |index, operation: &Mutation, prior: Option<&MutationSnapshot>| {
            compensated.push((index, operation.clone(), prior.cloned()));
            Ok(())
        };
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancellation)
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));
        assert_eq!(snapshots, vec![(0, Mutation::AddStaticNeighbor(neighbor))]);
        assert_eq!(
            compensated,
            vec![(
                0,
                Mutation::AddStaticNeighbor(neighbor),
                Some(MutationSnapshot::Neighbor(None))
            )]
        );
    }

    #[test]
    fn facade_reports_snapshot_failure_for_static_neighbor_operation() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION);
        let plan = MutationPlan::from_operations([Mutation::AddStaticNeighbor(static_neighbor())]);

        let mut snapshot = |_, _: &Mutation| Err(Error::InvalidState);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(
            report.outcome(0),
            Some(MutationOutcome::Failed {
                error: Error::InvalidState,
                may_have_applied: false,
            })
        ));
        assert!(matches!(
            report.operation_reports()[0].stop_reason,
            Some(MutationStopReason::SnapshotFailed)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::NotAttempted));
    }

    #[test]
    fn facade_executes_static_neighbor_add_and_remove_dispatch() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(static_neighbor()),
            Mutation::RemoveStaticNeighbor(existing_static_neighbor()),
        ]);
        lattice
            .validate_plan(&plan)
            .expect("add and remove target distinct neighbors");

        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(report.applied_count(), 2);
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(report.outcome(1), Some(MutationOutcome::Applied)));
        assert!(matches!(report.rollback(), RollbackStatus::NotNeeded));
    }

    #[test]
    fn facade_executes_ipv6_static_neighbor_add_and_remove_dispatch() {
        let lattice = lattice(Capability::NEIGHBOR_MUTATION);
        let neighbor = StaticNeighbor::new(
            InterfaceId::new(1),
            IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0x17, 0, 0, 0, 1])),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x17]),
        );
        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(neighbor),
            Mutation::RemoveStaticNeighbor(existing_ipv6_static_neighbor()),
        ]);
        lattice
            .validate_plan(&plan)
            .expect("add and remove target distinct ipv6 neighbors");

        let mut options = ExecutionOptions::default();
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(report.applied_count(), 2);
        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(report.outcome(1), Some(MutationOutcome::Applied)));
        assert!(matches!(report.rollback(), RollbackStatus::NotNeeded));
    }

    /// Restores the observed interface configuration through the same public
    /// facade a consumer uses. The privileged acceptance test arms this before
    /// its first native submission so a panic cannot leave an attempted
    /// configuration behind.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    struct InterfaceConfigRestore<'a, B: LatticeBackend> {
        lattice: &'a Lattice<B>,
        config: InterfaceConfig,
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    impl<B: LatticeBackend> Drop for InterfaceConfigRestore<'_, B> {
        fn drop(&mut self) {
            let _ = self.lattice.set_interface_config(self.config.clone());
        }
    }

    /// Removes a submitted native test route if a later assertion exits the
    /// test before its explicit remove plan succeeds. This is test cleanup,
    /// not executor rollback.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    struct RouteRestore<'a, B: LatticeBackend> {
        lattice: &'a Lattice<B>,
        route: Option<RouteConfig>,
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    impl<B: LatticeBackend> Drop for RouteRestore<'_, B> {
        fn drop(&mut self) {
            if let Some(route) = self.route.take() {
                let _ = self.lattice.remove_route(route);
            }
        }
    }

    /// Removes a submitted native test address if a later assertion exits
    /// the test before its explicit remove plan succeeds. This is test
    /// cleanup, not executor rollback, mirroring `RouteRestore`'s shape for
    /// `InterfaceAddress`.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    struct AddressRestore<'a, B: LatticeBackend> {
        lattice: &'a Lattice<B>,
        address: Option<InterfaceAddress>,
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    impl<B: LatticeBackend> Drop for AddressRestore<'_, B> {
        fn drop(&mut self) {
            if let Some(address) = self.address.take() {
                let _ = self.lattice.remove_address(address);
            }
        }
    }

    /// Removes a submitted native test static neighbor if a later assertion
    /// exits the test before its explicit remove plan succeeds. Mirrors
    /// `RouteRestore`'s shape for `StaticNeighbor`.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    struct StaticNeighborRestore<'a, B: LatticeBackend> {
        lattice: &'a Lattice<B>,
        neighbor: Option<StaticNeighbor>,
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    impl<B: LatticeBackend> Drop for StaticNeighborRestore<'_, B> {
        fn drop(&mut self) {
            if let Some(neighbor) = self.neighbor.take() {
                let _ = self.lattice.remove_static_neighbor(neighbor);
            }
        }
    }

    /// Picks a non-loopback, administratively-up interface with an assigned
    /// IPv4 address, plus an unused address in that same on-link subnet, for
    /// native static-neighbor tests.
    ///
    /// Static ARP/NDP entries are an L2-resolution mechanism; unlike routes
    /// and addresses (which the other native facade tests deliberately
    /// prefer on loopback for stability), loopback interfaces do not
    /// participate in L2 neighbor resolution the same way and at least one
    /// backend is known to force ARP entries on `lo` to a non-`Permanent`
    /// state. An initial version of this helper picked any non-loopback
    /// interface and used a fixed documentation-range address (RFC 5737
    /// `192.0.2.0/24`) regardless of what subnet the interface actually
    /// carried; on CI runners this produced `ENETUNREACH`
    /// (`Error::Platform(Darwin(51))`) on macOS and `Error::NotFound` on
    /// Windows, and an intermittent failure on Linux — evidence that at
    /// least some backends validate on-link reachability for a static
    /// neighbor's destination against the target interface's own subnet.
    /// This version instead derives a target address from an address the
    /// interface actually has assigned, so the destination is always on-link
    /// for the interface it's being added against.
    ///
    /// `offset` selects which spare host address in the subnet to use (1 =
    /// the usual second-to-last address, 2 = the next one down, ...) so that
    /// two privileged tests running back-to-back under the shared
    /// [`native_facade_privileged_guard`] mutex target distinct addresses on
    /// the same interface, rather than racing on the same
    /// `(interface, address)` static-neighbor identity. An earlier version
    /// of this helper always picked the same address for every caller; when
    /// one test's native delete (`DeleteIpNetEntry2`) and the next test's
    /// native create (`CreateIpNetEntry2`) for that identical address landed
    /// back-to-back with no gap, Windows CI observed the create fail with
    /// `ERROR_OBJECT_ALREADY_EXISTS` (surfaced as `Error::AlreadyExists`) —
    /// evidence the OS had not yet fully retired the deleted row internally.
    /// Distinct addresses per caller remove the dependency on that
    /// delete-then-recreate timing entirely, without touching any backend.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn native_neighbor_test_target<B: LatticeBackend>(
        lattice: &Lattice<B>,
        offset: u32,
    ) -> (Interface, IpAddress) {
        let interfaces = lattice.interfaces().expect("failed to list interfaces");
        let addresses = lattice.addresses().expect("failed to list addresses");

        interfaces
            .iter()
            .filter(|interface| {
                !matches!(interface.kind, InterfaceKind::Loopback)
                    && matches!(interface.admin_state, AdminState::Up | AdminState::Unknown)
            })
            .find_map(|interface| {
                let assigned = addresses.iter().find_map(|address| {
                    if address.interface_index != interface.index {
                        return None;
                    }
                    match address.address {
                        Network::V4(network) => Some(network),
                        Network::V6(_) => None,
                    }
                })?;
                let target = unused_ipv4_in_subnet(assigned, offset)?;
                Some((interface.clone(), IpAddress::from(target)))
            })
            .expect(
                "native backend reported no non-loopback, up interface with an assigned IPv4 \
                 address; static-neighbor facade tests require one",
            )
    }

    /// Returns an address in `network`'s subnet distinct from `network`'s own
    /// assigned address, preferring the `offset`-th usable host address
    /// counting down from the broadcast address (`offset = 1` is the usual
    /// second-to-last address; the last is the broadcast address on most
    /// prefix lengths). Skips the interface's own address if the initial
    /// candidate collides with it. Returns `None` for prefixes too short to
    /// have a distinct usable host address (`/31`, `/32`) or for an `offset`
    /// that runs past the start of the subnet.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn unused_ipv4_in_subnet(network: Ipv4Network, offset: u32) -> Option<Ipv4Address> {
        let prefix = network.prefix().value();
        if !(1..31).contains(&prefix) {
            return None;
        }
        let host = u32::from_be_bytes(network.address().octets());
        let mask = !0u32 << (32 - prefix);
        let base = host & mask;
        let broadcast = base | !mask;
        let mut candidate = broadcast.checked_sub(offset)?;
        if candidate == host {
            candidate = candidate.checked_sub(1)?;
        }
        if candidate <= base {
            return None;
        }
        Some(Ipv4Address::from(std::net::Ipv4Addr::from(
            candidate.to_be_bytes(),
        )))
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    fn unused_ipv4_in_subnet_picks_a_distinct_on_link_address() {
        let network = Ipv4Network::new(
            Ipv4Address::new(192, 168, 1, 5),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        );
        let candidate = unused_ipv4_in_subnet(network, 1).expect("subnet has a spare address");
        assert_eq!(candidate, Ipv4Address::new(192, 168, 1, 254));

        // A larger offset picks a different, still-distinct spare address.
        let candidate = unused_ipv4_in_subnet(network, 2).expect("subnet has a spare address");
        assert_eq!(candidate, Ipv4Address::new(192, 168, 1, 253));

        // The interface's own address happens to be the usual spare pick;
        // the fallback must still land inside the subnet and stay distinct.
        let host_is_254 = Ipv4Network::new(
            Ipv4Address::new(10, 0, 0, 254),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        );
        let candidate = unused_ipv4_in_subnet(host_is_254, 1).expect("subnet has a spare address");
        assert_ne!(candidate, Ipv4Address::new(10, 0, 0, 254));
        assert_eq!(candidate, Ipv4Address::new(10, 0, 0, 253));

        // /31 and /32 have no distinct spare host address.
        assert!(
            unused_ipv4_in_subnet(
                Ipv4Network::new(
                    Ipv4Address::new(192, 168, 1, 1),
                    Ipv4PrefixLength::new(31).expect("valid prefix"),
                ),
                1
            )
            .is_none()
        );
        assert!(
            unused_ipv4_in_subnet(
                Ipv4Network::new(
                    Ipv4Address::new(192, 168, 1, 1),
                    Ipv4PrefixLength::new(32).expect("valid prefix"),
                ),
                1
            )
            .is_none()
        );
    }

    /// Exercises the complete facade transaction path for a static ARP entry
    /// against the native backend: capability-gated `execute_plan` add,
    /// read-after-write observation, and `execute_plan` remove. Intentionally
    /// ignored because static-neighbor mutation requires root/CAP_NET_ADMIN/
    /// Administrator and changes the host neighbor table.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_static_neighbor_transaction_round_trip -- --ignored`"]
    fn native_facade_static_neighbor_transaction_round_trip() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        assert!(
            lattice.supports(Capability::NEIGHBOR_MUTATION),
            "native backend does not advertise NEIGHBOR_MUTATION"
        );
        let (interface, target) = native_neighbor_test_target(&lattice, 1);
        let neighbor = StaticNeighbor::new(
            interface.id,
            target,
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xfa]),
        );

        // Recover from an interrupted prior run before attempting the add.
        let _ = lattice.remove_static_neighbor(neighbor);

        let add_plan = MutationPlan::from_operations([Mutation::AddStaticNeighbor(neighbor)]);
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let add_report = lattice.execute_plan(&add_plan, &mut options);
        assert!(
            add_report.is_success(),
            "static neighbor add report: {add_report:?}"
        );
        let mut restore = StaticNeighborRestore {
            lattice: &lattice,
            neighbor: Some(neighbor),
        };

        let observed = lattice
            .neighbors()
            .expect("failed to read neighbors after adding one")
            .into_iter()
            .find(|entry| {
                entry.interface_index == interface.index && entry.address == neighbor.address
            })
            .expect("added static neighbor was not observed");
        assert_eq!(observed.state, NeighborState::Permanent);
        assert_eq!(observed.mac, Some(neighbor.mac));

        let remove_plan = MutationPlan::from_operations([Mutation::RemoveStaticNeighbor(neighbor)]);
        let mut options = ExecutionOptions::default();
        let remove_report = lattice.execute_plan(&remove_plan, &mut options);
        assert!(
            remove_report.is_success(),
            "static neighbor remove report: {remove_report:?}"
        );
        restore.neighbor = None;
    }

    /// Exercises reverse-order compensation for a static-neighbor plan
    /// against the native backend, verified through a real native
    /// read-after-compensation check.
    ///
    /// Unlike routes, `validate_plan` checks interface existence for
    /// `AddStaticNeighbor`/`RemoveStaticNeighbor` up front, for the whole
    /// plan, before any operation executes (`AddRoute`'s validation has no
    /// such check, which is what lets
    /// `native_facade_compensates_after_second_route_operation_fails` force
    /// a second-operation *execution* failure via a bogus interface id). A
    /// bogus interface anywhere in a static-neighbor plan is therefore
    /// rejected atomically before anything is submitted natively — confirmed
    /// by an earlier version of this test, which used that same bogus-
    /// interface trick and got `rollback: NotNeeded` (nothing ever applied)
    /// instead of the intended per-operation compensation. This version
    /// triggers compensation the same way the deterministic
    /// `facade_executes_and_compensates_a_static_neighbor_plan` test does:
    /// cancelling the second operation, which still exercises the real
    /// native `remove_static_neighbor` compensation call for the first.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with the platform privileged test job"]
    fn native_facade_compensates_after_cancelled_static_neighbor_operation() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        assert!(
            lattice.supports(Capability::NEIGHBOR_MUTATION),
            "native backend does not advertise NEIGHBOR_MUTATION"
        );
        let (interface, target) = native_neighbor_test_target(&lattice, 2);
        let neighbor = StaticNeighbor::new(
            interface.id,
            target,
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xfb]),
        );

        // Recover from an interrupted prior run before attempting the add.
        let _ = lattice.remove_static_neighbor(neighbor);

        let plan = MutationPlan::from_operations([
            Mutation::AddStaticNeighbor(neighbor),
            Mutation::RemoveStaticNeighbor(neighbor),
        ]);
        lattice
            .validate_plan(&plan)
            .expect("add-then-remove of the same target is a valid plan");

        let mut cancellation = |index, _: &Mutation| index == 1;
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut compensate = |_, operation: &Mutation, _: Option<&MutationSnapshot>| match operation
        {
            Mutation::AddStaticNeighbor(neighbor) => lattice.remove_static_neighbor(*neighbor),
            _ => Ok(()),
        };
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancellation)
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(
            matches!(report.outcome(0), Some(MutationOutcome::Applied)),
            "static neighbor compensation report: {report:?}"
        );
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));

        let absent = !lattice
            .neighbors()
            .expect("failed to read neighbors after compensation")
            .into_iter()
            .any(|entry| entry.interface_index == interface.index && entry.address == target);
        assert!(
            absent,
            "compensation reported success but the static neighbor is still present"
        );
    }

    /// Exercises interface configuration through the complete public facade:
    /// capability checks, direct admin-only/MTU-only/combined read-after-write
    /// submissions, transaction-plan dispatch with a public snapshot callback,
    /// and restoration. It re-submits only observed values, so it does not
    /// deliberately alter shared-runner networking state.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with the platform privileged test job"]
    fn native_facade_interface_configuration_round_trip() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        assert!(
            lattice.supports(Capability::INTERFACE_MTU),
            "native backend does not advertise interface MTU configuration"
        );
        assert!(
            lattice.supports(Capability::INTERFACE_ADMIN_STATE),
            "native backend does not advertise interface administrative-state configuration"
        );
        let interfaces = lattice
            .interfaces()
            .expect("failed to list interfaces through the public facade");

        #[cfg(target_os = "windows")]
        let addresses = lattice
            .addresses()
            .expect("failed to list interface addresses through the public facade");

        #[cfg(target_os = "windows")]
        let original = interfaces
            .iter()
            .find(|interface| {
                !matches!(interface.kind, InterfaceKind::Loopback)
                    && matches!(interface.mtu, Some(mtu) if mtu != 0)
                    && matches!(interface.admin_state, AdminState::Up | AdminState::Down)
                    && addresses
                        .iter()
                        .any(|address| address.interface_index == interface.index)
            })
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "no non-loopback MTU-bearing interface with a public address was available: \
                     interfaces={interfaces:?}, addresses={addresses:?}"
                )
            });

        #[cfg(not(target_os = "windows"))]
        let original = interfaces
            .iter()
            .find(|interface| {
                !matches!(interface.kind, InterfaceKind::Loopback)
                    && matches!(interface.mtu, Some(mtu) if mtu != 0)
                    && matches!(interface.admin_state, AdminState::Up | AdminState::Down)
            })
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "no non-loopback interface with an MTU and known administrative state was available: \
                     interfaces={interfaces:?}"
                )
            });

        let desired_admin_state = match original.admin_state {
            AdminState::Up => DesiredAdminState::Up,
            AdminState::Down => DesiredAdminState::Down,
            _ => unreachable!("candidate filtering requires a known administrative state"),
        };
        let admin_only = InterfaceConfig::new(original.id, Some(desired_admin_state), None)
            .expect("an observed administrative state forms a valid patch");
        let mtu_only = InterfaceConfig::new(original.id, None, original.mtu)
            .expect("an observed nonzero MTU forms a valid patch");
        let combined = InterfaceConfig::new(original.id, Some(desired_admin_state), original.mtu)
            .expect("observed interface settings form a valid patch");

        let assert_observed = |observed: &Interface, context: &str| {
            assert_eq!(observed.id, original.id, "{context} changed the target");
            assert_eq!(
                observed.admin_state, original.admin_state,
                "{context} changed the administrative state"
            );
            assert_eq!(observed.mtu, original.mtu, "{context} changed the MTU");
        };

        {
            let _restore = InterfaceConfigRestore {
                lattice: &lattice,
                config: combined.clone(),
            };
            let admin_observed = lattice
                .set_interface_config(admin_only)
                .expect("direct admin-only facade configuration failed");
            assert_observed(&admin_observed, "admin-only facade configuration");

            let mtu_observed = lattice
                .set_interface_config(mtu_only)
                .expect("direct MTU-only facade configuration failed");
            assert_observed(&mtu_observed, "MTU-only facade configuration");

            let combined_observed = lattice
                .set_interface_config(combined.clone())
                .expect("direct combined facade configuration failed");
            assert_observed(&combined_observed, "combined facade configuration");

            let plan = MutationPlan::from_operations([Mutation::SetInterfaceConfig(combined)]);
            let mut captured_snapshot = false;
            let mut snapshot = |_, operation: &Mutation| {
                let result = lattice.snapshot_for_mutation(operation);
                captured_snapshot = matches!(
                    &result,
                    Ok(MutationSnapshot::Interface(Some(interface)))
                        if interface.id == original.id
                );
                result
            };
            let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
            let report = lattice.execute_plan(&plan, &mut options);

            assert!(report.is_success(), "interface plan report: {report:?}");
            assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
            assert!(
                captured_snapshot,
                "public snapshot callback missed the target"
            );

            let observed = lattice
                .interfaces()
                .expect("failed to read interface after plan execution")
                .into_iter()
                .find(|interface| interface.id == original.id)
                .expect("configured interface disappeared during plan execution");
            assert_observed(&observed, "plan execution");
        }

        let restored = lattice
            .interfaces()
            .expect("failed to read interface after restoration")
            .into_iter()
            .find(|interface| interface.id == original.id)
            .expect("configured interface disappeared during restoration");
        assert_observed(&restored, "restoration");
    }

    /// Exercises the complete facade transaction path against the native
    /// backend. This is intentionally ignored because route mutation requires
    /// root/CAP_NET_ADMIN/Administrator and changes the host routing table.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with the platform privileged test job"]
    fn native_facade_route_transaction_round_trip() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let destination = Network::from(Ipv4Network::new(
            Ipv4Address::new(203, 0, 113, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface.index);

        let add_plan = MutationPlan::from_operations([Mutation::AddRoute(route)]);
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let add_report = lattice.execute_plan(&add_plan, &mut options);
        assert!(add_report.is_success(), "route add report: {add_report:?}");
        let mut restore = RouteRestore {
            lattice: &lattice,
            route: Some(route),
        };

        let observed_route = lattice
            .routes()
            .expect("failed to read route after adding it")
            .into_iter()
            .find(|candidate| {
                candidate.destination == route.destination
                    && candidate.interface_index == route.interface_index
            })
            .expect("added route was not observed");
        let remove_plan = MutationPlan::from_operations([Mutation::RemoveRoute(to_route_config(
            &observed_route,
        ))]);
        let mut options = ExecutionOptions::default();
        let remove_report = lattice.execute_plan(&remove_plan, &mut options);
        assert!(
            remove_report.is_success(),
            "route remove report: {remove_report:?}"
        );
        restore.route = None;
    }

    /// Exercises the complete facade transaction path against the native
    /// backend for an IPv6 route. Mirrors
    /// `native_facade_route_transaction_round_trip` but uses the IPv6
    /// documentation prefix (RFC 3849, `2001:db8::/32`) instead of the IPv4
    /// documentation prefix. Intentionally ignored because route mutation
    /// requires root/CAP_NET_ADMIN/Administrator and changes the host
    /// routing table.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_ipv6_route_transaction_round_trip -- --ignored`"]
    fn native_facade_ipv6_route_transaction_round_trip() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let destination = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(32).expect("valid IPv6 prefix"),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface.index);

        let add_plan = MutationPlan::from_operations([Mutation::AddRoute(route)]);
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let add_report = lattice.execute_plan(&add_plan, &mut options);
        assert!(
            add_report.is_success(),
            "ipv6 route add report: {add_report:?}"
        );
        let mut restore = RouteRestore {
            lattice: &lattice,
            route: Some(route),
        };

        let observed_route = lattice
            .routes()
            .expect("failed to read route after adding it")
            .into_iter()
            .find(|candidate| {
                candidate.destination == route.destination
                    && candidate.interface_index == route.interface_index
            })
            .expect("added ipv6 route was not observed");
        let remove_plan = MutationPlan::from_operations([Mutation::RemoveRoute(to_route_config(
            &observed_route,
        ))]);
        let mut options = ExecutionOptions::default();
        let remove_report = lattice.execute_plan(&remove_plan, &mut options);
        assert!(
            remove_report.is_success(),
            "ipv6 route remove report: {remove_report:?}"
        );
        restore.route = None;
    }

    /// Exercises the complete facade transaction path against the native
    /// backend for an IPv6 interface address: add via `execute_plan`, read
    /// back the observed record through the public facade, then remove via
    /// `execute_plan` and confirm absence. Mirrors the backend-level
    /// `add_then_remove_ipv6_address_round_trips_through_the_kernel` test's
    /// shape and the facade-level `RouteRestore`/`execute_plan`/
    /// `snapshot_for_mutation` idiom used by
    /// `native_facade_ipv6_route_transaction_round_trip`. Uses the IPv6
    /// documentation prefix (RFC 3849, `2001:db8::/32`) scoped to the
    /// loopback interface, distinct from the route test's destination.
    /// Intentionally ignored because address mutation requires
    /// root/CAP_NET_ADMIN/Administrator and changes the host address table.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_ipv6_address_transaction_round_trip -- --ignored`"]
    fn native_facade_ipv6_address_transaction_round_trip() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let network = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 3, 0, 0, 0, 0, 9]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));

        // A prior interrupted ignored-test run must not turn this run into a
        // false duplicate; best-effort remove any matching leftover before
        // asserting, matching the backend-level test's cleanup idiom.
        if let Some(existing) = lattice
            .addresses()
            .expect("failed to list addresses before add")
            .into_iter()
            .find(|address| {
                address.interface_index == interface.index && address.address == network
            })
        {
            let _ = lattice.remove_address(existing);
        }

        let requested = NewInterfaceAddress::new(interface.id, network);
        let add_plan = MutationPlan::from_operations([Mutation::AddAddress(requested)]);
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let add_report = lattice.execute_plan(&add_plan, &mut options);
        assert!(
            add_report.is_success(),
            "ipv6 address add report: {add_report:?}"
        );

        let observed_address = lattice
            .addresses()
            .expect("failed to read addresses after adding one")
            .into_iter()
            .find(|address| {
                address.interface_index == interface.index && address.address == network
            })
            .expect("added ipv6 address was not observed");
        let mut restore = AddressRestore {
            lattice: &lattice,
            address: Some(observed_address.clone()),
        };

        let remove_plan =
            MutationPlan::from_operations([Mutation::RemoveAddress(observed_address.clone())]);
        let mut options = ExecutionOptions::default();
        let remove_report = lattice.execute_plan(&remove_plan, &mut options);
        assert!(
            remove_report.is_success(),
            "ipv6 address remove report: {remove_report:?}"
        );
        restore.address = None;

        let absent = !lattice
            .addresses()
            .expect("failed to read addresses after removal")
            .into_iter()
            .any(|address| address.id == observed_address.id);
        assert!(
            absent,
            "removed ipv6 address was still present in addresses() afterward"
        );
    }

    /// Exercises native first-failure stopping and reverse-order compensation
    /// without leaving the test route behind.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with the platform privileged test job"]
    fn native_facade_compensates_after_second_route_operation_fails() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let destination = Network::from(Ipv4Network::new(
            Ipv4Address::new(198, 51, 100, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface.index);
        let failed_route = RouteConfig::new(Network::from(Ipv4Network::new(
            Ipv4Address::new(198, 51, 101, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        )))
        .with_interface_index(u32::MAX);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(route),
            Mutation::AddRoute(failed_route),
        ]);

        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut compensate = |_, operation: &Mutation, _: Option<&MutationSnapshot>| match operation
        {
            Mutation::AddRoute(route) => lattice.remove_route(*route),
            _ => Ok(()),
        };
        let mut options = ExecutionOptions::default()
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::Failed { .. })
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));
    }

    /// IPv6 counterpart to `native_facade_compensates_after_second_route_operation_fails`.
    /// Mirrors it exactly except for using the IPv6 documentation prefix
    /// (RFC 3849, `2001:db8::/32`) with a subnet suffix distinct from the
    /// other IPv6 route/address facade tests, so a previous interrupted run
    /// of any of those tests can never collide with this one.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_compensates_after_second_ipv6_route_operation_fails -- --ignored`"]
    fn native_facade_compensates_after_second_ipv6_route_operation_fails() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let destination = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 4, 0, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface.index);
        let failed_route = RouteConfig::new(Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 5, 0, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        )))
        .with_interface_index(u32::MAX);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(route),
            Mutation::AddRoute(failed_route),
        ]);

        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut compensate = |_, operation: &Mutation, _: Option<&MutationSnapshot>| match operation
        {
            Mutation::AddRoute(route) => lattice.remove_route(*route),
            _ => Ok(()),
        };
        let mut options = ExecutionOptions::default()
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::Failed { .. })
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));

        let survives = lattice
            .routes()
            .expect("failed to read routes after compensation")
            .into_iter()
            .any(|candidate| {
                candidate.destination == route.destination
                    && candidate.interface_index == route.interface_index
            });
        assert!(
            !survives,
            "compensated ipv6 route was still observed after rollback"
        );
    }

    /// Address counterpart to
    /// `native_facade_compensates_after_second_ipv6_route_operation_fails`:
    /// two-operation plan whose second `AddAddress` operation targets a
    /// nonexistent interface id, forcing first-failure-stops plus explicit
    /// reverse-order compensation of the first `AddAddress`. Uses the IPv6
    /// documentation prefix with a subnet suffix distinct from every other
    /// IPv6 address facade test.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_compensates_after_second_ipv6_address_operation_fails -- --ignored`"]
    fn native_facade_compensates_after_second_ipv6_address_operation_fails() {
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let network = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 6, 0, 0, 0, 0, 9]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));

        // A prior interrupted ignored-test run must not turn this run into a
        // false duplicate; best-effort remove any matching leftover before
        // asserting, matching the round-trip test's cleanup idiom.
        if let Some(existing) = lattice
            .addresses()
            .expect("failed to list addresses before add")
            .into_iter()
            .find(|address| {
                address.interface_index == interface.index && address.address == network
            })
        {
            let _ = lattice.remove_address(existing);
        }

        let requested = NewInterfaceAddress::new(interface.id, network);
        // `validate_plan` does not inspect `broadcast`, so a bad interface
        // id (the technique the IPv4/route counterpart test uses) would be
        // rejected during whole-plan validation before either operation
        // executes, unlike `AddRoute`'s lazily-checked `interface_index`.
        // An IPv6 address with an explicit (IPv4-typed) broadcast is instead
        // rejected by every backend's `add_address` at execution time
        // (`Error::InvalidState`), giving the same
        // passes-validation-fails-at-execution shape the compensation path
        // under test requires.
        let failed_request = NewInterfaceAddress::new(
            interface.id,
            Network::from(Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 7, 0, 0, 0, 0, 9]),
                Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
            )),
        )
        .with_broadcast(Ipv4Address::new(255, 255, 255, 255));
        let plan = MutationPlan::from_operations([
            Mutation::AddAddress(requested.clone()),
            Mutation::AddAddress(failed_request),
        ]);

        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut compensate =
            |_, operation: &Mutation, snapshot: Option<&MutationSnapshot>| match operation {
                Mutation::AddAddress(_) => {
                    if let Some(MutationSnapshot::InterfaceAddress(None)) = snapshot
                        && let Some(observed) = lattice
                            .addresses()
                            .expect("failed to list addresses during compensation")
                            .into_iter()
                            .find(|address| {
                                address.interface_index == interface.index
                                    && address.address == network
                            })
                    {
                        return lattice.remove_address(observed);
                    }
                    Ok(())
                }
                _ => Ok(()),
            };
        let mut options = ExecutionOptions::default()
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::Failed { .. })
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));

        let survives = lattice
            .addresses()
            .expect("failed to read addresses after compensation")
            .into_iter()
            .any(|address| {
                address.interface_index == interface.index && address.address == network
            });
        assert!(
            !survives,
            "compensated ipv6 address was still observed after rollback"
        );
    }

    /// New pattern: no facade-level filtered-event/async-watcher test exists
    /// for any IP family before this test. Mirrors the backend-level
    /// `watch_observes_route_changes`/`watch_observes_ipv6_route_changes`
    /// shape through the public facade instead: `lattice.watch()` for the
    /// unfiltered add notification, `lattice.watch_filtered(EventFilter::
    /// none().route(id))` for the selected removal notification, and, with
    /// the `async` feature, `lattice.watch_async` polled the same way the
    /// backend crate's `tokio_route_event` helper polls its
    /// `TokioEventReceiver`. Obtains the watched id from the notification
    /// itself rather than assuming it, matching the backend-level test's
    /// approach. Uses `2001:db8:9::/64`, distinct from every other IPv6
    /// subnet already reserved by the other ignored facade tests in this
    /// module (plain `2001:db8::/32`, `2001:db8:3::9/64`, `2001:db8:4::/64`,
    /// `2001:db8:5::/64`, `2001:db8:6::9/64`, `2001:db8:7::9/64`).
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_ipv6_route_event_and_watcher -- --ignored`"]
    fn native_facade_ipv6_route_event_and_watcher() {
        use std::time::Duration;
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        assert!(lattice.supports(Capability::ROUTE_MONITORING));
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let destination = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 9, 0, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let route = RouteConfig::new(destination).with_interface_index(interface.index);

        // `Lattice::watch()` is deliberately all-domain and requires the
        // aggregate `Capability::MONITORING` (including neighbor
        // monitoring, which Windows never advertises); this test only
        // needs route events, so use the routes-only filter, matching the
        // async watcher subscription just below and the
        // `Capability::ROUTE_MONITORING` assertion above.
        let watcher = lattice
            .watch_filtered(EventFilter::none().routes())
            .expect("failed to subscribe to events");
        #[cfg(feature = "async")]
        let mut async_watcher = lattice
            .watch_async(EventFilter::none().routes())
            .expect("failed to subscribe to async events");

        // Recover from an interrupted prior run before attempting the add.
        let _ = lattice.remove_route(route);
        let add_plan = MutationPlan::from_operations([Mutation::AddRoute(route)]);
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let add_report = lattice.execute_plan(&add_plan, &mut options);
        assert!(
            add_report.is_success(),
            "ipv6 route add report: {add_report:?}"
        );
        let mut restore = RouteRestore {
            lattice: &lattice,
            route: Some(route),
        };

        // Obtain the identity from the notification itself, matching the
        // backend-level test's approach.
        let watched_id = (0..12)
            .find_map(|_| match watcher.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(Event::Route { id, .. })) => Some(id),
                _ => None,
            })
            .expect("watch() did not report the ipv6 route addition");
        #[cfg(feature = "async")]
        let async_observed = facade_async_route_event(&mut async_watcher, watched_id);

        let selected_watcher = lattice
            .watch_filtered(EventFilter::none().route(watched_id))
            .expect("failed to subscribe to selected route events");
        #[cfg(feature = "async")]
        let mut selected_async_watcher = lattice
            .watch_async(EventFilter::none().route(watched_id))
            .expect("failed to subscribe to selected async route events");

        // Re-read the observed route rather than reusing the locally
        // constructed `route`: `validate_plan`'s `same_route` match compares
        // `metric`, and the kernel may assign a nonzero default metric to an
        // IPv6 route that the locally constructed value (metric `None`)
        // does not carry, which would otherwise make removal fail validation
        // with `NotFound`.
        let observed_route = lattice
            .routes()
            .expect("failed to read routes before removal")
            .into_iter()
            .find(|candidate| {
                candidate.destination == route.destination
                    && candidate.interface_index == route.interface_index
            })
            .expect("added ipv6 route was not observed before removal");
        let remove_plan = MutationPlan::from_operations([Mutation::RemoveRoute(to_route_config(
            &observed_route,
        ))]);
        let mut remove_options = ExecutionOptions::default();
        let remove_report = lattice.execute_plan(&remove_plan, &mut remove_options);
        assert!(
            remove_report.is_success(),
            "ipv6 route remove report: {remove_report:?}"
        );
        restore.route = None;

        // Widened from the usual 3s (12 * 250ms) polling window used
        // elsewhere in this module: Windows IP Helper route-change
        // notification delivery has been observed to lag noticeably behind
        // 3s under CI load, unlike Linux Netlink/macOS PF_ROUTE.
        //
        // Diagnostic: record every poll outcome, matching the address
        // event test's equivalent logging, so a future failure here shows
        // real evidence instead of only "it didn't match".
        let mut observed_log = Vec::new();
        let selected_observed = (0..40).any(|_| {
            let outcome = selected_watcher.recv_timeout(Duration::from_millis(250));
            observed_log.push(format!("{outcome:?}"));
            matches!(
                outcome,
                Ok(Some(Event::Route { id, kind: ChangeKind::Removed })) if id == watched_id
            )
        });
        #[cfg(feature = "async")]
        let selected_async_observed =
            facade_async_route_event(&mut selected_async_watcher, watched_id);

        assert!(
            selected_observed,
            "object route filter did not report ipv6 removal; watched_id={watched_id:?}, \
             poll outcomes={observed_log:?}"
        );
        #[cfg(feature = "async")]
        assert!(
            async_observed,
            "watch_async() did not report the ipv6 route mutation"
        );
        #[cfg(feature = "async")]
        assert!(
            selected_async_observed,
            "async object route filter did not report ipv6 removal"
        );
    }

    /// Polls an [`EventStream`] for up to 10 seconds looking for a
    /// `Event::Route` notification matching `id`, mirroring the backend
    /// crate's `tokio_route_event` helper but for the facade's
    /// runtime-agnostic `EventStream` instead of a native
    /// `TokioEventReceiver`.
    #[cfg(feature = "async")]
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn facade_async_route_event(watcher: &mut EventStream<Event>, id: RouteId) -> bool {
        use futures::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        use std::time::Duration;

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        // Widened to 10s, matching the corresponding sync polling window
        // above (Windows IP Helper notification delivery has been observed
        // to lag noticeably behind 3s under CI load).
        for _ in 0..40 {
            match Pin::new(&mut *watcher).poll_next(&mut context) {
                Poll::Ready(Some(Ok(Event::Route { id: event_id, .. }))) if event_id == id => {
                    return true;
                }
                Poll::Ready(Some(_)) | Poll::Pending => {
                    std::thread::sleep(Duration::from_millis(250))
                }
                Poll::Ready(None) => return false,
            }
        }
        false
    }

    /// Address-domain counterpart of `native_facade_ipv6_route_event_and_
    /// watcher`: same three-phase shape (unfiltered `watch()` to learn the
    /// id from the notification, `watch_filtered(EventFilter::none()
    /// .address(id))` for the selected removal, and, with the `async`
    /// feature, `watch_async` polled via `facade_async_address_event`), but
    /// built through `execute_plan`/`MutationPlan`/`AddressRestore` for
    /// `Mutation::AddAddress`/`Mutation::RemoveAddress`, matching
    /// `native_facade_ipv6_address_transaction_round_trip`'s idiom. Asserts
    /// `Capability::ADDRESS_MONITORING` rather than the full `MONITORING`
    /// aggregate, matching the just-fixed route event test's rationale:
    /// Windows never advertises `NEIGHBOR_MONITORING`, so the aggregate
    /// would never pass there even though this test only needs address
    /// events. Uses `2001:db8:a::9/64` (RFC 3849), distinct from every
    /// other IPv6 subnet already reserved by the other ignored facade tests
    /// in this module (plain `2001:db8::/32`, `2001:db8:3::9/64`,
    /// `2001:db8:4::/64`, `2001:db8:5::/64`, `2001:db8:6::9/64`,
    /// `2001:db8:7::9/64`, `2001:db8:9::/64`).
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    #[ignore = "requires native networking privilege; run with \
                `cargo test -p net-lattice native_facade_ipv6_address_event_and_watcher -- --ignored`"]
    fn native_facade_ipv6_address_event_and_watcher() {
        use std::time::Duration;
        let _guard = native_facade_privileged_guard();

        let lattice = Lattice::connect().expect("failed to connect native backend");
        assert!(lattice.supports(Capability::ADDRESS_MONITORING));
        let interface = lattice
            .interfaces()
            .expect("failed to list interfaces")
            .into_iter()
            .find(|interface| matches!(interface.kind, InterfaceKind::Loopback))
            .or_else(|| {
                lattice
                    .interfaces()
                    .ok()
                    .and_then(|mut interfaces| interfaces.pop())
            })
            .expect("native backend reported no interfaces");
        let network = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0xa, 0, 0, 0, 0, 9]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));

        // Recover from an interrupted prior run before attempting the add.
        if let Some(existing) = lattice
            .addresses()
            .expect("failed to list addresses before add")
            .into_iter()
            .find(|address| {
                address.interface_index == interface.index && address.address == network
            })
        {
            let _ = lattice.remove_address(existing);
        }

        let watcher = lattice
            .watch_filtered(EventFilter::none().addresses())
            .expect("failed to subscribe to events");
        #[cfg(feature = "async")]
        let mut async_watcher = lattice
            .watch_async(EventFilter::none().addresses())
            .expect("failed to subscribe to async events");

        let requested = NewInterfaceAddress::new(interface.id, network);
        let add_plan = MutationPlan::from_operations([Mutation::AddAddress(requested)]);
        let mut snapshot = |_, operation: &Mutation| lattice.snapshot_for_mutation(operation);
        let mut options = ExecutionOptions::default().snapshot(&mut snapshot);
        let add_report = lattice.execute_plan(&add_plan, &mut options);
        assert!(
            add_report.is_success(),
            "ipv6 address add report: {add_report:?}"
        );
        let mut restore = AddressRestore {
            lattice: &lattice,
            address: None,
        };

        // Obtain the identity from the notification itself, matching the
        // backend-level and route-event facade tests' approach.
        let watched_id = (0..12)
            .find_map(|_| match watcher.recv_timeout(Duration::from_millis(250)) {
                Ok(Some(Event::Address { id, .. })) => Some(id),
                _ => None,
            })
            .expect("watch() did not report the ipv6 address addition");
        #[cfg(feature = "async")]
        let async_observed = facade_async_address_event(&mut async_watcher, watched_id);

        // Re-read the observed address before setting up compensation and
        // building the remove plan: `remove_address` and `RemoveAddress`
        // validation match by id (or interface_index + address), and the
        // locally constructed `requested` value carries no id at all.
        //
        // Retry rather than reading once: a newly added IPv6 address
        // remains Tentative while the OS runs Duplicate Address Detection
        // and may briefly be absent from a fresh table read even though the
        // add notification (and `add_report.is_success()` above) already
        // fired, most visibly on Windows.
        let observed_address = (0..12)
            .find_map(|_| {
                let found = lattice
                    .addresses()
                    .expect("failed to read addresses before removal")
                    .into_iter()
                    .find(|address| address.id == watched_id);
                if found.is_none() {
                    std::thread::sleep(Duration::from_millis(250));
                }
                found
            })
            .expect("added ipv6 address was not observed before removal");
        restore.address = Some(observed_address.clone());

        let selected_watcher = lattice
            .watch_filtered(EventFilter::none().address(watched_id))
            .expect("failed to subscribe to selected address events");
        #[cfg(feature = "async")]
        let mut selected_async_watcher = lattice
            .watch_async(EventFilter::none().address(watched_id))
            .expect("failed to subscribe to selected async address events");

        let remove_plan =
            MutationPlan::from_operations([Mutation::RemoveAddress(observed_address)]);
        let mut remove_options = ExecutionOptions::default();
        let remove_report = lattice.execute_plan(&remove_plan, &mut remove_options);
        assert!(
            remove_report.is_success(),
            "ipv6 address remove report: {remove_report:?}"
        );
        restore.address = None;

        // Widened from the usual 3s (12 * 250ms) polling window; see the
        // matching comment on the route event test's `selected_observed`.
        //
        // Diagnostic: record every poll outcome (event, timeout, or error),
        // not just whether a match was found, so a failure here shows what
        // (if anything) the selected watcher actually observed instead of
        // only "it didn't match" — this is the second remaining flaky
        // symptom after fixing cross-test concurrency and Windows
        // registration-readiness, and needs real evidence rather than
        // another blind guess.
        let mut observed_log = Vec::new();
        let selected_observed = (0..40).any(|_| {
            let outcome = selected_watcher.recv_timeout(Duration::from_millis(250));
            observed_log.push(format!("{outcome:?}"));
            matches!(
                outcome,
                Ok(Some(Event::Address { id, kind: ChangeKind::Removed })) if id == watched_id
            )
        });
        #[cfg(feature = "async")]
        let selected_async_observed =
            facade_async_address_event(&mut selected_async_watcher, watched_id);

        assert!(
            selected_observed,
            "object address filter did not report ipv6 removal; watched_id={watched_id:?}, \
             poll outcomes={observed_log:?}"
        );
        #[cfg(feature = "async")]
        assert!(
            async_observed,
            "watch_async() did not report the ipv6 address mutation"
        );
        #[cfg(feature = "async")]
        assert!(
            selected_async_observed,
            "async object address filter did not report ipv6 removal"
        );
    }

    /// Polls an [`EventStream`] for up to 10 seconds looking for an
    /// `Event::Address` notification matching `id`, mirroring
    /// `facade_async_route_event` but for the address domain.
    #[cfg(feature = "async")]
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn facade_async_address_event(
        watcher: &mut EventStream<Event>,
        id: InterfaceAddressId,
    ) -> bool {
        use futures::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};
        use std::time::Duration;

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        // Widened to 10s, matching the corresponding sync polling window
        // above (Windows IP Helper notification delivery has been observed
        // to lag noticeably behind 3s under CI load).
        for _ in 0..40 {
            match Pin::new(&mut *watcher).poll_next(&mut context) {
                Poll::Ready(Some(Ok(Event::Address { id: event_id, .. }))) if event_id == id => {
                    return true;
                }
                Poll::Ready(Some(_)) | Poll::Pending => {
                    std::thread::sleep(Duration::from_millis(250))
                }
                Poll::Ready(None) => return false,
            }
        }
        false
    }

    #[test]
    fn facade_runs_supplied_compensation_in_reverse_order() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(planned_route()),
            Mutation::RemoveRoute(planned_route()),
        ]);
        let mut compensated = Vec::new();

        let mut cancelled = |index, _: &Mutation| index == 1;
        let mut compensate = |index, _: &Mutation, _: Option<&MutationSnapshot>| {
            compensated.push(index);
            Ok(())
        };
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancelled)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(compensated, vec![0]);
        assert!(matches!(report.rollback(), RollbackStatus::Completed));
        assert_eq!(
            report.operation_report(0).expect("operation report").phase,
            MutationExecutionPhase::Compensation
        );
    }

    #[test]
    fn facade_executes_and_compensates_an_ipv6_route_plan() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        let route = ipv6_route();
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(route),
            Mutation::RemoveRoute(route),
        ]);
        lattice
            .validate_plan(&plan)
            .expect("IPv6 route plan is valid before execution");

        let mut snapshots = Vec::new();
        let mut compensated = Vec::new();
        let mut cancellation = |index, _: &Mutation| index == 1;
        let mut snapshot = |index, operation: &Mutation| {
            snapshots.push((index, operation.clone()));
            lattice.snapshot_for_mutation(operation)
        };
        let mut compensate = |index, operation: &Mutation, prior: Option<&MutationSnapshot>| {
            compensated.push((index, operation.clone(), prior.cloned()));
            Ok(())
        };
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancellation)
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));
        assert_eq!(snapshots, vec![(0, Mutation::AddRoute(route))]);
        assert_eq!(
            compensated,
            vec![(
                0,
                Mutation::AddRoute(route),
                Some(MutationSnapshot::Route(None))
            )]
        );
    }

    #[test]
    fn facade_executes_and_compensates_an_ipv6_address_plan() {
        let lattice = lattice(Capability::empty());
        let address = ipv6_address();
        let observed = InterfaceAddress::new(InterfaceAddressId::new(16), 1, address.address);
        let plan = MutationPlan::from_operations([
            Mutation::AddAddress(address.clone()),
            Mutation::RemoveAddress(observed),
        ]);
        lattice
            .validate_plan(&plan)
            .expect("IPv6 address plan is valid before execution");

        let mut snapshots = Vec::new();
        let mut compensated = Vec::new();
        let mut cancellation = |index, _: &Mutation| index == 1;
        let mut snapshot = |index, operation: &Mutation| {
            snapshots.push((index, operation.clone()));
            lattice.snapshot_for_mutation(operation)
        };
        let mut compensate = |index, operation: &Mutation, prior: Option<&MutationSnapshot>| {
            compensated.push((index, operation.clone(), prior.cloned()));
            Ok(())
        };
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancellation)
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(report.outcome(0), Some(MutationOutcome::Applied)));
        assert!(matches!(
            report.outcome(1),
            Some(MutationOutcome::NotAttempted)
        ));
        assert!(matches!(report.rollback(), RollbackStatus::Completed));
        assert_eq!(snapshots, vec![(0, Mutation::AddAddress(address.clone()))]);
        assert_eq!(
            compensated,
            vec![(
                0,
                Mutation::AddAddress(address),
                Some(MutationSnapshot::InterfaceAddress(None))
            )]
        );
    }

    #[test]
    fn facade_captures_prior_state_before_each_applied_operation() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(planned_route()),
            Mutation::RemoveRoute(planned_route()),
        ]);
        let mut captured = Vec::new();
        let mut restored = Vec::new();

        let mut cancelled = |index, _: &Mutation| index == 1;
        let mut snapshot = |index, _: &Mutation| {
            captured.push(index);
            Ok(MutationSnapshot::Dns(DnsConfig::default()))
        };
        let mut compensate = |index, _: &Mutation, state: Option<&MutationSnapshot>| {
            restored.push((index, state.is_some()));
            Ok(())
        };
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancelled)
            .snapshot(&mut snapshot)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert_eq!(captured, vec![0]);
        assert_eq!(restored, vec![(0, true)]);
        assert!(matches!(report.rollback(), RollbackStatus::Completed));
        assert_eq!(
            report.operation_report(0).expect("operation report").phase,
            MutationExecutionPhase::Compensation
        );
    }

    #[test]
    fn facade_reports_compensation_failure() {
        let lattice = lattice(Capability::ROUTE_MUTATION);
        let plan = MutationPlan::from_operations([
            Mutation::AddRoute(planned_route()),
            Mutation::RemoveRoute(planned_route()),
        ]);

        let mut cancelled = |index, _: &Mutation| index == 1;
        let mut compensate =
            |_, _: &Mutation, _: Option<&MutationSnapshot>| Err(Error::InvalidState);
        let mut options = ExecutionOptions::default()
            .cancellation(&mut cancelled)
            .compensation(&mut compensate);
        let report = lattice.execute_plan(&plan, &mut options);

        assert!(matches!(
            report.rollback(),
            RollbackStatus::Failed {
                operation_index: 0,
                error: Error::InvalidState,
            }
        ));
        assert!(matches!(
            report.operation_reports()[0].stop_reason,
            Some(MutationStopReason::CompensationFailed)
        ));
    }

    #[test]
    fn facade_enforces_monitoring_capability_and_forwards_filters() {
        let unsupported = lattice(Capability::empty());
        assert!(unsupported.watch().is_err());
        assert!(unsupported.watch_filtered(EventFilter::ALL).is_err());

        let lattice = lattice(Capability::MONITORING);
        assert!(lattice.supports(Capability::MONITORING));
        assert!(!lattice.supports(Capability::DNS_MUTATION));
        assert!(lattice.capabilities().contains(Capability::MONITORING));
        assert!(lattice.watch().expect("watch").recv().is_ok());
        assert!(
            lattice
                .watch_filtered(EventFilter::none().route(RouteId::new(1)))
                .expect("filtered watch")
                .recv()
                .is_ok()
        );
        assert!(
            lattice
                .watch_filtered(EventFilter::none())
                .expect("empty filtered watch")
                .try_recv()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn facade_requires_capability_for_each_selected_monitoring_domain() {
        let route_and_address =
            lattice(Capability::ROUTE_MONITORING | Capability::ADDRESS_MONITORING);
        assert!(
            route_and_address
                .watch_filtered(EventFilter::none().routes().addresses())
                .is_ok()
        );
        assert!(matches!(
            route_and_address.watch_filtered(EventFilter::none().neighbors()),
            Err(Error::Unsupported)
        ));
        assert!(matches!(route_and_address.watch(), Err(Error::Unsupported)));
        assert!(matches!(
            route_and_address.watch_filtered(EventFilter::ALL),
            Err(Error::Unsupported)
        ));
        assert!(
            route_and_address
                .watch_filtered(EventFilter::none())
                .is_ok()
        );
    }

    #[test]
    fn watch_with_additions_merges_native_and_addition_sourced_events() {
        use std::time::Duration;

        let neighbor_event = Event::Neighbor {
            id: NeighborId::new(1),
            kind: ChangeKind::Added,
        };
        let (addition_sender, addition_receiver) = EventReceiver::bounded();
        assert!(addition_sender.send(neighbor_event, Event::resync_all()));
        drop(addition_sender);

        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::MONITORING,
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::NEIGHBOR_MONITORING_POLLING,
                addition_receiver: std::sync::Mutex::new(Some(addition_receiver)),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        // Selects both the Route domain (native-sourced) and the Neighbor
        // domain (addition-sourced): since NL-152, an addition-sourced event
        // is only forwarded when it matches the caller's full requested
        // filter, so the filter must select Neighbor for the addition-source
        // assertion below to hold (narrowing-specific behavior is covered
        // separately by `watch_with_additions_narrows_addition_sourced_events_by_object_id`).
        let receiver = lattice
            .watch_with_additions(
                EventFilter::none().route(RouteId::new(1)).neighbors(),
                Addition::NEIGHBOR_MONITORING_POLLING,
            )
            .expect("watch_with_additions");

        let mut seen_route = false;
        let mut seen_neighbor = false;
        for _ in 0..40 {
            if seen_route && seen_neighbor {
                break;
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(Event::Route { .. })) => seen_route = true,
                Ok(Some(event)) if event == neighbor_event => seen_neighbor = true,
                Ok(Some(_)) | Ok(None) => {}
                Err(error) => panic!("unexpected merged receiver error: {error:?}"),
            }
        }
        assert!(seen_route, "native-sourced route event did not arrive");
        assert!(
            seen_neighbor,
            "addition-sourced neighbor event did not arrive"
        );
    }

    #[test]
    fn watch_with_additions_silently_skips_an_addition_the_backend_does_not_report() {
        use std::time::Duration;

        let lattice = lattice(Capability::MONITORING);
        // `TestBackend::additions` defaults to `Addition::empty()`, so the
        // requested bit is not reported by this backend.
        let receiver = lattice
            .watch_with_additions(EventFilter::none(), Addition::NEIGHBOR_MONITORING_POLLING)
            .expect("watch_with_additions must not error for an unreported addition");
        assert!(
            receiver
                .recv_timeout(Duration::from_millis(50))
                .expect("no producer error")
                .is_none(),
            "no addition event should have been synthesized"
        );
    }

    #[test]
    fn watch_with_additions_drop_tears_down_native_and_addition_fan_in() {
        let (_addition_sender, addition_receiver) = EventReceiver::bounded();
        let addition_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let addition_receiver =
            addition_receiver.with_subscription(NativeDropGuard(Arc::clone(&addition_drops)));

        let native_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::MONITORING,
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::NEIGHBOR_MONITORING_POLLING,
                addition_receiver: std::sync::Mutex::new(Some(addition_receiver)),
                native_drops: Arc::clone(&native_drops),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        let receiver = lattice
            .watch_with_additions(EventFilter::none(), Addition::NEIGHBOR_MONITORING_POLLING)
            .expect("watch_with_additions");
        assert_eq!(native_drops.load(Ordering::SeqCst), 0);
        assert_eq!(addition_drops.load(Ordering::SeqCst), 0);

        drop(receiver);

        // `AdditionMergeGuard::drop` joins every fan-in thread before
        // returning, so both counters are already updated here.
        assert_eq!(
            native_drops.load(Ordering::SeqCst),
            1,
            "receiver drop did not tear down the native subscription"
        );
        assert_eq!(
            addition_drops.load(Ordering::SeqCst),
            1,
            "receiver drop did not tear down the addition fan-in subscription"
        );
    }

    #[test]
    fn watch_with_additions_succeeds_when_domain_covered_only_by_addition() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::ROUTE_MONITORING
                    | Capability::INTERFACE_MONITORING
                    | Capability::ADDRESS_MONITORING,
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::NEIGHBOR_MONITORING_POLLING,
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        assert!(
            lattice
                .watch_with_additions(EventFilter::ALL, Addition::all())
                .is_ok(),
            "a domain covered only by a requested and reported Addition must not be rejected"
        );
    }

    #[test]
    fn watch_with_additions_strips_addition_covered_domain_before_native_call() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::ROUTE_MONITORING
                    | Capability::INTERFACE_MONITORING
                    | Capability::ADDRESS_MONITORING,
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::NEIGHBOR_MONITORING_POLLING,
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        lattice
            .watch_with_additions(EventFilter::ALL, Addition::NEIGHBOR_MONITORING_POLLING)
            .expect("watch_with_additions");

        let captured = lattice
            .backend
            .captured_watch_filter
            .lock()
            .expect("captured_watch_filter mutex poisoned")
            .clone()
            .expect("watch_filtered must have been called");
        assert_eq!(
            captured,
            EventFilter::ALL.without_domain(EventDomain::Neighbor)
        );
        assert!(!captured.selects_domain(EventDomain::Neighbor));
        assert!(captured.selects_domain(EventDomain::Route));
        assert!(captured.selects_domain(EventDomain::Interface));
        assert!(captured.selects_domain(EventDomain::Address));
    }

    #[test]
    fn watch_and_watch_filtered_unaffected_by_addition_gate_change() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::empty(),
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::NEIGHBOR_MONITORING_POLLING,
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        assert!(matches!(lattice.watch(), Err(Error::Unsupported)));
        assert!(matches!(
            lattice.watch_filtered(EventFilter::ALL),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn watch_with_additions_narrows_addition_sourced_events_by_object_id() {
        use std::time::Duration;

        let id_a = NeighborId::new(1);
        let id_b = NeighborId::new(2);
        let event_a = Event::Neighbor {
            id: id_a,
            kind: ChangeKind::Added,
        };
        let event_b = Event::Neighbor {
            id: id_b,
            kind: ChangeKind::Added,
        };
        let (addition_sender, addition_receiver) = EventReceiver::bounded();
        assert!(addition_sender.send(event_a, Event::resync_all()));
        assert!(addition_sender.send(event_b, Event::resync_all()));
        drop(addition_sender);

        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::empty(),
                fail_events: false,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::NEIGHBOR_MONITORING_POLLING,
                addition_receiver: std::sync::Mutex::new(Some(addition_receiver)),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };

        let receiver = lattice
            .watch_with_additions(
                EventFilter::none().neighbor(id_a),
                Addition::NEIGHBOR_MONITORING_POLLING,
            )
            .expect("watch_with_additions");

        let mut seen_a = false;
        let mut seen_b = false;
        for _ in 0..10 {
            match receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(event)) if event == event_a => seen_a = true,
                Ok(Some(event)) if event == event_b => seen_b = true,
                Ok(Some(_)) | Ok(None) => {}
                Err(error) => panic!("unexpected merged receiver error: {error:?}"),
            }
        }
        assert!(seen_a, "narrower-matching neighbor event did not arrive");
        assert!(
            !seen_b,
            "neighbor event for an unrequested object id must not arrive"
        );
    }

    #[test]
    fn facade_propagates_backend_watcher_errors() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::MONITORING,
                fail_events: true,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };
        assert!(lattice.watch().is_err());
        assert!(lattice.watch_filtered(EventFilter::ALL).is_err());
    }

    #[cfg(feature = "async")]
    #[test]
    fn async_facade_propagates_native_watcher_errors() {
        let lattice = Lattice {
            backend: TestBackend {
                capabilities: Capability::MONITORING,
                fail_events: true,
                fail_mutations: false,
                fail_dns_read: false,
                additions: Addition::empty(),
                addition_receiver: std::sync::Mutex::new(None),
                native_drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                captured_watch_filter: std::sync::Mutex::new(None),
            },
        };
        assert!(lattice.watch_async(EventFilter::ALL).is_err());
    }

    #[cfg(feature = "async")]
    #[test]
    fn async_facade_enforces_monitoring_capability() {
        let lattice = lattice(Capability::empty());
        assert!(lattice.watch_async(EventFilter::ALL).is_err());
    }

    #[cfg(feature = "async")]
    #[test]
    fn async_facade_requires_capability_for_each_selected_monitoring_domain() {
        let lattice = lattice(Capability::ROUTE_MONITORING);
        assert!(lattice.watch_async(EventFilter::none().routes()).is_ok());
        assert!(matches!(
            lattice.watch_async(EventFilter::none().neighbors()),
            Err(Error::Unsupported)
        ));
        assert!(matches!(
            lattice.watch_async(EventFilter::ALL),
            Err(Error::Unsupported)
        ));
        assert!(lattice.watch_async(EventFilter::none()).is_ok());
    }

    #[cfg(feature = "async")]
    #[test]
    fn async_facade_uses_the_backend_native_watcher_contract() {
        use futures::{FutureExt, StreamExt};

        futures::executor::block_on(async {
            let lattice = lattice(Capability::MONITORING);
            let mut events = lattice
                .watch_async(EventFilter::none().route(RouteId::new(1)))
                .expect("async watch");
            assert!(events.next().await.is_some());
            assert!(events.next().await.is_none());

            let mut events = lattice
                .watch_async(EventFilter::none())
                .expect("empty async watch");
            assert!(events.next().now_or_never().is_none());
        });
    }

    #[test]
    fn connect_uses_the_current_platform_backend() {
        let _ = Lattice::connect();
    }

    #[test]
    fn connect_propagates_backend_construction_error() {
        FORCE_CONNECT_FAILURE.store(true, Ordering::SeqCst);
        assert!(Lattice::connect().is_err());
    }
}
