//! The domain model of operating system networking state.
//!
//! No operating-system dependency. Covers interface (`interface`, `mac`),
//! route (`route`), DNS (`dns`), neighbor (`neighbor`), interface-address
//! (`ifaddr`), and change-event (`event`) observed state; mutation intent
//! and plan/execution/report machinery (`mutation`), including
//! `StaticNeighbor` desired-neighbor intent and its `Mutation` variants; the
//! whole-system `CurrentState` snapshot (`snapshot`); the whole-system,
//! caller-authored `DesiredState` aggregate (`desired_state`); the pure,
//! side-effect-free computed `Diff` between a `CurrentState` and a
//! `DesiredState` (`diff`); and the pure, side-effect-free `ApplyPlan`
//! compiled from a `Diff` (`apply`).

#![warn(missing_docs)]

mod address;
pub mod apply;
pub mod desired_state;
pub mod diff;
/// Observed and desired system resolver (DNS) configuration.
pub mod dns;
/// Change-notification event types and filtering.
pub mod event;
/// Native-firewall rule and policy types (whole-policy replacement, no NAT
/// or connection tracking).
pub mod firewall;
/// Observed interface-address (IP address on interface) state.
pub mod ifaddr;
/// Observed and desired network interface state.
pub mod interface;
/// Hardware (MAC) address types.
pub mod mac;
pub mod mutation;
/// Observed and desired static ARP/NDP neighbor entries.
pub mod neighbor;
/// Observed and desired routing table entries.
pub mod route;
pub mod snapshot;

pub use address::{IpAddress, Network};
pub use apply::{ApplyPlan, ApplyPlanReport, ApplyStep, ApplyStepOutcome, NonConvergentReason};
pub use desired_state::DesiredState;
pub use diff::{
    AddressChange, Change, Diff, DnsChange, FirewallChange, InterfaceDiff, NeighborChange,
    RouteChange,
};
pub use dns::{DnsConfig, NewDnsConfig};
pub use event::{ChangeKind, Event, EventDomain, EventFilter};
pub use firewall::{Direction, FirewallPolicy, FirewallRule, PortRange, Protocol, Verdict};
pub use ifaddr::{InterfaceAddress, InterfaceAddressId, NewInterfaceAddress};
pub use interface::{
    AdminState, DesiredAdminState, Interface, InterfaceConfig, InterfaceId, InterfaceKind,
    OperationalState,
};
pub use mac::MacAddress;
pub use mutation::{
    Mutation, MutationConfirmation, MutationExecutionPhase, MutationIdempotency, MutationKind,
    MutationOperationReport, MutationOutcome, MutationPlan, MutationPlanReport,
    MutationPrecondition, MutationPreflight, MutationPrivilege, MutationReversibility,
    MutationSemantics, MutationSnapshot, MutationStopReason, RollbackStatus,
};
pub use neighbor::{NeighborEntry, NeighborId, NeighborState, StaticNeighbor};
pub use route::Route;
pub use snapshot::CurrentState;
