//! A whole-system, best-effort observed-state snapshot.
//!
//! `CurrentState` is a distinct concept from [`crate::mutation::MutationSnapshot`]:
//! the latter is a narrow, single-domain capture taken immediately before one
//! mutation, while `CurrentState` aggregates every domain this crate models
//! (routes, interfaces, neighbors, interface addresses, DNS configuration,
//! and firewall rules) into one whole-system read. The two types are not
//! generalizations of one another and must not be conflated.

use crate::dns::DnsConfig;
use crate::firewall::FirewallRule;
use crate::ifaddr::InterfaceAddress;
use crate::interface::Interface;
use crate::neighbor::NeighborEntry;
use crate::route::Route;

/// A best-effort, non-atomic snapshot of observed networking state across
/// every domain this crate models.
///
/// Assembly of a `CurrentState` (performed elsewhere — the `net-lattice`
/// facade assembles one from a backend's individual provider reads, not this
/// crate, which has no operating-system dependency) reads each domain
/// sequentially and independently: routes, then interfaces, then neighbors,
/// then interface addresses, then DNS configuration. No lock or transaction
/// spans these reads, so a `CurrentState` is not a consistent point-in-time
/// view across domains — concurrent external changes between two of the
/// underlying reads are possible and are not detected or reported.
///
/// Assembly is fail-fast: if any one domain's read fails, no `CurrentState`
/// is produced at all. There is no partial-result variant with per-domain
/// `Result`/`Option` fields; a caller that wants best-effort partial data
/// should call the individual per-domain read methods directly instead of
/// requesting a whole-system snapshot.
///
/// `Capability` is deliberately not a field here: it is a runtime fact about
/// the connected backend, not domain state built from observed
/// `net-lattice-model` types, and is already available separately.
///
/// `#[non_exhaustive]`: a later stage may add a field (for example a
/// capture-time marker) without this being a breaking change for callers who
/// do not construct a `CurrentState` via a struct literal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CurrentState {
    /// Routes observed at read time.
    pub routes: Vec<Route>,
    /// Interfaces observed at read time.
    pub interfaces: Vec<Interface>,
    /// ARP/NDP neighbor entries observed at read time.
    pub neighbors: Vec<NeighborEntry>,
    /// Interface addresses observed at read time.
    pub addresses: Vec<InterfaceAddress>,
    /// Resolver configuration observed at read time.
    pub dns: DnsConfig,
    /// Firewall rules observed at read time, in the order the backend
    /// applies them. Does not carry the backend's current default verdict
    /// — see [`crate::mutation::MutationSnapshot::Firewall`] for why that
    /// value is not observable through this crate's provider contracts.
    pub firewall_rules: Vec<FirewallRule>,
}

impl CurrentState {
    /// Assembles a [`CurrentState`] from its six per-domain reads.
    ///
    /// `#[non_exhaustive]` blocks a struct-literal construction from outside
    /// this crate (for example from the `net-lattice` facade, which is the
    /// only place a whole-system snapshot is actually assembled — see
    /// [`crate::snapshot`]'s module documentation), so this constructor is
    /// the supported way to build one.
    pub fn new(
        routes: Vec<Route>,
        interfaces: Vec<Interface>,
        neighbors: Vec<NeighborEntry>,
        addresses: Vec<InterfaceAddress>,
        dns: DnsConfig,
        firewall_rules: Vec<FirewallRule>,
    ) -> Self {
        Self {
            routes,
            interfaces,
            neighbors,
            addresses,
            dns,
            firewall_rules,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpAddress;
    use crate::address::Network;
    use crate::ifaddr::InterfaceAddressId;
    use crate::interface::{InterfaceId, InterfaceKind};
    use crate::neighbor::NeighborId;
    use crate::route::RouteId;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

    fn network() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ))
    }

    fn sample() -> CurrentState {
        CurrentState {
            routes: vec![Route::new(RouteId::new(1), network())],
            interfaces: vec![Interface::new(
                InterfaceId::new(1),
                1,
                "eth0",
                InterfaceKind::Ethernet,
            )],
            neighbors: vec![NeighborEntry::new(
                NeighborId::new(1),
                1,
                IpAddress::from(Ipv4Address::new(192, 0, 2, 1)),
            )],
            addresses: vec![InterfaceAddress::new(
                InterfaceAddressId::new(1),
                1,
                network(),
            )],
            dns: DnsConfig::new(),
            firewall_rules: vec![FirewallRule::new(
                crate::firewall::Direction::Inbound,
                crate::firewall::Verdict::Deny,
            )],
        }
    }

    #[test]
    fn constructs_from_every_domain_field() {
        let state = sample();
        assert_eq!(state.routes.len(), 1);
        assert_eq!(state.interfaces.len(), 1);
        assert_eq!(state.neighbors.len(), 1);
        assert_eq!(state.addresses.len(), 1);
        assert_eq!(state.dns, DnsConfig::new());
        assert_eq!(state.firewall_rules.len(), 1);
    }

    #[test]
    fn equal_when_every_field_matches() {
        assert_eq!(sample(), sample());
    }

    #[test]
    fn differs_when_one_domain_changes() {
        let mut other = sample();
        other.routes.push(Route::new(RouteId::new(2), network()));
        assert_ne!(sample(), other);
    }

    #[test]
    fn empty_state_is_distinct_from_populated_state() {
        let empty = CurrentState {
            routes: Vec::new(),
            interfaces: Vec::new(),
            neighbors: Vec::new(),
            addresses: Vec::new(),
            dns: DnsConfig::new(),
            firewall_rules: Vec::new(),
        };
        assert_ne!(empty, sample());
        assert!(empty.routes.is_empty());
        assert!(empty.interfaces.is_empty());
        assert!(empty.neighbors.is_empty());
        assert!(empty.addresses.is_empty());
        assert!(empty.firewall_rules.is_empty());
    }

    #[test]
    fn clone_produces_an_equal_value() {
        let state = sample();
        assert_eq!(state.clone(), state);
    }
}
