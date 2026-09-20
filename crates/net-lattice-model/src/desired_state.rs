//! A whole-system, caller-authored desired-state aggregate.
//!
//! `DesiredState` is the declarative counterpart to [`crate::snapshot::CurrentState`]:
//! where `CurrentState` is assembled elsewhere (by a backend's provider
//! reads, via the `net-lattice` facade) from observed state types,
//! `DesiredState` is authored directly by a caller from the corresponding
//! per-domain *configuration/intent* types (`RouteConfig`,
//! `InterfaceConfig`, `StaticNeighbor`, `NewInterfaceAddress`,
//! `NewDnsConfig`) this crate already defines. It has no operating-system or
//! backend dependency and is never assembled from provider reads — building
//! one is purely a matter of calling this module's constructor/builder
//! methods with the values a caller wants.
//!
//! [`crate::diff::Diff`] compares a `CurrentState` against a `DesiredState`
//! to compute the actions needed to reconcile observed state toward desired
//! state. This module defines only the `DesiredState` data shape; it
//! computes nothing.

use crate::dns::NewDnsConfig;
use crate::firewall::FirewallPolicy;
use crate::ifaddr::NewInterfaceAddress;
use crate::interface::InterfaceConfig;
use crate::neighbor::StaticNeighbor;
use crate::route::RouteConfig;

/// A whole-system desired-state expression across every domain this crate
/// models, authored by a caller rather than observed from a backend.
///
/// Every field is wrapped in an outer [`Option`], and that outer `Option`
/// carries a domain-level, not entry-level, meaning:
///
/// - `None` means this domain is **not managed** by this `DesiredState` at
///   all — the caller does not care about it. [`crate::diff::Diff`] computed
///   against a `None` domain produces no changes for that domain, including
///   no proposed removals for entries that exist only in the observed
///   [`crate::snapshot::CurrentState`].
/// - `Some(_)` means this domain **is managed**, and the contained value is
///   the complete desired content for that domain. For the four
///   collection-shaped domains (`routes`, `interfaces`, `neighbors`,
///   `addresses`), `Some(vec![])` is a meaningful, distinct value: it means
///   "this domain is managed, and I want zero entries in it" —
///   [`crate::diff::Diff`] treats this as a request to remove every entry
///   currently observed in that domain, not as "nothing to do." An empty
///   `Vec` is never equivalent to `None`; the two must not be collapsed into
///   one representation.
///
/// This two-level `Option` reading (domain-level opt-out via the outer
/// `Option` on `DesiredState` itself, versus each per-domain config type's
/// own internal, field-level `Option`s such as [`InterfaceConfig`]'s
/// "don't touch this field" semantics) is a distinct concept from this
/// struct's own fields: `DesiredState`'s `Option` always means "is this
/// domain in scope," never "should this one field of an already-in-scope
/// entry be changed." Do not conflate the two when reading or extending
/// this type.
///
/// `#[non_exhaustive]`: a later stage may add a domain field without this
/// being a breaking change for callers who do not construct a
/// `DesiredState` via a struct literal, matching
/// [`crate::snapshot::CurrentState`]'s own non-exhaustive rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DesiredState {
    /// Desired routes, or `None` if routes are not managed by this
    /// `DesiredState`.
    pub routes: Option<Vec<RouteConfig>>,
    /// Desired interface configuration patches, or `None` if interfaces are
    /// not managed by this `DesiredState`.
    pub interfaces: Option<Vec<InterfaceConfig>>,
    /// Desired static neighbor entries, or `None` if neighbors are not
    /// managed by this `DesiredState`.
    pub neighbors: Option<Vec<StaticNeighbor>>,
    /// Desired interface addresses, or `None` if addresses are not managed
    /// by this `DesiredState`.
    pub addresses: Option<Vec<NewInterfaceAddress>>,
    /// Desired resolver configuration, or `None` if DNS is not managed by
    /// this `DesiredState`. Unlike the other four domains, this is a
    /// singleton value rather than a collection, since a system has exactly
    /// one resolver configuration.
    pub dns: Option<NewDnsConfig>,
    /// Desired firewall policy, or `None` if the firewall is not managed by
    /// this `DesiredState`. Like `dns`, this is a singleton value: a system
    /// has exactly one active default-verdict-plus-rules policy per
    /// backend.
    pub firewall: Option<FirewallPolicy>,
}

impl DesiredState {
    /// Creates a `DesiredState` that manages no domain at all (every field
    /// is `None`).
    ///
    /// This is the starting point for the `with_*` builder methods, mirroring
    /// this crate's existing builder convention (see [`RouteConfig::new`] /
    /// `with_gateway` and similar patterns on other domain types) rather than
    /// a single positional constructor: most callers only intend to manage a
    /// subset of the five domains, and starting from a fully-`None` value
    /// makes that intent explicit at each call site.
    pub fn empty() -> Self {
        Self {
            routes: None,
            interfaces: None,
            neighbors: None,
            addresses: None,
            dns: None,
            firewall: None,
        }
    }

    /// Marks the route domain as managed, with `routes` as its desired
    /// content (which may be empty to request removal of every observed
    /// route).
    pub fn with_routes(mut self, routes: Vec<RouteConfig>) -> Self {
        self.routes = Some(routes);
        self
    }

    /// Marks the interface domain as managed, with `interfaces` as its
    /// desired content (which may be empty to request no interface patches
    /// be applied).
    pub fn with_interfaces(mut self, interfaces: Vec<InterfaceConfig>) -> Self {
        self.interfaces = Some(interfaces);
        self
    }

    /// Marks the neighbor domain as managed, with `neighbors` as its desired
    /// content (which may be empty to request removal of every observed
    /// static neighbor).
    pub fn with_neighbors(mut self, neighbors: Vec<StaticNeighbor>) -> Self {
        self.neighbors = Some(neighbors);
        self
    }

    /// Marks the address domain as managed, with `addresses` as its desired
    /// content (which may be empty to request removal of every observed
    /// interface address).
    pub fn with_addresses(mut self, addresses: Vec<NewInterfaceAddress>) -> Self {
        self.addresses = Some(addresses);
        self
    }

    /// Marks the DNS domain as managed, with `dns` as its desired resolver
    /// configuration.
    pub fn with_dns(mut self, dns: NewDnsConfig) -> Self {
        self.dns = Some(dns);
        self
    }

    /// Marks the firewall domain as managed, with `firewall` as its desired
    /// policy (which may have an empty rule list, meaning "only the default
    /// verdict applies").
    pub fn with_firewall(mut self, firewall: FirewallPolicy) -> Self {
        self.firewall = Some(firewall);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpAddress;
    use crate::address::Network;
    use crate::interface::InterfaceId;
    use crate::mac::MacAddress;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

    fn network() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, 0),
            Ipv4PrefixLength::new(24).expect("valid prefix"),
        ))
    }

    fn sample() -> DesiredState {
        DesiredState::empty()
            .with_routes(vec![RouteConfig::new(network())])
            .with_neighbors(vec![StaticNeighbor::new(
                InterfaceId::new(1),
                IpAddress::from(Ipv4Address::new(192, 0, 2, 1)),
                MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            )])
            .with_addresses(vec![NewInterfaceAddress::new(
                InterfaceId::new(1),
                network(),
            )])
            .with_dns(NewDnsConfig::with(
                vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
                vec!["example.test".to_string()],
            ))
            .with_firewall(FirewallPolicy::new(crate::firewall::Verdict::Allow))
    }

    #[test]
    fn empty_manages_no_domain() {
        let state = DesiredState::empty();
        assert_eq!(state.routes, None);
        assert_eq!(state.interfaces, None);
        assert_eq!(state.neighbors, None);
        assert_eq!(state.addresses, None);
        assert_eq!(state.dns, None);
        assert_eq!(state.firewall, None);
    }

    #[test]
    fn builders_set_every_domain() {
        let state = sample();
        assert!(state.routes.is_some());
        assert!(state.neighbors.is_some());
        assert!(state.addresses.is_some());
        assert!(state.dns.is_some());
        assert!(state.firewall.is_some());
        assert_eq!(state.interfaces, None);
    }

    #[test]
    fn equal_when_every_field_matches() {
        assert_eq!(sample(), sample());
    }

    #[test]
    fn differs_when_one_domain_changes() {
        let mut other = sample();
        other.routes = Some(vec![
            RouteConfig::new(network()),
            RouteConfig::new(network()).with_metric(7),
        ]);
        assert_ne!(sample(), other);
    }

    #[test]
    fn none_and_some_empty_are_distinct_for_a_collection_domain() {
        let unmanaged = DesiredState::empty();
        let managed_empty = DesiredState::empty().with_routes(Vec::new());

        assert_ne!(unmanaged, managed_empty);
        assert_eq!(unmanaged.routes, None);
        assert_eq!(managed_empty.routes, Some(Vec::new()));
        assert_ne!(unmanaged.routes, managed_empty.routes);
    }

    #[test]
    fn none_and_some_default_are_distinct_for_the_dns_domain() {
        let unmanaged = DesiredState::empty();
        let managed_default = DesiredState::empty().with_dns(NewDnsConfig::new());

        assert_ne!(unmanaged, managed_default);
        assert_eq!(unmanaged.dns, None);
        assert_eq!(managed_default.dns, Some(NewDnsConfig::new()));
    }

    #[test]
    fn clone_produces_an_equal_value() {
        let state = sample();
        assert_eq!(state.clone(), state);
    }
}
