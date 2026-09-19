//! The computed, inspectable difference between a [`CurrentState`] and a
//! [`DesiredState`].
//!
//! `Diff` is pure and side-effect-free: [`Diff::compute`] reads only its two
//! arguments, performs no I/O, calls no provider/backend method, and
//! constructs no apply plan. Deciding *how* (or whether) to apply a `Diff`
//! against a live backend is out of this crate's scope entirely — that is a
//! later stage's concern.

use std::collections::HashMap;

use crate::desired_state::DesiredState;
use crate::dns::{DnsConfig, NewDnsConfig};
use crate::ifaddr::{InterfaceAddress, NewInterfaceAddress};
use crate::interface::{AdminState, DesiredAdminState, InterfaceId};
use crate::neighbor::{NeighborEntry, StaticNeighbor};
use crate::route::{Route, RouteConfig};
use crate::snapshot::CurrentState;

/// The computed difference between a [`CurrentState`] and a [`DesiredState`],
/// comparing state and config types field-by-field where they overlap, one
/// field per domain (mirroring [`CurrentState`]/[`DesiredState`]'s own
/// one-field-per-domain shape).
///
/// The five domains are not diffed uniformly: route/neighbor/address share
/// one natural-key set-diff shape, interface uses a distinct per-field
/// patch-diff shape mirroring [`crate::interface::InterfaceConfig`]'s own
/// "don't touch" semantics, and DNS is a whole-value singleton comparison.
/// See each field's documentation and [`Diff::compute`] for the exact rule
/// per domain.
///
/// `#[non_exhaustive]`: a later stage may add a field without this being a
/// breaking change for callers who do not construct a `Diff` via a struct
/// literal, matching [`CurrentState`]/[`DesiredState`]'s own rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diff {
    /// Routes to add or remove. Never contains a "changed" case: the
    /// four-field natural key (`destination + gateway + metric +
    /// interface_index`) already covers every settable [`RouteConfig`]
    /// field, so any field difference produces a different key entirely —
    /// a "changed" route is represented as a `Removed`/`Added` pair, not a
    /// third variant.
    ///
    /// **Darwin note:** `RouteConfig::metric` is silently ignored (never
    /// applied) on Darwin, while observed `Route::metric` is always `None`
    /// there. `Diff::compute` is structural-only and makes no convergence
    /// promise: a desired route with an explicit `metric` on Darwin will
    /// report the same `Removed`/`Added` pair every time it is recomputed,
    /// even after a hypothetical apply, because the key itself never
    /// matches. See [`RouteConfig::metric`]'s own documentation for the
    /// underlying platform gap, which this type does not introduce.
    pub routes: Vec<RouteChange>,
    /// Per-interface field-level patches, one entry per [`InterfaceId`] that
    /// has at least one requested field differing from its observed value.
    /// An interface with zero differing requested fields does not appear
    /// here at all — see [`InterfaceDiff`] for the exact per-field rule.
    pub interfaces: Vec<InterfaceDiff>,
    /// Static neighbor entries to add, remove, or change, matched by the
    /// natural key `(interface_id, address)`.
    pub neighbors: Vec<NeighborChange>,
    /// Interface addresses to add, remove, or change, matched by the natural
    /// key `(interface_id, address)`.
    pub addresses: Vec<AddressChange>,
    /// The whole-resolver-configuration change, if any. `None` means either
    /// DNS is unmanaged (`DesiredState::dns` is `None`) or the desired
    /// configuration already matches the observed one — the two cases are
    /// indistinguishable from `Diff`'s output alone, matching how an
    /// unmanaged and an already-matching domain collapse to "nothing to do"
    /// for every other domain too.
    pub dns: Option<DnsChange>,
}

/// One requested-but-unmatched field on an [`InterfaceDiff`]: the observed
/// value alongside the desired value that differs from it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Change<C, D> {
    /// The currently observed value.
    pub current: C,
    /// The desired value, which differs from `current`.
    pub desired: D,
}

/// A per-field patch-diff for one interface, mirroring
/// [`crate::interface::InterfaceConfig`]'s own field-level `Option`
/// ("don't touch") semantics.
///
/// A field is `Some` only when the corresponding [`crate::interface::InterfaceConfig`]
/// accessor returned `Some` (the caller requested that field) **and** the
/// requested value differs from the value observed on
/// [`crate::interface::Interface`]. A field that was never requested and a
/// field that was requested but already matches the observed value both
/// collapse to `None` — `InterfaceDiff` alone cannot distinguish "not asked
/// about" from "asked about, already satisfied," and per ADR-0009 it is not
/// required to: only a *not-requested* field must never appear *populated*,
/// which this satisfies either way.
///
/// An [`InterfaceDiff`] is omitted entirely from [`Diff::interfaces`] when
/// every requested field on the corresponding
/// [`crate::interface::InterfaceConfig`] already matches the observed
/// interface (nothing actionable to report), so a caller scanning
/// `Diff::interfaces` sees only interfaces that need a native write. An
/// [`crate::interface::InterfaceConfig`] naming an [`InterfaceId`] absent
/// from [`CurrentState::interfaces`] is likewise omitted (a target-missing
/// outcome, not a diff entry — [`Diff`] has no channel to report this today).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InterfaceDiff {
    /// The interface this patch-diff applies to.
    pub interface_id: InterfaceId,
    /// The requested administrative state, if it was requested and differs
    /// from the observed one.
    pub admin_state: Option<Change<AdminState, DesiredAdminState>>,
    /// The requested MTU, if it was requested and differs from the observed
    /// one.
    pub mtu: Option<Change<u32, u32>>,
}

/// A route to add or remove. See [`Diff::routes`] for why no `Changed`
/// variant exists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteChange {
    /// A desired route absent from [`CurrentState::routes`] under the
    /// four-field natural key.
    Added(RouteConfig),
    /// An observed route absent from the desired routes under the four-field
    /// natural key.
    Removed(Route),
}

/// A static neighbor entry to add, remove, or change, matched by
/// `(interface_id, address)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NeighborChange {
    /// A desired static neighbor whose `(interface_id, address)` key is
    /// absent from [`CurrentState::neighbors`].
    Added(StaticNeighbor),
    /// An observed neighbor entry whose `(interface_id, address)` key is
    /// absent from the desired neighbors.
    Removed(NeighborEntry),
    /// A paired entry (same `(interface_id, address)` key) whose `mac`
    /// differs.
    Changed {
        /// The currently observed entry.
        current: NeighborEntry,
        /// The desired entry, whose `mac` differs from `current`.
        desired: StaticNeighbor,
    },
}

/// An interface address to add, remove, or change, matched by
/// `(interface_id, address)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressChange {
    /// A desired address whose `(interface_id, address)` key is absent from
    /// [`CurrentState::addresses`].
    Added(NewInterfaceAddress),
    /// An observed address whose `(interface_id, address)` key is absent
    /// from the desired addresses.
    Removed(InterfaceAddress),
    /// A paired entry (same `(interface_id, address)` key) whose desired
    /// `broadcast` is `Some` and differs from the observed one. A desired
    /// `broadcast` of `None` never produces a `Changed` entry by itself —
    /// it means the caller expressed no preference, not that the observed
    /// broadcast address should be cleared.
    Changed {
        /// The currently observed address.
        current: InterfaceAddress,
        /// The desired address, whose `broadcast` differs from `current`.
        desired: NewInterfaceAddress,
    },
}

/// A whole-resolver-configuration change: the observed [`DnsConfig`]
/// alongside a desired [`NewDnsConfig`] that differs from it field-for-field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsChange {
    /// The currently observed resolver configuration.
    pub current: DnsConfig,
    /// The desired resolver configuration, which differs from `current`.
    pub desired: NewDnsConfig,
}

impl Diff {
    /// Computes the difference between `current` and `desired`.
    ///
    /// Pure and side-effect-free: reads only `current` and `desired`,
    /// performs no I/O, calls no provider/backend method, and constructs no
    /// apply plan.
    ///
    /// An unmanaged domain (`desired`'s corresponding field is `None`)
    /// always produces an empty `Vec`/`None` for that field, including zero
    /// `Removed` entries. A managed-but-empty domain (`Some(vec![])`, or
    /// `Some(NewDnsConfig::new())`-with-defaults for DNS-if-different)
    /// produces a `Removed` entry for every observed entry in that domain
    /// (or a `DnsChange` if the empty configuration differs from the
    /// observed one).
    ///
    /// **Duplicate natural keys:** if a `desired` collection contains more
    /// than one entry sharing the same natural key (interface: `InterfaceId`;
    /// address/neighbor: `(interface_id, address)`; route: the full
    /// four-field key), the later entry in `Vec` iteration order wins;
    /// earlier duplicates with the same key are silently discarded. This
    /// applies per domain, independently.
    pub fn compute(current: &CurrentState, desired: &DesiredState) -> Diff {
        Diff {
            routes: compute_routes(&current.routes, desired.routes.as_deref()),
            interfaces: compute_interfaces(&current.interfaces, desired.interfaces.as_deref()),
            neighbors: compute_neighbors(&current.neighbors, desired.neighbors.as_deref()),
            addresses: compute_addresses(&current.addresses, desired.addresses.as_deref()),
            dns: compute_dns(&current.dns, desired.dns.as_ref()),
        }
    }
}

fn compute_routes(current: &[Route], desired: Option<&[RouteConfig]>) -> Vec<RouteChange> {
    let Some(desired) = desired else {
        return Vec::new();
    };

    let current_keys: std::collections::HashSet<RouteKey> =
        current.iter().map(RouteKey::from_route).collect();
    // Last-one-wins for duplicate keys within `desired`.
    let desired_map: HashMap<RouteKey, RouteConfig> = desired
        .iter()
        .map(|config| (RouteKey::from_config(config), *config))
        .collect();

    let mut changes = Vec::new();
    for route in current {
        if !desired_map.contains_key(&RouteKey::from_route(route)) {
            changes.push(RouteChange::Removed(route.clone()));
        }
    }
    // Preserve caller order for deterministic diffs. The map above still
    // implements last-one-wins for duplicate keys; only the final occurrence
    // of each key is emitted.
    for config in desired {
        let key = RouteKey::from_config(config);
        if desired_map.get(&key) == Some(config) && !current_keys.contains(&key) {
            changes.push(RouteChange::Added(*config));
        }
    }
    changes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RouteKey {
    destination: crate::address::Network,
    gateway: Option<crate::address::IpAddress>,
    metric: Option<u32>,
    interface_index: Option<u32>,
}

impl RouteKey {
    fn from_route(route: &Route) -> Self {
        Self {
            destination: route.destination,
            gateway: route.gateway,
            metric: route.metric,
            interface_index: route.interface_index,
        }
    }

    fn from_config(config: &RouteConfig) -> Self {
        Self {
            destination: config.destination,
            gateway: config.gateway,
            metric: config.metric,
            interface_index: config.interface_index,
        }
    }
}

fn compute_interfaces(
    current: &[crate::interface::Interface],
    desired: Option<&[crate::interface::InterfaceConfig]>,
) -> Vec<InterfaceDiff> {
    let Some(desired) = desired else {
        return Vec::new();
    };

    // Last-one-wins for duplicate InterfaceId within `desired`.
    let mut desired_map: HashMap<InterfaceId, &crate::interface::InterfaceConfig> = HashMap::new();
    for config in desired {
        desired_map.insert(config.interface_id(), config);
    }

    let mut diffs = Vec::new();
    for config in desired {
        let interface_id = config.interface_id();
        // The map implements last-one-wins for duplicate IDs. Skip earlier
        // duplicates while retaining the caller's ordering for the surviving
        // entries.
        if desired_map.get(&interface_id).map(|candidate| *candidate) != Some(config) {
            continue;
        }

        let Some(observed) = current.iter().find(|iface| iface.id == interface_id) else {
            // Target-missing outcome: not represented in Diff's output.
            continue;
        };

        let admin_state = config.admin_state().and_then(|desired_admin| {
            if admin_state_matches(observed.admin_state, desired_admin) {
                None
            } else {
                Some(Change {
                    current: observed.admin_state,
                    desired: desired_admin,
                })
            }
        });

        let mtu = config.mtu().and_then(|desired_mtu| {
            if observed.mtu == Some(desired_mtu) {
                None
            } else {
                Some(Change {
                    current: observed.mtu.unwrap_or_default(),
                    desired: desired_mtu,
                })
            }
        });

        if admin_state.is_some() || mtu.is_some() {
            diffs.push(InterfaceDiff {
                interface_id,
                admin_state,
                mtu,
            });
        }
    }
    diffs
}

fn admin_state_matches(observed: AdminState, desired: DesiredAdminState) -> bool {
    matches!(
        (observed, desired),
        (AdminState::Up, DesiredAdminState::Up) | (AdminState::Down, DesiredAdminState::Down)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NeighborKey {
    interface_id: InterfaceId,
    address: crate::address::IpAddress,
}

/// The natural key for the address domain: `(interface_id, address)`, where
/// `address` includes the prefix length (`InterfaceAddress`/
/// `NewInterfaceAddress` both store a full `Network`, not a bare IP), unlike
/// the neighbor domain's bare-`IpAddress` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AddressKey {
    interface_id: InterfaceId,
    address: crate::address::Network,
}

fn compute_neighbors(
    current: &[NeighborEntry],
    desired: Option<&[StaticNeighbor]>,
) -> Vec<NeighborChange> {
    let Some(desired) = desired else {
        return Vec::new();
    };

    let mut desired_map: HashMap<NeighborKey, StaticNeighbor> = HashMap::new();
    for neighbor in desired {
        desired_map.insert(
            NeighborKey {
                interface_id: neighbor.interface_id,
                address: neighbor.address,
            },
            *neighbor,
        );
    }

    let mut changes = Vec::new();
    let mut matched: std::collections::HashSet<NeighborKey> = std::collections::HashSet::new();
    for entry in current {
        let key = NeighborKey {
            interface_id: InterfaceId::new(u64::from(entry.interface_index)),
            address: entry.address,
        };
        match desired_map.get(&key) {
            Some(desired_neighbor) => {
                matched.insert(key);
                if entry.mac != Some(desired_neighbor.mac) {
                    changes.push(NeighborChange::Changed {
                        current: entry.clone(),
                        desired: *desired_neighbor,
                    });
                }
            }
            None => changes.push(NeighborChange::Removed(entry.clone())),
        }
    }
    // Preserve desired input order while retaining last-one-wins
    // duplicate semantics from desired_map.
    for neighbor in desired {
        let key = NeighborKey {
            interface_id: neighbor.interface_id,
            address: neighbor.address,
        };
        if desired_map.get(&key) == Some(neighbor) && !matched.contains(&key) {
            changes.push(NeighborChange::Added(*neighbor));
        }
    }
    changes
}

fn compute_addresses(
    current: &[InterfaceAddress],
    desired: Option<&[NewInterfaceAddress]>,
) -> Vec<AddressChange> {
    let Some(desired) = desired else {
        return Vec::new();
    };

    let mut desired_map: HashMap<AddressKey, NewInterfaceAddress> = HashMap::new();
    for address in desired {
        desired_map.insert(
            AddressKey {
                interface_id: address.interface_id,
                address: address.address,
            },
            address.clone(),
        );
    }

    let mut changes = Vec::new();
    let mut matched: std::collections::HashSet<AddressKey> = std::collections::HashSet::new();
    for observed in current {
        let key = AddressKey {
            interface_id: InterfaceId::new(u64::from(observed.interface_index)),
            address: observed.address,
        };
        match desired_map.get(&key) {
            Some(desired_address) => {
                matched.insert(key);
                let mismatched_broadcast = match desired_address.broadcast {
                    Some(desired_broadcast) => {
                        observed.broadcast
                            != Some(crate::address::IpAddress::from(desired_broadcast))
                    }
                    None => false,
                };
                if mismatched_broadcast {
                    changes.push(AddressChange::Changed {
                        current: observed.clone(),
                        desired: desired_address.clone(),
                    });
                }
            }
            None => changes.push(AddressChange::Removed(observed.clone())),
        }
    }
    // Preserve desired input order while retaining last-one-wins
    // duplicate semantics from desired_map.
    for address in desired {
        let key = AddressKey {
            interface_id: address.interface_id,
            address: address.address,
        };
        if desired_map.get(&key) == Some(address) && !matched.contains(&key) {
            changes.push(AddressChange::Added(address.clone()));
        }
    }
    changes
}

fn compute_dns(current: &DnsConfig, desired: Option<&NewDnsConfig>) -> Option<DnsChange> {
    let desired = desired?;
    if desired.nameservers == current.nameservers
        && desired.search_domains == current.search_domains
    {
        return None;
    }
    Some(DnsChange {
        current: current.clone(),
        desired: desired.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpAddress;
    use crate::address::Network;
    use crate::ifaddr::InterfaceAddressId;
    use crate::interface::{Interface, InterfaceConfig, InterfaceKind};
    use crate::mac::MacAddress;
    use crate::neighbor::NeighborId;
    use crate::route::RouteId;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

    fn network(octet: u8) -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 0, 2, octet),
            Ipv4PrefixLength::new(32).expect("valid prefix"),
        ))
    }

    fn empty_state() -> CurrentState {
        CurrentState::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            DnsConfig::new(),
        )
    }

    // ---- routes ----

    #[test]
    fn route_no_op_when_current_matches_desired() {
        let route_config = RouteConfig::new(network(0)).with_interface_index(1);
        let route = Route::new(RouteId::new(1), network(0)).with_interface_index(1);
        let current = CurrentState {
            routes: vec![route],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_routes(vec![route_config]);
        let diff = Diff::compute(&current, &desired);
        assert!(diff.routes.is_empty());
    }

    #[test]
    fn route_added_only() {
        let route_config = RouteConfig::new(network(0));
        let current = empty_state();
        let desired = DesiredState::empty().with_routes(vec![route_config]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.routes, vec![RouteChange::Added(route_config)]);
    }

    #[test]
    fn route_removed_only() {
        let route = Route::new(RouteId::new(1), network(0));
        let current = CurrentState {
            routes: vec![route.clone()],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_routes(Vec::new());
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.routes, vec![RouteChange::Removed(route)]);
    }

    #[test]
    fn route_unmanaged_produces_no_diff() {
        let route = Route::new(RouteId::new(1), network(0));
        let current = CurrentState {
            routes: vec![route],
            ..empty_state()
        };
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        assert!(diff.routes.is_empty());
    }

    #[test]
    fn route_duplicate_natural_key_collapses_to_one_added_entry() {
        // Route's natural key IS the whole RouteConfig value (all four
        // fields), so two entries sharing a key are necessarily equal —
        // there is no distinguishing field left to prove "last one wins"
        // with for this domain specifically (unlike interface/neighbor/
        // address, which retain a non-key field that can differ). What this
        // test does confirm: duplicates collapse to exactly one `Added`
        // entry rather than two, matching `Diff::compute`'s HashMap-based
        // last-one-wins implementation for every domain.
        let current = empty_state();
        let dup_a = RouteConfig::new(network(0)).with_metric(1);
        let dup_b = RouteConfig::new(network(0)).with_metric(1);
        let desired = DesiredState::empty().with_routes(vec![dup_a, dup_b]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.routes.len(), 1);
    }

    // ---- interfaces ----

    #[test]
    fn interface_no_op_when_requested_fields_already_match() {
        let interface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet)
            .with_admin_state(AdminState::Up)
            .with_mtu(1500);
        let config =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), Some(1500))
                .expect("valid patch");
        let current = CurrentState {
            interfaces: vec![interface],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_interfaces(vec![config]);
        let diff = Diff::compute(&current, &desired);
        assert!(diff.interfaces.is_empty());
    }

    #[test]
    fn interface_changed_field_surfaces_as_change() {
        let interface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet)
            .with_admin_state(AdminState::Down)
            .with_mtu(1500);
        let config =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), Some(9000))
                .expect("valid patch");
        let current = CurrentState {
            interfaces: vec![interface],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_interfaces(vec![config]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.interfaces.len(), 1);
        let entry = &diff.interfaces[0];
        assert_eq!(entry.interface_id, InterfaceId::new(1));
        assert_eq!(
            entry.admin_state,
            Some(Change {
                current: AdminState::Down,
                desired: DesiredAdminState::Up,
            })
        );
        assert_eq!(
            entry.mtu,
            Some(Change {
                current: 1500,
                desired: 9000,
            })
        );
    }

    #[test]
    fn interface_not_requested_field_never_surfaces() {
        let interface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet)
            .with_admin_state(AdminState::Down)
            .with_mtu(1500);
        // Only admin_state requested, mtu untouched (differs but not asked).
        let config = InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), None)
            .expect("valid patch");
        let current = CurrentState {
            interfaces: vec![interface],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_interfaces(vec![config]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.interfaces.len(), 1);
        assert!(diff.interfaces[0].admin_state.is_some());
        assert_eq!(diff.interfaces[0].mtu, None);
    }

    #[test]
    fn interface_unmanaged_produces_no_diff() {
        let interface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet);
        let current = CurrentState {
            interfaces: vec![interface],
            ..empty_state()
        };
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        assert!(diff.interfaces.is_empty());
    }

    #[test]
    fn interface_target_missing_from_current_produces_no_diff() {
        let config = InterfaceConfig::new(InterfaceId::new(99), Some(DesiredAdminState::Up), None)
            .expect("valid patch");
        let current = empty_state();
        let desired = DesiredState::empty().with_interfaces(vec![config]);
        let diff = Diff::compute(&current, &desired);
        assert!(diff.interfaces.is_empty());
    }

    #[test]
    fn interface_duplicate_natural_key_last_one_wins() {
        let interface = Interface::new(InterfaceId::new(1), 1, "eth0", InterfaceKind::Ethernet)
            .with_admin_state(AdminState::Down);
        let first =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Up), None).unwrap();
        let second =
            InterfaceConfig::new(InterfaceId::new(1), Some(DesiredAdminState::Down), None).unwrap();
        let current = CurrentState {
            interfaces: vec![interface],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_interfaces(vec![first, second]);
        let diff = Diff::compute(&current, &desired);
        // second (Down) matches observed (Down), so no diff entry at all.
        assert!(diff.interfaces.is_empty());
    }

    // ---- neighbors ----

    fn neighbor_address() -> IpAddress {
        IpAddress::from(Ipv4Address::new(192, 0, 2, 1))
    }

    #[test]
    fn neighbor_no_op_when_current_matches_desired() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let entry = NeighborEntry::new(NeighborId::new(1), 1, neighbor_address()).with_mac(mac);
        let desired_neighbor = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac);
        let current = CurrentState {
            neighbors: vec![entry],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_neighbors(vec![desired_neighbor]);
        let diff = Diff::compute(&current, &desired);
        assert!(diff.neighbors.is_empty());
    }

    #[test]
    fn neighbor_added_only() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let desired_neighbor = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac);
        let current = empty_state();
        let desired = DesiredState::empty().with_neighbors(vec![desired_neighbor]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(
            diff.neighbors,
            vec![NeighborChange::Added(desired_neighbor)]
        );
    }

    #[test]
    fn neighbor_removed_only() {
        let entry = NeighborEntry::new(NeighborId::new(1), 1, neighbor_address());
        let current = CurrentState {
            neighbors: vec![entry.clone()],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_neighbors(Vec::new());
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.neighbors, vec![NeighborChange::Removed(entry)]);
    }

    #[test]
    fn neighbor_changed_mac() {
        let mac_a = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mac_b = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let entry = NeighborEntry::new(NeighborId::new(1), 1, neighbor_address()).with_mac(mac_a);
        let desired_neighbor = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac_b);
        let current = CurrentState {
            neighbors: vec![entry.clone()],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_neighbors(vec![desired_neighbor]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(
            diff.neighbors,
            vec![NeighborChange::Changed {
                current: entry,
                desired: desired_neighbor,
            }]
        );
    }

    #[test]
    fn neighbor_unmanaged_produces_no_diff() {
        let entry = NeighborEntry::new(NeighborId::new(1), 1, neighbor_address());
        let current = CurrentState {
            neighbors: vec![entry],
            ..empty_state()
        };
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        assert!(diff.neighbors.is_empty());
    }

    #[test]
    fn neighbor_duplicate_natural_key_last_one_wins() {
        let mac_a = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let mac_b = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let first = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac_a);
        let second = StaticNeighbor::new(InterfaceId::new(1), neighbor_address(), mac_b);
        let current = empty_state();
        let desired = DesiredState::empty().with_neighbors(vec![first, second]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.neighbors, vec![NeighborChange::Added(second)]);
    }

    // ---- addresses ----

    #[test]
    fn address_no_op_when_current_matches_desired() {
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0));
        let desired_addr = NewInterfaceAddress::new(InterfaceId::new(1), network(0));
        let current = CurrentState {
            addresses: vec![addr],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_addresses(vec![desired_addr]);
        let diff = Diff::compute(&current, &desired);
        assert!(diff.addresses.is_empty());
    }

    #[test]
    fn address_added_only() {
        let desired_addr = NewInterfaceAddress::new(InterfaceId::new(1), network(0));
        let current = empty_state();
        let desired = DesiredState::empty().with_addresses(vec![desired_addr.clone()]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.addresses, vec![AddressChange::Added(desired_addr)]);
    }

    #[test]
    fn address_removed_only() {
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0));
        let current = CurrentState {
            addresses: vec![addr.clone()],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_addresses(Vec::new());
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.addresses, vec![AddressChange::Removed(addr)]);
    }

    #[test]
    fn address_changed_broadcast() {
        let observed_broadcast = IpAddress::from(Ipv4Address::new(192, 0, 2, 255));
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0))
            .with_broadcast(observed_broadcast);
        let desired_addr = NewInterfaceAddress::new(InterfaceId::new(1), network(0))
            .with_broadcast(Ipv4Address::new(192, 0, 2, 254));
        let current = CurrentState {
            addresses: vec![addr.clone()],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_addresses(vec![desired_addr.clone()]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(
            diff.addresses,
            vec![AddressChange::Changed {
                current: addr,
                desired: desired_addr,
            }]
        );
    }

    #[test]
    fn address_desired_broadcast_none_never_produces_a_change() {
        let observed_broadcast = IpAddress::from(Ipv4Address::new(192, 0, 2, 255));
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0))
            .with_broadcast(observed_broadcast);
        let desired_addr = NewInterfaceAddress::new(InterfaceId::new(1), network(0));
        let current = CurrentState {
            addresses: vec![addr],
            ..empty_state()
        };
        let desired = DesiredState::empty().with_addresses(vec![desired_addr]);
        let diff = Diff::compute(&current, &desired);
        assert!(diff.addresses.is_empty());
    }

    #[test]
    fn address_unmanaged_produces_no_diff() {
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, network(0));
        let current = CurrentState {
            addresses: vec![addr],
            ..empty_state()
        };
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        assert!(diff.addresses.is_empty());
    }

    #[test]
    fn address_duplicate_natural_key_last_one_wins() {
        let first = NewInterfaceAddress::new(InterfaceId::new(1), network(0))
            .with_broadcast(Ipv4Address::new(192, 0, 2, 1));
        let second = NewInterfaceAddress::new(InterfaceId::new(1), network(0))
            .with_broadcast(Ipv4Address::new(192, 0, 2, 2));
        let current = empty_state();
        let desired = DesiredState::empty().with_addresses(vec![first, second.clone()]);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.addresses, vec![AddressChange::Added(second)]);
    }

    // ---- dns ----

    #[test]
    fn dns_no_op_when_current_matches_desired() {
        let dns = DnsConfig {
            nameservers: vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
            search_domains: vec!["example.test".to_string()],
        };
        let desired_dns = NewDnsConfig::with(
            vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
            vec!["example.test".to_string()],
        );
        let current = CurrentState {
            dns,
            ..empty_state()
        };
        let desired = DesiredState::empty().with_dns(desired_dns);
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.dns, None);
    }

    #[test]
    fn dns_changed_when_desired_differs() {
        let dns = DnsConfig::new();
        let desired_dns = NewDnsConfig::with(
            vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
            Vec::new(),
        );
        let current = CurrentState {
            dns: dns.clone(),
            ..empty_state()
        };
        let desired = DesiredState::empty().with_dns(desired_dns.clone());
        let diff = Diff::compute(&current, &desired);
        assert_eq!(
            diff.dns,
            Some(DnsChange {
                current: dns,
                desired: desired_dns,
            })
        );
    }

    #[test]
    fn dns_unmanaged_produces_no_diff() {
        let dns = DnsConfig {
            nameservers: vec![IpAddress::from(Ipv4Address::new(1, 1, 1, 1))],
            search_domains: Vec::new(),
        };
        let current = CurrentState {
            dns,
            ..empty_state()
        };
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        assert_eq!(diff.dns, None);
    }

    // ---- whole diff ----

    #[test]
    fn empty_current_and_empty_desired_produce_empty_diff() {
        let current = empty_state();
        let desired = DesiredState::empty();
        let diff = Diff::compute(&current, &desired);
        assert!(diff.routes.is_empty());
        assert!(diff.interfaces.is_empty());
        assert!(diff.neighbors.is_empty());
        assert!(diff.addresses.is_empty());
        assert_eq!(diff.dns, None);
    }
}
