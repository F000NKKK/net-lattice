use net_lattice_core::Id;

use crate::IpAddress;
use crate::mac::MacAddress;

/// Identifies a [`NeighborEntry`].
pub type NeighborId = Id<NeighborEntry>;

/// The reachability state of a neighbor entry, per the Neighbor Unreachability
/// Detection state machine shared (with minor naming differences) by Linux's
/// `NUD_*` states, BSD/macOS's route-socket `RTF_*` flags on an ARP/NDP
/// entry, and Windows's `NL_NEIGHBOR_STATE`.
///
/// `#[non_exhaustive]`: not every platform exposes every state (BSD/macOS's
/// route-socket view collapses several of these into a single flags word),
/// and `Unknown` covers whatever a platform can't map cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NeighborState {
    /// Address resolution is in progress; no link-layer address yet.
    Incomplete,
    /// Confirmed reachable within the last reachable-time window.
    Reachable,
    /// Reachability is unconfirmed but the entry has not yet been probed.
    Stale,
    /// About to send a reachability probe after a delay.
    Delay,
    /// Actively probing to reconfirm reachability.
    Probe,
    /// Address resolution failed.
    Failed,
    /// Manually configured; never expires or is probed.
    Permanent,
    /// The platform does not expose a separate reachability state.
    Unknown,
}

/// A single entry in the system's neighbor table (ARP for IPv4, NDP for
/// IPv6): the mapping from an on-link IP address to a link-layer (MAC)
/// address, as observed or configured on a given interface.
///
/// `#[non_exhaustive]`: platforms carry different neighbor fields (Linux
/// exposes NUD state and a routing-protocol-style entry `kind`; BSD/macOS
/// expose only a flags word; Windows exposes `IsRouter`/reachability
/// timestamps). Marking this non-exhaustive now means adding
/// platform-specific fields later is not a breaking change for consumers who
/// construct a `NeighborEntry` via [`NeighborEntry::new`] rather than a
/// struct literal — see ARCHITECTURE.md's note on model extensibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NeighborEntry {
    /// This entry's identity.
    pub id: NeighborId,
    /// The OS-level interface index this entry was observed on, the same raw
    /// value `Interface::index`/`Route::interface_index` carry.
    pub interface_index: u32,
    /// The neighbor's IP address.
    pub address: IpAddress,
    /// Absent for an entry still being resolved (`NeighborState::Incomplete`)
    /// or one the platform reports without a link-layer address at all.
    pub mac: Option<MacAddress>,
    /// The entry's reachability state.
    pub state: NeighborState,
}

impl NeighborEntry {
    /// Creates a neighbor entry with no MAC address and an unknown
    /// reachability state.
    pub fn new(id: NeighborId, interface_index: u32, address: IpAddress) -> Self {
        Self {
            id,
            interface_index,
            address,
            mac: None,
            state: NeighborState::Unknown,
        }
    }

    /// Sets the resolved link-layer (MAC) address.
    pub fn with_mac(mut self, mac: MacAddress) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Sets the observed reachability state.
    pub fn with_state(mut self, state: NeighborState) -> Self {
        self.state = state;
        self
    }
}

/// Intent to add or remove a static ARP/NDP neighbor entry.
///
/// This is intentionally distinct from [`NeighborEntry`]: a static neighbor
/// request carries neither a [`NeighborId`] (that identifier is synthesized
/// from an OS-observed interface index and address, and no native API
/// accepts it back as input) nor a [`NeighborState`] (state is reported by
/// the OS, not chosen by the caller). Identity for facade-level matching is
/// `(interface_id, address)` — this is narrower than the derived
/// `PartialEq`/`Eq`/`Hash`, which also compares `mac`: two `StaticNeighbor`
/// values with the same `(interface_id, address)` but different `mac` share
/// the same identity/match key yet are *not* equal, because `mac` is desired
/// intent (a replacement request for the mapping), not part of what
/// identifies the entry. See
/// `static_neighbor_identity_is_interface_and_address` below for the
/// behavior this produces. `mac` is required, not optional, because this
/// stage only creates static L2 mappings; a caller cannot request an
/// incomplete or dynamically resolved entry through this type.
///
/// `#[non_exhaustive]`: platform-specific static-neighbor fields (for
/// example a router flag or IPv6 lifetime) may be added later without
/// breaking callers who construct a `StaticNeighbor` via
/// [`StaticNeighbor::new`] rather than a struct literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StaticNeighbor {
    /// The interface this static entry applies to.
    pub interface_id: crate::interface::InterfaceId,
    /// The IP address resolved by this static entry.
    pub address: IpAddress,
    /// The link-layer address the static entry maps to.
    pub mac: MacAddress,
}

impl StaticNeighbor {
    /// Creates a static neighbor request mapping `address` on `interface_id`
    /// to `mac`.
    pub fn new(
        interface_id: crate::interface::InterfaceId,
        address: IpAddress,
        mac: MacAddress,
    ) -> Self {
        Self {
            interface_id,
            address,
            mac,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{Ipv4Address, Ipv6Address};

    #[test]
    fn new_entry_has_no_mac_and_unknown_state() {
        let entry = NeighborEntry::new(
            NeighborId::new(1),
            1,
            IpAddress::from(Ipv4Address::new(192, 168, 1, 1)),
        );
        assert!(entry.mac.is_none());
        assert_eq!(entry.state, NeighborState::Unknown);
    }

    #[test]
    fn builder_methods_set_optional_fields() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let entry = NeighborEntry::new(
            NeighborId::new(1),
            1,
            IpAddress::from(Ipv4Address::new(192, 168, 1, 1)),
        )
        .with_mac(mac)
        .with_state(NeighborState::Reachable);
        assert_eq!(entry.mac, Some(mac));
        assert_eq!(entry.state, NeighborState::Reachable);
    }

    #[test]
    fn ipv6_ndp_entry_preserves_observed_identity_and_state() {
        let id = NeighborId::new(0x16);
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x16]);
        let address = IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1]));

        let entry = NeighborEntry::new(id, 7, address)
            .with_mac(mac)
            .with_state(NeighborState::Reachable);

        assert_eq!(entry.id, id);
        assert_eq!(entry.interface_index, 7);
        assert_eq!(entry.address, address);
        assert_eq!(entry.mac, Some(mac));
        assert_eq!(entry.state, NeighborState::Reachable);
    }

    #[test]
    fn static_neighbor_requires_a_mac_and_carries_no_id_or_state() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let address = IpAddress::from(Ipv4Address::new(192, 168, 1, 2));
        let neighbor = StaticNeighbor::new(crate::interface::InterfaceId::new(3), address, mac);

        assert_eq!(neighbor.interface_id, crate::interface::InterfaceId::new(3));
        assert_eq!(neighbor.address, address);
        assert_eq!(neighbor.mac, mac);
    }

    #[test]
    fn static_neighbor_identity_is_interface_and_address() {
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]);
        let address = IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]));
        let a = StaticNeighbor::new(crate::interface::InterfaceId::new(1), address, mac);
        let b = StaticNeighbor::new(
            crate::interface::InterfaceId::new(1),
            address,
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x04]),
        );

        // Same identity, different mac: not equal because mac is part of the
        // desired intent (a replacement request), but interface_id/address
        // match.
        assert_ne!(a, b);
        assert_eq!(a.interface_id, b.interface_id);
        assert_eq!(a.address, b.address);
    }
}
