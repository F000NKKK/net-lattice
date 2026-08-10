use net_lattice_core::Id;

use crate::IpAddress;
use crate::address::Network;
use crate::interface::InterfaceId;
use net_lattice_ip::Ipv4Address;

/// Identifies an [`InterfaceAddress`].
pub type InterfaceAddressId = Id<InterfaceAddress>;

/// Intent to assign an IP address to an interface.
///
/// This is intentionally distinct from [`InterfaceAddress`]: callers do not
/// manufacture an `InterfaceAddressId`, and the backend may report derived
/// attributes after creation. `broadcast` is meaningful only for IPv4; when
/// omitted, the platform selects its normal broadcast behaviour. Point-to-
/// point peers, lifetimes, scope, and platform-specific flags are reserved
/// for a future extension rather than silently guessed here.
///
/// Identity for facade-level matching is `(interface_id, address)` — the
/// same natural key [`crate::diff::Diff::addresses`] uses to match requested
/// address intents against observed [`InterfaceAddress`] entries.
/// `broadcast` is not part of the key: it is a value carried alongside the
/// identity, not a distinguishing field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NewInterfaceAddress {
    /// The interface receiving the address.
    pub interface_id: InterfaceId,
    /// The requested address and prefix length.
    pub address: Network,
    /// An optional explicit IPv4 broadcast address.
    pub broadcast: Option<Ipv4Address>,
}

impl NewInterfaceAddress {
    /// Creates an address-assignment intent with no explicit broadcast
    /// address requested.
    pub fn new(interface_id: InterfaceId, address: Network) -> Self {
        Self {
            interface_id,
            address,
            broadcast: None,
        }
    }

    /// Requests an explicit IPv4 broadcast address.
    pub fn with_broadcast(mut self, broadcast: Ipv4Address) -> Self {
        self.broadcast = Some(broadcast);
        self
    }
}

/// An IP address assigned to a network interface, plus the prefix length it
/// was assigned with (e.g. `192.168.1.10/24`).
///
/// Named `ifaddr`, not `address`, to avoid colliding with the `address`
/// module's `IpAddress`/`Network` primitives — this is a distinct domain
/// concept (an address *bound to an interface*), not another address
/// representation.
///
/// `#[non_exhaustive]`: platforms carry different address fields (Linux
/// exposes address `scope` and lifetime/deprecation timers via
/// `IFA_CACHEINFO`; Windows exposes per-address `DadState`/`SkipAsSource`;
/// BSD/macOS expose a combined flags word). Marking this non-exhaustive now
/// means adding platform-specific fields later is not a breaking change for
/// consumers who construct an `InterfaceAddress` via
/// [`InterfaceAddress::new`] rather than a struct literal — see
/// ARCHITECTURE.md's note on model extensibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct InterfaceAddress {
    pub id: InterfaceAddressId,
    /// The OS-level interface index this address is assigned to, the same
    /// raw value `Interface::index`/`Route::interface_index` carry.
    pub interface_index: u32,
    /// The assigned address and the prefix length it carries.
    pub address: Network,
    /// The IPv4 broadcast address for this subnet, if the platform reports
    /// one. Always `None` for IPv6, which has no broadcast concept.
    pub broadcast: Option<IpAddress>,
}

impl InterfaceAddress {
    /// Creates an observed interface address with no broadcast address set.
    pub fn new(id: InterfaceAddressId, interface_index: u32, address: Network) -> Self {
        Self {
            id,
            interface_index,
            address,
            broadcast: None,
        }
    }

    /// Sets the observed IPv4 broadcast address.
    pub fn with_broadcast(mut self, broadcast: IpAddress) -> Self {
        self.broadcast = Some(broadcast);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{
        Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
    };

    fn sample_network() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(192, 168, 1, 10),
            Ipv4PrefixLength::new(24).unwrap(),
        ))
    }

    #[test]
    fn new_address_has_no_broadcast() {
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, sample_network());
        assert!(addr.broadcast.is_none());
    }

    #[test]
    fn with_broadcast_sets_the_field() {
        let broadcast = IpAddress::from(Ipv4Address::new(192, 168, 1, 255));
        let addr = InterfaceAddress::new(InterfaceAddressId::new(1), 1, sample_network())
            .with_broadcast(broadcast);
        assert_eq!(addr.broadcast, Some(broadcast));
    }

    #[test]
    fn new_address_intent_keeps_interface_identity_separate_from_output_id() {
        let intent = NewInterfaceAddress::new(InterfaceId::new(7), sample_network())
            .with_broadcast(Ipv4Address::new(192, 168, 1, 255));
        assert_eq!(intent.interface_id, InterfaceId::new(7));
        assert_eq!(intent.broadcast, Some(Ipv4Address::new(192, 168, 1, 255)));
    }

    #[test]
    fn ipv6_address_intent_and_observation_keep_a_64_prefix_without_broadcast() {
        let network = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 7]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let intent = NewInterfaceAddress::new(InterfaceId::new(7), network);
        let observed = InterfaceAddress::new(InterfaceAddressId::new(7), 7, network);

        assert_eq!(intent.address, network);
        assert!(intent.broadcast.is_none());
        assert_eq!(observed.address, network);
        assert!(observed.broadcast.is_none());
    }
}
