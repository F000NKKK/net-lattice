use net_lattice_core::Id;

use crate::address::{IpAddress, Network};

/// A single routing table entry.
///
/// `#[non_exhaustive]`: platforms carry different route fields (Linux adds
/// table/protocol/scope/type on top of destination/gateway/metric; Windows
/// and BSD expose a narrower set — see ARCHITECTURE.md's note on model
/// extensibility). Marking this non-exhaustive now means adding
/// platform-specific fields later is not a breaking change for consumers
/// who construct a `Route` via [`Route::new`] rather than a struct literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Route {
    pub id: RouteId,
    pub destination: Network,
    pub gateway: Option<IpAddress>,
    pub metric: Option<u32>,
    /// The outgoing interface, identified by its raw OS-level index.
    ///
    /// This is a raw `u32` rather than a typed `InterfaceId` because the
    /// `interface` domain module doesn't exist yet (it lands in Stage 0.4
    /// per ARCHITECTURE.md's Incremental Delivery Plan) — `Route` shouldn't
    /// block on it just to express what the kernel already gives us
    /// directly. Many routes are ambiguous or outright rejected by the
    /// kernel without an explicit output interface (on-link routes,
    /// multiple interfaces on the same subnet), so this isn't optional
    /// polish: without it, a meaningful fraction of real routes can't be
    /// added at all.
    pub interface_index: Option<u32>,
}

/// Identifies a [`Route`].
pub type RouteId = Id<Route>;

impl Route {
    /// Creates a route with no gateway, metric, or outgoing interface set.
    pub fn new(id: RouteId, destination: Network) -> Self {
        Self {
            id,
            destination,
            gateway: None,
            metric: None,
            interface_index: None,
        }
    }

    /// Sets the next-hop gateway address.
    pub fn with_gateway(mut self, gateway: IpAddress) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Sets the route metric.
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Sets the outgoing interface's raw OS-level index.
    pub fn with_interface_index(mut self, interface_index: u32) -> Self {
        self.interface_index = Some(interface_index);
        self
    }
}

/// Intent to add or remove a route.
///
/// This is intentionally distinct from [`Route`]: a route mutation request
/// carries no [`RouteId`] (that identifier is backend-synthesized — a hash
/// of observed fields on Windows/Darwin, a kernel-issued netlink handle on
/// Linux — and no native API accepts it back as mutation input), mirroring
/// how [`crate::neighbor::StaticNeighbor`] excludes
/// [`crate::neighbor::NeighborId`]. Every backend's add/remove call consumes
/// a full route description rather than a sparse patch, so this is a
/// full-value intent type like `StaticNeighbor`, not a partial-patch type
/// like `InterfaceConfig`. Identity for facade-level matching is
/// `destination + gateway + metric + interface_index` — here identity and
/// derived value equality (`PartialEq`/`Eq`/`Hash`) coincide: every field
/// that makes up the struct is also part of the identity/match key, unlike
/// [`crate::neighbor::StaticNeighbor`], where `mac` is excluded from
/// identity but still compared by the derived equality.
///
/// `#[non_exhaustive]`: platform-specific route-intent fields may be added
/// later without breaking callers who construct a `RouteConfig` via
/// [`RouteConfig::new`] rather than a struct literal, matching [`Route`]'s
/// own non-exhaustive rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RouteConfig {
    pub destination: Network,
    pub gateway: Option<IpAddress>,
    /// Requested route metric. Honored on Linux and Windows. **Not
    /// supported on Darwin**: no native call reads or writes route metric
    /// on macOS/BSD (`Route::metric` observed from a Darwin backend is
    /// always `None` too, a pre-existing platform gap this type does not
    /// introduce). A caller-supplied value is silently ignored on Darwin
    /// rather than rejected, matching every other documented cross-platform
    /// field gap in this crate (see [`Route::interface_index`]'s doc
    /// comment for the same pattern).
    pub metric: Option<u32>,
    pub interface_index: Option<u32>,
}

impl RouteConfig {
    /// Creates a route intent with no gateway, metric, or outgoing interface
    /// requested.
    pub fn new(destination: Network) -> Self {
        Self {
            destination,
            gateway: None,
            metric: None,
            interface_index: None,
        }
    }

    /// Requests a next-hop gateway address.
    pub fn with_gateway(mut self, gateway: IpAddress) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Requests a route metric.
    pub fn with_metric(mut self, metric: u32) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Requests an outgoing interface, identified by its raw OS-level index.
    pub fn with_interface_index(mut self, interface_index: u32) -> Self {
        self.interface_index = Some(interface_index);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{
        Ipv4Address, Ipv4Network, Ipv4PrefixLength, Ipv6Address, Ipv6Network, Ipv6PrefixLength,
    };

    fn destination() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(10, 0, 0, 0),
            Ipv4PrefixLength::new(24).unwrap(),
        ))
    }

    #[test]
    fn new_route_has_no_gateway_or_metric() {
        let route = Route::new(RouteId::new(1), destination());
        assert!(route.gateway.is_none());
        assert!(route.metric.is_none());
    }

    #[test]
    fn builder_methods_set_optional_fields() {
        let gateway = IpAddress::from(Ipv4Address::new(10, 0, 0, 1));
        let route = Route::new(RouteId::new(1), destination())
            .with_gateway(gateway)
            .with_metric(100)
            .with_interface_index(2);
        assert_eq!(route.gateway, Some(gateway));
        assert_eq!(route.metric, Some(100));
        assert_eq!(route.interface_index, Some(2));
    }

    #[test]
    fn builder_methods_preserve_ipv6_route_fields() {
        let destination = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let gateway = IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1]));

        let route = Route::new(RouteId::new(16), destination)
            .with_gateway(gateway)
            .with_metric(42)
            .with_interface_index(7);

        assert_eq!(route.destination, destination);
        assert_eq!(route.gateway, Some(gateway));
        assert_eq!(route.metric, Some(42));
        assert_eq!(route.interface_index, Some(7));
    }

    #[test]
    fn new_route_config_has_no_gateway_or_metric() {
        let config = RouteConfig::new(destination());
        assert!(config.gateway.is_none());
        assert!(config.metric.is_none());
        assert!(config.interface_index.is_none());
    }

    #[test]
    fn route_config_builder_methods_set_optional_fields() {
        let gateway = IpAddress::from(Ipv4Address::new(10, 0, 0, 1));
        let config = RouteConfig::new(destination())
            .with_gateway(gateway)
            .with_metric(100)
            .with_interface_index(2);
        assert_eq!(config.gateway, Some(gateway));
        assert_eq!(config.metric, Some(100));
        assert_eq!(config.interface_index, Some(2));
    }

    #[test]
    fn route_config_builder_methods_preserve_ipv6_fields() {
        let destination = Network::from(Ipv6Network::new(
            Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 0]),
            Ipv6PrefixLength::new(64).expect("valid IPv6 prefix"),
        ));
        let gateway = IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0x16, 0, 0, 0, 1]));

        let config = RouteConfig::new(destination)
            .with_gateway(gateway)
            .with_metric(42)
            .with_interface_index(7);

        assert_eq!(config.destination, destination);
        assert_eq!(config.gateway, Some(gateway));
        assert_eq!(config.metric, Some(42));
        assert_eq!(config.interface_index, Some(7));
    }

    #[test]
    fn route_config_equality_compares_all_four_fields() {
        let gateway = IpAddress::from(Ipv4Address::new(10, 0, 0, 1));
        let a = RouteConfig::new(destination())
            .with_gateway(gateway)
            .with_metric(10)
            .with_interface_index(1);
        let b = RouteConfig::new(destination())
            .with_gateway(gateway)
            .with_metric(10)
            .with_interface_index(1);
        let different_metric = a.with_metric(20);

        assert_eq!(a, b);
        assert_ne!(a, different_metric);
    }

    #[test]
    fn route_config_carries_no_route_id() {
        // RouteConfig has no `id` field at all: constructing it does not
        // require (and cannot accept) a RouteId, unlike Route::new.
        let config = RouteConfig::new(destination());
        assert_eq!(config.destination, destination());
    }
}
