use net_lattice_core::Result;

/// Lists IP addresses assigned to network interfaces.
///
/// Generic over an associated `InterfaceAddress` type rather than naming
/// `net_lattice_model::ifaddr::InterfaceAddress` directly —
/// `net-lattice-platform` does not depend on `net-lattice-model` (see
/// ARCHITECTURE.md). The facade crate (`net-lattice`) is what constrains
/// `InterfaceAddress` to the concrete model type.
///
/// Read-only for now, like [`InterfaceProvider`](crate::InterfaceProvider),
/// [`DnsProvider`](crate::DnsProvider), and
/// [`NeighborProvider`](crate::NeighborProvider): adding/removing addresses
/// is a separate concern deferred to a later stage.
pub trait AddressProvider {
    /// The backend's observed interface-address record.
    type InterfaceAddress;

    /// Returns every interface address currently observed on the system.
    fn addresses(&self) -> Result<Vec<Self::InterfaceAddress>>;
}
