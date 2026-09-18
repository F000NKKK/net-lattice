use net_lattice_core::Result;

/// Lists neighbor table entries (ARP for IPv4, NDP for IPv6).
///
/// Generic over an associated `NeighborEntry` type rather than naming
/// `net_lattice_model::neighbor::NeighborEntry` directly — `net-lattice-platform`
/// does not depend on `net-lattice-model` (see ARCHITECTURE.md). The facade
/// crate (`net-lattice`) is what constrains `NeighborEntry` to the concrete
/// model type.
///
/// Read-only for now, like [`InterfaceProvider`](crate::InterfaceProvider) and
/// [`DnsProvider`](crate::DnsProvider): adding/removing static neighbor
/// entries is a separate concern deferred to a later stage.
pub trait NeighborProvider {
    /// The backend's observed neighbor entry record.
    type NeighborEntry;

    /// Returns every neighbor table entry currently observed on the system.
    fn neighbors(&self) -> Result<Vec<Self::NeighborEntry>>;
}
