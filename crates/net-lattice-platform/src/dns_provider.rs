use net_lattice_core::Result;

/// Reads the system's current DNS resolver configuration.
///
/// Generic over an associated `DnsConfig` type rather than naming
/// `net_lattice_model::dns::DnsConfig` directly — `net-lattice-platform`
/// does not depend on `net-lattice-model` (see ARCHITECTURE.md). The facade
/// crate (`net-lattice`) is what constrains `DnsConfig` to the concrete
/// model type.
///
/// See [`DnsMutator`](crate::DnsMutator) for the complementary mutation
/// contract. Together these traits form the official DNS extension API for
/// third-party backends.
pub trait DnsProvider {
    /// The backend's observed resolver configuration record.
    type DnsConfig;

    /// Returns the system's current resolver configuration.
    fn dns_config(&self) -> Result<Self::DnsConfig>;
}
