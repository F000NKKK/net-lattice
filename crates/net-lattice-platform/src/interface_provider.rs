use net_lattice_core::Result;

/// Lists network interfaces.
///
/// Generic over an associated `Interface` type rather than naming
/// `net_lattice_model::interface::Interface` directly — `net-lattice-platform`
/// does not depend on `net-lattice-model` (see ARCHITECTURE.md). The facade
/// crate (`net-lattice`) is what constrains `Interface` to the concrete model
/// type.
///
/// This trait is read-only. See [`InterfaceMutator`](crate::InterfaceMutator)
/// for the complementary administrative-state and MTU configuration contract.
pub trait InterfaceProvider {
    /// The backend's observed interface record.
    type Interface;

    /// Returns every network interface currently observed on the system.
    fn interfaces(&self) -> Result<Vec<Self::Interface>>;
}
