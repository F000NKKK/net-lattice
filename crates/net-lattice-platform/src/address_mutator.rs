use net_lattice_core::Result;

/// Assigns and removes IP addresses on network interfaces.
///
/// Mutation is deliberately separate from [`crate::AddressProvider`]: listing
/// is normally unprivileged, while changing an address requires
/// `CAP_NET_ADMIN`, an elevated Windows token, or root on BSD/macOS. The
/// associated input and output types are distinct because an OS-observed
/// address has an ID and derived attributes that are not caller intent.
pub trait AddressMutator {
    /// Caller-authored intent for the address to assign.
    type NewInterfaceAddress;
    /// The backend's observed address record.
    type InterfaceAddress;

    /// Assigns an address and returns the canonical record observed from the
    /// backend after creation.
    fn add_address(&self, address: Self::NewInterfaceAddress) -> Result<Self::InterfaceAddress>;

    /// Removes the address identified by the observed record.
    fn remove_address(&self, address: Self::InterfaceAddress) -> Result<()>;
}
