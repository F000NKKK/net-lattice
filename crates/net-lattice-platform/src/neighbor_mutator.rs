use net_lattice_core::Result;

/// Adds and removes static ARP/NDP neighbor entries.
///
/// Mutation is deliberately separate from [`crate::NeighborProvider`]:
/// listing observed entries is normally unprivileged, while adding or
/// removing a static entry requires `CAP_NET_ADMIN`, an elevated Windows
/// token, or root on BSD/macOS. The associated input and output types are
/// distinct because an OS-observed neighbor entry has a synthesized ID and
/// reported reachability state that are not caller intent.
///
/// `remove_static_neighbor` must reject a target that is not presently a
/// permanent (static) entry rather than silently deleting dynamically
/// learned ARP/NDP state; see ADR-0001 for the full rationale.
pub trait NeighborMutator {
    /// Caller-authored intent for the static neighbor entry.
    type StaticNeighbor;
    /// The backend's observed neighbor entry record.
    type NeighborEntry;

    /// Adds a static neighbor entry and returns the observed record read
    /// back from the backend after creation.
    fn add_static_neighbor(&self, neighbor: Self::StaticNeighbor) -> Result<Self::NeighborEntry>;

    /// Removes the static neighbor entry matching `neighbor`.
    fn remove_static_neighbor(&self, neighbor: Self::StaticNeighbor) -> Result<()>;
}
