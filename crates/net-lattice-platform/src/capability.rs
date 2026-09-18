bitflags::bitflags! {
    /// Runtime-dependent operating system features that cannot be expressed
    /// through Rust trait implementation alone.
    ///
    /// Distinct from provider traits: a backend either implements
    /// `RouteProvider` or it doesn't, and that's fixed at compile time.
    /// Whether the *running* kernel has, say, VRF support enabled is a fact
    /// about the current machine, not the crate — see ARCHITECTURE.md's
    /// `net-lattice-platform` section.
    ///
    /// Capabilities describe the backend's view when queried; callers should
    /// still handle operation errors because permissions or system
    /// configuration may change later. Use the capability for the event
    /// domain a watcher selects; [`Capability::MONITORING`] is the aggregate
    /// that means every currently modeled event domain is deliverable.
    /// For example:
    ///
    /// ```ignore
    /// if lattice.supports(Capability::ROUTE_MONITORING) {
    ///     let watcher = lattice.watch_filtered(EventFilter::none().routes())?;
    /// }
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Capability: u64 {
        /// The backend supports IPv6 for this domain.
        const IPV6 = 1 << 0;
        /// The backend supports VRF (virtual routing and forwarding).
        const VRF = 1 << 1;
        /// The backend supports network namespaces.
        const NAMESPACES = 1 << 2;
        /// The backend delivers native route-change notifications.
        const ROUTE_MONITORING = 1 << 3;
        /// The backend can replace resolver configuration through a supported
        /// operating-system mechanism.
        const DNS_MUTATION = 1 << 4;
        /// The backend can request an interface's administrative up/down
        /// state through a supported operating-system mechanism.
        ///
        /// This is a feature gate, not proof that the current process has the
        /// privilege or policy permission to change the interface.
        const INTERFACE_ADMIN_STATE = 1 << 5;
        /// The backend can request an interface MTU through a supported
        /// operating-system mechanism.
        ///
        /// This is a feature gate, not proof that the current process has the
        /// privilege or policy permission to change the interface.
        const INTERFACE_MTU = 1 << 6;
        /// The backend delivers native interface-change notifications.
        const INTERFACE_MONITORING = 1 << 7;
        /// The backend delivers native neighbor-table change notifications.
        const NEIGHBOR_MONITORING = 1 << 8;
        /// The backend delivers native interface-address change notifications.
        const ADDRESS_MONITORING = 1 << 9;
        /// The backend can add and remove static ARP/NDP neighbor entries
        /// through a supported operating-system mechanism.
        ///
        /// This is a feature gate, not proof that the current process has the
        /// privilege or policy permission to change a neighbor entry.
        const NEIGHBOR_MUTATION = 1 << 10;
        /// The backend can add and remove routes through a supported
        /// operating-system mechanism.
        ///
        /// This is a feature gate, not proof that the current process has the
        /// privilege or policy permission to change a route.
        const ROUTE_MUTATION = 1 << 11;
        /// Every currently modeled event domain is deliverable by the
        /// backend. This is the capability required by an all-domain
        /// [`EventProvider::watch`](crate::EventProvider::watch) request.
        const MONITORING = Self::ROUTE_MONITORING.bits()
            | Self::INTERFACE_MONITORING.bits()
            | Self::NEIGHBOR_MONITORING.bits()
            | Self::ADDRESS_MONITORING.bits();
    }
}

/// Reports which runtime-dependent [`Capability`] flags the connected
/// backend currently has available.
///
/// Every backend implements this (it costs nothing when there's nothing to
/// report — an empty flag set is a valid answer), which is why `capabilities`
/// returns a bare `Capability` rather than `Result<Capability>`: unlike the
/// other provider traits, there is no OS call here that can fail in a way
/// worth surfacing to the caller. `addresses`-style methods that really do
/// call into the OS keep returning `Result`.
pub trait CapabilityProvider {
    /// Returns the runtime-dependent capabilities the connected backend
    /// currently has available.
    fn capabilities(&self) -> Capability;
}

#[cfg(test)]
mod tests {
    use super::Capability;

    #[test]
    fn interface_configuration_capabilities_are_distinct_feature_gates() {
        assert_ne!(
            Capability::INTERFACE_ADMIN_STATE.bits(),
            Capability::INTERFACE_MTU.bits()
        );
        assert!(!Capability::INTERFACE_ADMIN_STATE.contains(Capability::INTERFACE_MTU));
    }

    #[test]
    fn monitoring_aggregate_requires_every_event_domain() {
        let partial = Capability::ROUTE_MONITORING
            | Capability::INTERFACE_MONITORING
            | Capability::ADDRESS_MONITORING;
        assert!(!partial.contains(Capability::MONITORING));
        assert!((partial | Capability::NEIGHBOR_MONITORING).contains(Capability::MONITORING));
    }

    #[test]
    fn neighbor_mutation_is_a_distinct_bit_outside_the_monitoring_aggregate() {
        assert_ne!(
            Capability::NEIGHBOR_MUTATION.bits(),
            Capability::NEIGHBOR_MONITORING.bits()
        );
        assert!(!Capability::MONITORING.contains(Capability::NEIGHBOR_MUTATION));
        assert!(!Capability::NEIGHBOR_MUTATION.contains(Capability::NEIGHBOR_MONITORING));
    }

    #[test]
    fn route_mutation_is_a_distinct_bit_outside_the_monitoring_aggregate() {
        assert_ne!(
            Capability::ROUTE_MUTATION.bits(),
            Capability::ROUTE_MONITORING.bits()
        );
        assert!(!Capability::MONITORING.contains(Capability::ROUTE_MUTATION));
        assert!(!Capability::ROUTE_MUTATION.contains(Capability::ROUTE_MONITORING));
    }
}
