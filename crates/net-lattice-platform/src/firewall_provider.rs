use net_lattice_core::Result;

/// Lists the rules in this crate's own managed native-firewall policy.
///
/// Generic over an associated `FirewallRule` type rather than naming
/// `net_lattice_model::firewall::FirewallRule` directly — `net-lattice-platform`
/// does not depend on `net-lattice-model` (see ARCHITECTURE.md). The facade
/// crate (`lattice`) is what constrains `FirewallRule` to the concrete model
/// type.
///
/// This returns only the policy this crate's own managed native-firewall
/// table/sublayer/anchor currently holds — never the system's entire
/// firewall ruleset, which may contain rules from other tools this crate has
/// no contract with.
///
/// Mutation is deliberately separate, in [`crate::FirewallMutator`]: listing
/// is normally unprivileged, while replacing the managed policy requires
/// `CAP_NET_ADMIN`, an elevated Windows token, or root on BSD/macOS — the
/// same read/write split used by [`crate::RouteProvider`]/
/// [`crate::RouteMutator`] and its siblings.
pub trait FirewallProvider {
    /// The backend's observed firewall-rule record.
    type FirewallRule;

    /// Returns every rule in this crate's own managed native-firewall
    /// policy, in evaluation order.
    fn firewall_rules(&self) -> Result<Vec<Self::FirewallRule>>;
}
