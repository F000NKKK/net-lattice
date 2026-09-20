use net_lattice_core::Result;

use crate::FirewallProvider;

/// Replaces or clears the native-firewall policy managed by a backend.
///
/// A successful [`set_firewall_policy`](FirewallMutator::set_firewall_policy)
/// call replaces the *entire* managed policy atomically (one netlink
/// transaction on Linux, one WFP transaction on Windows, one ticket-based
/// `pf` ruleset commit on macOS) rather than exposing incremental
/// add/remove-by-id the way [`crate::RouteMutator`] does: a caller wants
/// "this exact policy is in effect now," not to reason about accumulated
/// rule state across native reboots or crashes.
///
/// Every mutation is confined to this crate's own managed native-firewall
/// table/sublayer/anchor. A backend must never read or write firewall state
/// outside that scope — a caller's own rules configured through other tools
/// are never touched.
pub trait FirewallMutator: FirewallProvider {
    /// The desired native-firewall policy accepted by this backend.
    type FirewallPolicy;

    /// Replaces the managed policy with `policy`, atomically.
    ///
    /// A backend must reject (via [`Result::Err`]) a policy it cannot apply
    /// atomically rather than partially applying it.
    fn set_firewall_policy(&self, policy: Self::FirewallPolicy) -> Result<()>;

    /// Removes every rule from the managed policy, leaving it empty.
    ///
    /// This does not remove the managed table/sublayer/anchor itself, only
    /// its rules — a subsequent [`FirewallProvider::firewall_rules`] call
    /// observes an empty list.
    fn clear_firewall_policy(&self) -> Result<()>;
}
