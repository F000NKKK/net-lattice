use crate::address::Network;

/// Which side of a connection a [`FirewallRule`] matches.
///
/// Mirrors the native hook points every supported platform exposes: Linux
/// nftables' `input`/`output` chain hooks, Windows WFP's
/// `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`/`FWPM_LAYER_ALE_AUTH_CONNECT_V4`
/// layers, and macOS pf's `in`/`out` keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Direction {
    /// Matches inbound traffic (arriving at this host).
    Inbound,
    /// Matches outbound traffic (leaving this host).
    Outbound,
}

/// The terminating action a matching [`FirewallRule`] applies.
///
/// There is no `Reject`-with-response variant in this domain's current
/// scope: callers needing only a silent drop versus an explicit allow (the
/// common case for policy replacement) are fully served by these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verdict {
    /// Permit the matching traffic.
    Allow,
    /// Silently drop the matching traffic.
    Deny,
}

/// The transport-layer protocol a [`FirewallRule`] matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP (IPv4) or ICMPv6.
    Icmp,
}

/// An inclusive range of transport-layer ports, `start..=end`.
///
/// A single port is expressed as a range whose `start` equals its `end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    /// The first port in the range, inclusive.
    pub start: u16,
    /// The last port in the range, inclusive.
    pub end: u16,
}

impl PortRange {
    /// Creates a range covering exactly one port.
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Creates an inclusive port range.
    ///
    /// `start` and `end` are taken as given, including the degenerate case
    /// `start > end`; callers that need range validation should check
    /// `start <= end` themselves before constructing one.
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }
}

/// A single native-firewall rule: a packet match plus a terminating
/// [`Verdict`].
///
/// `#[non_exhaustive]`: this is a deliberately minimal model (see
/// ARCHITECTURE.md's Firewall domain notes) — no NAT, connection-tracking,
/// or application-identity matching. Marking it non-exhaustive means
/// growing it later (should a real need for one of those emerge) is not a
/// breaking change for callers who construct a `FirewallRule` via
/// [`FirewallRule::new`] rather than a struct literal, matching every other
/// domain type's non-exhaustive rationale in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FirewallRule {
    /// Which side of a connection this rule matches.
    pub direction: Direction,
    /// The interface this rule is scoped to, by raw OS-level index, if any.
    /// A rule with no interface matches on every interface.
    pub interface_index: Option<u32>,
    /// The remote network to match, if any (source for [`Direction::Inbound`],
    /// destination for [`Direction::Outbound`]). A rule with no remote
    /// network matches every remote address.
    pub remote: Option<Network>,
    /// The transport protocol to match, if any. Required for `port` to have
    /// any effect: a port range without a protocol is not representable
    /// natively on every platform.
    pub protocol: Option<Protocol>,
    /// The remote port range to match, if any. Only meaningful alongside
    /// `protocol` set to [`Protocol::Tcp`] or [`Protocol::Udp`].
    pub port: Option<PortRange>,
    /// The action this rule applies when it matches.
    pub verdict: Verdict,
}

impl FirewallRule {
    /// Creates a rule matching every interface and remote address for
    /// `direction`, applying `verdict`.
    pub const fn new(direction: Direction, verdict: Verdict) -> Self {
        Self {
            direction,
            interface_index: None,
            remote: None,
            protocol: None,
            port: None,
            verdict,
        }
    }

    /// Scopes this rule to one interface, by raw OS-level index.
    pub const fn with_interface_index(mut self, interface_index: u32) -> Self {
        self.interface_index = Some(interface_index);
        self
    }

    /// Scopes this rule to one remote network.
    pub const fn with_remote(mut self, remote: Network) -> Self {
        self.remote = Some(remote);
        self
    }

    /// Scopes this rule to one transport protocol.
    pub const fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Scopes this rule to one remote port range.
    pub const fn with_port(mut self, port: PortRange) -> Self {
        self.port = Some(port);
        self
    }
}

/// An ordered native-firewall policy: [`FirewallRule`]s evaluated in order,
/// first match wins, falling back to `default_verdict` when no rule
/// matches.
///
/// This mirrors the one evaluation semantic common to every supported
/// platform's native model (nftables' sequential rules with a terminating
/// verdict, WFP filters ordered by weight, and pf's `quick` rules), so a
/// caller reasons about one ordering model rather than three.
///
/// `#[non_exhaustive]`: reserves room for policy-level metadata (e.g. a
/// logging toggle) without a breaking change, matching this crate's other
/// non-exhaustive domain types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FirewallPolicy {
    /// The ordered list of rules, evaluated first-match-wins.
    pub rules: Vec<FirewallRule>,
    /// The verdict applied when no rule in `rules` matches.
    pub default_verdict: Verdict,
}

impl FirewallPolicy {
    /// Creates a policy with no rules, applying `default_verdict` to every
    /// packet.
    pub const fn new(default_verdict: Verdict) -> Self {
        Self {
            rules: Vec::new(),
            default_verdict,
        }
    }

    /// Appends one rule to the end of the ordered rule list.
    pub fn with_rule(mut self, rule: FirewallRule) -> Self {
        self.rules.push(rule);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

    fn remote() -> Network {
        Network::from(Ipv4Network::new(
            Ipv4Address::new(10, 0, 0, 0),
            Ipv4PrefixLength::new(24).unwrap(),
        ))
    }

    #[test]
    fn new_rule_matches_everything_on_its_direction() {
        let rule = FirewallRule::new(Direction::Outbound, Verdict::Deny);
        assert!(rule.interface_index.is_none());
        assert!(rule.remote.is_none());
        assert!(rule.protocol.is_none());
        assert!(rule.port.is_none());
        assert_eq!(rule.verdict, Verdict::Deny);
    }

    #[test]
    fn builder_methods_set_optional_fields() {
        let rule = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_interface_index(4)
            .with_remote(remote())
            .with_protocol(Protocol::Udp)
            .with_port(PortRange::single(53));

        assert_eq!(rule.interface_index, Some(4));
        assert_eq!(rule.remote, Some(remote()));
        assert_eq!(rule.protocol, Some(Protocol::Udp));
        assert_eq!(rule.port, Some(PortRange::single(53)));
    }

    #[test]
    fn port_range_single_has_equal_bounds() {
        let port = PortRange::single(443);
        assert_eq!(port.start, 443);
        assert_eq!(port.end, 443);
    }

    #[test]
    fn policy_default_verdict_applies_with_no_rules() {
        let policy = FirewallPolicy::new(Verdict::Deny);
        assert!(policy.rules.is_empty());
        assert_eq!(policy.default_verdict, Verdict::Deny);
    }

    #[test]
    fn policy_with_rule_preserves_insertion_order() {
        let allow_dns = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(PortRange::single(53));
        let deny_rest = FirewallRule::new(Direction::Outbound, Verdict::Deny);

        let policy = FirewallPolicy::new(Verdict::Allow)
            .with_rule(allow_dns)
            .with_rule(deny_rest);

        assert_eq!(policy.rules, vec![allow_dns, deny_rest]);
    }
}
