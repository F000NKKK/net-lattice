use crate::IpAddress;

/// The resolver configuration observed through the active platform backend.
///
/// This is an observed resolver view, not a promise of complete persistent or
/// per-interface DNS state. For example, Unix backends currently read the
/// active resolver file, while Windows collects adapter-provided resolver
/// data. Server and search-domain order is preserved as reported by the
/// backend.
///
/// `#[non_exhaustive]`: platforms surface DNS configuration differently
/// (a flat `/etc/resolv.conf` on Linux/BSD/macOS vs. per-adapter DNS server
/// lists plus a global suffix on Windows) — this carries the subset that
/// maps cleanly across all of them. Marking it non-exhaustive now means
/// adding platform-specific fields later (e.g. per-interface resolvers) is
/// not a breaking change for consumers who construct a `DnsConfig` via
/// [`DnsConfig::new`] rather than a struct literal — see ARCHITECTURE.md's
/// note on model extensibility.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DnsConfig {
    /// Nameserver addresses, in resolution order.
    pub nameservers: Vec<IpAddress>,
    /// Search-list domains appended to unqualified lookups, in order.
    pub search_domains: Vec<String>,
}

impl DnsConfig {
    /// Returns an empty `DnsConfig` with no nameservers or search domains.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Desired system resolver configuration.
///
/// This input model intentionally does not include backend-observed metadata:
/// callers state the resolver servers and search domains they want, and a
/// successful mutation returns the resulting observed [`DnsConfig`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NewDnsConfig {
    /// Nameserver addresses, in resolution order.
    pub nameservers: Vec<IpAddress>,
    /// Search-list domains appended to unqualified lookups, in order.
    pub search_domains: Vec<String>,
}

impl NewDnsConfig {
    /// Creates an empty resolver configuration.
    ///
    /// An empty configuration requests removal of explicitly configured
    /// nameservers and search domains where the platform supports it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a desired resolver configuration from ordered servers and
    /// search domains.
    pub fn with(nameservers: Vec<IpAddress>, search_domains: Vec<String>) -> Self {
        Self {
            nameservers,
            search_domains,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{Ipv4Address, Ipv6Address};

    #[test]
    fn new_config_has_no_entries() {
        let config = DnsConfig::new();
        assert!(config.nameservers.is_empty());
        assert!(config.search_domains.is_empty());
    }

    #[test]
    fn config_carries_nameservers_and_search_domains() {
        let config = DnsConfig {
            nameservers: vec![IpAddress::V4(Ipv4Address::new(1, 1, 1, 1))],
            search_domains: vec!["example.com".to_string()],
        };
        assert_eq!(config.nameservers.len(), 1);
        assert_eq!(config.search_domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn new_desired_config_has_no_entries() {
        let config = NewDnsConfig::new();
        assert!(config.nameservers.is_empty());
        assert!(config.search_domains.is_empty());
    }

    #[test]
    fn desired_config_constructor_preserves_entries() {
        let config = NewDnsConfig::with(
            vec![IpAddress::V4(Ipv4Address::new(9, 9, 9, 9))],
            vec!["example.test".to_string()],
        );
        assert_eq!(config.nameservers.len(), 1);
        assert_eq!(config.search_domains, ["example.test"]);
    }

    #[test]
    fn mixed_family_config_preserves_order_and_values() {
        let config = NewDnsConfig::with(
            vec![
                IpAddress::from(Ipv4Address::new(1, 1, 1, 1)),
                IpAddress::from(Ipv6Address::new([
                    0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
                ])),
                IpAddress::from(Ipv4Address::new(8, 8, 8, 8)),
            ],
            vec!["example.test".to_string()],
        );

        assert_eq!(config.nameservers.len(), 3);
        assert_eq!(
            config.nameservers[0],
            IpAddress::from(Ipv4Address::new(1, 1, 1, 1))
        );
        assert_eq!(
            config.nameservers[1],
            IpAddress::from(Ipv6Address::new([
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
            ]))
        );
        assert_eq!(
            config.nameservers[2],
            IpAddress::from(Ipv4Address::new(8, 8, 8, 8))
        );
        assert_eq!(config.search_domains, ["example.test"]);
    }
}
