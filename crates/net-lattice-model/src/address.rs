use std::fmt;

use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv6Address, Ipv6Network};

/// An IP address of either family.
///
/// Domain objects (routes, interfaces, ...) that need to hold "an IP
/// address, either family" use this instead of picking one family, since
/// most networking state (a gateway, a resolver entry) is not inherently
/// v4- or v6-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddress {
    /// An IPv4 address.
    V4(Ipv4Address),
    /// An IPv6 address.
    V6(Ipv6Address),
}

impl From<Ipv4Address> for IpAddress {
    fn from(value: Ipv4Address) -> Self {
        IpAddress::V4(value)
    }
}

impl From<Ipv6Address> for IpAddress {
    fn from(value: Ipv6Address) -> Self {
        IpAddress::V6(value)
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddress::V4(addr) => write!(f, "{addr}"),
            IpAddress::V6(addr) => write!(f, "{addr}"),
        }
    }
}

/// An IP network of either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// An IPv4 network.
    V4(Ipv4Network),
    /// An IPv6 network.
    V6(Ipv6Network),
}

impl From<Ipv4Network> for Network {
    fn from(value: Ipv4Network) -> Self {
        Network::V4(value)
    }
}

impl From<Ipv6Network> for Network {
    fn from(value: Ipv6Network) -> Self {
        Network::V6(value)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::V4(net) => write!(f, "{net}"),
            Network::V6(net) => write!(f, "{net}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_lattice_ip::{Ipv4PrefixLength, Ipv6PrefixLength};

    #[test]
    fn addresses_display_both_families() {
        assert_eq!(
            IpAddress::from(Ipv4Address::new(192, 0, 2, 1)).to_string(),
            "192.0.2.1"
        );
        assert_eq!(
            IpAddress::from(Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])).to_string(),
            "2001:db8::1"
        );
    }

    #[test]
    fn networks_display_both_families() {
        assert_eq!(
            Network::from(Ipv4Network::new(
                Ipv4Address::new(192, 0, 2, 0),
                Ipv4PrefixLength::new(24).expect("valid prefix"),
            ))
            .to_string(),
            "192.0.2.0/24"
        );
        assert_eq!(
            Network::from(Ipv6Network::new(
                Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]),
                Ipv6PrefixLength::new(32).expect("valid prefix"),
            ))
            .to_string(),
            "2001:db8::/32"
        );
    }
}
