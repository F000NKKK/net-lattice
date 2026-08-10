use std::fmt;

/// A validated IPv4 prefix length (0..=32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4PrefixLength(u8);

impl Ipv4PrefixLength {
    pub const MAX: u8 = 32;

    /// Validates `value` as an IPv4 prefix length, returning `None` when it
    /// exceeds [`Self::MAX`].
    ///
    /// Returns `Option` rather than `Result<Self, net_lattice_core::Error>`
    /// by deliberate convention: this constructor rejects exactly one
    /// self-contained numeric range check with a binary outcome and no
    /// diagnostic value beyond "in range" or "out of range" — `Self::MAX`
    /// already tells the caller everything an `Error` variant could add.
    /// `net-lattice-ip` also has no dependency on `net_lattice_core::Error`,
    /// so introducing one here would invert this crate's leaf position in
    /// the workspace's dependency direction purely to wrap one boolean
    /// check. Contrast with `net_lattice_model::InterfaceConfig::new`,
    /// whose `Result<Self, Error>` return enforces a cross-field
    /// precondition where the specific `Error` variant carries diagnostic
    /// value.
    pub const fn new(value: u8) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for Ipv4PrefixLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A validated IPv6 prefix length (0..=128).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6PrefixLength(u8);

impl Ipv6PrefixLength {
    pub const MAX: u8 = 128;

    /// Validates `value` as an IPv6 prefix length, returning `None` when it
    /// exceeds [`Self::MAX`].
    ///
    /// Returns `Option` rather than `Result<Self, net_lattice_core::Error>`
    /// for the same reason as [`Ipv4PrefixLength::new`]: a single
    /// self-contained range check with no diagnostic value beyond in/out of
    /// range, in a crate with no existing dependency on
    /// `net_lattice_core::Error`.
    pub const fn new(value: u8) -> Option<Self> {
        if value <= Self::MAX {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for Ipv6PrefixLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_accepts_0_to_32() {
        assert!(Ipv4PrefixLength::new(0).is_some());
        assert!(Ipv4PrefixLength::new(32).is_some());
        assert!(Ipv4PrefixLength::new(33).is_none());
        let prefix = Ipv4PrefixLength::new(24).expect("valid prefix");
        assert_eq!(prefix.value(), 24);
        assert_eq!(prefix.to_string(), "24");
    }

    #[test]
    fn ipv6_prefix_accepts_0_to_128() {
        assert!(Ipv6PrefixLength::new(0).is_some());
        assert!(Ipv6PrefixLength::new(128).is_some());
        assert!(Ipv6PrefixLength::new(129).is_none());
        let prefix = Ipv6PrefixLength::new(64).expect("valid prefix");
        assert_eq!(prefix.value(), 64);
        assert_eq!(prefix.to_string(), "64");
    }
}
