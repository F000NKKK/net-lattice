//! Typed IPv4/IPv6 address and network primitives.
//!
//! Pure data and arithmetic, no operating-system dependency. Buildable for
//! any target, including `wasm32`.

#![warn(missing_docs)]

mod ipv4;
mod ipv6;
mod prefix;

pub use ipv4::{Ipv4Address, Ipv4Network};
pub use ipv6::{Ipv6Address, Ipv6Network};
pub use prefix::{Ipv4PrefixLength, Ipv6PrefixLength};
