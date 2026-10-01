<div align="center">

# 🔢 net-lattice-ip

### Strongly Typed IPv4 and IPv6 Primitives for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-ip.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-ip)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-ip?cacheSeconds=86400)](https://docs.rs/net-lattice-ip)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

[Overview](#-overview) • [Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start)

</div>

---

## 📖 Overview

Strongly typed IPv4 and IPv6 primitives used by
[Net Lattice](https://github.com/F000NKKK/net-lattice). This crate is
platform-independent and performs no network I/O.

> Applications using the full library normally import these types from
> [`net-lattice`](https://crates.io/crates/net-lattice); protocol tooling
> can depend on `net-lattice-ip` directly.

## 🌟 Key Features

- ✅ validated IPv4 and IPv6 prefix lengths (`Ipv4PrefixLength`,
  `Ipv6PrefixLength`);
- ✅ address and network types (`Ipv4Address`, `Ipv6Address`,
  `Ipv4Network`, `Ipv6Network`) with canonical display formatting;
- ✅ conversions to and from the Rust standard library's IP types;
- ✅ family-safe APIs that keep IPv4 and IPv6 values distinct.

## 📦 Installation

```toml
[dependencies]
net-lattice-ip = "1.0"
```

## 🎓 Quick Start

```rust
use net_lattice_ip::{Ipv4Address, Ipv4Network, Ipv4PrefixLength};

let network = Ipv4Network::new(
    Ipv4Address::new(192, 0, 2, 0),
    Ipv4PrefixLength::new(24).expect("valid prefix"),
);
assert_eq!(network.to_string(), "192.0.2.0/24");
```

Invalid prefix lengths are rejected during construction rather than being
stored as malformed networks.

## 📖 Documentation

- **API reference**: [docs.rs/net-lattice-ip](https://docs.rs/net-lattice-ip)
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the [Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
