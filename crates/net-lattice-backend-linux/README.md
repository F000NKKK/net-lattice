<div align="center">

# 🐧 net-lattice-backend-linux

### The Netlink Backend for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-backend-linux.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-backend-linux)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-backend-linux?cacheSeconds=86400)](https://docs.rs/net-lattice-backend-linux)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

![Linux](https://img.shields.io/badge/Linux-supported-success)

[Overview](#-overview) • [Installation](#-installation) • [Quick Start](#-quick-start)
• [Privileges](#-privileges-and-safety)

</div>

---

## 📖 Overview

Linux backend for [Net Lattice](https://github.com/F000NKKK/net-lattice)
using Netlink and `/etc/resolv.conf` mechanisms. `LinuxBackend` implements
native inspection, mutation, and monitoring behind the generic
`net-lattice-platform` contracts.

> Applications should normally use the
> [`net-lattice`](https://crates.io/crates/net-lattice) facade, which
> selects this backend automatically on Linux. Direct use is intended for
> backend integration and diagnostics. Static neighbors
> (`Lattice::add_static_neighbor`/`remove_static_neighbor`,
> `Mutation::{AddStaticNeighbor, RemoveStaticNeighbor}`) and firewall policy
> (`firewall_rules`/`set_firewall_policy`/`clear_firewall_policy`) are
> reachable through the facade.

- interface, address, route, neighbor, and resolver inspection;
- route, address, resolver, interface MTU/administrative-state, and static
  ARP/NDP neighbor mutation (`NeighborMutator`,
  `Capability::NEIGHBOR_MUTATION`, real `RTM_NEWNEIGH`/`RTM_DELNEIGH`);
- nftables firewall policy management (`FirewallMutator`,
  `Capability::FIREWALL_MUTATION`), atomically replacing the rules in one
  Net-Lattice-owned table/chain pair;
- Netlink change subscriptions for every domain, optionally async;
- translation of native errors and state into portable Net Lattice types.

The crate compiles to an empty library on any target other than Linux. The
`async` feature enables native async event delivery (and
`net-lattice-platform/async`).

## 📦 Installation

```toml
[dependencies]
net-lattice-backend-linux = "1.0"
# or, with native async event delivery:
net-lattice-backend-linux = { version = "1.0", features = ["async"] }
```

Firewall management links against `libmnl` and `libnftnl` via the `nftnl`
crate (Mullvad, MIT/Apache-2.0); no `nft` subprocess is ever spawned. The
`-dev` packages are needed to *build* this crate, e.g. on Debian/Ubuntu
`apt-get install libmnl-dev libnftnl-dev`. The runtime shared libraries
(`libmnl0`/`libnftnl11` or newer) must be present wherever the binary runs;
otherwise this is a build-time header/`pkg-config` requirement only and
does not affect runtime portability.

## 🎓 Quick Start

```rust,no_run
use net_lattice_platform::InterfaceProvider;

fn main() -> net_lattice_core::Result<()> {
    let backend = net_lattice_backend_linux::LinuxBackend::new()?;
    for interface in backend.interfaces()? {
        println!("{interface:?}");
    }
    Ok(())
}
```

[`examples/kill_switch.rs`](https://github.com/F000NKKK/net-lattice/blob/main/crates/net-lattice-backend-linux/examples/kill_switch.rs)
builds a fail-closed default-deny policy from the generic firewall API (the
crate itself is not kill-switch specific). It applies the policy only when
`NET_LATTICE_APPLY_KILL_SWITCH_EXAMPLE=1` is set and the process has
`CAP_NET_ADMIN`.

## 🔐 Privileges and Safety

- Read-only operations generally require no elevated privilege.
- Interface, address, route, static-neighbor, and firewall changes require
  `CAP_NET_ADMIN`; resolver replacement also depends on filesystem
  permissions and the host resolver manager.
- One interface configuration request may carry MTU and administrative
  state together, and Linux can reject it after applying one field: re-read
  state after an error and use explicit transaction compensation if
  restoration is required.
- Removing a static neighbor first re-reads the neighbor table and refuses
  to delete a present but dynamically learned (non-`Permanent`) entry,
  returning `InvalidState`.
- Firewall replacement is confined to the one Net-Lattice-owned nftables
  table and never reads or writes firewall state configured by other tools.
- Privileged tests are ignored in ordinary runs and restore the observed
  interface configuration/neighbor state on every exit path:
  `sudo -E cargo test -p net-lattice-backend-linux -- --ignored`.

## 📖 Documentation

- **API reference**: [docs.rs](https://docs.rs/net-lattice-backend-linux)
- **Facade**: [`net-lattice`](https://crates.io/crates/net-lattice), which selects this backend
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
Built on [`rtnetlink`](https://github.com/rust-netlink/rtnetlink) and
Mullvad's [`nftnl`](https://github.com/mullvad/nftnl-rs) and
[`mnl`](https://github.com/mullvad/mnl-rs).
