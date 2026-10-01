<div align="center">

# 🐧 net-lattice-backend-linux

### The Netlink Backend for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-backend-linux.svg)](https://crates.io/crates/net-lattice-backend-linux)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-backend-linux)](https://docs.rs/net-lattice-backend-linux)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

![Linux](https://img.shields.io/badge/Linux-supported-success)

[Overview](#-overview) • [Features](#-key-features) • [Build Requirements](#-build-requirements) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Privileges](#-privileges-and-safety)

</div>

---

## 📖 Overview

Linux backend for [Net Lattice](https://github.com/F000NKKK/net-lattice)
using Netlink and `/etc/resolv.conf` mechanisms. It implements native
inspection, mutation, and monitoring behind the generic
`net-lattice-platform` contracts.

> Applications should normally use the
> [`net-lattice`](https://crates.io/crates/net-lattice) facade, which
> selects this backend automatically on Linux. Direct use is intended for
> backend integration and diagnostics.

## 🌟 Key Features

- ✅ interface, address, route, neighbor, and resolver inspection;
- ✅ route, address, resolver, interface MTU/administrative-state, and
  static ARP/NDP neighbor mutation;
- ✅ native-firewall (nftables) policy management (`FirewallMutator`,
  `Capability::FIREWALL_MUTATION`) — replaces the rules in one
  Net-Lattice-owned table/chain pair atomically;
- ✅ Netlink change subscriptions and optional native async delivery;
- ✅ translation of native errors and state into portable Net Lattice types.

Static neighbor mutation (`NeighborMutator`, `Capability::NEIGHBOR_MUTATION`)
submits real `RTM_NEWNEIGH`/`RTM_DELNEIGH` requests and is reachable through
the public `net-lattice` facade via `Lattice::add_static_neighbor`/
`remove_static_neighbor` and `Mutation::{AddStaticNeighbor,
RemoveStaticNeighbor}`.

Firewall policy management is likewise reachable through the facade via
`Lattice::firewall_rules`/`set_firewall_policy`/`clear_firewall_policy` —
direct use of this crate's `LinuxBackend` is not required.

## 💻 Platform and Feature Flags

The crate compiles to an empty library on any target other than Linux.

| Feature | Effect |
|---|---|
| `async` | Native async event delivery (enables `net-lattice-platform/async`) |

## 🧰 Build Requirements

Firewall management links against `libmnl` and `libnftnl` via the `nftnl`
crate (Mullvad, MIT/Apache-2.0) — no `nft` subprocess is ever spawned. The
corresponding `-dev` packages must be installed to *build* this crate, e.g.
on Debian/Ubuntu:

```sh
apt-get install libmnl-dev libnftnl-dev
```

The runtime shared libraries (`libmnl0`/`libnftnl11` or newer) must be
present wherever the resulting binary runs; this is a build-time header/
`pkg-config` requirement only and does not otherwise affect this crate's
runtime portability.

## 📦 Installation

```toml
[dependencies]
net-lattice-backend-linux = "1.0"

# With native async event delivery
net-lattice-backend-linux = { version = "1.0", features = ["async"] }
```

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

## 📚 Examples

See [`examples/kill_switch.rs`](https://github.com/F000NKKK/net-lattice/blob/main/crates/net-lattice-backend-linux/examples/kill_switch.rs)
for a fail-closed default-deny policy built from this generic firewall API —
the crate itself is not kill-switch specific. It only applies the policy
when `NET_LATTICE_APPLY_KILL_SWITCH_EXAMPLE=1` is set and the process has
`CAP_NET_ADMIN`.

## 🔐 Privileges and Safety

Read-only operations generally require no elevated privilege. Interface,
address, route, and static neighbor changes require `CAP_NET_ADMIN`; resolver
replacement also depends on filesystem permissions and the host resolver
manager. An interface configuration request may carry MTU and
administrative-state changes together, which Linux can reject after applying
one field, so callers must re-read state after an error and use explicit
transaction compensation if restoration is required. Removing a static
neighbor first re-reads the neighbor table and refuses to delete a present
but dynamically learned (non-`Permanent`) entry, returning `InvalidState`
instead. Firewall policy replacement also requires `CAP_NET_ADMIN`; it is
confined to one Net-Lattice-owned nftables table and never reads or writes
firewall state configured by other tools. Privileged tests are ignored in
ordinary test runs and restore the observed interface configuration/neighbor
state on every exit path:

```sh
sudo -E cargo test -p net-lattice-backend-linux -- --ignored
```

## 📖 Documentation

- **API reference**: [docs.rs/net-lattice-backend-linux](https://docs.rs/net-lattice-backend-linux)
- **Facade**: [`net-lattice`](https://crates.io/crates/net-lattice), which selects this backend on Linux
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the [Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).

## 🌟 Acknowledgments

Built on [`rtnetlink`](https://github.com/rust-netlink/rtnetlink) and
Mullvad's [`nftnl`](https://github.com/mullvad/nftnl-rs) and
[`mnl`](https://github.com/mullvad/mnl-rs).
