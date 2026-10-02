<div align="center">

# 🔌 net-lattice-platform

### Provider Traits and Capability Contracts for Net Lattice Backends

[![crates.io](https://img.shields.io/crates/v/net-lattice-platform.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-platform)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-platform?cacheSeconds=86400)](https://docs.rs/net-lattice-platform)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

[Overview](#-overview) • [Features](#-key-features) • [Installation](#-installation)
• [Quick Start](#-quick-start) • [Contract Notes](#-contract-notes)

</div>

---

## 📖 Overview

Generic provider traits and runtime capability contracts between
[Net Lattice](https://github.com/F000NKKK/net-lattice)'s public facade and
native platform backends.

This crate intentionally depends on `net-lattice-core`, not
`net-lattice-model`. The facade binds provider associated types to the
workspace's concrete domain model.

> Application code normally uses the
> [`net-lattice`](https://crates.io/crates/net-lattice) facade; backend
> authors depend on this crate directly.

## 🌟 Key Features

- **Provider/mutator traits** with associated types: `RouteProvider`/
  `RouteMutator`, `InterfaceProvider`/`InterfaceMutator` (administrative
  state and MTU patches), `DnsProvider`/`DnsMutator`, `NeighborProvider`/
  `NeighborMutator` (static ARP/NDP add/remove), `AddressProvider`/
  `AddressMutator`, and `FirewallProvider`/`FirewallMutator` (atomic
  whole-policy replace of one backend-owned native-firewall table/chain
  pair).
- **Route-replacement facts**: `RouteMutator`'s default-provided
  `supports_route_metric` and `route_replace_order` (returning
  `RouteReplaceOrder`) describe fixed per-backend facts a destination-paired
  route replacement needs; most backends inherit the defaults.
- **`SnapshotProvider`**: a whole-system state assembly contract. No backend
  implements it directly; the facade supplies it for any backend that
  implements the read providers above.
- runtime `Capability` reporting and synchronous event sender/receiver
  contracts.
- **`async` feature**: native Tokio watcher contracts (`TokioEventProvider`,
  `TokioEventReceiver`, `TokioEventSender`); pulls in `tokio`.
- **`Addition`/`AdditionProvider`**: a disjoint, explicitly opt-in tier of
  non-native capabilities built on a lesser-quality mechanism (for example
  polling instead of a native push subscription). `AdditionProvider`
  extends `EventProvider`; its `additions` and `watch_addition` methods
  default to empty/`Error::Unsupported`, so a backend with nothing to add
  costs nothing. `Addition` never expands what `Capability` means: it is a
  separate `#[non_exhaustive]` flag set a caller must request explicitly.

## 📦 Installation

```toml
[dependencies]
net-lattice-platform = "1.0"
# or, with the native Tokio watcher contracts:
net-lattice-platform = { version = "1.0", features = ["async"] }
```

## 🎓 Quick Start

```rust
use net_lattice_platform::{Capability, CapabilityProvider};

fn supports_route_monitoring<P: CapabilityProvider>(provider: &P) -> bool {
    provider.capabilities().contains(Capability::ROUTE_MONITORING)
}
```

## 📜 Contract Notes

Capabilities report implemented runtime surfaces. They do not guarantee that
the current process has native privileges or that state cannot change
between validation and submission. `Capability::INTERFACE_ADMIN_STATE` and
`Capability::INTERFACE_MTU` gate interface configuration independently; a
caller requesting both settings must require both flags.

Monitoring is domain-specific: `ROUTE_MONITORING`, `INTERFACE_MONITORING`,
`NEIGHBOR_MONITORING`, and `ADDRESS_MONITORING` each mean the backend has a
native delivery path for that domain. `MONITORING` is their all-domain
aggregate, not merely proof that some watcher can be constructed.

`Capability::NEIGHBOR_MUTATION` gates static ARP/NDP add/remove and is
distinct from `NEIGHBOR_MONITORING`; `Capability::ROUTE_MUTATION` gates
route add/remove and is distinct from `ROUTE_MONITORING`. All three shipped
backends (Linux, Windows, macOS) advertise both mutation flags; Windows does
not advertise `NEIGHBOR_MONITORING`.

## 📖 Documentation

- **API reference**: [docs.rs/net-lattice-platform](https://docs.rs/net-lattice-platform)
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
