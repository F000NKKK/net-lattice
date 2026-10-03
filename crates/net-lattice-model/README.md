<div align="center">

# 🗂️ net-lattice-model

### OS-Independent Network Domain Types for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-model.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-model)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-model?cacheSeconds=86400)](https://docs.rs/net-lattice-model)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.99-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

[Overview](#-overview) • [Features](#-key-features) • [Installation](#-installation)
• [Quick Start](#-quick-start) • [Contract Notes](#-contract-notes)

</div>

---

## 📖 Overview

Operating-system-independent network domain types for
[Net Lattice](https://github.com/F000NKKK/net-lattice). This crate models
data and contracts; it never inspects or mutates the host system.

> Use this crate directly for offline plan construction, policy analysis,
> serialization layers, or backend development. Use the
> [`net-lattice`](https://crates.io/crates/net-lattice) facade to connect
> these models to an operating system.

## 🌟 Key Features

- **Observed state**: interfaces, addresses, routes, neighbors, and DNS
  configuration, typed object identifiers, and filtered change events.
- **Intent types**, each distinct from its observed counterpart:
  - `InterfaceConfig`, a partial patch whose `DesiredAdminState` means
    observed `AdminState::Unknown` is never requested;
  - `StaticNeighbor` for ARP/NDP entries, requiring an explicit MAC;
  - `RouteConfig`, carrying no route identifier (no backend accepts one as
    mutation input); its `metric` is honored on Linux and Windows only and
    silently ignored on Darwin, matching the observed-side platform gap;
  - `FirewallRule`/`FirewallPolicy`, a minimal rule model (direction,
    interface, remote network, protocol/port, verdict) for whole-policy
    replacement, with no NAT, connection tracking, or custom chain graphs.
- **Plans and reports**: mutation descriptions, semantics, snapshots, plans,
  and execution reports, keeping inspectable plan data separate from
  runtime execution.
- **`CurrentState`**: a whole-system observed snapshot of routes,
  interfaces, neighbors, interface addresses, DNS, and firewall rules. The
  facade assembles it; this crate defines only the shape and a
  `CurrentState::new` constructor (the type is `#[non_exhaustive]`).
- **`DesiredState`**: the caller-authored parallel to `CurrentState`, never
  read from a backend. One `Option` field per domain: `None` leaves a domain
  unmanaged, `Some` (even an empty collection) manages exactly that content.
  Build it with `DesiredState::empty()` and the `with_routes`/
  `with_interfaces`/`with_neighbors`/`with_addresses`/`with_dns`/
  `with_firewall` builders.
- **`Diff::compute(&CurrentState, &DesiredState)`**: pure, no I/O, no
  provider call. Routes, neighbors, and addresses use a natural-key set-diff
  (`RouteChange`/`NeighborChange`/`AddressChange`; routes never produce
  `Changed`); interfaces use a per-field `InterfaceDiff` with
  `InterfaceConfig`'s "don't touch" semantics; DNS and firewall are
  whole-value comparisons (`DnsChange`/`FirewallChange`). It does not decide
  how or whether a diff is applied.
- **`ApplyPlan::compile(&Diff)`**: pure, infallible, no I/O. Interface, DNS,
  and firewall changes and unpaired or `Changed` route/neighbor/address
  entries lower to `ApplyStep::Single(Mutation)` (remove-then-add for a
  neighbor/address `Changed` pair); a route `Added`/`Removed` pair with the
  same destination lowers instead to one
  `ApplyStep::ReplaceRoute { old, new }`. It does not choose a backend or
  judge whether a step is acceptable there.
- **`ApplyPlanReport`, `ApplyStepOutcome`, `NonConvergentReason`**: the
  report shape an executor (the `net-lattice` facade) fills in. Building or
  inspecting them never changes operating-system state.

## 📦 Installation

```toml
[dependencies]
net-lattice-model = "1.0"
```

## 🎓 Quick Start

```rust
use net_lattice_model::{EventFilter, InterfaceId};

let filter = EventFilter::none().interface(InterfaceId::new(7));
assert!(!filter.is_empty());
```

## 📜 Contract Notes

`MutationPlan::preflight` is static and side-effect free. Runtime capability,
privilege, and object-state validation belongs to an executor such as the
one provided by the `net-lattice` facade.

`InterfaceConfig` requires at least one requested setting. Zero is rejected
as an invalid MTU here; all other MTU limits are platform- and
interface-specific backend validation. A patch can describe administrative
state, MTU, or both without manufacturing an observed `Interface`.

## 📖 Documentation

- **API reference**: [docs.rs/net-lattice-model](https://docs.rs/net-lattice-model)
- **State model**:
  [ARCHITECTURE.md](https://github.com/F000NKKK/net-lattice/blob/main/ARCHITECTURE.md#state-model-imperative-and-declarative)
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
