<div align="center">

# 🌐 net-lattice

### Typed, Cross-Platform OS Networking for Rust

[![crates.io](https://img.shields.io/crates/v/net-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice)
[![docs.rs](https://img.shields.io/docsrs/net-lattice?cacheSeconds=86400)](https://docs.rs/net-lattice)
[![Downloads](https://img.shields.io/crates/d/net-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice)
[![CI](https://github.com/F000NKKK/net-lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/F000NKKK/net-lattice/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.99-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

[Overview](#-overview) • [Platforms](#-supported-platforms) • [Quick Start](#-quick-start)
• [Mutation](#-mutation-and-transactions) • [Firewall](#-firewall-policy-management)
• [Monitoring](#-monitoring) • [Privileges](#-platform-and-privilege-notes)

</div>

---

## 📖 Overview

Cross-platform network inspection and configuration through one strongly
typed Rust API. This is the application-facing crate of
[Net Lattice](https://github.com/F000NKKK/net-lattice): it selects the
native backend for the current OS and exposes inspection, mutation,
transactions, declarative apply, and monitoring through `Lattice`.
Interfaces, addresses, routes, neighbors, DNS, and firewall rules are Rust
types, never parsed tool output; backends call native APIs (Netlink; IP
Helper and WFP; routing sockets and `pf`), never subprocesses. Runtime
`Capability` flags say what the backend supports, and unsupported requests
fail with a typed error. Every mutation takes a desired-intent type and
returns a fresh observed read-back.

Main surface: `Lattice` with per-domain reads, `current_state`, imperative
route/address/resolver/interface/static-neighbor mutations, `execute_plan`,
`diff`/`apply`, firewall policy calls, and `watch*`; domain types live in
the `model`, `mutation`, and `monitoring` modules, backend traits in
`backend`.

## 💻 Supported Platforms

- **Linux**: Netlink (`net-lattice-backend-linux`), nftables, monitoring
  for all domains.
- **Windows**: IP Helper (`net-lattice-backend-windows`), WFP, native
  monitoring for routes, interfaces, and addresses only; neighbor changes
  only through the opt-in polling `Addition` (`watch_with_additions`).
- **macOS**: routing sockets (`net-lattice-backend-darwin`), `pf`,
  monitoring for all domains.

All inspection and mutation domains work on all three, and CI runs the
privileged facade tests on all three
([full matrix](https://github.com/F000NKKK/net-lattice#-supported-platforms)).

## 📦 Installation

```toml
[dependencies]
net-lattice = "1.0"
# or, with the runtime-independent async event stream (`Lattice::watch_async`):
net-lattice = { version = "1.0", features = ["async"] }
```

On Linux, building needs the `libmnl` and `libnftnl` development packages
(for example `apt-get install libmnl-dev libnftnl-dev`).

## 🎓 Quick Start

```rust,no_run
use net_lattice::{Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    for interface in lattice.interfaces()? {
        println!("{interface:?}");
    }
    let state = lattice.current_state()?;
    println!("{} routes, {} interfaces", state.routes.len(), state.interfaces.len());
    Ok(())
}
```

`current_state()` returns routes, interfaces, neighbors, addresses, DNS, and
firewall rules as one `CurrentState`: independent, closely timed backend
reads with no lock spanning them, not one atomic capture. If any read
fails, the whole call fails and returns no partial state.

## 🧰 Mutation and Transactions

- **Interfaces**: `InterfaceConfig` (MTU and/or `DesiredAdminState`) is
  intent, distinct from the observed `Interface`, with at least one setting.
  Check `INTERFACE_MTU`/`INTERFACE_ADMIN_STATE`; success returns a re-read.
  Pick the target interface by name, never the first or loopback one.
  A backend may use separate native writes, so an error can leave a
  combined patch partially applied.
- **Static neighbors**: `StaticNeighbor` has no `NeighborId` or observed
  `NeighborState` and requires a MAC. Check `NEIGHBOR_MUTATION`; an add
  returns the entry read back from the OS. Removing a present but
  non-`Permanent` (dynamically learned) entry fails with
  `Error::InvalidState` instead of evicting it.
- **Plans**: `MutationPlan` is data. `execute_plan` takes one
  `ExecutionOptions` whose callbacks cancel, snapshot, and compensate; the
  report keeps plan indices and separates validation, snapshot, execution,
  cancellation, and compensation. Use an explicit compensator when
  restoration after a partial failure matters.
- **Declarative**: `Diff::compute` and `ApplyPlan::compile` are pure;
  `execute_apply_plan` runs `Single` steps with `execute_plan`'s primitives.
  An `ApplyStep::ReplaceRoute` is rejected before any native call if the
  backend cannot honor a requested metric change, submits its two calls in
  the backend's order, and converges only when a re-read shows the new route
  present and the old one gone. A `.compensation(...)` callback never runs
  for it (the facade reverses it internally, best effort) but still runs for
  compensated `Single` steps. Outcomes add `Rejected` (before any native
  call) and `NonConvergent` (unconfirmed, or a precondition no longer held)
  to `Applied`/`Failed`/`NotAttempted`.
- **Shortcuts**: `apply` chains `current_state` → `Diff::compute` →
  `ApplyPlan::compile` → `execute_apply_plan`; call the steps (or
  `validate_apply_plan`) to inspect the plan first. `diff` executes nothing.

See [declarative state](https://github.com/F000NKKK/net-lattice#declarative-desired-state),
[mutation contracts](https://github.com/F000NKKK/net-lattice#mutation-contracts), and the
[state model](https://github.com/F000NKKK/net-lattice/blob/main/ARCHITECTURE.md#state-model-imperative-and-declarative).

## 🔥 Firewall Policy Management

`FirewallPolicy` is ordered `FirewallRule`s plus a default verdict,
first-match-wins. `set_firewall_policy` replaces the backend's entire
managed policy atomically (no incremental add/remove); `firewall_rules`
reads it live from the kernel/engine on every shipped backend.
`clear_firewall_policy()` is `set_firewall_policy(FirewallPolicy::new(Verdict::Allow))`;
a `DesiredState::with_firewall` policy becomes a `FirewallChange` in
`Diff::compute`, which `ApplyPlan::compile` turns into the same call.
See also the Linux backend's fail-closed
[`kill_switch`](https://github.com/F000NKKK/net-lattice/blob/main/crates/net-lattice-backend-linux/examples/kill_switch.rs).

```rust,no_run
use net_lattice::model::{Direction, FirewallRule, PortRange, Protocol, Verdict};
use net_lattice::mutation::FirewallPolicy;
use net_lattice::{Capability, Lattice, Result};

fn main() -> Result<()> {
    let lattice = Lattice::connect()?;
    if lattice.supports(Capability::FIREWALL_MUTATION) {
        let dns = FirewallRule::new(Direction::Outbound, Verdict::Allow)
            .with_protocol(Protocol::Udp)
            .with_port(PortRange::single(53));
        lattice.set_firewall_policy(FirewallPolicy::new(Verdict::Deny).with_rule(dns))?;
        println!("{:?}", lattice.firewall_rules()?);
    }
    Ok(())
}
```

## 📡 Monitoring

Select only event domains the backend advertises. `watch()` requires the
aggregate `Capability::MONITORING` (route, interface, neighbor, and address
all deliverable); `watch_filtered` needs each selected domain's capability.
Windows rejects neighbor and all-domain subscriptions with
`Error::Unsupported` instead of returning a stream that omits neighbors;
`watch_with_additions` opts into backend-reported `Addition`s,
lesser-quality workarounds such as Windows neighbor polling. Streams are
bounded: a slow consumer receives `Event::ResyncRequired` and should re-read
state ([event delivery](https://github.com/F000NKKK/net-lattice#event-delivery)).

## 🔐 Platform and Privilege Notes

Read-only APIs are generally unprivileged. Mutations require the native
privileges and policy allowed by the OS (`CAP_NET_ADMIN` on Linux, an
Administrator context on Windows, root on macOS). Runtime capabilities
describe implemented surfaces, not proof that the process is authorized.
Prefer a read-after-write check when the operation's confirmation contract
requires it. See
[platform-specific setup](https://github.com/F000NKKK/net-lattice#-platform-specific-setup).

## 📖 Documentation and Examples

- **API reference**: [docs.rs/net-lattice](https://docs.rs/net-lattice)
- **Examples** for every facade operation (e.g. `interface_configuration`,
  `static_neighbor_mutation`, `firewall_policy`, `declarative_apply`):
  [`crates/net-lattice/examples`](https://github.com/F000NKKK/net-lattice/tree/main/crates/net-lattice/examples).
  Run with `cargo run -p net-lattice --example <name>` (`--features async`
  for `async_monitor`); mutation examples need an explicit
  environment-variable opt-in and elevated privilege.
- **Architecture**: [ARCHITECTURE.md](https://github.com/F000NKKK/net-lattice/blob/main/ARCHITECTURE.md)
- **Changelog**: [CHANGELOG.md](https://github.com/F000NKKK/net-lattice/blob/main/CHANGELOG.md)
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
