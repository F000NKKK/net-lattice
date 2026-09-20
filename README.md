# Net Lattice

**Languages**

🇺🇸 **English** | 🇷🇺 [Русский](README.ru.md)

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/net-lattice.svg)](https://crates.io/crates/net-lattice)
[![docs.rs](https://img.shields.io/docsrs/net-lattice)](https://docs.rs/net-lattice)
[![Downloads](https://img.shields.io/crates/d/net-lattice.svg)](https://crates.io/crates/net-lattice)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

**Net Lattice** is a modern, cross-platform Rust library for configuring and inspecting operating system networking through a single, strongly typed API.

> **Status:** `1.0` is the current stable line. Net Lattice provides
> cross-platform network inspection, route, address, DNS,
> administrative-state, MTU, static ARP/NDP neighbor, and native-firewall
> mutation, inspectable mutation plans, ordered transaction execution with
> cancellation, snapshots, compensation, and phase-aware reports, declarative
> desired-state/diff/apply, and whole-system `CurrentState` snapshots on
> Linux, Windows, and macOS. See Current Status below for the full
> capability breakdown.

## Overview

Operating systems expose networking configuration and state through wildly different, low-level, and often platform-specific interfaces: Linux Netlink, the Windows IP Helper API, and macOS BSD routing facilities, among others. Applications that need to inspect or configure networking — IP addresses, routes, interfaces, neighbors, and more — are typically forced to either shell out to external tools, parse text output, or write and maintain separate platform-specific integrations.

Net Lattice aims to unify these interfaces behind a single, strongly typed, idiomatic Rust API, so that consumers never need to deal with raw platform structures, shell commands, or ad hoc string parsing.

## Workspace crates

The published workspace is split into focused crates. Each crate has its own
crate-level README with its scope and a usage example:

| Crate | Purpose |
|---|---|
| [`net-lattice`](crates/net-lattice/README.md) | Public facade and transaction executor |
| [`net-lattice-model`](crates/net-lattice-model/README.md) | Observed state, intent, events, and mutation plans |
| [`net-lattice-platform`](crates/net-lattice-platform/README.md) | Provider and capability contracts |
| [`net-lattice-core`](crates/net-lattice-core/README.md) | Shared errors, results, and IDs |
| [`net-lattice-ip`](crates/net-lattice-ip/README.md) | IPv4/IPv6 addresses and networks |
| [`net-lattice-async`](crates/net-lattice-async/README.md) | Runtime-independent event stream adapter |
| [`net-lattice-backend-linux`](crates/net-lattice-backend-linux/README.md) | Linux Netlink backend |
| [`net-lattice-backend-windows`](crates/net-lattice-backend-windows/README.md) | Windows IP Helper backend |
| [`net-lattice-backend-darwin`](crates/net-lattice-backend-darwin/README.md) | macOS BSD/PF_ROUTE backend |

## The Lattice ecosystem

Net Lattice is the first crate in a wider Lattice family of composable,
cross-platform Rust networking libraries. The other crates are in the
bootstrap stage — repository workflow and packaging scaffolding exist, but no
implementation or public API has shipped yet — and are being designed to
compose with Net Lattice rather than duplicate it.

| Crate | Purpose |
|---|---|
| [net-lattice](https://github.com/F000NKKK/net-lattice) | OS networking inspection and configuration (routes, DNS, interfaces) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP tunnel interfaces |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Programmable DNS control plane |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Policy compiler: rules -> platform-neutral network plans |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Application-facing SDK composing the crates above |

Cross-repository dependency direction and API boundaries have not been
decided yet; they will be recorded in each repository's architecture
documents and ADRs as that design work happens.

## Motivation

Cross-platform networking tooling in the Rust ecosystem is fragmented. Existing solutions are frequently platform-specific, incomplete, or built around shelling out to system utilities such as `ip`, `netsh`, or `route`. This is fragile, hard to test, and unsuitable for building robust, production-grade network management software.

Net Lattice is intended to fill this gap by providing a single, well-designed abstraction layer over native OS networking APIs.

## Philosophy

- **Strong typing over strings.** Consumers interact with typed Rust values — addresses, prefixes, routes, interfaces — never raw strings or shell commands.
- **Native APIs, not subprocesses.** Net Lattice talks directly to platform networking APIs (Netlink, IP Helper API, route sockets) rather than invoking external CLI tools.
- **Cross-platform by design.** A single API surface backed by platform-specific implementations, so applications do not need to special-case operating systems.
- **Correctness and safety first.** Networking configuration is sensitive; the library should make incorrect states difficult to represent.
- **Incremental, well-considered growth.** Features are added deliberately, with attention to API design and long-term maintainability, rather than rushed to cover every possible use case.

## Capabilities

Implemented:

- IPv4/IPv6 address and prefix types
- Interface-address inspection and mutation
- Route inspection and mutation
- Interface inspection
- Interface administrative-state and MTU configuration
- DNS resolver inspection and mutation
- Static ARP/NDP neighbor mutation
- Inspectable mutation plans for routes, addresses, DNS, and static neighbors
- Ordered mutation-plan execution with cancellation, snapshots, explicit
  compensation, and phase-aware reports
- Neighbor tables (ARP/NDP)
- Network monitoring and change notifications
- Optional runtime-agnostic async event stream
- Whole-system `CurrentState` snapshots
- Declarative desired-state configuration: `DesiredState`, a pure `Diff`
  computed against a `CurrentState`, a pure compiled `ApplyPlan`, and
  `Lattice::apply()`/`execute_apply_plan()` to run it against a backend
- Native-firewall policy management (`FirewallProvider`/`FirewallMutator`),
  on Linux (nftables), Windows (WFP), and macOS (`pf`), integrated with
  `Mutation`, `DesiredState`, `Diff`, and `ApplyPlan`

Planned:

- VLANs
- VRFs
- Network namespaces

## Non-Goals

- Net Lattice is not a replacement for full network management daemons (e.g. NetworkManager, systemd-networkd).
- Net Lattice does not aim to provide a command-line interface or GUI as part of the core library.
- Net Lattice does not aim to parse or wrap the output of external CLI tools as a long-term strategy.
- Net Lattice does not aim to support every conceivable network protocol or vendor extension from day one.

## Current Status

Net Lattice assembles whole-system `CurrentState` snapshots: `net-lattice-model`'s
`CurrentState` aggregates routes, interfaces, neighbors, interface addresses,
and DNS configuration; `net-lattice-platform::SnapshotProvider` describes the
assembly contract; and `Lattice::current_state()` implements it, failing fast
on the first constituent read error with no partial result. No backend crate
needs any change to gain this — it is implemented once on `Lattice<B>`. See
[CHANGELOG.md](CHANGELOG.md) for the dated, per-version list of additions,
including the domain-scoped `net_lattice::model`/`mutation`/`monitoring`
re-export modules (the crate root no longer re-exports domain items
directly).

Net Lattice also exposes a declarative model, an inspectable diff, and a
compiled, executable apply plan: `DesiredState` (`net-lattice-model`, also
reachable as `net_lattice::mutation::DesiredState`) is a whole-system,
caller-authored aggregate parallel to `CurrentState` — one `Option`-wrapped
field per domain, built via `DesiredState::empty()` plus per-domain `with_*`
builders, with no backend dependency of its own — and
`Diff::compute(&CurrentState, &DesiredState) -> Diff`
(`net_lattice::mutation::Diff`) computes a pure, side-effect-free difference
between the two: route/neighbor/address as natural-key add/remove(/change)
sets, interface as a per-field patch-diff, and DNS and firewall policy each
as a whole-value comparison. `Diff::compute` performs no I/O and calls no
provider/backend method. `ApplyPlan::compile(&Diff) -> ApplyPlan`
(`net_lattice::mutation::ApplyPlan`) is likewise pure and side-effect-free,
compiling the diff into an ordered list of `ApplyStep`s (see the
[architecture](ARCHITECTURE.md)'s State Model section for how a paired
route add/remove at the same destination compiles to one `ReplaceRoute`
step instead of two independent ones); `Lattice::execute_apply_plan()`
executes that plan against the connected backend with capability-aware
rejection, per-backend route-replacement ordering, and mandatory
read-after-write verification, and the thin `Lattice::apply(&DesiredState,
&mut ExecutionOptions)` convenience chains all four steps
(`current_state` → `Diff::compute` → `ApplyPlan::compile` →
`execute_apply_plan`) for callers who do not need to inspect the compiled
plan first. See the `declarative_diff` example for a read-only diff
walkthrough and the `declarative_apply` example for a full apply
walkthrough.

The following surface, the frozen 1.0 public API described by
[architecture](ARCHITECTURE.md), is verified by the privileged Linux,
Windows, and macOS CI jobs:

- `net-lattice-core`, `net-lattice-ip`
- `net-lattice-model`'s `route`, `mac`, `interface`, `dns`, `neighbor`, `ifaddr`, `event`, and `mutation` modules; `NewInterfaceAddress`, `NewDnsConfig`, and `StaticNeighbor` express mutation intent separately from observed state
- `net-lattice-platform`'s `RouteProvider`, `RouteMutator`, `InterfaceProvider`, `InterfaceMutator`, `DnsProvider`, `DnsMutator`, `NeighborProvider`, `NeighborMutator`, `AddressProvider`, `AddressMutator`, `CapabilityProvider`, synchronous `EventProvider`/bounded `EventReceiver`, and optional async monitoring support
- `net-lattice-async`, which exposes the single runtime-agnostic `EventStream` type
- the `net-lattice` facade, including `Lattice::add_address()`, `Lattice::remove_address()`, `Lattice::set_dns_config()`, `Lattice::set_interface_config()`, `Lattice::add_static_neighbor()`, `Lattice::remove_static_neighbor()`, `Lattice::capabilities()`, `Lattice::supports()`, `Lattice::watch()`, `Lattice::watch_filtered()`, `Lattice::execute_plan()`, `Lattice::execute_apply_plan()`, `Lattice::apply()`, and feature-gated `Lattice::watch_async()`

This gives real route, interface-address, and static ARP/NDP neighbor
management, desired `InterfaceConfig` patches for administrative state and
MTU, interface listing, DNS resolver inspection and mutation, neighbor
(ARP/NDP) table reads, inspectable mutation plans, ordered transaction
execution, and bounded network-change monitoring on Linux, Windows, and
macOS. `InterfaceConfig` never reuses observed `Interface`: it selects one
interface and requests one or both supported settings. Check
`Capability::INTERFACE_ADMIN_STATE` and `Capability::INTERFACE_MTU` for each
requested field. Native backends may submit those fields separately, so a
failed combined patch may have partially applied; re-read state and use an
explicit executor compensator when attempted restoration matters. Address
creation accepts `NewInterfaceAddress` and returns the resulting observed
`InterfaceAddress`; resolver replacement accepts `NewDnsConfig` and returns
the resulting observed `DnsConfig`. Static-neighbor creation accepts
`StaticNeighbor` (distinct from `NeighborEntry`: no synthesized ID or
observed state, and a MAC address is required) and returns the resulting
observed `NeighborEntry`; check `Capability::NEIGHBOR_MUTATION` first, and
note that removing a present but non-`Permanent` (dynamically learned) entry
is refused with `Error::InvalidState` rather than silently evicting it.
`MutationPlan` is data only: it exposes operation semantics, while
`Lattice::execute_plan` applies a plan through one `ExecutionOptions` value
with runtime validation, cancellation boundaries, typed snapshots, explicit
compensation, and phase-aware reports. `EventFilter` composes domain
selectors (`routes()`) and object selectors (`route(route_id)`); every
backend applies the filter before enqueueing an ordinary event. Query the
capability for every domain selected by the filter before watching;
`Capability::MONITORING` means that all current domains are available. Unix
resolver managers may later regenerate `/etc/resolv.conf`; callers requiring
persistence should use the owning manager's configuration interface. Net
Lattice's `async` feature uses and re-exports the `EventStream`
implementation from `net-lattice-async`; applications need only enable that
facade feature.

| Capability | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Route inspection | ✅ | ✅ | ✅ |
| Route mutation | ✅ | ✅ | ✅ |
| Interface inspection | ✅ | ✅ | ✅ |
| Interface admin-state/MTU configuration | ✅ | ✅ | ✅ |
| Interface-address inspection | ✅ | ✅ | ✅ |
| Interface-address mutation | ✅ | ✅ | ✅ |
| Neighbor table inspection | ✅ | ✅ | ✅ |
| Static neighbor (ARP/NDP) mutation | ✅ | ✅ | ✅ |
| DNS resolver inspection | ✅ | ✅ | ✅ |
| DNS resolver mutation | ✅ | ✅ | ✅ |
| Native-firewall policy management | ✅ | ✅ | ✅ |
| Route/interface/address change monitoring | ✅ | ✅ | ✅ |
| Neighbor change monitoring | ✅ | ⚠ | ✅ |
| All-domain monitoring (`watch()`) | ✅ | — | ✅ |
| Async route/interface/address monitoring | ✅ | ✅ | ✅ |
| Async neighbor/all-domain monitoring | ✅ | — | ✅ |

✅ native `Capability`, — unsupported, ⚠ no native `Capability` but an opt-in,
weaker-guarantee `Addition` substitute is available — see the Addition
matrix below.

### Addition tier

`Addition` is a separate, disjoint flag type from `Capability`: a backend
reports one through `AdditionProvider::additions()` only when it has no
native mechanism for the underlying feature at all, and requesting it goes
through `Lattice::watch_with_additions` rather than `watch`/`watch_filtered`.
An `Addition` is never rendered as an ordinary `Capability` checkmark in
either matrix on this page.

| Addition | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Neighbor change monitoring via polling (`NEIGHBOR_MONITORING_POLLING`) | — | ✅ | — |

Linux and macOS have native `Capability::NEIGHBOR_MONITORING` (✅ in the
matrix above), so neither reports this `Addition` — `AdditionProvider`'s
default (`additions()` → empty) applies unchanged on both. Windows reports
`Addition::NEIGHBOR_MONITORING_POLLING`: an opt-in substitute that
synthesizes `Added`/`Removed`/`Changed` events from successive polls of the
neighbor table, at a weaker latency/ordering/coalescing/resource-cost tier
than native event delivery (see ARCHITECTURE.md's "Platform Support Matrix
and Gaps" and "Event Delivery Guarantees" sections for the full guarantee
and this convention's rationale). An `additions` bit not reported by the
connected backend's `AdditionProvider::additions()` is silently not
activated rather than an error, matching `Capability`'s own "query, don't
assume" contract, so a caller may request `NEIGHBOR_MONITORING_POLLING`
unconditionally and simply receive no addition-sourced events on a backend
that does not report it.

Static neighbor mutation is a request/response native call (`RTM_NEWNEIGH`/
`RTM_DELNEIGH`, `CreateIpNetEntry2`/`DeleteIpNetEntry2`, `PF_ROUTE`'s
`RTM_ADD`), not an event subscription. `Capability::NEIGHBOR_MUTATION` and
`Capability::NEIGHBOR_MONITORING` are independent capabilities: mutation
support does not imply native change notifications for the neighbor table.
Check `Capability::NEIGHBOR_MONITORING` (the "Neighbor change monitoring"
row above) before watching for neighbor-table changes; it is currently
advertised on Linux and macOS, but not Windows — see the "Addition tier"
section above for Windows's opt-in polling substitute.

### Event delivery

Event streams are bounded. If a consumer falls behind, the watcher records and delivers `Event::ResyncRequired { .. }` before a subsequent ordinary event instead of retaining an unbounded backlog. Re-read the affected provider state before relying on subsequent events.

Monitoring capabilities describe actual native delivery. Linux Netlink and
macOS PF_ROUTE expose route, interface, interface-address, and neighbor
delivery, so they advertise aggregate `Capability::MONITORING`. Windows IP
Helper exposes route, interface, and unicast-address delivery only: use the
matching `ROUTE_MONITORING`, `INTERFACE_MONITORING`, or
`ADDRESS_MONITORING` capability with `watch_filtered`. A Windows neighbor or
all-domain request returns `Error::Unsupported` before native registration;
it never silently drops a selected event domain.

```rust
let route_events = EventFilter::none().route(route_id);
if lattice.supports(Capability::ROUTE_MONITORING) {
    let watcher = lattice.watch_filtered(route_events)?;
    # let _ = watcher;
}
```

## Examples

The runnable sources in [`crates/net-lattice/examples`](crates/net-lattice/examples)
cover every currently available facade operation. Read-only examples are safe to
run; mutation examples require an explicit environment-variable opt-in and
elevated operating-system privilege.

| Scenario | Runnable example | Facade/API covered |
|---|---|---|
| Complete read-only state | [`snapshot`](crates/net-lattice/examples/snapshot.rs) | `capabilities`, `interfaces`, `routes`, `addresses`, `dns_config`, `neighbors` |
| Runtime feature selection | [`capabilities`](crates/net-lattice/examples/capabilities.rs) | `capabilities`, `supports`, every current `Capability` flag |
| Focused route read | [`list_routes`](crates/net-lattice/examples/list_routes.rs) | `routes` |
| Bounded synchronous delivery | [`sync_monitor`](crates/net-lattice/examples/sync_monitor.rs) | capability-gated `watch_filtered`, `recv_timeout`, `Event::ResyncRequired` |
| Domain and object filtering | [`filtered_monitor`](crates/net-lattice/examples/filtered_monitor.rs) | `watch_filtered`, every `EventFilter` domain and object selector |
| Native async delivery | [`async_monitor`](crates/net-lattice/examples/async_monitor.rs) | capability-gated `watch_async`, `EventStream` |
| Address lifecycle | [`address_assignment`](crates/net-lattice/examples/address_assignment.rs) | `NewInterfaceAddress`, `add_address`, `remove_address` |
| Route lifecycle | [`route_mutation`](crates/net-lattice/examples/route_mutation.rs) | `RouteConfig`, `add_route`, `remove_route` |
| Static neighbor lifecycle | [`static_neighbor_mutation`](crates/net-lattice/examples/static_neighbor_mutation.rs) | `StaticNeighbor`, `Capability::NEIGHBOR_MUTATION`, `add_static_neighbor`, `remove_static_neighbor` |
| Resolver replacement | [`dns_mutation`](crates/net-lattice/examples/dns_mutation.rs) | `NewDnsConfig`, `set_dns_config`, read-after-write verification |
| Interface configuration | [`interface_configuration`](crates/net-lattice/examples/interface_configuration.rs) | `InterfaceConfig`, `DesiredAdminState`, capability checks, `set_interface_config` |
| Mutation inspection | [`mutation_plan`](crates/net-lattice/examples/mutation_plan.rs) | every `Mutation` variant, `Mutation::semantics`, `MutationPlan` |
| Declarative diff (read-only) | [`declarative_diff`](crates/net-lattice/examples/declarative_diff.rs) | `DesiredState`, `Diff`, `Lattice::diff`, `RouteChange` |
| Declarative apply | [`declarative_apply`](crates/net-lattice/examples/declarative_apply.rs) | `DesiredState`, `ApplyPlan`, `Lattice::apply`, `ApplyPlanReport` |

Run an example with `cargo run -p net-lattice --example <name>`. Add
`--features async` for `async_monitor`.

For a compact application-facing walkthrough, use the
[`net-lattice` crate README](crates/net-lattice/README.md). The other crate
guides in the workspace table document direct library and backend use without
duplicating those contracts here.

## Roadmap

1.0 is the current stable line: complete cross-platform inspection,
monitoring, imperative mutation, ordered transactions, declarative apply, and
native-firewall policy management (imperative and transactional), each with
privileged regression coverage on Linux, Windows, and macOS. See
[CHANGELOG.md](CHANGELOG.md) for the dated history of how it got here and
[ARCHITECTURE.md](ARCHITECTURE.md) for the frozen public-API surface.

Planned for 2.0+ — each independently large enough to need its own
architecture pass, none a 1.0 prerequisite:

| Domain | Scope |
|---|---|
| VLAN | tagged-interface read/intent/mutation model, consistent across all three backends |
| VRF | routing-table isolation model and per-backend binding |
| Namespaces | process/network namespace isolation — not symmetric across Linux/Windows/macOS, needs its own design pass before implementation starts |

Tunnel interface management is out of scope for this repository entirely;
see [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) in the
ecosystem table above.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations, and [SECURITY.md](SECURITY.md) for reporting security issues.

## License

Net Lattice is licensed under the [Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).
