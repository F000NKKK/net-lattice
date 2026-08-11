# net-lattice-platform

Generic provider traits and runtime capability contracts between Net Lattice's
public facade and native platform backends.

## What it provides

- generic inspection and mutation provider traits using associated types:
  `RouteProvider`/`RouteMutator`, `InterfaceProvider`/`InterfaceMutator`
  (desired administrative-state and MTU patches), `DnsProvider`/
  `DnsMutator`, `NeighborProvider`/`NeighborMutator` (static ARP/NDP entry
  add/remove intent), and `AddressProvider`/`AddressMutator`;
  `RouteMutator` additionally exposes two default-provided methods,
  `supports_route_metric` and `route_replace_order` (returning the new
  `RouteReplaceOrder` enum), describing fixed per-backend facts a
  destination-paired route replacement needs — most backends inherit the
  defaults unchanged;
- `SnapshotProvider`, a generic whole-system state assembly contract; no
  backend implements it directly — the facade supplies the implementation,
  covering any backend that already implements the read providers above;
- runtime `Capability` reporting;
- synchronous event sender/receiver contracts;
- optional native Tokio watcher contracts behind the `async` feature;
- `Addition`/`AdditionProvider`, a disjoint, explicitly opt-in tier of
  non-native capabilities implemented through a lesser-quality mechanism
  (for example, polling instead of a native push subscription).
  `AdditionProvider` extends `EventProvider`; both of its methods,
  `additions` and `watch_addition`, are default-provided (empty/
  `Error::Unsupported`) so a backend with nothing to add costs nothing.
  `Addition` never expands what `Capability` means — it is a separate,
  `#[non_exhaustive]` flag set a caller must request explicitly.

This crate intentionally depends on `net-lattice-core`, not
`net-lattice-model`. The facade binds provider associated types to the
workspace's concrete domain model. Application code normally uses
`net-lattice`; backend authors depend on this crate directly.

## Usage

```rust
use net_lattice_platform::{Capability, CapabilityProvider};

fn supports_route_monitoring<P: CapabilityProvider>(provider: &P) -> bool {
    provider.capabilities().contains(Capability::ROUTE_MONITORING)
}
```

## Contract notes

Capabilities report implemented runtime surfaces. They do not guarantee that
the current process has native privileges or that state cannot change between
validation and submission. In particular,
`Capability::INTERFACE_ADMIN_STATE` and `Capability::INTERFACE_MTU` gate a
backend's interface-configuration surface independently; a caller requesting
both settings must require both flags.

Monitoring is also domain-specific: `ROUTE_MONITORING`,
`INTERFACE_MONITORING`, `NEIGHBOR_MONITORING`, and `ADDRESS_MONITORING` each
mean that the backend has a native delivery path for that domain.
`MONITORING` is their all-domain aggregate, not merely proof that some watcher
can be constructed.

`Capability::NEIGHBOR_MUTATION` gates static ARP/NDP add/remove support and is
distinct from `NEIGHBOR_MONITORING`. `Capability::ROUTE_MUTATION` gates route
add/remove support and is distinct from `ROUTE_MONITORING`. All three shipped
backends (Linux, Windows, macOS) advertise both.
