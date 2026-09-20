# net-lattice-backend-darwin

macOS backend for Net Lattice using BSD routing sockets, `getifaddrs`, and
native ioctls. It implements the generic `net-lattice-platform` contracts.

## What it provides

- interface, address, route, neighbor, and resolver inspection;
- route, address, resolver, and static ARP/NDP neighbor mutation where macOS
  exposes portable semantics;
- administrative-state and MTU configuration through `SIOCSIFFLAGS` and
  `SIOCSIFMTU`, with fresh observed-interface readback;
- routing-socket monitoring and optional async delivery;
- native-firewall (`pf`) policy management (`FirewallMutator`,
  `Capability::FIREWALL_MUTATION`) — one managed `pf` anchor (`net_lattice`),
  replaced atomically via `pf`'s own transaction ticket mechanism;
  `FirewallProvider::firewall_rules` reads live from the kernel, not a
  cache;
- preservation of native error codes in the shared error model.

Applications should normally use the `net-lattice` facade, which selects this
backend automatically on macOS. Direct use is intended for backend integration
and diagnostics. Firewall policy management is reachable through the facade
via `Lattice::firewall_rules`/`set_firewall_policy`/`clear_firewall_policy`.

## Build requirements

Firewall management uses raw `ioctl` calls on `/dev/pf` — no build-time
system package is required, but see this crate's `firewall` module
documentation for the real risk profile of this approach: there is no safe
Rust wrapper for `pf`, and Apple does not ship the kernel-private
`net/pfvar.h` header in the public SDK, so the ioctl structs are transcribed
field-for-field from Apple's own published XNU source rather than a
mismatched modern OpenBSD header.

## Direct usage

```rust,no_run
use net_lattice_platform::InterfaceProvider;

fn main() -> net_lattice_core::Result<()> {
    let backend = net_lattice_backend_darwin::DarwinBackend::new()?;
    for interface in backend.interfaces()? {
        println!("{interface:?}");
    }
    Ok(())
}
```

## Interface configuration

`InterfaceConfig` is a partial desired-state patch, distinct from the
observed `Interface`. The backend resolves its target from the observed ID,
updates the requested MTU and/or administrative state, and re-reads the
interface before returning success.

```rust,no_run
use net_lattice_model::interface::{DesiredAdminState, InterfaceConfig};
use net_lattice_platform::{InterfaceMutator, InterfaceProvider};

fn main() -> net_lattice_core::Result<()> {
    let backend = net_lattice_backend_darwin::DarwinBackend::new()?;
    let interface = backend.interfaces()?.into_iter().next().ok_or(
        net_lattice_core::Error::NotFound,
    )?;
    let config = InterfaceConfig::new(
        interface.id,
        Some(DesiredAdminState::Up),
        None,
    )?;
    let observed = backend.set_interface_config(config)?;
    println!("{} is now {:?}", observed.name, observed.admin_state);
    Ok(())
}
```

macOS uses separate ioctls for MTU and flags, so a failed combined patch may
have applied one requested field. Re-read the interface after errors and use
the facade transaction executor's explicit compensation only when restoration
is required.

The native PF_ROUTE watcher maps `RTM_IFINFO` notifications to the existing
`Event::Interface { kind: ChangeKind::Changed }` signal; the facade does not
synthesize a duplicate event. The shared privileged test runner intentionally
submits unchanged observed values and cannot safely create a disposable
interface, so it does not claim end-to-end delivery for a value-changing
configuration. Consumers should always re-read observed state after a change
signal.

## Privileges and safety

Inspection is normally unprivileged. Mutations can require root or specific
system entitlements and may interact with macOS network configuration
services. Interface configuration writes the real system interface and can
apply MTU and administrative state independently. Static-neighbor remove
reads the target first and refuses to delete a present entry that is not
currently `Permanent`, so a dynamically learned ARP/NDP cache entry is never
removed as a side effect of a static-removal request. Firewall policy
replacement requires root; it is confined to the `net_lattice` anchor and
never reads or writes rules configured by other tools (e.g. `pfctl` run by
hand against a different anchor). Privileged tests run separately and must
restore changed state.
