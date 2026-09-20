# net-lattice-backend-windows

Windows backend for Net Lattice using the IP Helper API. It implements the
generic `net-lattice-platform` contracts through native Windows APIs.

## What it provides

- interface, address, route, neighbor, and resolver inspection;
- route, address, resolver, and static ARP/NDP neighbor mutation where
  Windows exposes portable semantics;
- interface MTU and administrative-state patches, with a fresh observed
  readback after every successful native submission;
- native route, interface, and unicast-address notifications with optional
  async delivery;
- native-firewall (WFP) policy management (`FirewallMutator`,
  `Capability::FIREWALL_MUTATION`), atomically replacing this crate's own
  managed filter set across the four IPv4/IPv6 ALE layers;
- preservation of Windows error codes in the shared error model.

Applications should normally use the `net-lattice` facade, which selects this
backend automatically on Windows. Direct use is intended for backend
integration and diagnostics. Firewall policy management is reachable through
the facade via `Lattice::firewall_rules`/`set_firewall_policy`/
`clear_firewall_policy`.

## Build requirements

Firewall management links against the Windows Filtering Platform via the
`windows` crate's raw FFI bindings — no separate build-time system package
is required beyond a normal Windows SDK toolchain.

## Direct usage

```rust,no_run
use net_lattice_platform::InterfaceProvider;

fn main() -> net_lattice_core::Result<()> {
    let backend = net_lattice_backend_windows::WindowsBackend::new()?;
    for interface in backend.interfaces()? {
        println!("{interface:?}");
    }
    Ok(())
}
```

## Privileges and safety

Inspection is normally unprivileged. Mutating host networking, including an
interface MTU or administrative state, a route, an address, or a static ARP/NDP
neighbor entry, can require an administrator context and remains subject to
adapter and system policy. Windows applies MTU to its applicable IPv4/IPv6
interface rows and administrative state through a separate native operation,
so a combined patch can be partially applied after an error; callers must
re-read state and use explicit compensation where needed. Static-neighbor add
always re-reads the neighbor table after a successful `CreateIpNetEntry2`
call so callers observe what the kernel actually holds rather than a
synthesized guess; static-neighbor remove reads the target first and refuses
to delete a present entry that is not currently `Permanent`, so a
dynamically learned ARP/NDP cache entry is never removed as a side effect of
a static-removal request. IP Helper has no native neighbor-table change
callback, so this backend advertises route/interface/address monitoring
capabilities only and rejects neighbor or all-domain watcher requests before
registration; this is unrelated to (and does not gate) static-neighbor
mutation, which is a request/response native call rather than an event
subscription. The facade does not synthesize events. Firewall policy
replacement requires Administrator; it is confined to filters this crate's
own WFP provider GUID owns and never reads or writes Windows Firewall's own
rules or another application's WFP state. Privileged tests run separately
and must restore changed state.
