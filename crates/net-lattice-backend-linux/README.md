# net-lattice-backend-linux

Linux backend for Net Lattice using Netlink and `/etc/resolv.conf` mechanisms.
It implements native inspection, mutation, and monitoring behind the generic
`net-lattice-platform` contracts.

## What it provides

- interface, address, route, neighbor, and resolver inspection;
- route, address, resolver, interface MTU/administrative-state, and static
  ARP/NDP neighbor mutation;
- native-firewall (nftables) policy management (`FirewallMutator`,
  `Capability::FIREWALL_MUTATION`) — replaces the rules in one
  Net-Lattice-owned table/chain pair atomically;
- Netlink change subscriptions and optional native async delivery;
- translation of native errors and state into portable Net Lattice types.

Static neighbor mutation (`NeighborMutator`, `Capability::NEIGHBOR_MUTATION`)
submits real `RTM_NEWNEIGH`/`RTM_DELNEIGH` requests and is reachable through
the public `net-lattice` facade via `Lattice::add_static_neighbor`/
`remove_static_neighbor` and `Mutation::{AddStaticNeighbor,
RemoveStaticNeighbor}`.

Applications should normally use the `net-lattice` facade, which selects this
backend automatically on Linux. Direct use is intended for backend integration
and diagnostics.

## Build requirements

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

## Direct usage

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

See `examples/kill_switch.rs` for a fail-closed default-deny policy built
from this generic firewall API — the crate itself is not kill-switch
specific.

## Privileges and safety

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
state on every exit path.
