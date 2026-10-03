<div align="center">

# 🍎 net-lattice-backend-darwin

### The macOS Routing-Socket Backend for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-backend-darwin.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-backend-darwin)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-backend-darwin?cacheSeconds=86400)](https://docs.rs/net-lattice-backend-darwin)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.99-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

![macOS](https://img.shields.io/badge/macOS-supported-success)

[Overview](#-overview) • [Installation](#-installation) • [Quick Start](#-quick-start)
• [Interface Configuration](#-interface-configuration-and-monitoring)
• [Privileges](#-privileges-and-safety)

</div>

---

## 📖 Overview

macOS backend for [Net Lattice](https://github.com/F000NKKK/net-lattice)
using BSD routing sockets, `getifaddrs`, and native ioctls. `DarwinBackend`
implements the generic `net-lattice-platform` contracts.

> Applications should normally use the
> [`net-lattice`](https://crates.io/crates/net-lattice) facade, which
> selects this backend automatically on macOS. Direct use is intended for
> backend integration and diagnostics. Firewall policy management is
> reachable through the facade via `Lattice::firewall_rules`/
> `set_firewall_policy`/`clear_firewall_policy`.

- interface, address, route, neighbor, and resolver inspection;
- route, address, resolver, and static ARP/NDP neighbor mutation where
  macOS exposes portable semantics;
- administrative-state and MTU configuration through `SIOCSIFFLAGS` and
  `SIOCSIFMTU`, with fresh observed-interface readback;
- routing-socket monitoring and optional async delivery;
- `pf` firewall policy management (`FirewallMutator`,
  `Capability::FIREWALL_MUTATION`), atomically replacing one managed `pf`
  anchor (`net_lattice`);
- preservation of native error codes in the shared error model.

The crate compiles to an empty library on any target other than macOS. The
`async` feature enables native async event delivery (and
`net-lattice-platform/async`). Firewall management uses raw `ioctl` calls on
`/dev/pf`, so no build-time system package is required; the `firewall`
module's documentation describes the risk profile of that approach.

## 📦 Installation

```toml
[dependencies]
net-lattice-backend-darwin = "1.0"
# or, with native async event delivery:
net-lattice-backend-darwin = { version = "1.0", features = ["async"] }
```

## 🎓 Quick Start

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

## 🔧 Interface Configuration and Monitoring

`InterfaceConfig` is a partial desired-state patch, distinct from the
observed `Interface`. `InterfaceMutator::set_interface_config` resolves its
target from the observed ID, updates the requested MTU and/or
administrative state, and re-reads the interface before returning success.
macOS uses separate ioctls for MTU and flags, so a failed combined patch may
have applied one requested field: re-read the interface after errors and use
the facade transaction executor's explicit compensation only when
restoration is required.

The native PF_ROUTE watcher maps `RTM_IFINFO` notifications to the existing
`Event::Interface { kind: ChangeKind::Changed }` signal; the facade does not
synthesize a duplicate event. The shared privileged test runner submits
unchanged observed values and cannot safely create a disposable interface,
so it does not claim end-to-end delivery for a value-changing configuration.
Always re-read observed state after a change signal.

## 🔐 Privileges and Safety

- Inspection is normally unprivileged.
- Mutations can require root or specific system entitlements and may
  interact with macOS network configuration services. Interface
  configuration writes the real system interface and can apply MTU and
  administrative state independently.
- Static-neighbor remove reads the target first and refuses to delete a
  present entry that is not currently `Permanent`, so a dynamically learned
  ARP/NDP cache entry is never removed by a static-removal request.
- Firewall policy replacement requires root. It is confined to the
  `net_lattice` anchor and never reads or writes rules configured by other
  tools (e.g. `pfctl` run by hand against a different anchor).
- Privileged tests run separately and must restore changed state.

## 📖 Documentation

- **API reference**: [docs.rs](https://docs.rs/net-lattice-backend-darwin)
- **Facade**: [`net-lattice`](https://crates.io/crates/net-lattice), which selects this backend
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
