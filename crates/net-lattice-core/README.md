<div align="center">

# 🧱 net-lattice-core

### Shared Errors, Results, and IDs for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-core.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-core)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-core?cacheSeconds=86400)](https://docs.rs/net-lattice-core)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.99-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

[Overview](#-overview) • [Features](#-key-features) • [Installation](#-installation)
• [Quick Start](#-quick-start)

</div>

---

## 📖 Overview

Shared foundation types for the
[Net Lattice](https://github.com/F000NKKK/net-lattice) workspace. This crate
is platform-independent and performs no operating-system or network I/O.

> Most applications should use these types through the
> [`net-lattice`](https://crates.io/crates/net-lattice) facade. Depend on
> this crate directly when implementing a backend or a library that shares
> Net Lattice's foundational contracts.

## 🌟 Key Features

- ✅ **`Error` and `Result<T>`**, used across every Net Lattice crate;
- ✅ **`PlatformErrorCode`**, for preserving native Linux, Windows, and
  macOS errors;
- ✅ **`Id<T>`**, a strongly typed identifier that prevents mixing object
  domains: `Id<Route>` and `Id<Interface>` remain different Rust types even
  when their numeric values match.

## 📦 Installation

```toml
[dependencies]
net-lattice-core = "1.0"
```

## 🎓 Quick Start

```rust
use net_lattice_core::{Id, Result};

struct Interface;

fn selected_interface() -> Result<Id<Interface>> {
    Ok(Id::new(7))
}

assert_eq!(selected_interface().unwrap().value(), 7);
```

## 📖 Documentation

- **API reference**: [docs.rs/net-lattice-core](https://docs.rs/net-lattice-core)
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
