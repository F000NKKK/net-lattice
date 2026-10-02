<div align="center">

# ⚡ net-lattice-async

### Runtime-Independent Event Stream Adapter for Net Lattice

[![crates.io](https://img.shields.io/crates/v/net-lattice-async.svg?cacheSeconds=86400)](https://crates.io/crates/net-lattice-async)
[![docs.rs](https://img.shields.io/docsrs/net-lattice-async?cacheSeconds=86400)](https://docs.rs/net-lattice-async)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/net-lattice)

[Overview](#-overview) • [Features](#-key-features) • [Installation](#-installation)
• [Quick Start](#-quick-start) • [Runtime Behavior](#runtime-behavior)

</div>

---

## 📖 Overview

Runtime-independent asynchronous event-stream adapter for
[Net Lattice](https://github.com/F000NKKK/net-lattice).

> Applications normally enable the `async` feature on
> [`net-lattice`](https://crates.io/crates/net-lattice) and obtain the
> stream from its facade (`Lattice::watch_async`). Depend on this crate
> directly only when adapting a custom backend transport.

## 🌟 Key Features

- ✅ `EventStream<E>`, a `futures::Stream<Item = Result<E>>` surface;
- ✅ adaptation of blocking `EventReceiver` transports using one worker
  thread;
- ✅ direct wrapping of backend-native Tokio receivers;
- ✅ deterministic shutdown when the stream is dropped.

## 📦 Installation

```toml
[dependencies]
net-lattice-async = "1.0"
futures = "0.3"  # for `StreamExt` in the example below
```

## 🎓 Quick Start

```rust
use futures::StreamExt;
use net_lattice_async::{EventStream, Result};

async fn next_event<E>(stream: &mut EventStream<E>) -> Option<Result<E>>
where
    E: Unpin,
{
    stream.next().await
}
```

<a id="runtime-behavior"></a>

## ⚙️ Runtime Behavior

The adapter does not select an async runtime. A blocking receiver uses a
dedicated worker because `std::sync::mpsc::Receiver` cannot register a waker;
a native Tokio receiver is exposed without that worker.

## 📖 Documentation

- **API reference**: [docs.rs/net-lattice-async](https://docs.rs/net-lattice-async)
- **Facade**: [`net-lattice`](https://crates.io/crates/net-lattice), whose
  `async` feature uses this crate
- **Project**: [github.com/F000NKKK/net-lattice](https://github.com/F000NKKK/net-lattice)

## 📄 License

Licensed under the
[Mozilla Public License 2.0](https://github.com/F000NKKK/net-lattice/blob/main/LICENSE).
