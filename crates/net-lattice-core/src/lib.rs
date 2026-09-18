//! Foundational types with no networking semantics of their own.
//!
//! `net-lattice-core` carries no OS dependency and no networking-specific
//! types — those belong to `net-lattice-ip` and `net-lattice-model`. See
//! ARCHITECTURE.md for the full rationale.

#![warn(missing_docs)]

mod error;
mod id;

pub use error::{Error, PlatformErrorCode};
pub use id::Id;

/// A result returned by Net Lattice operations.
pub type Result<T> = core::result::Result<T, Error>;
