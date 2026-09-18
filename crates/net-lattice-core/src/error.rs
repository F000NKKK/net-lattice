use std::fmt;

/// The single error type surfaced across the Net Lattice workspace.
///
/// Provider trait methods return `Result<T, Error>` — never a raw OS error
/// type (`std::io::Error`, a bare `errno`, a Windows `DWORD`). See
/// ARCHITECTURE.md's Error Model for why.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The operation requires privileges the caller does not have (e.g.
    /// `CAP_NET_ADMIN` on Linux, Administrator on Windows).
    PermissionDenied,
    /// The referenced object does not exist.
    NotFound,
    /// An object with the same identity already exists.
    AlreadyExists,
    /// The operation has no meaning on this backend at all, as opposed to
    /// a `Capability` being merely absent at runtime.
    Unsupported,
    /// The operation is not valid given the object's current state.
    InvalidState,
    /// An event channel's producer (the backend's background watcher) has
    /// shut down — no further events will ever arrive. Distinct from a
    /// timeout (which is not an error at all — see
    /// `EventReceiver::recv_timeout`): this means the stream is over for
    /// good, typically because the backend itself, or the connection it
    /// watches over, was dropped.
    Disconnected,
    /// Escape hatch preserving the raw backend-specific error for
    /// diagnostics. Not the primary way consumers are expected to match on
    /// failures.
    Platform(PlatformErrorCode),
}

/// A platform-tagged raw error code.
///
/// Linux errno is a signed `i32`, Windows error codes are an unsigned
/// `DWORD` (`u32`); collapsing both into one untyped integer would either
/// truncate one of them or imply the two are comparable, which they are
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformErrorCode {
    /// A Linux `errno` value.
    Linux(i32),
    /// A Windows error code (`DWORD`).
    Windows(u32),
    /// A Darwin (macOS) `errno` value.
    Darwin(i32),
}

impl Error {
    /// Returns `true` if this is [`Error::PermissionDenied`].
    pub const fn is_permission_denied(&self) -> bool {
        matches!(self, Error::PermissionDenied)
    }

    /// Returns `true` if this is [`Error::NotFound`].
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound)
    }

    /// Returns `true` if this is [`Error::AlreadyExists`].
    pub const fn is_already_exists(&self) -> bool {
        matches!(self, Error::AlreadyExists)
    }

    /// Returns `true` if this is [`Error::Unsupported`].
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Error::Unsupported)
    }

    /// Returns `true` if this is [`Error::InvalidState`].
    pub const fn is_invalid_state(&self) -> bool {
        matches!(self, Error::InvalidState)
    }

    /// Returns `true` if this is [`Error::Disconnected`].
    pub const fn is_disconnected(&self) -> bool {
        matches!(self, Error::Disconnected)
    }

    /// Returns `true` if this is [`Error::Platform`].
    pub const fn is_platform(&self) -> bool {
        matches!(self, Error::Platform(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PermissionDenied => write!(f, "permission denied"),
            Error::NotFound => write!(f, "not found"),
            Error::AlreadyExists => write!(f, "already exists"),
            Error::Unsupported => write!(f, "unsupported operation"),
            Error::InvalidState => write!(f, "invalid state"),
            Error::Disconnected => write!(f, "event channel disconnected"),
            Error::Platform(code) => write!(f, "platform error: {code:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_error_has_a_stable_display_message() {
        let cases = [
            (Error::PermissionDenied, "permission denied"),
            (Error::NotFound, "not found"),
            (Error::AlreadyExists, "already exists"),
            (Error::Unsupported, "unsupported operation"),
            (Error::InvalidState, "invalid state"),
            (Error::Disconnected, "event channel disconnected"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
        assert_eq!(
            Error::Platform(PlatformErrorCode::Linux(-1)).to_string(),
            "platform error: Linux(-1)"
        );
    }

    #[test]
    fn platform_error_codes_preserve_their_platform_and_value() {
        assert_eq!(PlatformErrorCode::Linux(-1), PlatformErrorCode::Linux(-1));
        assert_ne!(PlatformErrorCode::Windows(1), PlatformErrorCode::Darwin(1));
    }

    #[test]
    fn is_helpers_match_only_their_own_variant() {
        assert!(Error::PermissionDenied.is_permission_denied());
        assert!(!Error::NotFound.is_permission_denied());

        assert!(Error::NotFound.is_not_found());
        assert!(!Error::AlreadyExists.is_not_found());

        assert!(Error::AlreadyExists.is_already_exists());
        assert!(!Error::Unsupported.is_already_exists());

        assert!(Error::Unsupported.is_unsupported());
        assert!(!Error::InvalidState.is_unsupported());

        assert!(Error::InvalidState.is_invalid_state());
        assert!(!Error::Disconnected.is_invalid_state());

        assert!(Error::Disconnected.is_disconnected());
        assert!(!Error::Platform(PlatformErrorCode::Linux(-1)).is_disconnected());

        assert!(Error::Platform(PlatformErrorCode::Linux(-1)).is_platform());
        assert!(!Error::PermissionDenied.is_platform());
    }
}
