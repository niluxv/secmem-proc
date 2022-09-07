//! Module containing the error structures used in the crate.

use core::fmt;
#[cfg(feature = "std")]
use thiserror::Error;

/// Trait describing systems errors.
///
/// Most code in this crate is generic over the error type as long as it
/// implements this trait. The `create` method is used to create a new error
/// for the last OS error that occurred (on systems which work with an `errno`/
/// `GetLastError` etc. system).
pub trait SysErr: fmt::Debug + fmt::Display {
    /// Create error for the last OS error.
    fn create() -> Self;

    /// Create error from raw OS error code.
    fn from_code(code: i32) -> Self;
}

/// Trait describing (system) allocation errors.
///
/// Mostly meant as an extension trait to [`SysErr`] to allow for allocation
/// errors.
pub trait AllocErr: fmt::Debug + fmt::Display {
    fn alloc_err() -> Self;
}

/// System error containing no information.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "std", derive(Error))]
pub struct EmptySystemError;

impl fmt::Display for EmptySystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("system error")
    }
}

impl SysErr for EmptySystemError {
    fn create() -> Self {
        Self
    }

    fn from_code(_code: i32) -> Self {
        Self
    }
}

impl AllocErr for EmptySystemError {
    fn alloc_err() -> Self {
        Self
    }
}

/// System error containing the error code, as a [`std::io::Error`].
#[cfg(feature = "std")]
pub type StdSystemError = std::io::Error;

#[cfg(feature = "std")]
impl SysErr for StdSystemError {
    fn create() -> Self {
        Self::last_os_error()
    }

    fn from_code(code: i32) -> Self {
        Self::from_raw_os_error(code)
    }
}

#[cfg(feature = "std")]
impl AllocErr for StdSystemError {
    fn alloc_err() -> Self {
        std::io::ErrorKind::OutOfMemory.into()
    }
}

// Prefered error type in (internals) tests.
#[cfg(test)]
cfg_if::cfg_if!(
    if #[cfg(feature = "std")] {
        pub(crate) use StdSystemError as TestSysErr;
    } else {
        pub(crate) use EmptySystemError as TestSysErr;
    }
);
