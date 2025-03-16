//! Module containing the error structures used in the crate.

/// Legacy error handling for macos, where we cannot (yet) use a `rustix` API.
#[cfg(target_os = "macos")]
mod sys_err {
    #[cfg(not(feature = "std"))]
    mod internal {
        #[derive(Debug, thiserror::Error)]
        #[error("system error")]
        pub(crate) struct SysErr;

        impl SysErr {
            pub fn create() -> Self {
                Self
            }

            pub fn create_anyhow() -> anyhow::Error {
                anyhow::anyhow!(Self::create())
            }
        }
    }

    #[cfg(feature = "std")]
    mod internal {
        #[derive(Debug, thiserror::Error)]
        #[error("system error: {0}")]
        pub(crate) struct SysErr(std::io::Error);

        impl SysErr {
            pub fn create() -> Self {
                Self(std::io::Error::last_os_error())
            }

            pub fn create_anyhow() -> anyhow::Error {
                anyhow::anyhow!(Self::create())
            }
        }
    }

    pub(crate) use internal::SysErr;
}

#[cfg(target_os = "macos")]
pub(crate) use sys_err::SysErr;

/// Private error types.
pub(crate) mod private {
    /// Error indicating that the global allocator returned a zero pointer,
    /// possibly due to OOM.
    #[derive(Debug, Clone, thiserror::Error)]
    #[error("allocation error, possibly OOM")]
    pub(crate) struct AllocError(core::alloc::Layout);

    impl AllocError {
        /// Create a new alloc error from a layout.
        #[must_use]
        pub(crate) fn new(layout: core::alloc::Layout) -> Self {
            Self(layout)
        }
    }

    pub(crate) fn alloc_err_from_size_align(size: usize, align: usize) -> anyhow::Error {
        let layout = core::alloc::Layout::from_size_align(size, align);
        match layout {
            Ok(layout) => anyhow::anyhow!(AllocError::new(layout)),
            Err(layout_err) => anyhow::anyhow!(layout_err),
        }
    }

    pub(crate) trait ResultExt {
        type T;
        fn map_anyhow(self) -> anyhow::Result<Self::T>;
    }

    impl<T, E: Send + Sync + core::fmt::Debug + core::fmt::Display + 'static> ResultExt
        for core::result::Result<T, E>
    {
        type T = T;

        fn map_anyhow(self) -> anyhow::Result<Self::T> {
            self.map_err(|e| anyhow::anyhow!(e))
        }
    }
}

// Public error types

/// The result type used throughout the public API of this crate.
pub type Result = core::result::Result<(), Error>;

/// Error that occurred during hardening.
///
/// Either an internal error occurred (`Err` variant), or a debugger was
/// detected (`BeingTraced` variant). This type implements
/// [`Display`](core::fmt::Display) in a way that clearly distinguishes these
/// cases, and prints more information about the detected debugger/tracer if
/// available.
#[must_use]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A debugger was detected. The [`Traced`] typed field might contain more
    /// information about the debugger/tracer.
    #[error("{0}")]
    BeingTraced(Traced),
    /// An internal error occurred. Contains an [`anyhow::Error`] with the
    /// internal error.
    #[error("{0}")]
    Err(anyhow::Error),
}

/// A structure potentially containing more information about a detected
/// debugger/tracer.
#[derive(Debug, Clone)]
pub struct Traced {
    #[cfg(unix)]
    pid: Option<rustix::process::Pid>,
}

#[cfg(unix)]
impl Traced {
    pub(crate) fn from_pid(pid: rustix::process::Pid) -> Self {
        Self { pid: Some(pid) }
    }
}

#[cfg(not(unix))]
impl Traced {
    pub(crate) const DEFAULT: Self = Self {};
}

impl core::fmt::Display for Traced {
    #[cfg(unix)]
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.pid {
            Some(pid) => write!(
                formatter,
                "program is being traced by the process with pid {}",
                pid.as_raw_nonzero()
            ),
            None => formatter.write_str("program is being traced"),
        }
    }

    #[cfg(not(unix))]
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("program is being traced")
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Err(err)
    }
}

pub(crate) trait ResultExt {
    fn create_ok() -> Self;
    fn create_being_traced(traced: Traced) -> Self;
    fn create_err(e: anyhow::Error) -> Self;
}

impl ResultExt for Result {
    fn create_ok() -> Self {
        Ok(())
    }

    fn create_being_traced(traced: Traced) -> Self {
        Err(Error::BeingTraced(traced))
    }

    fn create_err(e: anyhow::Error) -> Self {
        Err(Error::Err(e))
    }
}
