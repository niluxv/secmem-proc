//! Module containing the error structures used in the crate.

/// System error types for unix-like systems.
mod sys_err {
    #[cfg(not(feature = "std"))]
    mod internal {
        use core::fmt;

        #[derive(Debug)]
        pub(crate) struct SysErr;

        impl fmt::Display for SysErr {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("system error")
            }
        }

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
        use core::fmt;

        #[derive(Debug, thiserror::Error)]
        pub(crate) struct SysErr(std::io::Error);

        impl fmt::Display for SysErr {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "system error: {}", self.0)
            }
        }

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

pub(crate) use sys_err::SysErr;

/// Private error types.
pub(crate) mod private {
    use core::fmt;

    /// Error indicating that the global allocator returned a zero pointer,
    /// possibly due to OOM.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    pub(crate) struct AllocError(core::alloc::Layout);

    impl fmt::Display for AllocError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("allocation error, possibly OOM")
        }
    }

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

    impl<T, E: Send + Sync + fmt::Debug + fmt::Display + 'static> ResultExt
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
/// detected (`BeingTraced` variant).
#[must_use]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Debug)]
pub enum Error {
    /// A debugger was detected.
    BeingTraced,
    /// An internal error occurred. Contains an [`anyhow::Error`] with the
    /// internal error.
    Err(anyhow::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BeingTraced => formatter.write_str("error: process is being traced"),
            Self::Err(e) => e.fmt(formatter),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Err(err)
    }
}

pub(crate) trait ResultExt {
    fn create_ok() -> Self;
    fn create_being_traced() -> Self;
    fn create_err(e: anyhow::Error) -> Self;
}

impl ResultExt for Result {
    fn create_ok() -> Self {
        Ok(())
    }

    fn create_being_traced() -> Self {
        Err(Error::BeingTraced)
    }

    fn create_err(e: anyhow::Error) -> Self {
        Err(Error::Err(e))
    }
}
