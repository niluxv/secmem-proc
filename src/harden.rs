//! This module defines the `harden_process` function which performs all
//! possible hardening steps available for the platform.

#[cfg(windows)]
use crate::error::AllocErr;
use crate::error::{EmptySystemError, SysErr};
use core::fmt;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
use crate::internals::prctl;
#[cfg(unix)]
use crate::internals::rlimit;
#[cfg(windows)]
use crate::internals::win32::{self, get_process_handle, AclBox, AclSize};
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(windows)]
use winapi::um::accctrl::SE_KERNEL_OBJECT;

/// Error hardening process.
#[derive(Debug, Clone)]
pub struct HardenError<E: SysErr>(ImplHardenError<E>);

impl<E: SysErr> From<ImplHardenError<E>> for HardenError<E> {
    fn from(inner: ImplHardenError<E>) -> Self {
        Self(inner)
    }
}

impl<E: SysErr> HardenError<E> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn from_prctl(e: E) -> Self {
        ImplHardenError::PrCtl(e).into()
    }

    #[cfg(target_os = "macos")]
    fn from_ptrace(e: E) -> Self {
        ImplHardenError::Ptrace(e).into()
    }

    #[cfg(unix)]
    fn from_rlimit(e: E) -> Self {
        ImplHardenError::Rlimit(e).into()
    }

    #[cfg(windows)]
    fn from_winapi(e: E) -> Self {
        ImplHardenError::WinAPI(e).into()
    }
}

impl<E: SysErr> fmt::Display for HardenError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(feature = "std")]
impl<E: SysErr + std::error::Error + 'static> std::error::Error for HardenError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Error hardening process. Variants of this enum are system specific, so it
/// is not exposed as part of the public API, instead wrapped in the struct
/// [`HardenError`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "std", derive(Error))]
enum ImplHardenError<E: SysErr> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    PrCtl(#[cfg_attr(feature = "std", source)] E),
    #[cfg(target_os = "macos")]
    Ptrace(#[cfg_attr(feature = "std", source)] E),
    #[cfg(unix)]
    Rlimit(#[cfg_attr(feature = "std", source)] E),
    #[cfg(windows)]
    WinAPI(#[cfg_attr(feature = "std", source)] E),
}

impl<E: SysErr> fmt::Display for ImplHardenError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Self::PrCtl(_) => write!(f, "process hardening error in process control"),
            #[cfg(target_os = "macos")]
            Self::Ptrace(_) => write!(f, "process hardening error in ptrace"),
            #[cfg(unix)]
            Self::Rlimit(_) => write!(f, "process hardening error in resouce limits"),
            #[cfg(windows)]
            Self::WinAPI(_) => write!(f, "process hardening error in winapi"),
        }
    }
}

/// Harden error which does not include the underlying system error, but does
/// contain which hardening step went wrong.
///
/// Available on no-std targets.
pub type SimplHardenError = HardenError<EmptySystemError>;

/// Disable tracing for this process.
///
/// # Errors
/// Returns an error when the system or libc interface returns an error.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn disable_process_tracing<E: SysErr>() -> Result<(), HardenError<E>> {
    prctl::set_process_nontraceable().map_err(HardenError::from_prctl)
}

/// Disable tracing for this process.
///
/// # Errors
/// Returns an error when the system or libc interface returns an error.
#[cfg(target_os = "macos")]
fn disable_process_tracing<E: SysErr>() -> Result<(), HardenError<E>> {
    prctl::set_process_nontraceable().map_err(HardenError::from_ptrace)
}

/// Disable core dumps for this process.
///
/// # Errors
/// Returns an error when the system or libc interface returns an error.
#[cfg(unix)]
fn disable_core_dumps<E: SysErr>() -> Result<(), HardenError<E>> {
    let rlim = rlimit::Rlimit::new(0, 0);
    rlimit::set_coredump_rlimit(&rlim).map_err(HardenError::from_rlimit)
}

/// Limit user access to process by setting a default restrictive DACL for the
/// process.
#[cfg(windows)]
fn windows_set_dacl<E: SysErr + AllocErr>() -> Result<(), HardenError<E>> {
    // size of empty ACL
    let acl_size = AclSize::new();
    let acl = acl_size.allocate().map_err(HardenError::from_winapi)?;
    // SAFETY: `get_process_handle()` gives a valid handle to an `SE_KERNEL_OBJECT`
    // type object
    unsafe { acl.set_protected(get_process_handle(), SE_KERNEL_OBJECT) }
        .map_err(HardenError::from_winapi)
}

/// Performs all possible hardening steps for the platform.
///
/// # Errors
/// Returns an error when one of the available hardening steps error due to a
/// system or libc interface returning an error. In case of error it is
/// recommended to issue an error and shut down the application without loading
/// secrets into memory.
///
/// The system error can be any error implementing the [`SysErr`] trait. See
/// the [`error`](crate::error) module for more information.
#[cfg(unix)]
pub fn harden_process_other_err<E: SysErr>() -> Result<(), HardenError<E>> {
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
    disable_process_tracing()?;
    disable_core_dumps()?;
    Ok(())
}

/// Performs all possible hardening steps for the platform.
///
/// This is not implemented yet for windows.
///
/// # Errors
/// Returns an error when one of the available hardening steps error due to a
/// system or libc interface returning an error. In case of error it is
/// recommended to issue an error and shut down the application without loading
/// secrets into memory.
///
/// The system error can be any error implementing the [`SysErr`] trait. See
/// the [`error`](crate::error) module for more information.
#[cfg(windows)]
pub fn harden_process_other_err<E: SysErr + AllocErr>() -> Result<(), HardenError<E>> {
    windows_set_dacl()
}

/// Performs all possible hardening steps for the platform.
///
/// # Errors
/// Returns an error when one of the available hardening steps error due to a
/// system or libc interface returning an error. In case of error it is
/// recommended to issue an error and shut down the application without loading
/// secrets into memory.
///
/// The error doesn't contain the underlying system error but this function is
/// available on no-std targets.
pub fn harden_process() -> Result<(), SimplHardenError> {
    harden_process_other_err()
}

/// Performs all possible hardening steps for the platform.
///
/// # Errors
/// Returns an error when one of the available hardening steps error due to a
/// system or libc interface returning an error. In case of error it is
/// recommended to issue an error and shut down the application without loading
/// secrets into memory.
///
/// The error contains the underlying system error but this function is
/// available only when the `std` feature is enabled.
#[cfg(feature = "std")]
pub fn harden_process_std_err() -> Result<(), HardenError<crate::error::StdSystemError>> {
    harden_process_other_err()
}

#[cfg(test)]
mod tests {
    use super::harden_process;

    #[test]
    fn test_harden_process() {
        assert!(harden_process().is_ok());
    }

    #[test]
    #[cfg(feature = "std")]
    fn comptest_hardenerror_impl_error() {
        fn take_error<E: std::error::Error>(_e: E) {}

        let _ = harden_process().map_err(|e| take_error(e));
    }
}
