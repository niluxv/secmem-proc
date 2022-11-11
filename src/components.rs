//! Module containing hardening and anti-tracing components, which can be
//! combined into an appropriate hardening routine.
//!
//! The available components in this module are target/arch specific.

use crate::error::{Result, ResultExt as _};
use crate::internals;

/// Limit user access to process completely by setting an empty DACL (i.e. no
/// access allowed at all) for the process.
///
/// For fine-grained control over the DACL, use the API in [`crate::win_acl`].
///
/// * Type: memory-security, disable-debug
/// * Targets: windows
/// * API: WinApi (stable)
///
/// # Errors
/// Returns an error when the system interface returns an error.
#[cfg(windows)]
pub fn set_empty_dacl_winapi() -> Result {
    // Specify the ACL we want to create
    let acl_spec = crate::win_acl::EmptyAcl;

    // Create ACL and set as process DACL
    let acl = acl_spec.create()?;
    acl.set_process_dacl_protected()?;
    Result::create_ok()
}

/// Limit user access to process by setting a restrictive DACL for the process.
/// The access that is granted to the user owning the current process is given
/// by `access_mask`. Other users don't get any permissions.
///
/// For fine-grained control over the DACL, use the API in [`crate::win_acl`].
///
/// * Type: memory-security, disable-debug
/// * Targets: windows
/// * API: WinApi (stable)
///
/// # Errors
/// Returns an error when the system interface returns an error.
#[cfg(windows)]
pub fn set_custom_dacl_winapi(
    access_mask: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
) -> Result {
    use crate::win_acl::TokenUser;

    // First obtain the SID of the current user
    let user = TokenUser::process_user()?;
    let sid = user.sid();

    // Now specify the ACL we want to create
    let acl_spec = crate::win_acl::EmptyAcl;
    let acl_spec = crate::win_acl::AddAllowAceAcl::new(acl_spec, access_mask, sid);

    // Create ACL and set as process DACL
    let acl = acl_spec.create()?;
    acl.set_process_dacl_protected()?;
    Result::create_ok()
}

/// Limit user access to process by setting a default restrictive DACL for the
/// process.
///
/// For fine-grained control over the DACL, use the API in [`crate::win_acl`].
///
/// * Type: memory-security, disable-debug
/// * Targets: windows
/// * API: WinApi (stable)
///
/// # Errors
/// Returns an error when the system interface returns an error.
#[cfg(windows)]
pub fn set_default_dacl_winapi() -> Result {
    use windows::Win32::System::Threading::{
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };
    let access_mask = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE;
    set_custom_dacl_winapi(access_mask)
}

/// Disable core dumps for this process.
///
/// * Type: dont-dump
/// * Targets: posix/unix
/// * API: rlimit (stable)
///
/// # Errors
/// Returns an error when the system or libc interface returns an error.
#[cfg(unix)]
pub fn disable_core_dumps_rlimit() -> Result {
    use crate::error::private::ResultExt as _;

    const RESOURCE: rustix::process::Resource = rustix::process::Resource::Core;
    let rlim = rustix::process::Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(RESOURCE, rlim).map_anyhow()?;
    Result::create_ok()
}

/// Disable tracing for this process.
///
/// * Type: memory-security, disable-tracing, dont-dump
/// * Targets: linux, freebsd, macos
/// * API: prctl (stable) / ptrace (stable) (on macOS)
///
/// # Errors
/// Returns an error when the system or libc interface returns an error.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub fn disable_tracing_prctl() -> Result {
    internals::prctl::set_process_nontraceable()?;
    Result::create_ok()
}
