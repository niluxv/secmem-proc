//! Module containing hardening and anti-tracing components, which can be
//! combined into an appropriate hardening routine.
//!
//! The available components in this module are target/arch specific.
//!
//! You probably want to use the higher level platform independent configuration
//! API in [`crate::config`] instead; or the [`crate::harden_process`] function
//! which uses default configuration.

use crate::error::{Result, ResultExt as _, Traced};
use crate::internals;
use anyhow::Context;

/// Check whether a tracer is attached via the appropriate WinAPI calls.
///
/// * Type: anti-tracing
/// * Targets: windows
/// * API: WinAPI (stable)
///
/// # Errors
/// Returns an error when the system interface returns an error. Returns
/// `BeingTraced` when the process is being traced.
#[cfg(windows)]
pub fn check_tracer_winapi() -> Result {
    const TR: Traced = Traced::DEFAULT;

    if internals::win32::is_debugger_present() {
        return Result::create_being_traced(TR);
    };

    let res = unsafe {
        internals::win32::is_remote_debugger_present(internals::win32::get_process_handle())
    };
    match res {
        Ok(true) => {
            return Result::create_being_traced(TR);
        },
        Ok(false) => {},
        Err(e) => {
            return Result::create_err(
                e.context("Failed to check whether a tracer is present via WinAPI"),
            );
        },
    }

    Result::create_ok()
}

/// Check whether a tracer is attached using (undocumented) implementation
/// details of the OS.
///
/// * Type: anti-tracing
/// * Targets: windows
/// * API: unstable
///
/// # Errors
/// Returns `BeingTraced` when the process is being traced.
#[cfg(all(windows, feature = "unstable"))]
pub fn check_tracer_unstable() -> Result {
    const TR: Traced = Traced::DEFAULT;

    let res = unsafe { internals::win32::is_kernelflag_debugger_present() };
    if res {
        return Result::create_being_traced(TR);
    }

    Result::create_ok()
}

/// Hide thread from debugger using (undocumented) Windows native API.
///
/// * Type: anti-tracing
/// * Targets: windows
/// * API: NtApi (unstable)
///
/// # Errors
/// Returns an error when the system interface returns an error.
#[cfg(all(windows, feature = "unstable"))]
pub fn hide_thread_from_debugger_ntapi() -> Result {
    // SAFETY: `internals::win32::get_thread_handle()` gives a valid thread handle
    unsafe { internals::win32::hide_thread_from_debugger(internals::win32::get_thread_handle()) }
        .context("Failed hide the thread from potential tracers")?;
    Result::create_ok()
}

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
    const CTX: &str = "Failed to set a process DACL";

    // Specify the ACL we want to create
    let acl_spec = crate::win_acl::EmptyAcl;

    // Create ACL and set as process DACL
    let acl = acl_spec.create().context(CTX)?;
    acl.set_process_dacl_protected().context(CTX)?;
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
    const CTX: &str = "Failed to set a process DACL";

    // First obtain the SID of the current user
    let user = TokenUser::process_user().context(CTX)?;
    let sid = user.sid();

    // Now specify the ACL we want to create
    let acl_spec = crate::win_acl::EmptyAcl;
    let acl_spec = crate::win_acl::AddAllowAceAcl::new(acl_spec, access_mask, sid);

    // Create ACL and set as process DACL
    let acl = acl_spec.create().context(CTX)?;
    acl.set_process_dacl_protected().context(CTX)?;
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
    rustix::process::setrlimit(RESOURCE, rlim)
        .map_anyhow()
        .context("Failed to disable core-dumps via rlimit")?;
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
    internals::prctl::set_process_nontraceable()
        .context("Failed to disable ptrace-ability of the process")?;
    Result::create_ok()
}

/// Check whether a tracer is attached via the procfs virtual filesystem.
///
/// * Type: anti-tracing
/// * Targets: linux
/// * API: procfs (stable)
///
/// # Errors
/// Returns an error when the required procfs file `/proc/self/status` could not
/// be opened, or if it doesn't contain a valid `TracerPid` entry. Returns
/// `BeingTraced` when the process is being traced.
#[cfg(all(target_os = "linux", feature = "std"))]
pub fn check_tracer_procfs() -> Result {
    if let Some(pid) = internals::std::is_tracer_present()
        .context("Failed to check tracer presence via /proc/self/status")?
    {
        return Result::create_being_traced(Traced::from_pid(pid));
    };
    Result::create_ok()
}

/// Check whether a tracer is attached via the procfs virtual filesystem.
///
/// * Type: anti-tracing
/// * Targets: freebsd
/// * API: prctl (stable)
///
/// # Errors
/// Returns an error when the system or libc interface returns an error.
/// Returns `BeingTraced` when the process is being traced.
#[cfg(target_os = "freebsd")]
pub fn check_tracer_prctl() -> Result {
    if let Some(pid) = internals::prctl::is_tracer_present()
        .context("Failed to check tracer presence via procctl")?
    {
        return Result::create_being_traced(Traced::from_pid(pid));
    };
    Result::create_ok()
}
