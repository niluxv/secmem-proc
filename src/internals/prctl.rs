//! Helper functions for interfacing with platform specific process control
//! APIs.

use crate::error::private::ResultExt;

/// Make `ptrace` call.
///
/// # Safety
/// `addr` must be valid for the `request`.
#[cfg(target_os = "macos")]
unsafe fn ptrace(request: i32, pid: libc::pid_t, addr: *mut u8, data: i32) -> i32 {
    // SAFETY: must be upheld by caller
    unsafe { libc::ptrace(request, pid, addr.cast::<libc::c_char>(), data) }
}

/// Set process to non-traceable/non-dumpable. This disables core-dumps and
/// attaching via `ptrace`.
///
/// # Errors
/// Returns an error when the underlying syscall returns an error.
#[cfg(target_os = "linux")]
pub fn set_process_nontraceable() -> anyhow::Result<()> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_anyhow()
}

/// Set process to non-traceable/non-dumpable. This disables core-dumps and
/// attaching via `ptrace`.
///
/// # Errors
/// Returns an error when the underlying syscall returns an error.
#[cfg(target_os = "freebsd")]
pub fn set_process_nontraceable() -> anyhow::Result<()> {
    rustix::process::set_dumpable_behavior(
        None,
        rustix::process::DumpableBehavior::NotDumpableExecPreserved,
    )
    .map_anyhow()
}

/// Set process to non-traceable. This disables attaching via `ptrace`.
///
/// # Errors
/// Returns an error when the underlying syscall returns an error.
// TODO: upstream to `rustix`
#[cfg(target_os = "macos")]
pub fn set_process_nontraceable() -> anyhow::Result<()> {
    // SAFETY: with `PT_DENY_ATTACH` request, all other arguments are ignored
    let res: i32 = unsafe { ptrace(libc::PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
    if res == 0 {
        Ok(())
    } else {
        Err(crate::error::SysErr::create_anyhow())
    }
}

/// Check whether the current process is being traced.
///
/// # Errors
/// Returns an error when the underlying syscall returns an error.
#[cfg(target_os = "freebsd")]
pub fn is_tracer_present() -> anyhow::Result<Option<rustix::process::Pid>> {
    match rustix::process::trace_status(None).map_anyhow()? {
        rustix::process::TracingStatus::BeingTraced(pid) => Ok(Some(pid)),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
    #[test]
    fn test_process_nondumpable() {
        assert!(set_process_nontraceable().is_ok());
    }
}
