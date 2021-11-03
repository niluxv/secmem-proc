//! Helper functions for interfacing with platform specific process control
//! APIs.

use crate::error::SysErr;

/// Set traceability/dumpability of the current process to `arg`. `arg` must be
/// either `0` (not dumpable) or `1` (dumpable).
///
/// # Safety
/// `arg` must be either `0` or `1`.
#[cfg(target_os = "linux")]
unsafe fn prctl_set_traceable<E: SysErr>(arg: u64) -> Result<(), E> {
    debug_assert!(arg == 0 || arg == 1);
    let res: i32 = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, arg) };
    if res == 0 {
        Ok(())
    } else {
        Err(E::create())
    }
}

// #[cfg(target_os = "freebsd")]
// const PROC_TRACE_CTL_ENABLE: i32 = 1;
// #[cfg(target_os = "freebsd")]
// const PROC_TRACE_CTL_DISABLE: i32 = 2;
#[cfg(target_os = "freebsd")]
const PROC_TRACE_CTL_DISABLE_EXEC: i32 = 3;

/// Return the process ID of the calling process.
#[cfg(target_os = "freebsd")]
fn getpid() -> libc::pid_t {
    libc::getpid()
}

/// Set traceability/dumpability of the current process to `arg`. `arg` must be
/// `PROC_TRACE_CTL_ENABLE`, `PROC_TRACE_CTL_DISABLE` or
/// `PROC_TRACE_CTL_DISABLE`.
///
/// # Safety
/// `arg` must be `libc::PROC_TRACE_CTL_ENABLE`, `libc::PROC_TRACE_CTL_DISABLE`
/// or `libc::PROC_TRACE_CTL_DISABLE`.
#[cfg(target_os = "freebsd")]
unsafe fn prctl_set_traceable<E: SysErr>(arg: i32) -> Result<(), E> {
    debug_assert!(
        arg == libc::PROC_TRACE_CTL_ENABLE
            || arg == libc::PROC_TRACE_CTL_DISABLE
            || arg == libc::PROC_TRACE_CTL_DISABLE
    );
    let arg_ptr: *mut c_void = (&mut arg as *mut i32).cast::<libc::c_void>();
    let pid = getpid();
    let res: i32 = unsafe { libc::procctl(libc::P_PID, pid, libc::PROC_TRACE_CTL, arg_ptr) };
    if res == 0 {
        Ok(())
    } else {
        Err(E::create())
    }
}

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
pub fn set_process_nontraceable<E: SysErr>() -> Result<(), E> {
    // SAFETY: argument is `0`, which is a valid argument
    unsafe { prctl_set_traceable(0) }
}

/// Set process to non-traceable/non-dumpable. This disables core-dumps and
/// attaching via `ptrace`.
///
/// # Errors
/// Returns an error when the underlying syscall returns an error.
#[cfg(target_os = "freebsd")]
pub fn set_process_nontraceable<E: SysErr>() -> Result<(), E> {
    // SAFETY: argument is `0`, which is a valid argument
    unsafe { prctl_set_traceable(PROC_TRACE_CTL_DISABLE_EXEC) }
}

/// Set process to non-traceable. This disables attaching via `ptrace`.
///
/// # Errors
/// Returns an error when the underlying syscall returns an error.
#[cfg(target_os = "macos")]
pub fn set_process_nontraceable<E: SysErr>() -> Result<(), E> {
    // SAFETY: with `PT_DENY_ATTACH` request, all other arguments are ignored
    let res: i32 = unsafe { ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if res == 0 {
        Ok(())
    } else {
        Err(E::create())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    cfg_if::cfg_if!(
        if #[cfg(feature = "std")] {
            use crate::error::StdSystemError as TestSysErr;
        } else {
            use crate::error::EmptySystemError as TestSysErr;
        }
    );

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
    #[test]
    fn test_process_nondumpable() {
        assert!(set_process_nontraceable::<TestSysErr>().is_ok());
    }
}
