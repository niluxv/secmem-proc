//! Wrappers around platform specific functions, ffi and compiler intrinsics.

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub mod prctl;
#[cfg(unix)]
pub mod rlimit;
#[cfg(windows)]
pub mod win32;
