//! Wrappers around platform specific functions, ffi and compiler intrinsics.

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub mod prctl;
#[cfg(feature = "std")]
pub mod std;
#[cfg(windows)]
pub mod win32;
