//! Wrappers around platform specific functions, ffi and compiler intrinsics.

pub mod prctl;
pub mod rlimit;
#[cfg(windows)]
pub mod win32;
