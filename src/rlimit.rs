//! Module giving a basic resource limit api bindings for the platform.
//!
//! This module is only available when using the `rlimit` feature.
//!
//! For a full-fetched high level resource limit api, see e.g. the
//! [`rlimit`](https://crates.io/crates/rlimit) crate.

use crate::error::SysErr;
use crate::internals::rlimit as internals;

pub use internals::Rlimit;

/// Resources which can be limited using the rlimit interface.
#[repr(u32)]
#[non_exhaustive]
pub enum Resource {
    AddrSpace = libc::RLIMIT_AS,
    Core = libc::RLIMIT_CORE,
    Cpu = libc::RLIMIT_CPU,
    Data = libc::RLIMIT_DATA,
    FileSize = libc::RLIMIT_FSIZE,
    Locks = libc::RLIMIT_LOCKS,
    MemLock = libc::RLIMIT_MEMLOCK,
    #[cfg(target_os = "linux")]
    MsgQueue = libc::RLIMIT_MSGQUEUE,
    #[cfg(target_os = "linux")]
    Nice = libc::RLIMIT_NICE,
    NFiles = libc::RLIMIT_NOFILE,
    NProcs = libc::RLIMIT_NPROC,
    Rss = libc::RLIMIT_RSS,
    #[cfg(target_os = "linux")]
    RTPrio = libc::RLIMIT_RTPRIO,
    #[cfg(target_os = "linux")]
    RTTime = libc::RLIMIT_RTTIME,
    #[cfg(target_os = "linux")]
    SigPending = libc::RLIMIT_SIGPENDING,
    Stack = libc::RLIMIT_STACK,
}

/// Get resource limit for `resource` to the limit pair pointed to by `rlim`.
pub fn get_rlimit<E: SysErr>(resource: Resource) -> Result<Rlimit, E> {
    let mut rlim = Rlimit::new(0, 0);
    // SAFETY: by the construction of the enum above, `resource as u32` is a valid
    // resource
    unsafe { internals::get_rlimit(resource as u32, &mut rlim) }?;
    Ok(rlim)
}

/// Set resource limit for `resource` to the limit pair pointed to by `rlim`.
pub fn set_rlimit<E: SysErr>(resource: Resource, rlim: &Rlimit) -> Result<(), E> {
    // SAFETY: by the construction of the enum above, `resource as u32` is a valid
    // resource
    unsafe { internals::set_rlimit(resource as u32, rlim) }
}
