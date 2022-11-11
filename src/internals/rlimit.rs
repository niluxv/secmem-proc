//! Helper functions for interfacing with platform specific resource limit APIs.

use crate::error::SysErr;

cfg_if::cfg_if!(
    if #[cfg(target_env = "gnu")] {
        /// Type of rlimit resource identifiers.
        pub type RlimitResource = u32;
    } else {
        /// Type of rlimit resource identifiers.
        pub type RlimitResource = i32;
    }
);

/// Pair of soft and hard limit on a resource.
#[cfg(unix)]
pub struct Rlimit(libc::rlimit);

#[cfg(unix)]
impl Rlimit {
    /// Create [`Rlimit`] pair from soft and hard limits.
    #[must_use]
    pub fn new(rlim_cur: libc::rlim_t, rlim_max: libc::rlim_t) -> Self {
        debug_assert!(rlim_cur <= rlim_max);
        Self(libc::rlimit { rlim_cur, rlim_max })
    }

    /// Get the soft limit from an [`Rlimit`] pair.
    #[cfg(feature = "rlimit")]
    #[must_use]
    pub const fn soft_limit(&self) -> &libc::rlim_t {
        &self.0.rlim_cur
    }

    /// Get the hard limit from an [`Rlimit`] pair.
    #[cfg(feature = "rlimit")]
    #[must_use]
    pub const fn hard_limit(&self) -> &libc::rlim_t {
        &self.0.rlim_max
    }
}

#[cfg(unix)]
/// Set resource limit for `resource` to the limit pair pointed to by `rlim`.
///
/// # Safety
/// `resource` must be a valid resource identifier for the platform.
pub unsafe fn set_rlimit<E: SysErr>(resource: RlimitResource, rlim: &Rlimit) -> Result<(), E> {
    let res: i32 = unsafe { libc::setrlimit(resource, &rlim.0 as *const libc::rlimit) };
    if res == 0 {
        Ok(())
    } else {
        Err(E::create())
    }
}

#[cfg(unix)]
/// Set resource limit for core dumps to the limit pair pointed to by `rlim`.
pub fn set_coredump_rlimit<E: SysErr>(rlim: &Rlimit) -> Result<(), E> {
    // SAFETY: `libc::RLIMIT_CORE` is a valid resource
    unsafe { set_rlimit(libc::RLIMIT_CORE, rlim) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TestSysErr;

    #[cfg(unix)]
    #[test]
    fn test_resource_nodump() {
        let rlim = Rlimit::new(0, 0);
        assert!(set_coredump_rlimit::<TestSysErr>(&rlim).is_ok());
    }
}
