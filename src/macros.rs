//! This module contains a macro [`define_harden_function`] which allows to
//! create a custom hardening function according to given configuration options.
//! Under the hood this just uses the configuration API in [`crate::config`].
//!
//! # Examples
//! The following code defines a hardening function `harden` with `pub(crate)`
//! visibility using the default configuration. Calling `harden` is equivalent
//! to [`crate::harden_process`].
//!
//! ```
//! use secmem_proc::macros::define_harden_function;
//! define_harden_function! {
//!     pub(crate) fn harden {}
//! }
//!
//! // in main:
//! harden().expect("error during process hardening");
//! ```
//!
//! The next example disables anti-tracing techniques and anything that requires
//! file-system access:
//!
//! ```
//! use secmem_proc::macros::define_harden_function;
//! define_harden_function! {
//!     fn harden {
//!         anti_tracing = false,
//!         fs = false,
//!     }
//! }
//!
//! // in main:
//! harden().expect("error during process hardening");
//! ```
//!
//! # Configuration keys
//! * `anti_tracing` (bool)
//! * `fs` (bool)
//! * `fs.procfs` (bool)
//! * `unstable` (bool)
//! * `unstable.win.ntapi` (bool)
//! * `unstable.win.kernelmem` (bool)
//! * `unstable.assert_feature_enabled` (`true`): compile time assert that the
//!   `unstable` crate feature is enabled
//! * `win.dacl`: possible values:
//!   - `default`
//!   - `empty`
//!   - `custom_user_perm(<something of type WinDaclProcessAccess>)`
//!   - `custom_fnptr(<fn ptr of type fn() -> crate::Result>)`

/// Define a custom hardening function. See the module level documentation
/// [`crate::macros`] for details.
#[macro_export]
macro_rules! define_harden_function {
    ($visibility:vis fn $name:ident {$($($path:tt).+ = $rhs:tt,)*}) => {
        $visibility fn $name() -> $crate::error::Result {
            #[allow(unused_mut)]
            let mut config = $crate::config::Config::DEFAULT;
            $(
                define_harden_function!(@@ config, $($path).+ = $rhs);
            )*
            config.harden_process()
        }
    };
    (@@ $config:ident, anti_tracing = false) => {
        $config.set_anti_tracing(false);
    };
    (@@ $config:ident, anti_tracing = true) => {
        $config.set_anti_tracing(true);
    };
    (@@ $config:ident, fs = false) => {
        $config.set_fs(false);
    };
    (@@ $config:ident, fs = true) => {
        $config.set_fs(true);
    };
    (@@ $config:ident, fs.procfs = false) => {
        $config.set_fs_procfs(false);
    };
    (@@ $config:ident, fs.procfs = true) => {
        $config.set_fs_procfs(true);
    };
    (@@ $config:ident, unstable = false) => {
        $config.set_unstable(false);
    };
    (@@ $config:ident, unstable = true) => {
        $config.set_unstable(true);
    };
    (@@ $config:ident, unstable.win.ntapi = false) => {
        $config.set_unstable_win_ntapi(false);
    };
    (@@ $config:ident, unstable.win.ntapi = true) => {
        $config.set_unstable_win_ntapi(true);
    };
    (@@ $config:ident, unstable.win.kernelmem = false) => {
        $config.set_unstable_win_kernelmem(false);
    };
    (@@ $config:ident, unstable.win.kernelmem = true) => {
        $config.set_unstable_win_kernelmem(true);
    };
    (@@ $config:ident, unstable.assert_feature_enabled = true) => {
        const _: () = core::assert!(
            core::cfg!(feature = "unstable"),
            "`secmem_proc` crate feature `unstable` is not enabled, \
            while the configuration requires it"
        );
    };
    (@@ $config:ident, win.dacl = default) => {
        $config.set_win_dacl_default();
    };
    (@@ $config:ident, win.dacl = empty) => {
        $config.set_win_dacl_empty();
    };
    (@@ $config:ident, win.dacl = custom_user_perm($access:expr)) => {
        let access: $crate::config::WinDaclProcessAccess = $access;
        $config.set_win_dacl_custom_user_perm(access);
    };
    (@@ $config:ident, win.dacl = custom_fnptr($fnptr:expr)) => {
        let fnptr: fn() -> $crate::components::Result = $fnptr;
        $config.set_win_dacl_custom_fn(fnptr);
    };
}

pub use define_harden_function;

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::define_harden_function;

    #[test]
    fn macrotest_empty() {
        define_harden_function! {
            fn harden {}
        }
    }

    #[test]
    fn macrotest_visibility() {
        define_harden_function! {
            pub(crate) fn harden {}
        }
    }

    #[test]
    fn macrotest_anti_tracing() {
        define_harden_function! {
            fn harden {
                anti_tracing = false,
            }
        }
    }

    #[test]
    fn macrotest_multisetting() {
        define_harden_function! {
            fn harden {
                anti_tracing = false,
                fs = false,
                unstable = false,
            }
        }
    }

    #[test]
    fn macrotest_subsetting() {
        define_harden_function! {
            fn harden {
                fs.procfs = false,
            }
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn macrotest_assert_unstable_feature() {
        define_harden_function! {
            fn harden {
                unstable.assert_feature_enabled = true,
            }
        }
    }
}
