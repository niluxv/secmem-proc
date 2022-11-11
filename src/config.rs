//! Module containing hardening configuration.
use crate::components;
use crate::error::Result;

/// Configuration for the hardening procedure. The configuration allows to
/// enable or disable certain features, such as filesystem access (e.g. for
/// procfs), anti-tracing methods and to use a custom DACL on windows.
pub struct Config {
    anti_tracing: bool,
    fs: Fs,
    unstable: Unstable,
    win_dacl: WinDacl,
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Config {
    /// Default configuration.
    pub const DEFAULT: Self = Self {
        anti_tracing: true,
        fs: Fs::DEFAULT,
        unstable: Unstable::DEFAULT,
        win_dacl: WinDacl::DEFAULT,
    };

    /// Create new default configuration, with anti-tracing set to
    /// `anti_tracing`.
    #[must_use]
    pub const fn new_with_anti_tracing(anti_tracing: bool) -> Self {
        Self {
            anti_tracing,
            fs: Fs::DEFAULT,
            unstable: Unstable::DEFAULT,
            win_dacl: WinDacl::DEFAULT,
        }
    }

    /// Set anti-tracing to `b` (true means enabled).
    pub fn set_anti_tracing(&mut self, b: bool) {
        self.anti_tracing = b;
    }

    /// Set filesystem access to `b` (true means enabled).
    pub fn set_fs(&mut self, b: bool) {
        self.fs = match b {
            true => Fs::TRUE,
            false => Fs::FALSE,
        };
    }

    /// Get mutable reference to filesystem access configuration, allowing to
    /// modify it.
    pub fn fs_mut(&mut self) -> &mut Fs {
        &mut self.fs
    }

    /// Set procfs access to `b` (true means enabled).
    pub fn set_fs_procfs(&mut self, b: bool) {
        self.fs.set_procfs(b);
    }

    /// Set unstable hardening methods to `b` (true means enabled).
    ///
    /// Default is disabled (false). Note that the `unstable` crate feature is
    /// required for this configuration to have any effect. Without that crate
    /// feature, the value of this configuration is silently ignored, and
    /// unstable hardening is not performed.
    pub fn set_unstable(&mut self, b: bool) {
        self.unstable = match b {
            true => Unstable::TRUE,
            false => Unstable::FALSE,
        };
    }

    /// Get mutable reference to unstable hardening configuration, allowing to
    /// modify it.
    pub fn unstable_mut(&mut self) -> &mut Unstable {
        &mut self.unstable
    }

    /// Set use of unstable windows native API to `b` (true means enabled).
    ///
    /// Default is disabled (false). Note that the `unstable` crate feature is
    /// required for this configuration to have any effect. Without that crate
    /// feature, the value of this configuration is silently ignored, and
    /// unstable hardening is not performed.
    pub fn set_unstable_win_ntapi(&mut self, b: bool) {
        self.unstable.set_win_ntapi(b);
    }

    /// Set use of unstable windows hardening relying on shared kernel memory to
    /// `b` (true means enabled).
    ///
    /// Default is disabled (false). Note that the `unstable` crate feature is
    /// required for this configuration to have any effect. Without that crate
    /// feature, the value of this configuration is silently ignored, and
    /// unstable hardening is not performed.
    pub fn set_unstable_win_kernelmem(&mut self, b: bool) {
        self.unstable.set_win_kernelmem(b);
    }

    /// Configure a custom windows DACL `dacl` (for the process).
    pub fn set_win_dacl(&mut self, dacl: WinDacl) {
        self.win_dacl = dacl;
    }

    /// Configure the windows DAC (for the process)L as the default.
    pub fn set_win_dacl_default(&mut self) {
        self.set_win_dacl(WinDacl::Default);
    }

    /// Configure the windows DACL (for the process) as an empty DACL. This
    /// means giving no access to any user at all. This is extremely strict. Use
    /// with caution.
    pub fn set_win_dacl_empty(&mut self) {
        self.set_win_dacl(WinDacl::Empty);
    }

    /// Configure the windows DACL (for the process) as a DACL which gives
    /// precisely the accesses specified by `access` to the current user, and no
    /// access to any other user.
    pub fn set_win_dacl_custom_user_perm(&mut self, access: WinDaclProcessAccess) {
        self.set_win_dacl(WinDacl::CustomUserPerm(access));
    }

    /// Configure to, instead of setting a DACL (for the process) on windows,
    /// call the function `fnptr`. This callback function `fnptr` can then be
    /// used to set a custom DACL yourself, using the API in
    /// [`crate::win_acl`].
    pub fn set_win_dacl_custom_fn(&mut self, fnptr: fn() -> Result) {
        self.set_win_dacl(WinDacl::CustomFn(fnptr));
    }

    /// Use the configuration `self` to harden the current process.
    pub fn harden_process(self) -> Result {
        // hide from debugger
        {
            if self.unstable.has_win_ntapi() {
                #[cfg(all(windows, feature = "unstable"))]
                components::hide_thread_from_debugger_ntapi()?;
            }
        }

        // disable debugger attaching; set up memory security; don't dump
        {
            #[cfg(windows)]
            self.win_dacl.call()?;

            #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
            components::disable_tracing_prctl()?;

            #[cfg(unix)]
            components::disable_core_dumps_rlimit()?;
        }

        // anti-tracing
        if self.anti_tracing {
            #[cfg(windows)]
            components::check_tracer_winapi()?;

            if self.unstable.has_win_kernelmem() {
                #[cfg(all(windows, feature = "unstable"))]
                components::check_tracer_unstable()?;
            }

            if self.fs.has_procfs() {
                #[cfg(all(target_os = "linux", feature = "std"))]
                components::check_tracer_procfs()?;
            }

            #[cfg(target_os = "freebsd")]
            components::check_tracer_prctl()?;
        }

        Ok(())
    }
}

/// Filesystem access configuration.
#[derive(Clone, Debug, PartialEq)]
pub struct Fs {
    procfs: bool,
}

impl Default for Fs {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Fs {
    /// Default filesystem configuration.
    pub const DEFAULT: Self = Self::TRUE;
    /// Disable all filesystem access.
    pub const FALSE: Self = Self { procfs: false };
    /// Enable all filesystem access.
    pub const TRUE: Self = Self { procfs: true };

    /// Set procfs access to `b` (true means enabled).
    pub fn set_procfs(&mut self, b: bool) {
        self.procfs = b;
    }

    /// Return whether procfs access is enabled.
    const fn has_procfs(&self) -> bool {
        self.procfs
    }
}

/// Structure for configuring hardening methods which rely on undocumented or
/// unstable target OS/platform details.
///
/// The default is to disable all. Note that the `unstable` crate feature is
/// required for this configuration to have any effect. Without that crate
/// feature, the value of this configuration is silently ignored.
#[derive(Clone, Debug, PartialEq)]
pub struct Unstable {
    /// Windows native API.
    win_ntapi: bool,
    /// Windows shared kernel memory.
    win_kernelmem: bool,
}

impl Default for Unstable {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Unstable {
    /// Default unstable configuration. This is the same as [`Self::FALSE`].
    pub const DEFAULT: Self = Self::FALSE;
    /// Disable (all) unstable hardening methods.
    pub const FALSE: Self = Self {
        win_ntapi: false,
        win_kernelmem: false,
    };
    /// Enable all unstable hardening methods.
    pub const TRUE: Self = Self {
        win_ntapi: true,
        win_kernelmem: true,
    };

    /// Set unstable windows native API hardening methods to `b` (true means
    /// enabled).
    pub fn set_win_ntapi(&mut self, b: bool) {
        self.win_ntapi = b;
    }

    /// Set unstable windows hardening methods relying on shared kernel memory
    /// to `b` (true means enabled).
    pub fn set_win_kernelmem(&mut self, b: bool) {
        self.win_kernelmem = b;
    }

    /// Return whether windows native API methods are enabled.
    const fn has_win_ntapi(&self) -> bool {
        self.win_ntapi
    }

    /// Return whether shared kernel memory methods are enabled.
    const fn has_win_kernelmem(&self) -> bool {
        self.win_kernelmem
    }
}

/// Custom windows DACL configuration.
pub enum WinDacl {
    /// The empty DACL. This means giving no access to any user at all. This is
    /// extremely strict. Use with caution.
    Empty,
    /// The default DACL.
    Default,
    /// A DACL which gives precisely the accesses specified in the first tuple
    /// position to the current user, and no access to any other user.
    CustomUserPerm(WinDaclProcessAccess),
    /// Don't set a DACL at all.
    False,
    /// Instead of setting a DACL, call the function in the first tuple
    /// position. This callback function can then be used to set a custom DACL
    /// yourself, using the API in [`crate::win_acl`].
    CustomFn(fn() -> Result),
}

/// Cross-platform type for windows process access masks, used for setting a
/// process DACL on windows.
///
/// Accesses can be added by bit-or-ing them together.
///
/// The type and all associated constants are available on all platforms, but
/// only meaningful on windows.
#[derive(Debug, Clone, Copy)]
pub struct WinDaclProcessAccess(u32);

impl core::ops::BitOr for WinDaclProcessAccess {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for WinDaclProcessAccess {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitOrAssign for WinDaclProcessAccess {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAndAssign for WinDaclProcessAccess {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

#[cfg(windows)]
impl From<WinDaclProcessAccess> for windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS {
    fn from(access: WinDaclProcessAccess) -> Self {
        Self(access.0)
    }
}

#[cfg(windows)]
impl From<&WinDaclProcessAccess> for windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS {
    fn from(access: &WinDaclProcessAccess) -> Self {
        Self(access.0)
    }
}

#[cfg(windows)]
impl WinDaclProcessAccess {
    pub const ALL_ACCESS: Self = Self::new(windows::Win32::System::Threading::PROCESS_ALL_ACCESS);
    pub const CREATE_PROCESS: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_CREATE_PROCESS);
    pub const CREATE_THREAD: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_CREATE_THREAD);
    pub const DELETE: Self = Self::new(windows::Win32::System::Threading::PROCESS_DELETE);
    pub const DUP_HANDLE: Self = Self::new(windows::Win32::System::Threading::PROCESS_DUP_HANDLE);
    pub const QUERY_INFORMATION: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION);
    pub const QUERY_LIMITED_INFORMATION: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION);
    pub const READ_CONTROL: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_READ_CONTROL);
    pub const SET_INFORMATION: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_SET_INFORMATION);
    pub const SET_QUOTA: Self = Self::new(windows::Win32::System::Threading::PROCESS_SET_QUOTA);
    pub const SUSPEND_RESUME: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_SUSPEND_RESUME);
    pub const SYNCHRONIZE: Self = Self::new(windows::Win32::System::Threading::PROCESS_SYNCHRONIZE);
    pub const TERMINATE: Self = Self::new(windows::Win32::System::Threading::PROCESS_TERMINATE);
    pub const VM_OPERATION: Self =
        Self::new(windows::Win32::System::Threading::PROCESS_VM_OPERATION);
    pub const VM_READ: Self = Self::new(windows::Win32::System::Threading::PROCESS_VM_READ);
    pub const VM_WRITE: Self = Self::new(windows::Win32::System::Threading::PROCESS_VM_WRITE);
    pub const WRITE_DAC: Self = Self::new(windows::Win32::System::Threading::PROCESS_WRITE_DAC);
    pub const WRITE_OWNER: Self = Self::new(windows::Win32::System::Threading::PROCESS_WRITE_OWNER);

    const fn new(access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS) -> Self {
        Self(access.0)
    }
}

// on non-windows targets just a bunch of dummy constants
#[cfg(not(windows))]
impl WinDaclProcessAccess {
    pub const ALL_ACCESS: Self = Self(0);
    pub const CREATE_PROCESS: Self = Self(0);
    pub const CREATE_THREAD: Self = Self(0);
    pub const DELETE: Self = Self(0);
    pub const DUP_HANDLE: Self = Self(0);
    pub const QUERY_INFORMATION: Self = Self(0);
    pub const QUERY_LIMITED_INFORMATION: Self = Self(0);
    pub const READ_CONTROL: Self = Self(0);
    pub const SET_INFORMATION: Self = Self(0);
    pub const SET_QUOTA: Self = Self(0);
    pub const SUSPEND_RESUME: Self = Self(0);
    pub const SYNCHRONIZE: Self = Self(0);
    pub const TERMINATE: Self = Self(0);
    pub const VM_OPERATION: Self = Self(0);
    pub const VM_READ: Self = Self(0);
    pub const VM_WRITE: Self = Self(0);
    pub const WRITE_DAC: Self = Self(0);
    pub const WRITE_OWNER: Self = Self(0);
}

impl Default for WinDacl {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl WinDacl {
    /// Default DACL.
    pub const DEFAULT: Self = Self::Default;

    /// Set the DACL configured in `self`. Most users probably want to set this
    /// DACL configuration in a [`Config`] using [`Config::set_win_dacl`], and
    /// then harden the process using that configuration
    /// ([`Config::harden_process`]) instead.
    pub fn call(&self) -> Result {
        #[cfg(windows)]
        return match self {
            Self::Empty => components::set_empty_dacl_winapi(),
            Self::Default => components::set_default_dacl_winapi(),
            Self::CustomUserPerm(access) => components::set_custom_dacl_winapi(access.into()),
            Self::False => Ok(()),
            Self::CustomFn(f) => f(),
        };
        #[cfg(not(windows))]
        Ok(())
    }
}
