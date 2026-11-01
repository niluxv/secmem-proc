use std::str::FromStr;

enum Mode {
    AssertSuccess,
    AssertSuccessResetDacl,
    AssertFailure,
}

fn main() {
    let mut args = std::env::args();
    assert!(args.next().is_some(), "no zero-th commandline argument");
    let pid =
        u32::from_str(args.next().expect("no pid argument").trim()).expect("could not parse pid");
    let addr = usize::from_str(args.next().expect("no addr argument").trim())
        .expect("could not parse address");
    let mode = match args.next().expect("no mode argument").trim() {
        "assert_success" => Mode::AssertSuccess,
        "assert_failure" => Mode::AssertFailure,
        "assert_success_reset_dacl" => Mode::AssertSuccessResetDacl,
        _ => panic!("invalid mode"),
    };

    platform::init();

    match mode {
        // Check that we can read the process memory
        Mode::AssertSuccess => platform::assert_success(pid, addr),
        // Check that we can read the process memory by first erasing the DACL for the process
        Mode::AssertSuccessResetDacl => platform::assert_success_reset_dacl(pid, addr),
        // Check we cannot read the process memory or reset the DACL
        Mode::AssertFailure => platform::assert_failure(pid),
    }
}
#[cfg(not(windows))]
mod platform {
    pub fn init() {}
    pub fn assert_success(_pid: u32, _addr: usize) {}
    pub fn assert_success_reset_dacl(_pid: u32, _addr: usize) {}
    pub fn assert_failure(_pid: u32) {}
}

#[cfg(windows)]
mod platform {
    use windows::Win32::Security;
    use windows::Win32::System;
    use System::Threading::{PROCESS_ACCESS_RIGHTS, PROCESS_VM_READ};

    const WRITE_DAC: PROCESS_ACCESS_RIGHTS =
        PROCESS_ACCESS_RIGHTS(windows::Win32::Storage::FileSystem::WRITE_DAC.0);

    /// Handle to a process.
    #[derive(Copy, Clone, Debug)]
    pub struct ProcessHandle(windows::Win32::Foundation::HANDLE);

    impl ProcessHandle {
        pub fn current_process() -> Self {
            Self(unsafe { System::Threading::GetCurrentProcess() })
        }

        pub fn open(pid: u32, desired_access: PROCESS_ACCESS_RIGHTS) -> anyhow::Result<Self> {
            Ok(Self(unsafe {
                System::Threading::OpenProcess(desired_access, false, pid)
            }?))
        }

        pub fn read_memory<T>(self, addr: usize, buf: &mut T) -> anyhow::Result<()> {
            let hprocess = self.0;
            let lpbaseaddress = std::ptr::without_provenance(addr);
            let lpbuffer = buf as *mut T as *mut _;
            let nsize = std::mem::size_of::<T>();

            Ok(unsafe {
                System::Diagnostics::Debug::ReadProcessMemory(
                    hprocess,
                    lpbaseaddress,
                    lpbuffer,
                    nsize,
                    None,
                )
            }?)
        }
    }

    /// Handle to an access token.
    #[derive(Debug)]
    pub struct AccessToken(windows::Win32::Foundation::HANDLE);

    impl Drop for AccessToken {
        fn drop(&mut self) {
            // SAFETY: safe since `self.0` must be an open (access token) handle
            let res = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
            res.unwrap()
        }
    }

    impl AccessToken {
        /// Given a process handle, this function returns a pointer to the process
        /// token of this process.
        pub fn open_process_token(
            handle: ProcessHandle,
            access: windows::Win32::Security::TOKEN_ACCESS_MASK,
        ) -> anyhow::Result<Self> {
            let mut token_handle = windows::Win32::Foundation::HANDLE(core::ptr::null_mut());
            unsafe {
                System::Threading::OpenProcessToken(handle.0, access, &mut token_handle as *mut _)
            }?;
            Ok(Self(token_handle))
        }

        pub fn disable_all_privileges(&self) -> anyhow::Result<()> {
            Ok(unsafe { Security::AdjustTokenPrivileges(self.0, true, None, 0, None, None) }?)
        }
    }

    pub fn init() {
        // Apparently GitHub Actions runners get the `SeDebugPrivilege` privilege, which bypasses
        // all DACL checks, so we need to disable privileges before trying to mount the attack.
        let proc = ProcessHandle::current_process();
        let access = Security::TOKEN_ADJUST_PRIVILEGES;
        AccessToken::open_process_token(proc, access)
            .expect("could not open process token with `TOKEN_ADJUST_PRIVILEGES` access")
            .disable_all_privileges()
            .expect("could not disable all privileges");
    }

    pub fn assert_success_reset_dacl(pid: u32, addr: usize) {
        let mut buf: u32 = 0;
        let proc = ProcessHandle::open(pid, WRITE_DAC)
            .expect("error opening child process with `WRITE_DAC` permission");
        unsafe {
            Security::Authorization::SetSecurityInfo(
                proc.0,
                Security::Authorization::SE_KERNEL_OBJECT,
                Security::DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
            )
        }
        .ok()
        .expect("could not unset DACL");

        let proc = ProcessHandle::open(pid, PROCESS_VM_READ)
            .expect("error opening child process with `PROCESS_VM_READ` permission");
        proc.read_memory(addr, &mut buf)
            .expect("error reading child process memory");

        assert_eq!(buf, 37);
    }

    pub fn assert_success(pid: u32, addr: usize) {
        let mut buf: u32 = 0;
        let proc = ProcessHandle::open(pid, PROCESS_VM_READ)
            .expect("error opening child process with `PROCESS_VM_READ` permission");
        proc.read_memory(addr, &mut buf)
            .expect("error reading child process memory");

        assert_eq!(buf, 37);
    }

    pub fn assert_failure(pid: u32) {
        ProcessHandle::open(pid, PROCESS_VM_READ)
            .expect_err("opened hardened child process with `PROCESS_VM_READ` permission");
        ProcessHandle::open(pid, WRITE_DAC)
            .expect_err("opened hardened child process with `WRITE_DAC` permission");
    }
}
