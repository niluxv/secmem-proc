use std::str::FromStr;

enum Mode {
    AssertSuccess,
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
        _ => panic!("invalid mode"),
    };

    match mode {
        // Check that we can read the process memory when it is not hardened
        Mode::AssertSuccess => platform::assert_success(pid, addr),
        // Check we cannot read the process memory when it is hardened
        Mode::AssertFailure => platform::assert_failure(pid),
    }
}
#[cfg(not(windows))]
mod platform {
    pub fn assert_success(_pid: u32, _addr: usize) {}
    pub fn assert_failure(_pid: u32) {}
}

#[cfg(windows)]
mod platform {
    use std::error::Error;

    use windows::Win32::System;
    use System::Threading::{PROCESS_ACCESS_RIGHTS, PROCESS_VM_READ};

    #[derive(Copy, Clone, Debug)]
    struct ProcessHandle(windows::Win32::Foundation::HANDLE);

    impl ProcessHandle {
        fn open(pid: u32, desired_access: PROCESS_ACCESS_RIGHTS) -> Result<Self, impl Error> {
            unsafe { System::Threading::OpenProcess(desired_access, false, pid) }.map(|h| Self(h))
        }

        fn read_memory<T>(self, addr: usize, buf: &mut T) -> Result<(), impl Error> {
            let hprocess = self.0;
            let lpbaseaddress = std::ptr::without_provenance(addr);
            let lpbuffer = buf as *mut T as *mut _;
            let nsize = std::mem::size_of::<T>();

            unsafe {
                System::Diagnostics::Debug::ReadProcessMemory(
                    hprocess,
                    lpbaseaddress,
                    lpbuffer,
                    nsize,
                    None,
                )
            }
        }
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
    }
}
