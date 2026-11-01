use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Stdio},
    sync::LazyLock,
};

static TEST_PROGRAM: LazyLock<escargot::CargoRun> = LazyLock::new(build_test_program);
#[cfg(windows)]
static ADVESARY_PROGRAM: LazyLock<escargot::CargoRun> = LazyLock::new(build_advesary_program);

fn build_test_program() -> escargot::CargoRun {
    escargot::CargoBuild::new()
        .example("test_print_addr")
        .run()
        .expect("failed to build test program")
}

#[cfg(windows)]
fn build_advesary_program() -> escargot::CargoRun {
    escargot::CargoBuild::new()
        .example("test_try_read_mem_windows")
        .run()
        .expect("failed to build test program")
}

fn run_test_program<F: FnOnce(&mut Child, usize) -> ()>(harden: bool, f: F) {
    let test_prog = &*TEST_PROGRAM;

    let mut cmd = test_prog.command();
    if harden {
        cmd.arg("--harden");
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd
        .spawn()
        .expect("could not spawn child process for testing");

    let stdout = child
        .stdout
        .as_mut()
        .expect("stdout handle should be present");
    let mut reader = BufReader::new(stdout);
    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .expect("error reading stdout of child");

    assert_eq!(buf.trim(), if harden { "hardened" } else { "not hardened" });
    buf.clear();

    reader
        .read_line(&mut buf)
        .expect("error reading stdout of child");

    let child_secret_addr =
        usize::from_str_radix(&buf.trim()[2..], 16).expect("could not parse address");

    f(&mut child, child_secret_addr);

    let stdin = child
        .stdin
        .as_mut()
        .expect("stdin handle should be present");
    stdin
        .write_all(b"\r\n")
        .expect("error writing to stdin of child");
}

/// Simply test that the child spawning etc. works if we do not interfere.
#[test]
fn run_test_program_hardened() {
    run_test_program(true, |_, _| {});
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{run_test_program, ADVESARY_PROGRAM};

    fn child_pid(child: &std::process::Child) -> u32 {
        use std::os::windows::io::AsRawHandle;

        let handle = windows::Win32::Foundation::HANDLE(child.as_raw_handle());
        unsafe { windows::Win32::System::Threading::GetProcessId(handle) }
    }

    /// Check that we can read the childs memory when it is not hardened.
    #[test]
    fn run_test_program_read_vm_memory_unhardened() {
        run_test_program(false, |child, addr| {
            let pid = child_pid(child);

            let mut adv_cmd = (*ADVESARY_PROGRAM).command();
            adv_cmd.arg(pid.to_string());
            adv_cmd.arg(addr.to_string());
            adv_cmd.arg("assert_success");

            let mut cmd = assert_cmd::Command::from_std(adv_cmd);
            cmd.assert().success();
        });
    }

    // /// Check we cannot read the childs memory when it is hardened.
    #[test]
    fn run_test_program_read_vm_memory_hardened() {
        run_test_program(true, |child, addr| {
            let pid = child_pid(child);

            let mut adv_cmd = (*ADVESARY_PROGRAM).command();
            adv_cmd.arg(pid.to_string());
            adv_cmd.arg(addr.to_string());
            adv_cmd.arg("assert_success");

            assert_cmd::Command::from_std(adv_cmd).assert().failure();

            let mut adv_cmd = (*ADVESARY_PROGRAM).command();
            adv_cmd.arg(pid.to_string());
            adv_cmd.arg(addr.to_string());
            adv_cmd.arg("assert_failure");

            assert_cmd::Command::from_std(adv_cmd).assert().success();
        });
    }
}
