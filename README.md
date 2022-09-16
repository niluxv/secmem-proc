# secmem-proc ![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue) [![secmem-proc on crates.io](https://img.shields.io/crates/v/secmem-proc)](https://crates.io/crates/secmem-proc) [![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/niluxv/secmem-proc)

`secmem-proc` is a crate designed to harden a process against *low-privileged* attackers running on the same system trying to obtain secret memory contents of the current process. More specifically, the crate disables core dumps and tries to disable tracing on unix-like OSes.

**Note**: all the crate does is *hardening*, i.e. it tries to make attacks *harder*. It can by no means promise any security! In particular, when an attacker ptrace attaches to the process before `harden_process` is executed, it is game over for the process. This crate is no substitute for properly hardening your OS (configuration)!

Note that hardening the process also severely limits the ability to debug it. Therefore you are advised to only harden release builds, not debug builds.


## Windows

On Windows, [`harden_process`][__link0] sets a severly restricted DACL for the process. (More precisely, only the `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_TERMINATE` and `SYNCHRONIZE` permissions are enabled.) This could be too restrictive for the application to function correctly. When more permissions are required, the safe API in the [`win_acl`][__link1] module can be used to create and set a custom DACL instead.


## Examples

In the below example the main function of some application calls the main hardening function provided by this crate: `harden_process`. This will perform all available hardening steps on the target platform. If an error is returned then one of the hardening steps failed and the process is quits at the `return` after printing an error to stdout.


```rust
fn main() {
    // call `secmem_proc::harden_process` before doing anything else, to harden the process
    // against low-privileged attackers trying to obtain secret parts of memory which will
    // be handled by the process
    if secmem_proc::harden_process().is_err() {
        println!("ERROR: could not harden process, exiting");
        return;
    }
    // rest of your program
}
```

If you have the `std` feature enabled you can get more informative errors using [`harden_process_std_err`][__link2] instead of [`harden_process`][__link3].

In the next example we use the API in [`win_acl`][__link4] to set a custom DACL on Windows. In the example we grant the `PROCESS_CREATE_THREAD` permissions in addition to the default ones.


```rust
#[cfg(not(windows))]
use secmem_proc::harden_process;

#[cfg(windows)]
fn harden_process() -> Result<(), secmem_proc::error::EmptySystemError> {
    use windows::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };

    use secmem_proc::win_acl::{AddAllowAceAcl, EmptyAcl, TokenUser};

    // First obtain the SID of the process user
    let user = TokenUser::process_user()?;
    let sid = user.sid();

    // Now specify the ACL we want to create
    // Only things explicitly allowed with `AddAllowAceAcl` will be allowed; noting else
    let acl_spec = EmptyAcl;
    let access_mask = PROCESS_QUERY_LIMITED_INFORMATION
        | PROCESS_TERMINATE
        | PROCESS_SYNCHRONIZE
        | PROCESS_CREATE_THREAD;
    let acl_spec = AddAllowAceAcl::new(acl_spec, access_mask, sid);

    // Create ACL and set as process DACL
    let acl = acl_spec.create()?;
    acl.set_process_dacl_protected()
}

fn main() {
    if harden_process().is_err() {
        println!("ERROR: could not harden process, exiting");
        return;
    }
    // rest of your program
}
```


## Cargo features

 - `std` (default): Enable functionality that requires `std`. Currently only required for `Error` implements and required for tests. This feature is enabled by default.
 - `rlimit`: Expose a minimal resource limit API in the `rlimit` module.
 - `dev`: This feature enables all features required to run the test-suite, and should only be enabled for that purpose.


## Implementation

 - Disable ptrace and core dumps on the process on linux using prctl
 - Disable ptrace and core dumps on the process on freebsd using procctl
 - Disable ptrace on macos using ptrace
 - Disable core dumps for the process on posix systems using rlimit
 - Set restricted DACL for the process on windows


## TODOs

 - improve tests (how exactly?)


 [__cargo_doc2readme_dependencies_info]: ggGkYW0AYXSEG1xml6_F1TQjG2vbnLmziiP3GzgVz50YgVu4G490RSdCJM2nYXKEG0INHCJv8-HUG5-lZgNd46XDG3mILvaz9xHMG4oceCSt4aZvYWSBg2tzZWNtZW0tcHJvY2UwLjIuMGtzZWNtZW1fcHJvYw
 [__link0]: https://docs.rs/secmem-proc/0.2.0/secmem_proc/?search=secmem_proc::harden::harden_process
 [__link1]: https://docs.rs/secmem-proc/0.2.0/secmem_proc/?search=secmem_proc::win_acl
 [__link2]: https://docs.rs/secmem-proc/0.2.0/secmem_proc/?search=secmem_proc::harden::harden_process_std_err
 [__link3]: https://docs.rs/secmem-proc/0.2.0/secmem_proc/?search=secmem_proc::harden::harden_process
 [__link4]: https://docs.rs/secmem-proc/0.2.0/secmem_proc/?search=secmem_proc::win_acl


