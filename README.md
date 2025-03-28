# secmem-proc ![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue) [![secmem-proc on crates.io](https://img.shields.io/crates/v/secmem-proc)](https://crates.io/crates/secmem-proc) [![secmem-proc on docs.rs](https://docs.rs/secmem-proc/badge.svg)](https://docs.rs/secmem-proc) [![Source Code Repository](https://img.shields.io/badge/Code-On%20GitHub-blue?logo=GitHub)](https://github.com/niluxv/secmem-proc) ![Rust Version: 1.65.0](https://img.shields.io/badge/rustc-1.65.0-orange.svg)

`secmem-proc` is a crate designed to harden a process against
*low-privileged* attackers running on the same system trying to obtain
secret memory contents of the current process. More specifically, the crate
disables core dumps, makes a best effort to disable the ability to trace it,
and makes a minimal effort to detect already attached tracers.

**Note**: all the crate does is *hardening*, i.e. it tries to make attacks
*harder*. It can by no means promise any security! In particular, when an
attacker ptrace attaches to the process before `harden_process` is
executed, it is game over for the process. This crate is no substitute for
properly hardening your OS (configuration)!

Note that hardening the process also severely limits the ability to debug
it. Therefore you are advised to only harden release builds, not debug
builds.

## Windows

On Windows, [`harden_process`][__link0] sets a severly restricted DACL for the
process. (More precisely, only the `PROCESS_QUERY_LIMITED_INFORMATION`,
`PROCESS_TERMINATE` and `SYNCHRONIZE` permissions are enabled.) This could
be too restrictive for the application to function correctly. When more
permissions are required, the safe API in the [`win_acl`][__link1] module can be used
to create and set a custom DACL instead.

On windows, this crate depends on `std` via a dependency on the [`windows`
crate][__link2].

## Examples

In the below example the main function of some application calls the main
hardening function provided by this crate: `harden_process`. This will
perform all available hardening steps (except unstable ones) on the target
platform. When one of the hardening steps fails or a debugger is detected,
the function returns an error. It is advised to terminate the application on
any error.

```rust
fn main() {
    // call `secmem_proc::harden_process` before doing anything else, to harden the process
    // against low-privileged attackers trying to obtain secret parts of memory which will
    // be handled by the process
    if let Err(e) = secmem_proc::harden_process() {
        println!("ERROR: could not harden process, exiting");
        println!("ERROR: {}", e);
        return;
    }
    // rest of your program
}
```

It is also possible to configure what kind of hardening steps are performed.
For this, the API in [`config`][__link3] can be used. An example is shown below:

```rust
fn main() {
    // harden before doing anything else
    let mut config = secmem_proc::Config::DEFAULT;
    config.set_anti_tracing(false);
    config.set_fs(false);
    if let Err(e) = config.harden_process() {
        println!("ERROR: could not harden process, exiting");
        println!("ERROR: {}", e);
        return;
    }
    // rest of your program
}
```

In the last example we use the API in [`win_acl`][__link4] to set a custom DACL on
Windows. In the example we grant the `PROCESS_CREATE_THREAD` permissions in
addition to the default ones. Note that in this particular use case the same
could have been achieved using [`Config::set_win_dacl_custom_user_perm`][__link5],
which is clearly a lot easier. The below approach is, however, a lot more
flexible.

```rust
#[cfg(windows)]
fn set_windows_dacl() -> secmem_proc::Result {
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
    acl.set_process_dacl_protected()?;
    Ok(())
}

fn main() {
    // harden before doing anything else
    let mut config = secmem_proc::Config::DEFAULT;
    #[cfg(windows)]
    config.set_win_dacl_custom_fn(set_windows_dacl);
    config.set_fs(false);
    if let Err(e) = config.harden_process() {
        println!("ERROR: could not harden process, exiting");
        println!("ERROR: {}", e);
        return;
    }
    // rest of your program
}
```

## Cargo features

* `std` (default): Enable functionality that requires `std`. Currently
  required for anti-tracing on Linux via `/proc/self/status`. This feature
  is enabled by default.
* `unstable`: Enable functionality that depends on undocumented or unstable
  OS/platform details. This feature only enables support for these; to
  actually enable these anti-debugging methods, they have to be specifically
  enabled in the [configuration][__link6].
* `dev`: This feature enables all features required to run the test-suite,
  and should only be enabled for that purpose.

## Implementation

* Disable ptrace and core dumps for the process on linux using prctl
* Disable ptrace and core dumps for the process on freebsd using procctl
* Disable ptrace on macos using ptrace
* Disable core dumps for the process on posix systems using rlimit
* Set restricted DACL for the process on windows
* When the `std` feature is enabled, detect debuggers on linux by reading
  `/proc/self/status` (std, anti-tracing)
* Detect debuggers on windows using `IsDebuggerPresent` and
  `CheckRemoteDebuggerPresent` (anti-tracing)
* With unstable enabled, hide the thread from a debugger on windows
  (unstable, anti-tracing)
* With unstable enabled, detect debuggers on windows by reading from the
  kernel structure `KUSER_SHARED_DATA` (unstable, anti-tracing)

## Anti-tracing

The hardening methods employed by this crate can be divided into two groups:

* security related process hardening, and
* anti-tracing.

The difference between the two lies in the thread model. Process hardening
mostly assumes the process is not yet under attack, e.g. it is not yet being
traced. Hardening methods then make changed to the configuration of the
process to limit access other processes have to it, e.g. disable tracing of
the process or disable core dumps. Anti-tracing assumes the process is
already traced/debugged by a malicious process (malware). The goal is then
to detect the tracer/debugger. Anti-tracing methods can always be subverted
by a tracer/debugger, though some are harder to work around than others.
(The `KUSER_SHARED_DATA` unstable anti-tracing method on windows is a
difficult one to work around.) Anti-tracing can be disabled using
[`Config::set_anti_tracing(false)`][__link7].


 [__cargo_doc2readme_dependencies_info]: ggGkYW0BYXSEG_W_Gn_kaocAGwCcVPfenh7eGy6gYLEwyIe4G6-xw_FwcbpjYXKEG8lkptmLxZJsG_25AfZOt-uQG6Fho7Wj4MqeG8jUIo7JWaZwYWSBg2tzZWNtZW0tcHJvY2UwLjMuN2tzZWNtZW1fcHJvYw
 [__link0]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/?search=harden::harden_process
 [__link1]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/win_acl/index.html
 [__link2]: https://crates.io/crates/windows
 [__link3]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/config/index.html
 [__link4]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/win_acl/index.html
 [__link5]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/?search=config::Config::set_win_dacl_custom_user_perm
 [__link6]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/?search=config::Config
 [__link7]: https://docs.rs/secmem-proc/0.3.7/secmem_proc/?search=config::Config::set_anti_tracing
