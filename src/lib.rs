#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(future_incompatible, rust_2018_compatibility, unsafe_op_in_unsafe_fn)]
#![deny(rust_2018_idioms)]
#![warn(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#![warn(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
//! `secmem-proc` is a crate designed to harden a process against
//! *low-privileged* attackers running on the same system trying to obtain
//! secret memory contents of the current process. More specifically, the crate
//! disables core dumps and tries to disable tracing on unix-like OSes.
//!
//! __Note__: all the crate does is *hardening*, i.e. it tries to make attacks
//! *harder*. It can by no means promise any security! In particular, when an
//! attacker ptrace attaches to the process before `harden_process` is
//! executed, it is game over for the process. This crate is no substitute for
//! properly hardening your OS (configuration)!
//!
//! Note that hardening the process also severely limits the ability to debug
//! it. Therefore you are advised to only harden release builds, not debug
//! builds.
//!
//! # Examples
//! In the below example the main function of some application calls the main
//! hardening function provided by this crate: `harden_process`. This will
//! perform all available hardening steps on the target platform. If an error
//! is returned then one of the hardening steps failed and the process is quits
//! at the `return` after printing an error to stdout.
//!
//! ```
//! fn main() {
//!     // call `secmem_proc::harden_process` before doing anything else, to harden the process
//!     // against low-privileged attackers trying to obtain secret parts of memory which will
//!     // be handled by the process
//!     if secmem_proc::harden_process().is_err() {
//!         println!("ERROR: could not harden process, exiting");
//!         return;
//!     }
//!     // rest of your program
//! }
//! ```
//!
//! If you have the `std` feature enabled you can get more informative errors
//! using [`harden_process_std_err`] instead of [`harden_process`].
//!
//! # Cargo features
//! - `std` (default): Enable functionality that requires `std`. Currently only
//!   required for `Error` implements and required for tests. This feature is
//!   enabled by default.
//! - `rlimit`: Expose a minimal resource limit API in the `rlimit` module.
//! - `dev`: This feature enables all features required to run the test-suite,
//!   and should only be enabled for that purpose.
//!
//! # Implementation
//! - Disable ptrace and core dumps on the process on linux using prctl
//! - Disable ptrace and core dumps on the process on freebsd using procctl
//! - Disable ptrace on macos using ptrace
//! - Disable core dumps for the process on posix systems using rlimit
//! - Set restricted DACL for the process on windows

#[cfg(windows)]
extern crate alloc;

mod internals;

pub mod error;

pub mod harden;
#[cfg(all(feature = "rlimit", unix))]
pub mod rlimit;
#[cfg(windows)]
pub mod win_acl;

pub use harden::harden_process;
#[cfg(feature = "std")]
pub use harden::harden_process_std_err;

#[cfg(test)]
mod tests {
    /// > Freedom is the freedom to say that two plus two makes four.
    ///
    /// Nineteen Eighty-Four, George Orwell
    #[test]
    fn freedom() {
        assert_ne!(2 + 2, 5);
        assert_eq!(2 + 2, 4);
    }
}
