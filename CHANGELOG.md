# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.4 - 2024-10-14
### Fixed
- Fixed the compilation error on FreeBSD due to missing `RawNonZeroPid` being removed from `rustix`
  in version `0.38`.

## 0.3.3 - 2024-01-17
### Internal
- Updated `windows` dependency to `0.52`.

## 0.3.2 - 2023-07-01
### Internal
- Updated `rustix` dependency to `0.38`.

## 0.3.1 - 2023-05-04
### Internal
- Updated `windows` and `rustix` dependencies.

## 0.3.0 - 2022-11-25
### Added
- tracer detection techniques.
- API in `config` module to configure the process hardening steps that are performed.
- macro `macros::define_harden_function` which functions analogous to the config API.
- `components` module which contains all low-level hardening techniques available on the platform.

### Changed
- **BREAKING**: Removed `rlimit` module.
- **BREAKING**: Removed all previous content of the `error` module.
- **BREAKING**: Removed all previous content of the `harden` module except `harden::harden_process`.
- **BREAKING**: Removed `harden_process_std_err` crate level re-export.
- **BREAKING**: Changed return type of `harden::harden_process` and it's crate root re-export
  `harden_process`, to use the new error type.
- Overhauled error handling, now using [`anyhow`](https://crates.io/crates/anyhow), with new `Error`
  and `Result` types in the `error` module. Errors should now be much more informative.
- Switched to [`rustix`](https://crates.io/crates/rustix) for most unix-like OS bindings. As a
  result, on linux the crate doesn't depend on a libc anymore (when using `no_std`).

## 0.2.1 - 2022-10-04
### Fixed
- wrong `debug_assert!` on FreeBSD in the `procctl` code.

### Internal
- Use constants in `libc` for the FreeBSD `procctl` code.

## 0.2.0 - 2022-09-16
### Added
- API to create and set custom DACLs on Windows.

### Changed
- Switched from `winapi` to `windows` crate for Windows bindings.

## 0.1.1 - 2022-01-08
### Added
- Windows DACL support: `harden_process` now sets a restricted DACL on windows.

## 0.1.0 - 2021-11-03
Initial version.
