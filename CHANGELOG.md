# Changelog

## 0.2.1 - 2022-10-04
### Changed
- Use constants in `libc` for the FreeBSD `procctl` code

### Fixed
- wrong `debug_assert!` on FreeBSD in the `procctl` code

## 0.2.0 - 2022-09-16
### Added
- API to create and set custom DACLs on Windows

### Changed
- Switched from `winapi` to `windows` crate for Windows bindings

## 0.1.1 - 2022-01-08
- Added Windows DACL support: `harden_process` now sets a restricted DACL on windows

## 0.1.0 - 2021-11-03
Initial version
