//! This module defines the `harden_process` function which performs all
//! possible hardening steps available for the platform.

use crate::config::Config;
use crate::error::Result;

/// Performs all possible stable hardening steps for the platform. This uses the
/// default configuration, so unstable hardening methods are disabled regardless
/// of the `unstable` crate feature.
///
/// # Errors
/// Returns an error when one of the available hardening steps error due to a
/// system or libc interface returning an error. In case of error it is
/// recommended to issue an error and shut down the application without loading
/// secrets into memory.
pub fn harden_process() -> Result {
    const CONF: Config = Config::DEFAULT;
    CONF.harden_process()
}

#[cfg(test)]
mod tests {
    use super::harden_process;

    #[test]
    fn test_harden_process() {
        assert!(harden_process().is_ok());
    }

    #[test]
    #[cfg(feature = "std")]
    fn comptest_hardenerror_impl_error() {
        fn take_error<E: std::error::Error>(_e: E) {}

        let _ = harden_process().map_err(|e| take_error(e));
    }
}
